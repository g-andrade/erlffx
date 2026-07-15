-module(erlffx).
-compile([inline, inline_list_funcs]).

-ifdef(E48).
-moduledoc """
Format-preserving encryption using the FFX mode of operation.

`erlffx` implements the mechanism described in the 2010 paper "The FFX Mode of
Operation for Format-Preserving Encryption" by Bellare, Rogaway and Spies. It
enciphers a non-negative integer into another integer of the same length, under
a chosen radix, so the ciphertext keeps the format of the plaintext. See the
[README](readme.html) for the paper link and examples.

- AES-128 / AES-192 / AES-256 keys are supported (CBC mode).
- Any positive word length is supported.
- Any radix / alphabet size between 2 and 255 is acceptable (10 by default).
- Optional 'tweak' values may be defined.
- The number of Feistel rounds is configurable (10 by default).
""".
-endif.

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([
    config/2,
    config/3,
    encrypt/2,
    decrypt/2
]).

-ignore_xref([
    config/2,
    config/3,
    encrypt/2,
    decrypt/2
]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(VERSION, 1).
-define(ADDITION_BLOCKWISE, 1).
-define(METHOD_ALTERNATING_FEISTEL, 2).

-define(MIN_RADIX, 2).
-define(MAX_RADIX, 65535).

-define(DEFAULT_RADIX, 10).
-define(DEFAULT_NUMBER_OF_ROUNDS, 10).

% -define(LOG(Fmt, Params), io:format(Fmt ++ "~n", Params)).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type radix() :: ?MIN_RADIX..?MAX_RADIX.
-export_type([radix/0]).

-type optional_config_params() :: #{
    tweak => iodata(),
    radix => radix(),
    number_of_rounds => non_neg_integer()
}.
-export_type([optional_config_params/0]).

-opaque config() :: #{
    aes_key := binary(),
    value_length := pos_integer(),
    tweak := iodata(),
    radix := radix(),
    number_of_rounds := non_neg_integer()
}.
-export_type([config/0]).

% A config/3 map before validation: the mandatory params are always present,
% the optional ones may not be yet.
-type raw_config() :: #{
    aes_key := iodata(),
    value_length := pos_integer(),
    tweak => iodata(),
    radix => radix(),
    number_of_rounds => non_neg_integer()
}.

-record(aux, {
    key :: binary(),
    radix :: radix(),
    tweak_vec :: iolist() | binary(),
    u :: pos_integer(),
    v :: pos_integer(),
    small_b :: non_neg_integer(),
    d :: non_neg_integer(),
    p :: binary(),
    q_zeros :: binary()
}).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-ifdef(E48).
-doc """
Like `config/3` but with default optional parameters.
""".
-endif.
-spec config(AesKey, ValueLength) -> Config when
    AesKey :: iodata(),
    ValueLength :: pos_integer(),
    Config :: config().
config(AesKey, ValueLength) ->
    config(AesKey, ValueLength, #{}).

-ifdef(E48).
-doc """
Builds an opaque encryption `t:config/0`.

- `AesKey` must be a 16-, 24- or 32-byte (AES-128/192/256) key.
- `ValueLength` is the word length, in digits of the chosen radix.
- `OptionalParams` may set the `tweak`, the `radix` (2..255, default 10) and
  the `number_of_rounds` (default 10).

The same `t:config/0` must be used to `encrypt/2` and `decrypt/2` a value.
""".
-endif.
-spec config(AesKey, ValueLength, OptionalParams) -> Config when
    AesKey :: iodata(),
    ValueLength :: pos_integer(),
    OptionalParams :: optional_config_params(),
    Config :: config().
config(AesKey, ValueLength, OptionalParams) ->
    MandatoryParams =
        #{
            aes_key => AesKey,
            value_length => ValueLength
        },
    Config = maps:merge(OptionalParams, MandatoryParams),
    validate_config(Config).

-ifdef(E48).
-doc """
Enciphers the non-negative integer `Value` under `Config`.

Returns an integer of the same word length and radix. Reverse it with
`decrypt/2` using the same `t:config/0`.
""".
-endif.
-spec encrypt(Config, Value) -> EncryptedValue when
    Config :: config(),
    Value :: non_neg_integer(),
    EncryptedValue :: non_neg_integer().
encrypt(Config, Value) ->
    #{
        aes_key := Key,
        radix := Radix,
        tweak := Tweak,
        value_length := ValueLength,
        number_of_rounds := NumberOfRounds
    } = Config,

    do_encdec(Key, Radix, Tweak, NumberOfRounds, Value, ValueLength, true).

-ifdef(E48).
-doc """
Deciphers `EncryptedValue` produced by `encrypt/2`, recovering the original
`Value`.

Must be given the same `t:config/0` that produced the ciphertext.
""".
-endif.
-spec decrypt(Config, EncryptedValue) -> Value when
    Config :: config(),
    EncryptedValue :: non_neg_integer(),
    Value :: non_neg_integer().
decrypt(Config, EncryptedValue) ->
    #{
        aes_key := Key,
        radix := Radix,
        tweak := Tweak,
        value_length := ValueLength,
        number_of_rounds := NumberOfRounds
    } = Config,

    do_encdec(Key, Radix, Tweak, NumberOfRounds, EncryptedValue, ValueLength, false).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec validate_config(raw_config()) -> config().
validate_config(Config) ->
    #{
        aes_key => validate_aes_key(maps:get(aes_key, Config)),
        value_length => validate_value_length(maps:get(value_length, Config)),
        tweak => validate_tweak(maps:get(tweak, Config, undefined)),
        radix => validate_radix(maps:get(radix, Config, undefined)),
        number_of_rounds => validate_number_of_rounds(maps:get(number_of_rounds, Config, undefined))
    }.

-spec validate_aes_key(iodata()) -> binary().
validate_aes_key(AesKey) ->
    % Normalize to a binary so the CBC primitive (which uses byte_size/1) can
    % accept any iodata() key.
    Binary = iolist_to_binary(AesKey),
    assert(lists:member(byte_size(Binary), [16, 24, 32])),
    Binary.

-spec validate_value_length(pos_integer()) -> pos_integer().
validate_value_length(ValueLength) when is_integer(ValueLength), ValueLength > 0 ->
    ValueLength.

-spec validate_tweak(iodata() | undefined) -> iodata().
validate_tweak(Tweak) when is_binary(Tweak); is_list(Tweak) ->
    Tweak;
validate_tweak(undefined) ->
    "".

-spec validate_radix(radix() | undefined) -> radix().
validate_radix(Radix) when is_integer(Radix), Radix >= ?MIN_RADIX, Radix =< ?MAX_RADIX ->
    Radix;
validate_radix(undefined) ->
    ?DEFAULT_RADIX.

-spec validate_number_of_rounds(non_neg_integer() | undefined) -> non_neg_integer().
validate_number_of_rounds(NumberOfRounds) when is_integer(NumberOfRounds), NumberOfRounds >= 0 ->
    NumberOfRounds;
validate_number_of_rounds(undefined) ->
    ?DEFAULT_NUMBER_OF_ROUNDS.

%%%%

do_encdec(Key, Radix, Tweak, NumberOfRounds, X, X_Length, DoEncrypt) ->
    TweakVec = erlang:iolist_to_iovec(Tweak),
    {Aux, A, B} = setup_encdec_vars(Key, Radix, TweakVec, NumberOfRounds, X, X_Length),

    {FinalA, FinalB} =
        case DoEncrypt of
            true ->
                do_encrypt_rounds(Aux, 0, NumberOfRounds, A, B);
            %
            false ->
                do_decrypt_rounds(Aux, NumberOfRounds - 1, A, B)
        end,

    %%
    FinalB + (FinalA * integer_pow(Radix, Aux#aux.v)).

%%%%

setup_encdec_vars(Key, Radix, Tweak, NumberOfRounds, X, X_Length) ->
    N = X_Length,

    TweakVec = erlang:iolist_to_iovec(Tweak),
    T = iolist_size(Tweak),

    U = N div 2,
    V = N - U,

    {A, B} = split_num_string_int(Radix, X, V),

    SmallB = byte_size(binary:encode_unsigned(integer_pow(Radix, V) - 1)),

    D = (4 * ((SmallB + 3) div 4)) + 4,

    P = <<
        ?VERSION,
        ?METHOD_ALTERNATING_FEISTEL,
        ?ADDITION_BLOCKWISE,
        Radix:24,
        NumberOfRounds,
        (non_negative_rem(U, 256)),
        N:32,
        T:32
    >>,

    Q_Zeros_Size = non_negative_rem(-T - SmallB - 1, 16),
    Q_Zeros = <<0:Q_Zeros_Size/unsigned-unit:8>>,

    Aux =
        #aux{
            key = Key,
            radix = Radix,
            tweak_vec = TweakVec,
            u = U,
            v = V,
            small_b = SmallB,
            d = D,
            p = P,
            q_zeros = Q_Zeros
        },

    {Aux, A, B}.

split_num_string_int(Radix, X, B_Length) ->
    split_num_string_int_recur(Radix, X, 0, 0, B_Length).

split_num_string_int_recur(Radix, A, B, N, Amount) when N < Amount ->
    Digit = A rem Radix,
    UpdatedA = A div Radix,
    UpdatedB = B + (Digit * integer_pow(Radix, N)),
    split_num_string_int_recur(Radix, UpdatedA, UpdatedB, N + 1, Amount);
split_num_string_int_recur(_Radix, A, B, _N, _Amount) ->
    {A, B}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

do_encrypt_rounds(Aux, I, NumberOfRounds, A, B) when I < NumberOfRounds ->
    #aux{
        key = Key,
        radix = Radix,
        tweak_vec = TweakVec,
        u = U,
        v = V,
        small_b = SmallB,
        d = D,
        p = P,
        q_zeros = Q_Zeros
    } = Aux,

    %%

    PRF_Arg2 = [
        P,
        % Q var
        TweakVec,
        Q_Zeros,
        I,
        <<B:SmallB/unsigned-unit:8>>
    ],

    R = prf(Key, PRF_Arg2),

    S_Blocks = compute_s_blocks(Key, D, R),
    S = binary_part(S_Blocks, 0, D),

    Y = binary:decode_unsigned(S),

    M =
        case (I band 1) of
            0 ->
                U;
            %
            _ ->
                V
        end,

    SmallC = non_negative_rem(A + Y, integer_pow(Radix, M)),

    C = SmallC,

    UpdatedA = B,
    UpdatedB = C,

    do_encrypt_rounds(Aux, I + 1, NumberOfRounds, UpdatedA, UpdatedB);
%
do_encrypt_rounds(_Aux, I, NumberOfRounds, A, B) when I =:= NumberOfRounds ->
    {A, B}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

do_decrypt_rounds(Aux, I, A, B) when I >= 0 ->
    #aux{
        key = Key,
        radix = Radix,
        tweak_vec = TweakVec,
        u = U,
        v = V,
        small_b = SmallB,
        d = D,
        p = P,
        q_zeros = Q_Zeros
    } = Aux,

    %%

    PRF_Arg2 = [
        P,
        % Q var
        TweakVec,
        Q_Zeros,
        I,
        <<A:SmallB/unsigned-unit:8>>
    ],

    R = prf(Key, PRF_Arg2),

    S_Blocks = compute_s_blocks(Key, D, R),
    S = binary_part(S_Blocks, 0, D),

    Y = binary:decode_unsigned(S),

    M =
        case (I band 1) of
            0 ->
                U;
            %
            _ ->
                V
        end,

    SmallC = non_negative_rem(B - Y, integer_pow(Radix, M)),

    C = SmallC,

    UpdatedB = A,
    UpdatedA = C,

    do_decrypt_rounds(Aux, I - 1, UpdatedA, UpdatedB);
%
do_decrypt_rounds(_Aux, I, A, B) when I =:= -1 ->
    {A, B}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

prf(Key, X) ->
    Cipher = map_get(bit_size(Key), #{128 => aes_128_cbc, 192 => aes_192_cbc, 256 => aes_256_cbc}),

    CT = crypto:crypto_one_time(Cipher, Key, <<0:128>>, X, true),
    binary_part(CT, byte_size(CT) - 16, 16).

ciph(Key, X) ->
    Cipher = map_get(bit_size(Key), #{128 => aes_128_ecb, 192 => aes_192_ecb, 256 => aes_256_ecb}),
    crypto:crypto_one_time(Cipher, Key, X, true).

compute_s_blocks(Key, SmallD, BigR) ->
    LastIndex = ((SmallD + 15) div 16) - 1,
    AccSize = byte_size(BigR),
    iolist_to_binary([BigR | compute_s_blocks_recur(Key, SmallD, BigR, AccSize, 1, LastIndex)]).

compute_s_blocks_recur(Key, SmallD, BigR, AccSize, Index, LastIndex) when
    Index =< LastIndex, AccSize < SmallD
->
    [
        ciph(Key, crypto:exor(BigR, <<Index:16/unsigned-unit:8>>))
        | compute_s_blocks_recur(Key, SmallD, BigR, AccSize + 16, Index + 1, LastIndex)
    ];
compute_s_blocks_recur(_Key, _SmallD, _BigR, _AccSize, _Index, _LastIndex) ->
    [].

%%%%

-spec integer_pow(Value, Power) -> Result when
    Value :: radix(),
    Power :: non_neg_integer(),
    Result :: pos_integer().
integer_pow(_Value, 0) ->
    1;
integer_pow(Value, Power) when Power > 0 ->
    Value * integer_pow(Value, Power - 1).

-spec assert(true) -> ok.
assert(true) -> ok.

-spec non_negative_rem(A, B) -> Rem when
    A :: integer(),
    B :: pos_integer(),
    Rem :: non_neg_integer().
non_negative_rem(A, B) when B > 0 ->
    % Erlang's `rem` follows the sign of the dividend, so for negative A it
    % yields a value in (-B, 0]. Adding B and taking `rem` again folds every
    % case into [0, B) -- crucially, when A is an exact negative multiple of B,
    % `A rem B` is 0 and the naive `(A rem B) + B` would wrongly return B.
    ((A rem B) + B) rem B.
