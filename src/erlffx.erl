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
-define(MAX_RADIX, 255).

-define(DEFAULT_RADIX, 10).
-define(DEFAULT_NUMBER_OF_ROUNDS, 10).

-define(DIV_BY_2(V), ((V) bsr 1)).
-define(DIV_BY_4(V), ((V) bsr 2)).
-define(DIV_BY_8(V), ((V) bsr 3)).

-ifdef(TEST).
-define(LOG(Fmt, Params), io:format(Fmt ++ "~n", Params)).
-else.
-define(LOG(Fmt, Params), ok).
-endif.

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

%-type radix() :: ?MIN_RADIX..?MAX_RADIX. % otherwise edoc blows up
-type radix() :: 2..255.
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

% The P value is always exactly 16 bytes (see generate_p/1).
-type p_value() :: <<_:128>>.
% The magnitude is always a positive power of the radix (see integer_pow/2).
-type maginteger() :: {Value :: non_neg_integer(), Magnitude :: pos_integer()}.

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
    P = generate_p(Config),
    ?LOG("P value: ~p", [P]),
    #{
        radix := Radix,
        value_length := ValueLength
    } = Config,
    L = ?DIV_BY_2(ValueLength + 1),
    InitialAMagnitude = integer_pow(Radix, ValueLength - L),
    InitialBMagnitude = integer_pow(Radix, L),
    InitialAValue = Value div InitialBMagnitude,
    InitialBValue = Value rem InitialBMagnitude,
    InitialA = maginteger(InitialAValue, InitialAMagnitude),
    InitialB = maginteger(InitialBValue, InitialBMagnitude),
    encrypt_loop(Config, P, 0, InitialA, InitialB).

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
    P = generate_p(Config),
    ?LOG("P value: ~p", [P]),
    #{
        radix := Radix,
        value_length := ValueLength,
        number_of_rounds := NumberOfRounds
    } = Config,
    L = ?DIV_BY_2(ValueLength + 1),
    InitialAMagnitude = integer_pow(Radix, ValueLength - L),
    InitialBMagnitude = integer_pow(Radix, L),
    InitialAValue = EncryptedValue div InitialBMagnitude,
    InitialBValue = EncryptedValue rem InitialBMagnitude,
    InitialA = maginteger(InitialAValue, InitialAMagnitude),
    InitialB = maginteger(InitialBValue, InitialBMagnitude),
    decrypt_loop(Config, P, NumberOfRounds - 1, InitialA, InitialB).

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

-spec encrypt_loop(config(), p_value(), non_neg_integer(), maginteger(), maginteger()) ->
    non_neg_integer().
encrypt_loop(#{number_of_rounds := NumberOfRounds}, _P, RoundIndex, A, B) when
    RoundIndex >= NumberOfRounds
->
    (maginteger_value(A) * maginteger_magnitude(B)) + maginteger_value(B);
encrypt_loop(Config, P, RoundIndex, A, B) ->
    FkValue = fk(Config, P, RoundIndex, maginteger_value(B)),
    C = maginteger_add(A, FkValue),
    NewA = B,
    NewB = C,
    encrypt_loop(Config, P, RoundIndex + 1, NewA, NewB).

-spec decrypt_loop(config(), p_value(), non_neg_integer() | -1, maginteger(), maginteger()) ->
    non_neg_integer().
decrypt_loop(_Config, _P, RoundIndex, A, B) when
    RoundIndex < 0
->
    (maginteger_value(A) * maginteger_magnitude(B)) + maginteger_value(B);
decrypt_loop(Config, P, RoundIndex, A, B) ->
    C = B,
    NewB = A,
    FkValue = fk(Config, P, RoundIndex, maginteger_value(NewB)),
    NewA = maginteger_sub(C, FkValue),
    decrypt_loop(Config, P, RoundIndex - 1, NewA, NewB).

-spec fk(config(), p_value(), non_neg_integer(), non_neg_integer()) -> non_neg_integer().
fk(Config, P, RoundIndex, BValue) ->
    #{
        tweak := Tweak,
        radix := Radix,
        value_length := ValueLength
    } = Config,
    ParamT = iolist_size(Tweak),
    ParamBeta = ?DIV_BY_2(ValueLength + 1),
    ParamB = ?DIV_BY_8(ceil(ParamBeta * math:log2(Radix)) + 7),
    ParamD = 4 * ?DIV_BY_4(ParamB + 3),
    ParamM = ?DIV_BY_2(ValueLength + (RoundIndex band 1)),

    TweakPaddingLength = (-ParamT - ParamB - 1) band 16#0F,
    BBytes = binary:encode_unsigned(BValue, big),
    assert(byte_size(BBytes) =< ParamB),
    BBytesPaddingLength = ParamB - byte_size(BBytes),

    Q = [
        Tweak,
        zeroed_binary(TweakPaddingLength),
        RoundIndex,
        zeroed_binary(BBytesPaddingLength),
        BBytes
    ],

    ToEncrypt = [P, Q],
    Y = aes_cbc_mac(Config, ToEncrypt),
    assert(byte_size(Y) >= (ParamD + 4)),

    ParamYBytes = binary:part(Y, {0, ParamD + 4}),
    ParamY = binary:decode_unsigned(ParamYBytes, big),
    Divisor = integer_pow(Radix, ParamM),
    ParamZ = non_negative_rem(ParamY, Divisor),

    ?LOG(
        "-----------------------~n"
        "RoundIndex: ~p~n"
        "B value: ~p~n"
        "Q value: ~p~n"
        "CBC-MAC value: ~p~n"
        "Output: ~p",
        [
            RoundIndex,
            integer_to_list(BValue, Radix),
            iolist_to_binary(Q),
            Y,
            integer_to_list(ParamZ, Radix)
        ]
    ),
    ParamZ.

-spec generate_p(config()) -> p_value().
generate_p(#{
    tweak := Tweak,
    radix := Radix,
    value_length := ValueLength,
    number_of_rounds := NumberOfRounds
}) ->
    TweakSize = iolist_size(Tweak),
    SplitN = (?DIV_BY_2(ValueLength) band 16#FF),
    <<?VERSION:8, ?METHOD_ALTERNATING_FEISTEL:8, ?ADDITION_BLOCKWISE:8, 0:16, Radix:8,
        NumberOfRounds:8, SplitN:8, ValueLength:4/big-unsigned-integer-unit:8,
        TweakSize:4/big-unsigned-integer-unit:8>>.

%-spec aes_cbc_mac(Config, ToEncrypt) -> Encrypted when
%    Config :: config(),
%    ToEncrypt :: iodata(),
%    Encrypted :: binary().
aes_cbc_mac(#{aes_key := AesKey}, ToEncrypt) ->
    IVec = zeroed_binary(16),
    Encrypted = aes_cbc(AesKey, IVec, ToEncrypt),
    binary:part(Encrypted, {byte_size(Encrypted) - 16, 16}).

%-spec aes_cbc(binary(), binary(), iodata()) -> binary().
-ifdef(POST_OTP_22).
aes_cbc(AesKey, IVec, ToEncrypt) ->
    Cipher =
        case iolist_size(AesKey) of
            16 -> aes_128_cbc;
            24 -> aes_192_cbc;
            32 -> aes_256_cbc
        end,
    crypto:crypto_one_time(Cipher, AesKey, IVec, ToEncrypt, true).
-else.
aes_cbc(AesKey, IVec, ToEncrypt) ->
    crypto:block_encrypt(aes_cbc, AesKey, IVec, ToEncrypt).
-endif.

-spec zeroed_binary(N :: non_neg_integer()) -> binary().
zeroed_binary(N) ->
    <<<<0:8>> || _ <- lists:seq(1, N)>>.

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
non_negative_rem(A, B) when A < 0, B > 0 ->
    (A rem B) + B;
non_negative_rem(A, B) when A >= 0, B > 0 ->
    A rem B.

-spec maginteger(Value, Magnitude) -> MagInteger when
    Value :: non_neg_integer(),
    Magnitude :: pos_integer(),
    MagInteger :: maginteger().
maginteger(Value, Magnitude) ->
    {Value, Magnitude}.

-spec maginteger_add(MagInteger1, Integer) -> MagInteger2 when
    MagInteger1 :: maginteger(),
    Integer :: non_neg_integer(),
    MagInteger2 :: maginteger().
maginteger_add({Value, Magnitude}, Integer) when is_integer(Integer) ->
    {non_negative_rem(Value + Integer, Magnitude), Magnitude}.

-spec maginteger_sub(MagInteger1, Integer) -> MagInteger2 when
    MagInteger1 :: maginteger(),
    Integer :: non_neg_integer(),
    MagInteger2 :: maginteger().
maginteger_sub({Value, Magnitude}, Integer) when is_integer(Integer) ->
    {non_negative_rem(Value - Integer, Magnitude), Magnitude}.

-spec maginteger_value(maginteger()) -> non_neg_integer().
maginteger_value({Value, _Magnitude}) ->
    Value.

-spec maginteger_magnitude(maginteger()) -> pos_integer().
maginteger_magnitude({_Value, Magnitude}) ->
    Magnitude.
