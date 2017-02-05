-module(erlffx).
-compile([inline, inline_list_funcs]).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([config/2]).  -ignore_xref({config,2}).
-export([config/3]).  -ignore_xref({config,3}).
-export([encrypt/2]). -ignore_xref({encrypt,2}).
-export([decrypt/2]). -ignore_xref({decrypt,2}).

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

-type radix() :: ?MIN_RADIX..?MAX_RADIX.
-export_type([radix/0]).

-type optional_config_params() :: #{ tweak => iodata(),
                                     radix => radix(),
                                     number_of_rounds => non_neg_integer() }.
-export_type([optional_config_params/0]).


-ifdef(pre19).
-type config() :: #{ aes_key => iodata(),
                     value_length => pos_integer(),
                     tweak => iodata(),
                     radix => radix(),
                     number_of_rounds => non_neg_integer() }.
-else.
-type config() :: #{ aes_key := iodata(),
                     value_length := pos_integer(),
                     tweak => iodata(),
                     radix => radix(),
                     number_of_rounds => non_neg_integer() }.
-endif.
-export_type([config/0]).

-type p_value() :: binary().
-type maginteger() :: {Value :: non_neg_integer(), Magnitude :: non_neg_integer()}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec config(AesKey, ValueLength) -> Config
        when AesKey :: iodata(),
             ValueLength :: pos_integer(),
             Config :: config().
config(AesKey, ValueLength) ->
    config(AesKey, ValueLength, #{}).

-spec config(AesKey, ValueLength, OptionalParams) -> Config
        when AesKey :: iodata(),
             ValueLength :: pos_integer(),
             OptionalParams :: optional_config_params(),
             Config :: config().
config(AesKey, ValueLength, OptionalParams) ->
    MandatoryParams =
        #{ aes_key => AesKey,
           value_length => ValueLength },
    Config = maps:merge(OptionalParams, MandatoryParams),
    validate_config(Config).

-spec encrypt(Config, Value) -> EncryptedValue
        when Config :: config(),
             Value :: non_neg_integer(),
             EncryptedValue :: non_neg_integer().
encrypt(Config, Value) ->
    P = generate_p(Config),
    ?LOG("P value: ~p", [P]),
    #{ radix := Radix,
       value_length := ValueLength } = Config,
    L = ?DIV_BY_2(ValueLength + 1),
    InitialA_Magnitude = integer_pow(Radix, ValueLength - L),
    InitialB_Magnitude = integer_pow(Radix, L),
    InitialA_Value = Value div InitialB_Magnitude,
    InitialB_Value = Value rem InitialB_Magnitude,
    InitialA = maginteger(InitialA_Value, InitialA_Magnitude),
    InitialB = maginteger(InitialB_Value, InitialB_Magnitude),
    encrypt_loop(Config, P, 0, InitialA, InitialB).

-spec decrypt(Config, EncryptedValue) -> Value
        when Config :: config(),
             EncryptedValue :: non_neg_integer(),
             Value :: non_neg_integer().
decrypt(Config, EncryptedValue) ->
    P = generate_p(Config),
    ?LOG("P value: ~p", [P]),
    #{ radix := Radix,
       value_length := ValueLength,
       number_of_rounds := NumberOfRounds } = Config,
    L = ?DIV_BY_2(ValueLength + 1),
    InitialA_Magnitude = integer_pow(Radix, ValueLength - L),
    InitialB_Magnitude = integer_pow(Radix, L),
    InitialA_Value = EncryptedValue div InitialB_Magnitude,
    InitialB_Value = EncryptedValue rem InitialB_Magnitude,
    InitialA = maginteger(InitialA_Value, InitialA_Magnitude),
    InitialB = maginteger(InitialB_Value, InitialB_Magnitude),
    decrypt_loop(Config, P, NumberOfRounds - 1, InitialA, InitialB).


%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec validate_config(config()) -> config().
validate_config(Config) ->
    #{ aes_key => validate_aes_key(maps:get(aes_key, Config)),
       value_length => validate_value_length(maps:get(value_length, Config)),
       tweak => validate_tweak(maps:get(tweak, Config, undefined)),
       radix => validate_radix(maps:get(radix, Config, undefined)),
       number_of_rounds => validate_number_of_rounds(maps:get(number_of_rounds, Config, undefined)) }.

-spec validate_aes_key(iodata()) -> iodata().
-ifdef(pre19).
validate_aes_key(AesKey) ->
    assert(lists:member(iolist_size(AesKey), [16, 32])),
    AesKey.
-else.
validate_aes_key(AesKey) ->
    assert(lists:member(iolist_size(AesKey), [16, 24, 32])),
    AesKey.
-endif.

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

-spec encrypt_loop(config(), p_value(), non_neg_integer(), maginteger(), maginteger())
        -> non_neg_integer().
encrypt_loop(#{ number_of_rounds := NumberOfRounds }, _P, RoundIndex, A, B)
  when RoundIndex >= NumberOfRounds ->
    (maginteger_value(A) * maginteger_magnitude(B)) + maginteger_value(B);
encrypt_loop(Config, P, RoundIndex, A, B) ->
    FkValue = fk(Config, P, RoundIndex, maginteger_value(B)),
    C = maginteger_add(A, FkValue),
    NewA = B,
    NewB = C,
    encrypt_loop(Config, P, RoundIndex + 1, NewA, NewB).

-spec decrypt_loop(config(), p_value(), non_neg_integer() | -1, maginteger(), maginteger())
        -> non_neg_integer().
decrypt_loop(_Config, _P, RoundIndex, A, B)
  when RoundIndex < 0 ->
    (maginteger_value(A) * maginteger_magnitude(B)) + maginteger_value(B);
decrypt_loop(Config, P, RoundIndex, A, B) ->
    C = B,
    NewB = A,
    FkValue = fk(Config, P, RoundIndex, maginteger_value(NewB)),
    NewA = maginteger_sub(C, FkValue),
    decrypt_loop(Config, P, RoundIndex - 1, NewA, NewB).

-spec fk(config(), p_value(), non_neg_integer(), non_neg_integer()) -> non_neg_integer().
fk(Config, P, RoundIndex, B_Value) ->
    #{ tweak := Tweak,
       radix := Radix,
       value_length := ValueLength } = Config,
    ParamT = iolist_size(Tweak),
    ParamBeta = ?DIV_BY_2(ValueLength + 1),
    ParamB = ?DIV_BY_8(ceil(ParamBeta * log2(Radix)) + 7),
    ParamD = 4 * ?DIV_BY_4(ParamB + 3),
    ParamM = ?DIV_BY_2(ValueLength + (RoundIndex band 1)),

    Tweak_PaddingLength = (-ParamT - ParamB - 1) band 16#0F,
    B_Bytes = binary:encode_unsigned(B_Value, big),
    assert(byte_size(B_Bytes) =< ParamB),
    B_Bytes_PaddingLength = ParamB - byte_size(B_Bytes),

    Q = [Tweak,
         zeroed_binary(Tweak_PaddingLength),
         RoundIndex,
         zeroed_binary(B_Bytes_PaddingLength),
         B_Bytes],

    ToEncrypt = [P, Q],
    Y = aes_cbc_mac(Config, ToEncrypt),
    assert(byte_size(Y) >= (ParamD + 4)),

    ParamY_Bytes = binary:part(Y, {0, ParamD + 4}),
    ParamY = binary:decode_unsigned(ParamY_Bytes, big),
    Divisor = integer_pow(Radix, ParamM),
    ParamZ = non_negative_rem(ParamY, Divisor),

    ?LOG("-----------------------~n"
         "RoundIndex: ~p~n"
         "B value: ~p~n"
         "Q value: ~p~n"
         "CBC-MAC value: ~p~n"
         "Output: ~p",
         [RoundIndex,
          integer_to_list(B_Value, Radix),
          iolist_to_binary(Q), Y,
          integer_to_list(ParamZ, Radix)]),
    ParamZ.

-spec ceil(float()) -> integer().
ceil(V) when V < 0.0 ->
    case (V - trunc(V)) >= -0.5 of
        true -> trunc(V);
        false -> trunc(V - 1)
    end;
ceil(V) ->
    case (V - trunc(V)) >= 0.5 of
        true -> trunc(V + 1);
        false -> trunc(V)
    end.

-spec log2(radix()) -> float().
-ifdef(pre18).
log2(V) -> math:log(V) / math:log(2).
-else.
log2(V) -> math:log2(V).
-endif.

-spec generate_p(config()) -> p_value().
generate_p(#{ tweak := Tweak,
              radix := Radix,
              value_length := ValueLength,
              number_of_rounds := NumberOfRounds }) ->
    TweakSize = iolist_size(Tweak),
    SplitN = (?DIV_BY_2(ValueLength) band 16#FF),
    <<?VERSION:8,
      ?METHOD_ALTERNATING_FEISTEL:8,
      ?ADDITION_BLOCKWISE:8,
      0:16,
      Radix:8,
      NumberOfRounds:8,
      SplitN:8,
      ValueLength:4/big-unsigned-integer-unit:8,
      TweakSize:4/big-unsigned-integer-unit:8>>.

-spec aes_cbc_mac(Config, ToEncrypt) -> Encrypted
        when Config :: config(),
             ToEncrypt :: iodata(),
             Encrypted :: binary().
-ifdef(pre19).
aes_cbc_mac(#{ aes_key := AesKey }, ToEncrypt) ->
    Cipher = case iolist_size(AesKey) of
                 16 -> aes_cbc128;
                 32 -> aes_cbc256
             end,
    IVec = zeroed_binary(16),
    Encrypted = crypto:block_encrypt(Cipher, AesKey, IVec, ToEncrypt),
    binary:part(Encrypted, {byte_size(Encrypted) - 16, 16}).
-else.
aes_cbc_mac(#{ aes_key := AesKey }, ToEncrypt) ->
    IVec = zeroed_binary(16),
    Encrypted = crypto:block_encrypt(aes_cbc, AesKey, IVec, ToEncrypt),
    binary:part(Encrypted, {byte_size(Encrypted) - 16, 16}).
-endif.

-spec zeroed_binary(N :: non_neg_integer()) -> binary().
zeroed_binary(N) ->
    <<<<0:8>> || _ <- lists:seq(1, N)>>.

-spec integer_pow(Value, Power) -> Result
        when Value :: integer(),
             Power :: non_neg_integer(),
             Result :: integer().
integer_pow(_Value, 0) ->
    1;
integer_pow(Value, Power) when Power > 0 ->
    Value * integer_pow(Value, Power - 1).

-spec assert(true) -> ok.
assert(true) -> ok.

-spec non_negative_rem(A, B) -> Rem
        when A :: integer(),
             B :: pos_integer(),
             Rem :: non_neg_integer().
non_negative_rem(A, B) when A < 0, B > 0 ->
    (A rem B) + B;
non_negative_rem(A, B) when A >= 0, B > 0 ->
    A rem B.

-spec maginteger(Value, Magnitude) -> MagInteger
        when Value :: non_neg_integer(),
             Magnitude :: non_neg_integer(),
             MagInteger :: maginteger().
maginteger(Value, Magnitude) ->
    {Value, Magnitude}.

-spec maginteger_add(MagInteger1, Integer) -> MagInteger2
        when MagInteger1 :: maginteger(),
             Integer :: integer(),
             MagInteger2 :: maginteger().
maginteger_add({Value, Magnitude}, Integer) when is_integer(Integer) ->
    {non_negative_rem(Value + Integer, Magnitude), Magnitude}.

-spec maginteger_sub(MagInteger1, Integer) -> MagInteger2
        when MagInteger1 :: maginteger(),
             Integer :: integer(),
             MagInteger2 :: maginteger().
maginteger_sub({Value, Magnitude}, Integer) when is_integer(Integer) ->
    {non_negative_rem(Value - Integer, Magnitude), Magnitude}.

-spec maginteger_value(maginteger()) -> non_neg_integer().
maginteger_value({Value, _Magnitude}) ->
    Value.

-spec maginteger_magnitude(maginteger()) -> non_neg_integer().
maginteger_magnitude({_Value, Magnitude}) ->
    Magnitude.

%% ------------------------------------------------------------------
%% Unit Testing Function definitions
%% ------------------------------------------------------------------

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> ok.

-spec run_encryptdecrypt_test_(erlffx:config(), non_neg_integer(), non_neg_integer()) -> ok.
run_encryptdecrypt_test_(Config, Value, ExpectedEncryptedValue) ->
    EncryptedValue = erlffx:encrypt(Config, Value),
    ?assertEqual(EncryptedValue, ExpectedEncryptedValue),
    DecryptedValue = erlffx:decrypt(Config, EncryptedValue),
    ?assertEqual(DecryptedValue, Value).

-spec common_testing_aes128_key() -> binary().
common_testing_aes128_key() ->
    <<(16#2b7e151628aed2a6abf7158809cf4f3c):16/big-unsigned-integer-unit:8>>.

%
% http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
%

-spec aes_ffx_vector1_test() -> ok.
aes_ffx_vector1_test() ->
    Config =
        config(common_testing_aes128_key(), 10,
               #{ tweak => "9876543210" }),
    run_encryptdecrypt_test_(Config, 123456789, 6124200773).

-spec aes_ffx_vector2_test() -> ok.
aes_ffx_vector2_test() ->
    Config = config(common_testing_aes128_key(), 10),
    run_encryptdecrypt_test_(Config, 123456789, 2433477484).

-spec aes_ffx_vector3_test() -> ok.
aes_ffx_vector3_test() ->
    Config =
        config(common_testing_aes128_key(), 6,
               #{ tweak => "2718281828" }),
    run_encryptdecrypt_test_(Config, 314159, 535005).

-spec aes_ffx_vector4_test() -> ok.
aes_ffx_vector4_test() ->
    Config =
        config(common_testing_aes128_key(), 9,
               #{ tweak => "7777777" }),
    run_encryptdecrypt_test_(Config, 999999999, 658229573).

-spec aes_ffx_vector5_test() -> ok.
aes_ffx_vector5_test() ->
    Config =
        config(common_testing_aes128_key(), 16,
               #{ tweak => "TQF9J5QDAGSCSPB1",
                  radix => 36 }),
    run_encryptdecrypt_test_(Config, 36#C4XPWULBM3M863JH, 36#C8AQ3U846ZWH6QZP).

%
% http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF1samples.pdf
%

-spec digit_list_in_radix(radix(), [0..254]) -> string().
digit_list_in_radix(Radix, Digits) ->
    lists:map(
      fun (Digit) when Digit < Radix ->
              [EncodedDigit] = integer_to_list(Digit, Radix),
              EncodedDigit
      end,
      Digits).

-spec digit_list_to_number(radix(), [0..254]) -> non_neg_integer().
digit_list_to_number(_Radix, []) -> 0;
digit_list_to_number(Radix, Digits) ->
    EncodedDigits = digit_list_in_radix(Radix, Digits),
    list_to_integer(EncodedDigits, Radix).

-spec ff1_sample3_aes128_test() -> ok.
ff1_sample3_aes128_test() ->
    Config =
        config(common_testing_aes128_key(), 19,
               #{ tweak => <<16#37,16#37,16#37,16#37,16#70,16#71,16#72,16#73,16#37,16#37,16#37>>,
                  radix => 36 }),
    EncryptedValue =
        digit_list_to_number(36, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                                  10, 11, 12, 13, 14, 15, 16, 17, 18]),
    DecryptedValue =
        digit_list_to_number(36, [10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13,
                                  30, 5, 0, 9, 14, 30, 22]),
    run_encryptdecrypt_test_(Config, EncryptedValue, DecryptedValue).

-ifndef(pre19).
-spec ff1_sample4_aes192_test() -> ok.
ff1_sample4_aes192_test() ->
    Config =
        config(<<16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F
                 :24/big-unsigned-integer-unit:8>>,
               10),
    run_encryptdecrypt_test_(Config, 123456789, 2830668132).

-spec ff1_sample5_aes192_test() -> ok.
ff1_sample5_aes192_test() ->
    Config =
        config(<<16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F
                 :24/big-unsigned-integer-unit:8>>,
               10,
               #{ tweak => <<16#39383736353433323130:10/big-unsigned-integer-unit:8>> }),
    run_encryptdecrypt_test_(Config, 123456789, 2496655549).

-spec ff1_sample6_aes192_test() -> ok.
ff1_sample6_aes192_test() ->
    Config =
        config(<<16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F
                 :24/big-unsigned-integer-unit:8>>,
               19,
               #{ tweak => <<16#3737373770717273373737:11/big-unsigned-integer-unit:8>>,
                  radix => 36 }),
    EncryptedValue =
        digit_list_to_number(36, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                                  10, 11, 12, 13, 14, 15, 16, 17, 18]),
    DecryptedValue =
        digit_list_to_number(36, [33, 11, 19, 3, 20, 31, 3, 5, 19, 27, 10, 32,
                                  33, 31, 3, 2, 34, 28, 27]),
    run_encryptdecrypt_test_(Config, EncryptedValue, DecryptedValue).
-endif.

-spec ff1_sample7_aes256_test() -> ok.
ff1_sample7_aes256_test() ->
    Config =
        config(<<16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94
                 :32/big-unsigned-integer-unit:8>>,
               10),
    run_encryptdecrypt_test_(Config, 123456789, 6657667009).

-spec ff1_sample8_aes256_test() -> ok.
ff1_sample8_aes256_test() ->
    Config =
        config(<<16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94
                 :32/big-unsigned-integer-unit:8>>,
               10,
               #{ tweak => <<16#39383736353433323130:10/big-unsigned-integer-unit:8>> }),
    run_encryptdecrypt_test_(Config, 123456789, 1001623463).

-spec ff1_sample9_aes256_test() -> ok.
ff1_sample9_aes256_test() ->
    Config =
        config(<<16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94
                 :32/big-unsigned-integer-unit:8>>,
               19,
               #{ tweak => <<16#3737373770717273373737:11/big-unsigned-integer-unit:8>>,
                  radix => 36 }),
    EncryptedValue =
        digit_list_to_number(36, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                                  10, 11, 12, 13, 14, 15, 16, 17, 18]),
    DecryptedValue =
        digit_list_to_number(36, [33, 28, 8, 10, 0, 10, 35, 17, 2, 10,
                                  31, 34, 10, 21, 34, 35, 30, 32, 13]),
    run_encryptdecrypt_test_(Config, EncryptedValue, DecryptedValue).

-endif.
