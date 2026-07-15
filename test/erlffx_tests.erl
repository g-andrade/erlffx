-module(erlffx_tests).

-include_lib("eunit/include/eunit.hrl").

%% ------------------------------------------------------------------
%% Test Helpers
%% ------------------------------------------------------------------

run_encryptdecrypt_test_(Config, Value, ExpectedEncryptedValue) ->
    EncryptedValue = erlffx:encrypt(Config, Value),
    ?assertEqual(ExpectedEncryptedValue, EncryptedValue),
    DecryptedValue = erlffx:decrypt(Config, EncryptedValue),
    ?assertEqual(Value, DecryptedValue).

common_testing_aes128_key() ->
    <<(16#2b7e151628aed2a6abf7158809cf4f3c):16/big-unsigned-integer-unit:8>>.

digit_list_in_radix(Radix, Digits) ->
    lists:map(
        fun(Digit) when Digit < Radix ->
            [EncodedDigit] = integer_to_list(Digit, Radix),
            EncodedDigit
        end,
        Digits
    ).

digit_list_to_number(_Radix, []) ->
    0;
digit_list_to_number(Radix, Digits) ->
    EncodedDigits = digit_list_in_radix(Radix, Digits),
    list_to_integer(EncodedDigits, Radix).

%% ------------------------------------------------------------------
%% AES FFX Test Vector Data
%% http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
%% ------------------------------------------------------------------

aes_ffx_vector1_test() ->
    Config =
        erlffx:config(
            common_testing_aes128_key(),
            10,
            #{tweak => "9876543210"}
        ),
    run_encryptdecrypt_test_(Config, 123456789, 6124200773).

aes_ffx_vector2_test() ->
    Config = erlffx:config(common_testing_aes128_key(), 10),
    run_encryptdecrypt_test_(Config, 123456789, 2433477484).

aes_ffx_vector3_test() ->
    Config =
        erlffx:config(
            common_testing_aes128_key(),
            6,
            #{tweak => "2718281828"}
        ),
    run_encryptdecrypt_test_(Config, 314159, 535005).

aes_ffx_vector4_test() ->
    Config =
        erlffx:config(
            common_testing_aes128_key(),
            9,
            #{tweak => "7777777"}
        ),
    run_encryptdecrypt_test_(Config, 999999999, 658229573).

aes_ffx_vector5_test() ->
    Config =
        erlffx:config(
            common_testing_aes128_key(),
            16,
            #{
                tweak => "TQF9J5QDAGSCSPB1",
                radix => 36
            }
        ),
    run_encryptdecrypt_test_(Config, 36#C4XPWULBM3M863JH, 36#C8AQ3U846ZWH6QZP).

%% ------------------------------------------------------------------
%% FF1 samples
%% http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF1samples.pdf
%% ------------------------------------------------------------------

ff1_sample3_aes128_test() ->
    Config =
        erlffx:config(
            common_testing_aes128_key(),
            19,
            #{
                tweak =>
                    <<16#37, 16#37, 16#37, 16#37, 16#70, 16#71, 16#72, 16#73, 16#37, 16#37, 16#37>>,
                radix => 36
            }
        ),
    EncryptedValue =
        digit_list_to_number(36, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]),
    DecryptedValue =
        digit_list_to_number(36, [
            10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22
        ]),
    run_encryptdecrypt_test_(Config, EncryptedValue, DecryptedValue).

ff1_sample4_aes192_test() ->
    Config =
        erlffx:config(
            <<16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F:24/big-unsigned-integer-unit:8>>,
            10
        ),
    run_encryptdecrypt_test_(Config, 123456789, 2830668132).

ff1_sample5_aes192_test() ->
    Config =
        erlffx:config(
            <<16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F:24/big-unsigned-integer-unit:8>>,
            10,
            #{tweak => <<16#39383736353433323130:10/big-unsigned-integer-unit:8>>}
        ),
    run_encryptdecrypt_test_(Config, 123456789, 2496655549).

ff1_sample6_aes192_test() ->
    Config =
        erlffx:config(
            <<16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F:24/big-unsigned-integer-unit:8>>,
            19,
            #{
                tweak => <<16#3737373770717273373737:11/big-unsigned-integer-unit:8>>,
                radix => 36
            }
        ),
    EncryptedValue =
        digit_list_to_number(36, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]),
    DecryptedValue =
        digit_list_to_number(36, [
            33, 11, 19, 3, 20, 31, 3, 5, 19, 27, 10, 32, 33, 31, 3, 2, 34, 28, 27
        ]),
    run_encryptdecrypt_test_(Config, EncryptedValue, DecryptedValue).

ff1_sample7_aes256_test() ->
    Config =
        erlffx:config(
            <<
                16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94:32/big-unsigned-integer-unit:8
            >>,
            10
        ),
    run_encryptdecrypt_test_(Config, 123456789, 6657667009).

ff1_sample8_aes256_test() ->
    Config =
        erlffx:config(
            <<
                16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94:32/big-unsigned-integer-unit:8
            >>,
            10,
            #{tweak => <<16#39383736353433323130:10/big-unsigned-integer-unit:8>>}
        ),
    run_encryptdecrypt_test_(Config, 123456789, 1001623463).

ff1_sample9_aes256_test() ->
    Config =
        erlffx:config(
            <<
                16#2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94:32/big-unsigned-integer-unit:8
            >>,
            19,
            #{
                tweak => <<16#3737373770717273373737:11/big-unsigned-integer-unit:8>>,
                radix => 36
            }
        ),
    EncryptedValue =
        digit_list_to_number(36, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]),
    DecryptedValue =
        digit_list_to_number(36, [
            33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13
        ]),
    run_encryptdecrypt_test_(Config, EncryptedValue, DecryptedValue).

%% ------------------------------------------------------------------
%% Others
%% ------------------------------------------------------------------

large_s_block_test() ->
    %
    % Ensures coverage of the recursive `compute_s_blocks` case
    %
    AesKey =
        <<121, 94, 3, 182, 203, 31, 247, 3, 116, 127, 231, 162, 173, 64, 161, 96, 122, 135, 89, 177,
            94, 111, 98, 99, 43, 40, 1, 140, 9, 46, 242, 73>>,

    Radix = 1166,
    ValueLength = 42,
    Tweak = "",

    Config =
        erlffx:config(
            AesKey,
            ValueLength,
            #{radix => Radix, tweak => Tweak}
        ),

    Value = 1,
    Encrypted = erlffx:encrypt(Config, Value),
    Decrypted = erlffx:decrypt(Config, Encrypted),

    ?assertEqual(1, Decrypted).

random_cases_test() ->
    MaxValue = 1 bsl 600,

    lists:foreach(
        fun(_) ->
            Key = random_key(),
            Radix = random_radix(),

            MaxValueLength = floor(math:log(MaxValue) / math:log(Radix)),
            ValueLength = rand:uniform(MaxValueLength),

            Value = rand:uniform(int_pow(Radix, ValueLength)) - 1,
            ?assertMatch(_ when Value >= 0 andalso Value < MaxValue, Value),

            Tweak = random_tweak(),

            Config = erlffx:config(Key, ValueLength, #{
                radix => Radix, tweak => Tweak, value_length => ValueLength
            }),

            EncryptedValue = erlffx:encrypt(Config, Value),
            DecryptedValue = erlffx:decrypt(Config, EncryptedValue),

            % logger:notice("Key size ~p", [byte_size(Key)]),
            % logger:notice("Radix ~p", [Radix]),
            % logger:notice("TweakLength ~p", [byte_size(Tweak)]),
            % logger:notice("ValueLength ~p", [ValueLength]),
            % logger:notice("EncryptedValue ~p", [EncryptedValue]),
            % logger:notice("DecryptedValue ~p", [DecryptedValue]),
            % logger:notice("------------"),

            ?assertEqual(Value, DecryptedValue)
        end,
        lists:seq(1, 1000)
    ).

random_key() ->
    case rand:uniform(3) of
        1 ->
            crypto:strong_rand_bytes(16);
        %
        2 ->
            crypto:strong_rand_bytes(24);
        %
        3 ->
            crypto:strong_rand_bytes(32)
    end.

random_radix() ->
    case rand:uniform(5) of
        1 ->
            1 + rand:uniform(99);
        %
        2 ->
            100 + rand:uniform(900);
        %
        3 ->
            1000 + rand:uniform(9000);
        %
        4 ->
            10000 + rand:uniform(30000);
        %
        5 ->
            30000 + rand:uniform(35535 - 1)
    end.

random_tweak() ->
    case rand:uniform(4) of
        1 ->
            <<>>;
        %
        _ ->
            Length = rand:uniform(50) - 1,
            crypto:strong_rand_bytes(Length)
    end.

int_pow(Base, Exp) when Exp > 0 ->
    Base * int_pow(Base, Exp - 1);
int_pow(_, 0) ->
    1.
