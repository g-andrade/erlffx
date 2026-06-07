-module(erlffx_tests).

-include_lib("eunit/include/eunit.hrl").

%% ------------------------------------------------------------------
%% Test Helpers
%% ------------------------------------------------------------------

run_encryptdecrypt_test_(Config, Value, ExpectedEncryptedValue) ->
    EncryptedValue = erlffx:encrypt(Config, Value),
    ?assertEqual(EncryptedValue, ExpectedEncryptedValue),
    DecryptedValue = erlffx:decrypt(Config, EncryptedValue),
    ?assertEqual(DecryptedValue, Value).

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
