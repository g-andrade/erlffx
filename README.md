

# erlffx #

Copyright (c) 2017 Guilherme Andrade

__Version:__ 1.0.2

__Authors:__ Guilherme Andrade ([`erlffx(at)gandrade(dot)net`](mailto:erlffx(at)gandrade(dot)net)).

`erlffx`: Format Preserving Encryption - FFX for Erlang


---------

`erlffx` is an Erlang implementation of the mechanism described in the 2010 paper [The FFX Mode of Operation for Format-Preserving Encryption](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.304.1736&rep=rep1&type=pdf) by Bellare, Rogaway and Spies. It is based on an existing [Java implementation](https://github.com/michaeltandy/java-ffx-format-preserving-encryption) by Michael Tandy.

* AES-128 / AES-192 (only Erlang 19 and up) / AES-256 keys are supported (CBC mode)
* Any positive word length is supported
* Any radix / alphabet size between 2 and 255 is acceptable (10 by default)
* Optional 'tweak' values may be defined
* Number of rounds is configurable (10 by default)

The code was successfully tested on generations 17, 18 and 19 of Erlang/OTP; the unit tests themselves were written using the following lists of test vectors:
* [AES FFX Test Vector Data](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt)
* [FF1 samples](http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF1samples.pdf)


### <a name="Examples">Examples</a> ###


```erlang

% AES-128 CBC / 10-digit decimal words
AesKey = <<43,126,21,22,40,174,210,166,171,247,21,136,9,207,79,60>>,
ValueLength = 10,
Config = erlffx:config(AesKey, ValueLength).

Encrypted = erlffx:encrypt(Config, 123456789). % 2433477484
Decrypted = erlffx:decrypt(Config, Encrypted). % 123456789

```

---------

```erlang

% AES-128 CBC / 10-digit decimal words / custom tweak
AesKey = <<43,126,21,22,40,174,210,166,171,247,21,136,9,207,79,60>>,
ValueLength = 10,
Config = erlffx:config(AesKey, ValueLength, #{ tweak => "9876543210" }).

Encrypted = erlffx:encrypt(Config, 123456789). % 6124200773
Decrypted = erlffx:decrypt(Config, Encrypted). % 123456789

```

---------

```erlang

% AES-128 CBC / 16-digit base-36 words / custom tweak
AesKey = <<43,126,21,22,40,174,210,166,171,247,21,136,9,207,79,60>>,
ValueLength = 16,
Config = erlffx:config(AesKey, ValueLength, #{ tweak => "TQF9J5QDAGSCSPB1", radix => 36 }).

Encrypted = erlffx:encrypt(Config, 36#C4XPWULBM3M863JH). % 36#C8AQ3U846ZWH6QZP
Decrypted = erlffx:decrypt(Config, Encrypted).           % 36#C4XPWULBM3M863JH

```

---------

```erlang

% AES-256 CBC / 6-digit binary words
AesKey = <<43,126,21,22,40,174,210,166,171,247,21,136,9,207,79,60,
           239,67,89,216,213,128,170,79,127,3,109,111,4,252,106,148>>,
ValueLength = 6,
Config = erlffx:config(AesKey, ValueLength, #{ radix => 2 }).

Encrypted = erlffx:encrypt(Config, 2#000001).  % 2#100100
Decrypted = erlffx:decrypt(Config, Encrypted). % 2#000001

```


## Modules ##


<table width="100%" border="0" summary="list of modules">
<tr><td><a href="https://github.com/g-andrade/erlffx/blob/master/doc/erlffx.md" class="module">erlffx</a></td></tr></table>

