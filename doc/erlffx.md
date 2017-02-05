

# Module erlffx #
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

<a name="types"></a>

## Data Types ##




### <a name="type-config">config()</a> ###


__abstract datatype__: `config()`




### <a name="type-optional_config_params">optional_config_params()</a> ###


<pre><code>
optional_config_params() = #{tweak =&gt; iodata(), radix =&gt; <a href="#type-radix">radix()</a>, number_of_rounds =&gt; non_neg_integer()}
</code></pre>




### <a name="type-radix">radix()</a> ###


<pre><code>
radix() = 2..255
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#config-2">config/2</a></td><td></td></tr><tr><td valign="top"><a href="#config-3">config/3</a></td><td></td></tr><tr><td valign="top"><a href="#decrypt-2">decrypt/2</a></td><td></td></tr><tr><td valign="top"><a href="#encrypt-2">encrypt/2</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="config-2"></a>

### config/2 ###

<pre><code>
config(AesKey, ValueLength) -&gt; Config
</code></pre>

<ul class="definitions"><li><code>AesKey = iodata()</code></li><li><code>ValueLength = pos_integer()</code></li><li><code>Config = <a href="#type-config">config()</a></code></li></ul>

<a name="config-3"></a>

### config/3 ###

<pre><code>
config(AesKey, ValueLength, OptionalParams) -&gt; Config
</code></pre>

<ul class="definitions"><li><code>AesKey = iodata()</code></li><li><code>ValueLength = pos_integer()</code></li><li><code>OptionalParams = <a href="#type-optional_config_params">optional_config_params()</a></code></li><li><code>Config = <a href="#type-config">config()</a></code></li></ul>

<a name="decrypt-2"></a>

### decrypt/2 ###

<pre><code>
decrypt(Config, EncryptedValue) -&gt; Value
</code></pre>

<ul class="definitions"><li><code>Config = <a href="#type-config">config()</a></code></li><li><code>EncryptedValue = non_neg_integer()</code></li><li><code>Value = non_neg_integer()</code></li></ul>

<a name="encrypt-2"></a>

### encrypt/2 ###

<pre><code>
encrypt(Config, Value) -&gt; EncryptedValue
</code></pre>

<ul class="definitions"><li><code>Config = <a href="#type-config">config()</a></code></li><li><code>Value = non_neg_integer()</code></li><li><code>EncryptedValue = non_neg_integer()</code></li></ul>

