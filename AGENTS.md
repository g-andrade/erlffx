# erlffx

Erlang/OTP library for **format-preserving encryption** via the FFX mode of
operation (Bellare, Rogaway & Spies, 2010). It enciphers a non-negative integer
into another integer of the same word length and radix, optionally under a
tweak, using AES-CBC as the underlying PRF. Single module, no dependencies, no
processes — pure functions.

## Build, test, check

```bash
make compile         # compile
make test            # eunit (+ ct, which has no suites here)
make check           # check-fast + check-slow
make check-fast      # format check (erlfmt) + xref + dead-code (hank) + lint (elvis)
make check-slow      # dialyzer
make format          # auto-format source with erlfmt
make eunit           # unit tests
make doc             # EEP-48 chunks (rebar3 edoc) + ex_doc HTML into ./doc
make shell           # interactive REPL
```

All checks run sequentially (`.NOTPARALLEL`). CI runs `make check-fast`,
`make test`, and `make check-slow` over OTP 24.3–29.0 on Linux.

## Compiler flags

Always on: `warn_export_vars`, `warn_missing_spec`, `warn_unused_import`,
`warnings_as_errors`. `warn_missing_spec` only requires specs on **exported**
functions, so the public API and the `validate_*` helpers are spec'd, but the
internal round/PRF helpers (`do_encdec/7`, `do_encrypt_rounds/5`, etc.) are not.
The `test` profile relaxes `warn_missing_spec` and `warnings_as_errors`.

## Architecture

There is one module, `erlffx`, with a four-function public API:

| Function | Role |
|---|---|
| `config/2`, `config/3` | Build an opaque `config()` from an AES key + word length (+ optional `tweak`, `radix`, `number_of_rounds`) |
| `encrypt/2` | Encipher a non-negative integer under a `config()` |
| `decrypt/2` | Reverse `encrypt/2` |

Internally: `config/3` merges params into a `raw_config()` map and validates it
into the opaque `config()` (mandatory keys). Both `encrypt/2` and `decrypt/2`
delegate to `do_encdec/7` (a `DoEncrypt` boolean picks the direction).
`setup_encdec_vars/6` derives the per-call parameters into an `#aux{}` record
(`u`/`v` halves, `small_b`, `d`, the `P` block, the `Q` zero-padding) and splits
the input integer into its `{A, B}` halves via `split_num_string_int/3`. The
Feistel network then runs as `do_encrypt_rounds/5` (rounds `0..NumberOfRounds-1`)
or `do_decrypt_rounds/4` (rounds counting back down to `-1`). Each round builds
the FFX `P || Q` blocks, computes `R = prf/2` (AES-CBC-MAC: `crypto_one_time/5`
in CBC mode, keeping the last 16 bytes), expands it to `S` with
`compute_s_blocks/3` (`R || CIPH(R⊕1) || …` using `ciph/2`, AES-ECB), and folds
`Y = NUM(S)` into the running half with `non_negative_rem/2` (addition when
encrypting, subtraction when decrypting) modulo `radix^m`. The result is
reconstructed as `FinalB + FinalA * radix^v`. Integers are plain Erlang
integers throughout — the earlier `maginteger()` `{Value, Magnitude}` pairs are
gone.

> **`non_negative_rem/2` gotcha:** it must fold the result fully into `[0, B)`
> via `((A rem B) + B) rem B`. A negative `A` that is an exact multiple of `B`
> makes `A rem B` zero, so the naïve `(A rem B) + B` wrongly returns `B` — which
> broke `decrypt/2` round-trips for the rare inputs where `B - Y` lands on an
> exact multiple of `radix^m`.

## Conventions and gotchas

- **OTP-version gating** (`rebar.config.script`): `erlfmt`, `rebar3_hank` and
  `rebar3_lint` are dropped on OTP ≤ 25; `erlfmt` alone is also dropped on OTP
  26 (its `-doc` triple-quoted-string handling is broken there); `rebar3_hank`
  is dropped on OTP 29 (katana_code bug). So `make check-fast` is a partial
  no-op on those OTP releases — develop/lint on OTP 27+ (28 is the reference).
- **Crypto**: `prf/2` and `ciph/2` call `crypto:crypto_one_time/5`
  unconditionally (no OTP 22 `crypto:block_encrypt/4` fallback anymore). The old
  `POST_OTP_22` `platform_define` is gone and `minimum_otp_vsn` is `24.0`, which
  matches what is actually supported.
- **Docs are EEP-48**, not edoc text. Public docs are `-moduledoc`/`-doc`
  triple-quoted attributes guarded by `-ifdef(E48).` (`E48` is defined on OTP
  27+). The internal helpers are simply unexported, so ex_doc omits them — no
  `@private`/`-doc false` is needed here.
- **Docs pipeline**: `make doc` runs `rebar3 edoc` (NOT `rebar3 as docs edoc`),
  which the top-level `edoc_opts` (`edoc_doclet_chunks` / `edoc_layout_chunks`,
  `{dir, "_build/docs/lib/erlffx/doc"}`) turn into EEP-48 chunks; the ex_doc
  escript (downloaded to `tmp/`) then renders `_build/docs/lib/erlffx/ebin`
  into `./doc` using `ex_doc.config`. There is no `docs` rebar3 profile.
- **Formatting**: `erlfmt` via `make format`; the bulk reformat commit is in
  `.git-blame-ignore-revs`. `make check-formatted` enforces it.
- **Documented lint exceptions** (`elvis.config`): the `test/**` group disables
  `dont_repeat_yourself` and `max_line_length` because the known-answer test
  vectors are intentionally repetitive and carry long literals (256-bit keys,
  digit lists). `src/` uses the default ruleset with no exceptions.
- **dialyzer** runs with `underspecs` on. Keep specs tight: the opaque
  `config()` uses mandatory (`:=`) keys, the `#aux{}` record fields are typed
  (`u`/`v` as `pos_integer()`, `radix()`, binaries for `p`/`q_zeros`), and the
  AES key flow is typed over binaries (`validate_aes_key/1` normalizes any
  `iodata()` key to a binary).

## Tests

`test/erlffx_tests.erl` — eunit known-answer vectors from the NIST AES-FFX
test-vector data and the FF1 sample document (AES-128/192/256, radix 10 and 36,
with and without tweaks). There are no Common Test suites, so `make ct` reports
zero tests.

## Releasing

`make publish` runs `rebar3 hex publish --doc-dir=doc`. Versioning is SemVer;
history is in `CHANGELOG.md` (Keep a Changelog format).
