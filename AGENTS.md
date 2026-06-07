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
`warnings_as_errors`. Every function (including internal helpers) carries a
`-spec`. The `test` profile relaxes `warn_missing_spec` and
`warnings_as_errors`.

## Architecture

There is one module, `erlffx`, with a four-function public API:

| Function | Role |
|---|---|
| `config/2`, `config/3` | Build an opaque `config()` from an AES key + word length (+ optional `tweak`, `radix`, `number_of_rounds`) |
| `encrypt/2` | Encipher a non-negative integer under a `config()` |
| `decrypt/2` | Reverse `encrypt/2` |

Internally: `config/3` merges params into a `raw_config()` map and validates it
into the opaque `config()` (mandatory keys). `encrypt`/`decrypt` run the
alternating Feistel network (`encrypt_loop`/`decrypt_loop`); each round's PRF
`fk/4` builds the FFX `P`/`Q` blocks and runs AES-CBC-MAC (`aes_cbc_mac/2` →
`aes_cbc/3`). Integers are carried as `maginteger()` `{Value, Magnitude}` pairs.

## Conventions and gotchas

- **OTP-version gating** (`rebar.config.script`): `erlfmt`, `rebar3_hank` and
  `rebar3_lint` are dropped on OTP ≤ 25; `erlfmt` alone is also dropped on OTP
  26 (its `-doc` triple-quoted-string handling is broken there); `rebar3_hank`
  is dropped on OTP 29 (katana_code bug). So `make check-fast` is a partial
  no-op on those OTP releases — develop/lint on OTP 27+ (28 is the reference).
- **Crypto API split**: `aes_cbc/3` uses `crypto:crypto_one_time/5` on OTP ≥ 23
  and the removed `crypto:block_encrypt/4` on OTP 22, selected by the
  `POST_OTP_22` `platform_define`. `minimum_otp_vsn` is `22.0` but only **24+**
  is supported.
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
- **dialyzer** runs with `underspecs` on. Keep specs tight: the P value is
  `<<_:128>>`, magnitudes are `pos_integer()`, the opaque `config()` uses
  mandatory (`:=`) keys, and the AES key/CBC data flow is typed over binaries
  (`validate_aes_key/1` normalizes any `iodata()` key to a binary).

## Tests

`test/erlffx_tests.erl` — eunit known-answer vectors from the NIST AES-FFX
test-vector data and the FF1 sample document (AES-128/192/256, radix 10 and 36,
with and without tweaks). There are no Common Test suites, so `make ct` reports
zero tests.

## Releasing

`make publish` runs `rebar3 hex publish --doc-dir=doc`. Versioning is SemVer;
history is in `CHANGELOG.md` (Keep a Changelog format).
