# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- support for OTP 25, 26, 27, 28 and 29
- `ex_doc`-based documentation with EEP-48 (`-moduledoc`/`-doc`) attributes
- dev tooling: `erlfmt`, `rebar3_hank` and `elvis` (via `rebar3_lint`)

### Changed

- CI to GitHub Actions with an OTP 24-29 matrix (replacing the container build)
- build system to the current rebar3-based Makefile / `rebar.config`

### Removed

- the semi-archival/maintenance notice (the library is maintained again)
- the `edown` + `pandoc` README-generation pipeline (README is now hand-written)

## [1.2.0] - 2021-05-13

### Added

- support for OTP 24
- Hex.pm and CI badges to the README

### Removed

- support for OTP 19, 20 and 21
- the legacy approach to generating documentation

## [1.1.1] - 2021-02-27

### Changed

- CI from Travis to GitHub Actions

### Fixed

- a crash when publishing the package to Hex

## [1.1.0] - 2020-05-14

### Added

- support for OTP 22 and 23

### Removed

- support for OTP 17 and 18

## [1.0.3] - 2019-03-16

### Added

- OTP 21.3 to the tested targets

### Fixed

- Dialyzer `underspecs` warnings

## [1.0.2] - 2019-01-19

### Added

- a link to the GitLab mirror in the Hex package metadata
- OTP 21.2 to the tested targets

## [1.0.1] - 2018-06-20

### Fixed

- compatibility with OTP 20 and 21

## [1.0.0] - 2017-04-30

### Added

- initial release: FFX format-preserving encryption with `config/2`,
  `config/3`, `encrypt/2` and `decrypt/2`
- AES-128 / AES-192 / AES-256 keys (CBC mode)
- any positive word length, any radix between 2 and 255 (10 by default),
  optional tweak values, and a configurable number of rounds (10 by default)
