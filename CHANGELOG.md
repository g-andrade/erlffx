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

## [1.1.1] - 2021-02-27

## [1.1.0] - 2020-05-14

## [1.0.3] - 2019-03-16

## [1.0.2] - 2019-01-19

## [1.0.1] - 2018-06-20

## [1.0.0] - 2017-04-30

[//]: # (Releases up to and including 1.2.0 predate this changelog; see the)
[//]: # (git tags and history for their details.)
