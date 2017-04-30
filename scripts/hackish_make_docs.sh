#!/usr/bin/env bash

# sigh.....
rebar3 as generate_documentation compile
mkdir -p _build/generate_documentation/lib/erlffx/doc/
cp -p overview.edoc _build/generate_documentation/lib/erlffx/doc/
erl -pa _build/generate_documentation/lib/*/ebin -noshell -run edoc_run application "erlffx"
erl -pa _build/generate_documentation/lib/*/ebin -noshell -run edoc_run application "erlffx" '[{doclet, edown_doclet}, {top_level_readme, {"README.md", "https://github.com/g-andrade/erlffx", "master"}}]'
rm -rf doc
mv _build/generate_documentation/lib/erlffx/doc ./
sed -i -e 's/^\(---------\)$/\n\1/g' README.md
