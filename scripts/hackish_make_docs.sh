#!/usr/bin/env bash

# sigh.....
sed -i -e 's/^\(\s*\)%{edown/\1{edown/g' -e 's/^\(\s*\)%{doclet, edown/\1{doclet, edown/g' rebar.config
rebar3 compile
mkdir -p _build/default//lib/erlffx/doc/
cp -p overview.edoc _build/default/lib/erlffx/doc/
erl -pa _build/default/lib/*/ebin -noshell -run edoc_run application "erlffx"
erl -pa _build/default/lib/*/ebin -noshell -run edoc_run application "erlffx" '[{doclet, edown_doclet}, {top_level_readme, {"README.md", "https://github.com/g-andrade/erlffx", "master"}}]'
rm -rf doc
mv _build/default/lib/erlffx/doc ./
sed -i -e 's/^\(\s*\){edown/\1%{edown/g' -e 's/^\(\s*\){doclet, edown/\1%{doclet, edown/g' rebar.config
sed -i -e 's/^\(---------\)$/\n\1/g' README.md
