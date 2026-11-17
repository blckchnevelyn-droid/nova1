#!/usr/bin/env bash
# Model-check the pilot lifecycle and the two planted-bug mutants. Requires Java and the pinned TLC jar.
set -euo pipefail
JAR="${TLA2TOOLS_JAR:-/tmp/tla2tools.jar}"
TLC_URL="https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar"
TLC_SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
if [ ! -f "$JAR" ]; then curl -sSL -o "$JAR" "$TLC_URL"; fi
echo "${TLC_SHA256}  ${JAR}" | sha256sum -c -
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
echo "== clean model: all invariants must hold =="
java -cp "$JAR" tlc2.TLC -deadlock -nowarning FileWritePilot.tla -config FileWritePilot.cfg | tee results-clean.txt
grep -q "No error has been found" results-clean.txt
echo "== mutants: each must be caught =="
TMP="$(mktemp -d)"; cp FileWritePilot.cfg "$TMP/"
for m in MutA MutB; do
  cp "mutants/$m.tla" "$TMP/FileWritePilot.tla"
  if java -cp "$JAR" tlc2.TLC -deadlock -nowarning "$TMP/FileWritePilot.tla" -config "$TMP/FileWritePilot.cfg" > "results-$m.txt" 2>&1; then
    echo "mutant $m was NOT caught"; exit 1
  fi
  grep -q "is violated" "results-$m.txt" && echo "mutant $m caught" 
done
rm -rf "$TMP"
