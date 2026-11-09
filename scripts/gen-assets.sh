#!/bin/sh
# Generate man page and shell completions into target/assets (used by cargo-deb and releases).
set -eu
BIN="${1:-target/release/ndo4git}"
OUT="${2:-target/assets}"
mkdir -p "$OUT"
"$BIN" man > "$OUT/ndo4git.1"
"$BIN" completions bash > "$OUT/ndo4git.bash"
"$BIN" completions zsh > "$OUT/_ndo4git"
"$BIN" completions fish > "$OUT/ndo4git.fish"
echo "assets written to $OUT"
