#!/usr/bin/env bash
# Run PatchProof against a throwaway C target.
#
#   bash examples/demo/run.sh              # regression patch -> expected exit 20
#   bash examples/demo/run.sh --correct    # correct patch    -> expected exit 0
#
# KEEP_DEMO=1 keeps the temporary repo and report for inspection.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MODE="${1:-}"

case "$MODE" in
  ""|"--regression")
    EXPECTED=20
    PATCHED_SOURCE="$HERE/patched/app.c"
    ;;
  "--correct")
    EXPECTED=0
    PATCHED_SOURCE="$HERE/base/app.c"
    ;;
  *)
    echo "usage: $0 [--correct|--regression]" >&2
    exit 2
    ;;
esac

TMP="$(mktemp -d)"
cleanup() {
  if [ "${KEEP_DEMO:-0}" = "1" ]; then
    echo "kept demo directory: $TMP"
  else
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT

REPO="$TMP/repo"
git init -q -b main "$REPO"
git -C "$REPO" config user.name "PatchProof Demo"
git -C "$REPO" config user.email "demo@patchproof.local"

cp "$HERE/base/app.c" "$REPO/app.c"
git -C "$REPO" add app.c
git -C "$REPO" commit -q -m "base"
git -C "$REPO" tag base

cp "$PATCHED_SOURCE" "$REPO/app.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q --allow-empty -m "patched"
git -C "$REPO" tag patched

mkdir -p "$TMP/config/inputs"
cp "$HERE/inputs/"*.txt "$TMP/config/inputs/"

cat > "$TMP/config/patchproof.toml" <<EOF
[target]
name = "demo"
repo = "$REPO"
base_ref = "base"
patched_ref = "patched"

[build]
command = ["cc", "-O0", "-g", "-o", "app", "app.c"]
binary = "app"

[build.sanitized]
command = ["cc", "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-o", "app-asan", "app.c"]
binary = "app-asan"

[run]
timeout_seconds = 5
memory_mb = 256
cpu_seconds = 5
file_size_mb = 16

[[tests]]
id = "valid-positive"
kind = "functional"
input_mode = "stdin"
input = "inputs/positive.txt"
expect_exit = 0
stdout_contains = "OK 7"

[[tests]]
id = "valid-zero"
kind = "boundary"
input_mode = "stdin"
input = "inputs/zero.txt"
expect_exit = 0
stdout_contains = "OK 0"

[[tests]]
id = "invalid-text"
kind = "invalid"
input_mode = "stdin"
input = "inputs/text.txt"
expect_exit = 1
stderr_contains = "invalid input"
EOF

cd "$ROOT"
set +e
PYTHONPATH="$ROOT" python3 -m patchproof run \
  -c "$TMP/config/patchproof.toml" \
  -o "$TMP/out" \
  -v
CODE=$?
set -e

if [ "$CODE" -ne "$EXPECTED" ]; then
  echo "FAIL: expected exit $EXPECTED, got $CODE" >&2
  exit 1
fi

echo "PASS: exit $CODE as expected"
