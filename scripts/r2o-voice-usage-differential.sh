#!/bin/sh
# C/Rust differential: usage/flag set d2kvoice vs r2o-controller voice commands.
# Сравниваем набор флагов и exit при неверном аргументе; точный текст
# (defaults/формулировки) осознанно не сравнивается.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CC=${CC:-cc}
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-voice-usage.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -s -B -C "$DONOR/core" d2kvoice CC="$CC" >/dev/null
cargo build --manifest-path "$ROOT/Cargo.toml" --locked -p r2o-controller \
    --bin r2o-controller >/dev/null
R2O="$ROOT/target/debug/r2o-controller"
D2O_VOICE="$DONOR/core/d2kvoice"

set +e
"$D2O_VOICE" --bogus >"$TEMP/c.out" 2>"$TEMP/c.err"
c_status=$?
"$R2O" --voice-check --bogus >"$TEMP/r1.out" 2>"$TEMP/r1.err"
r1_status=$?
"$R2O" --voice-list --bogus >"$TEMP/r2.out" 2>"$TEMP/r2.err"
r2_status=$?
set -e

[ "$c_status" -eq 2 ] && [ "$r1_status" -eq 2 ] && [ "$r2_status" -eq 2 ] || {
    printf 'FAIL: exit C=%s Rust-check=%s Rust-list=%s\n' \
        "$c_status" "$r1_status" "$r2_status" >&2
    exit 1
}

normalize() {
    grep -v -E -- '--bogus|неизвест|unknown' "$1" | awk '{
        while (match($0, /--[a-z-]+/)) {
            print substr($0, RSTART, RLENGTH);
            $0 = substr($0, RSTART + RLENGTH);
        }
    }' | grep -v -E '^--voice(-check|-list)?$' | sort -u
}
{
    normalize "$TEMP/c.err"
} >"$TEMP/c.flags"
{
    normalize "$TEMP/r1.err"
    normalize "$TEMP/r2.err"
} | sort -u >"$TEMP/r.flags"

if ! diff -u "$TEMP/c.flags" "$TEMP/r.flags"; then
    printf 'FAIL: voice usage flag sets differ\n' >&2
    exit 1
fi
cat "$TEMP/c.flags"
printf 'PASS: voice usage flag set and exit match C (%s)\n' "$ACTUAL_SHA"
