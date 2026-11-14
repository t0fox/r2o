#!/bin/sh
# M4: paired C/Rust differential d2kvoice --list vs r2o --voice-list.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}
FIXTURE="$ROOT/scripts/fixtures/voice_conntrack.txt"

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-m4-voice-list.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
: >"$TEMP/empty.txt"

make -s -B -C "$D2O_ROOT/core" d2kvoice CC="$CC" >/dev/null
D2O_VOICE="$D2O_ROOT/core/d2kvoice"

run_case() {
    name=$1
    file=$2
    set +e
    "$D2O_VOICE" --list --conntrack "$file" >"$TEMP/c-$name.out" 2>"$TEMP/c-$name.err"
    c_status=$?
    "$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -q -p r2o-controller --bin r2o-controller -- \
        --voice-list --conntrack "$file" >"$TEMP/r-$name.out" 2>"$TEMP/r-$name.err"
    r_status=$?
    set -e
    if [ "$c_status" != "$r_status" ]; then
        printf 'FAIL: %s exit C=%s Rust=%s\n' "$name" "$c_status" "$r_status" >&2
        printf 'C stderr: '; cat "$TEMP/c-$name.err" >&2
        printf 'Rust stderr: '; cat "$TEMP/r-$name.err" >&2
        return 1
    fi
    if ! diff -u "$TEMP/c-$name.out" "$TEMP/r-$name.out"; then
        printf 'FAIL: %s output\n' "$name" >&2
        return 1
    fi
}

run_case list "$FIXTURE"
run_case empty "$TEMP/empty.txt"

run_list_extra() {
    name=$1
    shift
    set +e
    "$D2O_VOICE" --list "$@" >"$TEMP/c-$name.out" 2>"$TEMP/c-$name.err"
    c_status=$?
    "$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -q -p r2o-controller --bin r2o-controller -- \
        --voice-list "$@" >"$TEMP/r-$name.out" 2>"$TEMP/r-$name.err"
    r_status=$?
    set -e
    if [ "$c_status" != "$r_status" ]; then
        printf 'FAIL: %s exit C=%s Rust=%s\n' "$name" "$c_status" "$r_status" >&2
        return 1
    fi
    if ! diff -u "$TEMP/c-$name.out" "$TEMP/r-$name.out"; then
        printf 'FAIL: %s output\n' "$name" >&2
        return 1
    fi
}

# C `--list` принимает весь набор флагов и игнорирует всё, кроме --conntrack.
run_list_extra list_wait_zero --wait 0 --mark 0x2d --control 127.0.0.1:9 \
    --conntrack "$FIXTURE"
run_list_extra list_addr --addr 1.2.3.4:9 --conntrack "$FIXTURE"
run_list_extra list_unknown --bogus
run_list_extra list_missing --conntrack

# Алиас `--list` у r2o-controller ведёт себя как d2kvoice --list.
set +e
"$D2O_VOICE" --list --conntrack "$FIXTURE" >"$TEMP/c-alias.out" 2>"$TEMP/c-alias.err"
c_status=$?
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --bin r2o-controller -- \
    --list --conntrack "$FIXTURE" >"$TEMP/r-alias.out" 2>"$TEMP/r-alias.err"
r_status=$?
set -e
if [ "$c_status" != "$r_status" ] || ! diff -u "$TEMP/c-alias.out" "$TEMP/r-alias.out"; then
    printf 'FAIL: alias --list\n' >&2
    exit 1
fi

run_measure() {
    name=$1
    shift
    set +e
    "$D2O_VOICE" --conntrack "$TEMP/empty.txt" "$@" >"$TEMP/c-$name.out" 2>"$TEMP/c-$name.err"
    c_status=$?
    "$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -q -p r2o-controller --bin r2o-controller -- \
        --voice-check --conntrack "$TEMP/empty.txt" "$@" >"$TEMP/r-$name.out" 2>"$TEMP/r-$name.err"
    r_status=$?
    set -e
    if [ "$c_status" != "$r_status" ]; then
        printf 'FAIL: %s exit C=%s Rust=%s\n' "$name" "$c_status" "$r_status" >&2
        printf 'C stdout: '; cat "$TEMP/c-$name.out" >&2
        printf 'Rust stdout: '; cat "$TEMP/r-$name.out" >&2
        return 1
    fi
    if ! diff -u "$TEMP/c-$name.out" "$TEMP/r-$name.out"; then
        printf 'FAIL: %s output\n' "$name" >&2
        return 1
    fi
}

run_measure measure_no_call
run_measure measure_wait_zero --wait 0

printf 'cases=9\n'
cat "$TEMP/c-list.out"
printf 'PASS: C/Rust voice list matches (D2O %s)\n' "$ACTUAL_D2O_SHA"
