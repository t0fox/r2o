#!/bin/sh
# CLI-контракт C d2kd/Rust r2o-datapath: apply-требования и предел copy-range.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CARGO=${CARGO:-cargo}
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

cargo build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --bin r2o-datapath >/dev/null
C_D2KD="$D2O_ROOT/datapath/d2kd"
RUST_D2KD="$ROOT/target/debug/r2o-datapath"
[ -x "$C_D2KD" ] || { printf 'нет %s\n' "$C_D2KD" >&2; exit 2; }

TEMP=$(mktemp -d "${TMPDIR:-${ROOT%/r2o}/r2o-tooling/tmp}/r2o-cli.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

run_reject() {
    name=$1
    c_phrase=$2
    rust_phrase=$3
    shift 3
    set +e
    "$C_D2KD" "$@" >"$TEMP/c.$name.out" 2>&1
    c_rc=$?
    "$RUST_D2KD" "$@" >"$TEMP/r.$name.out" 2>&1
    rust_rc=$?
    set -e
    if [ "$c_rc" -eq 0 ] || [ "$rust_rc" -eq 0 ]; then
        printf 'FAIL %s: c_rc=%s rust_rc=%s\n' "$name" "$c_rc" "$rust_rc" >&2
        exit 1
    fi
    grep -q "$c_phrase" "$TEMP/c.$name.out" || {
        printf 'FAIL %s: C не сказал «%s»\n' "$name" "$c_phrase" >&2
        cat "$TEMP/c.$name.out" >&2
        exit 1
    }
    grep -q "$rust_phrase" "$TEMP/r.$name.out" || {
        printf 'FAIL %s: Rust не сказал «%s»\n' "$name" "$rust_phrase" >&2
        cat "$TEMP/r.$name.out" >&2
        exit 1
    }
    printf '%s reject c=%s rust=%s\n' "$name" "$c_rc" "$rust_rc"
}

run_reject copy_range_1601 "64 до 1600" "64 до 1600" \
    --queue 65535 --copy-range 1601
run_reject apply_no_source "apply без --plan и без --control" \
    "apply без --plan и без --control" --queue 65535 --mode apply --mark 45
run_reject apply_no_mark "apply без --mark" "apply без --mark" \
    --queue 65535 --mode apply --control /tmp/r2o-cli.sock

printf 'cases=3\n'
printf 'PASS: C/Rust CLI apply/copy-range contract (D2O %s)\n' "$ACTUAL_D2O_SHA"
