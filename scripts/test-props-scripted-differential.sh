#!/bin/sh
# C/Rust differential: property local_err, md5-err и stop.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT}
EXPECTED_D2O_SHA=${R2O_EXPECTED_DONOR_SHA:-a378e230947ebfd011439e1cac0f1e994d883aae}
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-props-scripted.XXXXXX")
cleanup() {
    status=$?
    rm -rf -- "$TEMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$TEMP/core/profiles"
cp "$D2O_ROOT/core/profiles/modern.hex" "$D2O_ROOT/core/profiles/legacy.hex" \
    "$TEMP/core/profiles/"
make -s -C "$TEMP/core" -f "$D2O_ROOT/core/Makefile" hello_profiles.inc >/dev/null

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/detect" -I"$D2O_ROOT/detect/include" \
    -I"$D2O_ROOT/core/include" -I"$TEMP/core" \
    -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-props-scripted" \
    "$ROOT/crates/r2o-controller/tests/d2o_props_scripted_differential.c" \
    "$D2O_ROOT/detect/poison.c" "$D2O_ROOT/detect/trigger.c" \
    "$D2O_ROOT/detect/response.c" "$D2O_ROOT/detect/raw.c" \
    "$D2O_ROOT/core/measured.c" "$D2O_ROOT/core/hello.c" \
    "$D2O_ROOT/core/plantlv.c" "$D2O_ROOT/core/quic.c" \
    "$D2O_ROOT/core/quicwire.c" "$D2O_ROOT/core/crypto.c" \
    "$D2O_ROOT/datapath/plan_parse.c" "$D2O_ROOT/datapath/plan_apply.c" \
    "$D2O_ROOT/datapath/wire.c" -lpthread
"$TEMP/d2o-props-scripted" >"$TEMP/c.out"

R2O_PROPS_LOCAL_OUTPUT="$TEMP/local.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib \
    raw_probe::tests::scripted_property_local_error_does_not_change_props \
    -- --exact --test-threads=1 >"$TEMP/local.log" 2>&1
R2O_PROPS_MD5_OUTPUT="$TEMP/md5.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib \
    raw_probe::tests::scripted_md5_local_error_keeps_md5_in_sweep \
    -- --exact --test-threads=1 >"$TEMP/md5.log" 2>&1
R2O_PROPS_STOP_OUTPUT="$TEMP/stop.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib \
    raw_probe::tests::scripted_property_stop_does_not_run_extra_probes \
    -- --exact --test-threads=1 >"$TEMP/stop.log" 2>&1

cat "$TEMP/local.out" "$TEMP/md5.out" "$TEMP/stop.out" >"$TEMP/rust.out"
if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: property scripted differential\n' >&2
    exit 1
fi
cat "$TEMP/c.out"
printf 'PASS: C/Rust property local_err/md5/stop rows match (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
