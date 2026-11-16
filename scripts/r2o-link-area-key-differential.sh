#!/bin/sh
# C/Rust differential: полный кадр area-key (`send_area_key`, core/link.c).
# C-оракул — production `d2k_link_*_family`/`d2k_link_area_identified`;
# Rust — `encode_*` + `control_frame_with_area_id`.
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
CORE="$DONOR/core"
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-link-area-key.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$CORE" -I"$CORE/include" -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
    -DD2K_RELEASE_ID='"dev"' \
    "$ROOT/crates/r2o-controller/tests/d2o_link_area_key_differential.c" \
    "$CORE/link.c" "$CORE/quicsnap.c" "$CORE/quic.c" "$CORE/quicwire.c" "$CORE/crypto.c" \
    -Wl,--gc-sections -lpthread -o "$TEMP/c"

"$TEMP/c" >"$TEMP/c.out"
R2O_LINK_AREA_KEY_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --locked -p r2o-controller --bin r2o-controller \
    tests::link_area_key_frame_matches_c -- --exact >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'PASS: area-key frames match C (%s)\n' "$ACTUAL_SHA"
