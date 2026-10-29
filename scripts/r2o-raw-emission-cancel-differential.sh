#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

donor_detect="$donor_root/detect"
donor_core="$donor_root/core"
donor_datapath="$donor_root/datapath"
cc=${CC:-cc}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-d2o-raw-emission.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

"$cc" -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor_detect" -I"$donor_detect/include" -I"$donor_core/include" \
    -I"$donor_datapath/include" \
    -o "$tmp_dir/d2o_raw_emission_cancel_fixture" \
    "$repo_root/crates/r2o-controller/tests/d2o_raw_emission_cancel_fixture.c" \
    "$donor_detect/poison.c" "$donor_detect/trigger.c" \
    "$donor_core/measured.c" "$donor_core/hello.c" "$donor_core/plantlv.c" \
    "$donor_core/quic.c" "$donor_core/quicwire.c" "$donor_core/crypto.c" \
    "$donor_datapath/plan_parse.c" "$donor_datapath/plan_apply.c" \
    "$donor_datapath/wire.c" -Wl,--gc-sections -lpthread
"$tmp_dir/d2o_raw_emission_cancel_fixture" >"$tmp_dir/c.out"

R2O_RAW_EMISSION_C_OUTPUT="$tmp_dir/c.out" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/r2o-target}" \
    cargo +1.98.0 test -p r2o-controller --locked --offline --lib \
        measured_emission_finishes_an_started_gap_before_observing_cancellation \
        -- --nocapture >"$tmp_dir/rust.out" 2>&1 || {
        cat "$tmp_dir/c.out"
        cat "$tmp_dir/rust.out"
        exit 1
    }

c_row=$(sed -n '/^RAW_EMISSION_CANCEL /p' "$tmp_dir/c.out")
rust_row=$(sed -n '/^RAW_EMISSION_CANCEL /p' "$tmp_dir/rust.out")
if [ "$c_row" != "$rust_row" ]; then
    printf 'C: %s\nRust: %s\n' "$c_row" "$rust_row" >&2
    exit 1
fi
printf '%s\nC/Rust raw emission cancellation matches d2o %s.\n' "$c_row" "$expected_donor_sha"
