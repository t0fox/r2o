#!/bin/sh
# C/Rust differential входов моста detect/bridge.c:
#   bridge_input, d2k_detect_stop_all/stop_asked, d2k_detect_sched_tcp_ack.
# C: production detect/bridge.c включается в фикстуру, лишние функции
#    выбрасываются -ffunction-sections/-Wl,--gc-sections.
# Rust: production r2o_bridge_input, r2o_detect_stop_all*,
#    r2o_detect_sched_tcp_ack_with.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_D2O_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-gcc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi
if ! git -C "$D2O_ROOT" diff --quiet HEAD -- \
    detect/bridge.c detect/classify.c detect/include/d2k_detect.h \
    core/hello.c core/include/d2k_meas.h; then
    printf 'D2O bridge sources have tracked changes\n' >&2
    exit 2
fi
for tool in "$CC" "$CARGO"; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing required command: %s\n' "$tool" >&2
        exit 127
    }
done

TEMP=$(mktemp -d "$TMPDIR/r2o-detect-bridge.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

if [ ! -f "$D2O_ROOT/core/hello_profiles.inc" ]; then
    make -s -C "$D2O_ROOT/core" hello_profiles.inc
fi

# Флаги передаются функцией, а не строкой: иначе кавычки для
# `-DR2O_BRIDGE_C="..."` теряются при разбиении (SC2089/SC2090).
bridge_cc() {
    "$CC" -std=c99 -O2 -Wall -Wextra -Werror -Wno-unused-function \
        -ffunction-sections -fdata-sections \
        -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/detect/include" \
        -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core" \
        -DR2O_BRIDGE_C="\"$D2O_ROOT/detect/bridge.c\"" \
        "$@"
}
bridge_cc \
    "$ROOT/crates/r2o-controller/tests/d2o_bridge_input_differential.c" \
    "$D2O_ROOT/core/hello.c" "$D2O_ROOT/detect/trigger.c" \
    -Wl,--gc-sections -o "$TEMP/input"
bridge_cc \
    "$ROOT/crates/r2o-controller/tests/d2o_bridge_ack_differential.c" \
    -Wl,--gc-sections -o "$TEMP/ack"
bridge_cc \
    "$ROOT/crates/r2o-controller/tests/d2o_bridge_stop_differential.c" \
    -Wl,--gc-sections -o "$TEMP/stop"

"$TEMP/input" >"$TEMP/input.c.out"
"$TEMP/ack" >"$TEMP/ack.c.out"
"$TEMP/stop" >"$TEMP/stop.c.out"

R2O_BRIDGE_INPUT_DIFF_OUTPUT="$TEMP/input.rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --test d2o_detect_bridge \
    bridge_input_products_match_the_c_fixture >"$TEMP/input.rust.log" 2>&1
R2O_BRIDGE_ACK_DIFF_OUTPUT="$TEMP/ack.rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --test d2o_detect_bridge \
    neutral_ack_hook_matches_the_c_codes >"$TEMP/ack.rust.log" 2>&1
R2O_BRIDGE_STOP_DIFF_OUTPUT="$TEMP/stop.rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --test d2o_detect_stop >"$TEMP/stop.rust.log" 2>&1

diff -u "$TEMP/input.c.out" "$TEMP/input.rust.out"
diff -u "$TEMP/ack.c.out" "$TEMP/ack.rust.out"
diff -u "$TEMP/stop.c.out" "$TEMP/stop.rust.out"
printf 'C/Rust detect bridge input/stop/ack matches d2o %s.\n' "$ACTUAL_D2O_SHA"
