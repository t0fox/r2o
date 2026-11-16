#!/bin/sh
# C/Rust differential: production on_suspect (sched.c:8181-8592).
# Коды SUSPECT 1..8, planned/no-plan/has-solution/covering, повторный SUSPECT
# (hot_event), мёртвый адрес и отсрочка. Код 7 — QUIC-ветвь C; Rust legacy
# строит цель только по TCP HELLO, поэтому code7_* остаётся C-эталоном.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-a378}
EXPECTED_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD 2>/dev/null ||
    cat /mnt/e/d2o/.git/worktrees/d2o-a378/HEAD 2>/dev/null || true)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CC=${CC:-cc}
CORE="$DONOR/core"
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-suspect-codes.XXXXXX")
[ "${R2O_KEEP_TEMP:-0}" = 1 ] || trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -s -C "$CORE" test_sched CC="$CC" >/dev/null
SCHED_OBJECTS=$(make -s -C "$CORE" CC="$CC" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$CORE"
    "$CC" -std=gnu11 -O2 -Wall -Wextra -ffunction-sections -fdata-sections \
        -I. -Iinclude -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
        -DD2K_RELEASE_ID='"dev"' \
        "$ROOT/crates/r2o-controller/tests/d2o_on_suspect_codes_differential.c" \
        $SCHED_OBJECTS .udp-engine/udpplan.o .udp-engine/udpruntime.o \
        diagnostics.o libd2k_udp.a \
        -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"
)
"$TEMP/c" >"$TEMP/c.all"
grep -v '^code7_' "$TEMP/c.all" >"$TEMP/c.out"
grep '^code7_' "$TEMP/c.all" >"$TEMP/c.code7" || true

R2O_ON_SUSPECT_CODES_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    on_suspect_codes_matrix_matches_c >"$TEMP/rust.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'PASS: on_suspect codes 1-6,8 and gate order match C %s.\n' "$ACTUAL_SHA"
printf 'C-only QUIC code 7 reference lines: %s\n' \
    "$(wc -l <"$TEMP/c.code7" | tr -d ' ')"
