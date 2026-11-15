#!/bin/sh
# C/Rust differential: on_exchange, ветвь d2k_ev_outer_appdata.
# C: production `on_exchange` (sched.c) с T_WATCHING/ver_flow/recall.
# Rust: production `r2o_handle_outer_appdata_followup` + `r2o_finish_watching_task`.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-outer-appdata.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -s -C "$DONOR/core" test_sched CC="$CC" >/dev/null
SCHED_OBJ=$(make -C "$DONOR/core" -pn 2>/dev/null |
    sed -n 's/^SCHED_TEST_OBJ = //p' | head -1 |
    sed 's/ sched\.o / /')
[ -n "$SCHED_OBJ" ] || {
    echo "не удалось прочитать SCHED_TEST_OBJ" >&2
    exit 2
}
(
    cd "$DONOR/core"
    "$CC" -std=gnu11 -O2 -Wall -Wextra \
        -I. -Iinclude -I../datapath/include -I../runtime \
        -o "$TEMP/c" \
        "$ROOT/crates/r2o-controller/tests/d2o_outer_appdata_differential.c" \
        $SCHED_OBJ diagnostics.o libd2k_udp.a -lpthread -lm
)
"$TEMP/c" >"$TEMP/c.out"
R2O_OUTER_APPDATA_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    tests::outer_appdata_followup_matches_c -- --exact \
    >"$TEMP/rust.log" 2>&1
if [ ! -f "$TEMP/rust.out" ]; then
    cat "$TEMP/rust.log" >&2
    echo "Rust-тест не записал трассу" >&2
    exit 1
fi
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: outer_appdata followup matches C on_exchange (%s).\n' "$ACTUAL_SHA"
