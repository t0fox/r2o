#!/bin/sh
# C/Rust differential: production `install_next` (core/sched.c) — порядок
# выбора, probe cap, plan/trial id, bind/mark, SET_NAME_PROBE/SET_ADDR_PROBE
# и refill запасного перебора.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-install-next-production.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -s -C "$CORE" test_sched CC="$CC" >/dev/null
SCHED_OBJECTS=$(make -s -C "$CORE" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$CORE"
    "$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
        -I. -Iinclude -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
        -DD2K_RELEASE_ID='"dev"' \
        "$ROOT/crates/r2o-controller/tests/d2o_install_next_production_differential.c" \
        $SCHED_OBJECTS .udp-engine/udpplan.o .udp-engine/udpruntime.o \
        diagnostics.o libd2k_udp.a \
        -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"
)
"$TEMP/c" >"$TEMP/c.json" 2>"$TEMP/c.err"
cat "$TEMP/c.err" >&2
R2O_INSTALL_NEXT_PRODUCTION_DIFF_OUTPUT="$TEMP/c.json" \
R2O_INSTALL_NEXT_RUST_OUTPUT="$TEMP/rust.json" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    tests::install_next_production_matches_c -- --exact \
    >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys

# C_ONLY: ветви, у которых в Rust нет одноимённого production-эквивалента:
# ladder_unmeasurable, family_fast, rx_bootstrap_only, cached_measure_valid и
# продолжение перебора после непереводимого плана. own_first==2 закрыт
# production-исходом r2o_own_first_exhausted_outcome.
C_ONLY = {
    "ladder_unmeasurable_skip",
    "bad_plan_skip",
    "family_fast_stop",
    "rx_bootstrap_stop",
    "cached_measure_stop",
}
KEYS = (
    "scenario",
    "rc",
    "cap",
    "installed",
    "trial_nonzero",
    "plan_id_nonzero",
    "mark_value",
    "wire",
)
c_all = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
c = [{key: case[key] for key in KEYS} for case in c_all if case["scenario"] not in C_ONLY]
if c != r:
    for left, right in zip(c, r):
        if left != right:
            print("C:", json.dumps(left, ensure_ascii=False, sort_keys=True))
            print("R:", json.dumps(right, ensure_ascii=False, sort_keys=True))
            break
    if len(c) != len(r):
        print(f"C scenarios={len(c)}, R scenarios={len(r)}")
    raise SystemExit(1)
print(f"PASS: production install_next C/Rust match; matched={len(c)}")
print("C_ONLY branches: " + ", ".join(sorted(C_ONLY)))
PY
printf 'matched=%s\n' "$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))))' "$TEMP/rust.json")"
printf 'PASS: production install_next matches C (%s).\n' "$ACTUAL_SHA"
