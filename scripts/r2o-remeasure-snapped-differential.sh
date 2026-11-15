#!/bin/sh
# C/Rust differential: C `remeasure_snapped` против production-сброса
# R2O перед повторным замером снимком клиента.
#
# Сравниваются долговременные курсоры, которые в Rust переживают отдельный
# job: tried/next_candidate/probes/plans/rx-cursor. Task-local поля C
# (own_seen/rx_bootstrap_only/family_reuse/ech_grease/...) в R2O являются
# переменными нового запуска; C fixture печатает их в stderr для протокола.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
fi
CC=${CC:-cc}
CORE="$DONOR/core"
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-remeasure.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -s -C "$CORE" test_sched CC="$CC" >/dev/null
SCHED_OBJECTS=$(make -s -C "$CORE" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$CORE"
    "$CC" -std=gnu11 -O2 -Wall -Wextra -ffunction-sections -fdata-sections \
        -I. -Iinclude -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
        -DD2K_RELEASE_ID='"dev"' \
        "$ROOT/crates/r2o-controller/tests/d2o_remeasure_snapped_differential.c" \
        $SCHED_OBJECTS .udp-engine/udpplan.o .udp-engine/udpruntime.o \
        diagnostics.o libd2k_udp.a \
        -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"
)
"$TEMP/c" >"$TEMP/c.json" 2>"$TEMP/c.err"

R2O_REMEASURE_DIFF_OUTPUT="$TEMP/rust.json" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    snapshot_recheck_resets_candidate_cursors_and_tried_plans \
    >"$TEMP/rust.log" 2>&1

python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys

c = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
if c != r:
    print("C:", json.dumps(c, ensure_ascii=False, sort_keys=True, indent=2))
    print("R:", json.dumps(r, ensure_ascii=False, sort_keys=True, indent=2))
    raise SystemExit(1)
PY

cat "$TEMP/c.err"
printf 'PASS: C remeasure_snapped resets match R2O production reset (%s).\n' \
    "$ACTUAL_SHA"
