#!/bin/sh
# C/Rust differential: полный live.json в 8 состояниях против C
# `d2k_sched_write_live` current main 7a5fab9.
#
# Состояния: rich (areas/autopick/исключения), empty, boxes, bindings,
# groups, measurements, tasks (T_ASKING/T_VERIFY/T_VERIFY_WAIT/
# T_TRIAL_SETTLE/T_WATCHING/T_RESTING), dns (detected/checking/direct_ok/
# plan_applied/bypass_ok/no_bypass/failed/candidate-without-answer/DoQ).
#
# Сравнивается весь JSON без фильтрации: поля, значения, типы, порядок
# массивов. Порядок ключей объекта не сравнивается — JSON-объект неупорядочен.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_D2O_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O current %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP=$(mktemp -d "$TMPDIR/r2o-live-full.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

COMMON_CFLAGS="-std=gnu11 -O2 -ffunction-sections -fdata-sections \
-I$D2O_ROOT/core -I$D2O_ROOT/core/include \
-I$D2O_ROOT/datapath/include -I$D2O_ROOT/runtime"
CORE_SOURCES="$D2O_ROOT/core/catalog.c $D2O_ROOT/core/groups.c $D2O_ROOT/core/domain.c"

# shellcheck disable=SC2086
"$CC" $COMMON_CFLAGS -o "$TEMP/d2o-live-rich" \
    "$ROOT/crates/r2o-controller/tests/d2o_live_snapshot_differential.c" \
    $CORE_SOURCES -Wl,--gc-sections -lpthread -lm
# shellcheck disable=SC2086
"$CC" $COMMON_CFLAGS -o "$TEMP/d2o-live-states" \
    "$ROOT/crates/r2o-controller/tests/d2o_live_states_differential.c" \
    $CORE_SOURCES -Wl,--gc-sections -lpthread -lm

"$TEMP/d2o-live-rich" >"$TEMP/rich.json"
for mode in empty boxes bindings groups measurements tasks dns; do
    "$TEMP/d2o-live-states" "$mode" >"$TEMP/state_$mode.json"
done

python3 - "$TEMP" <<'PY'
import json
import sys

root = sys.argv[1]
modes = ["empty", "boxes", "bindings", "groups", "measurements", "tasks", "dns"]
# C `%.100s` может оборвать UTF-8: панель (Go) читает такой JSON с U+FFFD.
# errors="replace" воспроизводит именно то, что видит панель.
states = [json.load(open(f"{root}/rich.json", encoding="utf-8", errors="replace"))]
states += [
    json.load(open(f"{root}/state_{mode}.json", encoding="utf-8", errors="replace"))
    for mode in modes
]
json.dump(states, open(f"{root}/c.json", "w", encoding="utf-8"), ensure_ascii=False)
PY

R2O_LIVE_SNAPSHOT_DIFF_OUTPUT="$TEMP/rich_rust.json" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib live::tests::live_snapshot_differential_matches_c \
    -- --exact >"$TEMP/rich_cargo.log" 2>&1
R2O_LIVE_STATES_DIFF_OUTPUT="$TEMP/states_rust.json" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib live::tests::live_snapshot_states_differential_matches_c \
    -- --exact >"$TEMP/states_cargo.log" 2>&1

python3 - "$TEMP" <<'PY'
import json
import sys

root = sys.argv[1]
rich = json.load(open(f"{root}/rich_rust.json", encoding="utf-8", errors="replace"))
states = json.load(open(f"{root}/states_rust.json", encoding="utf-8", errors="replace"))
json.dump([rich, *states], open(f"{root}/r.json", "w", encoding="utf-8"), ensure_ascii=False)
PY

python3 - "$TEMP/c.json" "$TEMP/r.json" <<'PY'
import json
import sys

NAMES = ["rich", "empty", "boxes", "bindings", "groups", "measurements", "tasks", "dns"]


def walk(left, right, path):
    if type(left) is not type(right):
        print(f"  type {path}: C={type(left).__name__} R={type(right).__name__}")
        return False
    if isinstance(left, dict):
        ok = True
        for key in sorted(left.keys() | right.keys()):
            if key not in left:
                print(f"  only-rust {path}/{key}")
                ok = False
            elif key not in right:
                print(f"  only-c {path}/{key}")
                ok = False
            else:
                ok = walk(left[key], right[key], f"{path}/{key}") and ok
        return ok
    if isinstance(left, list):
        ok = True
        if len(left) != len(right):
            print(f"  length {path}: C={len(left)} R={len(right)}")
            ok = False
        for index, (c_item, r_item) in enumerate(zip(left, right)):
            ok = walk(c_item, r_item, f"{path}[{index}]") and ok
        return ok
    if left != right:
        print(f"  value {path}: C={left!r} R={right!r}")
        return False
    return True


c = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
if len(c) != len(r) or len(c) != len(NAMES):
    print(f"state count: C={len(c)} R={len(r)} expected={len(NAMES)}")
    raise SystemExit(1)

failed = False
for name, c_state, r_state in zip(NAMES, c, r):
    if walk(c_state, r_state, name):
        print(f"{name}: PASS")
    else:
        print(f"{name}: DIFF")
        failed = True
if failed:
    raise SystemExit(1)
print(f"PASS: full live.json C/Rust match in {len(NAMES)} states (D2O current main)")
PY
