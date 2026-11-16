#!/bin/sh
# C/Rust differential: TLV-сборщики compose.c.
# C-оракул — production overlap_plan_tlv/reorder_plan_tlv/
# badsum_fake_plan_tlv/checksum_plan_tlv; Rust — соответствующий текст
# compose_d2o, скомпилированный production plan_text::compile_text.
# Rust-текст сначала компилируется и переводится в D2KP, затем
# удостоверяется тем же FNV-1a, что C `plan_tlv_stamp_ident`.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CORE="$DONOR/core"
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-compose-tlv.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$CORE" -I"$CORE/include" -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
    -DD2K_RELEASE_ID='"dev"' \
    "$ROOT/crates/r2o-controller/tests/d2o_compose_tlv_differential.c" \
    -Wl,--gc-sections -lpthread -o "$TEMP/c"

"$TEMP/c" >"$TEMP/c.out"
R2O_COMPOSE_TLV_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --locked -p r2o-controller --lib \
    compose_d2o::tests::compose_texts_compile_to_d2o_tlv -- --exact \
    >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }

python3 - "$TEMP/c.out" "$TEMP/rust.out" <<'PY'
import sys

def load(path):
    out = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            name, rest = line.split(maxsplit=1)
            out[name] = rest.strip()
    return out

c = load(sys.argv[1])
r = load(sys.argv[2])
for name in ("overlap", "reorder", "badsum", "badsum_gap"):
    if c[name] != r[name]:
        raise SystemExit(f"FAIL: {name} stamped TLV differs")
if c["checksum"] != r["badsum"]:
    raise SystemExit("FAIL: checksum stamped TLV differs from Rust badsum")
for name in ("short", "wrong_type", "wrong_len"):
    if c[name] != r[name] or c[name] != "rc=-1":
        raise SystemExit(f"FAIL: {name} layout guard differs")
print("compose TLV: 4 builders + checksum + layout guards match")
PY

printf 'PASS: compose TLV builders match C (%s)\n' "$ACTUAL_SHA"
