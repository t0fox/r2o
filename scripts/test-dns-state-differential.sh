#!/bin/sh
# C/Rust differential: dns_service_observe / dns_service_note_applied и
# live-состояния dns_services current main 7a5fab9.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DNS_DONOR_ROOT=${R2O_DNS_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_DNS_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_DNS_SHA=$(git -C "$DNS_DONOR_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}

if [ "$ACTUAL_DNS_SHA" != "$EXPECTED_DNS_SHA" ]; then
    printf 'Expected D2O current %s, got %s\n' "$EXPECTED_DNS_SHA" "$ACTUAL_DNS_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-dns-state.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$DNS_DONOR_ROOT/core" -I"$DNS_DONOR_ROOT/core/include" \
    -I"$DNS_DONOR_ROOT/datapath/include" -I"$DNS_DONOR_ROOT/runtime" \
    -o "$TEMP/d2o-dns-state" \
    "$ROOT/crates/r2o-controller/tests/d2o_dns_state_differential.c" \
    "$DNS_DONOR_ROOT/core/catalog.c" "$DNS_DONOR_ROOT/core/groups.c" \
    "$DNS_DONOR_ROOT/core/domain.c" "$DNS_DONOR_ROOT/runtime/d2k_dns_config.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/d2o-dns-state" >"$TEMP/c.json"

R2O_DNS_STATE_DIFF_OUTPUT="$TEMP/rust.json" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    tests::dns_live_state_differential_matches_current_d2o \
    -- --exact >"$TEMP/cargo.log" 2>&1

python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys

c = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
for item in c:
    item.pop("end", None)
if c != r:
    for left, right in zip(c, r):
        if left != right:
            print("C:", json.dumps(left, ensure_ascii=False, sort_keys=True))
            print("R:", json.dumps(right, ensure_ascii=False, sort_keys=True))
            break
    raise SystemExit(1)
print("PASS: dns_services observe/applied live C/Rust match (current main)")
PY

printf 'cases=%s\n' "$(grep -o '"scenario"' "$TEMP/c.json" | wc -l)"
