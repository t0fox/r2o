#!/bin/sh
# C/Rust differential: DoQ DNS task-ячейка в live-секции current D2O main
# 7a5fab9 (checking / bypass_ok / no_bypass).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-dns-doq.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$DNS_DONOR_ROOT/core" -I"$DNS_DONOR_ROOT/core/include" \
    -I"$DNS_DONOR_ROOT/datapath/include" -I"$DNS_DONOR_ROOT/runtime" \
    -o "$TEMP/d2o-dns-doq" \
    "$ROOT/crates/r2o-controller/tests/d2o_dns_doq_differential.c" \
    "$DNS_DONOR_ROOT/core/catalog.c" "$DNS_DONOR_ROOT/core/groups.c" \
    "$DNS_DONOR_ROOT/core/domain.c" "$DNS_DONOR_ROOT/runtime/d2k_dns_config.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/d2o-dns-doq" >"$TEMP/c.json"

R2O_DNS_DOQ_DIFF_OUTPUT="$TEMP/rust.json" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    tests::dns_doq_live_differential_matches_current_d2o \
    -- --exact >"$TEMP/cargo.log" 2>&1

python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys

c = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
for item in c:
    item.pop("end", None)
    for service in item["dns_services"]:
        # В доноре текст общий для DoH/DoQ. R2O указывает фактический протокол.
        if service["status_reason"] == "Проверяется кандидат штатным конвейером D2O.":
            service["status_reason"] = "Проверяется кандидат."
        elif service["protocol"] == "doq" and service["status_reason"].startswith("Плановый DoH-зонд "):
            service["status_reason"] = service["status_reason"].replace("Плановый DoH-зонд ", "Плановый DoQ-зонд ", 1)
if c != r:
    for left, right in zip(c, r):
        if left != right:
            print("C:", json.dumps(left, ensure_ascii=False, sort_keys=True))
            print("R:", json.dumps(right, ensure_ascii=False, sort_keys=True))
            break
    raise SystemExit(1)
print("PASS: dns_services DoQ task C/Rust match (current main)")
PY

printf 'cases=%s\n' "$(grep -o '"scenario"' "$TEMP/c.json" | wc -l)"
