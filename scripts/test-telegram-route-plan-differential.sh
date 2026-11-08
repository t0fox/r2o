#!/bin/sh
# TG9: paired C/Rust differential route plan (`route_plan.c`).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-gcc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-route-plan.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

python3 - "$TEMP" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
plans = []
index = 0
for policy in range(4):
    for prefer in (0, 1):
        for dc in (1, 2, 4, 5, 203, 6, 999):
            for media in (0, 1):
                for workers in (0, 1, 2, 8):
                    for cf in (0, 1, 3, 64):
                        for diag in (0, 1):
                            plans.append(
                                f"p{index}\t{dc}\t{media}\t{policy}\t{prefer}\t"
                                f"{workers}\t{cf}\t{diag}"
                            )
                            index += 1
plans.extend([
    f"invalid-dc\t1000\t0\t0\t0\t0\t0\t0",
    f"negative-dc\t-1\t0\t0\t0\t0\t0\t0",
    f"invalid-policy\t4\t0\t0\t0\t0\t0\t0",
    f"invalid-policy-5\t2\t0\t5\t0\t0\t0\t0",
    f"invalid-media\t2\t2\t0\t0\t0\t0\t0",
    f"invalid-prefer\t2\t0\t0\t2\t0\t0\t0",
    f"invalid-diag\t2\t0\t0\t0\t0\t0\t2",
    f"workers-over\t2\t0\t0\t0\t9\t0\t0",
    f"cf-over\t2\t0\t0\t0\t0\t65\t0",
    f"max-plan\t999\t1\t0\t0\t8\t64\t1",
    f"max-plan-direct\t2\t1\t0\t0\t8\t64\t1",
])
(root / "plans.tsv").write_text("\n".join(plans) + "\n", encoding="utf-8")

domains = [
    "example.co.uk",
    "",
    "UPPER.Example",
    "a" * 250 + ".co.uk",
    "b" * 260 + ".co.uk",
]
hostnames = []
index = 0
for dc in (0, 1, 2, 6, 203, 999, 1000):
    for media in (0, 1, 2):
        for domain in domains:
            for capacity in (0, 1, 4, 5, 6, 10, 20, 64, 254, 300):
                hostnames.append(
                    f"h{index}\t{dc}\t{media}\t{domain}\t{capacity}"
                )
                index += 1
(root / "hostnames.tsv").write_text("\n".join(hostnames) + "\n", encoding="utf-8")
PY

"$CC" -std=c11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/telegram/include" \
    -o "$TEMP/d2o-route-plan" \
    "$ROOT/crates/r2o-telegram/tests/d2o_route_plan_differential.c" \
    "$D2O_ROOT/telegram/src/route_plan.c"
"$TEMP/d2o-route-plan" "$TEMP/plans.tsv" "$TEMP/hostnames.tsv" > "$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg9_plan_trace -- \
    "$TEMP/plans.tsv" "$TEMP/hostnames.tsv" > "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: route plan C/Rust differential\n' >&2
    exit 1
fi

printf 'plans=%s hostnames=%s\n' \
    "$(grep -c '^plan ' "$TEMP/c.out")" \
    "$(grep -c '^hostname ' "$TEMP/c.out")"
grep '^plan max-plan ' "$TEMP/c.out"
grep '^hostname h0 ' "$TEMP/c.out" || true
printf 'PASS: C/Rust route plan, CF hostname and DC mapping match (D2O %s)\n' "$ACTUAL_D2O_SHA"
