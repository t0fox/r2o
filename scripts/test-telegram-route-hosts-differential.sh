#!/bin/sh
# TG9: donor differential DC→WSS/CF host lists and attempt sequencing.
# Реализация берётся из z2kOW 42c8111; C11 D2O не источник.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR_ROOT=${R2O_Z2KOW_ROOT:?set R2O_Z2KOW_ROOT to the z2kOW checkout}
EXPECTED_SHA=42c8111765fe5bc5a2a690223df2523e85400eb5
ACTUAL_SHA=$(git -C "$DONOR_ROOT" rev-parse HEAD)
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    printf 'Expected z2kOW %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-route-hosts.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

python3 "$ROOT/scripts/fixtures/compare_donor_route_hosts.py" \
    "$DONOR_ROOT/platform/openwrt/tg-proxy/src/ws_client.rs" \
    "$ROOT/crates/r2o-telegram/src/ws_client.rs"

python3 - "$TEMP/cases.tsv" <<'PY'
import sys
from pathlib import Path

cases = []
for dc in (0, 1, 2, 4, 5, 6, 203, 999, 1000):
    for media in (0, 1):
        cases.append(f"ws\tdc{dc}-m{media}\t{dc}\t{media}")
domains = [
    "",
    "a.example",
    "a.example,b.example",
    "a.example,a.example",
    "UPPER.Example",
    "a.example.,b.example",
    "kws2.example",
]
for dc in (1, 2, 4, 203, 999, 1000):
    for media in (0, 1):
        for index, value in enumerate(domains):
            cases.append(f"cf\tdc{dc}-m{media}-d{index}\t{dc}\t{media}\t{value}")
Path(sys.argv[1]).write_text("\n".join(cases) + "\n", encoding="utf-8")
PY

DONOR_CRATE="$DONOR_ROOT/platform/openwrt/tg-proxy"
cp -a "$DONOR_CRATE" "$TEMP/donor"
printf '\n[patch.crates-io]\nrustls = { path = "%s" }\n' "$ROOT/vendor/rustls" \
    >> "$TEMP/donor/Cargo.toml"
mkdir -p "$TEMP/donor/examples"
sed 's/r2o_telegram/z2kow_tg_transparent/g' \
    "$ROOT/crates/r2o-telegram/examples/tg9_route_hosts_trace.rs" \
    > "$TEMP/donor/examples/tg9_route_hosts_trace.rs"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg9_route_hosts_trace -- \
    "$TEMP/cases.tsv" > "$TEMP/r2o.out"
CARGO_TARGET_DIR="$TEMP/target-donor" \
    "$CARGO" run --manifest-path "$TEMP/donor/Cargo.toml" --offline \
    -q --example tg9_route_hosts_trace -- "$TEMP/cases.tsv" > "$TEMP/donor.out"

if ! diff -u "$TEMP/donor.out" "$TEMP/r2o.out"; then
    printf 'FAIL: z2kOW route host differential\n' >&2
    exit 1
fi

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --lib ws_client::tests >/dev/null
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --test ws_client >/dev/null

printf 'cases=%s\n' "$(grep -c ' hosts=' "$TEMP/r2o.out")"
grep '^ws-dc203-m0 ' "$TEMP/r2o.out"
grep '^cf-dc2-m1-d2 ' "$TEMP/r2o.out"
printf 'PASS: z2kOW DC→WSS/CF host lists and attempts match %s\n' "$ACTUAL_SHA"
