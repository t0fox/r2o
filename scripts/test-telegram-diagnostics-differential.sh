#!/bin/sh
# TG23: donor differential diagnostics `--check` (z2kOW 42c8111).
# Сравниваются исходная реализация (кроме ca_bundle-интеграции), JSON-схема
# отчёта, состояния DC/маршрутов и donor-тесты.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-diagnostics.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

DONOR_CRATE="$DONOR_ROOT/platform/openwrt/tg-proxy"
python3 "$ROOT/scripts/fixtures/compare_donor_diagnostics.py" \
    "$DONOR_CRATE/src/diagnostics.rs" \
    "$ROOT/crates/r2o-telegram/src/diagnostics.rs"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg23_diagnostics_trace > "$TEMP/r2o.out"

cp -a "$DONOR_CRATE" "$TEMP/donor"
printf '\n[patch.crates-io]\nrustls = { path = "%s" }\n' "$ROOT/vendor/rustls" \
    >> "$TEMP/donor/Cargo.toml"
mkdir -p "$TEMP/donor/examples"
sed 's/r2o_telegram/z2kow_tg_transparent/g' \
    "$ROOT/crates/r2o-telegram/examples/tg23_diagnostics_trace.rs" \
    > "$TEMP/donor/examples/tg23_diagnostics_trace.rs"
CARGO_TARGET_DIR="$TEMP/target-donor" \
    "$CARGO" run --manifest-path "$TEMP/donor/Cargo.toml" --offline \
    -q --example tg23_diagnostics_trace > "$TEMP/donor.out"

if ! diff -u "$TEMP/donor.out" "$TEMP/r2o.out"; then
    printf 'FAIL: z2kOW diagnostics report differential\n' >&2
    exit 1
fi

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --lib diagnostics::tests >/dev/null
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --test config standalone_check_mode_is_an_explicit_runtime_option \
    >/dev/null

cat "$TEMP/r2o.out"
printf 'PASS: z2kOW diagnostics --check interface/report matches %s\n' "$ACTUAL_SHA"
