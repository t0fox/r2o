#!/bin/sh
# C/Rust differential: d2k_props_contact_on_family_tcp_profile
# (compose.c:632-753): family 4/6, use_fd/out_fd, пустое приветствие,
# локальные адрес/порт, коды -1/-3 и факт отправки.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-props-contact.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-props-contact" \
    "$ROOT/crates/r2o-controller/tests/d2o_props_contact_differential.c" \
    "$D2O_ROOT/core/catalog.c" "$D2O_ROOT/core/groups.c" \
    "$D2O_ROOT/core/domain.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/d2o-props-contact" >"$TEMP/c.json"

R2O_PROPS_CONTACT_DIFF_OUTPUT="$TEMP/rust.json" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    tests::props_contact_contract_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys

c = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
if c != r:
    print("C:", json.dumps(c, ensure_ascii=False, sort_keys=True))
    print("R:", json.dumps(r, ensure_ascii=False, sort_keys=True))
    raise SystemExit(1)
print("PASS: props_contact family/use_fd/out_fd/-3 C/Rust match")
PY

printf 'cases=%s\n' "$(grep -o '"name"' "$TEMP/c.json" | wc -l)"
