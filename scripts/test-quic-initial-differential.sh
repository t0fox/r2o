#!/bin/sh
# C/Rust differential: d2k_quic_is_initial — структура Initial без AEAD.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-quic-initial.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/cases"

python3 - "$ROOT/crates/r2k-core/tests/fixtures" "$TEMP/cases" <<'PY'
import sys
from pathlib import Path

fixtures = Path(sys.argv[1])
out = Path(sys.argv[2])
v1 = (fixtures / "quic_v1_initial.bin").read_bytes()
v2 = (fixtures / "quic_v2_initial.bin").read_bytes()

cases = {"v1": v1, "v2": v2}
tag = bytearray(v1)
tag[-1] ^= 0xFF
cases["v1-bad-tag"] = bytes(tag)
tag2 = bytearray(v2)
tag2[-1] ^= 0xFF
cases["v2-bad-tag"] = bytes(tag2)

handshake = bytearray(v1)
handshake[0] = (handshake[0] & 0xCF) | 0x10
cases["type-handshake"] = bytes(handshake)
unknown_version = bytearray(v1)
unknown_version[1:5] = (0x1A2A3A4A).to_bytes(4, "big")
cases["unknown-version"] = bytes(unknown_version)
v0 = bytearray(v1)
v0[1:5] = b"\x00\x00\x00\x01"
cases["version-1"] = bytes(v0)
short = bytearray(v1)
short[0] &= 0x7F
cases["short-header"] = bytes(short)
for length in (0, 1, 5, 6, 7, 8, 20, 50, 100, 500, 1199):
    cases[f"trunc-{length}"] = v1[:length]
dcid0 = bytearray(v1)
dcid0[5] = 0
cases["dcid-len-0"] = bytes(dcid0)
dcid21 = bytearray(v1)
dcid21[5] = 21
cases["dcid-len-21"] = bytes(dcid21)
oversized = v1 + b"\x00" * (1501 - len(v1))
cases["oversized-1501"] = oversized
cases["oversized-65535"] = v1 + b"\x00" * (65535 - len(v1))
trailing = v1 + b"\x00" * 8
cases["trailing-8"] = trailing
cases["random-40"] = bytes(range(40))
cases["empty"] = b""

for name, payload in cases.items():
    (out / f"{name}.bin").write_bytes(payload)
(out.parent / "cases.txt").write_text("\n".join(cases) + "\n", encoding="utf-8")
PY

"$CC" -std=c11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/core" \
    -o "$TEMP/d2o-quic-initial" \
    "$ROOT/crates/r2o-controller/tests/d2o_quic_initial_differential.c" \
    "$D2O_ROOT/core/quic.c" "$D2O_ROOT/core/quicwire.c" "$D2O_ROOT/core/crypto.c"
"$TEMP/d2o-quic-initial" "$TEMP/cases" "$TEMP/cases.txt" > "$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example tg_quic_initial_trace -- \
    "$TEMP/cases" "$TEMP/cases.txt" > "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: quic initial structural differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(wc -l < "$TEMP/cases.txt")"
grep '^v1-bad-tag ' "$TEMP/c.out"
printf 'PASS: C/Rust d2k_quic_is_initial match (D2O %s)\n' "$ACTUAL_D2O_SHA"
