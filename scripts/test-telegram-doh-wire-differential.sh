#!/bin/sh
# TG14: paired C/Rust differential DNS-wire DoH encode/parse (route_dns.c).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-doh-wire.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/packets"

python3 - "$TEMP/packets" <<'PY'
import struct
import sys
from pathlib import Path

out = Path(sys.argv[1])
question = b"\x04edge\x07example\x00" + struct.pack("!HH", 1, 1)

def header(qd, an, flags=0x8180, ident=0x1234):
    return struct.pack("!HHHHHH", ident, flags, qd, an, 0, 0)

def rr(rtype, data, klass=1, name=b"\xc0\x0c"):
    return name + struct.pack("!HHIH", rtype, klass, 60, len(data)) + data

def write(name, packet):
    (out / f"{name}.bin").write_bytes(packet)

write("valid", header(1, 2) + question +
      rr(1, bytes([104, 21, 75, 42])) +
      rr(28, bytes.fromhex("26064700470000000000000000001111")))
write("private", header(1, 1) + question + rr(1, bytes([10, 0, 0, 1])))
write("mixed", header(1, 2) + question +
      rr(1, bytes([10, 0, 0, 1])) +
      rr(28, bytes.fromhex("26064700470000000000000000001111")))
write("duplicate", header(1, 2) + question +
      rr(1, bytes([104, 21, 75, 42])) +
      rr(1, bytes([104, 21, 75, 42])))
write("cname", header(1, 2) + question +
      rr(5, b"\x00") +
      rr(1, bytes([104, 21, 75, 42])))
write("wrong-id", header(1, 1, ident=0x9999) + question +
      rr(1, bytes([104, 21, 75, 42])))
write("tc-flag", header(1, 1, flags=0x8380) + question +
      rr(1, bytes([104, 21, 75, 42])))
write("rcode", header(1, 1, flags=0x8182) + question +
      rr(1, bytes([104, 21, 75, 42])))
write("class-mismatch", header(1, 1) + question +
      rr(1, bytes([104, 21, 75, 42]), klass=3))
write("truncated", header(1, 1) + question + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x68\x15")
write("many", header(1, 9) + question +
      b"".join(rr(1, bytes([104, 21, 75, i])) for i in range(1, 10)))
PY

PARSE_NAMES="valid private mixed duplicate cname wrong-id tc-flag rcode class-mismatch truncated many"

OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$CC" -std=c11 -O2 -Wall -Wextra $OPENSSL_CFLAGS \
    -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/telegram/include" -I"$D2O_ROOT/telegram/src" \
    -o "$TEMP/d2o-doh-wire" \
    "$ROOT/crates/r2o-telegram/tests/d2o_doh_wire_differential.c" \
    -Wl,--gc-sections -pthread \
    -L/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3

: > "$TEMP/c.out"
for domain in edge.example kws2.pclead.co.uk; do
    "$TEMP/d2o-doh-wire" encode "$domain" 1 >> "$TEMP/c.out"
    "$TEMP/d2o-doh-wire" encode "$domain" 28 >> "$TEMP/c.out"
done
"$TEMP/d2o-doh-wire" encode "$(printf 'a%.0s' $(seq 1 70)).example" 1 >> "$TEMP/c.out"
long_domain=$(python3 -c 'print(".".join(["a"*40]*7))')
"$TEMP/d2o-doh-wire" encode "$long_domain" 1 >> "$TEMP/c.out"
# shellcheck disable=SC2086
"$TEMP/d2o-doh-wire" parse "$TEMP/packets" $PARSE_NAMES >> "$TEMP/c.out"

: > "$TEMP/rust.out"
for domain in edge.example kws2.pclead.co.uk; do
    "$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -q -p r2o-telegram --example tg14_wire_trace -- encode "$domain" 1 >> "$TEMP/rust.out"
    "$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -q -p r2o-telegram --example tg14_wire_trace -- encode "$domain" 28 >> "$TEMP/rust.out"
done
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg14_wire_trace -- \
    encode "$(printf 'a%.0s' $(seq 1 70)).example" 1 >> "$TEMP/rust.out"
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg14_wire_trace -- encode "$long_domain" 1 >> "$TEMP/rust.out"
# shellcheck disable=SC2086
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg14_wire_trace -- \
    parse "$TEMP/packets" $PARSE_NAMES >> "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: DoH DNS-wire C/Rust differential\n' >&2
    exit 1
fi
cat "$TEMP/c.out"
printf 'PASS: C/Rust DoH DNS-wire encode and parser match (D2O %s)\n' "$ACTUAL_D2O_SHA"
