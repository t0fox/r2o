#!/bin/sh
# TG12: paired C/Rust differential WebSocket upgrade и кадров.
#
# C-оракул — production ws.c (`tg_ws_upgrade_*`) и ws_pump.c
# (`tg_ws_reassembly_feed`); Rust — production tungstenite handshake/parser.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-ws.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/frames"

python3 - "$TEMP/frames" <<'PY'
import sys
from pathlib import Path

out = Path(sys.argv[1])


def frame(opcode, payload, fin=True, mask=False, rsv=0):
    payload = bytes(payload)
    first = (0x80 if fin else 0) | (rsv << 4) | opcode
    length = len(payload)
    if length < 126:
        header = bytes([first, length | (0x80 if mask else 0)])
    elif length <= 0xFFFF:
        header = bytes([first, 126 | (0x80 if mask else 0)]) + length.to_bytes(2, "big")
    else:
        header = bytes([first, 127 | (0x80 if mask else 0)]) + length.to_bytes(8, "big")
    if mask:
        key = b"\x01\x02\x03\x04"
        payload = bytes(byte ^ key[index & 3] for index, byte in enumerate(payload))
        return header + key + payload
    return header + payload


cases = {
    "binary-single": frame(0x82, b"hello"),
    "binary-empty": frame(0x82, b""),
    "binary-126": frame(0x82, b"a" * 126),
    "binary-65535": frame(0x82, b"b" * 65535),
    "fragmented": frame(0x02, b"he", fin=False) + frame(0x80, b"llo"),
    "fragmented-empty": frame(0x02, b"", fin=False) + frame(0x80, b"ok"),
    "ping": frame(0x89, b"ab"),
    "pong": frame(0x8A, b"ab"),
    "ping-in-fragment": frame(0x02, b"he", fin=False) + frame(0x89, b"x") + frame(0x80, b"llo"),
    "text": frame(0x81, b"hi"),
    "text-fragmented": frame(0x01, b"he", fin=False) + frame(0x80, b"llo"),
    "text-invalid-utf8": frame(0x81, b"\xff"),
    "close-1000": frame(0x88, b"\x03\xe8"),
    "close-empty": frame(0x88, b""),
    "close-len1": frame(0x88, b"\x03"),
    "close-bad-utf8": frame(0x88, b"\x03\xe8\xff"),
    "masked-server": frame(0x82, b"hi", mask=True),
    "rsv-bit": bytes([0x82 | 0x40, 0x01]) + b"x",
    "control-fragmented": bytes([0x09, 0x01]) + b"x",
    "control-126": bytes([0x89, 126, 0x00, 126]) + b"a" * 126,
    "noncanonical-126": bytes([0x82, 126, 0x00, 0x05]) + b"hello",
    "length-msb": bytes([0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0]),
    "continuation-without-start": frame(0x80, b"x"),
    "data-while-fragmented": frame(0x02, b"a", fin=False) + frame(0x82, b"b"),
    "two-binary": frame(0x82, b"one") + frame(0x82, b"two"),
    "oversize-declared": bytes([0x82, 127]) + (4 * 1024 * 1024 + 1).to_bytes(8, "big"),
}
for name, payload in cases.items():
    (out / f"{name}.bin").write_bytes(payload)
(out.parent / "cases.txt").write_text("\n".join(cases) + "\n", encoding="utf-8")
PY

OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$CC" -std=c11 -O2 -Wall -Wextra -pthread $OPENSSL_CFLAGS \
    -I"$D2O_ROOT/telegram/include" -I"$D2O_ROOT/telegram/src" \
    -o "$TEMP/d2o-ws" \
    "$ROOT/crates/r2o-telegram/tests/d2o_ws_differential.c" \
    "$D2O_ROOT/telegram/src/ws.c" \
    "$D2O_ROOT/telegram/src/ws_pump.c" \
    "$D2O_ROOT/telegram/src/memory_budget.c" \
    -L/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3

"$TEMP/d2o-ws" upgrade > "$TEMP/c-upgrade.out"
"$TEMP/d2o-ws" frames "$TEMP/frames" "$TEMP/cases.txt" > "$TEMP/c-frames.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg12_ws_trace -- upgrade > "$TEMP/rust-upgrade.out"
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg12_ws_trace -- \
    frames "$TEMP/frames" "$TEMP/cases.txt" > "$TEMP/rust-frames.out"

if ! diff -u "$TEMP/c-upgrade.out" "$TEMP/rust-upgrade.out"; then
    printf 'FAIL: WebSocket upgrade C/Rust differential\n' >&2
    exit 1
fi
if ! diff -u "$TEMP/c-frames.out" "$TEMP/rust-frames.out"; then
    printf 'FAIL: WebSocket frame C/Rust differential\n' >&2
    exit 1
fi

cat "$TEMP/c-upgrade.out"
cat "$TEMP/c-frames.out"
printf 'PASS: C/Rust WebSocket upgrade and frame behavior match (D2O %s)\n' "$ACTUAL_D2O_SHA"
