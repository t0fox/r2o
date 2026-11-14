#!/bin/sh
# C/Rust differential: d2k_hello_rename/splice_sni (core/hello.c:409-535).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-hello-rename.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/cases"

python3 - "$TEMP/cases" <<'PY'
import struct
import sys
from pathlib import Path

out = Path(sys.argv[1])


def ext(kind, data):
    return struct.pack("!HH", kind, len(data)) + data


def sni(name):
    entry = b"\x00" + struct.pack("!H", len(name)) + name
    return ext(0, struct.pack("!H", len(entry)) + entry)


def supported_versions(versions):
    values = b"".join(struct.pack("!H", version) for version in versions)
    return ext(0x2B, bytes([len(values)]) + values)


def key_share():
    share = struct.pack("!H", 29) + struct.pack("!H", 32) + b"\x11" * 32
    return ext(0x33, struct.pack("!H", len(share)) + share)


def hello(extensions, record_type=0x16, extra=b"", declared_handshake=None):
    body = struct.pack("!H", 0x0303) + b"\x01" * 32 + b"\x00"
    body += struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + (len(body) if declared_handshake is None else declared_handshake).to_bytes(3, "big") + body
    record = bytes([record_type]) + b"\x03\x01" + struct.pack("!H", len(handshake) + len(extra)) + handshake + extra
    return record


cases = {
    "equal": hello(sni(b"example.com") + supported_versions([0x0304]) + key_share()),
    "shorter": hello(sni(b"a.b") + supported_versions([0x0304]) + key_share()),
    "longer": hello(sni(b"long.example.name") + supported_versions([0x0304]) + key_share()),
    "sni-last": hello(supported_versions([0x0304]) + key_share() + sni(b"zz")),
    "sni-first": hello(sni(b"zz") + supported_versions([0x0304]) + key_share()),
    "legacy": hello(sni(b"legacy.example")),
    "no-extensions": hello(b""),
    "no-sni": hello(supported_versions([0x0304]) + key_share()),
    "sni-empty": hello(sni(b"")),
    "sni-two-names": hello(
        ext(
            0,
            struct.pack("!H", 3 + 2 + 3 + 2 + 7)
            + b"\x00\x00\x03abc"
            + b"\x00\x00\x07example",
        )
    ),
    "sni-list-over": hello(ext(0, struct.pack("!H", 200) + b"\x00\x00\x03abc")),
    "sni-name-over": hello(ext(0, struct.pack("!H", 5) + b"\x00\x00\x20abc")),
    "trailing-8": hello(sni(b"example.com") + supported_versions([0x0304]), extra=b"\x00" * 8),
    "truncated": hello(sni(b"example.com") + supported_versions([0x0304]))[:-3],
    "exts-short": hello(sni(b"example.com") + supported_versions([0x0304]))[:-8],
    "appdata-record": hello(sni(b"example.com"), record_type=0x17),
    "non-tls": b"\x00" * 40,
    "short-4": b"\x16\x03\x01\x00",
    "zero-body": b"\x16\x03\x01\x00\x00",
    "handshake-short": hello(sni(b"example.com"), declared_handshake=10),
}

for name, payload in cases.items():
    (out / f"{name}.bin").write_bytes(payload)
(out.parent / "cases.txt").write_text("\n".join(cases) + "\n", encoding="utf-8")
PY

"$CC" -std=c11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-hello-rename" \
    "$ROOT/crates/r2o-controller/tests/d2o_hello_rename_differential.c" \
    "$D2O_ROOT/core/hello.c"
"$TEMP/d2o-hello-rename" "$TEMP/cases" "$TEMP/cases.txt" > "$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example tg_hello_rename_trace -- \
    "$TEMP/cases" "$TEMP/cases.txt" > "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: ClientHello rename/splice differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(wc -l < "$TEMP/cases.txt")"
grep '^shorter ' "$TEMP/c.out"
printf 'PASS: C/Rust d2k_hello_rename/splice_sni match (D2O %s)\n' "$ACTUAL_D2O_SHA"
