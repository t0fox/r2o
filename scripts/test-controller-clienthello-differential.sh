#!/bin/sh
# CL12: paired C/Rust differential ClientHello/TLS1.2/1.3/ECH parser helpers.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-cl12-tls.XXXXXX")
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


def ech(payload=b"\xaa\xbb", config_id=0x2A):
    # Раскладка тела ECH из core/hello.c: b[0]=0, config_id на +5,
    # enc_len на +6, payload_len на +8+enc_len, payload в хвосте.
    body = b"\x00" + b"\x13\x01\x00\x01" + bytes([config_id])
    body += struct.pack("!H", 0)
    body += struct.pack("!H", len(payload)) + payload
    return ext(0xFE0D, body)


def hello(extensions, version=0x0303, record_type=0x16, handshake_type=1):
    body = struct.pack("!H", version) + b"\x01" * 32 + b"\x00"
    body += struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = bytes([handshake_type]) + len(body).to_bytes(3, "big") + body
    return bytes([record_type]) + b"\x03\x01" + struct.pack("!H", len(handshake)) + handshake


modern = sni(b"example.com") + supported_versions([0x0304, 0x0303]) + key_share()
cases = {
    "modern": hello(modern),
    "sv-before-sni": hello(supported_versions([0x0304]) + sni(b"example.com") + key_share()),
    "legacy": hello(sni(b"legacy.example")),
    "legacy-no13": hello(sni(b"legacy.example") + supported_versions([0x0303])),
    "no-sni": hello(supported_versions([0x0304]) + key_share()),
    "no-extensions": hello(b""),
    "sni-empty": hello(sni(b"")),
    "sni-ip": hello(sni(b"1.2.3.4")),
    "ech-valid": hello(modern + ech()),
    "ech-empty-payload": hello(modern + ech(b"")),
    "ech-short": hello(modern + ext(0xFE0D, b"\x00\x01\x02")),
    "duplicate-sv": hello(
        sni(b"example.com")
        + supported_versions([0x0303])
        + supported_versions([0x0304])
        + key_share()
    ),
    "appdata-record": hello(modern, record_type=0x17),
    "server-hello": hello(modern, handshake_type=2),
    "non-tls": b"\x00" * 20,
    "trailing-4": hello(modern) + b"\x00" * 4,
    "second-record": hello(modern) + b"\x16\x03\x01\x00\x04\x00\x00\x00\x00",
}
base = hello(modern)
for length in (0, 1, 2, 4, 5, 8, 9, 10, 20, 40, 60, 67, 100, len(base) - 1):
    cases[f"trunc-{length}"] = base[:length]
record_bad = bytearray(base)
record_bad[3] = (record_bad[3] + 1) & 0xFF
cases["record-len-plus"] = bytes(record_bad)
record_bad = bytearray(base)
record_bad[4] = (record_bad[4] + 1) & 0xFF
cases["record-len-minus"] = bytes(record_bad)
handshake_bad = bytearray(base)
handshake_bad[6] = (handshake_bad[6] + 1) & 0xFF
cases["handshake-len-plus"] = bytes(handshake_bad)
truncated_key_share = hello(
    sni(b"example.com")
    + ext(0x33, struct.pack("!H", 1000))
)
cases["key-share-truncated"] = truncated_key_share
bad_sv = hello(sni(b"example.com") + ext(0x2B, b"\x05\x03\x04"))
cases["sv-bad-list"] = bad_sv

# Хвост за записью: shape/SNI его терпят, hello_complete — нет.
cases["trailing-64"] = base + b"\x00" * 64

# Оборванный блок расширений: признак TLS 1.3 найден и не найден.
cases["exts-truncated-sv"] = base[:-8]
no13 = hello(sni(b"example.com") + key_share())
cases["exts-truncated-nosv"] = no13[:-8]

# Объявленная длина блока расширений меньше фактической.
exts_short = bytearray(base)
exts_short[50:52] = struct.pack("!H", 2)
cases["exts-short"] = bytes(exts_short)

# server_name: список/имя не сходятся, несколько имён, пустое первое.
cases["sni-malformed-list"] = hello(
    ext(0, struct.pack("!H", 200) + b"\x00" + struct.pack("!H", 11) + b"example.com")
)
first_type = b"\x01" + struct.pack("!H", 1) + b"x"
second_type = b"\x00" + struct.pack("!H", 11) + b"example.com"
two_names = struct.pack("!H", len(first_type) + len(second_type)) + first_type + second_type
cases["sni-two-names"] = hello(ext(0, two_names))
empty_first = b"\x00\x00\x00" + second_type
cases["sni-first-empty"] = hello(ext(0, struct.pack("!H", len(empty_first)) + empty_first))
cases["sni-name-over"] = hello(ext(0, struct.pack("!H", 5) + b"\x00\x00\x20" + b"abc"))

# ECH: дубликат, неверный тип, enc_len за телом, payload_len не сходится.
cases["ech-duplicate"] = hello(modern + ech() + ech(config_id=0x2B))
bad_ech = bytearray(ech())
bad_ech[4] = 1
cases["ech-bad-type"] = hello(modern + bytes(bad_ech))
bad_enc = bytearray(ech())
bad_enc[10:12] = struct.pack("!H", 200)
cases["ech-enc-over"] = hello(modern + bytes(bad_enc))
bad_payload = bytearray(ech())
bad_payload[12:14] = struct.pack("!H", 5)
cases["ech-payload-mismatch"] = hello(modern + bytes(bad_payload))

# supported_versions: пустой список и список длиннее тела.
cases["sv-empty"] = hello(sni(b"example.com") + ext(0x2B, b"") + key_share())
cases["sv-huge-list"] = hello(sni(b"example.com") + ext(0x2B, b"\xff\x03\x04") + key_share())

# Рукопожатие: длина меньше и больше собственной записи.
handshake_short = bytearray(base)
handshake_short[8] = (handshake_short[8] - 1) & 0xFF
cases["handshake-len-minus"] = bytes(handshake_short)

# Запись TLS и ServerHello: короткие и полные.
cases["record-2"] = b"\x16\x03"
cases["record-3"] = b"\x16\x03\x01"


def record_message(kind, body, record_type=0x16):
    handshake = bytes([kind]) + len(body).to_bytes(3, "big") + body
    return bytes([record_type]) + b"\x03\x01" + struct.pack("!H", len(handshake)) + handshake


server_body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x13\x01" + b"\x00"
cases["server-hello-valid"] = record_message(2, server_body)
cases["server-hello-short"] = record_message(2, server_body[:-1])
cases["server-hello-min"] = record_message(
    2, b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x13\x01" + b"\x00", record_type=0x17
)

for name, payload in cases.items():
    (out / f"{name}.bin").write_bytes(payload)
(out.parent / "cases.txt").write_text("\n".join(cases) + "\n", encoding="utf-8")
PY

"$CC" -std=c11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-tls-parse" \
    "$ROOT/crates/r2o-controller/tests/d2o_tls_parse_differential.c" \
    "$D2O_ROOT/datapath/tls.c" \
    "$D2O_ROOT/core/hello.c"
"$TEMP/d2o-tls-parse" "$TEMP/cases" "$TEMP/cases.txt" > "$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example tg_cl12_tls_trace -- \
    "$TEMP/cases" "$TEMP/cases.txt" > "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: ClientHello/TLS/ECH parser differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(wc -l < "$TEMP/cases.txt")"
grep '^modern ' "$TEMP/c.out"
grep '^ech-valid ' "$TEMP/c.out"
printf 'PASS: C/Rust ClientHello/TLS1.2/1.3/ECH parser helpers match (D2O %s)\n' "$ACTUAL_D2O_SHA"
