#!/bin/sh
# CL13: paired C/Rust differential HTTPS-зонда и кэша состояний.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-cl13-httpsprobe.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/cases" "$TEMP/c-out" "$TEMP/rust-out"

python3 - "$TEMP/cases" <<'PY'
import sys
from pathlib import Path

out = Path(sys.argv[1])
wall = 1_700_000_000
cases = []


def write_text(name, text):
    cases.append(name)
    (out / f"{name}.txt").write_text(text, encoding="utf-8")


def write_bytes(name, data):
    cases.append(name)
    (out / f"{name}.txt").write_bytes(data)


write_text("v1-basic", "d2k-https 1\nserved 1700003600 a.test\nclosed 1700001800 b.test\n")
write_text(
    "v2-basic",
    f"d2k-https 2 {wall}\n"
    "served 1700003600 a.test\n"
    "tls-blocked 1700003600 b.test\n"
    "closed 1700001800 c.test\n"
    "other-name 1700001800 d.test\n"
    "unconfirmed 1700000120 e.test\n",
)
write_text("empty-v1", "d2k-https 1\n")
write_text("bad-header", "d2k-https 3 1\nserved 1700003600 a.test\n")
write_text("header-no-newline", "d2k-https 1")
write_text("bad-written", "d2k-https 2 abc\n")
write_text("negative-written", "d2k-https 2 -1\n")
write_text("future", f"d2k-https 2 {wall + 1}\nserved 1700003600 a.test\n")
write_text(
    "clamp",
    f"d2k-https 2 {wall}\n"
    f"served {wall + 999999} a.test\n"
    f"closed {wall + 999999} b.test\n",
)
write_text(
    "expired",
    f"d2k-https 2 {wall}\nserved {wall} a.test\nclosed {wall - 1} b.test\n",
)
write_text(
    "unknown-state",
    f"d2k-https 2 {wall}\nprobing 1700003600 a.test\n"
    "unknown 1700003600 b.test\nweird 1700003600 c.test\n",
)
write_text(
    "bad-host",
    f"d2k-https 2 {wall}\nserved 1700003600 bad_host\n"
    "served 1700003600 bad/host\n"
    f"served 1700003600 {'a' * 254}\n",
)
write_text("uppercase", f"d2k-https 2 {wall}\nserved 1700003600 Example.Test\n")
write_text(
    "duplicates",
    f"d2k-https 2 {wall}\nserved 1700003600 dup.test\n"
    "closed 1700001800 dup.test\n",
)
write_text("extra-token", f"d2k-https 2 {wall}\nserved 1700003600 a.test extra\n")
write_text("negative-exp", f"d2k-https 2 {wall}\nserved -5 a.test\n")
write_text("trailing-space", f"d2k-https 2 {wall}\nserved 1700003600 a.test   \n")
write_text("zero-ttl", f"d2k-https 2 {wall}\nserved {wall} a.test\n")
write_text("dots", f"d2k-https 2 {wall}\nserved 1700003600 ...\n")
write_text(
    "state-names",
    f"d2k-https 2 {wall}\nserved 1700003600 s.test\n"
    "tls-blocked 1700003600 t.test\nclosed 1700003600 c.test\n"
    "other-name 1700003600 o.test\nunconfirmed 1700003600 u.test\n",
)
capacity = "".join(f"served 1700003600 h{index:03}.test\n" for index in range(130))
write_text("capacity", f"d2k-https 2 {wall}\n" + capacity)
write_bytes(
    "non-utf8",
    b"d2k-https 1\nserved 1700003600 a\xff.test\nclosed 1700003600 b.test\n",
)
cases.append("no-file")

(out.parent / "cases.txt").write_text("\n".join(cases) + "\n", encoding="utf-8")
PY

make -C "$D2O_ROOT/core" \
    httpsprobe.o hello.o tls13.o tls12.o p256.o tls13core.o x25519.o \
    crypto.o diagnostics.o >/dev/null
"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-httpsprobe" \
    "$ROOT/crates/r2o-controller/tests/d2o_httpsprobe_differential.c" \
    "$D2O_ROOT/core/httpsprobe.o" \
    "$D2O_ROOT/core/hello.o" \
    "$D2O_ROOT/core/tls13.o" \
    "$D2O_ROOT/core/tls12.o" \
    "$D2O_ROOT/core/p256.o" \
    "$D2O_ROOT/core/tls13core.o" \
    "$D2O_ROOT/core/x25519.o" \
    "$D2O_ROOT/core/crypto.o" \
    "$D2O_ROOT/core/diagnostics.o" \
    -lpthread
"$TEMP/d2o-httpsprobe" "$TEMP/cases" "$TEMP/cases.txt" "$TEMP/c-out" > "$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example tg_cl13_httpsprobe_trace -- \
    "$TEMP/cases" "$TEMP/cases.txt" "$TEMP/rust-out" > "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: HTTPS probe/cache differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(wc -l < "$TEMP/cases.txt")"
grep '^state 1 ' "$TEMP/c.out"
grep '^load capacity ' "$TEMP/c.out"
printf 'PASS: C/Rust HTTPS probe and cache states match (D2O %s)\n' "$ACTUAL_D2O_SHA"
