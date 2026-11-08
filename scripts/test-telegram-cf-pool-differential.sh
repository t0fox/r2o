#!/bin/sh
# TG13: paired C/Rust differential CF domain pool parse/cache.
#
# C-оракул — production `tg_cf_domain_pool_parse_remote`/`init`/`install_remote`;
# Rust — `parse_remote_domains` и `CfDomainPool` с текстовым кэшем D2O.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-cf-pool.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/parse" "$TEMP/cache"

python3 - "$TEMP" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
parse = root / "parse"
cache = root / "cache"

def write(name, data):
    if isinstance(data, str):
        data = data.encode()
    (parse / f"{name}.txt").write_bytes(data)

write("valid", "# comment\n  virkgj.com  \nvmmzovy.com\nvirkgj.com\nnot-encoded.org\n\n")
write("duplicates", "virkgj.com\nvirkgj.com\n")
write("uppercase", "VIRKGJ.COM\n")
write("whitespace", "\tvirkgj.com\t\n vmmzovy.com \n")
write("badtld", "a.1\nvirkgj.com\n")
write("longline", "a" * 300 + ".com\nvirkgj.com\n")
write("nul", b"virkgj.com\x00vmmzovy.com\n")
write("oversize", b"a" * (64 * 1024 + 1))
many = []
for index in range(33):
    first = chr(97 + index % 26)
    second = chr(97 + index // 26)
    many.append(f"{first}{second}x.com")
write("many", "\n".join(many) + "\n")

def cache_file(name, header, fetched, domains, final_newline=True):
    body = header + f"fetched_at={fetched}\n" + "\n".join(domains)
    if domains and final_newline:
        body += "\n"
    (cache / name).write_bytes(body.encode())

cache_file("valid.cache", "D2K-CF-DOMAINS 1\n", 123,
           ["Alpha.CO.UK.", "beta.co.uk", "alpha.co.uk", "gamma.co.uk"])
cache_file("valid-manual.cache", "D2K-CF-DOMAINS 1\n", 123,
           ["remote.co.uk", "beta.co.uk", "gamma.co.uk"])
cache_file("zero.cache", "D2K-CF-DOMAINS 1\n", 0,
           ["a.co.uk", "b.co.uk", "c.co.uk"])
cache_file("few.cache", "D2K-CF-DOMAINS 1\n", 123,
           ["a.co.uk", "b.co.uk"])
cache_file("nonl.cache", "D2K-CF-DOMAINS 1\n", 123,
           ["a.co.uk", "b.co.uk", "c.co.uk"], final_newline=False)
cache_file("bad-domain.cache", "D2K-CF-DOMAINS 1\n", 123,
           ["a.co.uk", "-bad.co.uk", "c.co.uk"])
cache_file("too-many.cache", "D2K-CF-DOMAINS 1\n", 123,
           [f"d{index}.co.uk" for index in range(33)])
cache_file("bad-header.cache", "D2K-CF-DOMAINS 2\n", 123,
           ["a.co.uk", "b.co.uk", "c.co.uk"])
PY
ln -s "$TEMP/cache/valid.cache" "$TEMP/cache/symlink.cache"

PARSE_NAMES="valid duplicates uppercase whitespace badtld longline nul oversize many"
POOL_CASES="valid valid-manual zero few nonl bad-domain too-many bad-header symlink missing"

OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$CC" -std=c11 -O2 -Wall -Wextra -pthread $OPENSSL_CFLAGS \
    -I"$D2O_ROOT/telegram/include" \
    -o "$TEMP/d2o-cf" \
    "$ROOT/crates/r2o-telegram/tests/d2o_cf_pool_differential.c" \
    "$D2O_ROOT/telegram/src/cf_domains.c" \
    "$D2O_ROOT/telegram/src/route_dns.c" \
    "$D2O_ROOT/telegram/src/tls.c" \
    -L/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3

# shellcheck disable=SC2086  # список имён — намеренный набор аргументов
"$TEMP/d2o-cf" parse "$TEMP/parse" $PARSE_NAMES > "$TEMP/c.out"
# shellcheck disable=SC2086
for case in $POOL_CASES; do
    case "$case" in
        valid-manual) manual=manual.co.uk ;;
        *) manual= ;;
    esac
    "$TEMP/d2o-cf" pool "$case" "$TEMP/cache/$case.cache" "$manual" >> "$TEMP/c.out"
done
"$TEMP/d2o-cf" write "$TEMP/c-cache" >> "$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg13_trace -- \
    parse "$TEMP/parse" $PARSE_NAMES > "$TEMP/rust.out"
for case in $POOL_CASES; do
    case "$case" in
        valid-manual) manual=manual.co.uk ;;
        *) manual= ;;
    esac
    "$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -q -p r2o-telegram --example tg13_trace -- \
        pool "$case" "$TEMP/cache/$case.cache" "$manual" >> "$TEMP/rust.out"
done
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg13_trace -- write "$TEMP/r-cache" >> "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: CF domain pool C/Rust differential\n' >&2
    exit 1
fi
if ! cmp "$TEMP/c-cache" "$TEMP/r-cache"; then
    printf 'FAIL: CF cache bytes differ\n' >&2
    exit 1
fi

cat "$TEMP/c.out"
printf 'PASS: C/Rust CF domain parse and D2K-CF-DOMAINS cache match (D2O %s)\n' "$ACTUAL_D2O_SHA"
