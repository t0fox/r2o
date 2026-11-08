#!/bin/sh
# TG11: paired C/Rust differential TLS-проверки и SNI.
#
# C-оракул — production `tg_tls_client_context`/`tg_tls_connect_fd_sni`;
# Rust — production `meta_edge::check_meta_edge_at` (нейтральный SNI
# example.com при проверке сертификата instagram.com).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-tls-sni.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make_ca() {
    name=$1
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
        -keyout "$TEMP/$name.key" -out "$TEMP/$name.pem" \
        -subj "/CN=$name" \
        -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
}
make_leaf() {
    name=$1
    domain=$2
    ca=$3
    printf 'subjectAltName=DNS:%s\nbasicConstraints=critical,CA:FALSE\n' "$domain" \
        > "$TEMP/$name.ext"
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$TEMP/$name.key" -out "$TEMP/$name.csr" \
        -subj "/CN=$domain" >/dev/null 2>&1
    openssl x509 -req -in "$TEMP/$name.csr" -days 2 \
        -CA "$TEMP/$ca.pem" -CAkey "$TEMP/$ca.key" -CAcreateserial \
        -extfile "$TEMP/$name.ext" -out "$TEMP/$name.pem" >/dev/null 2>&1
}
make_ca ca1
make_ca ca2
make_leaf instagram instagram.com ca1

OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$CC" -std=c11 -O2 -Wall -Wextra -pthread $OPENSSL_CFLAGS \
    -I"$D2O_ROOT/telegram/include" \
    -o "$TEMP/d2o-tls-sni" \
    "$ROOT/crates/r2o-telegram/tests/d2o_tls_sni_differential.c" \
    "$D2O_ROOT/telegram/src/tls.c" \
    -L/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3
"$TEMP/d2o-tls-sni" "$TEMP/instagram.pem" "$TEMP/instagram.key" \
    "$TEMP/ca1.pem" "$TEMP/ca2.pem" > "$TEMP/c.trace"

R2O_TG_TLS_CERT="$TEMP/instagram.pem" \
R2O_TG_TLS_KEY="$TEMP/instagram.key" \
R2O_TG_TLS_GOOD_CA="$TEMP/ca1.pem" \
R2O_TG_TLS_OTHER_CA="$TEMP/ca2.pem" \
R2O_TG_TLS_C_TRACE="$TEMP/c.trace" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-telegram --lib \
        d2o_tls_sni_and_hostname_verification_matches_c_trace -- --ignored \
        > "$TEMP/rust.log" 2>&1
grep -q 'test result: ok. 1 passed' "$TEMP/rust.log" || {
    cat "$TEMP/rust.log" >&2
    exit 1
}

cat "$TEMP/c.trace"
printf 'PASS: C/Rust Meta-edge TLS hostname verification and neutral SNI match (D2O %s)\n' "$ACTUAL_D2O_SHA"
