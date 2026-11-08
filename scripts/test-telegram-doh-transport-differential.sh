#!/bin/sh
# TG14: paired C/Rust differential DoH-транспорта D2O.
#
# C-оракул — production `doh_lookup`/`doh_query_endpoint` из route_dns.c;
# Rust — production `resolve_cf_ips_via_doh` (POST /dns-query, DNS-wire).
# Локальный сервер в `unshare -Urn` слушает alias-IP всех четырёх endpoints
# на :443, поддерживает HTTP/1.1 и HTTP/2 (ALPN), а также сбойные режимы.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-doh-transport.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$CC" -std=c11 -O2 -Wall -Wextra $OPENSSL_CFLAGS -pthread \
    -I"$D2O_ROOT/telegram/include" -I"$D2O_ROOT/telegram/src" \
    -o "$TEMP/d2o-doh-client" \
    "$ROOT/crates/r2o-telegram/tests/d2o_doh_transport_differential.c" \
    "$D2O_ROOT/telegram/src/tls.c" \
    "$D2O_ROOT/telegram/src/cf_domains.c" \
    -L/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3

"$CARGO" build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --examples

cat > "$TEMP/inner.sh" <<INNER
set -eu
ip link set lo up
ip addr add 31.31.207.68/32 dev lo
ip addr add 1.1.1.1/32 dev lo
ip addr add 8.8.8.8/32 dev lo
ip addr add 185.222.222.222/32 dev lo
SERVER="$ROOT/target/debug/examples/doh_test_server"
RUST_CLIENT="$ROOT/target/debug/examples/tg14_doh_client"
C_CLIENT="$TEMP/d2o-doh-client"
DOMAIN=kws2.tg14.example

wait_port() {
    attempts=0
    while [ ! -s "$TEMP/port" ]; do
        attempts=\$((attempts + 1))
        [ "\$attempts" -lt 200 ] || { echo "server did not bind" >&2; exit 1; }
        sleep 0.05
    done
}

run_side() {
    side=\$1
    client=\$2
    rm -f "$TEMP/port" "$TEMP/\$side.log"
    "\$SERVER" "\$mode" "$TEMP/\$side-ca.pem" "$TEMP/port" "$TEMP/\$side.log" &
    server_pid=\$!
    wait_port
    set +e
    "\$client" "$TEMP/\$side-ca.pem" "\$DOMAIN" > "$TEMP/\$side.out" 2> "$TEMP/\$side.err"
    status=\$?
    set -e
    sleep 0.2
    kill "\$server_pid" 2>/dev/null || true
    wait "\$server_pid" 2>/dev/null || true
    [ "\$status" -eq 0 ] || { echo "client \$side failed status=\$status" >&2; cat "$TEMP/\$side.err" >&2; exit 1; }
}

for mode in valid fallback private mixed aaaa bad-id nxdomain first-down; do
    run_side c "\$C_CLIENT"
    run_side rust "\$RUST_CLIENT"
    if ! cmp "$TEMP/c.out" "$TEMP/rust.out"; then
        echo "FAIL \$mode: C/Rust DoH result differ" >&2
        echo "C:" >&2; cat "$TEMP/c.out" >&2
        echo "Rust:" >&2; cat "$TEMP/rust.out" >&2
        exit 1
    fi
    if ! diff -u "$TEMP/c.log" "$TEMP/rust.log"; then
        echo "FAIL \$mode: DoH request sequence differ" >&2
        exit 1
    fi
    printf '%s %s\n' "\$mode" "\$(cat "$TEMP/c.out")"
done
cat "$TEMP/c.log" | grep -c '^req ' > /dev/null
printf 'PASS: C/Rust DoH POST h1+h2, endpoint order and fallback match (D2O %s)\n' "$ACTUAL_D2O_SHA"
INNER

unshare -Urn sh "$TEMP/inner.sh"
