#!/bin/sh
# TG10: strict C/Rust differential публичных IP маршрутного DNS.
# C-оракул — production `route_dns.c`/`cf_domains.c`/`tls.c`; Rust —
# `route_dns`-фильтр. Закреплено на строгой ревизии a378.
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
expected_donor_sha=a378e230947ebfd011439e1cac0f1e994d883aae
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi
if ! git -C "$donor_root" diff --quiet HEAD -- \
    telegram/src/route_dns.c telegram/src/cf_domains.c telegram/src/tls.c \
    telegram/include/tg_route_dns.h telegram/include/tg_cf_domains.h \
    telegram/include/tg_tls.h; then
    printf 'D2O Telegram route-DNS sources have tracked changes\n' >&2
    exit 2
fi

donor_telegram="$donor_root/telegram"
fixture="$repo_root/crates/r2o-telegram/tests/fixtures/d2o_route_dns_public_ips.tsv"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-telegram-route-dns.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
cc=${CC:-gcc}
cargo_cmd=${CARGO:-cargo}

# Заголовки OpenSSL — из распакованного -dev пакета, runtime-библиотеки
# системные. При наличии pkg-config он главнее.
OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$cc" -std=c11 -O2 -Wall -Wextra \
    -D_POSIX_C_SOURCE=200809L -pthread $OPENSSL_CFLAGS \
    -I"$donor_telegram/include" \
    -Wl,--wrap=getaddrinfo -Wl,--wrap=socket \
    -o "$tmp_dir/d2o-route-dns" \
    "$repo_root/crates/r2o-telegram/tests/d2o_route_dns_public_ip_differential.c" \
    "$donor_telegram/src/route_dns.c" \
    "$donor_telegram/src/cf_domains.c" \
    "$donor_telegram/src/tls.c" \
    -L/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3
"$tmp_dir/d2o-route-dns" "$fixture" >"$tmp_dir/c.out"

R2O_TELEGRAM_ROUTE_DNS_DIFF_OUTPUT="$tmp_dir/rust.out" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/r2o-target}" \
    "$cargo_cmd" test -p r2o-telegram --lib \
    d2o_route_dns_public_ip_filter_matches_shared_vectors \
    --locked --offline -- --nocapture
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust Telegram route-DNS address and fallback behavior match d2o %s.\n' \
    "$actual_donor_sha"
cat "$tmp_dir/c.out"
