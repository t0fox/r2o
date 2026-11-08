#!/bin/sh
# TG21: strict C/Rust differential наблюдателя ответов MTProto.
# C-оракул — production `epoll_proxy.c:observe_mtproto_response`; Rust —
# `response_observer.rs`. Закреплено на строгой ревизии a378.
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
expected_donor_sha=${R2O_EXPECTED_DONOR_SHA:-a378e230947ebfd011439e1cac0f1e994d883aae}
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi
if ! git -c core.autocrlf=true -C "$donor_root" diff --quiet HEAD -- \
    telegram/src/epoll_proxy.c telegram/src/mtproto_crypto.c \
    telegram/include/tg_epoll_proxy.h telegram/include/tg_mtproto.h \
    telegram/include/tg_mtproto_splitter.h; then
    printf 'D2O Telegram response-observer sources have tracked changes\n' >&2
    exit 2
fi

donor_telegram="$donor_root/telegram"
fixture="$repo_root/crates/r2o-telegram/tests/fixtures/d2o_mtproto_response_observer.tsv"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-telegram-response-observer.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
cc=${CC:-gcc}
cargo_cmd=${CARGO:-cargo}

# Заголовки OpenSSL/zlib в этом окружении — из распакованных -dev пакетов,
# runtime-библиотеки системные. При наличии pkg-config он главнее.
OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
ZLIB_CFLAGS=$(pkg-config --cflags zlib 2>/dev/null || true)
ZLIB_LIBS=$(pkg-config --libs zlib 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi
if [ -z "$ZLIB_CFLAGS" ]; then
    ZLIB_CFLAGS="-I/tmp/zlib-dev/usr/include"
fi
if [ -z "$ZLIB_LIBS" ]; then
    ZLIB_LIBS="-L/lib/x86_64-linux-gnu -l:libz.so.1"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$cc" -std=c11 -O2 -Wall -Wextra \
    -D_POSIX_C_SOURCE=200809L \
    -DR2O_D2O_EPOLL_PROXY_SOURCE='"'"$donor_telegram/src/epoll_proxy.c"'"' \
    -I"$donor_telegram/include" $OPENSSL_CFLAGS $ZLIB_CFLAGS -pthread \
    -o "$tmp_dir/d2o-response-observer" \
    "$repo_root/crates/r2o-telegram/tests/d2o_mtproto_response_observer_differential.c" \
    "$donor_telegram/src/stats_socket.c" "$donor_telegram/src/limits.c" \
    "$donor_telegram/src/listener.c" "$donor_telegram/src/tls.c" \
    "$donor_telegram/src/ws.c" "$donor_telegram/src/ws_pump.c" \
    "$donor_telegram/src/memory_budget.c" "$donor_telegram/src/mtproto_crypto.c" \
    "$donor_telegram/src/mtproto_splitter.c" "$donor_telegram/src/cf_domains.c" \
    "$donor_telegram/src/route_plan.c" "$donor_telegram/src/route_dns.c" \
    -L/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3 $ZLIB_LIBS

"$tmp_dir/d2o-response-observer" "$fixture" >"$tmp_dir/c.out"
if R2O_TELEGRAM_RESPONSE_DIFF_OUTPUT="$tmp_dir/rust.out" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/r2o-target}" \
    "$cargo_cmd" test --locked --offline -p r2o-telegram --lib \
    observer_matches_d2o_mtproto_response_vectors >"$tmp_dir/rust.log" 2>&1; then
    cat "$tmp_dir/rust.log"
else
    cat "$tmp_dir/rust.log"
    exit 1
fi

diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust Telegram response-observer behavior matches d2o %s.\n' \
    "$actual_donor_sha"
cat "$tmp_dir/c.out"
