#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
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
cc=${CC:-clang-18}
build_dir=$(realpath --relative-to="$donor_telegram" "$tmp_dir/donor")

make -B -s -C "$donor_telegram" BUILD_DIR="$build_dir" \
    test-route-dns "CC=$cc"

"$cc" -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
    -D_POSIX_C_SOURCE=200809L -pthread \
    -I"$donor_telegram/include" \
    -Wl,--wrap=getaddrinfo -Wl,--wrap=socket \
    -o "$tmp_dir/d2o-route-dns" \
    "$repo_root/crates/r2o-telegram/tests/d2o_route_dns_public_ip_differential.c" \
    "$donor_telegram/src/route_dns.c" \
    "$donor_telegram/src/cf_domains.c" \
    "$donor_telegram/src/tls.c" -lssl -lcrypto
"$tmp_dir/d2o-route-dns" "$fixture" >"$tmp_dir/c.out"

R2O_TELEGRAM_ROUTE_DNS_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo +1.98.0 test -p r2o-telegram --lib \
    d2o_route_dns_public_ip_filter_matches_shared_vectors \
    --locked --offline -- --nocapture
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust Telegram route-DNS address and fallback behavior match d2o %s.\n' \
    "$actual_donor_sha"
cat "$tmp_dir/c.out"
