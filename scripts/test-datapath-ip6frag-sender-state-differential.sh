#!/bin/sh
# C/Rust differential: состояние d2k_ip6frag_sender и RawSocket IPv4/IPv6.
#
# C: d2k_ip6frag_sender_init/close (идемпотентность, fd=-1) и send после
# close без маршрута → ENETUNREACH. Rust: R2oIp6FragSender::default,
# повторный сброс fd и r2o_send после close. Дополнительно Rust unit
# проверяет RawSocket::open/Drop для AF_INET/AF_INET6, закрытие fd и
# отсутствие утечки на 32 циклах.
#
# Нужен CAP_NET_RAW; скрипт сам переисполняется через `unshare -Urn`.
set -eu

if [ -z "${R2O_IN_USERNS:-}" ] && [ "$(id -u)" -ne 0 ]; then
    R2O_IN_USERNS=1 exec unshare -Urn sh "$0" "$@"
fi

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
TEMP=$(mktemp -d "$TMPDIR/r2o-ip6frag-sender-state.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-sender-state" \
    "$ROOT/crates/r2o-datapath/tests/d2o_ip6frag_sender_state_differential.c" -lm

cd "$ROOT"
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib --no-run >"$TEMP/build.log" 2>&1
RUST_BIN=$(sed -n 's/.*Executable unittests src\/lib.rs (\(.*\))/\1/p' "$TEMP/build.log" | tail -1)
if [ -z "$RUST_BIN" ]; then
    echo "не найден тестовый бинарник r2o-datapath lib" >&2
    cat "$TEMP/build.log" >&2
    exit 2
fi
case "$RUST_BIN" in
    /*) ;;
    *) RUST_BIN="$ROOT/$RUST_BIN" ;;
esac

ip link set lo up
"$TEMP/d2o-sender-state" >"$TEMP/c.out"
R2O_IP6FRAG_SENDER_STATE_OUTPUT="$TEMP/rust.out" \
    "$RUST_BIN" --ignored --exact --nocapture \
    raw::tests::ip6frag_sender_state_differential_matches_c \
    >"$TEMP/rust.log" 2>&1
diff -u "$TEMP/c.out" "$TEMP/rust.out"
"$RUST_BIN" --ignored --exact --nocapture \
    raw::tests::raw_socket_open_drop_ipv4_ipv6 >"$TEMP/raw.log" 2>&1
printf 'cases=1\n'
printf 'PASS: ip6frag sender state C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
