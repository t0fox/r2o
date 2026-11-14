#!/bin/sh
# C/Rust differential: IPv6-fragment route/neighbor/prepare на veth.
#
# Проверяются RTM_GETROUTE (src/dst/mark), RTM_GETNEIGH (NDA_DST/NDA_LLADDR),
# HWADDR/MAC и MTU>=1280 без реальной отправки. Требуется CAP_NET_ADMIN —
# скрипт сам переисполняется через `unshare -Urn`.
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
VETH0="r2f6c$$"
VETH1="r2f6s$$"

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi
for tool in ip; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "required command is missing: $tool" >&2
        exit 1
    }
done

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-ip6frag-route.XXXXXX")
cleanup() {
    ip link del "$VETH0" 2>/dev/null || true
    rm -rf -- "$TEMP"
}
trap cleanup EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-ip6frag-route" \
    "$ROOT/crates/r2o-datapath/tests/d2o_ip6frag_route_differential.c"

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

ip link add "$VETH0" type veth peer name "$VETH1"
ip link set "$VETH1" up
ip addr add fd00::1/64 dev "$VETH0" nodad
ip link set "$VETH0" up
ip link set "$VETH0" mtu 1500
ip -6 neigh add fd00::2 lladdr 02:11:22:33:44:55 dev "$VETH0" nud permanent

run_case() {
    label=$1
    "$TEMP/d2o-ip6frag-route" >"$TEMP/c-$label.out"
    R2O_IP6FRAG_ROUTE_DIFF_OUTPUT="$TEMP/rust-$label.out" \
        "$RUST_BIN" --exact --nocapture \
        raw::tests::ip6frag_route_neighbor_differential_matches_c \
        >"$TEMP/rust-$label.log" 2>&1
    cat "$TEMP/c-$label.out" >>"$TEMP/c.out"
    cat "$TEMP/rust-$label.out" >>"$TEMP/rust.out"
}

: >"$TEMP/c.out"
: >"$TEMP/rust.out"
run_case mtu1500
ip link set "$VETH0" mtu 1280
run_case mtu1280

if [ "${R2O_SHOW_OUTPUT:-0}" = 1 ]; then
    cat "$TEMP/c.out"
fi
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: IPv6 fragment route/neighbor/prepare C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
