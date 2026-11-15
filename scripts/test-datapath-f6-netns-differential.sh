#!/bin/sh
# Живой netns differential: d2k_f6_route/d2k_f6_neighbor на реальном ядре.
#
# Проверяются ветви, которые нельзя гарантировать shim'ом:
#   - RTN_UNREACHABLE и полное отсутствие маршрута;
#   - RTN_LOCAL (::1);
#   - policy route по ненулевому RTA_MARK (fwmark 0x2e) и неверной метке;
#   - NUD PERMANENT/STALE/DELAY/PROBE/REACHABLE на veth;
#   - отсутствие соседа → EHOSTUNREACH.
#
# C production d2k_f6_route/neighbor и Rust production r2o_f6_route/neighbor
# запускаются в ОДНОМ netns; вывод сравнивается побайтно. Скрипт сам
# переисполняется через `unshare -Urn`; root на хосте не нужен.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-f6-netns.XXXXXX")
cleanup() {
    ip link del f6v0 2>/dev/null || true
    rm -rf -- "$TEMP"
}
trap cleanup EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-f6-live" \
    "$ROOT/crates/r2o-datapath/tests/d2o_f6_netlink_differential.c" -lm

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
ip link add f6v0 type veth peer name f6v1
ip link set f6v1 up
ip addr add fd00::1/64 dev f6v0 nodad
ip link set f6v0 up
ip -6 route add fd00::2/128 dev f6v0

: >"$TEMP/c.out"
: >"$TEMP/rust.out"
run_case() {
    name=$1
    shift
    env "$@" LD_PRELOAD= "$TEMP/d2o-f6-live" >"$TEMP/c-one.out"
    env "$@" R2O_F6_DIFF_OUTPUT="$TEMP/rust-one.out" \
        LD_PRELOAD= "$RUST_BIN" --ignored --exact --nocapture \
        raw::tests::f6_netlink_differential_matches_c \
        >"$TEMP/rust-$name.log" 2>&1
    if ! diff -u "$TEMP/c-one.out" "$TEMP/rust-one.out"; then
        echo "FAIL: $name" >&2
        cat "$TEMP/rust-$name.log" >&2
        exit 1
    fi
    printf '=== %s\n' "$name"
    cat "$TEMP/c-one.out"
    cat "$TEMP/c-one.out" >>"$TEMP/c.out"
    cat "$TEMP/rust-one.out" >>"$TEMP/rust.out"
}

ip -6 neigh replace fd00::2 lladdr 02:11:22:33:44:55 dev f6v0 nud permanent
run_case permanent

ip -6 neigh replace fd00::2 lladdr 02:11:22:33:44:55 dev f6v0 nud stale
run_case stale

ip -6 neigh replace fd00::2 lladdr 02:11:22:33:44:55 dev f6v0 nud delay
run_case delay

ip -6 neigh replace fd00::2 lladdr 02:11:22:33:44:55 dev f6v0 nud probe
run_case probe

ip -6 neigh replace fd00::2 lladdr 02:11:22:33:44:55 dev f6v0 nud reachable
run_case reachable

ip -6 neigh del fd00::2 dev f6v0
run_case no_neighbor

# Ядро на `unreachable` отдаёт EHOSTUNREACH (113); ENETUNREACH (101)
# получаем на полностью отсутствующем маршруте.
ip -6 route add unreachable 2001:db8:dead::/64
run_case unreachable R2O_F6_DST=2001:db8:dead::1 \
    R2O_F6_MARK=0 R2O_F6_SKIP_NEIGHBOR=1
run_case no_route R2O_F6_DST=2001:db8:ffff::1 \
    R2O_F6_MARK=0 R2O_F6_SKIP_NEIGHBOR=1

run_case local R2O_F6_SRC=::1 R2O_F6_DST=::1 \
    R2O_F6_MARK=0 R2O_F6_SKIP_NEIGHBOR=1

ip -6 rule add fwmark 0x2e table 100
ip -6 route add 2001:db8:2::/64 dev f6v0 table 100
run_case policy_mark R2O_F6_DST=2001:db8:2::1 \
    R2O_F6_MARK=46 R2O_F6_SKIP_NEIGHBOR=1
run_case policy_wrong_mark R2O_F6_DST=2001:db8:2::1 \
    R2O_F6_MARK=47 R2O_F6_SKIP_NEIGHBOR=1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(grep -c '^route ' "$TEMP/c.out")"
printf 'PASS: live f6 route/neighbor C/Rust match in netns (D2O %s)\n' "$ACTUAL_D2O_SHA"
