#!/bin/sh
# C/Rust differential: d2k_udp_plan_build (C core/udpruntime.c:33-93)
# против r2k-core::udp_plan::r2o_udp_plan_batch на отказах.
#
# C fixture включает production udpruntime.c и в режиме
# R2O_UDP_PLAN_BUILD_ONLY вызывает d2k_udp_plan_build; Rust test в том же
# режиме вызывает r2o_udp_plan_batch. Сравниваются код и отсутствие
# частичных байтов (build rc=0/-1).
#
# HOLD и ipfrag-с-poison/pre/seq — защитные ветви, недостижимые из
# текстового плана (C d2k_plan_apply не порождает HOLD, а парсер не
# пропускает ipfrag с этими полями); они отмечены в отчёте, а не
# подменены фиктивным планом.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-udp-plan-build.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

cat >"$TEMP/pass.plan" <<'EOF'
d2k-plan 1 1
id 00000000000000000000000000000000
proto udp quic
EOF
cat >"$TEMP/tcp.plan" <<'EOF'
d2k-plan 1 1
id 00000000000000000000000000000000
proto tcp tls
EOF
cat >"$TEMP/split.plan" <<'EOF'
d2k-plan 1 1
id 00000000000000000000000000000000
proto udp quic
payload 1 0011223344556677
split payload_start +1
order forward
EOF
cat >"$TEMP/ipidzero.plan" <<'EOF'
d2k-plan 1 1
id 00000000000000000000000000000000
proto udp quic
payload 1 0011223344556677
poison 1 ipidzero
fake payload=1 poison=1 repeats=1 gap_us=0 place=before
order forward
EOF
cat >"$TEMP/fake26.plan" <<'EOF'
d2k-plan 1 1
id 00000000000000000000000000000000
proto udp quic
payload 1 0011223344556677
poison 1
fake payload=1 poison=1 repeats=26 gap_us=0 place=before
order forward
EOF
cat >"$TEMP/frag1.plan" <<'EOF'
d2k-plan 1 7
id 00000000000000000000000000000000
proto udp quic
ipfrag 1
EOF

make -C "$D2O_ROOT/core" test_udp_runtime >"$TEMP/d2o-build.log" 2>&1
UDP_SESSION_SRC=$(make -C "$D2O_ROOT/core" -pn 2>/dev/null | sed -n 's/^UDP_SESSION_SRC = //p' | head -1)
(
    cd "$D2O_ROOT/core"
    "$CC" -std=c99 -O2 -Wall -Wextra -Werror -D_GNU_SOURCE \
        -I. -Iinclude -I../datapath/include -DD2K_RELEASE_ID='"dev"' \
        -o "$TEMP/d2o-build" \
        "$ROOT/crates/r2k-core/tests/d2o_udp_plan_send_differential.c" \
        $UDP_SESSION_SRC quicarms.o quichello.o hello.o tls13core.o x25519.o meas.o \
        diagnostics.o libd2k_udp.a -lpthread
)

cd "$ROOT"
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --lib --no-run >"$TEMP/rust-build.log" 2>&1
RUST_BIN=$(sed -n 's/.*Executable unittests src\/lib.rs (\(.*\))/\1/p' "$TEMP/rust-build.log" | tail -1)
if [ -z "$RUST_BIN" ]; then
    echo "не найден тестовый бинарник r2k-core lib" >&2
    cat "$TEMP/rust-build.log" >&2
    exit 2
fi
case "$RUST_BIN" in
    /*) ;;
    *) RUST_BIN="$ROOT/$RUST_BIN" ;;
esac

: >"$TEMP/c.out"
: >"$TEMP/rust.out"
run_case() {
    name=$1
    family=$2
    plan=$3
    empty=${4:-}
    rm -f "$TEMP/$name.tlv" "$TEMP/c-one.out" "$TEMP/r-one.out"
    if [ -n "$empty" ]; then
        R2O_UDP_PLAN_TEXT="$(cat "$TEMP/$plan.plan")" \
        R2O_UDP_PLAN_FAMILY="$family" \
        R2O_UDP_PLAN_TLV_OUT="$TEMP/$name.tlv" \
        R2O_UDP_PLAN_BUILD_ONLY=1 \
        R2O_UDP_PLAN_EMPTY=1 \
        LD_PRELOAD= \
            "$TEMP/d2o-build" >"$TEMP/c-one.out"
        R2O_UDP_PLAN_TLV_OUT="$TEMP/$name.tlv" \
        R2O_UDP_PLAN_FAMILY="$family" \
        R2O_UDP_PLAN_BUILD_ONLY=1 \
        R2O_UDP_PLAN_EMPTY=1 \
        R2O_UDP_PLAN_BUILD_DIFF_OUTPUT="$TEMP/r-one.out" \
        LD_PRELOAD= \
            "$RUST_BIN" --exact --nocapture \
            udp_plan::tests::udp_plan_send_differential_matches_c \
            >"$TEMP/r-$name.log" 2>&1
    else
        R2O_UDP_PLAN_TEXT="$(cat "$TEMP/$plan.plan")" \
        R2O_UDP_PLAN_FAMILY="$family" \
        R2O_UDP_PLAN_TLV_OUT="$TEMP/$name.tlv" \
        R2O_UDP_PLAN_BUILD_ONLY=1 \
        LD_PRELOAD= \
            "$TEMP/d2o-build" >"$TEMP/c-one.out"
        R2O_UDP_PLAN_TLV_OUT="$TEMP/$name.tlv" \
        R2O_UDP_PLAN_FAMILY="$family" \
        R2O_UDP_PLAN_BUILD_ONLY=1 \
        R2O_UDP_PLAN_BUILD_DIFF_OUTPUT="$TEMP/r-one.out" \
        LD_PRELOAD= \
            "$RUST_BIN" --exact --nocapture \
            udp_plan::tests::udp_plan_send_differential_matches_c \
            >"$TEMP/r-$name.log" 2>&1
    fi
    if ! diff -u "$TEMP/c-one.out" "$TEMP/r-one.out"; then
        echo "FAIL: $name" >&2
        cat "$TEMP/r-$name.log" >&2
        exit 1
    fi
    cat "$TEMP/c-one.out" >>"$TEMP/c.out"
    cat "$TEMP/r-one.out" >>"$TEMP/rust.out"
    printf '%s: %s\n' "$name" "$(cat "$TEMP/c-one.out")"
}

run_case pass4 4 pass
run_case frag1-4 4 frag1
run_case frag1-6 6 frag1
run_case empty4 4 pass empty
run_case tcp4 4 tcp
run_case split4 4 split
run_case ipidzero4 4 ipidzero
run_case fake26-4 4 fake26

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=8\n'
printf 'PASS: UDP plan build refusal C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
