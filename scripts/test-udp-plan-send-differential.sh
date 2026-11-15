#!/bin/sh
# C/Rust differential: d2k_udp_plan_send (C core/udpruntime.c:147-190)
# против r2k-core::udp_plan::r2o_udp_plan_send_with_sink.
#
# C fixture включает production udpruntime.c и подменяет
# udp_prepare_io/udp_send_io/udp_fragment_id_io. Обычные send, TTL
# getsockopt/setsockopt и nanosleep перехватывает udp_plan_send_shim.c,
# поэтому оба процесса проходят одинаковую трассу на реальном connected
# UDP-сокете. Fragment-байты, порядок, TTL get/set/restore, delay/EINTR,
# ECONNREFUSED→-2, ошибки prepare/send и mark сравниваются побайтно.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-udp-plan-send.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

cat >"$TEMP/pass.plan" <<'EOF'
d2k-plan 1 1
id 00000000000000000000000000000000
proto udp quic
EOF
cat >"$TEMP/fake1.plan" <<'EOF'
d2k-plan 1 1
id 00000000000000000000000000000000
proto udp quic
payload 1 0011223344556677
poison 1
fake payload=1 poison=1 repeats=1 gap_us=0 place=before
order forward
EOF
cat >"$TEMP/fake25.plan" <<'EOF'
d2k-plan 1 1
id 00000000000000000000000000000000
proto udp quic
payload 1 0011223344556677
poison 1
fake payload=1 poison=1 repeats=25 gap_us=1000 place=before
order forward
EOF
cat >"$TEMP/frag1.plan" <<'EOF'
d2k-plan 1 7
id 00000000000000000000000000000000
proto udp quic
ipfrag 1
EOF
cat >"$TEMP/delay.plan" <<'EOF'
d2k-plan 1 6
id 00000000000000000000000000000000
proto udp quic
delay 15000
EOF

make -C "$D2O_ROOT/core" test_udp_runtime >"$TEMP/d2o-build.log" 2>&1
UDP_SESSION_SRC=$(make -C "$D2O_ROOT/core" -pn 2>/dev/null | sed -n 's/^UDP_SESSION_SRC = //p' | head -1)
if [ -z "$UDP_SESSION_SRC" ]; then
    echo "не удалось прочитать UDP_SESSION_SRC" >&2
    exit 2
fi
(
    cd "$D2O_ROOT/core"
    "$CC" -std=c99 -O2 -Wall -Wextra -Werror -D_GNU_SOURCE \
        -I. -Iinclude -I../datapath/include -DD2K_RELEASE_ID='"dev"' \
        -o "$TEMP/d2o-send" \
        "$ROOT/crates/r2k-core/tests/d2o_udp_plan_send_differential.c" \
        $UDP_SESSION_SRC quicarms.o quichello.o hello.o tls13core.o x25519.o meas.o \
        diagnostics.o libd2k_udp.a -lpthread
)
"$CC" -shared -fPIC -O2 -Wall -Wextra -Werror -D_GNU_SOURCE \
    -o "$TEMP/send-shim.so" \
    "$ROOT/crates/r2k-core/tests/udp_plan_send_shim.c" -ldl

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
: >"$TEMP/c.log"
: >"$TEMP/rust.log"
run_case() {
    name=$1
    family=$2
    plan=$3
    scenario=$4
    ttl=${5:-47}
    rm -f "$TEMP/c-one.out" "$TEMP/r-one.out" "$TEMP/c-one.log" "$TEMP/r-one.log" \
        "$TEMP/c-one.build" "$TEMP/r-one.build"
    R2O_UDP_PLAN_TEXT="$(cat "$TEMP/$plan.plan")" \
    R2O_UDP_PLAN_FAMILY="$family" \
    R2O_UDP_PLAN_TLV_OUT="$TEMP/$name.tlv" \
    R2O_UDP_PLAN_BUILD_OUT="$TEMP/c-one.build" \
    R2O_UDP_SEND_SCENARIO="$scenario" \
    R2O_UDP_SEND_SHIM_LOG="$TEMP/c-one.log" \
    R2O_UDP_SHIM_TTL="$ttl" \
    LD_PRELOAD="$TEMP/send-shim.so" \
        "$TEMP/d2o-send" >"$TEMP/c-one.out"
    R2O_UDP_PLAN_TLV_OUT="$TEMP/$name.tlv" \
    R2O_UDP_PLAN_FAMILY="$family" \
    R2O_UDP_PLAN_SEND_DIFF_OUTPUT="$TEMP/r-one.out" \
    R2O_UDP_PLAN_BUILD_OUT="$TEMP/r-one.build" \
    R2O_UDP_SEND_SCENARIO="$scenario" \
    R2O_UDP_SEND_SHIM_LOG="$TEMP/r-one.log" \
    R2O_UDP_SHIM_TTL="$ttl" \
    R2O_UDP_TEST_REAL_SLEEP=1 \
    LD_PRELOAD="$TEMP/send-shim.so" \
        "$RUST_BIN" --exact --nocapture \
        udp_plan::tests::udp_plan_send_differential_matches_c \
        >"$TEMP/r-$name.log" 2>&1
    if ! diff -u "$TEMP/c-one.build" "$TEMP/r-one.build"; then
        echo "FAIL build: $name" >&2
        exit 1
    fi
    if ! diff -u "$TEMP/c-one.out" "$TEMP/r-one.out"; then
        echo "FAIL output: $name" >&2
        cat "$TEMP/r-$name.log" >&2
        exit 1
    fi
    if ! diff -u "$TEMP/c-one.log" "$TEMP/r-one.log"; then
        echo "FAIL trace: $name" >&2
        exit 1
    fi
    cat "$TEMP/c-one.out" >>"$TEMP/c.out"
    cat "$TEMP/c-one.log" >>"$TEMP/c.log"
    cat "$TEMP/r-one.out" >>"$TEMP/rust.out"
    cat "$TEMP/r-one.log" >>"$TEMP/rust.log"
    printf '%s: %s\n' "$name" "$(cat "$TEMP/c-one.out")"
}

run_case pass4 4 pass pass4
run_case pass6 6 pass pass6
run_case fake1-4 4 fake1 fake1
run_case fake1-6 6 fake1 fake1
run_case fake25-4 4 fake25 fake25
run_case fake25-6 6 fake25 fake25
run_case frag1-4 4 frag1 frag4
run_case frag1-6 6 frag1 frag6
run_case delay4 4 delay delay
run_case delay-eintr4 4 delay delay_eintr
run_case ttl0-4 4 pass pass4 0
run_case ttl300-4 4 pass pass4 300
run_case send-refused4 4 pass send_refused
run_case send-error4 4 pass send_error
run_case prepare-error4 4 frag1 prepare_error
run_case raw-send-error4 4 frag1 raw_send_error

diff -u "$TEMP/c.out" "$TEMP/rust.out"
diff -u "$TEMP/c.log" "$TEMP/rust.log"
printf 'cases=%s\n' "$(grep -c '^send ' "$TEMP/c.out")"
printf 'PASS: UDP plan send C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
