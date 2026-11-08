#!/bin/sh
# S13: live v22 control-wire — реальный D2O d2kc против production
# r2o-datapath ControlServer (без NFQUEUE, только тот же код сервера).
#
# Проверяется:
#   - C oracle test_d2kc_proto принимает только точную версию/release;
#   - v22 greeting + release id пускает d2kc, который остаётся жив;
#   - v48 greeting и чужой release отвергаются до отправки любой команды.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
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
TEMP=$(mktemp -d "$TMPDIR/r2o-control-v22-live.XXXXXX")
# AF_UNIX не поддерживается на DrvFs (E:), поэтому сокеты и трассы — в /tmp.
SOCK_TMP=$(mktemp -d /tmp/r2o-control-v22-sock.XXXXXX)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ -n "${harness_pid:-}" ]; then
        kill "$harness_pid" 2>/dev/null || true
        wait "$harness_pid" 2>/dev/null || true
    fi
    rm -rf -- "$TEMP" "$SOCK_TMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

# D2O release-сборка d2kc. Прямая native-сборка, потому что Makefile-цель
# d2kc дублирует wire.o (и archive, и ../datapath/wire.c).
(
    cd "$D2O_ROOT/core"
    "$CC" -std=c99 -O2 -Wall -Wextra \
        -Iinclude -I../datapath/include -I../detect/include \
        -DD2K_RELEASE_ID='"dev"' -o "$TEMP/d2kc" \
        d2kc.c diagnostics.c httpsprobe.c httpsearch.c httpup_logic.c sched.c \
        quichello.c plantlv.c verdict.c meas.c crypto.c quic.c quicsnap.c \
        quicsnap_reseal.c quicwire.c quicprobe.c quicarms.c ipfrag.c net4.c \
        props.c voice.c voice_discovery.c stun.c hello.c catalog.c groups.c \
        domain.c match.c compose.c measured.c link.c volume.c tls13.c tls12.c \
        p256.c tls13core.c x25519.c verify.c verify_quic_replay.c quicconn.c \
        h3.c ../detect/bridge.c ../detect/classify.c ../detect/poison.c \
        ../detect/props.c ../detect/raw.c ../detect/trigger.c \
        ../detect/response.c ../datapath/plan_parse.c ../datapath/plan_apply.c \
        ../datapath/wire.c ../datapath/wire_udp.c udpplan.c udpruntime.c -lpthread
)

# C-oracle: та же проверка точной пары version/release для реального d2kc.
(
    cd "$D2O_ROOT/core"
    "$CC" -std=c11 -O2 -Wall -Wextra \
        -Iinclude -I../datapath/include -I../runtime \
        -DD2K_RELEASE_ID='"dev"' -o "$TEMP/test_d2kc_proto" test_d2kc_proto.c
)
cp "$TEMP/d2kc" "$TEMP/c-oracle-d2kc"
(
    cd "$TEMP"
    mkdir -p "$TEMP/c-oracle"
    cp "$TEMP/d2kc" "$TEMP/c-oracle/d2kc"
    cd "$TEMP/c-oracle"
    "$TEMP/test_d2kc_proto"
)

# C/Rust differential трансляции событий: production `core/link.c` разбирает
# ровно те кадры, которые отдаёт v22-профиль r2o-datapath.
(
    cd "$D2O_ROOT"
    "$CC" -std=c11 -O2 -Wall -Wextra \
        -Icore/include -Idatapath/include -Iruntime \
        -DD2K_RELEASE_ID='"dev"' -o "$TEMP/c-v22-events" \
        "$ROOT/scripts/fixtures/control_v22_events.c" core/link.c
)
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --example v22_event_frames > "$TEMP/v22-events.frames"
"$TEMP/c-v22-events" "$TEMP/v22-events.frames" > "$TEMP/v22-events.c"
if ! diff -u "$ROOT/scripts/fixtures/control_v22_events.expected" "$TEMP/v22-events.c"; then
    printf 'FAIL: v22 event translation C/Rust differential\n' >&2
    exit 1
fi

"$CARGO" build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --example control_v22_harness
HARNESS="$ROOT/target/debug/examples/control_v22_harness"
[ -x "$HARNESS" ] || { echo "harness не собран: $HARNESS" >&2; exit 2; }

run_case() {
    wire=$1
    release=$2
    expected_rc=$3
    expected_stderr=$4
    name=$5
    sock=$SOCK_TMP/$name.sock
    trace=$SOCK_TMP/$name.trace
    : > "$trace"
    "$HARNESS" --control "$sock" --wire "$wire" --release "$release" \
        --duration-ms 3000 --trace "$trace" &
    harness_pid=$!
    attempt=0
    while [ ! -S "$sock" ] && [ "$attempt" -lt 100 ]; do
        sleep 0.05
        attempt=$((attempt + 1))
    done
    [ -S "$sock" ] || { echo "control socket не поднялся: $name" >&2; exit 1; }
    set +e
    timeout 1.5 "$TEMP/d2kc" --control "$sock" --catalog "$TEMP/$name.catalog.json" \
        --live "$TEMP/$name.live.json" >"$TEMP/$name.out" 2>"$TEMP/$name.err"
    rc=$?
    set -e
    kill "$harness_pid" 2>/dev/null || true
    wait "$harness_pid" 2>/dev/null || true
    harness_pid=
    if [ "$expected_rc" = alive ]; then
        [ "$rc" -eq 124 ] || {
            echo "$name: d2kc завершился (rc=$rc), ожидалось «жив»" >&2
            cat "$TEMP/$name.err" >&2
            exit 1
        }
    else
        [ "$rc" -eq "$expected_rc" ] || {
            echo "$name: d2kc rc=$rc, ожидался $expected_rc" >&2
            cat "$TEMP/$name.err" >&2
            exit 1
        }
    fi
    if [ -n "$expected_stderr" ]; then
        grep -q "$expected_stderr" "$TEMP/$name.err" || {
            echo "$name: в stderr нет «$expected_stderr»" >&2
            cat "$TEMP/$name.err" >&2
            exit 1
        }
    fi
    if [ -s "$trace" ]; then
        echo "$name: d2kc отправил команды до/без подтверждения профиля:" >&2
        cat "$trace" >&2
        exit 1
    fi
}

run_case v22 dev alive '' accepted-v22
run_case v22 other 1 'несовместимое приветствие' rejected-release
run_case v48 dev 1 'несовместимое приветствие' rejected-v48

printf 'PASS: real d2kc accepts v22 greeting/release and rejects v48/foreign release before any command; v22 events parse in D2O link.c (D2O %s)\n' "$ACTUAL_D2O_SHA"
