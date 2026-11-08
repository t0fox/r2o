#!/bin/sh
# S15: live v22 controller принимает C SUSPECT/EXCHANGE и связывает их с
# Discovery. C-стенд использует production d2k_session + d2k_ctlsrv_pump.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-control-v22-legacy.XXXXXX")
SOCK_TMP=$(mktemp -d /tmp/r2o-control-v22-legacy-sock.XXXXXX)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ -n "${ctl_pid:-}" ]; then
        kill "$ctl_pid" 2>/dev/null || true
        wait "$ctl_pid" 2>/dev/null || true
    fi
    if [ -n "${harness_pid:-}" ]; then
        echo quit >&3 2>/dev/null || true
        exec 3>&- 2>/dev/null || true
        kill "$harness_pid" 2>/dev/null || true
        wait "$harness_pid" 2>/dev/null || true
    fi
    rm -rf -- "$TEMP" "$SOCK_TMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

make -C "$D2O_ROOT/datapath" clean >/dev/null 2>&1 || true
make -C "$D2O_ROOT/datapath" ctlprobe CC="$CC" >/dev/null
(
    cd "$D2O_ROOT/datapath"
    "$CC" -std=c99 -O2 -Wall -Wextra \
        -Iinclude -I../core/include -DD2K_RELEASE_ID='"dev"' \
        -o "$TEMP/legacy-events" "$ROOT/scripts/fixtures/control_v22_legacy_events.c" \
        icmpguard.o http80.o http_trace.o addr.o plan_parse.o plan_apply.o tls.o \
        capture.o hold.o udp_hold.o udp_release.o udp_path.o routemark.o wire.o \
        wire_udp.o track.o session.o nat.o nl.o ctq.o sched.o journal.o plans.o \
        ctl.o ctlsrv.o core_quic.o core_quicwire.o core_quicsnap.o core_crypto.o \
        core_ipfrag.o core_httpup_logic.o
)
"$CARGO" build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller
CONTROLLER="$ROOT/target/debug/r2o-controller"

SOCK=$SOCK_TMP/control.sock
FIFO=$SOCK_TMP/in
mkfifo "$FIFO"
printf '{"schema":1,"boxes":[]}' > "$TEMP/catalog.json"
"$TEMP/legacy-events" "$SOCK" < "$FIFO" > "$TEMP/harness.out" 2> "$TEMP/harness.err" &
harness_pid=$!
exec 3> "$FIFO"
attempt=0
while [ ! -S "$SOCK" ] && [ "$attempt" -lt 100 ]; do
    sleep 0.05
    attempt=$((attempt + 1))
done
[ -S "$SOCK" ] || { echo "C-стенд не поднял сокет" >&2; cat "$TEMP/harness.err" >&2; exit 1; }

"$CONTROLLER" --control-wire v22 --control-release-id dev \
    --serve "$SOCK" "$TEMP/catalog.json" --discover \
    > "$TEMP/controller.out" 2> "$TEMP/controller.err" &
ctl_pid=$!
attempt=0
while ! grep -q 'наблюдение и автопоиск активны' "$TEMP/controller.out" 2>/dev/null; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 100 ] || {
        echo "контроллер не подключился к C-стенду" >&2
        cat "$TEMP/controller.err" >&2
        exit 1
    }
    sleep 0.05
done

echo 'hello legacy.example.com' >&3
sleep 0.4
echo 'rst-same' >&3
sleep 1.2
echo 'hello clean.example.com' >&3
sleep 0.4
echo 'reply 22' >&3
sleep 0.8
echo quit >&3
exec 3>&-
kill "$ctl_pid" 2>/dev/null || true
wait "$ctl_pid" 2>/dev/null || true
ctl_pid=
wait "$harness_pid" 2>/dev/null || true
harness_pid=

grep -Fq 'v22 SUSPECT legacy.example.com: подозрение без плана — поставлено в очередь Discovery' \
    "$TEMP/controller.out" || {
    echo "SUSPECT v22 не связан с Discovery:" >&2
    cat "$TEMP/controller.out" >&2
    exit 1
}
grep -Fq 'v22 EXCHANGE clean.example.com: ответ сервера без плана отмечен как чистое рукопожатие' \
    "$TEMP/controller.out" || {
    echo "EXCHANGE v22 не отмечен как чистое рукопожатие:" >&2
    cat "$TEMP/controller.out" >&2
    exit 1
}
if grep -Fq 'v22 SUSPECT legacy.example.com: нет свежего HELLO' "$TEMP/controller.out"; then
    echo "SUSPECT не нашёл HELLO того же ключа" >&2
    exit 1
fi

printf 'PASS: C SUSPECT/EXCHANGE v22 reach R2O Discovery through the real C session pump (D2O %s)\n' "$ACTUAL_D2O_SHA"
