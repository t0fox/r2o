#!/bin/sh
# S14: live v22 controller ↔ реальный C datapath (ctlprobe: production
# d2k_ctlsrv_command + d2k_session, без NFQUEUE).
#
# Проверяется:
#   - r2o-controller --control-wire v22 принимает приветствие C v22;
#   - контроллер отправляет D2KP и C-датапат ставит план;
#   - v48-профиль отвергает v22-датапат до отправки команды.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}
PLAN="$ROOT/crates/r2k-core/tests/fixtures/d2kp_minimal_tcp.tlv"

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi
[ -f "$PLAN" ] || { echo "нет fixture плана: $PLAN" >&2; exit 2; }

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-control-v22-ctlprobe.XXXXXX")
SOCK_TMP=$(mktemp -d /tmp/r2o-control-v22-ctlprobe-sock.XXXXXX)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ -n "${probe_pid:-}" ]; then
        echo quit >&3 2>/dev/null || true
        exec 3>&- || true
        kill "$probe_pid" 2>/dev/null || true
        wait "$probe_pid" 2>/dev/null || true
    fi
    rm -rf -- "$TEMP" "$SOCK_TMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

# ctlprobe — единственный C-стенд без NFQUEUE с production-разбором команд и
# настоящей сессией датапата. Чистим stale Windows .o, иначе ld.lld их отвергает.
make -C "$D2O_ROOT/datapath" clean >/dev/null 2>&1 || true
make -C "$D2O_ROOT/datapath" ctlprobe CC="$CC" >/dev/null
"$CARGO" build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller
CONTROLLER="$ROOT/target/debug/r2o-controller"

start_probe() {
    name=$1
    sock=$SOCK_TMP/$name.sock
    fifo=$SOCK_TMP/$name.fifo
    mkfifo "$fifo"
    "$D2O_ROOT/datapath/ctlprobe" "$sock" < "$fifo" > "$TEMP/$name.out" 2> "$TEMP/$name.err" &
    probe_pid=$!
    # держим stdin ctlprobe открытым отдельным дескриптором
    exec 3> "$fifo"
    attempt=0
    while [ ! -S "$sock" ] && [ "$attempt" -lt 100 ]; do
        sleep 0.05
        attempt=$((attempt + 1))
    done
    [ -S "$sock" ] || { echo "ctlprobe $name не поднялся" >&2; cat "$TEMP/$name.err" >&2; exit 1; }
    PROBE_SOCK=$sock
}

stop_probe() {
    name=$1
    echo plans >&3 || true
    echo quit >&3 || true
    exec 3>&- || true
    wait "$probe_pid" 2>/dev/null || true
    probe_pid=
    cat "$TEMP/$name.out" > "$TEMP/$name.summary"
}

start_probe accepted
set +e
"$CONTROLLER" --control-wire v22 --control-release-id dev \
    --set-name "$PROBE_SOCK" example.com 4 modern "$PLAN" \
    > "$TEMP/accepted.ctl.out" 2> "$TEMP/accepted.ctl.err"
rc=$?
set -e
[ "$rc" -eq 0 ] || {
    echo "v22 controller rc=$rc" >&2
    cat "$TEMP/accepted.ctl.err" >&2
    exit 1
}
grep -q 'план установлен: example.com' "$TEMP/accepted.ctl.out"
stop_probe accepted
grep -Fq 'planов 1, команд принято 1, отвергнуто 0' "$TEMP/accepted.summary" || {
    echo "C-датапат не подтвердил установку плана:" >&2
    cat "$TEMP/accepted.summary" >&2
    exit 1
}

start_probe rejected
set +e
"$CONTROLLER" --control-wire v48 \
    --set-name "$PROBE_SOCK" example.com 4 modern "$PLAN" \
    > "$TEMP/rejected.ctl.out" 2> "$TEMP/rejected.ctl.err"
rc=$?
set -e
[ "$rc" -ne 0 ] || { echo "v48 controller принял v22-датапат" >&2; exit 1; }
grep -q 'несовместимый r2o-datapath: wire=22' "$TEMP/rejected.ctl.err" || {
    echo "v48 отказ не назван несовместимым приветствием:" >&2
    cat "$TEMP/rejected.ctl.err" >&2
    exit 1
}
stop_probe rejected
grep -Fq 'planов 0, команд принято 0, отвергнуто 0' "$TEMP/rejected.summary" || {
    echo "v48-контроллер отправил команду до проверки профиля:" >&2
    cat "$TEMP/rejected.summary" >&2
    exit 1
}

printf 'PASS: v22 controller installs D2KP into production C ctlprobe; v48 is rejected before any command (D2O %s)\n' "$ACTUAL_D2O_SHA"
