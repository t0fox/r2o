#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -P "$SCRIPT_DIR/.." && pwd)
TOOL_HOME=${R2O_TOOL_HOME:-${ROOT%/*}/r2o-tooling}
TEMP_BASE=${R2O_TEST_TMP:-$TOOL_HOME/tests}
REAL_BIN=${R2OD_REAL_BIN:-$TOOL_HOME/linux-target/release/r2o-datapath}
CC=${CC:-cc}

case "$TEMP_BASE" in
    /mnt/e/*) ;;
    *) echo "Temporary directory must be on E: $TEMP_BASE" >&2; exit 2 ;;
esac
case "$TOOL_HOME" in
    /mnt/e/*) ;;
    *) echo "Tool directory must be on E: $TOOL_HOME" >&2; exit 2 ;;
esac
[ -x "$REAL_BIN" ] || { echo "release datapath binary is missing: $REAL_BIN" >&2; exit 2; }
mkdir -p "$TEMP_BASE" "$TOOL_HOME/tests"
TEMP=$(mktemp -d "$TEMP_BASE/r2o-nfq-recv-eio.XXXXXX")
LOG=${R2O_TEST_LOG:-$TOOL_HOME/tests/r2o-nfq-ipv6-recv-eio-$(date +%F).log}
case "$LOG" in
    /mnt/e/*) ;;
    *) echo "Log path must be on E: $LOG" >&2; exit 2 ;;
esac
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared \
    "$SCRIPT_DIR/nfq-recv-eio-preload.c" -ldl -o "$TEMP/libnfq-recv-eio.so"
cat >"$TEMP/r2od-eio-launcher" <<'SH'
#!/bin/sh
LD_PRELOAD=${R2O_NFQ_EIO_PRELOAD:?} exec "${R2O_NFQ_EIO_BIN:?}" "$@"
SH
chmod +x "$TEMP/r2od-eio-launcher"

if TMPDIR="$TEMP" \
    R2OD_BIN="$TEMP/r2od-eio-launcher" \
    R2O_NFQ_EIO_PRELOAD="$TEMP/libnfq-recv-eio.so" \
    R2O_NFQ_EIO_BIN="$REAL_BIN" \
    sh "$ROOT/scripts/test-nfq-ipv6-forward-netns.sh" >"$LOG" 2>&1; then
    :
else
    cat "$LOG" >&2
    exit 1
fi

for expected in \
    'FAULT-INJECTED recv(EIO) on NFQUEUE socket' \
    'r2o-datapath: ошибка чтения NFQUEUE: Input/output error' \
    'reply=4096' \
    'tcp_reply=65536' \
    'IPv6 fail-open forwarded 33 packets' \
    'bulk_received=100' \
    'conntrack содержит IPv6 original/reply tuples' \
    'ПРОЙДЕНО: IPv6 SO_MARK'; do
    if ! grep -Fq "$expected" "$LOG"; then
        echo "Expected IPv6 recv-error recovery evidence is missing: $expected" >&2
        cat "$LOG" >&2
        exit 1
    fi
done

if [ "$(grep -Fc 'FAULT-INJECTED recv(EIO) on NFQUEUE socket' "$LOG")" -ne 1 ]; then
    echo "NFQUEUE recv(EIO) must be injected exactly once" >&2
    cat "$LOG" >&2
    exit 1
fi

grep -E 'FAULT-INJECTED|ошибка чтения NFQUEUE|reply=4096|tcp_reply=65536|fail-open forwarded|bulk_received=100|conntrack содержит|ПРОЙДЕНО: IPv6 SO_MARK' "$LOG"
printf 'IPv6 NFQUEUE recv(EIO) recovery passed; log: %s\n' "$LOG"