#!/bin/sh
# B46: paired differential Telegram watchdog health contract.
#
# Проверяется:
#   - heartbeat-файл, записанный Rust `HealthWriter`, принимают оба сторожа
#     (C files/d2k-tg-watchdog.sh и router/r2o-telegram-watchdog.sh);
#   - missing/stale/ready=0/чужой start_ticks дают одинаковый перезапуск;
#   - лимит перезапусков и маркер limited совпадают.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CARGO=${CARGO:-cargo}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TMP=$(mktemp -d /tmp/r2o-tg-health.XXXXXX)
cleanup() {
    [ -z "${emit_pid:-}" ] || kill "$emit_pid" 2>/dev/null || true
    rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM

cat > "$TMP/firewall" <<'SH'
#!/bin/sh
printf '%s\n' "$1" >> "$WATCHDOG_FIREWALL_CALLS"
SH
cat > "$TMP/init" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$WATCHDOG_INIT_CALLS"
SH
mkdir -p "$TMP/cdir"
cp "$TMP/firewall" "$TMP/cdir/d2k-tg-firewall.sh"
chmod 0755 "$TMP/firewall" "$TMP/init" "$TMP/cdir/d2k-tg-firewall.sh"
# D2O checkout на DrvFs хранит CRLF; для sh нужен LF-вариант.
tr -d '\r' < "$D2O_ROOT/files/d2k-tg-watchdog.sh" > "$TMP/c-watchdog.sh"
chmod 0755 "$TMP/c-watchdog.sh"

"$CARGO" build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --example health_emit >/dev/null
EMIT=$ROOT/target/debug/examples/health_emit

boot_id=$(cat /proc/sys/kernel/random/boot_id)
start_ticks=$(awk '{ sub(/^.*\) /, ""); print $20 }' "/proc/$$/stat")

write_health() {
    path=$1
    heartbeat=$2
    ready=$3
    ticks=$4
    boot=$5
    printf 'D2KH1 %s %s %s %s test 48 - 0 %s 0\n' \
        "$$" "$ticks" "$heartbeat" "$boot" "$ready" > "$path"
}

run_impl() {
    impl=$1
    name=$2
    health=$3
    expected_restarts=$4
    expect_limited=$5
    require_firewall=$6
    dir=$TMP/$name-$impl
    mkdir -p "$dir/state"
    : > "$dir/init.calls"
    : > "$dir/fw.calls"
    if [ "$impl" = c ]; then
        watchdog=$TMP/c-watchdog.sh
        impl_env="TG_WATCHDOG_DIR=$TMP/cdir"
    else
        watchdog=$ROOT/router/r2o-telegram-watchdog.sh
        impl_env="R2O_TG_FIREWALL=$TMP/firewall TG_ENABLED=1 TG_MODE=local"
    fi
    set +e
    # shellcheck disable=SC2086  # impl_env — намеренный набор VAR=VALUE
    timeout 3 env $impl_env \
        TG_WATCHDOG_INIT="$TMP/init" \
        TG_WATCHDOG_HEALTH="$health" \
        TG_WATCHDOG_STATE="$dir/state/failures" \
        TG_WATCHDOG_RESTARTS="$dir/state/restarts" \
        TG_WATCHDOG_LIMITED="$dir/state/limited" \
        TG_WATCHDOG_INTERVAL=1 \
        TG_WATCHDOG_FAILURE_LIMIT=1 \
        TG_WATCHDOG_RESTART_WINDOW=900 \
        TG_WATCHDOG_MAX_RESTARTS=1 \
        TG_WATCHDOG_BACKOFF_BASE=1 \
        TG_WATCHDOG_BACKOFF_MAX=1 \
        WATCHDOG_INIT_CALLS="$dir/init.calls" \
        WATCHDOG_FIREWALL_CALLS="$dir/fw.calls" \
        sh "$watchdog" run >/dev/null 2>&1
    rc=$?
    set -e
    [ "$rc" -eq 124 ] || {
        echo "$impl/$name: watchdog завершился rc=$rc вместо цикла" >&2
        exit 1
    }
    restarts=$(wc -l < "$dir/init.calls" | tr -d ' ')
    [ "$restarts" -eq "$expected_restarts" ] || {
        echo "$impl/$name: перезапусков $restarts, ожидалось $expected_restarts" >&2
        cat "$dir/init.calls" >&2
        exit 1
    }
    if [ "$expect_limited" = 1 ]; then
        [ -e "$dir/state/limited" ] || {
            echo "$impl/$name: нет маркера restart-limited" >&2
            exit 1
        }
    else
        [ ! -e "$dir/state/limited" ] || {
            echo "$impl/$name: неожиданный restart-limited" >&2
            exit 1
        }
    fi
    if [ "$require_firewall" = 1 ] && [ ! -s "$dir/fw.calls" ]; then
        echo "$impl/$name: watchdog не вызвал firewall heal" >&2
        exit 1
    fi
}

run_case() {
    name=$1
    health=$2
    expected_restarts=$3
    expect_limited=$4
    require_firewall=$5
    if [ -n "$health" ]; then
        run_impl c "$name" "$health" "$expected_restarts" "$expect_limited" "$require_firewall"
        run_impl rust "$name" "$health" "$expected_restarts" "$expect_limited" "$require_firewall"
    fi
}

# 1. Rust producer → оба сторожа видят свежий heartbeat и не перезапускают.
health_emit_path=$TMP/rust-health
"$EMIT" "$health_emit_path" 15 1 &
emit_pid=$!
attempt=0
while [ ! -s "$health_emit_path" ] && [ "$attempt" -lt 100 ]; do
    sleep 0.05
    attempt=$((attempt + 1))
done
[ -s "$health_emit_path" ] || { echo "health_emit не создал файл" >&2; exit 1; }
run_impl c rust-fresh "$health_emit_path" 0 0 1
run_impl rust rust-fresh "$health_emit_path" 0 0 1
kill "$emit_pid" 2>/dev/null || true
wait "$emit_pid" 2>/dev/null || true
emit_pid=

now_ms=$(awk '{ printf "%.0f", $1 * 1000 }' /proc/uptime)

write_health "$TMP/missing" 0 1 "$start_ticks" "$boot_id"
rm -f "$TMP/missing"
run_case missing "$TMP/missing" 1 1 1

write_health "$TMP/stale" "$((now_ms - 60000))" 1 "$start_ticks" "$boot_id"
run_case stale "$TMP/stale" 1 1 1

write_health "$TMP/not-ready" "$now_ms" 0 "$start_ticks" "$boot_id"
run_case not-ready "$TMP/not-ready" 1 1 1

write_health "$TMP/wrong-ticks" "$now_ms" 1 "$((start_ticks + 1))" "$boot_id"
run_case wrong-ticks "$TMP/wrong-ticks" 1 1 1

write_health "$TMP/wrong-boot" "$now_ms" 1 "$start_ticks" "00000000-0000-0000-0000-000000000000"
run_case wrong-boot "$TMP/wrong-boot" 1 1 1

printf 'PASS: C/Rust Telegram watchdog accept the Rust D2KH1 heartbeat and agree on stale/missing/malformed restarts (D2O %s)\n' "$ACTUAL_D2O_SHA"
