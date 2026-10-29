#!/bin/sh
set -eu

r2o_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_temp=$(mktemp -d)
r2o_cleanup() {
    r2o_status=$?
    trap - EXIT HUP INT TERM
    env R2O_DIR="$r2o_temp/root" R2O_CONFIG="$r2o_temp/root/config" \
        R2O_MANAGER="$r2o_temp/manager" R2O_FIREWALL="$r2o_temp/firewall" \
        R2O_PPE_ADAPTER="$r2o_temp/ppe" R2O_LOG_MAINTENANCE="$r2o_temp/no-log-worker" \
        R2O_PROC=/proc R2O_RUNTIME_DIR="$r2o_temp/runtime" \
        R2O_NFQUEUE_STATUS="$r2o_temp/proc/net/netfilter/nfnetlink_queue" \
        sh "$r2o_root/router/S99r2o" engine-stop >/dev/null 2>&1 || true
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_temp/launches" ]; then
        cat "$r2o_temp/launches" >&2
    fi
    rm -rf "$r2o_temp"
    exit "$r2o_status"
}
trap r2o_cleanup EXIT HUP INT TERM

mkdir -p "$r2o_temp/root/releases/test/builds" "$r2o_temp/proc/net/netfilter"
cp /bin/sleep "$r2o_temp/root/releases/test/builds/r2o-datapath-linux-test"
cp /bin/sleep "$r2o_temp/root/releases/test/builds/r2o-controller-linux-test"
cp /bin/sleep "$r2o_temp/root/releases/test/builds/r2o-panel-linux-test"
chmod 0755 "$r2o_temp/root/releases/test/builds/"*
cat >"$r2o_temp/root/config" <<EOF
MODE=observe
MARK=0x2d
PROBE_MARK=0x2e
ONLY_MARK=0xffffaaa/0xffffff00
R2O_FLOW_CAPACITY=64
IPV6_ENABLED=1
EOF
printf '2000 1\n2001 1\n' >"$r2o_temp/proc/net/netfilter/nfnetlink_queue"
cat >"$r2o_temp/manager" <<'EOF'
#!/bin/sh
set -eu
[ "${1:-}" = exec ] || exit 2
shift
component=
root=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --root) root=$2; shift 2 ;;
        --component) component=$2; shift 2 ;;
        --) shift; break ;;
        *) exit 2 ;;
    esac
done
printf '%s' "$component" >>"$R2O_LAUNCHES"
for argument do printf '|%s' "$argument" >>"$R2O_LAUNCHES"; done
printf '\n' >>"$R2O_LAUNCHES"
exec "$root/releases/test/builds/$component-linux-test" 120
EOF
cat >"$r2o_temp/firewall" <<'EOF'
#!/bin/sh
case "${1:-}" in up|down|status) exit 0 ;; *) exit 2 ;; esac
EOF
cat >"$r2o_temp/ppe" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$r2o_temp/manager" "$r2o_temp/firewall" "$r2o_temp/ppe"

r2o_run_service() {
    env R2O_DIR="$r2o_temp/root" R2O_CONFIG="$r2o_temp/root/config" \
        R2O_MANAGER="$r2o_temp/manager" R2O_FIREWALL="$r2o_temp/firewall" \
        R2O_PPE_ADAPTER="$r2o_temp/ppe" R2O_LOG_MAINTENANCE="$r2o_temp/no-log-worker" \
        R2O_PROC=/proc R2O_RUNTIME_DIR="$r2o_temp/runtime" \
        R2O_NFQUEUE_STATUS="$r2o_temp/proc/net/netfilter/nfnetlink_queue" \
        R2O_LAUNCHES="$r2o_temp/launches" \
        sh "$r2o_root/router/S99r2o" "$@"
}

r2o_run_service engine-start

r2o_mark=$(printf '%d' 0xffffaaa)
r2o_mask=$(printf '%d' 0xffffff00)
for r2o_family in ipv4 ipv6; do
    r2o_queue=2000
    [ "$r2o_family" = ipv4 ] || r2o_queue=2001
    grep -Fq "r2o-datapath|--queue|$r2o_queue|--family|$r2o_family" "$r2o_temp/launches"
done
[ "$(grep -c '^r2o-datapath|' "$r2o_temp/launches")" -eq 2 ]
grep -Fq "|--probe-mark|46|--only-mark|$r2o_mark/$r2o_mask" "$r2o_temp/launches"
grep -Fq '|--r2o-flow-capacity|64' "$r2o_temp/launches"
[ -s "$r2o_temp/root/run/r2o-datapath4.pid" ]
[ -s "$r2o_temp/root/run/r2o-datapath6.pid" ]

r2o_run_service engine-stop
cat >"$r2o_temp/root/config" <<'EOF'
MODE=observe
IPV6_ENABLED=0
PANEL_LISTEN=127.0.0.1:8090
AUTOUPDATE=0
TG_ENABLED=0
EOF
: >"$r2o_temp/launches"
r2o_run_service engine-start
[ "$(wc -l <"$r2o_temp/launches")" -eq 2 ] || {
    echo "режим IPv4-only запустил неверное количество служб" >&2
    exit 1
}
r2o_run_service engine-start
[ "$(wc -l <"$r2o_temp/launches")" -eq 2 ] || {
    cat "$r2o_temp/launches" >&2
    echo "повторный engine-start перезапустил исправный IPv4-only datapath" >&2
    exit 1
}

r2o_run_service stop
: >"$r2o_temp/launches"
r2o_run_service start
grep -Fq 'r2o-panel|serve|' "$r2o_temp/launches" || {
    echo "панель не запустилась в тестовой конфигурации" >&2
    exit 1
}
grep -Fq '|--listen|127.0.0.1:8090' "$r2o_temp/launches" || {
    cat "$r2o_temp/launches" >&2
    echo "PANEL_LISTEN из конфигурации не передан панели" >&2
    exit 1
}
r2o_run_service stop

echo "Проверены route-gate, повторный IPv4-only запуск и адрес панели из конфигурации"
