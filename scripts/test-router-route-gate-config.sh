#!/bin/sh
set -eu

r2o_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
d2o_root=${R2O_DONOR_ROOT:-${r2o_root%/*}/d2o}
expected_d2o_sha=304ba893dd37197128ac8799c0495b035f6a38c0
actual_d2o_sha=$(git -C "$d2o_root" rev-parse HEAD)
[ "$actual_d2o_sha" = "$expected_d2o_sha" ] || {
    printf 'Expected d2o %s, got %s\n' "$expected_d2o_sha" "$actual_d2o_sha" >&2
    exit 2
}
d2o_service=$d2o_root/files/S99d2k
grep -Fq -- '--mark "$PROBE_MARK"' "$d2o_service" || {
    echo "D2O controller startup no longer uses PROBE_MARK; update this differential case" >&2
    exit 2
}
d2o_default_probe_mark=$(awk -F= '$1 == "PROBE_MARK" { gsub(/\r/, "", $2); print $2; exit }' "$d2o_service")
r2o_default_probe_mark=$(awk -F= '$1 == "PROBE_MARK" { gsub(/\r/, "", $2); print $2; exit }' "$r2o_root/router/config.default")
d2o_default_probe_mark=$(printf '%d' "$d2o_default_probe_mark")
r2o_default_probe_mark=$(printf '%d' "$r2o_default_probe_mark")
[ "$r2o_default_probe_mark" = "$d2o_default_probe_mark" ] || {
    printf 'D2O default PROBE_MARK is %s; R2O config.default uses %s\n' \
        "$d2o_default_probe_mark" "$r2o_default_probe_mark" >&2
    exit 1
}
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

mkdir -p "$r2o_temp/root/releases/test/builds" "$r2o_temp/proc/net/netfilter" "$r2o_temp/mockbin"
: >"$r2o_temp/up-runtime"
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
case "${1:-}" in
    ipv6-enabled)
        if [ -n "${R2O_IPV6_TEST_CAPABILITY:-}" ]; then
            printf '%s\n' "$R2O_IPV6_TEST_CAPABILITY"
        else
            . "$R2O_CONFIG"
            printf '%s\n' "$IPV6_ENABLED"
        fi
        ;;
    up)
        printf '<%s>\n' "${R2O_IPV6_ENABLED_RUNTIME-unset}" >>"$R2O_UP_RUNTIME_TRACE"
        exit 0
        ;;
    down|status|flowoffload-ensure|flowoffload-restore) exit 0 ;;
    *) exit 2 ;;
esac
EOF
cat >"$r2o_temp/ppe" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$r2o_temp/mockbin/start-stop-daemon" <<'EOF'
#!/bin/sh
set -eu
pidfile=
program=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -p) pidfile=$2; shift 2 ;;
        -x) program=$2; shift 2 ;;
        --) shift; break ;;
        *) shift ;;
    esac
done
[ -n "$pidfile" ] && [ -n "$program" ] && [ "$#" -gt 0 ] || exit 2
"$program" "$@" &
printf '%s' "$!" >"$pidfile"
EOF
chmod 0755 "$r2o_temp/manager" "$r2o_temp/firewall" "$r2o_temp/ppe" \
    "$r2o_temp/mockbin/start-stop-daemon"

r2o_run_service() {
    env R2O_DIR="$r2o_temp/root" R2O_CONFIG="$r2o_temp/root/config" \
        R2O_MANAGER="$r2o_temp/manager" R2O_FIREWALL="$r2o_temp/firewall" \
        R2O_PPE_ADAPTER="$r2o_temp/ppe" R2O_LOG_MAINTENANCE="$r2o_temp/no-log-worker" \
        R2O_PROC=/proc R2O_RUNTIME_DIR="$r2o_temp/runtime" \
        R2O_NFQUEUE_STATUS="$r2o_temp/proc/net/netfilter/nfnetlink_queue" \
        R2O_IPV6_TEST_CAPABILITY="${R2O_IPV6_TEST_CAPABILITY:-}" \
        R2O_UP_RUNTIME_TRACE="$r2o_temp/up-runtime" \
        R2O_LAUNCHES="$r2o_temp/launches" \
        sh "$r2o_temp/S99r2o" "$@"
}

{
    sed -n '1p' "$r2o_root/router/S99r2o"
    printf 'SCRIPT_DIR=%s\n' "$r2o_root/router"
    sed -n '3,4p' "$r2o_root/router/S99r2o"
    printf 'PATH=%s:$PATH\n' "$r2o_temp/mockbin"
    sed -n '5,$p' "$r2o_root/router/S99r2o"
} >"$r2o_temp/S99r2o"

R2O_IPV6_TEST_CAPABILITY=0 r2o_run_service engine-start
grep -Fxq '<>' "$r2o_temp/up-runtime" || {
    echo "engine-start passed a stale IPv4-only probe result to firewall up" >&2
    exit 1
}
R2O_IPV6_TEST_CAPABILITY=0 r2o_run_service status >"$r2o_temp/status-fallback"
grep -Fq 'IPv6: не обслуживается — нет ip6tables mangle, работа только по IPv4' "$r2o_temp/status-fallback"

r2o_mark=$(printf '%d' 0xffffaaa)
r2o_mask=$(printf '%d' 0xffffff00)
for r2o_family in ipv4 ipv6; do
    r2o_queue=2000
    [ "$r2o_family" = ipv4 ] || r2o_queue=2001
    grep -Fq "r2o-datapath|--queue|$r2o_queue|--family|$r2o_family" "$r2o_temp/launches"
done
[ "$(grep -c '^r2o-datapath|' "$r2o_temp/launches")" -eq 2 ]
grep -Fq "|--probe-mark|46|--only-mark|$r2o_mark/$r2o_mask" "$r2o_temp/launches"
grep -Fq '|--discover|--mark|46|--live|' "$r2o_temp/launches" || {
    cat "$r2o_temp/launches" >&2
    echo "R2O controller probe mark diverges from D2O PROBE_MARK" >&2
    exit 1
}
grep -Fq '|--r2o-flow-capacity|64' "$r2o_temp/launches"
[ -s "$r2o_temp/root/run/r2o-datapath4.pid" ]
[ -s "$r2o_temp/root/run/r2o-datapath6.pid" ]

: >"$r2o_temp/up-runtime"
R2O_IPV6_TEST_CAPABILITY=0 r2o_run_service reapply
grep -Fxq '<>' "$r2o_temp/up-runtime" || {
    echo "reapply passed a stale IPv4-only probe result to firewall up" >&2
    exit 1
}
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
grep -Fq '|--probe-mark|46|' "$r2o_temp/launches" || {
    cat "$r2o_temp/launches" >&2
    echo "service startup without PROBE_MARK must use the D2O default 46" >&2
    exit 1
}
grep -Fq '|--discover|--mark|46|--live|' "$r2o_temp/launches" || {
    cat "$r2o_temp/launches" >&2
    echo "service startup without PROBE_MARK did not pass the D2O default to controller" >&2
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
printf 'PROBE_MARK=0\n' >>"$r2o_temp/root/config"
r2o_run_service start
grep -Fq 'r2o-panel|serve|' "$r2o_temp/launches" || {
    echo "панель не запустилась в тестовой конфигурации" >&2
    exit 1
}
grep -Fq '|--discover|--mark|45|--live|' "$r2o_temp/launches" || {
    cat "$r2o_temp/launches" >&2
    echo "явный PROBE_MARK=0 должен сохранить MARK для controller probes" >&2
    exit 1
}
if grep -Fq 'r2o-datapath|' "$r2o_temp/launches" && grep -Fq '|--probe-mark|' "$r2o_temp/launches"; then
    cat "$r2o_temp/launches" >&2
    echo "явный PROBE_MARK=0 не должен передаваться datapath как отдельная метка" >&2
    exit 1
fi
grep -Fq '|--listen|127.0.0.1:8090' "$r2o_temp/launches" || {
    cat "$r2o_temp/launches" >&2
    echo "PANEL_LISTEN из конфигурации не передан панели" >&2
    exit 1
}
r2o_run_service stop

echo "Проверены route-gate, повторный IPv4-only запуск и адрес панели из конфигурации"
