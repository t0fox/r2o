#!/opt/bin/sh
set -eu
LAB=${LAB:-/opt/lab}
export LAB
PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
DURATION=${1:-600}
REPORT=${2:-/tmp/r2o-soak.log}
SAMPLE_INTERVAL=${SAMPLE_INTERVAL:-30}
exec >"$REPORT" 2>&1
report_exit() {
    if [ "$1" -ne 0 ]; then
        printf 'SOAK_FAIL status=%s\n' "$1"
    fi
}
trap 'report_exit "$?"' EXIT

uptime_sec() {
    IFS='. ' read -r seconds rest </proc/uptime
    printf '%s\n' "$seconds"
}
queues() {
    awk '$1 == 2000 || $1 == 2001 {print $1, $2, $3, $4, $6, $7, $8}' \
        /proc/net/netfilter/nfnetlink_queue
}
process_pids() {
    active=$(sed -n '2p' /opt/r2o/release-slots)
    for component in datapath controller; do
        found=0
        for suffix in '' 4 6; do
            file=/opt/r2o/run/r2o-$component$suffix.pid
            [ -s "$file" ] || continue
            pid=$(cat "$file")
            case "$pid" in ''|*[!0-9]*) continue ;; esac
            case "$(readlink "/proc/$pid/exe" || true)" in
                /opt/r2o/releases/"$active"/builds/r2o-"$component"-linux-*)
                    printf '%s\n' "$pid"
                    found=1
                    ;;
            esac
        done
        if [ "$found" -ne 1 ]; then
            echo "Реальный процесс $component из $active не найден" >&2
            tail -35 /opt/r2o/log/r2o-"$component"*.log >&2 || true
            return 1
        fi
    done
}
process_metrics() {
    for pid in $pids; do
        if [ ! -r "/proc/$pid/status" ]; then
            echo "SOAK_PROCESS_LOST pid=$pid"
            return 1
        fi
        awk -v pid="$pid" '
            /^(VmRSS|VmHWM|Threads):/ { printf "%s=%s ", $1, $2 }
            END { printf "pid=%s ", pid }
        ' "/proc/$pid/status"
        awk '{sub(/^.*\) /, ""); print "cpu_ticks=" $12+$13 " start_ticks=" $20}' "/proc/$pid/stat"
        if [ -r "/proc/$pid/smaps_rollup" ]; then
            awk '/^Pss:/ {print "pss_kib=" $2}' "/proc/$pid/smaps_rollup"
        elif [ -r "/proc/$pid/smaps" ]; then
            awk '/^Pss:/ {n+=$2} END {print "pss_kib=" n}' "/proc/$pid/smaps"
        fi
        printf 'fd_count=%s\n' "$(ls "/proc/$pid/fd" | wc -l)"
    done
}
start=$(uptime_sec)
pids=$(process_pids)
[ -n "$pids" ]
[ "$(printf '%s\n' "$pids" | wc -l)" -ge 2 ]
count=0
while :; do
    elapsed=$(($(uptime_sec)-start))
    echo "SOAK_SAMPLE elapsed_s=$elapsed"
    [ "$(process_pids)" = "$pids" ]
    process_metrics
    awk '/^(MemAvailable|MemFree):/ {print}' /proc/meminfo
    awk '/^cpu / {print}' /proc/stat
    before=$(queues)
    printf '%s\n' "$before"
    "$LAB/network.sh" client
    after=$(queues)
    printf '%s\n' "$before" "$after" | awk '
        NF != 7 || $4 != 2 || $5 != 0 || $6 != 0 {exit 1}
        NR <= 2 {seq[$1]=$7; peer[$1]=$2; next}
        $7 <= seq[$1] || $2 != peer[$1] {exit 1}
        END {if (NR != 4) exit 1}
    '
    count=$((count+1))
    if [ "$elapsed" -ge "$DURATION" ]; then break; fi
    sleep "$SAMPLE_INTERVAL"
done
printf 'SOAK_PASS elapsed_s=%s samples=%s\n' "$elapsed" "$count"
