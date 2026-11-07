#!/bin/sh
# B9: clear-found снимает не только каталог, но и производные state-файлы.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
R2OC_BIN=${R2OC_TEST_BINARY:-$ROOT/target/release/r2o-controller}
[ -x "$R2OC_BIN" ] || { echo "нужен исполняемый файл r2o-controller: $R2OC_BIN" >&2; exit 2; }

TEMP=$(mktemp -d)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$result" -ne 0 ] && [ -f "$TEMP/events" ]; then cat "$TEMP/events" >&2; fi
    rm -rf "$TEMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$TEMP/root/state" "$TEMP/root/run" "$TEMP/runtime"
printf 'MODE=off\nSTATE_DIR=%s\nFW_BACKEND=nft\n' "$TEMP/root/state" > "$TEMP/root/config"
printf '{"schema":1,"boxes":[{"id":"found"}]}\n' > "$TEMP/root/state/catalog.json"
printf '{"schema":1}\n' > "$TEMP/root/state/https-cache.json"
printf '{"linked":true}\n' > "$TEMP/root/state/live.json"
printf 'legacy\n' > "$TEMP/root/state/https-cache.txt"
printf 'legacy\n' > "$TEMP/root/state/http-plans.txt"
mkdir -p "$TEMP/root/state/measurements"
printf 'legacy\n' > "$TEMP/root/state/measurements/probe.json"

cat > "$TEMP/manager" <<'EOF'
#!/bin/sh
printf 'manager:%s\n' "$*" >> "$EVENTS"
[ "${1:-}" = exec ] || exit 2
shift
component=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --component) component=$2; shift 2 ;;
        --) shift; break ;;
        *) shift ;;
    esac
done
[ "$component" = r2o-controller ] || exit 2
[ "${1:-}" = --clear-catalog ] || exit 2
exec "$R2OC_TEST_BINARY" "$@"
EOF
cat > "$TEMP/firewall" <<'EOF'
#!/bin/sh
if [ "${1:-}" = ipv6-enabled ]; then printf '1\n'; exit 0; fi
printf 'firewall:%s\n' "$1" >> "$EVENTS"
EOF
chmod 0755 "$TEMP/manager" "$TEMP/firewall"

env EVENTS="$TEMP/events" R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/root/config" \
    R2O_MANAGER="$TEMP/manager" R2O_R2OC_TEST_BINARY="$R2OC_BIN" \
    R2O_FIREWALL="$TEMP/firewall" R2O_PROC=/proc \
    R2O_NFQUEUE_STATUS="$TEMP/proc/net/netfilter/nfnetlink_queue" \
    R2O_RUNTIME_DIR="$TEMP/runtime" \
    R2OC_TEST_BINARY="$R2OC_BIN" sh "$ROOT/router/S99r2o" clear-found

"$R2OC_BIN" --check-catalog "$TEMP/root/state/catalog.json" | grep -q '0 коробок'
for leftover in https-cache.json live.json https-cache.txt http-plans.txt measurements; do
    if [ -e "$TEMP/root/state/$leftover" ]; then
        echo "clear-found оставил state: $leftover" >&2
        exit 1
    fi
done
grep -q -- '--clear-catalog ' "$TEMP/events"
echo "clear-found снял каталог и все производные state-файлы"
