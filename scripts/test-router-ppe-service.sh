#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
INSTALL_ROOT=$TEMP/opt/r2o
EVENTS=$TEMP/events
RUNTIME=$TEMP/r2o-runtime
mkdir -p "$TEMP/proc" "$INSTALL_ROOT/run" "$INSTALL_ROOT/releases/test/builds"
cleanup() {
    if [ -f "$INSTALL_ROOT/run/r2o-datapath4.pid" ]; then
        run_service engine-stop >/dev/null 2>&1 || true
    fi
    rm -rf "$TEMP"
}
trap cleanup EXIT HUP INT TERM

cat > "$INSTALL_ROOT/config" <<'CONFIG'
MODE=apply
QUEUE_NUM=2000
QUEUE_NUM6=2001
R2O_FLOW_CAPACITY=2048
IPV6_ENABLED=0
MARK=45
PROBE_MARK=0
ONLY_MARK=
FW_BACKEND=iptables
PORTS=0:65535
CONNBYTES=0:8
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
DNS_PORTS=53,853
TG_ENABLED=0
TG_PORT=1443
R2O_PPE_DEOFFLOAD=1
CONFIG
for component in r2o-datapath r2o-controller; do
    : > "$INSTALL_ROOT/releases/test/builds/$component-linux-testhost"
done
printf '#!/bin/sh\nexit 0\n' > "$INSTALL_ROOT/r2o-manager"
cat > "$TEMP/firewall" <<EOF
#!/bin/sh
if [ "\$1" = ipv6-enabled ]; then . "\$R2O_CONFIG"; printf '%s\\n' "\$IPV6_ENABLED"; exit 0; fi
case "\$1" in
    up)
        printf 'firewall:up\\n' >> "$EVENTS"
        "\$R2O_PPE_ADAPTER" ensure
        ;;
    down)
        "\$R2O_PPE_ADAPTER" remove
        printf 'firewall:down\\n' >> "$EVENTS"
        ;;
    ppe)
        shift
        "\$R2O_PPE_ADAPTER" "\$@"
        ;;
    *) printf 'firewall:%s\\n' "\$1" >> "$EVENTS" ;;
esac
EOF
cat > "$TEMP/ppe" <<EOF
#!/bin/sh
printf 'ppe:%s\\n' "\$*" >> "$EVENTS"
EOF
chmod +x "$TEMP/firewall" "$TEMP/ppe" "$INSTALL_ROOT/r2o-manager"

sleep 300 >/dev/null 2>&1 &
FAKE_PID=$!
printf '%s\n' "$FAKE_PID" > "$INSTALL_ROOT/run/r2o-datapath4.pid"
mkdir -p "$TEMP/proc/$FAKE_PID"
ln -s "$INSTALL_ROOT/releases/test/builds/r2o-datapath-linux-testhost" "$TEMP/proc/$FAKE_PID/exe"

run_service() {
    R2O_DIR="$INSTALL_ROOT" \
    R2O_CONFIG="$INSTALL_ROOT/config" \
    R2O_PROC="$TEMP/proc" \
    R2O_RUNTIME_DIR="$RUNTIME" \
    R2O_MANAGER="$INSTALL_ROOT/r2o-manager" \
    R2O_FIREWALL="$TEMP/firewall" \
    R2O_PPE_ADAPTER="$TEMP/ppe" \
    R2O_LOG_MAINTENANCE="$TEMP/no-log-worker" \
        sh "$ROOT/router/S99r2o" "$@"
}

run_service reapply
run_service ppe-status 87.228.47.201
run_service engine-stop

FW_UP=$(grep -n '^firewall:up$' "$EVENTS" | cut -d: -f1)
PPE_UP=$(grep -n '^ppe:ensure$' "$EVENTS" | cut -d: -f1)
FW_DOWN=$(grep -n '^firewall:down$' "$EVENTS" | tail -n 1 | cut -d: -f1)
PPE_DOWN=$(grep -n '^ppe:remove$' "$EVENTS" | tail -n 1 | cut -d: -f1)
if [ -z "$FW_UP" ] || [ -z "$PPE_UP" ] || [ "$FW_UP" -ge "$PPE_UP" ]; then
    cat "$EVENTS" >&2
    echo "PPE ensure did not follow firewall reapply" >&2
    exit 1
fi
if [ -z "$FW_DOWN" ] || [ -z "$PPE_DOWN" ] || [ "$PPE_DOWN" -ge "$FW_DOWN" ]; then
    cat "$EVENTS" >&2
    echo "PPE cleanup did not precede firewall teardown" >&2
    exit 1
fi
grep -qx 'ppe:status 87.228.47.201' "$EVENTS" || {
    echo "служба не передала IPv4-адрес адаптеру PPE status" >&2
    exit 1
}
echo "S99r2o reapplies PPE after firewall setup and removes it on stop"
