#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/target"}
R2OD_BIN=${R2OD_BIN:-"$TARGET_DIR/release/r2o-datapath"}
R2OC_BIN=${R2OC_BIN:-"$TARGET_DIR/release/r2o-controller"}
FIXTURE="$ROOT/crates/r2k-core/tests/fixtures/quic_v1_initial.bin"
QUEUE=65490
MARK=21082
NS="r2o-quic-silence-$$"
WORK=$(mktemp -d)

cleanup() {
    if ip netns list | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" | xargs -r kill 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
    if [ "${KEEP_TEST_WORK:-0}" = "1" ]; then
        echo "сохранены файлы проверки: $WORK" >&2
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT HUP INT TERM

if [ "$(id -u)" -ne 0 ]; then
    echo "запустите эту проверку от root" >&2
    exit 1
fi
for tool in ip nft python3 grep; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "не найдена обязательная команда: $tool" >&2
        exit 1
    }
done
if [ ! -x "$R2OD_BIN" ] || [ ! -x "$R2OC_BIN" ]; then
    (cd "$ROOT" && cargo build --release --locked --package r2o-datapath --package r2o-controller)
fi

printf '%s\n' '{"boxes":[]}' >"$WORK/catalog.json"
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" nft add table inet r2o
ip netns exec "$NS" nft 'add chain inet r2o output { type filter hook output priority 0; policy accept; }'
ip netns exec "$NS" nft 'add chain inet r2o input { type filter hook input priority 0; policy accept; }'
ip netns exec "$NS" nft add rule inet r2o output udp dport 443 meta mark != "$MARK" queue num "$QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o input udp sport 443 queue num "$QUEUE" bypass

ip netns exec "$NS" "$R2OD_BIN" --queue "$QUEUE" --family ipv4 --controller-only \
    --mark "$MARK" --control "$WORK/r2o-datapath.sock" --r2o-udp-reverse-visible \
    >"$WORK/r2o-datapath.log" 2>&1 &
ip netns exec "$NS" "$R2OC_BIN" --serve "$WORK/r2o-datapath.sock" "$WORK/catalog.json" \
    >"$WORK/r2o-controller.log" 2>&1 &

attempt=0
while ! grep -Fq "наблюдение активно" "$WORK/r2o-controller.log"; do
    if [ "$attempt" -ge 100 ]; then
        cat "$WORK/r2o-datapath.log" "$WORK/r2o-controller.log" >&2
        echo "ОШИБКА: контроллер не подключился к datapath" >&2
        exit 1
    fi
    sleep 0.05
    attempt=$((attempt + 1))
done

ip netns exec "$NS" python3 - "$FIXTURE" <<'PY'
import socket
import sys
import time

with open(sys.argv[1], "rb") as fixture:
    initial = fixture.read()
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 443))
server.settimeout(3)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind(("127.0.0.1", 40152))
client.sendto(initial, ("127.0.0.1", 443))
time.sleep(0.1)
client.sendto(initial, ("127.0.0.1", 443))
received = [server.recvfrom(2048)[0], server.recvfrom(2048)[0]]
client.close()
server.close()
if received != [initial, initial]:
    raise SystemExit("ОШИБКА: datapath изменил или потерял QUIC Initial")
print("ПРОЙДЕНО: оба аутентичных QUIC Initial дошли до UDP-сервера без изменений")
PY

attempt=0
while ! grep -Fq "наблюдение QUIC: после повтора Initial" "$WORK/r2o-controller.log"; do
    if [ "$attempt" -ge 120 ]; then
        cat "$WORK/r2o-datapath.log" "$WORK/r2o-controller.log" >&2
        echo "ОШИБКА: контроллер не получил наблюдение молчания QUIC" >&2
        exit 1
    fi
    sleep 0.05
    attempt=$((attempt + 1))
done

if ! grep -Fq "127.0.0.1:40152 -> 127.0.0.1:443" "$WORK/r2o-controller.log"; then
    cat "$WORK/r2o-controller.log" >&2
    echo "ОШИБКА: событие QUIC указало неверное направление клиента" >&2
    exit 1
fi
echo "ПРОЙДЕНО: NFQUEUE и контроллер передали QUIC-подозрение после повтора и 2 с молчания"
