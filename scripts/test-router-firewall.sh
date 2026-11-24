#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
NFT=$(command -v nft) || {
    echo "для проверки синтаксиса межсетевого экрана нужен nft" >&2
    exit 127
}
if [ "${1:-}" != isolated ]; then
    exec unshare -n sh "$0" isolated
fi
TEMP=$(mktemp -d)
DP=
cleanup() {
    if [ -n "$DP" ]; then kill "$DP" 2>/dev/null || :; wait "$DP" 2>/dev/null || :; fi
    rm -rf "$TEMP"
}
trap cleanup EXIT HUP INT TERM
R2O_DATAPATH_BIN=${R2O_DATAPATH_BIN:-$ROOT/target/release/r2o-datapath}
export R2O_DATAPATH_BIN
export R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/config" R2O_RUN_DIR="$TEMP/root/run"
export FW_BACKEND=nft QUEUE_NUM=34000 IPV6_ENABLED=0 R2O_PLATFORM_RUNTIME=1
mkdir -p "$TEMP/bin" "$R2O_RUN_DIR"
printf 'CONNBYTES=auto\nPORTS=443\n' > "$R2O_CONFIG"
modprobe nfnetlink_queue
modprobe nft_queue
"$R2O_DATAPATH_BIN" --queue "$QUEUE_NUM" --mode observe --r2o-flow-capacity 64 > "$TEMP/datapath.log" 2>&1 &
DP=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
    if awk '$1 == 34000 && $2 != 0 { found=1 } END { exit !found }' /proc/net/netfilter/nfnetlink_queue; then break; fi
    sleep 0.1
done
FIREWALL="$ROOT/router/r2o-firewall.sh"
sh "$FIREWALL" up
sh "$FIREWALL" status
nft list chain inet r2o out | grep -q '443.*ct original packets 1-8.*queue num 34000 bypass'
nft list chain inet r2o out | grep -q '443.*ct original packets 9-.*rst.*queue num 34000 bypass'
nft list chain inet r2o in_rules | grep -q '443.*ct reply packets 9-.*fin.*queue num 34000 bypass'
nft list chain inet r2o out | grep -q 'meta mark 0x0000002f return'
nft list chain inet r2o_rst output | grep -q '@rst4 drop'
nft insert rule inet r2o out tcp dport 444 return
if sh "$FIREWALL" status; then exit 1; fi
sh "$FIREWALL" event
for i in 1 2 3 4 5 6 7 8 9 10; do
    if sh "$FIREWALL" status 2>/dev/null; then break; fi
    sleep 0.2
done
sh "$FIREWALL" status
kill "$DP"
wait "$DP" || :
DP=
if sh "$FIREWALL" status; then exit 1; fi
sh "$FIREWALL" down
sh "$FIREWALL" rst-down
cat > "$TEMP/bin/nft" <<EOF
#!/bin/sh
if [ "\${1:-}" = list ]; then
    exit 1
fi
if [ "\${1:-}" = -f ]; then
    cat "\$2" >> "\$R2O_TEST_RULES"
    exec "$NFT" --check --file "\$2"
fi
exec "$NFT" "\$@"
EOF
chmod 0755 "$TEMP/bin/nft"

R2O_DIR="$TEMP/root" \
R2O_CONFIG=/dev/null \
R2O_RUN_DIR="$TEMP/root/run" \
R2O_TEST_RULES="$TEMP/telegram.nft" \
R2O_FW=nft \
PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/r2o-tg-firewall.sh" start
grep -qF 'comment "r2o-managed"' "$TEMP/telegram.nft"
grep -qF 'meta mark 0x31 return' "$TEMP/telegram.nft"

echo "Проверены восстановление nftables, отсутствие NFQUEUE peer и синтаксис правил Telegram"
