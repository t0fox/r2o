#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
NFT=$(command -v nft) || {
    echo "для проверки синтаксиса межсетевого экрана нужен nft" >&2
    exit 127
}
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin" "$TEMP/root/run"
cat > "$TEMP/bin/nft" <<EOF
#!/bin/sh
if [ "\${1:-}" = list ]; then
    exit 1
fi
if [ "\${1:-}" = -f ]; then
    [ -z "\${R2O_TEST_RULES:-}" ] || cp "\$2" "\$R2O_TEST_RULES"
    exec "$NFT" --check --file "\$2"
fi
exec "$NFT" "\$@"
EOF
chmod 0755 "$TEMP/bin/nft"
for tool in iptables ip6tables; do
    printf '#!/bin/sh\nexit 1\n' > "$TEMP/bin/$tool"
    chmod 0755 "$TEMP/bin/$tool"
done
printf '#!/bin/sh\nexit 0\n' > "$TEMP/bin/conntrack"
chmod 0755 "$TEMP/bin/conntrack"

R2O_DIR="$TEMP/root" \
R2O_CONFIG=/dev/null \
R2O_RUN_DIR="$TEMP/root/run" \
R2O_TEST_RULES="$TEMP/main.nft" \
FW_BACKEND=nft \
QUEUE_NUM=34000 \
QUEUE_NUM6=34001 \
PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/r2o-firewall.sh" up
grep -qF 'meta mark 0x40000000 return' "$TEMP/main.nft"

R2O_DIR="$TEMP/root" \
R2O_CONFIG=/dev/null \
R2O_RUN_DIR="$TEMP/root/run" \
R2O_TEST_RULES="$TEMP/telegram.nft" \
R2O_FW=nft \
PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/r2o-tg-firewall.sh" start
grep -qF 'comment "r2o-managed"' "$TEMP/telegram.nft"
grep -qF 'meta mark 0x40000000 return' "$TEMP/telegram.nft"

echo "Синтаксис правил nftables для роутера и Telegram проверен без установки правил"
