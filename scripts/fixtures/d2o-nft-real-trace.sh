#!/bin/sh
# shellcheck disable=SC2034
# B10 C-side: применить nft-генератор D2O к реальному nft в netns.
set -eu

D2O_ROOT=${1:?D2O root}
TEMP=${2:?temp dir}
D2K_DIR="$TEMP/d2k"
mkdir -p "$D2K_DIR/run" "$D2K_DIR/state"
cat >"$D2K_DIR/config" <<'EOF'
FW_BACKEND=nft
QUEUE_NUM=2000
MARK=0x2d
MEASURE_MARK=0x2f
PORTS=0:65535
CONNBYTES=0:8
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
DNS_PORTS=53,853
EOF
export D2K_DIR
CONF="$D2K_DIR/config"
DIR="$D2K_DIR"
RUN="$D2K_DIR/run"
tr -d '\r' <"$D2O_ROOT/files/S99d2k" |
    awk '$0 == "case \"$1\" in" { exit } { print }' >"$TEMP/c-functions.sh"
. "$TEMP/c-functions.sh"
say() { :; }
fw_iptables_down() { :; }

fw_nft_up
echo "up=$?"
fw_nft_installed
echo "installed=$?"
if nft list table inet d2k_rst >/dev/null 2>&1; then echo "rst_table=1"; else echo "rst_table=0"; fi
nft list ruleset >"$TEMP/c-rules"
nft delete table inet d2k >/dev/null 2>&1 || true
nft delete table inet d2k_rst >/dev/null 2>&1 || true
echo "main_down=0"
echo "rst_down=0"
if nft list table inet d2k >/dev/null 2>&1; then echo "main_present=1"; else echo "main_present=0"; fi
if nft list table inet d2k_rst >/dev/null 2>&1; then echo "rst_present=1"; else echo "rst_present=0"; fi
