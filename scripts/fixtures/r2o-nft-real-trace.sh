#!/bin/sh
# B10 Rust-side: применить nft-генератор R2O к реальному nft в netns.
set -eu

ROOT=${1:?R2O root}
TEMP=${2:?temp dir}
mkdir -p "$TEMP/r2o/run"
cat >"$TEMP/r2o/config" <<'EOF'
FW_BACKEND=nft
QUEUE_NUM=2000
QUEUE_NUM6=2001
MARK=0x2d
PROBE_MARK=0x2e
PORTS=0:65535
CONNBYTES=0:8
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
DNS_PORTS=53,853
IPV6_ENABLED=1
EOF
export R2O_DIR="$TEMP/r2o"
export R2O_CONFIG="$TEMP/r2o/config"
export R2O_RUN_DIR="$TEMP/r2o/run"
export R2O_PROC_DIR="$TEMP/proc"
export R2O_SYS_MODULE_DIR="$TEMP/sys"
export R2O_MODULES_DIR="$TEMP/modules"
sed -n '1,/^case "${1:-}" in$/p' "$ROOT/router/r2o-firewall.sh" |
    sed '$d' | tr -d '\r' >"$TEMP/r2o-functions.sh"
. "$TEMP/r2o-functions.sh"

nft_up
echo "up=$?"
firewall_status_nft
echo "installed=$?"
if nft list table inet r2o_rst >/dev/null 2>&1; then echo "rst_table=1"; else echo "rst_table=0"; fi
nft list ruleset >"$TEMP/r2o-rules"
nft_main_down
echo "main_down=$?"
nft_rst_down
echo "rst_down=$?"
if nft list table inet r2o >/dev/null 2>&1; then echo "main_present=1"; else echo "main_present=0"; fi
if nft list table inet r2o_rst >/dev/null 2>&1; then echo "rst_present=1"; else echo "rst_present=0"; fi
