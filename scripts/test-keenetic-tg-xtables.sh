#!/bin/sh
# Run with a Linux r2o-datapath binary for the current host.
set -eu
export R2O_DATAPATH_BIN=${1:?path to r2o-datapath}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/state"
export R2O_DIR="$tmp" R2O_RUNTIME_DIR="$tmp/run" R2O_FW=iptables
export PATH="$tmp/bin:$PATH"
cat > "$tmp/bin/iptables" <<'EOF'
#!/bin/sh
if [ "$1" = --version ]; then echo 'iptables v1.4.21'; exit 0; fi
if [ "${EXPECT_WAIT:-1}" = 1 ]; then
    [ "$1" = -w ] || exit 4
    shift
    if [ "${0##*/}" = iptables ]; then sleep 3; fi
fi
[ "$*" = '-t nat -S' ] || exit 2
echo "${0##*/}" >> "$R2O_DIR/reads"
if [ "${0##*/}" = ip6tables ]; then echo 'no IPv6 NAT' >&2; exit 3; fi
EOF
chmod +x "$tmp/bin/iptables"
ln -s iptables "$tmp/bin/ip6tables"
printf 'r2o-tg-dc-options-v1 1 1\n149.154.175.52 443\n' > "$tmp/state/telegram-dc-endpoints.tsv"
for platform in keenetic openwrt; do
    : > "$tmp/reads"
    case "$platform" in keenetic) wait=1 ;; openwrt) wait=0 ;; esac
    EXPECT_WAIT=$wait R2O_PLATFORM=$platform sh "$root/router/r2o-tg-firewall.sh" sync-dc-map
    [ "$(cat "$tmp/reads")" = "$(printf 'iptables\nip6tables')" ]
    grep -q 'exit=3' "$tmp/run/telegram-firewall.ipv6"
done
echo 'PASS: Keenetic waits for xtables, OpenWrt keeps its existing invocation'
