#!/bin/sh
# Фирменный NDM здесь не требуется: проверяем границу с legacy iptables.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
HELPER=$ROOT/router/r2o-ppe-deoffload.sh
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
export R2O_DATAPATH_BIN=${R2O_DATAPATH_BIN:-$ROOT/target/release/r2o-datapath}
export WORK R2O_DIR="$WORK" R2O_PROC_DIR="$WORK/proc"
export R2O_PLATFORM=keenetic FW_BACKEND=iptables
export PATH="$WORK/bin:$PATH"
mkdir -p "$WORK/bin" "$WORK/proc/net"
cat > "$WORK/bin/iptables" <<'SCRIPT'
#!/bin/sh
if [ "$1" = --version ]; then echo 'iptables v1.4.21'; exit 0; fi
[ "$*" = '-w -t mangle -S' ] || exit 2
cat "$WORK/rules"
SCRIPT
cat > "$WORK/bin/iptables-restore" <<'SCRIPT'
#!/bin/sh
[ "$*" = --noflush ] || exit 2
cat >> "$WORK/attempt"
[ "${FAIL_RESTORE:-0}" = 0 ] || exit 23
sed '/--comment "r2o-ppe"/d; /--comment d2k-ppe/d' "$WORK/rules" > "$WORK/remaining"
mv "$WORK/remaining" "$WORK/rules"
SCRIPT
cat > "$WORK/bin/ip6tables" <<'SCRIPT'
#!/bin/sh
exit 2
SCRIPT
chmod +x "$WORK/bin/"*
cat > "$WORK/rules" <<'RULES'
-P FORWARD ACCEPT
-A PREROUTING -p tcp -m comment --comment "r2o-ppe" -j PPE
-A FORWARD -p tcp -m comment --comment d2k-ppe -j PPE
-A FORWARD -p udp -m comment --comment other-ppe -j PPE
RULES
printf 'PPE\n' > "$R2O_PROC_DIR/net/ip_tables_targets"

"$HELPER" status | grep -q 'target=present.*lan_coverage=unverified'
rm "$R2O_PROC_DIR/net/ip_tables_targets"
"$HELPER" status | grep -q 'target=unavailable.*lan_coverage=unverified'
if FAIL_RESTORE=1 "$HELPER" remove; then exit 1; fi
grep -q r2o-ppe "$WORK/rules"
"$HELPER" remove
grep -q other-ppe "$WORK/rules"
if grep -Eq 'r2o-ppe|d2k-ppe' "$WORK/rules"; then exit 1; fi
: > "$WORK/attempt"
"$HELPER" remove
test ! -s "$WORK/attempt"
printf '%s\n' 'PPE: признак возможностей, отказ транзакции, удаление своих правил и повтор'
