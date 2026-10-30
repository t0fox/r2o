#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
SH_BIN=$(command -v sh)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-ipv6-fallback.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/empty" "$TEMP/no-mangle-bin" "$TEMP/no-w-bin" "$TEMP/up-bin" "$TEMP/down-bin" \
    "$TEMP/d2o-run" "$TEMP/r2o-run" "$TEMP/root" "$TEMP/no-modprobe-bin" \
    "$TEMP/empty-proc/net" "$TEMP/empty-sys" "$TEMP/empty-modules"
sed 's/\r$//' "$D2O_ROOT/files/S99d2k" > "$TEMP/d2o-S99d2k"
awk '/^fw_family_up\(\) \(/ { copy=1 } copy { print } copy && /^\)/ { exit }' \
    "$TEMP/d2o-S99d2k" > "$TEMP/d2o-family-functions.sh"
sed -n '/^fw_up_unlocked() {/,/^}/p; /^fw_iptables_down() {/,/^}/p' \
    "$TEMP/d2o-S99d2k" > "$TEMP/d2o-firewall-functions.sh"
sed -n '/^module_present() {/,/^}/p; /^load_modules() {/,/^}/p' \
    "$TEMP/d2o-S99d2k" > "$TEMP/d2o-module-functions.sh"
sed -n '/^fw_installed() {/,/^}/p' \
    "$TEMP/d2o-S99d2k" > "$TEMP/d2o-installed-function.sh"
sed -n '/^configure_ipv6() {/,/^}/p; /^ipv6_components_running() {/,/^}/p' \
    "$ROOT/router/S99r2o" > "$TEMP/r2o-ipv6-functions.sh"
sed -n '/^check_runtime_dependencies() {/,/^}/p' \
    "$ROOT/scripts/install.sh" > "$TEMP/r2o-install-function.sh"

cat > "$TEMP/d2o-family-probe" <<'D2OFAMILY'
#!/bin/sh
CHAIN_OUT=D2K_OUT
CHAIN_IN=D2K_IN
late_rst_from() { echo 65535; }
. "$D2O_FUNCTIONS"
if fw_family_up ip6tables; then rc=0; else rc=$?; fi
printf '%s\n' "$rc"
D2OFAMILY

cat > "$TEMP/d2o-up-probe" <<'D2OUP'
#!/bin/sh
RUN=$D2O_RUN
FW_V4ONLY=$RUN/fw-ipv4-only
. "$D2O_FUNCTIONS"
fw_family_up() {
    case "$1" in
        iptables) printf 'up4\n' >> "$D2O_TRACE"; return 0 ;;
        ip6tables) printf 'up6\n' >> "$D2O_TRACE"; return 3 ;;
    esac
    return 1
}
fw_family_down() { printf 'down:%s\n' "$1" >> "$D2O_TRACE"; }
ppe_up() { printf 'ppe\n' >> "$D2O_TRACE"; }
say() { printf 'say:%s\n' "$*" >> "$D2O_TRACE"; }
if fw_up_unlocked; then rc=0; else rc=$?; fi
printf '%s\n' "$rc"
[ -f "$FW_V4ONLY" ] && printf 'ipv4-only\n'
D2OUP

cat > "$TEMP/d2o-recovery-probe" <<'D2ORECOVERY'
#!/bin/sh
RUN=$D2O_RUN
FW_V4ONLY=$RUN/fw-ipv4-only
. "$D2O_FUNCTIONS"
fw_family_up() {
    case "$1" in
        iptables) printf 'up4\n' >> "$D2O_TRACE"; return 0 ;;
        ip6tables)
            if [ -f "$IPV6_AVAILABLE" ]; then printf 'up6\n' >> "$D2O_TRACE"; return 0; fi
            printf 'ipv4-only\n' >> "$D2O_TRACE"
            return 3
            ;;
    esac
    return 1
}
fw_family_down() { printf 'down:%s\n' "$1" >> "$D2O_TRACE"; }
ppe_up() { :; }
ppe_down() { :; }
say() { :; }
fw_down_unlocked() { fw_iptables_down; }
fw_up_unlocked || exit 1
[ -f "$FW_V4ONLY" ] || exit 1
: > "$IPV6_AVAILABLE"
FW_BACKEND=iptables
fw_family_installed() { printf 'installed:%s\n' "$1" >> "$D2O_TRACE"; return 0; }
. "$D2O_INSTALLED_FUNCTION"
fw_installed || exit 1
grep -Fxq installed:iptables "$D2O_TRACE" || exit 1
! grep -Fxq installed:ip6tables "$D2O_TRACE" || exit 1
fw_down_unlocked
fw_up_unlocked || exit 1
[ ! -f "$FW_V4ONLY" ] || exit 1
D2ORECOVERY

cat > "$TEMP/no-mangle-bin/ip6tables" <<'IP6TABLES'
#!/bin/sh
exit 1
IP6TABLES
cat > "$TEMP/no-w-bin/ip6tables" <<'IP6TABLES'
#!/bin/sh
case " $* " in
    *' -w '*) exit 2 ;;
    *' -t mangle -N '*) exit 1 ;;
    *' -t mangle -n -L '*) exit 0 ;;
    *' -D '*|*' -C '*) exit 1 ;;
    *) exit 0 ;;
esac
IP6TABLES
cat > "$TEMP/up-bin/iptables" <<'IPTABLES'
#!/bin/sh
for arg do case "$arg" in -D|-C) exit 1 ;; esac; done
exit 0
IPTABLES
cat > "$TEMP/down-bin/iptables" <<'IPTABLES'
#!/bin/sh
printf 'iptables %s\n' "$*" >> "$FW_TRACE"
for arg do case "$arg" in -D|-C) exit 1 ;; esac; done
exit 0
IPTABLES
cat > "$TEMP/down-bin/ip6tables" <<'IP6TABLES'
#!/bin/sh
printf 'ip6tables %s\n' "$*" >> "$FW_TRACE"
for arg do case "$arg" in -D|-C) exit 1 ;; esac; done
exit 0
IP6TABLES
chmod 0700 "$TEMP/d2o-family-probe" "$TEMP/d2o-up-probe" "$TEMP/d2o-recovery-probe" \
    "$TEMP/no-mangle-bin/ip6tables" "$TEMP/no-w-bin/ip6tables" "$TEMP/up-bin/iptables" \
    "$TEMP/down-bin/iptables" "$TEMP/down-bin/ip6tables"
cat > "$TEMP/up-bin/start-stop-daemon" <<'SSD'
#!/bin/sh
exit 0
SSD
chmod 0700 "$TEMP/up-bin/start-stop-daemon"

failures=0
for path in "$TEMP/empty" "$TEMP/no-mangle-bin"; do
    family_rc=$(D2O_FUNCTIONS=$TEMP/d2o-family-functions.sh PATH=$path \
        "$SH_BIN" "$TEMP/d2o-family-probe")
    [ "$family_rc" = 3 ] || {
        printf 'D2O should classify unavailable IPv6 mangle as fallback (got %s)\n' "$family_rc" >&2
        failures=1
    }
done
legacy_family_rc=$(D2O_FUNCTIONS=$TEMP/d2o-family-functions.sh PATH=$TEMP/no-w-bin:/usr/bin:/bin \
    "$SH_BIN" "$TEMP/d2o-family-probe")
[ "$legacy_family_rc" = 3 ] || {
    printf 'D2O should use IPv4-only fallback when -w is unsupported during its family probe (got %s)\n' "$legacy_family_rc" >&2
    failures=1
}
d2o_up_result=$(D2O_RUN=$TEMP/d2o-run D2O_TRACE=$TEMP/d2o-up.trace \
    D2O_FUNCTIONS=$TEMP/d2o-firewall-functions.sh "$SH_BIN" "$TEMP/d2o-up-probe")
[ "$d2o_up_result" = "0
ipv4-only" ] || {
    printf 'D2O IPv4-only fallback differs: %s\n' "$d2o_up_result" >&2
    failures=1
}

cat > "$TEMP/no-modprobe-bin/modprobe" <<'MODPROBE'
#!/bin/sh
exit 1
MODPROBE
cat > "$TEMP/no-modprobe-bin/lsmod" <<'LSMOD'
#!/bin/sh
exit 0
LSMOD
chmod 0700 "$TEMP/no-modprobe-bin/modprobe" "$TEMP/no-modprobe-bin/lsmod"

mkdir -p "$TEMP/d2o-recovery-run" "$TEMP/d2o-recovery-bin"
cat > "$TEMP/d2o-recovery-bin/iptables" <<'IPTABLES'
#!/bin/sh
exit 0
IPTABLES
cat > "$TEMP/d2o-recovery-bin/ip6tables" <<'IP6TABLES'
#!/bin/sh
[ -f "$IPV6_AVAILABLE" ]
IP6TABLES
chmod 0700 "$TEMP/d2o-recovery-bin/iptables" "$TEMP/d2o-recovery-bin/ip6tables"
: > "$TEMP/d2o-recovery.trace"
D2O_RUN=$TEMP/d2o-recovery-run D2O_TRACE=$TEMP/d2o-recovery.trace \
    D2O_FUNCTIONS=$TEMP/d2o-firewall-functions.sh \
    D2O_INSTALLED_FUNCTION=$TEMP/d2o-installed-function.sh \
    IPV6_AVAILABLE=$TEMP/d2o-recovery-bin/ipv6-available \
    PATH=$TEMP/d2o-recovery-bin:/usr/bin:/bin "$SH_BIN" "$TEMP/d2o-recovery-probe"
grep -Fxq up6 "$TEMP/d2o-recovery.trace" || {
    echo 'D2O did not restore IPv6 rules after mangle became available' >&2
    failures=1
}

run_r2o_up() {
    mode=$1
    path=$TEMP/up-bin:/usr/bin:/bin
    [ "$mode" != no-mangle ] || path=$TEMP/no-mangle-bin:$path
    [ "$mode" != no-w ] || path=$TEMP/no-w-bin:$path
    R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/r2o-run \
        R2O_PROC_DIR=$TEMP/empty-proc R2O_SYS_MODULE_DIR=$TEMP/empty-sys \
        R2O_MODULES_DIR=$TEMP/empty-modules \
        FW_BACKEND=iptables IPV6_ENABLED=1 PATH=$TEMP/no-modprobe-bin:$path \
        sh "$ROOT/router/r2o-firewall.sh" up
}
for mode in missing no-mangle no-w; do
    rm -f "$TEMP/r2o-run/fw-ipv4-only"
    if run_r2o_up "$mode" 2> "$TEMP/r2o-$mode.error"; then r2o_rc=0; else r2o_rc=$?; fi
    if [ "$r2o_rc" -ne 0 ]; then
        printf 'R2O failed to fall back to IPv4 when ip6tables is %s\n' "$mode" >&2
        cat "$TEMP/r2o-$mode.error" >&2
        failures=1
    fi
    [ -f "$TEMP/r2o-run/fw-ipv4-only" ] || {
        printf 'R2O did not persist the IPv4-only marker for %s ip6tables\n' "$mode" >&2
        failures=1
    }
done
[ -f "$TEMP/r2o-run/fw-ipv4-only" ] || {
    echo 'R2O did not persist the IPv4-only fallback marker' >&2
    failures=1
}

mkdir -p "$TEMP/module-load-bin" "$TEMP/d2o-module-proc/net" \
    "$TEMP/r2o-module-proc/net" "$TEMP/module-load-sys" "$TEMP/module-load-ko"
cat > "$TEMP/module-load-bin/modprobe" <<'MODPROBE'
#!/bin/sh
printf '%s\n' "$1" >> "$MODULE_TRACE"
if [ "$1" = ip6table_mangle ]; then
    printf 'mangle\n' > "$MODULE_PROC_DIR/net/ip6_tables_names"
    exit 0
fi
exit 1
MODPROBE
cat > "$TEMP/module-load-bin/lsmod" <<'LSMOD'
#!/bin/sh
exit 0
LSMOD
cat > "$TEMP/module-load-bin/ip6tables" <<'IP6TABLES'
#!/bin/sh
case " $* " in
    *' -L '*) grep -qw mangle "$R2O_PROC_DIR/net/ip6_tables_names" 2>/dev/null ;;
    *' -D '*|*' -C '*) exit 1 ;;
    *) printf '%s\n' "$*" >> "$FW_TRACE"; exit 0 ;;
esac
IP6TABLES
chmod 0700 "$TEMP/module-load-bin/modprobe" "$TEMP/module-load-bin/lsmod" \
    "$TEMP/module-load-bin/ip6tables"
cat > "$TEMP/d2o-module-probe" <<'D2OMODULE'
#!/bin/sh
PROC_DIR=$MODULE_PROC_DIR
SYS_MODULE_DIR=$MODULE_SYS_DIR
MODULES_DIR=$MODULES_ROOT
FW_BACKEND=${MODULE_BACKEND:-iptables}
D2K_MODULES=${MODULE_LIST:-'nfnetlink_queue xt_NFQUEUE xt_conntrack xt_connbytes xt_multiport xt_mark xt_connmark xt_CONNMARK xt_addrtype xt_comment ip6table_mangle nf_conntrack_netlink'}
say() { :; }
. "$MODULE_FUNCTIONS"
load_modules
D2OMODULE
chmod 0700 "$TEMP/d2o-module-probe"
: > "$TEMP/d2o-module.trace"
MODULE_FUNCTIONS=$TEMP/d2o-module-functions.sh MODULE_PROC_DIR=$TEMP/d2o-module-proc \
    MODULE_SYS_DIR=$TEMP/module-load-sys MODULES_ROOT=$TEMP/module-load-ko \
    MODULE_TRACE=$TEMP/d2o-module.trace PATH=$TEMP/module-load-bin:/usr/bin:/bin \
    sh "$TEMP/d2o-module-probe"
: > "$TEMP/r2o-module.trace"
: > "$TEMP/r2o-module-rules.trace"
MODULE_PROC_DIR=$TEMP/r2o-module-proc MODULE_TRACE=$TEMP/r2o-module.trace \
    R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/module-load-r2o-run \
    R2O_PROC_DIR=$TEMP/r2o-module-proc R2O_SYS_MODULE_DIR=$TEMP/module-load-sys \
    R2O_MODULES_DIR=$TEMP/module-load-ko FW_BACKEND=iptables IPV6_ENABLED=1 \
    FW_TRACE=$TEMP/r2o-module-rules.trace PATH=$TEMP/module-load-bin:$TEMP/up-bin:/usr/bin:/bin \
    sh "$ROOT/router/r2o-firewall.sh" up
if ! cmp -s "$TEMP/d2o-module.trace" "$TEMP/r2o-module.trace"; then
    echo 'R2O kernel module load attempts differ from D2O load_modules' >&2
    diff -u "$TEMP/d2o-module.trace" "$TEMP/r2o-module.trace" >&2 || true
    failures=1
fi
grep -Fq -- '--queue-num 2001' "$TEMP/r2o-module-rules.trace" || {
    echo 'R2O did not install IPv6 rules after loading ip6table_mangle' >&2
    failures=1
}

mkdir -p "$TEMP/nft-bin" "$TEMP/d2o-nft-proc/net" "$TEMP/r2o-nft-proc/net" \
    "$TEMP/nft-sys" "$TEMP/nft-modules"
cat > "$TEMP/nft-bin/nft" <<'NFT'
#!/bin/sh
case "$1" in
    list) exit 1 ;;
    -f) exit 0 ;;
    *) exit 1 ;;
esac
NFT
chmod 0700 "$TEMP/nft-bin/nft"
: > "$TEMP/d2o-nft.trace"
MODULE_FUNCTIONS=$TEMP/d2o-module-functions.sh MODULE_PROC_DIR=$TEMP/d2o-nft-proc \
    MODULE_SYS_DIR=$TEMP/nft-sys MODULES_ROOT=$TEMP/nft-modules MODULE_BACKEND=nft \
    MODULE_LIST='nfnetlink_queue nft_queue nf_conntrack_netlink' \
    MODULE_TRACE=$TEMP/d2o-nft.trace PATH=$TEMP/module-load-bin:/usr/bin:/bin \
    sh "$TEMP/d2o-module-probe"
: > "$TEMP/r2o-nft.trace"
MODULE_PROC_DIR=$TEMP/r2o-nft-proc MODULE_TRACE=$TEMP/r2o-nft.trace \
    R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/nft-r2o-run \
    R2O_PROC_DIR=$TEMP/r2o-nft-proc R2O_SYS_MODULE_DIR=$TEMP/nft-sys \
    R2O_MODULES_DIR=$TEMP/nft-modules FW_BACKEND=nft IPV6_ENABLED=1 \
    PATH=$TEMP/nft-bin:$TEMP/module-load-bin:$TEMP/up-bin:/usr/bin:/bin \
    sh "$ROOT/router/r2o-firewall.sh" up 2>/dev/null
if ! cmp -s "$TEMP/d2o-nft.trace" "$TEMP/r2o-nft.trace"; then
    echo 'R2O nft kernel module load attempts differ from D2O load_modules' >&2
    diff -u "$TEMP/d2o-nft.trace" "$TEMP/r2o-nft.trace" >&2 || true
    failures=1
fi

mkdir -p "$TEMP/insmod-bin" "$TEMP/d2o-insmod-proc/net" \
    "$TEMP/r2o-insmod-proc/net" "$TEMP/d2o-insmod-sys" \
    "$TEMP/r2o-insmod-sys" "$TEMP/insmod-ko"
: > "$TEMP/insmod-ko/nfnetlink_queue.ko"
: > "$TEMP/insmod-ko/ip6table_mangle.ko"
cat > "$TEMP/insmod-bin/modprobe" <<'MODPROBE'
#!/bin/sh
printf '%s\n' "$1" >> "$MODULE_TRACE"
if [ "$1" = ip6table_mangle ]; then exit 0; fi
exit 1
MODPROBE
cat > "$TEMP/insmod-bin/lsmod" <<'LSMOD'
#!/bin/sh
exit 0
LSMOD
cat > "$TEMP/insmod-bin/insmod" <<'INSMOD'
#!/bin/sh
printf '%s\n' "$1" >> "$INSMOD_TRACE"
case "$1" in
    */nfnetlink_queue.ko) mkdir -p "$MODULE_SYS_DIR/nfnetlink_queue" ;;
    */ip6table_mangle.ko)
        mkdir -p "$MODULE_SYS_DIR/ip6table_mangle"
        printf 'mangle\n' > "$MODULE_PROC_DIR/net/ip6_tables_names"
        ;;
esac
exit 0
INSMOD
chmod 0700 "$TEMP/insmod-bin/modprobe" "$TEMP/insmod-bin/lsmod" "$TEMP/insmod-bin/insmod"
: > "$TEMP/d2o-insmod.trace"
: > "$TEMP/d2o-insmod-modprobe.trace"
MODULE_FUNCTIONS=$TEMP/d2o-module-functions.sh MODULE_PROC_DIR=$TEMP/d2o-insmod-proc \
    MODULE_SYS_DIR=$TEMP/d2o-insmod-sys MODULES_ROOT=$TEMP/insmod-ko \
    MODULE_TRACE=$TEMP/d2o-insmod-modprobe.trace INSMOD_TRACE=$TEMP/d2o-insmod.trace \
    PATH=$TEMP/insmod-bin:/usr/bin:/bin sh "$TEMP/d2o-module-probe"
: > "$TEMP/r2o-insmod.trace"
: > "$TEMP/r2o-insmod-modprobe.trace"
: > "$TEMP/r2o-insmod-rules.trace"
MODULE_PROC_DIR=$TEMP/r2o-insmod-proc MODULE_SYS_DIR=$TEMP/r2o-insmod-sys \
    MODULE_TRACE=$TEMP/r2o-insmod-modprobe.trace INSMOD_TRACE=$TEMP/r2o-insmod.trace \
    R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/insmod-r2o-run \
    R2O_PROC_DIR=$TEMP/r2o-insmod-proc R2O_SYS_MODULE_DIR=$TEMP/r2o-insmod-sys \
    R2O_MODULES_DIR=$TEMP/insmod-ko FW_BACKEND=iptables IPV6_ENABLED=1 \
    FW_TRACE=$TEMP/r2o-insmod-rules.trace PATH=$TEMP/insmod-bin:$TEMP/module-load-bin:$TEMP/up-bin:/usr/bin:/bin \
    sh "$ROOT/router/r2o-firewall.sh" up 2>"$TEMP/r2o-insmod.stderr" || {
        cat "$TEMP/r2o-insmod.stderr" >&2
        failures=1
    }
if ! cmp -s "$TEMP/d2o-insmod.trace" "$TEMP/r2o-insmod.trace" ||
    ! cmp -s "$TEMP/d2o-insmod-modprobe.trace" "$TEMP/r2o-insmod-modprobe.trace"; then
    echo 'R2O insmod fallback attempts differ from D2O load_modules' >&2
    diff -u "$TEMP/d2o-insmod.trace" "$TEMP/r2o-insmod.trace" >&2 || true
    diff -u "$TEMP/d2o-insmod-modprobe.trace" "$TEMP/r2o-insmod-modprobe.trace" >&2 || true
    failures=1
fi
grep -Fq -- '--queue-num 2001' "$TEMP/r2o-insmod-rules.trace" || {
    echo 'R2O did not install IPv6 rules after insmod fallback' >&2
    failures=1
}

mkdir -p "$TEMP/status-bin"
cat > "$TEMP/status-bin/iptables" <<'IPTABLES'
#!/bin/sh
case " $* " in *' -C '*) exit 0 ;; esac
exit 0
IPTABLES
cat > "$TEMP/status-bin/ip6tables" <<'IP6TABLES'
#!/bin/sh
printf '%s\n' "$*" >> "$STATUS_TRACE"
case " $* " in
    *' -L '*) grep -qw mangle "$R2O_PROC_DIR/net/ip6_tables_names" 2>/dev/null ;;
    *' -C '*) exit 1 ;;
    *) exit 0 ;;
esac
IP6TABLES
chmod 0700 "$TEMP/status-bin/iptables" "$TEMP/status-bin/ip6tables"
printf 'mangle\n' > "$TEMP/empty-proc/net/ip6_tables_names"
: > "$TEMP/status-ip6.trace"
if R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/r2o-run \
    R2O_PROC_DIR=$TEMP/empty-proc R2O_SYS_MODULE_DIR=$TEMP/empty-sys \
    R2O_MODULES_DIR=$TEMP/empty-modules FW_BACKEND=iptables IPV6_ENABLED=1 \
    STATUS_TRACE=$TEMP/status-ip6.trace PATH=$TEMP/status-bin:/usr/bin:/bin \
    sh "$ROOT/router/r2o-firewall.sh" status; then r2o_status_rc=0; else r2o_status_rc=$?; fi
[ "$r2o_status_rc" = 0 ] && ! grep -q -- ' -C ' "$TEMP/status-ip6.trace" || {
    echo 'R2O did not preserve D2O IPv4-only status after mangle became available' >&2
    failures=1
}
: > "$TEMP/r2o-reapply.trace"
R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/r2o-run \
    R2O_PROC_DIR=$TEMP/empty-proc R2O_SYS_MODULE_DIR=$TEMP/empty-sys \
    R2O_MODULES_DIR=$TEMP/empty-modules FW_BACKEND=iptables IPV6_ENABLED=1 \
    FW_TRACE=$TEMP/r2o-reapply.trace PATH=$TEMP/no-modprobe-bin:$TEMP/module-load-bin:$TEMP/up-bin:/usr/bin:/bin \
    sh "$ROOT/router/r2o-firewall.sh" up
[ ! -f "$TEMP/r2o-run/fw-ipv4-only" ] && grep -Fq -- '--queue-num 2001' "$TEMP/r2o-reapply.trace" || {
    echo 'R2O explicit reapply did not clear IPv4-only state and restore IPv6 rules' >&2
    failures=1
}

cat > "$TEMP/r2o-ipv6-harness" <<'R2OIPV6'
#!/bin/sh
ROOT=$R2O_ROOT
CONF=$R2O_CONFIG
RUN=$R2O_RUN_DIR
FIREWALL=$R2O_FIREWALL
R2O_FW=iptables
IPV6_ENABLED=1
say() { :; }
die() { echo "$*" >&2; exit 1; }
component_running() { [ "$2" = running ]; }
. "$R2O_IPV6_FUNCTIONS"
configure_ipv6
if [ "$IPV6_ENABLED/$R2O_IPV6_ENABLED_RUNTIME" != 1/0 ]; then
    printf 'R2O changed configured IPV6_ENABLED while applying runtime fallback: %s/%s\n' \
        "$IPV6_ENABLED" "$R2O_IPV6_ENABLED_RUNTIME" >&2
    exit 1
fi
DP6_PID=stopped
CT6_PID=stopped
if ipv6_components_running; then exit 1; fi
DP6_PID=running
CT6_PID=running
ipv6_components_running
IPV6_ENABLED=0
DP6_PID=running
CT6_PID=stopped
if ipv6_components_running; then
    echo 'R2O accepted stale IPv6 components after IPV6_ENABLED=0' >&2
    exit 1
fi
DP6_PID=stopped
CT6_PID=stopped
ipv6_components_running
R2OIPV6
cat > "$TEMP/r2o-install-harness" <<'INSTALL'
#!/bin/sh
ROOT=$INSTALL_ROOT
PLATFORM=keenetic
say() { :; }
die() { echo "$*" >&2; exit 1; }
. "$INSTALL_FUNCTION"
check_runtime_dependencies
INSTALL
chmod 0700 "$TEMP/r2o-ipv6-harness" "$TEMP/r2o-install-harness"
cat > "$TEMP/ipv6-config" <<'CONFIG'
FW_BACKEND=iptables
IPV6_ENABLED=1
TG_ENABLED=0
CONFIG
R2O_ROOT=$TEMP/root R2O_CONFIG=$TEMP/ipv6-config R2O_RUN_DIR=$TEMP/s99-run \
    R2O_FIREWALL=$ROOT/router/r2o-firewall.sh R2O_IPV6_FUNCTIONS=$TEMP/r2o-ipv6-functions.sh \
    R2O_IPV6_ENABLED_RUNTIME= PATH=$TEMP/up-bin:/usr/bin:/bin \
    sh "$TEMP/r2o-ipv6-harness"

cat > "$TEMP/up-bin/ip6tables" <<'IP6TABLES'
#!/bin/sh
printf '%s\n' "$*" >> "$FW_TRACE"
for arg do case "$arg" in -D|-C) exit 1 ;; esac; done
exit 0
IP6TABLES
chmod 0700 "$TEMP/up-bin/ip6tables"
cat > "$TEMP/r2o-ipv6-restore-harness" <<'R2ORESTORE'
#!/bin/sh
ROOT=$R2O_ROOT
CONF=$R2O_CONFIG
RUN=$R2O_RUN_DIR
FIREWALL=$R2O_FIREWALL
R2O_FW=iptables
IPV6_ENABLED=1
say() { :; }
die() { echo "$*" >&2; exit 1; }
component_running() { [ "$2" = running ]; }
. "$R2O_IPV6_FUNCTIONS"
configure_ipv6
[ "$IPV6_ENABLED/$R2O_IPV6_ENABLED_RUNTIME" = 1/1 ] || exit 1
DP6_PID=running
CT6_PID=running
ipv6_components_running
R2ORESTORE
chmod 0700 "$TEMP/r2o-ipv6-restore-harness"
R2O_ROOT=$TEMP/root R2O_CONFIG=$TEMP/ipv6-config R2O_RUN_DIR=$TEMP/s99-run \
    R2O_FIREWALL=$ROOT/router/r2o-firewall.sh R2O_IPV6_FUNCTIONS=$TEMP/r2o-ipv6-functions.sh \
    R2O_IPV6_ENABLED_RUNTIME= PATH=$TEMP/up-bin:/usr/bin:/bin \
    sh "$TEMP/r2o-ipv6-restore-harness"
: > "$TEMP/r2o-restored.trace"
R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/r2o-restored-run \
    FW_BACKEND=iptables IPV6_ENABLED=1 R2O_IPV6_ENABLED_RUNTIME=1 \
    FW_TRACE=$TEMP/r2o-restored.trace PATH=$TEMP/up-bin:/usr/bin:/bin \
    sh "$ROOT/router/r2o-firewall.sh" up
grep -Fq -- '--queue-num 2001' "$TEMP/r2o-restored.trace" || {
    echo 'R2O did not restore IPv6 NFQUEUE rules after mangle became available' >&2
    failures=1
}

mkdir -p "$TEMP/install-root"
cat > "$TEMP/install-root/config" <<'CONFIG'
FW_BACKEND=iptables
IPV6_ENABLED=1
TG_ENABLED=0
CONFIG
INSTALL_ROOT=$TEMP/install-root INSTALL_FUNCTION=$TEMP/r2o-install-function.sh \
    PATH=$TEMP/up-bin:/usr/bin:/bin sh "$TEMP/r2o-install-harness"
cat > "$TEMP/install-root/config" <<'CONFIG'
FW_BACKEND=iptables
IPV6_ENABLED=1
TG_ENABLED=1
CONFIG
if INSTALL_ROOT=$TEMP/install-root INSTALL_FUNCTION=$TEMP/r2o-install-function.sh \
    PATH=$TEMP/up-bin:/usr/bin:/bin sh "$TEMP/r2o-install-harness" 2>/dev/null; then
    echo 'installer accepted Telegram + IPv6 without ip6tables' >&2
    failures=1
fi

cat > "$TEMP/d2o-down-probe" <<'D2ODOWN'
#!/bin/sh
. "$D2O_FUNCTIONS"
ppe_down() { printf 'ppe-down\n' >> "$FW_TRACE"; }
fw_family_down() { printf '%s\n' "$1" >> "$FW_TRACE"; }
fw_iptables_down
D2ODOWN
chmod 0700 "$TEMP/d2o-down-probe"
: > "$TEMP/d2o-down.trace"
D2O_FUNCTIONS=$TEMP/d2o-firewall-functions.sh FW_TRACE=$TEMP/d2o-down.trace \
    PATH=$TEMP/down-bin:/usr/bin:/bin sh "$TEMP/d2o-down-probe"
grep -Fxq ip6tables "$TEMP/d2o-down.trace" || {
    echo 'D2O down fixture did not clean the IPv6 family' >&2
    failures=1
}

: > "$TEMP/r2o-down.trace"
mkdir -p "$TEMP/r2o-down-run"
: > "$TEMP/r2o-down-run/fw-ipv4-only"
R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/r2o-down-run \
    FW_BACKEND=iptables IPV6_ENABLED=0 FW_TRACE=$TEMP/r2o-down.trace \
    PATH=$TEMP/down-bin:/usr/bin:/bin sh "$ROOT/router/r2o-firewall.sh" down
grep -q '^ip6tables ' "$TEMP/r2o-down.trace" || {
    echo 'R2O down left stale IPv6 rules when IPV6_ENABLED=0' >&2
    failures=1
}
[ ! -f "$TEMP/r2o-down-run/fw-ipv4-only" ] || {
    echo 'R2O down left the persistent IPv4-only marker behind' >&2
    failures=1
}

[ "$failures" = 0 ] || exit 1
printf 'D2O/R2O IPv4-only firewall fallback and disabled-family cleanup match %s.\n' "$ACTUAL_D2O_SHA"
