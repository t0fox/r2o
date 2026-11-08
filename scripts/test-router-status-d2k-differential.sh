#!/bin/sh
# B8: C/Rust differential статуса роутера.
#
# C-оракул — `status()` из files/S99d2k; Rust — `status_d2k()` из router/S99r2o.
# Проверяются работающее и остановленное состояния, коды firewall/policy/telegram.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-router-status.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

awk '/^status\(\) \{/{p=1} p{print} p&&/^}/{exit}' "$D2O_ROOT/files/S99d2k" | tr -d '\r' > "$TEMP/c-status.sh"
awk '/^status_d2k\(\) \{/{p=1} p{print} p&&/^}/{exit}' "$ROOT/router/S99r2o" | tr -d '\r' > "$TEMP/r2o-status.sh"
[ -s "$TEMP/c-status.sh" ] || { echo "не извлечён C status()" >&2; exit 1; }
[ -s "$TEMP/r2o-status.sh" ] || { echo "не извлечён status_d2k()" >&2; exit 1; }

cat > "$TEMP/version" <<'EOF'
#!/bin/sh
printf 'r2o release=test wire=48\n'
EOF
chmod 0755 "$TEMP/version"

run_case() {
    name=$1
    running=$2
    firewall_ok=$3
    policy=$4
    tg_enabled=$5
    c_out=$TEMP/$name.c
    r_out=$TEMP/$name.r

    cat > "$TEMP/$name-c.sh" <<EOF
. "$TEMP/c-status.sh"
NAME=r2o
DP_PID=$TEMP/dp.pid; CT_PID=$TEMP/ct.pid; PN_PID=$TEMP/pn.pid
TG_PID=$TEMP/tg.pid; DNS_SCHED_PID=$TEMP/dns.pid; UPD_PID=$TEMP/upd.pid; HL_PID=$TEMP/hl.pid
printf '111\n' > "\$DP_PID"; printf '222\n' > "\$CT_PID"; printf '333\n' > "\$PN_PID"
printf '444\n' > "\$TG_PID"; printf '555\n' > "\$DNS_SCHED_PID"
printf '666\n' > "\$UPD_PID"; printf '777\n' > "\$HL_PID"
TG_ENABLED=$tg_enabled
KEENETIC_POLICY=Policy0
FW_V4ONLY=$TEMP/no-v4only
FW_BACKEND=nft
QUEUE_NUM=65534
BIN=$TEMP/version
running() {
    [ "$running" = 1 ] || return 1
    case "\$1" in "\$DP_PID"|"\$CT_PID"|"\$PN_PID"|"\$TG_PID"|"\$DNS_SCHED_PID"|"\$UPD_PID"|"\$HL_PID") return 0;; esac
    return 1
}
fw_installed() { [ "$firewall_ok" = 1 ]; }
policy_mark() { [ "$policy" = found ] && printf '1234\n'; }
status
EOF
    sh "$TEMP/$name-c.sh" > "$c_out"

    cat > "$TEMP/$name-r.sh" <<EOF
. "$TEMP/r2o-status.sh"
NAME=r2o
DP4_PID=$TEMP/dp.pid; CT4_PID=$TEMP/ct.pid; PN_PID=$TEMP/pn.pid
TG_PID=$TEMP/tg.pid; META_DNS_PID=$TEMP/dns.pid; UPD_PID=$TEMP/upd.pid
FW_WD_PID=$TEMP/hl.pid
printf '111\n' > "\$DP4_PID"; printf '222\n' > "\$CT4_PID"; printf '333\n' > "\$PN_PID"
printf '444\n' > "\$TG_PID"; printf '555\n' > "\$META_DNS_PID"
printf '666\n' > "\$UPD_PID"; printf '777\n' > "\$FW_WD_PID"
TG_ENABLED=$tg_enabled
KEENETIC_POLICY=Policy0
FW_V4ONLY=$TEMP/no-v4only
FW_BACKEND=nft
QUEUE4=65534
NFQUEUE_STATUS=$TEMP/nfqueue
: > "\$NFQUEUE_STATUS"
ROOT=$TEMP/root
MANAGER=$TEMP/version
FIREWALL=$TEMP/firewall
printf '#!/bin/sh\nexit %s\n' "$([ "$firewall_ok" = 1 ] && echo 0 || echo 1)" > "\$FIREWALL"
chmod 0755 "\$FIREWALL"
component_running() {
    [ "$running" = 1 ] || return 1
    case "\$2" in "\$DP4_PID"|"\$CT4_PID"|"\$PN_PID"|"\$TG_PID") return 0;; esac
    return 1
}
meta_dns_scheduler_running() { [ "$running" = 1 ] && [ -s "\$META_DNS_PID" ]; }
update_scheduler_running() { [ "$running" = 1 ] && [ -s "\$UPD_PID" ]; }
firewall_watchdog_running() { [ "$running" = 1 ] && [ -s "\$FW_WD_PID" ]; }
r2o_keenetic_policy_mark() { [ "$policy" = found ] && printf '1234\n'; }
status_d2k
EOF
    sh "$TEMP/$name-r.sh" > "$r_out"

    if ! diff -u "$c_out" "$r_out"; then
        echo "FAIL: router status $name" >&2
        exit 1
    fi
}

run_case running 1 1 found 1
run_case stopped 0 0 missing 0

printf 'PASS: D2O status fields/codes match R2O status --d2k (D2O %s)\n' "$ACTUAL_D2O_SHA"
