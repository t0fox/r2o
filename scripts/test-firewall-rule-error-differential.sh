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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-firewall-rule-error.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin" "$TEMP/root/run" "$TEMP/proc/net" "$TEMP/sys" "$TEMP/modules"
sed -n '/^fw_family_up() (/,/^)/p' "$D2O_ROOT/files/S99d2k" | tr -d '\r' > "$TEMP/d2o-family.sh"

cat > "$TEMP/bin/iptables" <<'IPTABLES'
#!/bin/sh
printf '%s\n' "$*" >> "$FW_TRACE"
case " $* " in
    *' -D '*|*' -C '*) exit 1 ;;
esac
for failure_pattern in "${D2O_FAIL_PATTERN:-}" "${R2O_FAIL_PATTERN:-}"; do
    [ -n "$failure_pattern" ] || continue
    case " $* " in *"$failure_pattern"*) exit 1 ;; esac
done
exit 0
IPTABLES
for tool in modprobe insmod; do
    printf '#!/bin/sh\nexit 1\n' > "$TEMP/bin/$tool"
done
printf '#!/bin/sh\nexit 0\n' > "$TEMP/bin/lsmod"
chmod 0700 "$TEMP/bin/iptables" "$TEMP/bin/modprobe" "$TEMP/bin/insmod" "$TEMP/bin/lsmod"

cat > "$TEMP/d2o-probe" <<'D2O'
#!/bin/sh
CHAIN_OUT=D2K_OUT
CHAIN_IN=D2K_IN
MARK=45
MEASURE_MARK=47
GATE_IP=
GATE_PORT=443
PORTS=0:65535
CONNBYTES=0:8
DNS_PORTS=53,853
QUEUE_NUM=2000
VOICE_PORTS=50000:50099
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
late_rst_from() { echo 9; }
fw_return_broadcast() { return 0; }
fw_icmp_te_rule() { return 0; }
. "$D2O_FUNCTIONS"
if fw_family_up iptables; then exit 0; else exit $?; fi
D2O
chmod 0700 "$TEMP/d2o-probe"
: > "$TEMP/d2o.trace"
if D2O_FUNCTIONS=$TEMP/d2o-family.sh FW_TRACE=$TEMP/d2o.trace \
    D2O_FAIL_PATTERN='-A D2K_OUT -s 127.0.0.0/8 -j RETURN' \
    PATH=$TEMP/bin:/usr/bin:/bin "$SH_BIN" "$TEMP/d2o-probe"; then d2o_rc=0; else d2o_rc=$?; fi

: > "$TEMP/r2o.trace"
if R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/root/run \
    R2O_PROC_DIR=$TEMP/proc R2O_SYS_MODULE_DIR=$TEMP/sys R2O_MODULES_DIR=$TEMP/modules \
    FW_BACKEND=iptables IPV6_ENABLED=0 FW_TRACE=$TEMP/r2o.trace \
    R2O_FAIL_PATTERN='-A R2O_OUT -s 127.0.0.0/8 -j RETURN' \
    PATH=$TEMP/bin:/usr/bin:/bin "$SH_BIN" "$ROOT/router/r2o-firewall.sh" up; then
    r2o_rc=0
else
    r2o_rc=$?
fi

grep -Fq -- '-A D2K_OUT -s 127.0.0.0/8 -j RETURN' "$TEMP/d2o.trace" || {
    echo 'D2O fixture did not reach the injected loopback rule failure' >&2
    exit 1
}
grep -Fq -- '-A R2O_OUT -s 127.0.0.0/8 -j RETURN' "$TEMP/r2o.trace" || {
    echo 'R2O fixture did not reach the injected loopback rule failure' >&2
    exit 1
}
[ "$d2o_rc" = "$r2o_rc" ] || {
    printf 'D2O returned %s but R2O returned %s after iptables rejected a rule\n' "$d2o_rc" "$r2o_rc" >&2
    exit 1
}
[ "$d2o_rc" = 1 ] || {
    printf 'expected both implementations to reject the incomplete firewall (got %s)\n' "$d2o_rc" >&2
    exit 1
}

: > "$TEMP/d2o-late.trace"
if D2O_FUNCTIONS=$TEMP/d2o-family.sh FW_TRACE=$TEMP/d2o-late.trace \
    D2O_FAIL_PATTERN='-I POSTROUTING -j D2K_OUT' \
    PATH=$TEMP/bin:/usr/bin:/bin "$SH_BIN" "$TEMP/d2o-probe"; then d2o_late_rc=0; else d2o_late_rc=$?; fi
: > "$TEMP/r2o-late.trace"
if R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/root/run \
    R2O_PROC_DIR=$TEMP/proc R2O_SYS_MODULE_DIR=$TEMP/sys R2O_MODULES_DIR=$TEMP/modules \
    FW_BACKEND=iptables IPV6_ENABLED=0 FW_TRACE=$TEMP/r2o-late.trace \
    R2O_FAIL_PATTERN='-I POSTROUTING 1 -j R2O_OUT' \
    PATH=$TEMP/bin:/usr/bin:/bin "$SH_BIN" "$ROOT/router/r2o-firewall.sh" up; then
    r2o_late_rc=0
else
    r2o_late_rc=$?
fi
[ "$d2o_late_rc" = "$r2o_late_rc" ] && [ "$d2o_late_rc" = 1 ] || {
    printf 'late hook failure returned D2O=%s R2O=%s\n' "$d2o_late_rc" "$r2o_late_rc" >&2
    exit 1
}

printf 'D2O/R2O reject early and late iptables rule-installation failures (%s).\n' "$ACTUAL_D2O_SHA"
