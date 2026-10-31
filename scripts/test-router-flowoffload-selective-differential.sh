#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-flowoffload-selective.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin" "$TEMP/run" "$TEMP/proc/net" "$TEMP/sys" "$TEMP/modules" "$TEMP/nft"

cat >"$TEMP/bin/nft" <<'NFT'
#!/bin/sh
case "$*" in
    'list table inet r2o'|'-a list table inet r2o')
        [ -f "$NFT_STATE_DIR/r2o" ] || exit 1
        echo 'table inet r2o { comment "r2o-managed"; }'
        ;;
    'list table inet r2o_rst'|'-a list table inet r2o_rst'|\
    'list chain inet r2o_rst output'|'list set inet r2o_rst rst4'|'list set inet r2o_rst rst6')
        [ -f "$NFT_STATE_DIR/r2o_rst" ] || exit 1
        echo 'table inet r2o_rst { comment "r2o-managed"; }'
        ;;
    'list chain inet fw4 forward'|'-a list chain inet fw4 forward')
        [ -f "$NFT_STATE_DIR/fw4-forward" ] || exit 1
        cat "$NFT_STATE_DIR/fw4-forward"
        [ ! -f "$NFT_STATE_DIR/fw4-extra-forward" ] || cat "$NFT_STATE_DIR/fw4-extra-forward"
        ;;
    'list flowtable inet fw4 ft'|'-a list flowtable inet fw4 ft')
        [ -f "$NFT_STATE_DIR/fw4-ft" ] || exit 1
        cat "$NFT_STATE_DIR/fw4-ft"
        ;;
    'list table inet fw4'|'-a list table inet fw4')
        printf 'table inet fw4 {\n'
        cat "$NFT_STATE_DIR/fw4-ft"
        [ ! -f "$NFT_STATE_DIR/fw4-alt-ft" ] || cat "$NFT_STATE_DIR/fw4-alt-ft"
        printf '\nchain forward {\n'
        cat "$NFT_STATE_DIR/fw4-forward"
        [ ! -f "$NFT_STATE_DIR/fw4-extra-forward" ] || cat "$NFT_STATE_DIR/fw4-extra-forward"
        printf '}\n'
        ;;
    '-f '*)
        rules=$2
        case "$rules" in
            *firewall-rst.nft.*) : >"$NFT_STATE_DIR/r2o_rst" ;;
            *firewall.nft.*)
                cp "$rules" "$NFT_STATE_DIR/r2o-rules"
                : >"$NFT_STATE_DIR/r2o"
                ;;
            *flowoffload.nft.*)
                if [ "${NFT_FAIL_SELECTIVE:-0}" = 1 ] && grep -q 'flow offload @ft' "$rules"; then exit 1; fi
                if grep -q 'delete rule inet fw4 forward handle' "$rules"; then
                    if grep -q 'delete rule inet fw4 forward handle 18' "$rules"; then rm -f "$NFT_STATE_DIR/fw4-extra-forward"; fi
                    if grep -q 'delete flowtable inet fw4 ft' "$rules"; then
                        rm -f "$NFT_STATE_DIR/fw4-ft"
                        printf '%s\n' "$(( $(cat "$NFT_STATE_DIR/flowtable-resets" 2>/dev/null || echo 0) + 1 ))" >"$NFT_STATE_DIR/flowtable-resets"
                    fi
                    if grep -q 'delete flowtable inet fw4 altft' "$rules"; then rm -f "$NFT_STATE_DIR/fw4-alt-ft"; fi
                    if grep -q 'add flowtable inet fw4 ft' "$rules"; then
                        sed -n '/^add flowtable inet fw4 ft {/,/^}/p' "$rules" \
                            | sed 's/^add flowtable inet fw4 ft /flowtable ft /' >"$NFT_STATE_DIR/fw4-ft"
                    fi
                    if grep -q 'flow offload @ft' "$rules"; then
                        if grep -q 'ct mark & 0x80000000 == 0 flow offload @ft' "$rules"; then
                            printf '%s\n' 'meta l4proto { tcp, udp } ct mark & 0x80000000 == 0 flow offload @ft comment "r2o-flowoffload" # handle 5' >"$NFT_STATE_DIR/fw4-forward"
                        else
                            printf '%s\n' 'meta l4proto { tcp, udp } flow offload @ft # handle 5' >"$NFT_STATE_DIR/fw4-forward"
                        fi
                        [ ! -f "$NFT_STATE_DIR/fw4-extra-forward" ] || cat "$NFT_STATE_DIR/fw4-extra-forward" >>"$NFT_STATE_DIR/fw4-forward"
                    else
                        : >"$NFT_STATE_DIR/fw4-forward"
                        rm -f "$NFT_STATE_DIR/fw4-extra-forward"
                    fi
                fi
                ;;
            *) echo "unexpected nft file: $rules" >&2; exit 2 ;;
        esac
        ;;
    replace\ rule\ inet\ fw4\ forward\ handle\ *)
        shift 6
        handle=$1
        shift
        expression=$*
        case "$handle" in ''|*[!0-9]*) handle=5 ;; esac
        printf '%s # handle %s\n' "$expression" "$handle" >"$NFT_STATE_DIR/fw4-forward"
        ;;
    delete\ table\ inet\ r2o) rm -f "$NFT_STATE_DIR/r2o" ;;
    delete\ table\ inet\ r2o_rst) rm -f "$NFT_STATE_DIR/r2o_rst" ;;
    *) echo "unexpected nft command: $*" >&2; exit 2 ;;
esac
NFT
for tool in modprobe insmod; do printf '#!/bin/sh\nexit 1\n' >"$TEMP/bin/$tool"; done
printf '#!/bin/sh\nexit 0\n' >"$TEMP/bin/lsmod"
chmod 0755 "$TEMP/bin/nft" "$TEMP/bin/modprobe" "$TEMP/bin/insmod" "$TEMP/bin/lsmod"
cat >"$TEMP/bin/fw4" <<'FW4'
#!/bin/sh
case "${1:-}" in
    reload)
        cp "$NFT_STATE_DIR/fw4-forward.initial" "$NFT_STATE_DIR/fw4-forward"
        cp "$NFT_STATE_DIR/fw4-ft.initial" "$NFT_STATE_DIR/fw4-ft"
        if [ -f "$NFT_STATE_DIR/fw4-extra-forward.initial" ]; then cp "$NFT_STATE_DIR/fw4-extra-forward.initial" "$NFT_STATE_DIR/fw4-extra-forward"; else rm -f "$NFT_STATE_DIR/fw4-extra-forward"; fi
        if [ -f "$NFT_STATE_DIR/fw4-alt-ft.initial" ]; then cp "$NFT_STATE_DIR/fw4-alt-ft.initial" "$NFT_STATE_DIR/fw4-alt-ft"; else rm -f "$NFT_STATE_DIR/fw4-alt-ft"; fi
        printf '%s\n' "$(( $(cat "$NFT_STATE_DIR/fw4-reloads" 2>/dev/null || echo 0) + 1 ))" >"$NFT_STATE_DIR/fw4-reloads"
        ;;
    *) exit 2 ;;
esac
FW4
chmod 0755 "$TEMP/bin/fw4"

cat >"$TEMP/config" <<'CONFIG'
FW_BACKEND=nft
IPV6_ENABLED=0
PORTS=443,5222
CONNBYTES=0:8
VOICE_PORTS=3478:3481,50000:50099
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
DNS_PORTS=53,853
CONFIG
cat >"$TEMP/nft/fw4-forward" <<'RULE'
meta l4proto { tcp, udp } flow offload @ft # handle 5
ct state vmap { established : accept, related : accept } # handle 6
RULE
cat >"$TEMP/nft/fw4-ft" <<'FLOWTABLE'
flowtable ft {
    hook ingress priority 0;
    devices = { br-lan, eth0 };
    counter;
    flags offload;
}
FLOWTABLE
cp "$TEMP/nft/fw4-forward" "$TEMP/nft/fw4-forward.initial"
cp "$TEMP/nft/fw4-ft" "$TEMP/nft/fw4-ft.initial"

firewall() {
    R2O_DIR=$TEMP R2O_CONFIG=$TEMP/config R2O_RUN_DIR=$TEMP/run \
    R2O_PROC_DIR=$TEMP/proc R2O_SYS_MODULE_DIR=$TEMP/sys R2O_MODULES_DIR=$TEMP/modules \
    R2O_PPE_DEOFFLOAD=0 R2O_FW4="$TEMP/bin/fw4" NFT_STATE_DIR=$TEMP/nft \
    PATH="$TEMP/bin:$PATH" sh "$ROOT/router/r2o-firewall.sh" "$@"
}

firewall up

rules=$TEMP/nft/r2o-rules
[ -s "$rules" ] || { echo "R2O nft rules were not captured" >&2; exit 1; }
grep -Fq 'chain mark_flow' "$rules" || { echo "missing first-packet conntrack mark chain" >&2; exit 1; }
grep -Fq 'meta l4proto { tcp, udp } th dport { 53, 853 } return' "$rules" || { echo "DNS exclusions changed" >&2; exit 1; }
grep -Fq 'ct status dnat return' "$rules" || { echo "DNAT exclusions changed" >&2; exit 1; }
grep -Fq 'meta mark != 45 meta mark != 0x40000000' "$rules" || { echo "R2O/Telegram packet marks are not excluded" >&2; exit 1; }
grep -Fq 'th dport != { 3478-3481, 50000-50099 }' "$rules" || { echo "generic UDP marking overlaps the shorter voice window" >&2; exit 1; }
grep -Fq 'th dport { 443, 5222 } ct original packets 0-8 ct mark set ct mark | 0x80000000' "$rules" || {
    echo "original R2O flows are not marked from their first analysis packet" >&2
    exit 1
}
grep -Fq 'th sport { 443, 5222 } ct reply packets 0-8 ct mark set ct mark | 0x80000000' "$rules" || {
    echo "reply R2O flows are not marked during their analysis window" >&2
    exit 1
}
grep -Fq 'th dport { 3478-3481, 50000-50099 } ct original packets 0-4 ct mark set ct mark | 0x80000000' "$rules" || {
    echo "voice flows do not use their smaller analysis window" >&2
    exit 1
}
grep -Fq 'ct mark set ct mark & 0x7fffffff' "$rules" || {
    echo "completed analysis windows never release native offload" >&2
    exit 1
}
grep -Fq 'ct mark & 0x80000000 != 0 ct original packets 9-18446744073709551615 ct reply packets 9-18446744073709551615 ct mark set ct mark & 0x7fffffff' "$rules" || {
    echo "marked flows are released before both analysis windows have completed" >&2
    exit 1
}
grep -Fq 'ct mark & 0x80000000 != 0 meta l4proto udp ct original packets 5-18446744073709551615 ct reply packets 5-18446744073709551615 th dport { 3478-3481, 50000-50099 } ct mark set ct mark & 0x7fffffff' "$rules" || {
    echo "voice flows do not release offload at their own analysis boundary" >&2
    exit 1
}
grep -Fq 'tcp flags & rst == rst ct mark set ct mark | 0x80000000' "$rules" || {
    echo "late TCP resets are no longer visible to NFQUEUE" >&2
    exit 1
}
grep -Fq 'ct mark & 0x80000000 == 0 flow offload @ft' "$TEMP/nft/fw4-forward" || {
    echo "fw4 flow offload rule still includes R2O-marked connections" >&2
    exit 1
}

[ "$(cat "$TEMP/run/flow-offloading.runtime")" = selective ] || {
    echo "selective offload state was not saved" >&2
    exit 1
}
for attr in 'devices = { br-lan, eth0 };' 'counter;' 'flags offload;'; do
    grep -Fq "$attr" "$TEMP/nft/fw4-ft" || {
        echo "selective rewrite did not preserve fw4 flowtable attribute: $attr" >&2
        exit 1
    }
done

initial_resets=$(cat "$TEMP/nft/flowtable-resets")
firewall down
firewall up
[ "$(cat "$TEMP/nft/flowtable-resets")" = "$((initial_resets + 1))" ] || {
    echo "reinstalling a missing R2O table did not flush flows created during the gap" >&2
    exit 1
}
grep -Fq 'ct mark & 0x80000000 == 0 flow offload @ft' "$TEMP/nft/fw4-forward" || {
    echo "reinstalling R2O lost the selective flow rule" >&2
    exit 1
}

flow_resets=$(cat "$TEMP/nft/flowtable-resets")
firewall flowoffload-ensure
[ "$(cat "$TEMP/nft/flowtable-resets")" = "$flow_resets" ] || {
    echo "repeated ensure unnecessarily reset the native flowtable" >&2
    exit 1
}

NFT_STATE_DIR=$TEMP/nft "$TEMP/bin/fw4" reload
firewall flowoffload-ensure
grep -Fq 'ct mark & 0x80000000 == 0 flow offload @ft' "$TEMP/nft/fw4-forward" || {
    echo "fw4 reload lost R2O's selective flow rule" >&2
    exit 1
}
[ "$(cat "$TEMP/nft/flowtable-resets")" = "$((flow_resets + 1))" ] || {
    echo "fw4 reload recovery did not flush flows created before the include hook" >&2
    exit 1
}

NFT_STATE_DIR=$TEMP/nft "$TEMP/bin/fw4" reload
export NFT_FAIL_SELECTIVE=1
firewall flowoffload-ensure
unset NFT_FAIL_SELECTIVE
[ "$(cat "$TEMP/run/flow-offloading.runtime")" = fallback ] || {
    echo "failed selective transaction did not enter runtime fallback" >&2
    exit 1
}
[ ! -e "$TEMP/nft/fw4-ft" ] || { echo "failed selective transaction left flowtable entries active" >&2; exit 1; }
firewall flowoffload-restore
grep -Fq 'flow offload @ft' "$TEMP/nft/fw4-forward" || { echo "failed selective transaction was not restored from fw4" >&2; exit 1; }

printf '%s\n' 'meta l4proto { tcp, udp } flow offload @ft comment "r2o-flowoffload" # handle 5' >"$TEMP/nft/fw4-forward"
firewall flowoffload-ensure
[ "$(cat "$TEMP/run/flow-offloading.runtime")" = fallback ] || {
    echo "a stale R2O comment without the ct-mark predicate did not enter runtime fallback" >&2
    exit 1
}
[ ! -e "$TEMP/nft/fw4-ft" ] || { echo "a stale R2O comment left flowtable entries active" >&2; exit 1; }
firewall flowoffload-restore
grep -Fq 'flow offload @ft' "$TEMP/nft/fw4-forward" || { echo "stale R2O rule was not restored from fw4" >&2; exit 1; }

printf '%s\n' 'ct state established meta l4proto { tcp, udp } flow offload @ft # handle 12' >"$TEMP/nft/fw4-forward"
firewall flowoffload-ensure
[ "$(cat "$TEMP/run/flow-offloading.runtime")" = fallback ] || {
    echo "unrecognized fw4 rule did not enter runtime fallback" >&2
    exit 1
}
[ ! -e "$TEMP/nft/fw4-ft" ] || { echo "runtime fallback left flowtable entries active" >&2; exit 1; }
firewall flowoffload-restore
[ ! -e "$TEMP/run/flow-offloading.runtime" ] || { echo "flow-offload state was not cleared on restore" >&2; exit 1; }
grep -Fq 'flow offload @ft' "$TEMP/nft/fw4-forward" || { echo "fw4 restore did not reinstate native offload" >&2; exit 1; }

printf '%s\n' 'meta l4proto { tcp, udp } flow offload @altft # handle 17' >"$TEMP/nft/fw4-forward"
rm -f "$TEMP/nft/fw4-ft"
cat >"$TEMP/nft/fw4-alt-ft" <<'ALT_FLOWTABLE'
flowtable altft {
    hook ingress priority 0;
    devices = { br-lan, eth0 };
}
ALT_FLOWTABLE
firewall flowoffload-ensure
[ "$(cat "$TEMP/run/flow-offloading.runtime")" = fallback ] || {
    echo "an active fw4 offload rule with a nonstandard flowtable did not enter runtime fallback" >&2
    exit 1
}
[ ! -e "$TEMP/nft/fw4-alt-ft" ] || { echo "runtime fallback left the nonstandard flowtable active" >&2; exit 1; }
firewall flowoffload-restore
[ ! -e "$TEMP/run/flow-offloading.runtime" ] || { echo "nonstandard-flowtable state was not cleared on restore" >&2; exit 1; }
grep -Fq 'flow offload @ft' "$TEMP/nft/fw4-forward" || { echo "fw4 restore did not reinstate the configured native offload rule" >&2; exit 1; }

printf '%s\n' 'meta l4proto { tcp, udp } flow offload @altft # handle 18' >"$TEMP/nft/fw4-extra-forward"
cp "$TEMP/nft/fw4-extra-forward" "$TEMP/nft/fw4-extra-forward.initial"
cp "$TEMP/nft/fw4-ft.initial" "$TEMP/nft/fw4-ft"
cat >"$TEMP/nft/fw4-alt-ft" <<'ALT_FLOWTABLE'
flowtable altft {
    hook ingress priority 0;
    devices = { br-lan, eth0 };
}
ALT_FLOWTABLE
cp "$TEMP/nft/fw4-alt-ft" "$TEMP/nft/fw4-alt-ft.initial"
firewall flowoffload-ensure
[ "$(cat "$TEMP/run/flow-offloading.runtime")" = fallback ] || {
    echo "multiple fw4 offload rules did not enter runtime fallback" >&2
    exit 1
}
[ ! -e "$TEMP/nft/fw4-ft" ] && [ ! -e "$TEMP/nft/fw4-alt-ft" ] && [ ! -e "$TEMP/nft/fw4-extra-forward" ] || {
    echo "runtime fallback left another fw4 offload rule or flowtable active" >&2
    exit 1
}
firewall flowoffload-restore
grep -Fq 'flow offload @ft' "$TEMP/nft/fw4-forward" || { echo "fw4 reload did not restore the standard offload rule" >&2; exit 1; }
grep -Fq 'flow offload @altft' "$TEMP/nft/fw4-extra-forward" || { echo "fw4 reload did not restore the custom offload rule" >&2; exit 1; }
 [ -e "$TEMP/nft/fw4-ft" ] && [ -e "$TEMP/nft/fw4-alt-ft" ] || { echo "fw4 reload did not restore both configured flowtables" >&2; exit 1; }
firewall down
[ ! -e "$TEMP/nft/r2o" ] || { echo "R2O firewall table survived stop" >&2; exit 1; }

sed 's/^FW_BACKEND=nft$/FW_BACKEND=iptables/' "$TEMP/config" >"$TEMP/config.iptables"
mv -f "$TEMP/config.iptables" "$TEMP/config"
firewall flowoffload-ensure
[ "$(cat "$TEMP/run/flow-offloading.runtime" 2>/dev/null || true)" = fallback ] || {
    echo "iptables backend left fw4 flow offload active without selective conntrack marking" >&2
    exit 1
}
[ ! -e "$TEMP/nft/fw4-ft" ] || {
    echo "iptables backend fallback left the native fw4 flowtable active" >&2
    exit 1
}
firewall flowoffload-restore
grep -Fq 'flow offload @ft' "$TEMP/nft/fw4-forward" || {
    echo "iptables backend stop did not restore the configured fw4 flow offload" >&2
    exit 1
}

cat >"$TEMP/bin/iptables" <<'IPTABLES'
#!/bin/sh
case " $* " in
    *' -D '*) exit 1 ;;
    *' -C '*) exit 1 ;;
    *) exit 0 ;;
esac
IPTABLES
chmod 0755 "$TEMP/bin/iptables"
firewall up
[ "$(cat "$TEMP/run/flow-offloading.runtime" 2>/dev/null || true)" = fallback ] || {
    echo "iptables firewall startup did not disable unsupported fw4 offload" >&2
    exit 1
}
[ ! -e "$TEMP/nft/fw4-ft" ] || {
    echo "iptables firewall startup left native fw4 offload active" >&2
    exit 1
}
firewall down
firewall flowoffload-restore
grep -Fq 'flow offload @ft' "$TEMP/nft/fw4-forward" || {
    echo "iptables firewall stop did not restore fw4 offload" >&2
    exit 1
}

echo "test-router-flowoffload-selective-differential: selective marks preserve fw4 offload and unsupported backends restore it on stop"
