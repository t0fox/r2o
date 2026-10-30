#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-dns-exclusion.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin" "$TEMP/d2o-run" "$TEMP/r2o-run" "$TEMP/root"

sed 's/\r$//' "$D2O_ROOT/files/S99d2k" > "$TEMP/d2o-S99d2k"
sed -n '/^fw_lock_acquire() {/,/^}/p; /^fw_lock_release() {/,/^}/p; /^dns_upstreams() {/,/^}/p; /^dns_excl_rule() {/,/^}/p; /^dns_excl_sync_unlocked() {/,/^}/p; /^dns_excl_sync() {/,/^}/p' \
    "$TEMP/d2o-S99d2k" > "$TEMP/d2o-dns-functions.sh"
cat > "$TEMP/d2o-dns-harness" <<'D2O'
#!/bin/sh
FW_BACKEND=iptables
RUN=$D2O_RUN
CHAIN_OUT=D2K_OUT
CHAIN_IN=D2K_IN
FW_V4ONLY=$D2O_V4ONLY
FW_LOCK=$D2O_RUN/firewall-operation.lock
. "$D2O_FUNCTIONS"
case "${1:-}" in
    fresh) dns_excl_sync_unlocked fresh ;;
    locked) dns_excl_sync ;;
    *) dns_excl_sync_unlocked ;;
esac
D2O
cat > "$TEMP/bin/ndmc" <<'NDMC'
#!/bin/sh
cat "$DNS_CONFIG"
NDMC
cat > "$TEMP/bin/nslookup" <<'NSLOOKUP'
#!/bin/sh
[ "${DNS_FAIL:-0}" = 1 ] && exit 1
case "$1" in
    dns.example)
        printf 'Name: dns.example\nAddress 1: %s\n' "$DNS_IPV4"
        [ -n "${DNS_IPV6:-}" ] && printf 'Address 2: %s\n' "$DNS_IPV6"
        ;;
    *) exit 1 ;;
esac
NSLOOKUP
cat > "$TEMP/bin/iptables" <<'IPTABLES'
#!/bin/sh
tool=${0##*/}
database=$FW_DB_DIR/$tool.rules
printf '%s %s\n' "$tool" "$*" >> "$FW_TRACE"
action=
rule=
for arg do
    case "$arg" in
        -w) ;;
        -C|-I|-D) action=$arg ;;
        *) rule="$rule $arg" ;;
    esac
done
rule=${rule# }
case "$action" in
    -C)
        [ "${FW_CHECK_DELAY:-0}" = 1 ] && sleep 0.05
        while IFS= read -r saved; do [ "$saved" != "$rule" ] || exit 0; done < "$database"
        exit 1
        ;;
    -I)
        while IFS= read -r saved; do [ "$saved" != "$rule" ] || exit 0; done < "$database"
        printf '%s\n' "$rule" >> "$database"
        ;;
    -D) exit 1 ;;
esac
IPTABLES
cp "$TEMP/bin/iptables" "$TEMP/bin/ip6tables"
chmod 0700 "$TEMP/bin/ndmc" "$TEMP/bin/nslookup" "$TEMP/bin/iptables" "$TEMP/bin/ip6tables"
mkdir -p "$TEMP/d2o-db" "$TEMP/r2o-db"
: > "$TEMP/d2o-db/iptables.rules"
: > "$TEMP/d2o-db/ip6tables.rules"
: > "$TEMP/r2o-db/iptables.rules"
: > "$TEMP/r2o-db/ip6tables.rules"

cat > "$TEMP/dns-phase1" <<'DNS'
dns_server = 9.9.9.9 # 9.9.9.9
dns_server = 127.0.0.1 # https://dns.example/dns-query
dns_server = ::1 # tls://[2001:db8::1]:8853
DNS
cat > "$TEMP/dns-phase2" <<'DNS'
dns_server = 127.0.0.1 # https://dns.example/dns-query
dns_server = ::1 # tls://[2001:db8::1]:8853
DNS
cat > "$TEMP/dns-concurrent" <<'DNS'
dns_server = 9.9.9.9
DNS

d2o_sync() {
    D2O_RUN=$TEMP/d2o-run D2O_V4ONLY=$TEMP/no-ipv6 D2O_FUNCTIONS=$TEMP/d2o-dns-functions.sh \
        DNS_CONFIG=$DNS_CONFIG DNS_IPV4=$DNS_IPV4 DNS_IPV6=$DNS_IPV6 DNS_FAIL=$DNS_FAIL \
        FW_TRACE=$TEMP/d2o.trace FW_DB_DIR=$TEMP/d2o-db PATH="$TEMP/bin:$PATH" \
        sh "$TEMP/d2o-dns-harness" "${1:-}"
}
r2o_sync() {
    R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/r2o-run \
        R2O_RUNTIME_DIR=$TEMP/runtime FW_BACKEND=iptables IPV6_ENABLED=1 \
        DNS_CONFIG=$DNS_CONFIG DNS_IPV4=$DNS_IPV4 DNS_IPV6=$DNS_IPV6 DNS_FAIL=$DNS_FAIL \
        FW_TRACE=$TEMP/r2o.trace FW_DB_DIR=$TEMP/r2o-db PATH="$TEMP/bin:$PATH" \
        sh "$ROOT/router/r2o-firewall.sh" dns-ensure
}
r2o_up() {
    R2O_DIR=$TEMP/root R2O_CONFIG=/dev/null R2O_RUN_DIR=$TEMP/r2o-run \
        R2O_RUNTIME_DIR=$TEMP/runtime FW_BACKEND=iptables IPV6_ENABLED=1 \
        DNS_CONFIG=$DNS_CONFIG DNS_IPV4=$DNS_IPV4 DNS_IPV6=$DNS_IPV6 DNS_FAIL=$DNS_FAIL \
        FW_TRACE=$TEMP/r2o.trace FW_DB_DIR=$TEMP/r2o-db PATH="$TEMP/bin:$PATH" \
        sh "$ROOT/router/r2o-firewall.sh" up
}
normalize_trace() {
    grep -E ' -I | -D ' "$1" 2>/dev/null | grep -E ' --(dport|sport) ' |
        sed -e 's/ -w / /g' -e 's/D2K_OUT/R2O_OUT/g' -e 's/D2K_IN/R2O_IN/g' |
        sed -e 's/^iptables /ipv4 /' -e 's/^ip6tables /ipv6 /' > "$2"
}
compare_phase() {
    d2o_sync "$1" || { echo "D2O dns_excl_sync_unlocked failed" >&2; return 1; }
    if [ "$1" = fresh ]; then
        r2o_command=r2o_up
    else
        r2o_command=r2o_sync
    fi
    if ! "$r2o_command" 2> "$TEMP/r2o.error"; then
        echo "D2O applied DNS exclusions, but R2O dns-ensure failed in phase $1" >&2
        cat "$TEMP/r2o.error" >&2
        return 1
    fi
    normalize_trace "$TEMP/d2o.trace" "$TEMP/d2o.normalized"
    normalize_trace "$TEMP/r2o.trace" "$TEMP/r2o.normalized"
    cmp "$TEMP/d2o.normalized" "$TEMP/r2o.normalized" || {
        printf 'DNS exclusion rule transitions differ in phase %s\nD2O:\n' "$1" >&2
        cat "$TEMP/d2o.normalized" >&2
        printf 'R2O:\n' >&2
        cat "$TEMP/r2o.normalized" >&2
        return 1
    }
}

DNS_CONFIG=$TEMP/dns-phase1
DNS_IPV4=198.51.100.53
DNS_IPV6=2001:db8::53
DNS_FAIL=0
export DNS_CONFIG DNS_IPV4 DNS_IPV6 DNS_FAIL
: > "$TEMP/d2o.trace"
: > "$TEMP/r2o.trace"
grep -Fq 'dns_excl_sync_unlocked fresh' "$TEMP/d2o-S99d2k" || {
    echo "D2O fw_up no longer invokes fresh DNS reconciliation" >&2
    exit 1
}
compare_phase fresh

DNS_CONFIG=$TEMP/dns-phase2
DNS_IPV4=198.51.100.54
DNS_IPV6=
compare_phase normal

DNS_FAIL=1
compare_phase normal

# Two refreshes must share D2O/R2O's firewall-operation lock. Delay `-C` so an
# unlocked implementation would allow both processes to insert the same rule.
DNS_CONFIG=$TEMP/dns-concurrent
DNS_IPV4=198.51.100.53
DNS_IPV6=2001:db8::53
DNS_FAIL=0
FW_CHECK_DELAY=1
export DNS_CONFIG DNS_IPV4 DNS_IPV6 DNS_FAIL FW_CHECK_DELAY
: > "$TEMP/d2o.trace"
: > "$TEMP/r2o.trace"
: > "$TEMP/d2o-db/iptables.rules"
: > "$TEMP/d2o-db/ip6tables.rules"
: > "$TEMP/r2o-db/iptables.rules"
: > "$TEMP/r2o-db/ip6tables.rules"
rm -f "$TEMP/d2o-run/dns-excl" "$TEMP/r2o-run/dns-excl"
d2o_sync locked & d2o_pid1=$!
d2o_sync locked & d2o_pid2=$!
if wait "$d2o_pid1" && wait "$d2o_pid2"; then :; else
    echo 'concurrent D2O DNS refresh failed' >&2
    exit 1
fi
r2o_sync & r2o_pid1=$!
r2o_sync & r2o_pid2=$!
if wait "$r2o_pid1" && wait "$r2o_pid2"; then :; else
    echo 'concurrent R2O DNS refresh failed' >&2
    exit 1
fi
normalize_trace "$TEMP/d2o.trace" "$TEMP/d2o.normalized"
normalize_trace "$TEMP/r2o.trace" "$TEMP/r2o.normalized"
cmp "$TEMP/d2o.normalized" "$TEMP/r2o.normalized" || {
    printf 'concurrent DNS exclusion transitions differ\nD2O:\n' >&2
    cat "$TEMP/d2o.normalized" >&2
    printf 'R2O:\n' >&2
    cat "$TEMP/r2o.normalized" >&2
    exit 1
}
[ "$(grep -c ' -I ' "$TEMP/d2o.trace")" = 4 ] || {
    echo 'concurrent D2O refresh inserted a DNS exclusion more than once' >&2
    cat "$TEMP/d2o.trace" >&2
    exit 1
}
[ "$(grep -c ' -I ' "$TEMP/r2o.trace")" = 4 ] || {
    echo 'concurrent R2O refresh inserted a DNS exclusion more than once' >&2
    cat "$TEMP/r2o.trace" >&2
    exit 1
}
printf 'D2O/R2O dynamic DNS upstream exclusions and address-failure fallback match %s.\n' "$ACTUAL_D2O_SHA"
