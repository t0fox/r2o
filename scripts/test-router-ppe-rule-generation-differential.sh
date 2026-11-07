#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=8e2c98146cf0b712dc967fbec558c7b904666e87
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-ppe-rules.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
sed -n '/^_d2k_ppe_rules() {/,/^}/p' "$D2O_ROOT/files/d2k-ppe-deoffload.sh" |
    tr -d '\r' >"$TEMP/d2o-rules.sh"
{
    sed -n '/^_r2o_ppe_emit_proto_rules() {/,/^}/p' "$ROOT/router/r2o-ppe-deoffload.sh"
    sed -n '/^_r2o_ppe_rules() {/,/^}/p' "$ROOT/router/r2o-ppe-deoffload.sh"
} | tr -d '\r' >"$TEMP/r2o-rules.sh"
[ -s "$TEMP/d2o-rules.sh" ] && [ -s "$TEMP/r2o-rules.sh" ] || {
    echo "could not extract the production PPE rule generators" >&2
    exit 1
}

cat >"$TEMP/run-d2o.sh" <<'D2O'
#!/bin/sh
set -eu
D2K_PPE_CONNSKIP=30
D2K_PPE_TAG=parity-ppe
D2K_PPE_TARGET=PPE
D2K_PPE_TCP_PORTS=$1
D2K_PPE_UDP_PORTS=443,$2
D2K_PPE_HTTP_PORTS=$3
D2K_PPE_HTTP_CONNSKIP=1000000
. "$4"
_d2k_ppe_rules
D2O
cat >"$TEMP/run-r2o.sh" <<'R2O'
#!/bin/sh
set -eu
R2O_PPE_CONNSKIP=30
R2O_PPE_TAG=parity-ppe
R2O_PPE_TARGET=PPE
R2O_PPE_TCP_PORTS=$1
R2O_PPE_VOICE_PORTS=$2
R2O_PPE_UDP_PORTS=443,$2
R2O_PPE_HTTP_PORTS=$3
R2O_PPE_HTTP_CONNSKIP=1000000
# Both configured cases fit xt_multiport's 15 slots, so production validation
# selects the same single combined UDP rule that C emits.
_r2o_ppe_split_udp=0
. "$4"
_r2o_ppe_rules
R2O
chmod 0755 "$TEMP/run-d2o.sh" "$TEMP/run-r2o.sh"

compare_case() {
    name=$1
    tcp_ports=$2
    voice_ports=$3
    http_ports=$4
    sh "$TEMP/run-d2o.sh" "$tcp_ports" "$voice_ports" "$http_ports" \
        "$TEMP/d2o-rules.sh" >"$TEMP/d2o.out"
    sh "$TEMP/run-r2o.sh" "$tcp_ports" "$voice_ports" "$http_ports" \
        "$TEMP/r2o-rules.sh" >"$TEMP/r2o.out"
    if ! cmp -s "$TEMP/d2o.out" "$TEMP/r2o.out"; then
        printf 'PPE rule generator mismatch in %s case\nD2O:\n' "$name" >&2
        cat "$TEMP/d2o.out" >&2
        printf 'R2O:\n' >&2
        cat "$TEMP/r2o.out" >&2
        exit 1
    fi
    printf '%s: %s rules match\n' "$name" "$(wc -l <"$TEMP/d2o.out" | tr -d ' ')"
}

compare_case default 0:65535 '50000:50099,1400,3478:3481,5349,19294:19344' 80
compare_case custom 443,8443 '10000:10010,2100,3000:3002' 8080
printf 'D2O %s and R2O PPE default/custom rule generators match.\n' "$ACTUAL_D2O_SHA"
