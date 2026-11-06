#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=8e2c98146cf0b712dc967fbec558c7b904666e87
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-ppe-removal-error.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin"
ln -s iptables "$TEMP/bin/ip6tables"
mkdir -p "$TEMP/proc"

sed -n '/^_d2k_ppe_ipt() {/,/^# ---- состояние /{ /^# ---- состояние /d; p; }' \
    "$D2O_ROOT/files/d2k-ppe-deoffload.sh" | tr -d '\r' >"$TEMP/d2o-functions.sh"
sed '/^r2o_ppe_status() {/,${d;}' \
    "$ROOT/router/r2o-ppe-deoffload.sh" | tr -d '\r' >"$TEMP/r2o-functions.sh"
[ -s "$TEMP/d2o-functions.sh" ] && [ -s "$TEMP/r2o-functions.sh" ] || {
    echo 'could not extract production PPE removal functions' >&2
    exit 1
}

cat >"$TEMP/bin/iptables" <<'IPTABLES'
#!/bin/sh
tool=${0##*/}
case " $* " in
    *' -S '*)
        [ "${PPE_FAILURE:-list}" != list ] || exit 1
        case " $* " in
            *' -S PREROUTING '*)
                cat <<'RULES'
-A PREROUTING -p tcp -m multiport --dports 443 -m comment --comment d2k-ppe -j PPE
-A PREROUTING -p tcp -m multiport --dports 8443 -m comment --comment r2o-ppe -j PPE
RULES
                ;;
            *' -S FORWARD '*)
                cat <<'RULES'
-A FORWARD -p tcp -m multiport --dports 443 -m comment --comment d2k-ppe -j PPE
-A FORWARD -p tcp -m multiport --dports 8443 -m comment --comment r2o-ppe -j PPE
RULES
                ;;
        esac
        exit 0
        ;;
    *' -D '*)
        [ "${PPE_FAILURE:-delete}" != delete ] || exit 1
        exit 0
        ;;
    *' -C '*) exit 1 ;;
    *' -I '*)
        case "${PPE_FAILURE:-}" in
            insert-v4) [ "$tool" != iptables ] || exit 1 ;;
            insert-v6) [ "$tool" != ip6tables ] || exit 1 ;;
        esac
        exit 0
        ;;
esac
exit 1
IPTABLES
chmod 0755 "$TEMP/bin/iptables"

run_case() {
    name=$1
    operation=$2
    failure=$3
    if [ "$operation" = ensure ] && [ "$failure" != target-missing ]; then
        printf 'PPE\n' >"$TEMP/proc/ip_tables_targets"
        printf 'PPE\n' >"$TEMP/proc/ip6_tables_targets"
    else
        rm -f "$TEMP/proc/ip_tables_targets" "$TEMP/proc/ip6_tables_targets"
    fi
    for kind in d2o r2o; do
        output=$TEMP/$name-$kind.out
        if [ "$kind" = d2o ]; then
            library=$TEMP/d2o-functions.sh
            if [ "$operation" = ensure ]; then
                command_name=d2k_ppe_ensure
                if [ "$failure" = delete ]; then D2K_PPE_DEOFFLOAD=0; else D2K_PPE_DEOFFLOAD=1; fi
            else
                command_name=d2k_ppe_remove
                D2K_PPE_DEOFFLOAD=1
            fi
            (
                PATH=$TEMP/bin:/usr/bin:/bin
                export PATH
                PPE_FAILURE=$failure
                export PPE_FAILURE
                export D2K_PPE_TAG=d2k-ppe
                export D2K_PPE_TARGET=PPE
                export D2K_PPE_CONNSKIP=30
                export D2K_PPE_TCP_PORTS=443,8443
                export D2K_PPE_UDP_PORTS=443,8443
                export D2K_PPE_HTTP_PORTS=80
                export D2K_PPE_HTTP_CONNSKIP=1000000
                export D2K_PPE_PROC=$TEMP/proc
                D2K_PPE_DEOFFLOAD=$D2K_PPE_DEOFFLOAD
                # shellcheck disable=SC1090 # the harness sources an extracted production helper
                . "$library"
                if "$command_name"; then rc=0; else rc=$?; fi
                printf 'rc=%s\n' "$rc"
            ) >"$output" 2>&1
        else
            library=$TEMP/r2o-functions.sh
            if [ "$operation" = ensure ]; then
                command_name=r2o_ppe_ensure
                if [ "$failure" = delete ]; then R2O_PPE_DEOFFLOAD=0; else R2O_PPE_DEOFFLOAD=1; fi
            else
                command_name=r2o_ppe_remove
                R2O_PPE_DEOFFLOAD=1
            fi
            (
                PATH=$TEMP/bin:/usr/bin:/bin
                export PATH
                PPE_FAILURE=$failure
                export PPE_FAILURE
                export R2O_PPE_TAG=r2o-ppe
                export R2O_PPE_LEGACY_TAG=d2k-ppe
                export R2O_PPE_TARGET=PPE
                export R2O_PPE_PROC=$TEMP/proc
                export R2O_PPE_TCP_PORTS=443,8443
                export R2O_PPE_UDP_PORTS=443,8443
                export R2O_PPE_HTTP_PORTS=80
                export R2O_PPE_CONFIG=/dev/null
                R2O_PPE_DEOFFLOAD=$R2O_PPE_DEOFFLOAD
                # shellcheck disable=SC1090 # the harness sources an extracted production helper
                . "$library"
                if "$command_name"; then rc=0; else rc=$?; fi
                printf 'rc=%s\n' "$rc"
            ) >"$output" 2>&1
        fi
    done
    if ! cmp -s "$TEMP/$name-d2o.out" "$TEMP/$name-r2o.out"; then
        printf 'PPE removal policy mismatch in %s case\nD2O:\n' "$name" >&2
        cat "$TEMP/$name-d2o.out" >&2
        printf 'R2O:\n' >&2
        cat "$TEMP/$name-r2o.out" >&2
        return 1
    fi
    printf '%s: %s\n' "$name" "$(cat "$TEMP/$name-r2o.out")"
}

run_case list-failure remove list
run_case delete-failure remove delete
run_case disabled-ensure ensure delete
run_case insert-v4-failure ensure insert-v4
run_case insert-v6-failure ensure insert-v6
run_case unsupported-target ensure target-missing
run_case successful-ensure ensure none
printf 'D2O %s and R2O PPE insertion, removal, and failure return policies match.\n' "$ACTUAL_D2O_SHA"
