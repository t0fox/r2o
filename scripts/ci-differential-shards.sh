#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

BASELINE_SHA=eb848976ed9491791b7f2130b874867b61b2ca5d
UPSTREAM_SHA=304ba893dd37197128ac8799c0495b035f6a38c0

BASELINE_EXPECTED='r2o-ask-differential.sh r2o-discord-discovery-differential.sh r2o-discovery-active-lifetime-differential.sh r2o-discovery-coalesce-differential.sh r2o-fetch-cli-differential.sh r2o-quic-stun-watch-differential.sh r2o-tcp-exchange-differential.sh r2o-hold-differential.sh r2o-tcp-payload-stats-differential.sh r2o-tcp-rst-cut-differential.sh r2o-tcp-rst-observation-differential.sh r2o-udp-exchange-differential.sh'
UPSTREAM_EXPECTED='r2o-ask-differential.sh r2o-ack-applied-persist-differential.sh r2o-bridge-clone-decoy-differential.sh r2o-catalog-persist-differential.sh r2o-catalog-sync-differential.sh r2o-control-dropped-differential.sh r2o-control-events-differential.sh r2o-diagnostics-differential.sh r2o-discord-discovery-differential.sh r2o-discovery-active-lifetime-differential.sh r2o-discovery-coalesce-differential.sh r2o-discovery-concurrency-check.sh r2o-discovery-quic-stop-differential.sh r2o-ech-rx-ladder-differential.sh r2o-fallback-differential.sh r2o-fetch-cli-differential.sh r2o-http-search-differential.sh r2o-known-plans-differential.sh r2o-layered-rx-differential.sh r2o-meas-differential.sh r2o-measured-split-differential.sh r2o-nat-proc-differential.sh r2o-net-whitelist-probe-differential.sh r2o-own-first-differential.sh r2o-quic-hello-differential.sh r2o-quic-local-address-differential.sh r2o-queue-order-differential.sh r2o-quic-stun-watch-differential.sh r2o-raw-connect-fallback-differential.sh r2o-raw-emission-cancel-differential.sh r2o-raw-profile-differential.sh r2o-raw-split-support-differential.sh r2o-resource-limit-differential.sh r2o-route-gate-differential.sh r2o-scheduler-concurrent-endpoint-differential.sh r2o-scheduler-cooldown-differential.sh r2o-scheduler-dead-address-differential.sh r2o-scheduler-differential.sh r2o-socket-split-deadline-differential.sh r2o-tcp-exchange-differential.sh r2o-hold-differential.sh r2o-tcp-payload-stats-differential.sh r2o-tcp-reply-hidden-differential.sh r2o-tcp-rst-cut-differential.sh r2o-tcp-rst-observation-differential.sh r2o-telegram-route-dns-differential.sh r2o-telegram-response-observer-differential.sh r2o-tls-verify-differential.sh r2o-udp-exchange-differential.sh r2o-udp-session-table-check.sh r2o-worker-permit-differential.sh test-d2o-shared-fixtures.sh'

shards_for() {
    case "$1" in
        baseline)
            printf '%s\n' host tcp
            ;;
        upstream) printf '%s\n' discovery httpsearch quic-control rst-udp scheduler tcp telegram tls ;;
        *) echo "ci-differential-shards: unknown snapshot: $1" >&2; return 2 ;;
    esac
}

scripts_for() {
    snapshot=$1
    shard=$2
    case "$snapshot:$shard" in
        baseline:host)
            printf '%s\n' \
                r2o-ask-differential.sh \
                r2o-discord-discovery-differential.sh \
                r2o-discovery-active-lifetime-differential.sh \
                r2o-discovery-coalesce-differential.sh \
                r2o-fetch-cli-differential.sh \
                r2o-quic-stun-watch-differential.sh \
                r2o-tcp-exchange-differential.sh \
                r2o-hold-differential.sh \
                r2o-tcp-rst-cut-differential.sh \
                r2o-tcp-rst-observation-differential.sh \
                r2o-udp-exchange-differential.sh
            ;;
        baseline:tcp)
            printf '%s\n' r2o-tcp-payload-stats-differential.sh
            ;;
        upstream:discovery)
            printf '%s\n' \
                r2o-ask-differential.sh \
                r2o-bridge-clone-decoy-differential.sh \
                r2o-discord-discovery-differential.sh \
                r2o-discovery-active-lifetime-differential.sh \
                r2o-discovery-coalesce-differential.sh \
                r2o-fetch-cli-differential.sh \
                r2o-discovery-concurrency-check.sh \
                r2o-ech-rx-ladder-differential.sh \
                r2o-known-plans-differential.sh \
                test-d2o-shared-fixtures.sh \
                r2o-net-whitelist-probe-differential.sh \
                r2o-own-first-differential.sh \
                r2o-layered-rx-differential.sh \
                r2o-fallback-differential.sh
            ;;
        upstream:quic-control)
            printf '%s\n' \
                r2o-discovery-quic-stop-differential.sh \
                r2o-quic-hello-differential.sh \
                r2o-quic-local-address-differential.sh \
                r2o-quic-stun-watch-differential.sh
            ;;
        upstream:scheduler)
            printf '%s\n' \
                r2o-ack-applied-persist-differential.sh \
                r2o-catalog-persist-differential.sh \
                r2o-catalog-sync-differential.sh \
                r2o-control-dropped-differential.sh \
                r2o-control-events-differential.sh \
                r2o-meas-differential.sh \
                r2o-measured-split-differential.sh \
                r2o-raw-connect-fallback-differential.sh \
                r2o-raw-emission-cancel-differential.sh \
                r2o-raw-split-support-differential.sh \
                r2o-queue-order-differential.sh \
                r2o-scheduler-concurrent-endpoint-differential.sh \
                r2o-scheduler-cooldown-differential.sh \
                r2o-scheduler-dead-address-differential.sh \
                r2o-resource-limit-differential.sh \
                r2o-socket-split-deadline-differential.sh \
                r2o-worker-permit-differential.sh \
                r2o-scheduler-differential.sh
            ;;
        upstream:httpsearch)
            printf '%s\n' r2o-diagnostics-differential.sh r2o-http-search-differential.sh
            ;;
        upstream:tcp)
            printf '%s\n' \
                r2o-tcp-exchange-differential.sh \
                r2o-hold-differential.sh \
                r2o-tcp-payload-stats-differential.sh \
                r2o-tcp-reply-hidden-differential.sh
            ;;
        upstream:tls)
            printf '%s\n' r2o-tls-verify-differential.sh
            ;;
        upstream:telegram)
            printf '%s\n' r2o-telegram-route-dns-differential.sh r2o-telegram-response-observer-differential.sh
            ;;
        upstream:rst-udp)
            printf '%s\n' \
                r2o-raw-profile-differential.sh \
                r2o-tcp-rst-cut-differential.sh \
                r2o-tcp-rst-observation-differential.sh \
                r2o-udp-exchange-differential.sh \
                r2o-udp-session-table-check.sh \
                r2o-route-gate-differential.sh \
                r2o-nat-proc-differential.sh
            ;;
        *) echo "ci-differential-shards: unknown shard: $snapshot/$shard" >&2; return 2 ;;
    esac
}

expected_for() {
    case "$1" in
        baseline) printf '%s\n' "$BASELINE_EXPECTED" | tr ' ' '\n' | LC_ALL=C sort ;;
        upstream) printf '%s\n' "$UPSTREAM_EXPECTED" | tr ' ' '\n' | LC_ALL=C sort ;;
        *) echo "ci-differential-shards: unknown snapshot: $1" >&2; return 2 ;;
    esac
}

assigned_for() {
    snapshot=$1
    # The shard names are fixed in this script and contain no whitespace.
    # shellcheck disable=SC2046
    set -- $(shards_for "$snapshot")
    for shard do
        scripts_for "$snapshot" "$shard"
    done
}

verify_snapshot() {
    snapshot=$1
    expected=$(expected_for "$snapshot")
    assigned=$(assigned_for "$snapshot" | LC_ALL=C sort)
    if [ "$expected" != "$assigned" ]; then
        echo "ci-differential-shards: $snapshot shards miss, duplicate, or add scenarios" >&2
        echo "expected: $expected" >&2
        echo "assigned: $assigned" >&2
        return 1
    fi
    while IFS= read -r script; do
        [ -n "$script" ] || continue
        if [ ! -f "$SCRIPT_DIR/$script" ]; then
            echo "ci-differential-shards: missing scenario script: $script" >&2
            return 1
        fi
    done <<EOF
$expected
EOF
}

verify() {
    verify_snapshot baseline
    verify_snapshot upstream
    discovered=$(find "$SCRIPT_DIR" -maxdepth 1 -type f \
        \( -name 'r2o-*-differential.sh' \
           -o -name 'r2o-discovery-concurrency-check.sh' \
           -o -name 'r2o-udp-session-table-check.sh' \
           -o -name 'test-d2o-shared-fixtures.sh' \) \
        -printf '%f\n' | LC_ALL=C sort)
    expected=$(expected_for upstream)
    if [ "$discovered" != "$expected" ]; then
        echo 'ci-differential-shards: update the pinned scenario manifests when differential scripts change' >&2
        echo "expected: $expected" >&2
        echo "discovered: $discovered" >&2
        return 1
    fi
    baseline_count=$(printf '%s\n' "$BASELINE_EXPECTED" | wc -w | tr -d ' ')
    upstream_count=$(printf '%s\n' "$UPSTREAM_EXPECTED" | wc -w | tr -d ' ')
    echo "ci-differential-shards: baseline $baseline_count and upstream $upstream_count scenarios are covered exactly once"
}

matrix() {
    verify >/dev/null
    first=1
    entries=
    for snapshot in baseline upstream; do
        case "$snapshot" in
            baseline) donor_sha=$BASELINE_SHA ;;
            upstream) donor_sha=$UPSTREAM_SHA ;;
        esac
        # The shard names are fixed in this script and contain no whitespace.
        # shellcheck disable=SC2046
        set -- $(shards_for "$snapshot")
        for shard do
            case "$snapshot:$shard" in
                upstream:quic-control|upstream:scheduler) cache_shard=quic-scheduler ;;
                *) cache_shard=$shard ;;
            esac
            if [ "$first" -eq 0 ]; then
                entries="$entries,"
            fi
            first=0
            entries="$entries{\"snapshot\":\"$snapshot\",\"donor_sha\":\"$donor_sha\",\"shard\":\"$shard\",\"cache_shard\":\"$cache_shard\"}"
        done
    done
    printf '{"include":[%s]}\n' "$entries"
}

if [ "$#" -eq 0 ]; then
    command=
else
    command=$1
fi
case "$command" in
    verify) verify ;;
    matrix) matrix ;;
    list)
        [ "$#" -eq 3 ] || { echo 'usage: ci-differential-shards.sh list SNAPSHOT SHARD' >&2; exit 2; }
        scripts_for "$2" "$3"
        ;;
    *)
        echo 'usage: ci-differential-shards.sh verify|matrix|list SNAPSHOT SHARD' >&2
        exit 2
        ;;
esac
