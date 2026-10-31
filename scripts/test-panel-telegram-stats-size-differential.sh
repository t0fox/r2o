#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TOOL_HOME=${R2O_TOOL_HOME:-${ROOT%/*}/r2o-tooling}
TEMP_BASE=${R2O_TEST_TMP:-$TOOL_HOME/tmp}
[ -d "$TEMP_BASE" ] || { printf 'Temporary directory must exist on E: %s\n' "$TEMP_BASE" >&2; exit 2; }
TEMP=$(mktemp -d "$TEMP_BASE/r2o-panel-telegram-stats-size.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

write_snapshot() {
    snapshot_path=$1
    size_case=$2
    printf '%s' '{"active_connections":2,"max_connections":64,"connections_started":9,"bytes_from_clients":1234,"bytes_from_upstreams":5678,"wss_attempts":8,"wss_failures":2,"wss_responses":5,"cf_wss_responses":3,"last_success_dc":2,"last_success_route":1,"last_success_latency_ms":126,"last_success_age_ms":500,"last_failure_dc":3,"last_failure_route":2,"last_failure_stage":4,"last_failure_age_ms":9000,"process_started_at":1800000000,"accepted_connections":9,"active_sessions":[{"id":9,"dc":2,"is_media":false,"stage":"upstream_ready","direct_state":"selected","direct_transport":"direct_wss","fallback_state":"idle","fallback_transport":null,"selected_transport":"direct_wss","telegram_response_seen":false,"events":[]}],"route_sessions_truncated":false,"route_cooldown_ms":30000,"route_cooldowns":[{"dc":4,"is_media":true,"transport":"cloudflare_proxy","remaining_ms":28750,"failure_stage":3}],"route_cooldowns_truncated":false,"listener_ready":true,"wss_established":1,"mtproto_success":1,"mtproto_failure":0,"last_mtproto_response_at":1800000001,"dc_map":{},"cf_domain_pool":{},"workers":{},"sessions_by_dc_transport":{},"failures":{},"ttfb":{},"padding":"' > "$snapshot_path"
    if [ "$size_case" = boundary ]; then
        prefix_size=$(wc -c < "$snapshot_path" | tr -d ' ')
        padding=$((131071 - prefix_size - 3))
    else
        padding=9000
    fi
    [ "$padding" -ge 0 ] || { echo 'stats fixture prefix exceeds boundary' >&2; exit 2; }
    head -c "$padding" /dev/zero | tr '\000' 'x' >> "$snapshot_path"
    printf '"}\n' >> "$snapshot_path"
}
write_snapshot "$TEMP/stats.json" regular
write_snapshot "$TEMP/stats-limit.json" boundary

CC=${CC:-cc}
"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-telegram-stats" \
    "$ROOT/crates/r2o-panel/tests/d2o_telegram_stats_size.c"
"$TEMP/d2o-telegram-stats" "$TEMP/stats.sock" "$TEMP/stats.json" > "$TEMP/c.json"
"$TEMP/d2o-telegram-stats" "$TEMP/stats-limit.sock" "$TEMP/stats-limit.json" > "$TEMP/c-limit.json"

export HOME=${R2O_TEST_HOME:-$TOOL_HOME/home}
export CARGO_HOME=${R2O_CARGO_HOME:-$TOOL_HOME/cargo-home}
export RUSTUP_HOME=${R2O_RUSTUP_HOME:-$TOOL_HOME/rustup-home}
export CARGO_TARGET_DIR=${R2O_CARGO_TARGET_DIR:-$TOOL_HOME/target-panel-telegram-stats-size}
export TMPDIR=$TEMP_BASE
export R2O_PANEL_TELEGRAM_STATS_SIZE_SOCKET="$TEMP/stats.sock"
export R2O_PANEL_TELEGRAM_STATS_SIZE_DATA="$TEMP/stats.json"
export R2O_PANEL_TELEGRAM_STATS_SIZE_C_BODY="$TEMP/c.json"
export R2O_PANEL_TELEGRAM_STATS_SIZE_LIMIT_SOCKET="$TEMP/stats-limit.sock"
export R2O_PANEL_TELEGRAM_STATS_SIZE_LIMIT_DATA="$TEMP/stats-limit.json"
export R2O_PANEL_TELEGRAM_STATS_SIZE_LIMIT_C_BODY="$TEMP/c-limit.json"

CARGO=${CARGO:-cargo}
"$CARGO" test --locked --offline -p r2o-panel --test http \
    d2o_telegram_stats_size_limit_matches_rust_route -- --ignored --nocapture
printf 'test-panel-telegram-stats-size-differential: C and Rust preserve the same snapshot\n'
