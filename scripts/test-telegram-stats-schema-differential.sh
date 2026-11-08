#!/bin/sh
# TG19: paired C/Rust differential D2O stats-схемы.
#
# C-оракул — production `stats_socket.c` (`append_active_sessions` + формат
# остальных полей). Rust — `RuntimeStats::d2o_snapshot`.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-gcc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-stats.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$CC" -std=c11 -O2 -Wall -Wextra $OPENSSL_CFLAGS \
    -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/telegram/include" -I"$D2O_ROOT/telegram/src" \
    -o "$TEMP/d2o-stats" \
    "$ROOT/crates/r2o-telegram/tests/d2o_stats_schema_differential.c" \
    -Wl,--gc-sections -L/lib/x86_64-linux-gnu -l:libcrypto.so.3
"$TEMP/d2o-stats" > "$TEMP/c.json"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg19_trace > "$TEMP/rust.json"

python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys

c = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
expected = [
    "active_connections", "process_started_at", "accepted_connections",
    "active_sessions", "route_sessions_truncated", "route_cooldown_ms",
    "route_cooldowns", "route_cooldowns_truncated", "max_connections",
    "active_wss_connections", "max_wss_connections",
    "buffer_bytes_current", "buffer_bytes_peak", "buffer_bytes_limit",
    "connections_started", "bytes_from_clients", "bytes_from_upstreams",
    "wss_attempts", "wss_failures", "wss_responses", "cf_wss_responses",
    "last_success_dc", "last_success_route", "last_success_latency_ms",
    "last_success_age_ms", "last_failure_dc", "last_failure_route",
    "last_failure_stage", "last_failure_age_ms",
    "client_response_latency_total", "client_response_latency_samples",
    "client_response_latency_last_us", "client_response_latency_p50_us",
    "client_response_latency_p95_us",
]
assert list(c) == expected, (list(c), expected)
assert set(expected).issubset(r), (set(expected) - set(r))
# Панель требует donor-маркер схемы; он остаётся R2O-расширением.
assert "mtproto_success" in r or "wss_established" in r
# Время/остаток cooldown зависят от момента снимка.
ignore = {"last_success_age_ms", "last_failure_age_ms"}
for key in expected:
    if key in ignore:
        continue
    if key == "route_cooldowns":
        left = [{k: v for k, v in item.items() if k != "remaining_ms"}
                for item in c[key]]
        right = [{k: v for k, v in item.items() if k != "remaining_ms"}
                 for item in r[key]]
        assert left == right, (key, left, right)
        continue
    if key == "active_sessions":
        left = [
            {**session, "events": [
                {k: v for k, v in event.items() if k != "age_ms"}
                for event in session["events"]
            ]}
            for session in c[key]
        ]
        right = [
            {**session, "events": [
                {k: v for k, v in event.items() if k != "age_ms"}
                for event in session["events"]
            ]}
            for session in r[key]
        ]
        assert left == right, (key, left, right)
        continue
    assert c[key] == r[key], (key, c[key], r[key])
print("stats schema ok")
PY

printf 'PASS: C/Rust D2O stats schema and counters match (D2O %s)\n' "$ACTUAL_D2O_SHA"
