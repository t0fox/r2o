#!/bin/sh
# A5: known-list D2O-конфига и отсутствие ложных unknown_keys у config.default R2O.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-panel-known-keys.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

cat > "$TEMP/config" <<'CONFIG'
SCHEMA=1
MODE=apply
PANEL_LISTEN=192.168.1.1:8090
STATE_DIR=/tmp/r2o-known-state
QUEUE_NUM=2345
CONTROL_SOCKET=/tmp/control.sock
DECOY_SNI=example.com
MARK=0x2e
PROBE_MARK=0x2d
FLOWS=2048
STATS_SEC=30
HEAL_EVERY=60
LOGMAX=2097152
LOGKEEP=1048576
LOG_EVERY=60
D2K_RUNTIME_DIR=/tmp/d2k
PORTS=0:65535
CONNBYTES=0:8
VOICE_PORTS=50000:50099
VOICE_CONNBYTES=0:8
TG_ENABLED=0
TG_MODE=local
TG_DC_MAP_PATH=/tmp/dc.json
TG_RELAY_URL=https://relay.example
TG_RELAY_SECRET=secret
TG_IDENTITY=/tmp/id
TG_CA_BUNDLE=/tmp/ca.pem
TG_STATUS=/tmp/tg.status
TG_STATS_SOCKET=/tmp/stats.sock
TG_PORT=1443
TG_ENROLL_PORT=9443
TG_DIAGNOSTIC_DIRECT_TCP=1
TG_CF_WORKER_DOMAIN=example.com
D2K_PPE_DEOFFLOAD=1
UNKNOWN_ONE=1
UNKNOWN_TWO=2
UNKNOWN_ONE=3
CONFIG

"$CC" -std=gnu11 -O2 -Wall -Wextra -pthread -D_POSIX_C_SOURCE=200809L \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-known-keys" \
    "$ROOT/crates/r2o-panel/tests/d2o_config_known_keys.c" \
    "$D2O_ROOT/panel/server.c"
"$TEMP/d2o-known-keys" "$TEMP/config" > "$TEMP/c.trace"
cp "$ROOT/router/config.default" "$TEMP/default-config"

R2O_PANEL_KNOWN_KEYS_CONFIG="$TEMP/config" \
R2O_PANEL_KNOWN_KEYS_C_TRACE="$TEMP/c.trace" \
R2O_PANEL_KNOWN_KEYS_DEFAULT_CONFIG="$TEMP/default-config" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-panel --test http d2o_known_config_keys_match -- --ignored \
        > "$TEMP/rust.log" 2>&1
grep -q 'test result: ok. 1 passed' "$TEMP/rust.log" || {
    cat "$TEMP/rust.log" >&2
    exit 1
}

printf 'PASS: D2O/Rust known config keys and unknown_keys order match; R2O config.default has no unknown keys (D2O %s)\n' "$ACTUAL_D2O_SHA"
