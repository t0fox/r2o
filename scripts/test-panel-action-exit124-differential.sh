#!/bin/sh
# A15: код выхода 124 сервисного действия отображается в control_state=timeout.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-panel-action124.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

cat > "$TEMP/service" <<'SERVICE'
#!/bin/sh
exit 124
SERVICE
chmod 0700 "$TEMP/service"

"$CC" -std=c11 -O2 -Wall -Wextra -pthread -D_POSIX_C_SOURCE=200809L \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-action124" \
    "$ROOT/crates/r2o-panel/tests/d2o_control_timeout.c" \
    "$D2O_ROOT/panel/server.c"
"$TEMP/d2o-action124" "$TEMP/service" > "$TEMP/c.trace"
grep -qx 'timeout' "$TEMP/c.trace" || {
    echo "C не отобразил exit 124 в timeout:" >&2
    cat "$TEMP/c.trace" >&2
    exit 1
}

R2O_PANEL_TIMEOUT_SERVICE="$TEMP/service" \
R2O_PANEL_TIMEOUT_C_TRACE="$TEMP/c.trace" \
R2O_PANEL_TIMEOUT_TRACE_OUTPUT="$TEMP/rust.trace" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-panel --lib d2o_control_timeout_state_trace -- --ignored \
        > "$TEMP/rust.log" 2>&1
grep -q 'test result: ok. 1 passed' "$TEMP/rust.log" || {
    cat "$TEMP/rust.log" >&2
    exit 1
}

printf 'PASS: D2O/Rust map service exit 124 to control_state=timeout (D2O %s)\n' "$ACTUAL_D2O_SHA"
