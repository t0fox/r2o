#!/bin/sh
# A19: атомарная запись config сохраняет режим независимо от umask.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-panel-config-mode.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

cat > "$TEMP/service" <<'SERVICE'
#!/bin/sh
exit 0
SERVICE
chmod 0700 "$TEMP/service"

"$CC" -std=c11 -O2 -Wall -Wextra -pthread -D_POSIX_C_SOURCE=200809L \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-config-mode" \
    "$ROOT/crates/r2o-panel/tests/d2o_config_mode.c" \
    "$D2O_ROOT/panel/server.c"

make_config() {
    printf 'MODE=apply\nTG_CF_WORKER_DOMAIN=old.example\n' > "$1"
    chmod 0640 "$1"
}
make_config "$TEMP/config-c"
"$TEMP/d2o-config-mode" "$TEMP/config-c" "$TEMP/service" > "$TEMP/c.trace"

make_config "$TEMP/config-rust"
R2O_PANEL_MODE_CONFIG="$TEMP/config-rust" \
R2O_PANEL_MODE_SERVICE="$TEMP/service" \
R2O_PANEL_MODE_C_TRACE="$TEMP/c.trace" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-panel --test config_mode \
        d2o_worker_config_write_preserves_mode_ignoring_umask -- --ignored \
        > "$TEMP/rust.log" 2>&1
grep -q 'test result: ok. 1 passed' "$TEMP/rust.log" || {
    cat "$TEMP/rust.log" >&2
    exit 1
}

printf 'PASS: D2O/Rust config write keeps mode 0640 under umask 0077 and preserves bytes (D2O %s)\n' "$ACTUAL_D2O_SHA"
