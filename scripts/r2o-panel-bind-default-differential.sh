#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${SCRIPT_DIR%/*}/d2o}
EXPECTED_D2O_SHA=${R2O_EXPECTED_DONOR_SHA:-304ba893dd37197128ac8799c0495b035f6a38c0}
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    echo "expected d2o $EXPECTED_D2O_SHA, got $ACTUAL_D2O_SHA" >&2
    exit 2
}

C_HELPER=$D2O_ROOT/scripts/select-panel-ip.sh
RUST_INSTALL_HELPER=$SCRIPT_DIR/router/select-panel-ip.sh
[ -f "$C_HELPER" ] && [ -f "$RUST_INSTALL_HELPER" ] || {
    echo "missing C/Rust panel-address selector" >&2
    exit 2
}

compare_selection() {
    label=$1
    addresses=$2
    c_result=$(printf '%s\n' "$addresses" | sh "$C_HELPER")
    rust_result=$(printf '%s\n' "$addresses" | sh "$RUST_INSTALL_HELPER")
    [ "$c_result" = "$rust_result" ] || {
        printf '%s: C selected <%s>, Rust selected <%s>\n' \
            "$label" "$c_result" "$rust_result" >&2
        return 1
    }
}

compare_selection primary-lan '9: ppp0 inet 198.51.100.11/24 scope global ppp0
10: br1 inet 10.1.30.1/24 scope global br1
11: br0 inet 192.168.1.1/24 scope global br0'
compare_selection private-fallback '9: ppp0 inet 198.51.100.11/24 scope global ppp0
10: eth0 inet 10.23.0.1/24 scope global eth0'
compare_selection no-private-address '9: ppp0 inet 198.51.100.11/24 scope global ppp0'

C_CONFIG=$(sed -n 's/^PANEL_LISTEN=//p' "$D2O_ROOT/files/config" | tail -n 1)
C_FALLBACK=$(sed -n 's/.*panel_listen = cfg .* : "\([^"]*\)";.*/\1/p' \
    "$D2O_ROOT/panel/server.c" | tail -n 1)
RUST_CONFIG=$(sed -n 's/^PANEL_LISTEN=//p' "$SCRIPT_DIR/router/config.default" | tail -n 1)
RUST_FALLBACK=$(sed -n 's/^PANEL_LISTEN=${PANEL_LISTEN:-\([^}]*\)}/\1/p' \
    "$SCRIPT_DIR/router/S99r2o" | head -n 1)
[ "$C_CONFIG" = "127.0.0.1:8090" ] &&
    [ "$C_FALLBACK" = "127.0.0.1:8090" ] &&
    [ "$RUST_CONFIG" = "$C_CONFIG" ] &&
    [ "$RUST_FALLBACK" = "$C_FALLBACK" ] || {
        printf 'panel bind defaults differ: C config=%s C fallback=%s Rust config=%s Rust fallback=%s\n' \
            "$C_CONFIG" "$C_FALLBACK" "$RUST_CONFIG" "$RUST_FALLBACK" >&2
        exit 1
    }

echo "C/Rust safe LAN panel bind selection and defaults match d2o $ACTUAL_D2O_SHA"
