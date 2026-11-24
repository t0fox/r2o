#!/bin/sh
# Совместимый вход для init и системных hooks. Правила и состояние ведёт Rust.
set -eu
ROOT=${R2O_DIR:-/opt/r2o}
CONF=${R2O_CONFIG:-$ROOT/config}
set -a
# shellcheck disable=SC1090
[ ! -r "$CONF" ] || . "$CONF"
set +a
export R2O_DIR="$ROOT"

if [ -n "${R2O_DATAPATH_BIN:-}" ]; then
    exec "$R2O_DATAPATH_BIN" --platform "$@"
fi
exec "${R2O_MANAGER:-$ROOT/r2o-manager}" exec --root "$ROOT" --component r2o-datapath -- --platform "$@"
