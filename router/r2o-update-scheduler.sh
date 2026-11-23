#!/bin/sh
set -eu

# Init передаёт настройки и запускает планировщик менеджера.
ROOT=${R2O_DIR:-/opt/r2o}
MANAGER=${R2O_MANAGER:-$ROOT/r2o-manager}
INIT=${R2O_INIT:-/opt/etc/init.d/S99r2o}
exec "$MANAGER" exec --root "$ROOT" --component r2o-manager -- \
    update-schedule --root "$ROOT" --service "$INIT" --enabled "${1:-1}"
