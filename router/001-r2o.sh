#!/bin/sh
# managed-by: R2O

case "${table:-}" in
    nat|mangle) ;;
    *) exit 0 ;;
esac

exec "${R2O_INIT:-/opt/etc/init.d/S99r2o}" heal
