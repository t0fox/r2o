#!/bin/sh
# Совместимый системный hook. Периодический опрос выполняет datapath.
[ "${1:-}" = tick ] || exit 0
exec "${R2O_INIT:-/opt/etc/init.d/S99r2o}" firewall-heal
