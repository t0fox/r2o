#!/bin/sh
ACTION=includes
export ACTION
exec "${R2O_INIT:-/opt/etc/init.d/S99r2o}"
