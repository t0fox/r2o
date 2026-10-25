#!/bin/sh
set -eu

r2o_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath="${R2O_DONOR_DATAPATH:-${r2o_root%/*}/d2o/datapath}"
r2o_tmp=$(mktemp -d)
trap 'rm -rf "$r2o_tmp"' EXIT HUP INT TERM

clang-18 -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$r2o_donor_datapath/include" \
    "$r2o_root/crates/r2o-datapath/tests/d2o_nat_cli.c" \
    "$r2o_donor_datapath/nat.c" \
    -o "$r2o_tmp/d2o-nat-oracle"

D2O_NAT_ORACLE="$r2o_tmp/d2o-nat-oracle" \
    cargo +1.98.0 test --locked -p r2o-datapath --test d2o_nat_proc \
    -- --ignored --nocapture
