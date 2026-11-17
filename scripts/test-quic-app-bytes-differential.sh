#!/bin/sh
# Прежний differential app-байт проверял только счётчик. С 2026-11-17
# производственный учёт ведёт `R2oQuicRanges` (C `d2k_qw_ranges_*`), поэтому
# тот же смысл — уникальные байты, включая смещения >32 бит — проверяется
# диапазонным differential. Имя сохранено для существующих вызовов.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
exec sh "$ROOT/scripts/r2o-quic-ranges-differential.sh"
