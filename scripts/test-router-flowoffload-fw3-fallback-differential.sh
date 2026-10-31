#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
R2O_FLOWOFFLOAD_BACKEND_ONLY=iptables \
    exec sh "$ROOT/scripts/test-router-flowoffload-d2o-differential.sh"
