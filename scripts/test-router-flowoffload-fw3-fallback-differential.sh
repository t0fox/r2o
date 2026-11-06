#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=8e2c98146cf0b712dc967fbec558c7b904666e87
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$(git -C "$D2O_ROOT" rev-parse HEAD)" >&2
    exit 2
}
R2O_FLOWOFFLOAD_BACKEND_ONLY=iptables \
    exec sh "$ROOT/scripts/test-router-flowoffload-d2o-differential.sh"
