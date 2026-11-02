#!/bin/sh
set -eu

R2O_ROOT=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-"${R2O_ROOT%/*}/d2o"}
EXPECTED_D2O_SHA=a63d9641f4e00aa35fa1e5ccbda47bb5f310c0fe
TMPDIR=${TMPDIR:-/tmp}
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
R2O_BIN=${R2O_BIN:-"$R2O_ROOT/target/debug/r2o-datapath"}

[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "expected current D2O main $EXPECTED_D2O_SHA" >&2
    exit 2
}

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-mode-default.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -B -C "$D2O_ROOT/datapath" d2kd CC="$CC"
"$CARGO" build --manifest-path "$R2O_ROOT/Cargo.toml" \
    --package r2o-datapath --bin r2o-datapath --locked --offline

"$D2O_ROOT/datapath/d2kd" --help >"$TEMP/d2o.help" 2>&1
"$R2O_BIN" --help >"$TEMP/r2o.help" 2>&1

default_mode() {
    mode_line=$(grep -F -- '--mode observe|apply' "$1")
    case "$mode_line" in
        *"умолчание observe"*|*"по умолчанию observe"*) printf observe ;;
        *"умолчание apply"*|*"по умолчанию apply"*) printf apply ;;
        *) printf unknown ;;
    esac
}

c_mode=$(default_mode "$TEMP/d2o.help")
rust_mode=$(default_mode "$TEMP/r2o.help")
if [ "$c_mode" != observe ] || [ "$rust_mode" != "$c_mode" ]; then
    printf 'default datapath mode differs: D2O=%s R2O=%s\n' "$c_mode" "$rust_mode" >&2
    diff -u "$TEMP/d2o.help" "$TEMP/r2o.help" >&2 || true
    exit 1
fi

printf 'D2O and R2O default datapath mode: %s\n' "$rust_mode"
