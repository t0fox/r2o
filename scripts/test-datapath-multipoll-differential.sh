#!/bin/sh
# C/Rust differential: multi-fd poll (NFQUEUE + 2 extra fd).
#
# Проверяются readiness любого fd, маски POLLIN/POLLHUP, чтение NFQUEUE
# только при POLLIN и таймаут. C-оракул — poll(2), Rust — новая
# receive_timeout_with_fds.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-multipoll.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -o "$TEMP/d2o-multipoll" \
    "$ROOT/crates/r2o-datapath/tests/d2o_multipoll_differential.c"

cd "$ROOT"
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib --no-run >"$TEMP/build.log" 2>&1
RUST_BIN=$(sed -n 's/.*Executable unittests src\/lib.rs (\(.*\))/\1/p' "$TEMP/build.log" | tail -1)
if [ -z "$RUST_BIN" ]; then
    echo "не найден тестовый бинарник r2o-datapath lib" >&2
    cat "$TEMP/build.log" >&2
    exit 2
fi
case "$RUST_BIN" in
    /*) ;;
    *) RUST_BIN="$ROOT/$RUST_BIN" ;;
esac

: >"$TEMP/c.out"
: >"$TEMP/rust.out"
for scenario in both extra_only timeout hup; do
    R2O_MULTIPOLL_SCENARIO="$scenario" "$TEMP/d2o-multipoll" >>"$TEMP/c.out"
    R2O_MULTIPOLL_SCENARIO="$scenario" \
        R2O_MULTIPOLL_DIFF_OUTPUT="$TEMP/one.out" \
        "$RUST_BIN" --exact --nocapture \
        nfqueue::tests::multipoll_differential_matches_c \
        >"$TEMP/run.log" 2>&1
    cat "$TEMP/one.out" >>"$TEMP/rust.out"
done

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: multi-fd poll C/Rust match\n'
