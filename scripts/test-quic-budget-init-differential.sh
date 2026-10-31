#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/r2o}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    echo "expected D2O $EXPECTED_D2O_SHA, got $ACTUAL_D2O_SHA" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-quic-budget.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"${CC:-cc}" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    "$ROOT/crates/r2o-controller/tests/d2o_quic_budget_init_differential.c" \
    -o "$TEMP/d2o"
"$TEMP/d2o" >"$TEMP/d2o.out"

rust_init=$(sed -n '/impl R2oQuicHttp3Budget {/,/    fn r2o_mark(/p' \
    "$ROOT/crates/r2o-controller/src/r2o_quic_http3.rs" | sed '$d')
rust_budget=$(sed -n '/^pub fn r2o_quic_http3_budget_datagrams(/,/^}/p' \
    "$ROOT/crates/r2o-controller/src/r2o_quic_http3.rs")
[ -n "$rust_init" ] && [ -n "$rust_budget" ] || {
    cat "$TEMP/d2o.out"
    echo "Rust QUIC budget initializer was not found" >&2
    exit 1
}
cat >"$TEMP/r2o.rs" <<'RUST_HEAD'
#![allow(dead_code)]
const R2O_QUIC_HTTP3_DEFAULT_BUDGET_PACKETS: u32 = 25;
struct R2oQuicHttp3Budget {
    need: u64,
    progress_mark: Option<u64>,
}
RUST_HEAD
printf '%s\n' "$rust_budget" "$rust_init" >>"$TEMP/r2o.rs"
cat >>"$TEMP/r2o.rs" <<'RUST_MAIN'
}
fn main() {
    for budget_packets in [0, 1, 25, u32::MAX / 2, u32::MAX / 2 + 1, u32::MAX] {
        let budget = R2oQuicHttp3Budget::r2o_initialize(budget_packets);
        println!("budget={budget_packets} need={}", budget.need);
    }
}
RUST_MAIN

rust_source_path=$(cygpath -w "$TEMP/r2o.rs")
rust_binary_path=$(cygpath -w "$TEMP/r2o.exe")
"${RUSTC:-rustc}" --edition=2024 --target "${RUSTC_TARGET:-x86_64-pc-windows-gnu}" \
    "$rust_source_path" -o "$rust_binary_path"
"$TEMP/r2o.exe" >"$TEMP/r2o.out"
if ! diff -u "$TEMP/d2o.out" "$TEMP/r2o.out"; then
    echo "D2O and Rust QUIC budget thresholds differ" >&2
    exit 1
fi
cat "$TEMP/r2o.out"
