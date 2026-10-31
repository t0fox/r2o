#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP_BASE=${R2O_TEST_TMP:-${TMPDIR:-/tmp}}
if [ ! -d "$TEMP_BASE" ]; then
    printf 'Temporary directory does not exist: %s\n' "$TEMP_BASE" >&2
    exit 2
fi
TEMP=$(mktemp -d "$TEMP_BASE/r2o-quic-app-bytes.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
CC=${CC:-cc}
CARGO=${CARGO:-cargo}

"$CC" -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-app-bytes" \
    "$ROOT/crates/r2o-controller/tests/d2o_quic_app_bytes_differential.c" \
    "$D2O_ROOT/core/quicwire.c" "$D2O_ROOT/core/crypto.c"
c_bytes=$("$TEMP/d2o-app-bytes")

mkdir -p "$TEMP/rust/src"
cat > "$TEMP/rust/Cargo.toml" <<'EOF'
[package]
name = "r2o-quic-app-bytes-differential"
version = "0.1.0"
edition = "2024"
EOF
cat > "$TEMP/rust/src/main.rs" <<'EOF'
use std::io::{self, Read};
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[cfg(target_has_atomic = "64")]
type R2oQuicHttp3AppByteCounter = AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
type R2oQuicHttp3AppByteCounter = Mutex<u64>;

EOF
sed -n 's/\r$//; /^fn r2o_quic_http3_count_app_bytes(/,/^}/p; /^fn r2o_quic_http3_app_bytes_load(/,/^}/p' \
    "$ROOT/crates/r2o-controller/src/r2o_quic_http3.rs" \
    >> "$TEMP/rust/src/main.rs"
cat >> "$TEMP/rust/src/main.rs" <<'EOF'

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let app_bytes = R2oQuicHttp3AppByteCounter::new(0);
    let mut previous = 0_u64;
    for line in input.lines() {
        let current: u64 = line.parse().unwrap();
        r2o_quic_http3_count_app_bytes(&app_bytes, current - previous);
        previous = current;
        println!("{}", r2o_quic_http3_app_bytes_load(&app_bytes));
    }
}
EOF

manifest=$TEMP/rust/Cargo.toml
if command -v cygpath >/dev/null 2>&1; then
    manifest=$(cygpath -w "$manifest")
fi
r_bytes=$(printf '%s\n' "$c_bytes" | RUSTFLAGS="${RUSTFLAGS:--Awarnings}" \
    "$CARGO" run --quiet --offline --manifest-path "$manifest")

if [ "$c_bytes" != "$r_bytes" ]; then
    printf 'D2O unique stream bytes:\n%s\nR2O application bytes:\n%s\n' \
        "$c_bytes" "$r_bytes" >&2
    printf 'C/Rust QUIC app-byte mismatch.\n' >&2
    exit 1
fi
printf 'D2O/R2O unique QUIC stream bytes match, including >32-bit offsets:\n%s\n' "$c_bytes"
printf 'VERDICT|match\n'
