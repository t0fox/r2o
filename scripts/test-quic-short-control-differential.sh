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

TEMP_BASE=${R2O_TEST_TMP:-${ROOT%/*}/r2o-tooling/tmp}
if [ ! -d "$TEMP_BASE" ]; then
    printf 'Temporary directory must exist on E: %s\n' "$TEMP_BASE" >&2
    exit 2
fi
TEMP=$(mktemp -d "$TEMP_BASE/r2o-quic-short-control.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
CC=${CC:-cc}
CARGO=${CARGO:-cargo}

"$CC" -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-short-control" \
    "$ROOT/crates/r2o-controller/tests/d2o_quic_short_control.c"
c_verdicts=$("$TEMP/d2o-short-control")

mkdir -p "$TEMP/rust/src"
cat > "$TEMP/rust/Cargo.toml" <<'EOF'
[package]
name = "r2o-quic-short-control-differential"
version = "0.1.0"
edition = "2024"
EOF
cat > "$TEMP/rust/src/main.rs" <<'EOF'
mod r2k_core {
    pub mod quic {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
EOF
sed -n 's/\r$//; /^pub enum R2kQuicDataVerdict/,/^}/p' "$ROOT/crates/r2k-core/src/quic.rs" \
    >> "$TEMP/rust/src/main.rs"
sed -n 's/\r$//; /^const R2K_QUIC_DATA_BYTES/,/^$/p' "$ROOT/crates/r2k-core/src/quic.rs" \
    >> "$TEMP/rust/src/main.rs"
sed -n 's/\r$//; /^pub fn r2k_quic_data_judge(/,/^}/p' "$ROOT/crates/r2k-core/src/quic.rs" \
    >> "$TEMP/rust/src/main.rs"
cat >> "$TEMP/rust/src/main.rs" <<'EOF'
    }
}

mod r2o_quic_http3 {
    #[derive(Default)]
    pub struct R2oQuicHttp3Result {
        pub handshake_confirmed: bool,
        pub status: u16,
        pub app_bytes: u64,
        pub complete: bool,
        pub budget_required: bool,
        pub budget_passed: bool,
        pub r2o_quic_stalled: bool,
    }
}

use r2k_core::quic::{R2kQuicDataVerdict, r2k_quic_data_judge};
EOF
sed -n 's/\r$//; /^pub fn r2o_quic_short_control_data_verdict(/,/^}/p' \
    "$ROOT/crates/r2o-controller/src/quic_replay.rs" >> "$TEMP/rust/src/main.rs"
cat >> "$TEMP/rust/src/main.rs" <<'EOF'

fn main() {
    let partial = r2o_quic_http3::R2oQuicHttp3Result {
        handshake_confirmed: true,
        status: 200,
        app_bytes: 32_768,
        ..Default::default()
    };
    let complete = r2o_quic_http3::R2oQuicHttp3Result {
        handshake_confirmed: true,
        status: 200,
        app_bytes: 64,
        complete: true,
        ..Default::default()
    };
    let stalled = r2o_quic_http3::R2oQuicHttp3Result {
        handshake_confirmed: true,
        status: 200,
        app_bytes: 6_144,
        r2o_quic_stalled: true,
        ..Default::default()
    };
    let refused = r2o_quic_http3::R2oQuicHttp3Result {
        handshake_confirmed: true,
        status: 451,
        app_bytes: 64,
        complete: true,
        ..Default::default()
    };
    for (label, result) in [
        ("partial", partial),
        ("complete", complete),
        ("stalled", stalled),
        ("refused", refused),
    ] {
        let verdict = r2o_quic_short_control_data_verdict(&result);
        let verdict = match verdict {
            R2kQuicDataVerdict::NotRun => "NOT_RUN",
            R2kQuicDataVerdict::Pass => "PASS",
            R2kQuicDataVerdict::NoHandshake => "NO_HANDSHAKE",
            R2kQuicDataVerdict::Cut => "CUT",
        };
        println!("{label}|{verdict}");
    }
}
EOF

manifest=$TEMP/rust/Cargo.toml
if command -v cygpath >/dev/null 2>&1; then
    manifest=$(cygpath -w "$manifest")
fi
r_verdicts=$(RUSTFLAGS="${RUSTFLAGS:--Awarnings}" \
    "$CARGO" run --quiet --offline --manifest-path "$manifest")

if [ "$c_verdicts" != "$r_verdicts" ]; then
    printf 'D2O short control:\n%s\nR2O short control:\n%s\n' "$c_verdicts" "$r_verdicts" >&2
    printf 'C/Rust short-control verdict mismatch.\n' >&2
    exit 1
fi
printf 'D2O and R2O short-control verdicts:\n%s\n' "$c_verdicts"
printf 'VERDICT|match\n'
