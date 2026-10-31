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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-discord-arm.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"${CC:-cc}" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    "$ROOT/crates/r2o-controller/tests/d2o_voice_discovery_arm_differential.c" \
    "$D2O_ROOT/core/voice_discovery.c" -o "$TEMP/d2o"
"$TEMP/d2o" >"$TEMP/d2o.out"
d2o_prefix=$(sed -n 's/^PREFIX://p' "$TEMP/d2o.out")
if [ "${#d2o_prefix}" -ne 40 ] ||
   ! printf '%s\n' "$d2o_prefix" | grep -Eq '^[0-9a-f]{40}$'; then
    cat "$TEMP/d2o.out"
    echo "D2O did not return a complete 20-byte Discovery arm" >&2
    exit 1
fi

rust_source=$ROOT/crates/r2o-controller/src/voice_measure.rs
rust_record=$(sed -n '/^fn r2o_record_voice_discovery_arm(/,/^}/p' "$rust_source")
rust_format=$(sed -n '/^pub fn r2o_format_voice_measurement(/,/^}/p' "$rust_source")
rust_blocked_arm=$(sed -n '/R2oDiscoveryVerdict::Blocked { cutoff, prefix }/,/return r2o_result;/p' "$rust_source")
if [ -z "$rust_record" ] || [ -z "$rust_format" ] ||
   ! printf '%s\n' "$rust_blocked_arm" | grep -Fq 'r2o_record_voice_discovery_arm(&mut r2o_result, prefix);'; then
    cat "$TEMP/d2o.out"
    echo "Rust voice measurement drops D2O's verified Discovery arm" >&2
    exit 1
fi

cat >"$TEMP/r2o.rs" <<'RUST_HEAD'
#![allow(dead_code, private_interfaces)]
use std::net::SocketAddrV4;
const R2O_VOICE_REPEATS: u8 = 3;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum R2oVoiceVerdict { Clear, Blocked, NoUdp, NoCall, Flaky, NoOracle, Unmeasured }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct R2oVoiceArm { name: &'static str, bytes: &'static [u8], copies: u8 }
struct R2oVoiceMeasurement {
    verdict: R2oVoiceVerdict,
    reason: String,
    address: Option<SocketAddrV4>,
    probes: u32,
    marked: bool,
    discovery_verified: bool,
    discovery_prefix: Option<[u8; 20]>,
    arm: Option<R2oVoiceArm>,
}
RUST_HEAD
printf '%s\n' "$rust_record" "$rust_format" >>"$TEMP/r2o.rs"
sed "s/@D2O_PREFIX@/$d2o_prefix/" >>"$TEMP/r2o.rs" <<'RUST_MAIN'
fn main() {
    let mut result = R2oVoiceMeasurement {
        verdict: R2oVoiceVerdict::Blocked,
        reason: "Discovery verified".into(),
        address: None,
        probes: 0,
        marked: true,
        discovery_verified: false,
        discovery_prefix: None,
        arm: None,
    };
    let prefix_hex = "@D2O_PREFIX@";
    let mut prefix = [0; 20];
    for (index, byte) in prefix.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&prefix_hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    r2o_record_voice_discovery_arm(&mut result, prefix);
    println!("PREFIX:{}", result.discovery_prefix.unwrap().iter().map(|byte| format!("{byte:02x}")).collect::<String>());
    print!("{}", r2o_format_voice_measurement(&result));
}
RUST_MAIN

rust_source_path=$(cygpath -w "$TEMP/r2o.rs")
rust_binary_path=$(cygpath -w "$TEMP/r2o.exe")
"${RUSTC:-rustc}" --edition=2024 --target "${RUSTC_TARGET:-x86_64-pc-windows-gnu}" \
    "$rust_source_path" -o "$rust_binary_path"
"$TEMP/r2o.exe" >"$TEMP/r2o.full.out"
sed -n '/^Приём:/p' "$TEMP/r2o.full.out" >"$TEMP/r2o.out"
sed -n '/^Приём:/p' "$TEMP/d2o.out" >"$TEMP/d2o-arm.out"
sed -n '/^PREFIX:/p' "$TEMP/r2o.full.out" >"$TEMP/r2o-prefix.out"
sed -n '/^PREFIX:/p' "$TEMP/d2o.out" >"$TEMP/d2o-prefix.out"
if ! cmp -s "$TEMP/d2o-arm.out" "$TEMP/r2o.out" ||
   ! cmp -s "$TEMP/d2o-prefix.out" "$TEMP/r2o-prefix.out"; then
    printf 'D2O: '; cat "$TEMP/d2o-arm.out" >&2
    printf 'D2O: '; cat "$TEMP/d2o-prefix.out" >&2
    printf 'R2O: '; cat "$TEMP/r2o.out" >&2
    printf 'R2O: '; cat "$TEMP/r2o-prefix.out" >&2
    exit 1
fi
cat "$TEMP/r2o-prefix.out" "$TEMP/r2o.out"
