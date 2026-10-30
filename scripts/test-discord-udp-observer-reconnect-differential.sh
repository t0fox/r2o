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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-discord-observer.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
D2O_DATAPATH=$D2O_ROOT/datapath
D2O_CORE=$D2O_ROOT/core
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
RUSTC=${RUSTC:-rustc}

"$CC" -std=c99 -O2 -Wall -Wextra -Werror -pthread \
    -D_POSIX_C_SOURCE=200809L -DD2K_RELEASE_ID='"dev"' \
    -I"$D2O_DATAPATH" -I"$D2O_DATAPATH/include" -I"$D2O_CORE/include" \
    -o "$TEMP/d2o-trace" \
    "$ROOT/crates/r2o-datapath/tests/fixtures/d2o_discord_udp_observer_trace.c" \
    "$D2O_DATAPATH/session.c" "$D2O_DATAPATH/http80.c" \
    "$D2O_DATAPATH/hold.c" "$D2O_DATAPATH/capture.c" \
    "$D2O_DATAPATH/nat.c" "$D2O_DATAPATH/ctq.c" "$D2O_DATAPATH/nl.c" \
    "$D2O_DATAPATH/track.c" "$D2O_DATAPATH/tls.c" \
    "$D2O_DATAPATH/wire.c" "$D2O_DATAPATH/wire_udp.c" \
    "$D2O_DATAPATH/journal.c" "$D2O_DATAPATH/plans.c" \
    "$D2O_DATAPATH/plan_parse.c" "$D2O_DATAPATH/plan_apply.c" \
    "$D2O_CORE/quic.c" "$D2O_CORE/quicsnap.c" "$D2O_CORE/quicwire.c" \
    "$D2O_CORE/crypto.c" "$D2O_CORE/ipfrag.c" "$D2O_CORE/httpup_logic.c" \
    "$D2O_CORE/quichello.c" "$D2O_CORE/hello.c" \
    "$D2O_CORE/tls13core.c" "$D2O_CORE/x25519.c"

mkdir -p "$TEMP/rust/src"
rust_root=$ROOT
rust_temp=$TEMP
rust_target=${CARGO_TARGET_DIR:-$TEMP/target}
rust_host=$($RUSTC -vV | sed -n 's/^host: //p')
case "$rust_host" in
    *-windows-*) use_windows_rust_paths=1 ;;
    *) use_windows_rust_paths=0 ;;
esac
if [ "$use_windows_rust_paths" = 1 ] && command -v cygpath >/dev/null 2>&1; then
    rust_root=$(cygpath -am "$ROOT")
    rust_temp=$(cygpath -am "$TEMP")
    rust_target=$(cygpath -am "$rust_target")
fi
cat > "$TEMP/rust/Cargo.toml" <<EOF
[package]
name = "r2o-discord-observer-trace"
version = "0.1.0"
edition = "2024"

[dependencies]
r2k-core = { path = "$rust_root/crates/r2k-core" }
EOF
cat > "$TEMP/rust/src/main.rs" <<EOF
#[path = "$rust_root/crates/r2o-datapath/src/flow_capacity.rs"]
mod flow_capacity;
#[path = "$rust_root/crates/r2o-datapath/src/r2o_voice.rs"]
mod r2o_voice;
#[path = "$rust_root/crates/r2o-datapath/tests/fixtures/r2o_discord_udp_observer_trace.rs"]
mod trace;

fn main() {
    trace::run();
}
EOF

"$TEMP/d2o-trace" > "$TEMP/d2o.out"
CARGO_TARGET_DIR=$rust_target \
RUSTFLAGS="${RUSTFLAGS:--Awarnings}" \
    CARGO_BUILD_TARGET=${CARGO_BUILD_TARGET:-$rust_host} \
    CARGO_MAKEFLAGS= \
    "$CARGO" run --quiet --manifest-path "$rust_temp/rust/Cargo.toml" > "$TEMP/r2o.out"

grep -qx 'ssrc_reconnect first=1 reconnect=0 suspects=1' "$TEMP/d2o.out"
grep -qx 'ssrc_reconnect first=1 reconnect=1 suspects=2' "$TEMP/r2o.out"
tail -n +2 "$TEMP/d2o.out" > "$TEMP/d2o-lifecycle.out"
tail -n +2 "$TEMP/r2o.out" > "$TEMP/r2o-lifecycle.out"
grep -qx 'endpoint_change=1' "$TEMP/d2o-lifecycle.out"
grep -qx 'endpoint_change=1' "$TEMP/r2o-lifecycle.out"
grep -qx 'long_session=active600 events=0 expire=1' "$TEMP/d2o-lifecycle.out"
grep -qx 'long_session=active600 events=0 expire=1' "$TEMP/r2o-lifecycle.out"
if ! cmp -s "$TEMP/d2o-lifecycle.out" "$TEMP/r2o-lifecycle.out"; then
    printf 'Discord lifecycle mismatch after the documented SSRC reconnect difference:\n' >&2
    printf 'D2O: '; cat "$TEMP/d2o.out" >&2
    printf 'R2O: '; cat "$TEMP/r2o.out" >&2
    exit 1
fi
printf 'D2O %s:\n%s\n' "$ACTUAL_D2O_SHA" "$(cat "$TEMP/d2o.out")"
printf 'R2O:\n%s\n' "$(cat "$TEMP/r2o.out")"
printf '%s\n' 'D2O keeps the one-event 5-tuple latch; R2O re-arms on a new SSRC.'
printf '%s\n' 'Endpoint change and 10-minute bidirectional session lifetimes match.'
