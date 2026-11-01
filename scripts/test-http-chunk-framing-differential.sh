#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_root=/mnt/e/r2o-tooling/d2o-clean-main
r2o_donor_core="$r2o_donor_root/core"
r2o_clang=/mnt/e/r2o-tooling/clang18-root/usr/bin/clang-18
r2o_cargo=/mnt/e/r2o-tooling/linux-rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo
r2o_rustc=/mnt/e/r2o-tooling/linux-rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc
r2o_expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
r2o_artifacts="$r2o_script_dir/.rea/http-chunk-framing-$$"
r2o_binary="$r2o_artifacts-c"
r2o_c_output="$r2o_artifacts-c.txt"
r2o_rust_output="$r2o_artifacts-rust.txt"

if [ "$(git -C "$r2o_donor_root" rev-parse HEAD)" != "$r2o_expected_donor_sha" ]; then
    printf 'HTTP chunk differential requires pinned clean D2O source %s\n' \
        "$r2o_expected_donor_sha" >&2
    exit 2
fi
if [ ! -f "$r2o_donor_core/verify.o" ] || [ ! -f "$r2o_donor_core/tls12.o" ]; then
    printf 'Build artifacts for the clean D2O oracle are missing under %s\n' \
        "$r2o_donor_core" >&2
    exit 2
fi

mkdir -p "$r2o_script_dir/.rea"
export TMPDIR="$r2o_script_dir/.rea"
trap 'rm -f "$r2o_binary" "$r2o_c_output" "$r2o_rust_output"' EXIT HUP INT TERM

LD_LIBRARY_PATH=/mnt/e/r2o-tooling/clang18-root/usr/lib/x86_64-linux-gnu:/mnt/e/r2o-tooling/clang18-root/usr/lib/llvm-18/lib \
    "$r2o_clang" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$r2o_donor_core/include" \
    -I"$r2o_donor_root/datapath/include" \
    -o "$r2o_binary" \
    "$r2o_script_dir/crates/r2k-core/tests/d2o_http_chunk_framing_differential.c" \
    "$r2o_donor_core/httpsearch.o" \
    "$r2o_donor_core/httpup_logic.o" \
    "$r2o_donor_core/plantlv.o" \
    "$r2o_donor_core/quic.o" \
    "$r2o_donor_core/quicwire.o" \
    "$r2o_donor_core/crypto.o" \
    "$r2o_donor_root/datapath/plan_parse.c" \
    "$r2o_donor_root/datapath/plan_apply.c" \
    "$r2o_donor_root/datapath/wire.c" \
    "$r2o_donor_core/verify.o" \
    "$r2o_donor_core/quicconn.o" \
    "$r2o_donor_core/h3.o" \
    "$r2o_donor_core/tls12.o" \
    "$r2o_donor_core/p256.o" \
    "$r2o_donor_core/compose.o" \
    "$r2o_donor_core/measured.o" \
    "$r2o_donor_core/hello.o" \
    "$r2o_donor_core/meas.o" \
    "$r2o_donor_core/link.o" \
    "$r2o_donor_core/tls13.o" \
    "$r2o_donor_core/tls13core.o" \
    "$r2o_donor_core/x25519.o" \
    -lpthread
"$r2o_binary" >"$r2o_c_output"

CARGO_HOME=/mnt/e/r2o-tooling/linux-cargo \
RUSTUP_HOME=/mnt/e/r2o-tooling/linux-rustup \
RUSTC="$r2o_rustc" \
CARGO_TARGET_DIR="$r2o_script_dir/target" \
R2O_HTTP_CHUNK_DIFF_OUTPUT="$r2o_rust_output" \
"$r2o_cargo" test --locked --offline \
    -p r2k-core --test http_response \
    matches_d2o_http_header_and_chunk_framing

diff -u "$r2o_c_output" "$r2o_rust_output"
printf 'C/Rust HTTP response header/chunk framing matches.\n'
