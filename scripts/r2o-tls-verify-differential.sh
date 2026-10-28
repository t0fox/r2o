#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

donor_core="$donor_root/core"
tests="$repo_root/crates/r2o-controller/tests"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-d2o-tls-verify.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

make -C "$donor_core" test_verify
cc -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$donor_core/include" -I"$donor_root/datapath/include" \
    "$tests/d2o_verify_fixture.c" \
    "$donor_core/verify.o" "$donor_core/tls12.o" "$donor_core/p256.o" \
    "$donor_core/quicconn.o" "$donor_core/quicwire.o" "$donor_core/h3.o" \
    "$donor_core/compose.o" "$donor_core/measured.o" "$donor_core/hello.o" \
    "$donor_core/meas.o" "$donor_core/link.o" "$donor_core/tls13.o" \
    "$donor_core/tls13core.o" "$donor_core/x25519.o" "$donor_core/crypto.o" \
    -lpthread -o "$tmp_dir/d2o_verify_fixture"

make -C "$donor_core" test_sched
"$donor_core/test_sched" --measured-only

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/r2o-target}" \
    cargo test -p r2o-controller --locked --bin r2o-controller \
        captured_non_http_alpn_requires_handshake_block_and_no_volume_cut

R2O_D2O_VERIFY_HELPER="$tmp_dir/d2o_verify_fixture" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/r2o-target}" \
    cargo test -p r2o-controller --locked --test d2o_verify_differential \
        -- --ignored --nocapture
