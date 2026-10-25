#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
expected_donor_sha=783aa75ce44dd6192cd1f4f1d98e4fe909ef3045
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

tests="$repo_root/crates/r2o-controller/tests"
fixture="$tests/fixtures/d2o_meas_send_timeout.tsv"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-d2o-meas.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

cc -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$donor_root/core/include" \
    "$tests/d2o_meas_send_timeout.c" "$donor_root/core/meas.c" \
    -pthread -o "$tmp_dir/d2o_meas_send_timeout"
c_output=$("$tmp_dir/d2o_meas_send_timeout" "$fixture")
printf '%s\n' "$c_output"
case "$c_output" in
    C_RESULT:ERROR) ;;
    *) printf 'Unexpected donor measurement result: %s\n' "$c_output" >&2; exit 1 ;;
esac

if rust_output=$(cargo test -p r2o-controller --locked --test d2o_meas_send_timeout -- --nocapture 2>&1); then
    rust_status=0
else
    rust_status=$?
fi
printf '%s\n' "$rust_output"
[ "$rust_status" -eq 0 ] || exit "$rust_status"
printf '%s\n' "$rust_output" | grep -F 'RUST_RESULT:ERROR' >/dev/null
printf 'C/Rust send-timeout measurement result matches donor %s\n' "$expected_donor_sha"
