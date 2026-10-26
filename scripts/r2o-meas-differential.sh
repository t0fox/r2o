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

eintr_fixture="$tests/fixtures/d2o_meas_eintr.tsv"
cc -std=c99 -O2 -Wall -Wextra -Werror -pthread \
    -I"$donor_root/core/include" \
    "$tests/d2o_meas_eintr.c" "$donor_root/core/meas.c" \
    -o "$tmp_dir/d2o_meas_eintr"
c_eintr_output=$("$tmp_dir/d2o_meas_eintr" "$eintr_fixture")
printf '%s\n' "$c_eintr_output"
printf '%s\n' "$c_eintr_output" | grep -Fx 'C_RESULT:REJECTED' >/dev/null

if rust_eintr_output=$(R2O_MEAS_EINTR_OUTPUT="$tmp_dir/rust-meas-eintr.out" \
    cargo test -p r2o-controller --locked --test d2o_meas_eintr \
    d2o_measurement_receive_interruption_matches_silence -- --nocapture 2>&1); then
    rust_eintr_status=0
else
    rust_eintr_status=$?
fi
printf '%s\n' "$rust_eintr_output"
[ "$rust_eintr_status" -eq 0 ] || exit "$rust_eintr_status"
printf '%s\n' "$c_eintr_output" >"$tmp_dir/c-meas-eintr.out"
diff -u "$tmp_dir/c-meas-eintr.out" "$tmp_dir/rust-meas-eintr.out"
printf 'C/Rust receive-interruption measurement result matches donor %s\n' "$expected_donor_sha"

send_eintr_fixture="$tests/fixtures/d2o_meas_send_eintr.tsv"
c_send_eintr_output=$("$tmp_dir/d2o_meas_eintr" "$send_eintr_fixture")
printf '%s\n' "$c_send_eintr_output"
printf '%s\n' "$c_send_eintr_output" | grep -Fx 'C_RESULT:ERROR' >/dev/null
if rust_send_eintr_output=$(R2O_MEAS_EINTR_OUTPUT="$tmp_dir/rust-send-meas-eintr.out" \
    cargo test -p r2o-controller --locked --test d2o_meas_eintr \
    d2o_measurement_send_interruption_matches_error -- --nocapture 2>&1); then
    rust_send_eintr_status=0
else
    rust_send_eintr_status=$?
fi
printf '%s\n' "$rust_send_eintr_output"
[ "$rust_send_eintr_status" -eq 0 ] || exit "$rust_send_eintr_status"
printf '%s\n' "$c_send_eintr_output" >"$tmp_dir/c-send-meas-eintr.out"
diff -u "$tmp_dir/c-send-meas-eintr.out" "$tmp_dir/rust-send-meas-eintr.out"
printf 'C/Rust send-interruption measurement result matches donor %s\n' "$expected_donor_sha"
