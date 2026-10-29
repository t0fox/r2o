#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_core=${R2O_DONOR_CORE:-${r2o_script_dir%/r2o}/d2o/core}
r2o_expected_donor_sha=${R2O_EXPECTED_DONOR_SHA:-304ba893dd37197128ac8799c0495b035f6a38c0}
r2o_actual_donor_sha=$(git -C "${r2o_donor_core%/core}" rev-parse HEAD)
r2o_fixture="$r2o_script_dir/crates/r2o-controller/tests/fixtures/d2o_quic_local_address.tsv"
r2o_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-quic-local-address.XXXXXX")
r2o_cleanup() {
    rm -rf -- "$r2o_tmp_dir"
}
trap r2o_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$r2o_actual_donor_sha" != "$r2o_expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$r2o_expected_donor_sha" "$r2o_actual_donor_sha" >&2
    exit 2
fi

if ! grep -Eq 'if[[:space:]]*\(!d2k_quic_allow_local\)' "$r2o_donor_core/quicprobe.c"; then
    printf 'The d2o local-address guard changed; review this differential fixture.\n' >&2
    exit 2
fi
awk '
    /static d2k_vres classify_run\(/ { in_classify = 1 }
    in_classify && /if[[:space:]]*\(!d2k_quic_allow_local\)/ { guard = NR }
    in_classify && /qp_budget start;/ { budget = NR; exit }
    END { if (!guard || !budget || guard >= budget) exit 1 }
' "$r2o_donor_core/quicprobe.c" || {
    printf 'd2o must reject local addresses before starting QUIC work.\n' >&2
    exit 2
}
awk '
    /fn r2o_run_quic_discovery_trial\(/ { in_trial = 1 }
    in_trial && /r2o_quic_address_is_local\(server\)/ { guard = NR }
    in_trial && /if deny_recheck/ { deny = NR; exit }
    END { if (!guard || !deny || guard >= deny) exit 1 }
' "$r2o_script_dir/crates/r2o-controller/src/main.rs" || {
    printf 'Rust must reject local addresses before every QUIC trial branch.\n' >&2
    exit 2
}

clang-18 -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$r2o_donor_core/include" \
    "$r2o_script_dir/crates/r2o-controller/tests/d2o_quic_local_address_differential.c" \
    "$r2o_donor_core/net4.c" -o "$r2o_tmp_dir/d2o-quic-local-address"
"$r2o_tmp_dir/d2o-quic-local-address" "$r2o_fixture" \
    >"$r2o_tmp_dir/c.out"

if R2O_QUIC_LOCAL_ADDRESS_DIFF_OUTPUT="$r2o_tmp_dir/rust.out" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/r2o-target}" \
    cargo +1.98.0 test --locked --offline -p r2o-controller --lib \
        r2o_quic_local_address_policy_matches_d2o \
        >"$r2o_tmp_dir/rust.log" 2>&1; then
    cat "$r2o_tmp_dir/rust.log"
else
    cat "$r2o_tmp_dir/rust.log"
    exit 1
fi

diff -u "$r2o_tmp_dir/c.out" "$r2o_tmp_dir/rust.out"
printf 'C/Rust QUIC local-address policy matches d2o %s.\n' "$r2o_actual_donor_sha"
