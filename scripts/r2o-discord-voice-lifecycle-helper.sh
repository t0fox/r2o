#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_core="${R2O_DONOR_CORE:-${r2o_script_dir%/*}/d2o/core}"
r2o_expected_donor_sha=${R2O_EXPECTED_DONOR_SHA:-304ba893dd37197128ac8799c0495b035f6a38c0}
r2o_actual_donor_sha=$(git -C "${r2o_donor_core%/core}" rev-parse HEAD)
if [ "$r2o_actual_donor_sha" != "$r2o_expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$r2o_expected_donor_sha" "$r2o_actual_donor_sha" >&2
    exit 2
fi

r2o_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-voice-lifecycle.XXXXXX")
trap 'rm -rf -- "$r2o_tmp_dir"' EXIT

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$r2o_donor_core/include" \
    -I"$r2o_donor_core/../datapath/include" \
    -I"$r2o_donor_core" \
    "$r2o_script_dir/crates/r2o-controller/tests/d2o_voice_lifecycle_trace.c" \
    "$r2o_donor_core/httpsprobe.o" "$r2o_donor_core/httpsearch.o" \
    "$r2o_donor_core/httpup_logic.o" "$r2o_donor_core/sched.o" \
    "$r2o_donor_core/verify_quic_replay.o" "$r2o_donor_core/quichello.o" \
    "$r2o_donor_core/plantlv.o" "$r2o_donor_core/verdict.o" \
    "$r2o_donor_core/meas.o" "$r2o_donor_core/crypto.o" \
    "$r2o_donor_core/quic.o" "$r2o_donor_core/quicwire.o" \
    "$r2o_donor_core/quicprobe.o" "$r2o_donor_core/quicsnap.o" \
    "$r2o_donor_core/quicsnap_reseal.o" "$r2o_donor_core/quicarms.o" \
    "$r2o_donor_core/ipfrag.o" "$r2o_donor_core/net4.o" \
    "$r2o_donor_core/props.o" "$r2o_donor_core/voice.o" \
    "$r2o_donor_core/voice_discovery.o" "$r2o_donor_core/stun.o" \
    "$r2o_donor_core/hello.o" "$r2o_donor_core/catalog.o" \
    "$r2o_donor_core/groups.o" "$r2o_donor_core/domain.o" \
    "$r2o_donor_core/match.o" "$r2o_donor_core/compose.o" \
    "$r2o_donor_core/measured.o" "$r2o_donor_core/link.o" \
    "$r2o_donor_core/volume.o" "$r2o_donor_core/tls13.o" \
    "$r2o_donor_core/tls13core.o" "$r2o_donor_core/x25519.o" \
    "$r2o_donor_core/verify.o" "$r2o_donor_core/tls12.o" \
    "$r2o_donor_core/p256.o" "$r2o_donor_core/quicconn.o" \
    "$r2o_donor_core/h3.o" "$r2o_donor_core/libd2k_udp.a" \
    -o "$r2o_tmp_dir/d2o-voice-lifecycle"

"$r2o_tmp_dir/d2o-voice-lifecycle" >"$r2o_tmp_dir/c.trace"
R2O_VOICE_LIFECYCLE_TRACE_OUTPUT="$r2o_tmp_dir/rust.trace" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
        voice_lifecycle_trace_matches_d2o_a_to_b_queue_lease_proof_and_persistence \
        -- --nocapture
diff -u "$r2o_tmp_dir/c.trace" "$r2o_tmp_dir/rust.trace"
printf 'C/Rust Discord endpoint lifecycle traces match d2o %s.\n' \
    "$r2o_actual_donor_sha"
