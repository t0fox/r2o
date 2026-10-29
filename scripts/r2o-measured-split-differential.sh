#!/bin/sh
set -eu

root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor=${R2O_DONOR_ROOT:-"${root%/*}/d2o"}
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
test "$(git -C "$donor" rev-parse HEAD)" = "$expected_donor_sha"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor/core/include" \
    "$root/crates/r2o-controller/tests/d2o_measured_split_differential.c" \
    "$donor/core/measured.c" -Wl,--gc-sections -o "$tmp/c"
"$tmp/c" | sed 's/d2k-plan/r2o-plan/' >"$tmp/c.out"

cd "$root"
R2O_MEASURED_SPLIT_DIFF_OUTPUT="$tmp/rust.out" \
    cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    measured_split_plans_match_donor
diff -u "$tmp/c.out" "$tmp/rust.out"
printf 'C/Rust measured PREFIX/WHOLE_PACKET split plans match d2o %s.\n' "$expected_donor_sha"

make -s -C "$donor/core" hello.o CC=clang-18
clang-18 -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor/detect/include" -I"$donor/core/include" \
    -I"$donor/datapath/include" \
    "$root/crates/r2o-controller/tests/d2o_bridge_split_gate_differential.c" \
    "$donor/detect/bridge.c" "$donor/core/hello.c" \
    -Wl,--gc-sections -o "$tmp/bridge-split-gate"
"$tmp/bridge-split-gate" >"$tmp/bridge-c.out"
cd "$root"
R2O_DISCOVERY_SPLIT_BRIDGE_DIFF_OUTPUT="$tmp/bridge-rust.out" \
    cargo +1.98.0 test --locked --offline -p r2o-controller \
    --bin r2o-controller discovery_bridge_rejects_socket_only_split_results
diff -u "$tmp/bridge-c.out" "$tmp/bridge-rust.out"
printf 'C/Rust bridge raw-split gate matches d2o %s.\n' "$expected_donor_sha"

make -s -C "$donor/detect" test_bridge CC=clang-18
clang-18 -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor/detect" -I"$donor/detect/include" -I"$donor/core/include" \
    -I"$donor/datapath/include" \
    "$root/crates/r2o-controller/tests/d2o_bridge_unplannable_differential.c" \
    "$donor/detect/bridge.o" "$donor/detect/poison.o" \
    "$donor/core/measured.o" "$donor/core/hello.o" "$donor/core/plantlv.o" \
    "$donor/core/quic.o" "$donor/core/quicwire.o" "$donor/core/crypto.o" \
    "$donor/datapath/plan_parse.o" "$donor/datapath/plan_apply.o" \
    "$donor/datapath/wire.o" -Wl,--gc-sections -lpthread \
    -o "$tmp/bridge-unplannable"
"$tmp/bridge-unplannable" >"$tmp/bridge-unplannable-c.out"
cd "$root"
R2O_BRIDGE_UNPLANNABLE_DIFF_OUTPUT="$tmp/bridge-unplannable-rust.out" \
    cargo +1.98.0 test --locked --offline -p r2o-controller --test classify \
    accepted_but_unplannable_poison_keeps_opaque_verdict_and_search_ownership -- --exact
diff -u "$tmp/bridge-unplannable-c.out" "$tmp/bridge-unplannable-rust.out"
printf 'C/Rust bridge unplannable-hit fallback matches d2o %s.\n' "$expected_donor_sha"

"$donor/detect/test_bridge"
cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    discovery_search_ownership_matches_donor_local_failure_gates
