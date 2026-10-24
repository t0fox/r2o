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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-resource-limit.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
cc=${CC:-clang-18}
donor_core="$donor_root/core"

make -s -C "$donor_core" tcp1620_whitelist.inc
"$cc" -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -pthread -I"$donor_core/include" -I"$donor_root/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' \
    -DD2O_SCHED_SOURCE='"'"$donor_core"'/sched.c"' \
    "$repo_root/crates/r2o-controller/tests/d2o_probe_budget_differential.c" \
    "$donor_core/compose.c" -Wl,--gc-sections -o "$tmp_dir/probe-budget"
probe_budget_fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_probe_budget.tsv"
"$tmp_dir/probe-budget" "$probe_budget_fixture" >"$tmp_dir/c-probe-budget.out"
R2O_PROBE_BUDGET_DIFF_C_OUTPUT="$tmp_dir/c-probe-budget.out" \
    R2O_PROBE_BUDGET_DIFF_OUTPUT="$tmp_dir/rust-probe-budget.out" \
    cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    d2o_probe_budget_matches_donor
diff -u "$tmp_dir/c-probe-budget.out" "$tmp_dir/rust-probe-budget.out"
cat "$tmp_dir/c-probe-budget.out"
printf 'C/Rust donor probe budgets match, including network whitelist allowance\n'

"$cc" -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -pthread -I"$donor_core/include" -I"$donor_root/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' -c "$donor_core/sched.c" -o "$tmp_dir/sched.o"
"$cc" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$donor_core/include" -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_cpu_parse_fixture.c" \
    "$tmp_dir/sched.o" -Wl,--gc-sections -pthread -o "$tmp_dir/cpu-parse"

"$tmp_dir/cpu-parse" >"$tmp_dir/c.out"
cat >"$tmp_dir/expected" <<'EOF'
0 1 1
0 0 0
0 6 10
EOF
diff -u "$tmp_dir/expected" "$tmp_dir/c.out"
printf 'C donor d2k_sched_cpu_parse: all three vectors match\n'

"$cc" -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -pthread -I"$donor_core" -I"$donor_core/include" \
    -I"$donor_root/datapath/include" -DD2K_RELEASE_ID='"dev"' \
    "$repo_root/crates/r2o-controller/tests/d2o_aimd_differential.c" \
    -Wl,--gc-sections -o "$tmp_dir/aimd"
fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_aimd.tsv"
"$tmp_dir/aimd" "$fixture" >"$tmp_dir/c-aimd.out"
R2O_AIMD_DIFF_OUTPUT="$tmp_dir/rust-aimd.out" \
    cargo +1.98.0 test --locked -p r2o-controller --lib \
    r2o_aimd_shared_inputs_match_d2o
diff -u "$tmp_dir/c-aimd.out" "$tmp_dir/rust-aimd.out"
printf 'C/Rust donor AIMD thresholds, backoff, resource loss, and slot ceiling match\n'

cargo +1.98.0 test --locked -p r2o-controller --lib \
    r2o_разбор_cpu_сохраняет_unsigned_арифметику_донора
