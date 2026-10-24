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

cargo +1.98.0 test --locked -p r2o-controller --lib \
    r2o_разбор_cpu_сохраняет_unsigned_арифметику_донора
