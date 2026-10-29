#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
donor_core="$donor_root/core"
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-d2o-sched-dead-address.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

make -B -s -C "$donor_root/detect" test_bridge "CC=${CC:-clang-18}"
"$donor_root/detect/test_bridge"

"${CC:-clang-18}" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -pthread \
    -I"$donor_core" -I"$donor_core/include" -I"$donor_root/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' \
    "$repo_root/crates/r2o-controller/tests/d2o_scheduler_dead_address_differential.c" \
    -Wl,--gc-sections -o "$tmp_dir/d2o-scheduler-dead-address"

"$tmp_dir/d2o-scheduler-dead-address" >"$tmp_dir/c.out"

# Run the donor's real scheduler task-54 scenario and expose the same compact
# observations as the Rust helper below. Instrument only a disposable copy of
# core/test_sched.c; the pinned donor checkout remains untouched.
cp -a "$donor_core" "$tmp_dir/core"
ln -s "$donor_root/datapath" "$tmp_dir/datapath"
ln -s "$donor_root/runtime" "$tmp_dir/runtime"
python3 - "$tmp_dir/core/test_sched.c" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
replacements = [
    (
        "static int ack_answer;\n",
        "static int ack_answer;\nstatic int ack_last_probes;\n",
    ),
    (
        "    if (probes) *probes = ack_answer > 0 ? 1 : 3;\n",
        "    if (probes) *probes = ack_answer > 0 ? 1 : 3;\n"
        "    ack_last_probes = probes ? *probes : 0;\n",
    ),
    (
        '            CHECK(tcp_calls == 2, "task54: перепроверка мёртвого адреса слала триггер");\n',
        '            CHECK(tcp_calls == 2, "task54: перепроверка мёртвого адреса слала триггер");\n'
        '            printf("saved_recheck_silent probes=%d trigger_delta=%d retry_30m=%d\\n",\n'
        '                   ack_last_probes, tcp_calls - 2, said("через 30 мин"));\n',
    ),
    (
        '            CHECK(said("вердикт address снят"), "task54: снятие вердикта не названо");\n',
        '            CHECK(said("вердикт address снят"), "task54: снятие вердикта не названо");\n'
        '            printf("saved_recheck_accepted probes=%d trigger_delta=%d\\n",\n'
        '                   ack_last_probes, tcp_calls - 3);\n',
    ),
    (
        '            CHECK(ack_calls == 4 && tcp_calls == 5, "task54: снятый вердикт адреса снова спрашивал байт");\n',
        '            CHECK(ack_calls == 4 && tcp_calls == 5, "task54: снятый вердикт адреса снова спрашивал байт");\n'
        '            printf("saved_recheck_cleared next_ack_delta=%d next_trigger_delta=%d\\n",\n'
        '                   ack_calls - 4, tcp_calls - 4);\n',
    ),
    (
        "    if (rx_only) { goto rx_volume_tests; }\n",
        "    if (getenv(\"D2K_SAVED_ADDRESS_DIFF_ONLY\")) goto saved_address_diff_only;\n"
        "    if (rx_only) { goto rx_volume_tests; }\n",
    ),
    (
        "    /* ЗАДАЧА 54. Поле 04.10, cdn.cookielaw.org: адрес 104.18.86.42 после\n",
        "saved_address_diff_only: ;\n"
        "    /* ЗАДАЧА 54. Поле 04.10, cdn.cookielaw.org: адрес 104.18.86.42 после\n",
    ),
    (
        "        tcp_answer = D2K_V_OPAQUE;\n    }\n\n"
        "    /* Обычный входящий RST запускает ТОЛЬКО прямую классификацию.",
        "        tcp_answer = D2K_V_OPAQUE;\n    }\n"
        "    if (getenv(\"D2K_SAVED_ADDRESS_DIFF_ONLY\")) return fails ? 1 : 0;\n\n"
        "    /* Обычный входящий RST запускает ТОЛЬКО прямую классификацию.",
    ),
]
for old, new in replacements:
    if source.count(old) != 1:
        raise SystemExit(f"expected one instrumentation anchor in {path}: {old!r}")
    source = source.replace(old, new)
path.write_text(source)
PY
make -s -C "$tmp_dir/core" test_sched "CC=${CC:-clang-18}"
D2K_SAVED_ADDRESS_DIFF_ONLY=1 "$tmp_dir/core/test_sched" >"$tmp_dir/sched.out"
grep '^saved_recheck_' "$tmp_dir/sched.out" >>"$tmp_dir/c.out"
cp -a "$donor_root/detect" "$tmp_dir/detect"
python3 - "$tmp_dir/detect/test_bridge.c" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
replacements = [
    (
        "        CHECK(rc == 0 && ack_calls == 3 && probes == 3);\n",
        "        CHECK(rc == 0 && ack_calls == 3 && probes == 3);\n"
        '        printf("saved_ack_silent probes=%d result=Silent\\n", probes);\n',
    ),
    (
        "        CHECK(rc == 1 && ack_calls == 2 && probes == 2);\n",
        "        CHECK(rc == 1 && ack_calls == 2 && probes == 2);\n"
        '        printf("saved_ack_accepted probes=%d result=Accepted\\n", probes);\n',
    ),
    (
        "        CHECK(rc < 0 && ack_calls == 1 && probes == 1);\n",
        "        CHECK(rc < 0 && ack_calls == 1 && probes == 1);\n"
        '        printf("saved_ack_failed probes=%d result=Unmeasured\\n", probes);\n',
    ),
    (
        "        CHECK(rc < 0 && probes == 0);\n",
        "        CHECK(rc < 0 && probes == 0);\n"
        '        printf("saved_ack_unsupported probes=%d result=Unmeasured\\n", probes);\n',
    ),
    (
        "            CHECK(rc < 0 && ack_calls == 0);\n",
        "            CHECK(rc < 0 && ack_calls == 0 && probes == 0);\n"
        '            printf("saved_ack_stopped probes=%d result=Unmeasured\\n", probes);\n',
    ),
]
for old, new in replacements:
    if source.count(old) != 1:
        raise SystemExit(f"expected one instrumentation anchor in {path}: {old!r}")
    source = source.replace(old, new)
path.write_text(source)
PY
make -s -C "$tmp_dir/detect" test_bridge "CC=${CC:-clang-18}"
"$tmp_dir/detect/test_bridge" >"$tmp_dir/bridge-diff.out"
grep '^saved_ack_' "$tmp_dir/bridge-diff.out" >>"$tmp_dir/c.out"
R2O_SCHED_DEAD_ADDRESS_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    d2o_scheduler_dead_address_matches_donor
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust saved-address cooldown state matches d2o %s.\n' "$actual_donor_sha"
