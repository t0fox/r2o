#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_core=${R2O_DONOR_CORE:-"${r2o_script_dir%/*}/d2o-main/core"}
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-discovery-quic-stop-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$r2o_log_dir"

r2o_run() {
    r2o_label=$1
    shift
    r2o_started=$(date +%s)
    if "$@" >>"$r2o_log" 2>&1; then
        r2o_status=0
    else
        r2o_status=$?
    fi
    printf 'Время %s: %s с (код %s)\n' \
        "$r2o_label" "$(( $(date +%s) - r2o_started ))" "$r2o_status" >>"$r2o_log"
    if [ "$r2o_status" -ne 0 ]; then
        tail -n 80 "$r2o_log"
        return "$r2o_status"
    fi
}

if [ ! -d "$r2o_donor_core" ]; then
    printf 'Не найден каталог исходников C: %s\n' "$r2o_donor_core" >&2
    exit 2
fi

{
    printf 'C/Rust-сверка очистки QUIC-пробы при остановке: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C: %s\n' "$r2o_donor_core"
    printf '\nSHA-256 исходников и тестов\n'
    sha256sum \
        "$r2o_donor_core/sched.c" \
        "$r2o_donor_core/test_sched.c" \
        "$r2o_script_dir/crates/r2o-controller/src/main.rs"
    printf '\nПереиспользованное REA Evidence без повторного разбора\n'
    printf 'd2k_plantab_del_addr_probe: ev_c669cbf72bf64146e22cf7c349e8c4e8f37435a1fd80c02791015ded52dd84a4\n'
    printf 'addr_probe_remove: ev_0e00787312c35345aa6c4945321e9ab7379361be27adc72c8cd582719a815c2d\n'
    printf 'NamePlans::clear_probes: ev_b0f133505366bfdce8bba750010b318b564f102255135188a868c6ad30a64467\n'
    printf '\nClang AST жизненного цикла задачи C\n'
} >"$r2o_log"

# shellcheck disable=SC2016 # параметры раскрываются во вложенном sh -c
r2o_run 'разбор AST планировщика C' sh -c \
    'clang-18 -std=gnu11 -pthread -I"$2/include" -I"$2/../datapath/include" -DD2K_RELEASE_ID="dev" -fsyntax-only -Xclang -ast-dump "$1" 2>/dev/null | grep -E "FunctionDecl.*(d2k_sched_tick|task_fail|task_done)"' \
    _ "$r2o_donor_core/sched.c" "$r2o_donor_core"

printf '\nЭталон C: снятие временной пробы при жизненном цикле задачи\n' >>"$r2o_log"
r2o_run 'сборка ARM64 C-теста планировщика' make -B -C "$r2o_donor_core" test_sched CC=aarch64-linux-gnu-gcc
r2o_run 'ARM64/QEMU lifecycle-тест планировщика C' \
    qemu-aarch64 -L /usr/aarch64-linux-gnu "$r2o_donor_core/test_sched" --lifecycle-only

printf '\nЦель Rust: остановка worker обслуживает DEL_ADDR_PROBE\n' >>"$r2o_log"
r2o_run 'ARM64/QEMU-тест очистки QUIC-пробы' env \
    QEMU_LD_PREFIX=/usr/aarch64-linux-gnu \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER='qemu-aarch64 -L /usr/aarch64-linux-gnu' \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    cargo +1.98.0 test --target aarch64-unknown-linux-gnu --locked --offline \
    -p r2o-controller --bin r2o-controller \
    r2o_остановка_quic_worker_обслуживает_удаление_временной_пробы -- --nocapture

printf '\nЖурнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
