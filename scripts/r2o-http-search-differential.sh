#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_core="${R2O_DONOR_CORE:-${r2o_script_dir%/*}/d2o/core}"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-http-search-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_upstream_sha=304ba893dd37197128ac8799c0495b035f6a38c0

if [ "${R2O_EXPECTED_DONOR_SHA:-}" != "$r2o_upstream_sha" ]; then
    printf 'HTTP-search differential requires pinned upstream donor %s\n' "$r2o_upstream_sha" >&2
    exit 2
fi
if [ ! -d "$r2o_donor_core" ]; then
    printf 'Каталог C-эталона не найден: %s\n' "$r2o_donor_core" >&2
    exit 2
fi

r2o_show_log_on_error() {
    r2o_status=$?
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_log" ]; then
        cat "$r2o_log"
    fi
}
trap r2o_show_log_on_error EXIT

r2o_run_timed() {
    r2o_label=$1
    shift
    r2o_started=$(date +%s)
    if "$@"; then
        r2o_status=0
    else
        r2o_status=$?
    fi
    printf '\nВремя %s: %s с (код %s)\n' \
        "$r2o_label" "$(( $(date +%s) - r2o_started ))" "$r2o_status"
    return "$r2o_status"
}

mkdir -p "$r2o_log_dir"
{
    printf 'Дифференциальная проверка HTTP baseline: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C: %s\n' "$r2o_donor_core"
    printf '\nSHA-256 исходников C-эталона\n'
    sha256sum "$r2o_donor_core/httpsearch.c" "$r2o_donor_core/test_httpsearch.c"
    r2o_httpsearch_sha=$(sha256sum "$r2o_donor_core/httpsearch.c" | awk '{print $1}')
    r2o_test_sha=$(sha256sum "$r2o_donor_core/test_httpsearch.c" | awk '{print $1}')
    if [ "$r2o_httpsearch_sha" != \
        '7075b74f1340b53c410422bfe2ac5f558d009b29c20a7085e674f49b0210fa3a' ] || \
        [ "$r2o_test_sha" != \
        '7a1f589858f8ab5bec6b419e64f2bd262da023008726984487f4efa1cdad8195' ]; then
        printf 'Исходники HTTP-search отличаются от проверенного снимка донора\n' >&2
        exit 1
    fi
    printf '\nТесты C-эталона HTTP-search\n'
    r2o_run_timed 'test_httpsearch C-эталона' \
        make -B -C "$r2o_donor_core" test-httpsearch CC=clang-18
    printf '\nТест Rust повторов базового HTTP-зонда\n'
    r2o_run_timed 'повторы baseline в Rust' \
        cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
            baseline_local_failure_and_cut_silence_follow_donor_retry_rules \
            --locked --offline -- --nocapture
} >"$r2o_log" 2>&1

grep -q 'test_httpsearch: все проверки прошли' "$r2o_log"
grep -q 'baseline_local_failure_and_cut_silence_follow_donor_retry_rules .*ok' "$r2o_log"
printf 'Журнал дифференциальной проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
