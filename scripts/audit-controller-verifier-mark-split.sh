#!/bin/sh
# Аудит SO_MARK verifier/measurement split.
#
# D2O-оракул: `install_next` ставит на зарезервированный verifier-сокет метку
# из `d2k_sched_new(..., --mark)`, а измерения получают `--measure-mark`.
# R2O: текущий `r2o_candidate_confirmation_mark` возвращает Some(0), поэтому
# production-тест контроллера подтверждает mark=0 у кандидата. Это расхождение
# с D2O; для исправления нужен controller/main.rs (чужой файл в этой ветке).
#
# Скрипт ничего не меняет и по умолчанию выходит 0 (аудит). С
# R2O_VERIFIER_MARK_STRICT=1 несовпадение даёт exit 1.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the current D2O checkout}
# sched.c сверяется с current main; для datapath-дифференциалов пин a378.
EXPECTED_D2O_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-verifier-mark.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/detect/include" \
    -I"$D2O_ROOT/runtime" \
    -o "$TEMP/d2o-sched-verifier-mark" \
    "$ROOT/scripts/fixtures/d2o_sched_verifier_mark.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/d2o-sched-verifier-mark" >"$TEMP/c.out"
c_line=$(cat "$TEMP/c.out")

cd "$ROOT"
if "$CARGO" test -q --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    candidate_confirmation_uses_datapath_mark_even_when_direct_probe_has_a_bypass_mark \
    >"$TEMP/rust.log" 2>&1; then
    rust_status=OK
else
    rust_status=FAIL
    tail -n 20 "$TEMP/rust.log" >&2
fi
rust_source=$(grep -n "fn r2o_candidate_confirmation_mark" -A4 \
    crates/r2o-controller/src/main.rs | tr '\n' ' ')

printf 'D2O sched: %s\n' "$c_line"
printf 'R2O cargo-test: %s (тест читает фактический getsockopt(SO_MARK) кандидата)\n' "$rust_status"
printf 'R2O source: %s\n' "$rust_source"
printf 'D2O verifier=0x2e, measurement=0x2f\n'
printf 'R2O verifier=0 (Some(0)), measurement=0x2f (test-controller-measure-mark-cli-differential.sh)\n'

if [ "$rust_status" != OK ]; then
    printf 'АУДИТ: production-тест R2O не прошёл\n' >&2
    exit 1
fi
if ! printf '%s\n' "$c_line" | grep -q 'verifier_mark=0x2e measure_mark=0x2f'; then
    printf 'АУДИТ: C-оракул не подтвердил 0x2e/0x2f\n' >&2
    exit 1
fi
if printf '%s\n' "$rust_source" | grep -q 'Some(0)'; then
    printf 'АУДИТ: расхождение — R2O verifier получает 0, а не --mark 0x2e.\n'
    printf 'Нужна правка controller/main.rs: r2o_candidate_confirmation_mark должен\n'
    printf 'возвращать direct_probe_mark (--mark), а не Some(0), и обновить тест.\n'
    if [ "${R2O_VERIFIER_MARK_STRICT:-0}" = 1 ]; then
        exit 1
    fi
else
    printf 'АУДИТ: R2O verifier использует --mark; расхождение не обнаружено.\n'
fi
