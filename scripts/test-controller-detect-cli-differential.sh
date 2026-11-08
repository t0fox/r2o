#!/bin/sh
# CL16: paired C/Rust differential detect CLI (dump-trigger, exit, JSON).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-cl16-detect-cli.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -C "$D2O_ROOT/detect" d2k-detect >/dev/null
DETECT="$D2O_ROOT/detect/d2k-detect"
R2O="$ROOT/target/debug/r2o-controller"
"$CARGO" build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --bin r2o-controller
printf '%s\n' 'R2O CLI: r2o-controller --classify' > "$TEMP/r2o-cli.txt"

trigger_cases=0
for name in example.com disk.rzd.ru a.example; do
    for hello in modern legacy; do
        if [ "$hello" = legacy ]; then
            r2o_flag=--legacy
        else
            r2o_flag=
        fi
        "$DETECT" classify "$name:443" --sni "$name" --hello "$hello" \
            --dump-trigger >"$TEMP/c-$name-$hello.hex"
        # shellcheck disable=SC2086 # намеренное пустое значение для modern
        "$R2O" --classify "$name" 443 "$name" $r2o_flag --dump-trigger \
            >"$TEMP/r-$name-$hello.hex"
        if ! cmp -s "$TEMP/c-$name-$hello.hex" "$TEMP/r-$name-$hello.hex"; then
            printf 'FAIL: dump-trigger %s/%s\n' "$name" "$hello" >&2
            diff -u "$TEMP/c-$name-$hello.hex" "$TEMP/r-$name-$hello.hex" >&2 || true
            exit 1
        fi
        trigger_cases=$((trigger_cases + 1))
    done
done

exit_cases=0
# Коды возврата инструментов совпадают на путях ошибок командной строки:
# оракул печатает usage() и возвращает 2. `--help` не сравнивается: для
# `d2k-detect` это неизвестный флаг (usage, 2), для `r2o-controller` —
# документированная команда (0). Соответствие ограничено classify-путями.
check_exit() {
    c_args=$1
    rust_args=$2
    set +e
    # shellcheck disable=SC2086 # набор аргументов задан списком
    "$DETECT" $c_args >/dev/null 2>&1
    c_status=$?
    # shellcheck disable=SC2086
    "$R2O" $rust_args >/dev/null 2>&1
    r_status=$?
    set -e
    if [ "$c_status" != "$r_status" ]; then
        printf 'FAIL: exit C(%s)=%s Rust(%s)=%s\n' \
            "$c_args" "$c_status" "$rust_args" "$r_status" >&2
        exit 1
    fi
    exit_cases=$((exit_cases + 1))
}
check_exit "" ""
check_exit "classify" "--classify"
check_exit "classify 127.0.0.1:443 --bad" \
    "--classify 127.0.0.1 443 example.com --bad"
check_exit "classify 127.0.0.1:443 --hello both" \
    "--classify 127.0.0.1 443 example.com --hello both"
check_exit "classify 127.0.0.1:443 --sni" \
    "--classify 127.0.0.1 443 example.com --sni"

"$DETECT" classify 127.0.0.1:1 --sni example.com --allow-loopback \
    --timeout 100 --repeats 1 --json >"$TEMP/c.json" 2>/dev/null
"$R2O" --classify 127.0.0.1 1 example.com --allow-loopback \
    --timeout 100 --repeats 1 --json >"$TEMP/r.json" 2>/dev/null
python3 "$ROOT/scripts/fixtures/detect-json-normalize.py" \
    "$TEMP/c.json" "$TEMP/r.json" >"$TEMP/json.result"
grep -qx 'JSON-EQUAL' "$TEMP/json.result"

printf 'triggers=%s exits=%s json=equal\n' "$trigger_cases" "$exit_cases"
printf 'PASS: C/Rust detect CLI dump-trigger/exit/JSON match (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
