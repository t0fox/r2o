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
R2O_DETECT="$ROOT/target/debug/r2o-detect"
"$CARGO" build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --bin r2o-controller --bin r2o-detect
printf '%s\n' 'R2O CLI: r2o-controller --classify / r2o-detect classify' > "$TEMP/r2o-cli.txt"

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

# Отдельный detect-совместимый бинарник: точные тексты stderr, JSON и
# человеческий отчёт C `d2k-detect`. Это не `--classify` контроллера.
check_detect_exact() {
    detect_args=$1
    set +e
    # shellcheck disable=SC2086 # набор аргументов задан списком
    "$DETECT" $detect_args >"$TEMP/detect-c.out" 2>"$TEMP/detect-c.err"
    c_status=$?
    # shellcheck disable=SC2086
    "$R2O_DETECT" $detect_args >"$TEMP/detect-r.out" 2>"$TEMP/detect-r.err"
    r_status=$?
    set -e
    if [ "$c_status" != "$r_status" ]; then
        printf 'FAIL: detect exit C(%s)=%s Rust(%s)=%s\n' \
            "$detect_args" "$c_status" "$r_status" >&2
        exit 1
    fi
    if ! cmp -s "$TEMP/detect-c.err" "$TEMP/detect-r.err"; then
        printf 'FAIL: detect stderr (%s)\n' "$detect_args" >&2
        diff -u "$TEMP/detect-c.err" "$TEMP/detect-r.err" >&2 || true
        exit 1
    fi
    if ! cmp -s "$TEMP/detect-c.out" "$TEMP/detect-r.out"; then
        printf 'FAIL: detect stdout (%s)\n' "$detect_args" >&2
        diff -u "$TEMP/detect-c.out" "$TEMP/detect-r.out" >&2 || true
        exit 1
    fi
    exit_cases=$((exit_cases + 1))
}

check_detect_exact ""
check_detect_exact "classify"
check_detect_exact "classify 127.0.0.1:443 --bad"
check_detect_exact "classify 127.0.0.1:443 --hello both"
check_detect_exact "classify 127.0.0.1:443 --sni"
check_detect_exact "classify 127.0.0.1:443 --raw zz"
check_detect_exact "classify 127.0.0.1:443 --raw 57"
check_detect_exact "classify 127.0.0.1:443 --sni example.com --raw 5741"
check_detect_exact "classify 127.0.0.1:443 --sni example.com --control-sni example.com"
check_detect_exact "classify 127.0.0.1:443 --control-sni a --control-raw 0000"
check_detect_exact "classify 127.0.0.1:443 --sni example.com --dump-trigger"
check_detect_exact "classify 127.0.0.1:443 --sni example.com --hello legacy --dump-trigger"
check_detect_exact "classify 127.0.0.1:443 --raw 57410603 --dump-trigger"
check_detect_exact "classify 127.0.0.1:443 --raw 57 41:06-03 --dump-trigger"

# JSON и человеческий отчёт достижимой цели: точная форма полей, кроме
# длительности и текста ошибки соединения (нормализуются как в CL16).
"$DETECT" classify 127.0.0.1:1 --sni example.com --allow-loopback \
    --timeout 100 --repeats 1 --write-gap 7 --json >"$TEMP/c.json" 2>/dev/null
"$R2O_DETECT" classify 127.0.0.1:1 --sni example.com --allow-loopback \
    --timeout 100 --repeats 1 --write-gap 7 --json >"$TEMP/r.json" 2>/dev/null
python3 "$ROOT/scripts/fixtures/detect-json-normalize.py" \
    "$TEMP/c.json" "$TEMP/r.json" >"$TEMP/json.result"
grep -qx 'JSON-EQUAL' "$TEMP/json.result"

"$DETECT" classify 127.0.0.1:1 --sni example.com --allow-loopback \
    --timeout 100 --repeats 1 >"$TEMP/c.human" 2>/dev/null
"$R2O_DETECT" classify 127.0.0.1:1 --sni example.com --allow-loopback \
    --timeout 100 --repeats 1 >"$TEMP/r.human" 2>/dev/null
sed 's/ за [0-9][0-9]*ms (по / за <duration>ms (по /' "$TEMP/c.human" >"$TEMP/c.human.norm"
sed 's/ за [0-9][0-9]*ms (по / за <duration>ms (по /' "$TEMP/r.human" >"$TEMP/r.human.norm"
if ! cmp -s "$TEMP/c.human.norm" "$TEMP/r.human.norm"; then
    printf 'FAIL: detect human output\n' >&2
    diff -u "$TEMP/c.human.norm" "$TEMP/r.human.norm" >&2 || true
    exit 1
fi

printf 'triggers=%s exits=%s json=equal human=equal\n' "$trigger_cases" "$exit_cases"
printf 'PASS: C/Rust detect CLI dump-trigger/exit/JSON/human match (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
