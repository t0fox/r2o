#!/bin/sh
# M2: paired C/Rust differential CLI d2kask vs r2o --ask (parse/exit).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/target"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-m2-ask-cli.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -s -B -C "$D2O_ROOT/core" d2kask CC="$CC" >/dev/null
D2O_BIN="$D2O_ROOT/core/d2kask"
CARGO_TARGET_DIR="$TARGET_DIR" "$CARGO" build --manifest-path "$ROOT/Cargo.toml" \
    --locked --offline -q -p r2o-controller --bin r2o-controller
R2O_BIN="$TARGET_DIR/debug/r2o-controller"

cases=0
check_case() {
    name=$1
    c_needle=$2
    r_needle=$3
    shift 3
    set +e
    "$D2O_BIN" "$@" >/dev/null 2>"$TEMP/c.err"
    c_status=$?
    "$R2O_BIN" --ask "$@" >/dev/null 2>"$TEMP/r.err"
    r_status=$?
    set -e
    if [ "$c_status" -ne 2 ] || [ "$r_status" -ne 2 ]; then
        printf 'FAIL: %s exit C=%s Rust=%s\n' "$name" "$c_status" "$r_status" >&2
        cat "$TEMP/c.err" >&2
        cat "$TEMP/r.err" >&2
        exit 1
    fi
    if ! grep -Fq -- "$c_needle" "$TEMP/c.err"; then
        printf 'FAIL: %s C stderr missing <%s>\n' "$name" "$c_needle" >&2
        cat "$TEMP/c.err" >&2
        exit 1
    fi
    if ! grep -Fq -- "$r_needle" "$TEMP/r.err"; then
        printf 'FAIL: %s Rust stderr missing <%s>\n' "$name" "$r_needle" >&2
        cat "$TEMP/r.err" >&2
        exit 1
    fi
    cases=$((cases + 1))
    printf '%s: C=%s Rust=%s\n' "$name" "$c_status" "$r_status"
}

check_case no-args 'использование' 'обязателен --control'
check_case missing-ip 'обязателен --ip' 'обязателен --ip' \
    --control "$TEMP/ctl"
check_case missing-sni 'обязателен --sni' 'обязателен --sni' \
    --control "$TEMP/ctl" --ip 127.0.0.1
check_case missing-hello 'нужен один способ' 'задайте ровно один' \
    --control "$TEMP/ctl" --ip 127.0.0.1 --sni example.com
check_case hello-exclusive 'взаимоисключающие' 'задайте ровно один' \
    --control "$TEMP/ctl" --ip 127.0.0.1 --sni example.com \
    --hello-hex "$TEMP/hello.hex" --arm-wait-ms 10
check_case control-exclusive '--control-hex и --control-sni взаимоисключающие' \
    '--control-hex и --control-sni взаимоисключающие' \
    --control "$TEMP/ctl" --ip 127.0.0.1 --sni example.com \
    --arm-wait-ms 10 --control-hex "$TEMP/control.hex" --control-sni control.example
check_case control-sni-needs-wait '--control-sni требует --arm-wait-ms' \
    '--control-sni требует --arm-wait-ms' \
    --control "$TEMP/ctl" --ip 127.0.0.1 --sni example.com \
    --hello-hex "$TEMP/hello.hex" --control-sni control.example
check_case unknown-flag 'неизвестный аргумент' 'неизвестный аргумент' \
    --bogus

printf 'cases=%s\n' "$cases"
printf 'PASS: C/Rust ask CLI parse/exit match (D2O %s)\n' "$ACTUAL_D2O_SHA"
