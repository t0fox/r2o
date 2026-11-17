#!/bin/sh
# C/Rust differential: справка датапата (`usage`, datapath/d2kd.c:834-861).
#
# Общие флаги и умолчания должны быть напечатаны теми же словами, что C.
# Дополнительные флаги R2O идут отдельной секцией и проверяются на наличие.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CC=${CC:-cc}
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-datapath-usage.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -B -C "$DONOR/datapath" d2kd CC="$CC" >/dev/null
cargo build --locked -p r2o-datapath --bin r2o-datapath >/dev/null
R2O_BIN="$ROOT/target/debug/r2o-datapath"

# C `usage()` печатает в stderr и завершается с ошибкой.
"$DONOR/datapath/d2kd" --help >"$TEMP/c.out" 2>&1 || true
"$R2O_BIN" --help >"$TEMP/r.out" 2>&1

# C-блок: от заголовка до финальной фразы включительно. Имя программы
# нормализуется: бинарь R2O называется иначе.
sed -e 's/^d2kd — /r2o-datapath — /' \
    -e '/^Без --mode apply служба ничего не меняет в трафике\.$/q' \
    "$TEMP/c.out" >"$TEMP/c.block"

# Rust-блок: всё до секции дополнительных флагов R2O, без хвостовых
# пустых строк.
awk '/^Дополнительные параметры R2O:$/{exit} {print}' "$TEMP/r.out" >"$TEMP/r.raw"
awk 'NF {last = NR} {line[NR] = $0} END {for (i = 1; i <= last; i++) print line[i]}' \
    "$TEMP/r.raw" >"$TEMP/r.block"

diff -u "$TEMP/c.block" "$TEMP/r.block"

for flag in --plan --controller-only --r2o-flow-capacity --r2o-udp-reverse-visible \
    --family --health-file --rcvbuf --control-wire --control-release-id --check \
    --version --help; do
    grep -F -- "$flag" "$TEMP/r.out" >/dev/null || {
        printf 'FAIL: R2O help does not list %s\n' "$flag" >&2
        exit 1
    }
done

printf 'PASS: datapath usage matches C for shared flags (%s)\n' "$ACTUAL_SHA"
