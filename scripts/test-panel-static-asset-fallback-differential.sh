#!/bin/sh
# A25: C static_file против Rust read_asset на missing/symlink/absent ассетах.
#
# Строгая часть: существующий каталог ассетов — отсутствующий файл, симлинк
# файла и симлинк корня дают 404 в обоих.
# Extension: если каталога ассетов нет вовсе, R2O отдаёт встроенный index.html,
# а C — 404. Это явно проверяется отдельно и не входит в strict-паритет.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-panel-static-fallback.XXXXXX")
# symlink-сценарии — только на Linux-ФС, не на DrvFs.
CASES=$(mktemp -d /tmp/r2o-panel-static-cases.XXXXXX)
trap 'rm -rf -- "$TEMP" "$CASES"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -pthread \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-static-status" \
    "$ROOT/scripts/fixtures/panel_static_asset_status.c" \
    "$D2O_ROOT/panel/server.c"

mkdir -p "$CASES/missing"
mkdir -p "$CASES/symlink-file"
printf '<html>target</html>\n' > "$CASES/target.html"
ln -s "$CASES/target.html" "$CASES/symlink-file/index.html"
mkdir -p "$CASES/real-root"
printf '<html>real</html>\n' > "$CASES/real-root/index.html"
ln -s "$CASES/real-root" "$CASES/symlink-root"
ABSENT=$CASES/absent

run_strict_case() {
    name=$1
    dir=$2
    "$TEMP/d2o-static-status" "$dir" > "$TEMP/$name.c"
    grep -q '^404 not found$' "$TEMP/$name.c" || {
        echo "C не вернул 404 для $name:" >&2
        cat "$TEMP/$name.c" >&2
        exit 1
    }
    R2O_PANEL_ASSET_STATUS_DIR="$dir" \
    R2O_PANEL_ASSET_STATUS_C_TRACE="$TEMP/$name.c" \
        "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
            -p r2o-panel --test http d2o_static_asset_missing_or_symlink_returns_404 \
            -- --ignored > "$TEMP/$name.rust.trace" 2>&1
    grep -q 'test result: ok. 1 passed' "$TEMP/$name.rust.trace"
}

run_strict_case missing "$CASES/missing"
run_strict_case symlink-file "$CASES/symlink-file"
run_strict_case symlink-root "$CASES/symlink-root"

"$TEMP/d2o-static-status" "$ABSENT" > "$TEMP/absent.c"
grep -q '^404 not found$' "$TEMP/absent.c" || {
    echo "C не вернул 404 для отсутствующего каталога" >&2
    exit 1
}
R2O_PANEL_ASSET_ABSENT_DIR="$ABSENT" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-panel --test http embedded_static_assets_are_an_explicit_extension_without_asset_dir \
        -- --ignored > "$TEMP/absent.rust.trace" 2>&1
grep -q 'test result: ok. 1 passed' "$TEMP/absent.rust.trace"

printf 'PASS: C/Rust 404 for missing and symlink assets; embedded fallback only without asset dir (D2O %s)\n' "$ACTUAL_D2O_SHA"
