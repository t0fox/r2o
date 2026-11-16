#!/bin/sh
# DT-CLI-OUTPUT: r2o-detect обязан попасть в release-артефакт и сохранить
# C-совместимые JSON/human/exit уже после упаковки и распаковки.
#
# Собираются host-release бинарники r2o-controller/r2o-detect, упаковываются
# package-release.sh под именем mipsel (проверяется форма архива, не ELF:
# кросс-ABI проверяется отдельными release-джобами) и запускаются из
# распакованного архива. C-оракул — закреплённый D2O a378.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-/mnt/e/d2o-a378w}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP=$(mktemp -d "$TMPDIR/r2o-detect-artifact.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
BUILDS="$TEMP/builds"
OUT="$TEMP/out"
UNPACK="$TEMP/unpack"
mkdir -p "$BUILDS" "$OUT" "$UNPACK"

"$CARGO" build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    --release -q -p r2o-controller --bin r2o-controller --bin r2o-detect

for component in r2o-datapath r2o-panel r2o-telegram r2o-manager r2o-fetch; do
    printf '%s fixture\n' "$component" >"$BUILDS/$component-linux-mipsel"
done
install -m 0755 "$ROOT/target/release/r2o-controller" \
    "$BUILDS/r2o-controller-linux-mipsel"
install -m 0755 "$ROOT/target/release/r2o-detect" \
    "$BUILDS/r2o-detect-linux-mipsel"

RELEASE_ID=r2o-detect-artifact VERSION=0.1.0 NOTES='detect artifact test' \
    sh "$ROOT/scripts/package-release.sh" "$BUILDS" "$OUT" mipsel

tar -xzf "$OUT/r2o-mipsel.tar.gz" -C "$UNPACK"
DETECT="$UNPACK/builds/r2o-detect-linux-mipsel"
CONTROLLER="$UNPACK/builds/r2o-controller-linux-mipsel"
test -x "$DETECT" || { echo "r2o-detect отсутствует или не исполняется в release-артефакте" >&2; exit 1; }
test -x "$CONTROLLER" || { echo "r2o-controller отсутствует в release-артефакте" >&2; exit 1; }

R2O_CONTROLLER_BIN="$CONTROLLER" \
R2O_DETECT_BIN="$DETECT" \
R2O_DONOR_ROOT="$D2O_ROOT" \
    sh "$ROOT/scripts/test-controller-detect-cli-differential.sh"

printf 'PASS: packaged r2o-detect C/Rust JSON/human/exit match (D2O %s).\n' \
    "$ACTUAL_D2O_SHA"
