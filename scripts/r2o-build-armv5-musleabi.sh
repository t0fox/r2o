#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
TARGET=armv5te-unknown-linux-musleabi
TARGET_DIR=${R2O_ARMV5_CARGO_TARGET_DIR:-"$ROOT/target"}
LINKER=${R2O_ARMV5_LINKER:-arm-linux-gnueabi-gcc}
ARCHIVER=${R2O_ARMV5_AR:-arm-linux-gnueabi-ar}

for tool in cargo rustup "$LINKER" "$ARCHIVER" qemu-arm readelf sha256sum grep mktemp; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "сборка ARMv5: не найден обязательный инструмент: $tool" >&2
        exit 1
    }
done

cd "$ROOT"
if ! rustup target list --installed | grep -qx "$TARGET"; then
    rustup target add "$TARGET"
fi

CARGO_TARGET_DIR="$TARGET_DIR" \
CARGO_TARGET_ARMV5TE_UNKNOWN_LINUX_MUSLEABI_LINKER="$LINKER" \
CC_armv5te_unknown_linux_musleabi="$LINKER" \
AR_armv5te_unknown_linux_musleabi="$ARCHIVER" \
    cargo build --workspace --release --locked --target "$TARGET"

BIN_DIR="$TARGET_DIR/$TARGET/release"
set -- r2o-datapath r2o-controller r2o-telegram r2o-panel r2o-manager r2o-fetch
for component do
    BINARY="$BIN_DIR/$component"
    [ -x "$BINARY" ] || {
        echo "сборка ARMv5: не создан исполняемый файл $component" >&2
        exit 1
    }
    readelf -h "$BINARY" | grep -Fq 'little endian' || {
        echo "сборка ARMv5: $component не является ARM little-endian ELF" >&2
        exit 1
    }
    readelf -h "$BINARY" | grep -Eq 'Machine:[[:space:]]+ARM$' || {
        echo "сборка ARMv5: $component собран не для ARM" >&2
        exit 1
    }
    readelf -h "$BINARY" | grep -Fq 'Version5 EABI' || {
        echo "сборка ARMv5: $component собран не с ABI EABI5" >&2
        exit 1
    }
    if readelf -l "$BINARY" | grep -Fq 'INTERP'; then
        echo "сборка ARMv5: $component зависит от динамического загрузчика" >&2
        exit 1
    fi
    qemu-arm "$BINARY" --version
done

SMOKE_DIR=$(mktemp -d)
trap 'rm -rf "$SMOKE_DIR"' EXIT HUP INT TERM
printf '{"schema":1,"boxes":[{"id":"smoke"}]}\n' > "$SMOKE_DIR/catalog.json"
qemu-arm "$BIN_DIR/r2o-controller" --clear-catalog "$SMOKE_DIR/catalog.json"
qemu-arm "$BIN_DIR/r2o-controller" --check-catalog "$SMOKE_DIR/catalog.json"
rm -rf "$SMOKE_DIR"
trap - EXIT HUP INT TERM

(cd "$BIN_DIR" && sha256sum "$@" >SHA256SUMS)
(cd "$BIN_DIR" && sha256sum -c SHA256SUMS)
