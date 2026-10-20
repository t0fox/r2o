#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
NIGHTLY=nightly-2026-10-17
TARGET=mipsel-unknown-linux-musl
SDK_URL=https://downloads.openwrt.org/releases/25.12.5/targets/malta/le/openwrt-toolchain-25.12.5-malta-le_gcc-14.3.0_musl.Linux-x86_64.tar.zst
SDK_SHA256=5a02d679c1ff052745b419b564624380dd3e5f6218db64c65b8ec9df56e2c263
CACHE=${R2O_OPENWRT_TOOLCHAIN_CACHE:-${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/r2o/openwrt}
TARGET_DIR=${R2O_OPENWRT_CARGO_TARGET_DIR:-"$ROOT/target"}

for tool in cargo rustup curl sha256sum tar zstd find readelf qemu-mipsel; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "сборка OpenWrt: не найден обязательный инструмент: $tool" >&2
        exit 1
    }
done

if ! rustup toolchain list | grep -q "^${NIGHTLY}-"; then
    rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src
elif ! rustup component list --toolchain "$NIGHTLY" --installed | grep -qx 'rust-src'; then
    rustup component add rust-src --toolchain "$NIGHTLY"
fi

if [ -n "${R2O_OPENWRT_MIPSEL_SDK:-}" ]; then
    SDK=$R2O_OPENWRT_MIPSEL_SDK
else
    mkdir -p "$CACHE"
    ARCHIVE="$CACHE/openwrt-mipsel-musl-toolchain-25.12.5.tar.zst"
    if ! printf '%s  %s\n' "$SDK_SHA256" "$ARCHIVE" | sha256sum -c --status 2>/dev/null; then
        PART="$ARCHIVE.part.$$"
        rm -f "$PART"
        curl --fail --location --silent --show-error --retry 3 --retry-all-errors \
            --proto '=https' --tlsv1.2 "$SDK_URL" -o "$PART"
        printf '%s  %s\n' "$SDK_SHA256" "$PART" | sha256sum -c --status || {
            rm -f "$PART"
            echo "сборка OpenWrt: SHA-256 SDK не совпал" >&2
            exit 1
        }
        mv -f "$PART" "$ARCHIVE"
    fi

    SDK_ROOT="$CACHE/openwrt-mipsel-musl-sdk"
    LINKER="$SDK_ROOT/bin/mipsel-openwrt-linux-musl-gcc"
    if [ ! -x "$LINKER" ]; then
        UNPACK_DIR=$(mktemp -d "$CACHE/.openwrt-mipsel-unpack.XXXXXX")
        trap 'rm -rf "$UNPACK_DIR"' EXIT HUP INT TERM
        tar --zstd -xf "$ARCHIVE" -C "$UNPACK_DIR"
        EXTRACTED_LINKER=$(find "$UNPACK_DIR" -path \
            '*/toolchain-mipsel_24kc_gcc-14.3.0_musl/bin/mipsel-openwrt-linux-musl-gcc' \
            -print -quit)
        [ -n "$EXTRACTED_LINKER" ] && [ -x "$EXTRACTED_LINKER" ] || {
            echo "сборка OpenWrt: в SDK не найден MIPS little-endian компилятор" >&2
            exit 1
        }
        EXTRACTED_SDK=${EXTRACTED_LINKER%/bin/mipsel-openwrt-linux-musl-gcc}
        mv "$EXTRACTED_SDK" "$SDK_ROOT"
        rm -rf "$UNPACK_DIR"
        trap - EXIT HUP INT TERM
    fi
    SDK="$SDK_ROOT"
fi

LINKER="$SDK/bin/mipsel-openwrt-linux-musl-gcc"
ARCHIVER="$SDK/bin/mipsel-openwrt-linux-musl-ar"
if [ ! -x "$LINKER" ] || [ ! -x "$ARCHIVER" ]; then
    echo "сборка OpenWrt: путь R2O_OPENWRT_MIPSEL_SDK должен указывать на каталог toolchain" >&2
    exit 1
fi

cd "$ROOT"
CARGO_TARGET_DIR="$TARGET_DIR" \
CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER="$LINKER" \
CC_mipsel_unknown_linux_musl="$LINKER" \
AR_mipsel_unknown_linux_musl="$ARCHIVER" \
CARGO_PROFILE_RELEASE_PANIC=abort \
    cargo +"$NIGHTLY" -Z build-std=std,panic_abort build \
        --workspace --release --locked --offline --target "$TARGET"

BIN_DIR="$TARGET_DIR/$TARGET/release"
for component in r2o-datapath r2o-controller r2o-telegram r2o-panel r2o-manager; do
    BINARY="$BIN_DIR/$component"
    [ -x "$BINARY" ] || {
        echo "сборка OpenWrt: не создан исполняемый файл $component" >&2
        exit 1
    }
    readelf -h "$BINARY" | grep -q 'little endian' || {
        echo "сборка OpenWrt: $component не является MIPS little-endian ELF" >&2
        exit 1
    }
    readelf -h "$BINARY" | grep -q 'mips32r2' || {
        echo "сборка OpenWrt: $component собран не для MIPS32r2" >&2
        exit 1
    }
    readelf -l "$BINARY" | grep -Fq '[Requesting program interpreter: /lib/ld-musl-mipsel-sf.so.1]' || {
        echo "сборка OpenWrt: у $component неверный musl-загрузчик" >&2
        exit 1
    }
    qemu-mipsel -L "$SDK" "$BINARY" --version
done

SMOKE_DIR=$(mktemp -d)
trap 'rm -rf "$SMOKE_DIR"' EXIT HUP INT TERM
printf '{"schema":1,"boxes":[{"id":"smoke"}]}\n' > "$SMOKE_DIR/catalog.json"
qemu-mipsel -L "$SDK" "$BIN_DIR/r2o-controller" --clear-catalog "$SMOKE_DIR/catalog.json"
qemu-mipsel -L "$SDK" "$BIN_DIR/r2o-controller" --check-catalog "$SMOKE_DIR/catalog.json"
rm -rf "$SMOKE_DIR"
trap - EXIT HUP INT TERM

(cd "$BIN_DIR" && sha256sum r2o-datapath r2o-controller r2o-telegram r2o-panel r2o-manager >SHA256SUMS)
(cd "$BIN_DIR" && sha256sum -c SHA256SUMS)
