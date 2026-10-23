#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
NIGHTLY=nightly-2026-10-17
TARGET=aarch64-unknown-linux-musl
SDK_URL=https://downloads.openwrt.org/releases/25.12.5/targets/rockchip/armv8/openwrt-toolchain-25.12.5-rockchip-armv8_gcc-14.3.0_musl.Linux-x86_64.tar.zst
SDK_SHA256=37875a8a69b46c9dc2a8c8bfd34a14f5de03fbea775f7cf8569f7e709c93403b
CACHE=${R2O_OPENWRT_TOOLCHAIN_CACHE:-${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/r2o/openwrt}
TARGET_DIR=${R2O_OPENWRT_CARGO_TARGET_DIR:-"$ROOT/target"}

for tool in cargo rustup curl sha256sum tar zstd find readelf qemu-aarch64; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "сборка OpenWrt ARM64: не найден обязательный инструмент: $tool" >&2
        exit 1
    }
done

if ! rustup toolchain list | grep -q "^${NIGHTLY}-"; then
    rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src
elif ! rustup component list --toolchain "$NIGHTLY" --installed | grep -qx 'rust-src'; then
    rustup component add rust-src --toolchain "$NIGHTLY"
fi
if ! rustup target list --toolchain "$NIGHTLY" --installed | grep -qx "$TARGET"; then
    rustup target add --toolchain "$NIGHTLY" "$TARGET"
fi

if [ -n "${R2O_OPENWRT_AARCH64_SDK:-}" ]; then
    SDK=$R2O_OPENWRT_AARCH64_SDK
else
    mkdir -p "$CACHE"
    ARCHIVE="$CACHE/openwrt-aarch64-musl-toolchain-25.12.5.tar.zst"
    if ! printf '%s  %s\n' "$SDK_SHA256" "$ARCHIVE" | sha256sum -c --status 2>/dev/null; then
        PART="$ARCHIVE.part.$$"
        rm -f "$PART"
        curl --fail --location --silent --show-error --retry 3 --retry-all-errors \
            --proto '=https' --tlsv1.2 "$SDK_URL" -o "$PART"
        printf '%s  %s\n' "$SDK_SHA256" "$PART" | sha256sum -c --status || {
            rm -f "$PART"
            echo "сборка OpenWrt ARM64: SHA-256 SDK не совпал" >&2
            exit 1
        }
        mv -f "$PART" "$ARCHIVE"
    fi

    SDK_ROOT="$CACHE/openwrt-aarch64-musl-sdk"
    LINKER="$SDK_ROOT/bin/aarch64-openwrt-linux-musl-gcc"
    if [ ! -x "$LINKER" ]; then
        UNPACK_DIR=$(mktemp -d "$CACHE/.openwrt-aarch64-unpack.XXXXXX")
        trap 'rm -rf "$UNPACK_DIR"' EXIT HUP INT TERM
        tar --zstd -xf "$ARCHIVE" -C "$UNPACK_DIR"
        EXTRACTED_LINKER=$(find "$UNPACK_DIR" -path \
            '*/toolchain-aarch64_*_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc' \
            -print -quit)
        if [ -z "$EXTRACTED_LINKER" ] || [ ! -x "$EXTRACTED_LINKER" ]; then
            echo "сборка OpenWrt ARM64: в SDK не найден AArch64-компилятор" >&2
            exit 1
        fi
        EXTRACTED_SDK=${EXTRACTED_LINKER%/bin/aarch64-openwrt-linux-musl-gcc}
        mv "$EXTRACTED_SDK" "$SDK_ROOT"
        rm -rf "$UNPACK_DIR"
        trap - EXIT HUP INT TERM
    fi
    SDK="$SDK_ROOT"
fi

LINKER="$SDK/bin/aarch64-openwrt-linux-musl-gcc"
ARCHIVER="$SDK/bin/aarch64-openwrt-linux-musl-ar"
if [ ! -x "$LINKER" ] || [ ! -x "$ARCHIVER" ]; then
    echo "сборка OpenWrt ARM64: R2O_OPENWRT_AARCH64_SDK должен указывать на каталог toolchain" >&2
    exit 1
fi

cd "$ROOT"
CARGO_TARGET_DIR="$TARGET_DIR" \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$LINKER" \
CC_aarch64_unknown_linux_musl="$LINKER" \
AR_aarch64_unknown_linux_musl="$ARCHIVER" \
STAGING_DIR="$SDK" \
CARGO_PROFILE_RELEASE_PANIC=abort \
    cargo +"$NIGHTLY" -Z build-std=std,panic_abort build \
        --workspace --release --locked --target "$TARGET"

BIN_DIR="$TARGET_DIR/$TARGET/release"
for component in r2o-datapath r2o-controller r2o-telegram r2o-panel r2o-manager r2o-fetch; do
    BINARY="$BIN_DIR/$component"
    [ -x "$BINARY" ] || {
        echo "сборка OpenWrt ARM64: не создан исполняемый файл $component" >&2
        exit 1
    }
    readelf -h "$BINARY" | grep -q 'little endian' || {
        echo "сборка OpenWrt ARM64: $component не является ARM64 ELF" >&2
        exit 1
    }
    readelf -h "$BINARY" | grep -q 'AArch64' || {
        echo "сборка OpenWrt ARM64: $component собран не для AArch64" >&2
        exit 1
    }
    if readelf -l "$BINARY" | grep -Fq 'Requesting program interpreter'; then
        echo "сборка OpenWrt ARM64: $component должен быть статически связан с musl" >&2
        exit 1
    fi
    if readelf -d "$BINARY" 2>/dev/null | grep -Fq '(NEEDED)'; then
        echo "сборка OpenWrt ARM64: $component содержит динамическую зависимость" >&2
        exit 1
    fi
    qemu-aarch64 -L "$SDK" "$BINARY" --version
done

SMOKE_DIR=$(mktemp -d)
trap 'rm -rf "$SMOKE_DIR"' EXIT HUP INT TERM
printf '{"schema":1,"boxes":[{"id":"smoke"}]}\n' > "$SMOKE_DIR/catalog.json"
qemu-aarch64 -L "$SDK" "$BIN_DIR/r2o-controller" --clear-catalog "$SMOKE_DIR/catalog.json"
qemu-aarch64 -L "$SDK" "$BIN_DIR/r2o-controller" --check-catalog "$SMOKE_DIR/catalog.json"
rm -rf "$SMOKE_DIR"
trap - EXIT HUP INT TERM

(cd "$BIN_DIR" && sha256sum r2o-datapath r2o-controller r2o-telegram r2o-panel r2o-manager r2o-fetch >SHA256SUMS)
(cd "$BIN_DIR" && sha256sum -c SHA256SUMS)
