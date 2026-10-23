#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
NIGHTLY=nightly-2026-10-17
TARGET=mipsel-unknown-linux-gnu
LINKER=${MIPSEL_LINUX_GNU_LINKER:-mipsel-linux-gnu-gcc}
SYSROOT=${MIPSEL_LINUX_GNU_SYSROOT:-/usr/mipsel-linux-gnu}

command -v "$LINKER" >/dev/null 2>&1 || {
    echo "не найден компоновщик MIPS: $LINKER" >&2
    exit 1
}
rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src

cd "$ROOT"
CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_GNU_LINKER="$LINKER" \
    cargo +"$NIGHTLY" -Z build-std=std,panic_abort build \
    --workspace --release --locked --target "$TARGET"

if command -v qemu-mipsel >/dev/null 2>&1; then
    qemu-mipsel -L "$SYSROOT" "target/$TARGET/release/r2o-datapath" --version
    qemu-mipsel -L "$SYSROOT" "target/$TARGET/release/r2o-controller" --version
    qemu-mipsel -L "$SYSROOT" "target/$TARGET/release/r2o-telegram" --version
    qemu-mipsel -L "$SYSROOT" "target/$TARGET/release/r2o-panel" --version
    qemu-mipsel -L "$SYSROOT" "target/$TARGET/release/r2o-manager" --version
    qemu-mipsel -L "$SYSROOT" "target/$TARGET/release/r2o-fetch" --version
    MIPS_SMOKE_DIR=$(mktemp -d)
    trap 'rm -rf "$MIPS_SMOKE_DIR"' EXIT HUP INT TERM
    printf '{"schema":1,"boxes":[{"id":"smoke"}]}\n' > "$MIPS_SMOKE_DIR/catalog.json"
    qemu-mipsel -L "$SYSROOT" "target/$TARGET/release/r2o-controller" \
        --clear-catalog "$MIPS_SMOKE_DIR/catalog.json"
    qemu-mipsel -L "$SYSROOT" "target/$TARGET/release/r2o-controller" \
        --check-catalog "$MIPS_SMOKE_DIR/catalog.json"
    rm -rf "$MIPS_SMOKE_DIR"
    trap - EXIT HUP INT TERM
fi

(cd "target/$TARGET/release" && sha256sum r2o-datapath r2o-controller r2o-telegram r2o-panel r2o-manager r2o-fetch >SHA256SUMS)
