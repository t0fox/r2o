#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
NIGHTLY=nightly-2026-10-17
TARGET=mipsel-unknown-linux-gnu
LINKER=${MIPSEL_LINUX_GNU_LINKER:-mipsel-linux-gnu-gcc}

command -v "$LINKER" >/dev/null 2>&1 || {
    echo "не найден компоновщик MIPS: $LINKER" >&2
    exit 1
}
rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src

cd "$ROOT"
CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_GNU_LINKER="$LINKER" \
    cargo +"$NIGHTLY" -Z build-std=std,panic_abort build \
    --workspace --release --locked --target "$TARGET"


(cd "target/$TARGET/release" && sha256sum r2o-datapath r2o-controller r2o-telegram r2o-panel r2o-manager r2o-fetch >SHA256SUMS)
