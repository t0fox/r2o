#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
NIGHTLY=nightly-2026-10-17
STABLE=1.98.0
ABI=${ABI:?не задан ABI сборки}
case "$ABI" in
    armv7-musleabi) TARGET=armv7-unknown-linux-musleabi; ZIG_TARGET=arm-linux-musleabi; ZIG_CPU=generic+v7a ;;
    mips-openwrt-musl) TARGET=mips-unknown-linux-musl; ZIG_TARGET=mips-linux-musleabi; ZIG_CPU=mips32r2+soft_float ;;
    mips64el-musl) TARGET=mips64el-unknown-linux-muslabi64; ZIG_TARGET=mips64el-linux-muslabi64; ZIG_CPU=mips64r2 ;;
    x86_64-musl) TARGET=x86_64-unknown-linux-musl; ZIG_TARGET=x86_64-linux-musl; ZIG_CPU=x86_64 ;;
    i686-musl) TARGET=i686-unknown-linux-musl; ZIG_TARGET=x86-linux-musl; ZIG_CPU=i686 ;;
    powerpc64-musl) TARGET=powerpc64-unknown-linux-musl; ZIG_TARGET=powerpc64-linux-musl; ZIG_CPU=ppc64 ;;
    riscv64-musl) TARGET=riscv64gc-unknown-linux-musl; ZIG_TARGET=riscv64-linux-musl; ZIG_CPU=generic_rv64+m+a+f+d+c ;;
    *) echo "неподдерживаемый статический ABI: $ABI" >&2; exit 2 ;;
esac

: "${ZIG:?не задан путь к Zig}"
cd "$ROOT"
target_env=$(printf '%s' "$TARGET" | tr '-' '_')
cargo_target_env=$(printf '%s' "$target_env" | tr '[:lower:]' '[:upper:]')
cc="$ROOT/scripts/ci-zig-cross-cc.sh"
export ZIG_TARGET ZIG_CPU R2O_ZIG_LINKER=1
export "CC_$target_env=$cc"
export "CARGO_TARGET_${cargo_target_env}_LINKER=$cc"
export "CARGO_TARGET_${cargo_target_env}_RUSTFLAGS=-Ctarget-feature=+crt-static -Clink-self-contained=no -Crelocation-model=static"
export CARGO_PROFILE_RELEASE_PANIC=abort
case "$ABI" in
    mips-openwrt-musl|mips64el-musl)
        if ! rustup component list --toolchain "$NIGHTLY" --installed 2>/dev/null | grep -qx rust-src; then
            rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src
        fi
        cargo +"$NIGHTLY" -Z build-std=std,panic_abort build --workspace --release --locked --target "$TARGET"
        ;;
    *)
        if ! rustup run "$STABLE" rustc --version >/dev/null 2>&1; then
            rustup toolchain install "$STABLE" --profile minimal
        fi
        rustup target add --toolchain "$STABLE" "$TARGET"
        cargo +"$STABLE" build --workspace --release --locked --target "$TARGET"
        ;;
esac
