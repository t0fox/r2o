#!/bin/sh
set -eu

sysroot=$(rustc --print sysroot)
host=$(rustc -vV | sed -n 's/^host: //p')
linker_dir="$sysroot/lib/rustlib/$host/bin/gcc-ld"
if [ ! -x "$linker_dir/ld.lld" ]; then
    echo "Rust LLD was not found under $linker_dir" >&2
    exit 1
fi

exec clang-18 --target=aarch64-linux-gnu --gcc-toolchain=/usr \
    -B"$linker_dir" -fuse-ld=lld "$@"
