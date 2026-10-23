#!/usr/bin/env bash
set -eu

sysroot=$(rustc --print sysroot)
host=$(rustc -vV | sed -n 's/^host: //p')
linker_dir="$sysroot/lib/rustlib/$host/bin/gcc-ld"
if [ ! -x "$linker_dir/ld.lld" ]; then
    echo "Rust LLD was not found under $linker_dir" >&2
    exit 1
fi

args=()
for arg in "$@"; do
    if [ "$arg" = "-no-pie" ]; then
        # Clang diagnoses -no-pie as unused for this cross target. Pass it to
        # LLD directly so Rust still gets the same non-PIE executable.
        args+=("-Wl,-no-pie")
    else
        args+=("$arg")
    fi
done

exec clang-18 --target=armv5te-unknown-linux-musleabi -mcpu=arm926ej-s \
    -B"$linker_dir" -fuse-ld=lld "${args[@]}"
