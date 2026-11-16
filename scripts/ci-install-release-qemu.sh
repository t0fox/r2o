#!/bin/sh
set -eu

dest=${1:?не задан каталог QEMU}
mkdir -p "$dest/bin"
pkg=qemu-user-static-11.1.3-1-x86_64.pkg.tar.zst
sha=2cc771423fa4c38d4f557dddf29d15c082a156f71e4f7af498318dbb7bd6b775
curl --fail --proto '=https' --location --retry 3 --retry-all-errors --max-time 300 \
    "https://geo.mirror.pkgbuild.com/extra/os/x86_64/$pkg" -o "$dest/$pkg"
printf '%s  %s\n' "$sha" "$dest/$pkg" | sha256sum -c
tar --zstd -xf "$dest/$pkg" -C "$dest"
for cpu in aarch64 arm mips mipsel mips64el ppc64 riscv64 i386 x86_64; do
    ln -sf "../usr/bin/qemu-$cpu-static" "$dest/bin/qemu-$cpu"
done
