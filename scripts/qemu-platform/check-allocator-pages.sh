#!/bin/sh
set -eu

page=${1:?ожидаемый размер страниц}
: "${ZIG:?нужен Zig 0.15.2}"
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
test "$("$ZIG" version)" = 0.15.2

src="$root/scripts/qemu-platform/allocator-retention.c"
case "$page" in
    4096)
        "$ZIG" cc -target x86_64-linux-musl -static -O2 -DEXPECTED_PAGE_SIZE=4096 "$src" -o "$work/test"
        "$work/test"
        ;;
    16384)
        # Use the signed Debian ARM64 kernel package and boot an actual 16 KiB guest.
        docker run --rm --volume "$work:/work" debian:trixie-slim sh -euc '
            dpkg --add-architecture arm64
            apt-get update -qq
            image=$(apt-cache depends linux-image-arm64-16k:arm64 |
                sed -n "s/^ *Depends: \(linux-image-[0-9][^ ]*arm64-16k\)\(:arm64\)\?$/\1/p" |
                head -n 1)
            test -n "$image"
            cd /work
            apt-get download "$image:arm64"
            dpkg-deb --fsys-tarfile ./*.deb | tar -xf - --wildcards "./boot/vmlinuz-*"
        '
        mkdir -p "$work/initramfs/proc"
        "$ZIG" cc -target aarch64-linux-musl -static -O2 -DEXPECTED_PAGE_SIZE=16384 "$src" -o "$work/initramfs/init"
        (cd "$work/initramfs" && find . -print | cpio -o -H newc) > "$work/initramfs.cpio"
        status=0
        timeout 150 qemu-system-aarch64 -machine virt -cpu max -m 256M \
            -nographic -nodefaults -serial stdio -no-reboot -kernel "$work"/boot/vmlinuz-* \
            -initrd "$work/initramfs.cpio" -append 'console=ttyAMA0 rdinit=/init panic=1 quiet' \
            > "$work/console.log" 2>&1 || status=$?
        cat "$work/console.log"
        test "$status" = 0
        grep -F "R2O_ALLOCATOR_OK page=$page " "$work/console.log"
        ;;
    *)
        echo "неподдерживаемый размер страницы: $page" >&2
        exit 2
        ;;
esac
