#!/bin/sh
set -eu
export LC_ALL=C

abi=${1:?не задан ABI}
dir=${2:?не задан каталог бинарников}
mode=${3:-}
case "$mode" in ''|--elf-only) ;; *) echo "неизвестный режим: $mode" >&2; exit 2 ;; esac
prefix=
loader=
flags=
attributes=
case "$abi" in
    mipsel)
        cpu=mipsel; class=32; endian=little; machine='MIPS R3000'
        prefix=/usr/mipsel-linux-gnu; loader=/lib/ld.so.1 ;;
    mipsel-openwrt-musl)
        cpu=mipsel; class=32; endian=little; machine='MIPS R3000'; flags=mips32r2
        loader=/lib/ld-musl-mipsel-sf.so.1
        if [ "$mode" != --elf-only ]; then
            cache=${R2O_OPENWRT_TOOLCHAIN_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/r2o/openwrt}
            sdk=${R2O_OPENWRT_MIPSEL_SDK:-"$cache/openwrt-mipsel-musl-sdk"}
            libc="$sdk/lib/libc.so"
            libgcc="$sdk/lib/libgcc_s.so.1"
            test -f "$libc" && test -f "$libgcc"
            prefix=$(mktemp -d)
            trap 'rm -rf -- "$prefix"' EXIT HUP INT TERM
            mkdir "$prefix/lib"
            ln -s "$libc" "$prefix$loader"
            ln -s "$libc" "$prefix/lib/libc.so"
            ln -s "$libgcc" "$prefix/lib/libgcc_s.so.1"
        fi ;;
    aarch64-openwrt-musl) cpu=aarch64; class=64; endian=little; machine=AArch64 ;;
    armv5-musleabi|armv7-musleabi)
        cpu=arm; class=32; endian=little; machine=ARM; flags='Version5 EABI'
        if [ "$abi" = armv5-musleabi ]; then model=arm926; else model=cortex-a7; fi ;;
    armv7-openwrt-musl)
        cpu=arm; class=32; endian=little; machine=ARM; model=cortex-a7
        flags='hard-float ABI'; attributes='Tag_ABI_VFP_args: VFP registers' ;;
    mips-openwrt-musl)
        cpu=mips; class=32; endian=big; machine='MIPS R3000'; model=24Kc
        flags=mips32r2; attributes='FP ABI: Soft float' ;;
    mips64el-musl)
        cpu=mips64el; class=64; endian=little; machine='MIPS R3000'; flags=mips64r2 ;;
    x86_64-musl) cpu=x86_64; class=64; endian=little; machine='Advanced Micro Devices X86-64' ;;
    i686-musl) cpu=i386; class=32; endian=little; machine='Intel 80386'; model=pentium3,+sse2 ;;
    powerpc64-musl) cpu=ppc64; class=64; endian=big; machine=PowerPC64; flags=abiv2 ;;
    riscv64-musl) cpu=riscv64; class=64; endian=little; machine=RISC-V; flags='double-float ABI' ;;
    *) echo "неизвестный ABI: $abi" >&2; exit 2 ;;
esac

set -- "qemu-$cpu"
if [ -n "${model:-}" ]; then
    set -- "$@" -cpu "$model"
fi
if [ -n "$prefix" ]; then
    set -- "$@" -L "$prefix"
fi

fail() {
    echo "$abi: $component: $*" >&2
    exit 1
}

for component in r2o-datapath r2o-controller r2o-panel r2o-telegram r2o-manager r2o-fetch r2o-detect; do
    bin="$dir/$component"
    test -s "$bin" && test -x "$bin" || fail 'отсутствует исполняемый файл'
    header=$(readelf -hW "$bin")
    printf '%s\n' "$header" | grep -Eq "Class:[[:space:]]+ELF$class$" || fail 'класс ELF'
    printf '%s\n' "$header" | grep -Fq "$endian endian" || fail 'порядок байт'
    printf '%s\n' "$header" | grep -Eq "Machine:[[:space:]]+$machine$" || fail 'архитектура ELF'
    if [ -n "$flags" ]; then
        printf '%s\n' "$header" | grep -Fq "$flags" || fail 'флаги ABI'
    fi
    if [ -n "$attributes" ]; then
        readelf -A "$bin" | grep -Fq "$attributes" || fail 'атрибуты ABI'
    fi
    program=$(readelf -lW "$bin")
    if [ -n "$loader" ]; then
        printf '%s\n' "$program" | grep -Fq "[Requesting program interpreter: $loader]" ||
            fail 'загрузчик ELF'
    else
        dynamic=$(readelf -dW "$bin")
        if printf '%s\n' "$program" | grep -qw INTERP ||
            printf '%s\n' "$dynamic" | grep -Fq '(NEEDED)'; then
            fail 'обнаружена динамическая зависимость'
        fi
    fi
    [ "$mode" = --elf-only ] && continue
    case "$component" in
        r2o-controller|r2o-panel) timeout 30 "$@" "$bin" --self-check ;;
        r2o-detect)
            output=$(timeout 30 "$@" "$bin" classify 127.0.0.1:443 --sni example.com --dump-trigger)
            printf '%s\n' "$output" | grep -Eq '^1603[0-9a-f]+$' || fail 'неверный TLS ClientHello'
            alias_output=$(timeout 30 "$@" -0 "r2o-detect-linux-$abi" "$dir/r2o-controller" \
                classify 127.0.0.1:443 --raw 00ff --dump-trigger)
            [ "$alias_output" = 00ff ] || fail 'режим detect в контроллере' ;;
        r2o-fetch)
            output=$(timeout 30 "$@" "$bin" --version)
            alias_output=$(timeout 30 "$@" -0 "r2o-fetch-linux-$abi" "$dir/r2o-controller" --version)
            [ "$alias_output" = "$output" ] || fail 'режим fetch в контроллере'
            printf '%s\n' "$output" ;;
        *) timeout 30 "$@" "$bin" --version ;;
    esac
done
