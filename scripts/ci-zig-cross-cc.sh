#!/bin/sh
set -eu

test -n "$ZIG" || { echo 'setup-zig action must set ZIG' >&2; exit 1; }
test -n "$ZIG_TARGET" || { echo 'set ZIG_TARGET to the Zig target triple' >&2; exit 1; }

# cc-rs passes the Rust target spelling, which Zig does not always accept.
if [ -n "${ZIG_SYSROOT:-}" ]; then
    set -- "$@" "--sysroot=$ZIG_SYSROOT"
fi
if [ "${R2O_ZIG_LINKER:-}" = 1 ]; then
    # build-std передаёт каталог готового std даже для целей без такого каталога.
    # LLD из Zig также сообщает об устаревшем флаге GNU ld -O1.
    remaining=$#
    while [ "$remaining" -gt 0 ]; do
        arg=$1
        shift
        remaining=$((remaining - 1))
        case "$arg" in
            -L)
                case "${1:-}" in
                    */lib/rustlib/*/lib)
                        if [ "$remaining" -gt 0 ] && [ ! -d "$1" ]; then
                            shift
                            remaining=$((remaining - 1))
                            continue
                        fi ;;
                esac ;;
            -Wl,-O1) continue ;;
            -Wl,-melf_i386)
                # Zig выбирает ELF i386 из -target и отвергает параметр GNU ld.
                [ "$ZIG_TARGET" != x86-linux-musl ] || continue ;;
        esac
        set -- "$@" "$arg"
    done
fi

if [ -n "${ZIG_CPU:-}" ]; then
    set -- "$@" "-mcpu=$ZIG_CPU"
fi
if [ -n "${R2O_MIPSEL_LINK_MAPS:-}" ]; then
    next_output=no
    for argument do
        if [ "$next_output" = yes ]; then
            output_name=${argument##*/}
            case "$output_name" in
                r2o_controller-*|r2o_datapath-*|r2o_panel-*|r2o_telegram-*|r2o_manager-*|r2o_fetch-*|r2o_detect-*)
                    set -- "$@" "-Wl,-Map,$R2O_MIPSEL_LINK_MAPS/$output_name.map" ;;
            esac
            break
        fi
        [ "$argument" != -o ] || next_output=yes
    done
fi
exec "$ZIG" cc "$@" -target "$ZIG_TARGET"
