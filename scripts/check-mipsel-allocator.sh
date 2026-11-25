#!/bin/sh
set -eu
export LC_ALL=C
dir=${1:?не задан каталог бинарников}

for component in r2o-controller r2o-datapath r2o-panel r2o-telegram r2o-manager r2o-fetch r2o-detect; do
    symbols=$(readelf -sW "$dir/$component")
    for symbol in malloc free __libc_malloc_impl __malloc_context; do
        if ! printf '%s\n' "$symbols" | awk -v name="$symbol" '$7 != "UND" && $8 == name { found = 1 } END { exit !found }'; then
            echo "$component: отсутствует символ mallocng $symbol" >&2
            exit 1
        fi
    done
    if printf '%s\n' "$symbols" | grep -qi SmpAllocator; then
        echo "$component: обнаружен Zig SmpAllocator" >&2
        exit 1
    fi
    printf '%s: musl mallocng\n' "$component"
done
