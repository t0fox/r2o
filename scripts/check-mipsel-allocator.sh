#!/bin/sh
set -eu
export LC_ALL=C
dir=${1:?не задан каталог бинарников}
maps=${2:?не задан каталог карт линковки}

for component in r2o-controller r2o-datapath r2o-panel r2o-telegram r2o-manager r2o-fetch r2o-detect; do
    binary="$dir/$component"
    readelf -hW "$binary" >/dev/null
    prefix=$(printf '%s' "$component" | tr - _)
    set -- "$maps"/"$prefix"-*.map
    if [ "$#" != 1 ] || [ ! -s "$1" ]; then
        echo "$component: нужна одна карта линковки ELF" >&2
        exit 1
    fi
    if ! grep -Eq '[[:space:]]__malloc_context$' "$1" ||
        ! grep -Eq '[[:space:]]__libc_malloc_impl$' "$1" ||
        grep -qi SmpAllocator "$1"; then
        echo "$component: в итоговых секциях ELF не подтверждён mallocng" >&2
        grep -E 'malloc|calloc|realloc|SmpAllocator' "$1" >&2 || :
        exit 1
    fi
    printf '%s: musl mallocng\n' "$component"
done
