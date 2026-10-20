#!/bin/sh
set -eu

BUILDS=${1:?использование: package-release.sh КАТАЛОГ_СБОРКИ КАТАЛОГ_ВЫПУСКА [АРХИТЕКТУРЫ]}
OUT=${2:?использование: package-release.sh КАТАЛОГ_СБОРКИ КАТАЛОГ_ВЫПУСКА [АРХИТЕКТУРЫ]}
: "${RELEASE_ID:?не задан идентификатор выпуска RELEASE_ID}"
: "${VERSION:?не задана версия выпуска VERSION}"
NOTES=${NOTES:-}
ARCHES=${3:-mipsel}
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)

case "$RELEASE_ID" in
    r2o-[A-Za-z0-9._-]*) ;;
    *) echo "небезопасный идентификатор выпуска RELEASE_ID" >&2; exit 1 ;;
esac
case "$RELEASE_ID" in *[!A-Za-z0-9._-]*) echo "небезопасный идентификатор выпуска RELEASE_ID" >&2; exit 1 ;; esac
ARCHES_SAFE=$(printf '%s' "$ARCHES" | tr -d ' ')
case "$ARCHES_SAFE" in *[!A-Za-z0-9_-]*) echo "небезопасный список архитектур выпуска" >&2; exit 1 ;; esac

set -- $ARCHES
[ "$#" -gt 0 ] || { echo "список архитектур выпуска пуст" >&2; exit 1; }
ARCH_COUNT=$#
SEEN_ARCHES=" "

mkdir -p "$OUT"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
ASSETS="$WORK/assets.tsv"
: > "$ASSETS"

for ARCH do
    case "$ARCH" in
        mipsel|mipsel-openwrt-musl) ;;
        *) echo "неподдерживаемая архитектура выпуска: $ARCH" >&2; exit 1 ;;
    esac
    case "$SEEN_ARCHES" in *" $ARCH "*) echo "архитектура выпуска повторена: $ARCH" >&2; exit 1 ;; esac
    SEEN_ARCHES="$SEEN_ARCHES$ARCH "

    SOURCE_BUILDS=$BUILDS
    if [ "$ARCH_COUNT" -gt 1 ]; then
        SOURCE_BUILDS="$BUILDS/$ARCH"
    fi
    STAGE="$WORK/$ARCH"
    mkdir -p "$STAGE/builds" "$STAGE/router"
    for component in r2o-datapath r2o-controller r2o-panel r2o-telegram r2o-manager; do
        source="$SOURCE_BUILDS/$component-linux-$ARCH"
        test -f "$source" && test -s "$source" || {
            echo "не найден исполняемый файл выпуска: $source" >&2
            exit 1
        }
        test ! -L "$source" || {
            echo "исполняемый файл выпуска не должен быть символической ссылкой: $source" >&2
            exit 1
        }
        install -m 0755 "$source" "$STAGE/builds/"
    done
    for file in S99r2o S99r2o.shim r2o-firewall.sh r2o-tg-firewall.sh r2o-update-scheduler.sh openwrt-init config.default install.sh; do
        source="$ROOT/router/$file"
        test -f "$source" && test ! -L "$source" || {
            echo "файл адаптера роутера отсутствует или небезопасен: $source" >&2
            exit 1
        }
        mode=0644
        case "$file" in S99r2o|S99r2o.shim|r2o-firewall.sh|r2o-tg-firewall.sh|r2o-update-scheduler.sh|openwrt-init|install.sh) mode=0755 ;; esac
        install -m "$mode" "$source" "$STAGE/router/$file"
    done

    archive="$OUT/r2o-$ARCH.tar.gz"
    tar -czf "$archive" -C "$STAGE" builds router
    digest=$(sha256sum "$archive" | cut -d ' ' -f 1)
    archive_size=$(wc -c < "$archive" | tr -d ' ')
    [ "$archive_size" -le 268435456 ] || {
        echo "архив выпуска превышает ограничение менеджера в 256 МиБ: $ARCH" >&2
        exit 1
    }
    printf '%s\t%s\n' "$ARCH" "$digest" >> "$ASSETS"
    printf 'собран выпуск %s (%s)\n' "$RELEASE_ID" "$ARCH"
done

python3 - "$RELEASE_ID" "$VERSION" "$NOTES" "$ASSETS" "$OUT/latest.json" <<'PY'
import json
import sys

release_id, version, notes, assets_path, manifest_path = sys.argv[1:]
if not release_id or len(release_id.encode("utf-8")) > 128:
    raise SystemExit("идентификатор выпуска должен занимать от 1 до 128 байт")
if not version or len(version.encode("utf-8")) > 128 or "\0" in version:
    raise SystemExit("версия должна занимать от 1 до 128 байт без нулевого байта")
if len(notes.encode("utf-8")) > 4096 or "\0" in notes:
    raise SystemExit("заметки выпуска должны занимать не более 4096 байт без нулевого байта")

assets = {}
with open(assets_path, encoding="utf-8") as records:
    for record in records:
        architecture, digest = record.rstrip("\n").split("\t")
        if architecture in assets:
            raise SystemExit(f"архитектура выпуска повторена: {architecture}")
        assets[architecture] = {"sha256": digest}

with open(manifest_path, "w", encoding="utf-8", newline="\n") as manifest:
    json.dump(
        {
            "release_id": release_id,
            "version": version,
            "notes": notes,
            "assets": assets,
        },
        manifest,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    manifest.write("\n")
PY
