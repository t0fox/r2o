#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/builds" "$TEMP/out"
for component in r2o-datapath r2o-controller r2o-panel r2o-telegram r2o-manager; do
    printf '%s\n' "$component fixture" > "$TEMP/builds/$component-linux-mipsel"
done
RELEASE_ID=r2o-test VERSION=0.1.0 NOTES='fixture release' \
    sh "$ROOT/scripts/package-release.sh" "$TEMP/builds" "$TEMP/out"
tar -tzf "$TEMP/out/r2o-mipsel.tar.gz" | sort > "$TEMP/entries"
printf '%s\n' \
    builds/ \
    builds/r2o-manager-linux-mipsel \
    builds/r2o-controller-linux-mipsel \
    builds/r2o-datapath-linux-mipsel \
    builds/r2o-panel-linux-mipsel \
    builds/r2o-telegram-linux-mipsel \
    router/ \
    router/S99r2o \
    router/S99r2o.shim \
    router/config.default \
    router/install.sh \
    router/openwrt-init \
    router/r2o-firewall.sh \
    router/r2o-tg-firewall.sh \
    router/r2o-update-scheduler.sh | sort > "$TEMP/expected"
cmp "$TEMP/expected" "$TEMP/entries"
python3 - "$TEMP/out/latest.json" "$TEMP/out/r2o-mipsel.tar.gz" <<'PY'
import hashlib
import json
import sys

with open(sys.argv[1], encoding="utf-8") as manifest_file:
    manifest = json.load(manifest_file)
with open(sys.argv[2], "rb") as archive_file:
    digest = hashlib.sha256(archive_file.read()).hexdigest()
assert manifest["release_id"] == "r2o-test"
assert manifest["assets"]["mipsel"]["sha256"] == digest
PY

mkdir -p "$TEMP/multi-builds/mipsel" "$TEMP/multi-builds/mipsel-openwrt-musl" \
    "$TEMP/multi-builds/aarch64-openwrt-musl" "$TEMP/multi-out"
for architecture in mipsel mipsel-openwrt-musl aarch64-openwrt-musl; do
    for component in r2o-datapath r2o-controller r2o-panel r2o-telegram r2o-manager; do
        printf '%s %s\n' "$component" "$architecture" \
            > "$TEMP/multi-builds/$architecture/$component-linux-$architecture"
    done
done
RELEASE_ID=r2o-test-multi VERSION=0.1.0 NOTES='fixture release' \
    sh "$ROOT/scripts/package-release.sh" "$TEMP/multi-builds" "$TEMP/multi-out" \
    'mipsel mipsel-openwrt-musl aarch64-openwrt-musl'
python3 - "$TEMP/multi-out/latest.json" "$TEMP/multi-out" <<'PY'
import hashlib
import json
import pathlib
import sys

with open(sys.argv[1], encoding="utf-8") as manifest_file:
    manifest = json.load(manifest_file)
assert manifest["release_id"] == "r2o-test-multi"
for architecture in ("mipsel", "mipsel-openwrt-musl", "aarch64-openwrt-musl"):
    archive = pathlib.Path(sys.argv[2]) / f"r2o-{architecture}.tar.gz"
    with archive.open("rb") as archive_file:
        digest = hashlib.sha256(archive_file.read()).hexdigest()
    assert manifest["assets"][architecture]["sha256"] == digest
PY
rm "$TEMP/builds/r2o-datapath-linux-mipsel"
ln -s r2o-controller-linux-mipsel "$TEMP/builds/r2o-datapath-linux-mipsel"
if RELEASE_ID=r2o-test VERSION=0.1.0 NOTES='fixture release' \
    sh "$ROOT/scripts/package-release.sh" "$TEMP/builds" "$TEMP/out" >/dev/null 2>&1; then
    echo "сборщик выпуска принял символическую ссылку вместо бинарного файла" >&2
    exit 1
fi
