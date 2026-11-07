#!/bin/sh
set -eu

# Проверить полный подписанный путь установки: два релиза, второй слот,
# откат и отказ повреждённому архиву. Нужны release-бинарники шести
# компонентов и python3/openssl с Ed25519.
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${R2O_RELEASE_BIN:-$ROOT_DIR/target/release}
ARCH=${R2O_RELEASE_ARCH:-x86_64}
MANAGER=$BIN/r2o-manager
fail() { echo "ОШИБКА: $*" >&2; exit 1; }

[ -x "$MANAGER" ] || fail "не найден release-менеджер: $MANAGER"
for component in r2o-datapath r2o-controller r2o-panel r2o-telegram r2o-manager r2o-fetch; do
    [ -x "$BIN/$component" ] || fail "не найден release-бинарник: $BIN/$component"
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
INSTALL_ROOT=$WORK/root
mkdir -p "$INSTALL_ROOT"

openssl genpkey -algorithm ED25519 -out "$WORK/key.pem" >/dev/null 2>&1 ||
    fail "не удалось создать Ed25519 ключ"
openssl pkey -in "$WORK/key.pem" -pubout -outform DER -out "$WORK/key.der" >/dev/null 2>&1 ||
    fail "не удалось извлечь открытый ключ"
tail -c 32 "$WORK/key.der" > "$WORK/key.raw"

make_release() {
    release_id=$1
    stage=$WORK/stage-$release_id
    mkdir -p "$stage/builds"
    for component in r2o-datapath r2o-controller r2o-panel r2o-telegram r2o-manager r2o-fetch; do
        cp "$BIN/$component" "$stage/builds/$component-linux-$ARCH"
        chmod 0755 "$stage/builds/$component-linux-$ARCH"
    done
    tar -czf "$WORK/$release_id.tar.gz" -C "$stage" builds
    digest=$(sha256sum "$WORK/$release_id.tar.gz" | cut -d' ' -f1)
    python3 - "$release_id" "$ARCH" "$digest" "$WORK/$release_id.json" <<'PY'
import json
import sys

release_id, arch, digest, output = sys.argv[1:]
with open(output, "w", encoding="utf-8", newline="\n") as manifest:
    json.dump(
        {
            "release_id": release_id,
            "version": "test",
            "notes": "",
            "assets": {arch: {"sha256": digest}},
        },
        manifest,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    manifest.write("\n")
PY
    openssl pkeyutl -sign -inkey "$WORK/key.pem" -rawin \
        -in "$WORK/$release_id.json" -out "$WORK/$release_id.sig"
}

install_release() {
    release_id=$1
    "$MANAGER" install-archive --root "$INSTALL_ROOT" \
        --archive "$WORK/$release_id.tar.gz" \
        --manifest "$WORK/$release_id.json" \
        --signature "$WORK/$release_id.sig" \
        --public-key "$WORK/key.raw" \
        --architecture "$ARCH" >"$WORK/$release_id.out" ||
        fail "подписанная установка $release_id не удалась"
    grep -q '"installed":true' "$WORK/$release_id.out" ||
        fail "менеджер не подтвердил установку $release_id"
}

make_release r2o-signed-1
make_release r2o-signed-2

install_release r2o-signed-1
[ "$(sed -n '2p' "$INSTALL_ROOT/release-slots")" = r2o-signed-1 ] ||
    fail "первая подписанная установка не активировала релиз 1"
[ -x "$INSTALL_ROOT/r2o-manager" ] || fail "launcher менеджера не установлен"

install_release r2o-signed-2
[ "$(sed -n '2p' "$INSTALL_ROOT/release-slots")" = r2o-signed-2 ] &&
    [ "$(sed -n '3p' "$INSTALL_ROOT/release-slots")" = r2o-signed-1 ] ||
    fail "вторая установка не сохранила предыдущий релиз"

"$MANAGER" rollback --root "$INSTALL_ROOT" >"$WORK/rollback.out" ||
    fail "подписанный откат не выполнился"
[ "$(sed -n '2p' "$INSTALL_ROOT/release-slots")" = r2o-signed-1 ] &&
    [ "$(sed -n '3p' "$INSTALL_ROOT/release-slots")" = r2o-signed-2 ] ||
    fail "откат не восстановил релиз 1"

cp "$WORK/r2o-signed-2.tar.gz" "$WORK/tampered.tar.gz"
printf 'x' >> "$WORK/tampered.tar.gz"
if "$MANAGER" install-archive --root "$INSTALL_ROOT" \
    --archive "$WORK/tampered.tar.gz" \
    --manifest "$WORK/r2o-signed-2.json" \
    --signature "$WORK/r2o-signed-2.sig" \
    --public-key "$WORK/key.raw" \
    --architecture "$ARCH" >"$WORK/tampered.out" 2>&1; then
    fail "повреждённый архив был принят"
fi
[ "$(sed -n '2p' "$INSTALL_ROOT/release-slots")" = r2o-signed-1 ] &&
    [ "$(sed -n '3p' "$INSTALL_ROOT/release-slots")" = r2o-signed-2 ] ||
    fail "повреждённый архив изменил активные слоты"

echo "Подписанная установка, второй слот, откат и отказ повреждённому архиву прошли"
