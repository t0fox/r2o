#!/bin/sh
set -eu
DIR=${1:?не задан каталог выпуска}
RELEASE_ID=${2:?не задан идентификатор выпуска}
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
openssl pkeyutl -verify -pubin -inkey "$ROOT/crates/r2o-manager/release-public.pem" \
    -rawin -in "$DIR/latest.json" -sigfile "$DIR/latest.json.sig"

if [ -e "$DIR/catalog.json" ] || [ -e "$DIR/catalog.json.sig" ]; then
    openssl pkeyutl -verify -pubin -inkey "$ROOT/crates/r2o-manager/release-public.pem" \
        -rawin -in "$DIR/catalog.json" -sigfile "$DIR/catalog.json.sig"
fi

python3 - "$DIR" "$RELEASE_ID" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
manifest = json.loads((root / "latest.json").read_bytes())
if manifest["release_id"] != sys.argv[2] or manifest["version"] != sys.argv[2]:
    raise SystemExit("идентификатор или версия выпуска не совпадают")
catalog_path = root / "catalog.json"
if catalog_path.exists() and json.loads(catalog_path.read_bytes())["releases"][0] != manifest:
    raise SystemExit("первый выпуск каталога не совпадает с подписанным манифестом")
archives = {f"r2o-{abi}.tar.gz": digest for abi, digest in manifest["assets"].items()}
if not archives or set(archives) != {path.name for path in root.glob("r2o-*.tar.gz")}:
    raise SystemExit("набор архивов не совпадает с latest.json")
for name, expected in archives.items():
    with (root / name).open("rb") as archive:
        actual = hashlib.file_digest(archive, "sha256").hexdigest()
    if actual != expected["sha256"] or (root / name).stat().st_size != expected["bytes"]:
        raise SystemExit(f"SHA-256 не совпадает: {name}")
print(f"Проверены подпись latest.json и SHA-256 {len(archives)} архивов")
PY
