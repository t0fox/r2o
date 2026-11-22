#!/usr/bin/env python3
import json
from pathlib import Path
import sys

old_tag, old_path, published_path, output = sys.argv[1:]
output = Path(output)
previous = json.loads(Path(old_path).read_bytes())
current = json.loads((output / "latest.json").read_bytes())
history = previous["releases"]
if previous["format"] != 1 or (history and history[0]["release_id"] != old_tag):
    raise SystemExit("Предыдущий каталог не соответствует опубликованному выпуску")

published = set(Path(published_path).read_text(encoding="utf-8").splitlines())
releases = [current, *(release for release in history if release["release_id"] in published)]
sequence_ceiling = (1 << 64) - 1
seen = set()
for release in releases:
    metadata = release["metadata"]
    sequence = metadata["sequence"]
    tag = release["release_id"]
    if (
        metadata["format"] != 2
        or metadata["state_format"] != 1
        or metadata["config_format"] != 1
        or not 0 < sequence < sequence_ceiling
        or tag in seen
    ):
        raise SystemExit(f"Неверный формат или порядок выпуска в каталоге: {tag}")
    sequence_ceiling = sequence
    seen.add(tag)

data = json.dumps({"format": 1, "releases": releases},
                  ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
if len(data) > 1024 * 1024:
    raise SystemExit("Подписанный каталог превысил лимит размера")
(output / "catalog.json").write_bytes(data)
