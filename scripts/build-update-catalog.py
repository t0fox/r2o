#!/usr/bin/env python3
import json
from pathlib import Path
import sys

old_tag, old_path, output = sys.argv[1:]
output = Path(output)
previous = json.loads(Path(old_path).read_bytes())
current = json.loads((output / "latest.json").read_bytes())
history = previous["releases"]
if previous["format"] != 1 or (
    history and (history[0]["release_id"] != old_tag
                 or history[0]["metadata"]["sequence"] >= current["metadata"]["sequence"])
):
    raise SystemExit("Предыдущий каталог не соответствует опубликованному выпуску")
data = json.dumps({"format": 1, "releases": [current, *history]},
                  ensure_ascii=False, separators=(",", ":")).encode()
if len(data) > 1024 * 1024:
    raise SystemExit("Подписанный каталог превысил лимит размера")
(output / "catalog.json").write_bytes(data + b"\n")
