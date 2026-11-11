#!/usr/bin/env python3
"""Посчитать строки и статусы в отчётах групп (для сверки с собранным файлом)."""
from __future__ import annotations

import re
import sys
from pathlib import Path

AUDIT = Path("/mnt/e/r2o/docs/audit")
PARTS = ["core-net", "core-state", "datapath-core", "datapath-plan", "detect"]


def main() -> int:
    for part in sys.argv[1:] or PARTS:
        path = AUDIT / f"{part}.md"
        if not path.exists():
            print(f"{part}: missing")
            continue
        counts = {key: 0 for key in "EPN?"}
        rows = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("|"):
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < 6 or not re.match(
                r"^`?[A-Za-z_][A-Za-z0-9_]*`?(?:\s|\||$)", cells[0]
            ):
                continue
            rows += 1
            for cell in cells:
                match = re.match(r"^(?:\*\*)?([EPN?])(?:\*\*)?(?:\s|$|\(|—|-)", cell)
                if match:
                    counts[match.group(1)] += 1
                    break
        print(f"{part}: rows={rows} counts={counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
