#!/usr/bin/env python3
"""Показать, по каким файлам среза в отчёте есть заголовок `### файл`.

Нужен для планирования построчной сверки: файлы без заголовка ещё не имеют
разобранного блока, даже если строки функций в таблице уже стоят.
"""
from __future__ import annotations

import csv
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path("/mnt/e/r2o")
AUDIT = ROOT / "docs" / "audit"
TOOL = Path("/mnt/e/r2o-tooling/audit")


def main() -> int:
    parts = sys.argv[1:] or ["core-net", "core-state", "datapath-core", "datapath-plan", "detect"]
    for part in parts:
        rows = list(csv.DictReader((TOOL / f"slice-{part}.csv").open(encoding="utf-8")))
        text = (AUDIT / f"{part}.md").read_text(encoding="utf-8")
        heads = set(re.findall(r"^### `([^`]+)`", text, re.M))
        counts = Counter(row["file"] for row in rows)
        missing = [(f, n) for f, n in sorted(counts.items()) if f not in heads]
        print(f"{part}: files={len(counts)} with_heading={len(heads)} missing={len(missing)}")
        for f, n in missing:
            print(f"  {n:4d}  {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
