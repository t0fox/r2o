#!/usr/bin/env python3
"""Проверка, что в отчётах групп присутствует каждая функция среза.

Сопоставление идёт по паре (line, end_line) из реестра: имена helper'ов могут
повторяться в разных файлах, а диапазоны строк уникальны внутри файла.
"""
from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

ROOT = Path("/mnt/e/r2o")
AUDIT = ROOT / "docs" / "audit"
TOOL = Path("/mnt/e/r2o-tooling/audit")
PARTS = ["core-net", "core-state", "datapath-core", "datapath-plan", "detect"]
RANGE_RE = re.compile(r"(?P<start>\d+)\s*(?:\.\.|–|-|—)\s*(?P<end>\d+)")


def main() -> int:
    failed = False
    for part in PARTS:
        csv_path = TOOL / f"slice-{part}.csv"
        md_path = AUDIT / f"{part}.md"
        if not csv_path.exists() or not md_path.exists():
            print(f"{part}: missing csv or md", file=sys.stderr)
            failed = True
            continue
        rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
        expected = {(int(row["line"]), int(row["end_line"])) for row in rows}
        text = md_path.read_text(encoding="utf-8")
        seen: set[tuple[int, int]] = set()
        for line in text.splitlines():
            if not line.lstrip().startswith("|"):
                continue
            match = RANGE_RE.search(line)
            if not match:
                continue
            pair = (int(match.group("start")), int(match.group("end")))
            seen.add(pair)
        missing = sorted(expected - seen)
        extra = sorted(seen - expected)
        print(
            f"{part}: expected={len(expected)} seen={len(seen)} missing={len(missing)} extra={len(extra)}"
        )
        if missing:
            print("  missing sample:", missing[:10])
            failed = True
        if extra:
            print("  extra sample:", extra[:10])
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
