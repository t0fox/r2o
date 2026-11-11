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
RANGE_RE = re.compile(r"^(?P<start>\d+)\s*(?:(?:\.\.|–|-|—)\s*(?P<end>\d+))?\s*$")


def main() -> int:
    parts = sys.argv[1:] or PARTS
    failed = False
    for part in parts:
        csv_path = TOOL / f"slice-{part}.csv"
        md_path = AUDIT / f"{part}.md"
        if not csv_path.exists() or not md_path.exists():
            print(f"{part}: missing csv or md", file=sys.stderr)
            failed = True
            continue
        rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
        expected: dict[tuple[int, int], int] = {}
        for row in rows:
            pair = (int(row["line"]), int(row["end_line"]))
            expected[pair] = expected.get(pair, 0) + 1
        text = md_path.read_text(encoding="utf-8")
        seen: dict[tuple[int, int], int] = {}
        for line in text.splitlines():
            if not line.lstrip().startswith("|"):
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < 6 or not re.match(
                r"^`?[A-Za-z_][A-Za-z0-9_]*`?(?:\s|\||$)", cells[0]
            ):
                continue
            match = RANGE_RE.match(cells[1])
            if not match:
                continue
            start = int(match.group("start"))
            end = int(match.group("end")) if match.group("end") else start
            pair = (start, end)
            seen[pair] = seen.get(pair, 0) + 1
        missing = sorted(
            (pair, count - seen.get(pair, 0))
            for pair, count in expected.items()
            if seen.get(pair, 0) < count
        )
        extra = sorted(
            (pair, count - expected.get(pair, 0))
            for pair, count in seen.items()
            if count > expected.get(pair, 0)
        )
        print(
            f"{part}: expected={len(rows)} seen={sum(seen.values())} "
            f"missing={sum(count for _, count in missing)} extra={sum(count for _, count in extra)}"
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
