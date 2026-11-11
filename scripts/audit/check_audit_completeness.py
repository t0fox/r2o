#!/usr/bin/env python3
"""Проверка, что в отчётах групп присутствует каждая функция среза.

Два режима:
- по умолчанию — по паре (line, end_line), как в срезе;
- `--by-name` — по паре (file, name), если аудитор уточнил границы тела
  функции и диапазоны перестали совпадать с эвристикой сканера.

Имена helper'ов могут повторяться в разных файлах, поэтому пара
(файл, имя) обязательна. Внутри одного файла допустимы одноимённые функции
(например, linux/не-linux ветки `d2k_ct_open`) — учитывается кратность.
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
NAME_RE = re.compile(r"^`?[A-Za-z_][A-Za-z0-9_]*`?(?:\s|\||$)")
CELL_SPLIT_RE = re.compile(r"(?<!\\)\|")
HEADING_RE = re.compile(r"^###\s+`(?P<file>[^`]+)`\s*$")


def split_row(line: str) -> list[str]:
    """Разделить markdown-строку по неэкранированным `|`."""
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|") and not stripped.endswith("\\|"):
        stripped = stripped[:-1]
    return [cell.strip().replace("\\|", "|") for cell in CELL_SPLIT_RE.split(stripped)]


def cell_name(cell: str) -> str | None:
    value = cell.strip()
    if value.startswith("`") and "`" in value[1:]:
        value = value[1 : value.index("`", 1)]
    else:
        value = value.split()[0] if value.split() else ""
    value = value.split("(")[0].strip()
    return value if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) else None


def main() -> int:
    args = [arg for arg in sys.argv[1:] if arg != "--by-name"]
    by_name = "--by-name" in sys.argv[1:]
    failed = False
    for part in args or PARTS:
        csv_path = TOOL / f"slice-{part}.csv"
        md_path = AUDIT / f"{part}.md"
        if not csv_path.exists() or not md_path.exists():
            print(f"{part}: missing csv or md", file=sys.stderr)
            failed = True
            continue
        rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
        if by_name:
            expected: dict[tuple[str, str], int] = {}
            for row in rows:
                key = (row["file"], row["name"])
                expected[key] = expected.get(key, 0) + 1
        else:
            expected = {}
            for row in rows:
                key = (int(row["line"]), int(row["end_line"]))
                expected[key] = expected.get(key, 0) + 1
        text = md_path.read_text(encoding="utf-8")
        seen: dict[tuple, int] = {}
        current_file: str | None = None
        for line in text.splitlines():
            heading = HEADING_RE.match(line)
            if heading:
                current_file = heading.group("file").strip()
                continue
            if re.match(r"^##\s", line):
                # Новый раздел (например, углублённая сверка) — таблицы ниже
                # уже не относятся к предыдущему файлу среза.
                current_file = None
                continue
            if not line.lstrip().startswith("|"):
                continue
            cells = split_row(line)
            if len(cells) < 7 or not NAME_RE.match(cells[0]):
                continue
            name = cell_name(cells[0])
            if name is None:
                continue
            if by_name:
                if current_file is None:
                    print(f"{part}: table row without file heading: {name}", file=sys.stderr)
                    failed = True
                    continue
                key = (current_file, name)
            else:
                match = RANGE_RE.match(cells[1])
                if not match:
                    continue
                start = int(match.group("start"))
                end = int(match.group("end")) if match.group("end") else start
                key = (start, end)
            seen[key] = seen.get(key, 0) + 1
        missing = sorted(
            (key, count - seen.get(key, 0))
            for key, count in expected.items()
            if seen.get(key, 0) < count
        )
        extra = sorted(
            (key, count - expected.get(key, 0))
            for key, count in seen.items()
            if count > expected.get(key, 0)
        )
        print(
            f"{part}: mode={'name' if by_name else 'range'} expected={len(rows)} "
            f"seen={sum(seen.values())} "
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
