#!/usr/bin/env python3
"""Посчитать строки и статусы в отчётах групп (для сверки с собранным файлом).

Статус берётся строго из колонки «статус» (шестая ячейка таблицы), а не из
любой ячейки: в описаниях встречаются фразы вида «N цифр подряд», которые
иначе дают ложные срабатывания. При разборе строки учитывается экранированный
разделитель `\\|` внутри ячеек (Rust-замыкания, `matches!`).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

AUDIT = Path("/mnt/e/r2o/docs/audit")
PARTS = ["core-net", "core-state", "datapath-core", "datapath-plan", "detect"]
NAME_RE = re.compile(r"^`?[A-Za-z_][A-Za-z0-9_]*`?(?:\s|\||$)")
STATUS_CELL_RE = re.compile(r"^(?:\*\*)?([EPN?])(?:\*\*)?\*?$")
CELL_SPLIT_RE = re.compile(r"(?<!\\)\|")


def split_row(line: str) -> list[str]:
    """Разделить markdown-строку по неэкранированным `|`."""
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|") and not stripped.endswith("\\|"):
        stripped = stripped[:-1]
    return [cell.strip().replace("\\|", "|") for cell in CELL_SPLIT_RE.split(stripped)]


def main() -> int:
    failed = False
    for part in sys.argv[1:] or PARTS:
        path = AUDIT / f"{part}.md"
        if not path.exists():
            print(f"{part}: missing")
            failed = True
            continue
        counts = {key: 0 for key in "EPN?"}
        rows = 0
        malformed = []
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.startswith("|"):
                continue
            cells = split_row(line)
            if len(cells) < 7 or not NAME_RE.match(cells[0]):
                continue
            match = STATUS_CELL_RE.match(cells[5])
            if not match:
                malformed.append((number, cells[0], cells[5]))
                continue
            rows += 1
            counts[match.group(1)] += 1
        print(f"{part}: rows={rows} counts={counts}")
        if malformed:
            print(f"  malformed status cells: {malformed[:5]}")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
