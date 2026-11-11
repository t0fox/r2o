#!/usr/bin/env python3
"""Собрать итоговый пофункциональный аудит из отчётов групп.

Скрипт не доверяет отчётам на слово: он считает строки таблиц и статусы,
сверяет число строк с размером среза и падает, если часть функций потеряна.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path("/mnt/e/r2o")
AUDIT = ROOT / "docs" / "audit"
OUT = ROOT / "docs" / "function-parity-audit.md"
PARTS = [
    ("core-net", 548),
    ("core-state", 692),
    ("datapath-core", 400),
    ("datapath-plan", 183),
    ("detect", 159),
]
STATUS_RE = re.compile(r"^\s*(?:\*\*)?([EPN?])(?:\*\*)?(?:\s|$|\(|—|-)")


def table_status(line: str) -> str | None:
    if not line.lstrip().startswith("|"):
        return None
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    if not cells or all(set(cell) <= set("-: ") for cell in cells):
        return None
    for cell in cells:
        match = STATUS_RE.match(cell)
        if match:
            return match.group(1)
    return None


def main() -> int:
    header = (AUDIT / "header.md").read_text(encoding="utf-8")
    summary_rows = []
    parts_text = []
    total_rows = 0
    total_counts = {key: 0 for key in "EPN?"}
    for name, expected in PARTS:
        path = AUDIT / f"{name}.md"
        if not path.exists():
            print(f"missing part: {path}", file=sys.stderr)
            return 1
        text = path.read_text(encoding="utf-8")
        counts = {key: 0 for key in "EPN?"}
        rows = 0
        for line in text.splitlines():
            status = table_status(line)
            if status is None:
                continue
            # Строка заголовка содержит слово «статус», а не код; сюда не попадёт.
            rows += 1
            counts[status] += 1
        if rows != expected:
            print(
                f"{name}: expected {expected} function rows, found {rows}",
                file=sys.stderr,
            )
            return 1
        total_rows += rows
        for key in counts:
            total_counts[key] += counts[key]
        summary_rows.append(
            f"| {name} | {rows} | {counts['E']} | {counts['P']} | {counts['N']} | {counts['?']} |"
        )
        parts_text.append(f"\n\n---\n\n# Группа `{name}`\n\n{text.strip()}\n")

    summary = (
        "\n## Итог по группам\n\n"
        "| Группа | Функций | E | P | N | ? |\n"
        "|---|---:|---:|---:|---:|---:|\n"
        + "\n".join(summary_rows)
        + f"\n| **Итого** | **{total_rows}** | **{total_counts['E']}** | **{total_counts['P']}** | "
        f"**{total_counts['N']}** | **{total_counts['?']}** |\n"
    )
    spot = AUDIT / "spot-checks.md"
    spot_text = f"\n\n---\n\n{spot.read_text(encoding='utf-8').strip()}\n" if spot.exists() else ""
    OUT.write_text(header + summary + spot_text + "".join(parts_text), encoding="utf-8")
    print(f"rows={total_rows} counts={total_counts} out={OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
