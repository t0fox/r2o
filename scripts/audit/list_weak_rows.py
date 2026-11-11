#!/usr/bin/env python3
"""Печатает строки аудита с коротким или пустым доказательством.

Скрипт нужен, чтобы находить места, где статус P/N/? поставлен без
построчной сверки. Он не меняет отчёты и не является доказательством
паритета.
"""

from __future__ import annotations

import glob
import sys


def main() -> int:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 35
    for path in sorted(glob.glob("docs/audit/*.md")):
        if "deep-" in path or path.endswith("header.md"):
            continue
        for number, line in enumerate(open(path, encoding="utf-8"), 1):
            if not line.startswith("| `"):
                continue
            columns = [part.strip() for part in line.strip().strip("|").split("|")]
            if len(columns) < 7:
                continue
            function, status, evidence = columns[0], columns[5], columns[6]
            if status not in {"P", "**P**", "N", "**N**", "?", "**?**"}:
                continue
            if len(evidence) < limit or evidence in {"—", "-", "нет"}:
                print(f"{path}:{number}: {function} | {status} | {evidence[:100]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
