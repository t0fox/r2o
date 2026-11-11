#!/usr/bin/env python3
"""Извлечение shell-функций D2O и R2O с диапазонами строк."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

FN_RE = re.compile(r"(?m)^[ \t]*(?:function[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(\)[ \t]*\{")


def matching_brace(text: str, start: int) -> int | None:
    depth = 0
    i = start
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def parse(path: Path, root: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rows = []
    for match in FN_RE.finditer(text):
        brace = text.find("{", match.start(), match.end())
        end = matching_brace(text, brace)
        if end is None:
            continue
        line = text.count("\n", 0, match.start()) + 1
        end_line = text.count("\n", 0, end) + 1
        rows.append(
            {
                "file": str(path.relative_to(root)).replace("\\", "/"),
                "name": match.group(1),
                "line": line,
                "end_line": end_line,
                "lines": end_line - line + 1,
            }
        )
    return rows


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: extract_shell_functions.py D2O_ROOT R2O_ROOT OUT_JSON", file=sys.stderr)
        return 2
    d2o = Path(sys.argv[1]).resolve()
    r2o = Path(sys.argv[2]).resolve()
    out = Path(sys.argv[3]).resolve()
    d2o_rows = []
    for name in ("S99d2k", "d2k-openwrt-init"):
        path = d2o / "files" / name
        if path.exists():
            d2o_rows.extend(parse(path, d2o))
    for path in sorted((d2o / "files").glob("*.sh")):
        if path.name == "d2k-fw-heal.sh":
            # восстанавливающий helper без функций — учитывается отдельно
            continue
        d2o_rows.extend(parse(path, d2o))
    r2o_rows = []
    for name in ("S99r2o", "openwrt-init"):
        path = r2o / "router" / name
        if path.exists():
            r2o_rows.extend(parse(path, r2o))
    for path in sorted((r2o / "router").glob("*.sh")):
        r2o_rows.extend(parse(path, r2o))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"d2o": d2o_rows, "r2o": r2o_rows}, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    print(f"d2o={len(d2o_rows)} r2o={len(r2o_rows)} out={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
