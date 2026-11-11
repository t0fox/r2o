#!/usr/bin/env python3
"""Извлечение production-функций D2O из закреплённого worktree.

Сканер намеренно лексический: он не требует сборки и работает с тем же
деревом исходников, что и differential-тесты. Комментарии, строки и
preprocessor-строки маскируются, затем на верхнем уровне ищутся определения
вида `... имя(аргументы) {` и для каждого находится парная закрывающая скобка.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from pathlib import Path

CONTROL = {"if", "for", "while", "switch", "return", "sizeof", "do", "else"}
INCLUDE_DIRS = ("core", "datapath", "detect")
EXCLUDE_FILES = {"planlab.c", "ctlprobe.c", "probe_mtproto.c"}
EXCLUDE_PREFIXES = ("test_", "test.")


def mask(text: str) -> str:
    """Заменить содержимое комментариев/строк/директив пробелами.

    Длины строк сохраняются, чтобы номера строк и столбцов не менялись.
    """
    out = list(text)
    i = 0
    n = len(text)
    state = "code"
    at_line_start = True
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if at_line_start:
                j = i
                while j < n and text[j] in " \t":
                    j += 1
                if j < n and text[j] == "#":
                    while j < n and text[j] != "\n":
                        if text[j] == "\\" and j + 1 < n and text[j + 1] == "\n":
                            out[j] = out[j + 1] = " "
                            j += 2
                            continue
                        out[j] = " "
                        j += 1
                    i = j
                    at_line_start = False
                    continue
                at_line_start = False
            if c == "/" and nxt == "/":
                state = "line"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c == '"':
                state = "string"
                out[i] = " "
                i += 1
                continue
            if c == "'":
                state = "char"
                out[i] = " "
                i += 1
                continue
            if c == "\n":
                at_line_start = True
            i += 1
            continue
        if state == "line":
            if c == "\n":
                state = "code"
                at_line_start = True
            else:
                out[i] = " "
            i += 1
            continue
        if state == "block":
            if c == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "code"
                continue
            if c != "\n":
                out[i] = " "
            i += 1
            continue
        if state in ("string", "char"):
            quote = '"' if state == "string" else "'"
            if c == "\\" and i + 1 < n:
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c == quote:
                out[i] = " "
                i += 1
                state = "code"
                continue
            if c == "\n":
                state = "code"
                at_line_start = True
                i += 1
                continue
            out[i] = " "
            i += 1
            continue
    return "".join(out)


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def matching_brace(masked: str, open_index: int) -> int | None:
    depth = 0
    i = open_index
    n = len(masked)
    while i < n:
        c = masked[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


DEF_RE = re.compile(
    r"(?m)^[ \t]*(?P<prefix>(?:static\s+)?(?:inline\s+)?[A-Za-z_][A-Za-z0-9_ \t\*]*?)"
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{"
)


def parse_file(path: Path, root: Path) -> list[dict]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    masked = mask(raw)
    results = []
    for match in DEF_RE.finditer(masked):
        name = match.group("name")
        if name in CONTROL:
            continue
        brace = masked.find("{", match.start(), match.end())
        if brace < 0:
            continue
        end = matching_brace(masked, brace)
        if end is None:
            continue
        start_line = line_of(masked, match.start("name"))
        end_line = line_of(masked, end)
        body = raw[brace : end + 1]
        signature = raw[match.start() : brace].strip()
        results.append(
            {
                "module": path.relative_to(root).parts[0],
                "file": str(path.relative_to(root)).replace("\\", "/"),
                "line": start_line,
                "end_line": end_line,
                "lines": end_line - start_line + 1,
                "static": signature.startswith("static"),
                "name": name,
                "signature": re.sub(r"\s+", " ", signature)[:400],
                "sha256": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
            }
        )
    return results


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: extract_c_functions.py D2O_ROOT OUT_JSON", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    out = Path(sys.argv[2]).resolve()
    rows = []
    for module in INCLUDE_DIRS:
        base = root / module
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.c")):
            rel = str(path.relative_to(root)).replace("\\", "/")
            if path.name in EXCLUDE_FILES or path.name.startswith(EXCLUDE_PREFIXES):
                continue
            if "/test" in rel or rel.endswith("_test.c"):
                continue
            rows.extend(parse_file(path, root))
        for path in sorted(base.rglob("*.h")):
            rel = str(path.relative_to(root)).replace("\\", "/")
            if "/test" in rel:
                continue
            rows.extend(parse_file(path, root))
    # Один и тот же заголовочный inline может встретиться в нескольких .c;
    # в таблице он должен быть один раз.
    unique = {}
    for row in rows:
        key = (row["file"], row["name"], row["line"])
        unique[key] = row
    rows = sorted(unique.values(), key=lambda r: (r["module"], r["file"], r["line"]))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    with out.with_suffix(".csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else [])
        writer.writeheader()
        writer.writerows(rows)
    print(f"functions={len(rows)} files={len({(r['file']) for r in rows})} out={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
