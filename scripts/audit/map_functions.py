#!/usr/bin/env python3
"""Сопоставление production-функций D2O с функциями R2O по именам и токенам.

Инструмент не доказывает паритет: он готовит черновик карты, которую затем
проверяет человек/агент по исходникам. Для каждой C-функции сохраняются
лучшие кандидаты Rust с файлом и строкой, чтобы аудит начинался не с нуля.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RUST_ROOT = Path("/mnt/e/r2o/crates")
CRATE_NAMES = ("r2k-core", "r2o-datapath", "r2o-controller", "r2o-panel", "r2o-telegram")
FN_RE = re.compile(
    r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:<[^>{};]*>)?\s*\("
)
CONTROL = {"if", "for", "while", "switch", "return", "match", "loop"}


def matching_brace(text: str, start: int) -> int | None:
    depth = 0
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def rust_functions() -> list[dict]:
    rows = []
    for path in sorted(RUST_ROOT.rglob("*.rs")):
        rel = path.relative_to(RUST_ROOT).as_posix()
        if "/target/" in rel or rel.endswith("build.rs"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in FN_RE.finditer(text):
            name = match.group("name")
            if name in CONTROL:
                continue
            brace = text.find("{", match.end())
            semi = text.find(";", match.end())
            if brace < 0 or (0 <= semi < brace):
                continue
            end = matching_brace(text, brace)
            if end is None:
                continue
            line = text.count("\n", 0, match.start()) + 1
            end_line = text.count("\n", 0, end) + 1
            before = text[max(0, match.start() - 400) : match.start()]
            is_test = "#[test]" in before or "tokio::test" in before or "test]" in before[-160:]
            rows.append(
                {
                    "crate": rel.split("/", 1)[0],
                    "file": rel,
                    "line": line,
                    "end_line": end_line,
                    "name": name,
                    "test": is_test,
                }
            )
    return rows


def normalize(name: str) -> str:
    value = name.lower()
    for prefix in ("d2kd_", "d2k_", "r2o_", "r2k_", "d2k"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    return value.strip("_")


def tokens(name: str) -> set[str]:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    return {part for part in value.split("_") if part and part not in {"d2k", "r2o", "r2k"}}


def edit_distance(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(
                min(previous[j] + 1, current[-1] + 1, previous[j - 1] + (ca != cb))
            )
        previous = current
    return previous[-1]


def score(c_name: str, r_name: str) -> float:
    cn, rn = normalize(c_name), normalize(r_name)
    if cn == rn:
        return 100.0
    ct, rt = tokens(c_name), tokens(r_name)
    if not ct or not rt:
        return 0.0
    common = len(ct & rt)
    if common == 0:
        return 0.0
    union = len(ct | rt)
    jaccard = common / union
    containment = 1.0 if ct <= rt or rt <= ct else 0.0
    distance = edit_distance(cn, rn)
    similarity = 1.0 - distance / max(len(cn), len(rn), 1)
    return 100.0 * (0.55 * jaccard + 0.25 * containment + 0.20 * max(similarity, 0.0))


def best_matches(c_name: str, rust: list[dict], limit: int = 3) -> list[dict]:
    scored = []
    for item in rust:
        if item["test"]:
            continue
        value = score(c_name, item["name"])
        if value <= 0:
            continue
        scored.append((value, item))
    scored.sort(key=lambda pair: (-pair[0], pair[1]["file"], pair[1]["line"]))
    return [
        {
            "crate": item["crate"],
            "file": item["file"],
            "line": item["line"],
            "name": item["name"],
            "score": round(value, 1),
        }
        for value, item in scored[:limit]
    ]


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: map_functions.py C_FUNCTIONS.json OUT_JSON", file=sys.stderr)
        return 2
    c_rows = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    rust = rust_functions()
    for row in c_rows:
        row["rust_candidates"] = best_matches(row["name"], rust)
    out = Path(sys.argv[2])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(c_rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"c_functions={len(c_rows)} rust_functions={len(rust)} out={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
