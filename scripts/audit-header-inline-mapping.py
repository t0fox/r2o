#!/usr/bin/env python3
"""Аудит mapping production header-inline helper'ов D2O на Rust.

Читает docs/audit/function-index.md, берёт секции заголовков (`include/`)
и проверяет, что у каждой функции есть Rust-владелец и контракт, а статус
не `missing`. Скрипт не доказывает поведение — он фиксирует, что
inventory/mapping не потерял helper.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "docs" / "audit" / "function-index.md"


def main() -> int:
    section = None
    rows = 0
    violations: list[str] = []
    for line in INDEX.read_text(encoding="utf-8").splitlines():
        if line.startswith("### "):
            section = (
                line
                if (
                    "include/" in line
                    or "runtime/d2k_runtime.h" in line
                    or "runtime/d2k_diagnostics_files.h" in line
                )
                else None
            )
            continue
        if section is None or not line.startswith("| "):
            continue
        parts = [part.strip() for part in line.split("|")[1:-1]]
        if len(parts) < 8 or not parts[0].isdigit():
            continue
        match = re.fullmatch(r"`([^`]+)`", parts[1])
        if not match:
            continue
        name = match.group(1)
        owner = parts[4]
        contract = parts[5]
        status = parts[6]
        rows += 1
        if owner == "—" or not contract:
            violations.append(f"{section}: {name}: нет Rust-владельца/контракта")
        elif status == "missing":
            violations.append(f"{section}: {name}: статус missing")
    print(f"header-inline rows={rows}")
    if violations:
        for violation in violations:
            print(f"FAIL: {violation}", file=sys.stderr)
        return 1
    print("PASS: все header-inline helper'ы имеют Rust-владельца и контракт")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
