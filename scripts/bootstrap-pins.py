#!/usr/bin/env python3
"""Подготовка входного сценария и проверка закреплённых SHA-256."""

import hashlib
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parent.parent
installer = root / "scripts/install.sh"
bootstrap = root / "scripts/bootstrap.sh"


def git_bytes(path):
    return path.read_bytes().replace(b"\r\n", b"\n")


def pin(script, content):
    value = hashlib.sha256(content).hexdigest().encode()
    result, count = re.subn(
        rb"(?m)^(INSTALL_SHA256=')[^'\r\n]+", lambda match: match[1] + value, script
    )
    if count != 1:
        raise SystemExit("не найдена единственная строка с закреплённой суммой")
    return result


args = sys.argv[1:]
boot = git_bytes(bootstrap)
expected = pin(boot, git_bytes(installer))
if args == ["--write"]:
    bootstrap.write_bytes(expected)
else:
    if boot != expected:
        raise SystemExit("обновите SHA-256: python3 scripts/bootstrap-pins.py --write")
    if args and len(args) == 3 and args[0] == "--pages" and re.fullmatch(r"[0-9a-f]{40}", args[1]):
        get = pin(boot, boot).replace(b"/scripts/install.sh", b"/scripts/bootstrap.sh", 1)
        get = get.replace(b"set -eu\n", b"set -eu\nexport R2O_BOOTSTRAP_REF=" + args[1].encode() + b"\n", 1)
        Path(args[2]).write_bytes(get)
    elif args:
        raise SystemExit("использование: bootstrap-pins.py [--write | --pages COMMIT OUTPUT]")
print("SHA-256 установщика совпадает")
