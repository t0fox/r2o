import re
import sys
from pathlib import Path

# Эти функции сохраняют контракт донора. Изменённые сетевые пути проверяются
# отдельно через реальные сокеты и сравнением совместимой JSON-схемы.
CONTRACTS = ("has_healthy_route", "route_failure_state", "elapsed_ms", "unix_time")


def function(source: str, name: str) -> str:
    match = re.search(rf"(?ms)^([ ]*)(?:pub )?fn {name}\(.*?^\1\}}", source)
    if match is None:
        raise ValueError(f"missing contract: {name}")
    return match.group(0)


def main() -> int:
    donor = Path(sys.argv[1]).read_text(encoding="utf-8")
    current = Path(sys.argv[2]).read_text(encoding="utf-8")
    for name in CONTRACTS:
        if function(donor, name) != function(current, name):
            print(f"unexpected diagnostics contract change: {name}", file=sys.stderr)
            return 1
    print("diagnostics.rs: unchanged donor contracts match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
