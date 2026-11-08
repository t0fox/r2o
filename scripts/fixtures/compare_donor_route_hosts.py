import re
import sys
from pathlib import Path


def extract(text: str, marker: str) -> str:
    start = text.find(marker)
    if start < 0:
        raise SystemExit(f"not found {marker!r}")
    brace = text.find("{", start)
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise SystemExit("unbalanced braces")


def normalize(source: str) -> str:
    source = re.sub(r"//[^\n]*", "", source)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"\s+", " ", source).strip()


def main() -> int:
    donor = Path(sys.argv[1]).read_text(encoding="utf-8")
    current = Path(sys.argv[2]).read_text(encoding="utf-8")
    checks = [
        "fn ws_domains(",
        "fn cf_ws_domains(",
        "fn ordered_records(",
        "fn cf_ip_attempts(",
        "impl<'a> CfAttempts<'a>",
    ]
    failed = False
    for marker in checks:
        left = normalize(extract(donor, marker))
        right = normalize(extract(current, marker))
        status = "MATCH" if left == right else "DIFF"
        print(f"{marker} {status}")
        if left != right:
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
