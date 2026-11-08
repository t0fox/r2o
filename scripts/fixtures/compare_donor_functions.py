import re
import sys
from pathlib import Path


def extract(path: Path, marker: str) -> str:
    text = path.read_text(encoding="utf-8")
    start = text.find(marker)
    if start < 0:
        raise SystemExit(f"not found {marker!r} in {path}")
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
    donor = Path(sys.argv[1])
    current = Path(sys.argv[2])
    checks = [
        ("ws_client.rs", "impl<K: Eq + Hash> CooldownMap<K>"),
        ("ws_client.rs", "fn cf_ip_attempts("),
        ("ws_client.rs", "impl<'a> CfAttempts<'a>"),
        ("routing.rs", "fn should_hedge_direct_recovery("),
        ("routing.rs", "pub(crate) async fn select_upstream("),
    ]
    failed = False
    for file_name, marker in checks:
        left = normalize(extract(donor / file_name, marker))
        right = normalize(extract(current / file_name, marker))
        status = "MATCH" if left == right else "DIFF"
        print(f"{file_name}: {marker} {status}")
        if left != right:
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
