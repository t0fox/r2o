import json
import re
import sys


def norm(value):
    if isinstance(value, dict):
        return {key: norm(item) for key, item in value.items()}
    if isinstance(value, list):
        return [norm(item) for item in value]
    if isinstance(value, str):
        return re.sub(r" \(os error \d+\)$", "", value)
    return value


left = norm(json.load(open(sys.argv[1], encoding="utf-8")))
right = norm(json.load(open(sys.argv[2], encoding="utf-8")))
left["duration"] = "<duration>"
right["duration"] = "<duration>"
if left != right:
    print("JSON-DIFF", file=sys.stderr)
    for key in sorted(set(left) | set(right)):
        if left.get(key) != right.get(key):
            print(key, "C=", left.get(key), "Rust=", right.get(key), file=sys.stderr)
    raise SystemExit(1)
print("JSON-EQUAL")
