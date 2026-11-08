import difflib
import sys
from pathlib import Path

ALLOWED = (
    "ca_bundle",
    "validate_doh_ca_bundle",
    "with_ca_bundle",
    "resolve_cf_ips",
)


def main() -> int:
    donor = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    current = Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
    hunks = []
    current_hunk = []
    for line in difflib.unified_diff(donor, current, lineterm=""):
        if line.startswith("@@"):
            if current_hunk:
                hunks.append(current_hunk)
            current_hunk = []
            continue
        if line.startswith(("---", "+++")):
            continue
        current_hunk.append(line)
    if current_hunk:
        hunks.append(current_hunk)

    unexpected = []
    for hunk in hunks:
        changed = [line for line in hunk if line.startswith(("+", "-"))]
        if not changed:
            continue
        if any(any(marker in line for marker in ALLOWED) for line in changed):
            continue
        unexpected.extend(changed)
    if unexpected:
        print("unexpected diagnostics.rs differences:", file=sys.stderr)
        for line in unexpected:
            print(line, file=sys.stderr)
        return 1
    print("diagnostics.rs: only ca_bundle integration differences")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
