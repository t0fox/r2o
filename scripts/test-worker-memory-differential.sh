#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
[ -d "$D2O_ROOT/core" ] || {
    echo "не найден D2O checkout: $D2O_ROOT" >&2
    exit 2
}
TEMP_BASE=${R2O_TEST_TMP:-${TMPDIR:-/tmp}}
mkdir -p "$TEMP_BASE"
TEMP=$(mktemp -d "$TEMP_BASE/r2o-worker-memory.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

CC=${CC:-cc}
make -C "$D2O_ROOT/core" test_sched_worker_lifecycle \
    CC="$CC" >"$TEMP/c-build.log" 2>&1 || {
    cat "$TEMP/c-build.log" >&2
    exit 1
}
"$D2O_ROOT/core/test_sched_worker_lifecycle" >"$TEMP/c.log" 2>&1 || {
    cat "$TEMP/c.log" >&2
    exit 1
}

(
    export CARGO_HOME=${R2O_CARGO_HOME:-$HOME/.cargo}
    export RUSTUP_HOME=${R2O_RUSTUP_HOME:-$HOME/.rustup}
    export CARGO_TARGET_DIR=${R2O_CARGO_TARGET_DIR:-$HOME/r2o-target}
    "${CARGO:-cargo}" test -p r2o-controller --test worker_memory --locked --offline \
        -- --nocapture >"$TEMP/rust.log" 2>&1
) || {
    cat "$TEMP/rust.log" >&2
    exit 1
}

python3 - "$TEMP/c.log" "$TEMP/rust.log" <<'PY'
import re
import sys
from pathlib import Path

limit = 5 * 1024
pattern = re.compile(
    r"VmRSS\s+(?:Some\()?(\d+)\)?\s*->\s*(?:Some\()?(\d+)\)?\s*->\s*(?:Some\()?(\d+)\)?.*?"
    r"VmData\s+(?:Some\()?(\d+)\)?\s*->\s*(?:Some\()?(\d+)\)?\s*->\s*(?:Some\()?(\d+)\)?",
    re.S,
)
results = {}
for name, path in (("C", sys.argv[1]), ("Rust", sys.argv[2])):
    text = Path(path).read_text(encoding="utf-8")
    match = pattern.search(text)
    if not match:
        raise SystemExit(f"не найдены RSS/VmData counters в {name}")
    values = [int(value) for value in match.groups()]
    rss_start, rss_warm, rss_end, data_start, data_warm, data_end = values
    if rss_end > rss_warm + limit or data_end > data_warm + limit:
        raise SystemExit(
            f"{name}: рост после прогрева превышает {limit} KiB: "
            f"VmRSS {rss_warm}->{rss_end}, VmData {data_warm}->{data_end}"
        )
    results[name] = (rss_start, rss_warm, rss_end, data_start, data_warm, data_end)
    print(
        f"{name}: VmRSS {rss_start} -> {rss_warm} -> {rss_end} KiB; "
        f"VmData {data_start} -> {data_warm} -> {data_end} KiB"
    )
print("worker memory differential: PASS (1500 cycles, two 4-KiB args, same 5-MiB bound)")
PY
