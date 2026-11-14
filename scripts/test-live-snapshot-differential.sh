#!/bin/sh
# C/Rust differential: полный live.json без активных поисков.
# Сверяются все секции D2O; поля расширения R2O вне схемы D2O отбрасываются.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-live-snapshot.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-live-snapshot" \
    "$ROOT/crates/r2o-controller/tests/d2o_live_snapshot_differential.c" \
    "$D2O_ROOT/core/catalog.c" "$D2O_ROOT/core/groups.c" \
    "$D2O_ROOT/core/domain.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/d2o-live-snapshot" >"$TEMP/c.json"

R2O_LIVE_SNAPSHOT_DIFF_OUTPUT="$TEMP/rust.json" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib live::tests::live_snapshot_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys


def d2o_view(doc):
    """Оставить только поля, которые пишет D2O `d2k_sched_write_live`."""
    out = {key: doc[key] for key in doc if key != "dns_services"}
    # `dns_services` появился только в D2O current main (7a5fab9); pinned
    # a378 этого поля не знает. Секция проверяется отдельным differential.
    boxes = []
    for box in doc.get("boxes", []):
        boxes.append({
            "id": box.get("id"),
            "created": box.get("created"),
            "updated": box.get("updated"),
            "signals": [
                {"kind": s.get("kind"), "human": s.get("human"), "seen": s.get("seen")}
                for s in box.get("signals", [])
            ],
            "plans": [
                {
                    "id": p.get("id"),
                    "proto": p.get("proto"),
                    "successes": p.get("successes"),
                    "enabled": p.get("enabled"),
                    "human": p.get("human"),
                    "text": p.get("text"),
                }
                for p in box.get("plans", [])
            ],
            "bindings": [
                {
                    "target": b.get("target"),
                    "family": b.get("family"),
                    "transport": b.get("transport"),
                    "shape": b.get("shape"),
                    "kind": b.get("kind"),
                    "level": b.get("level"),
                    "level_name": b.get("level_name"),
                    "successes": b.get("successes"),
                    "confirmed": b.get("confirmed"),
                    "enabled": b.get("enabled"),
                    "recheck": b.get("recheck"),
                }
                for b in box.get("bindings", [])
            ],
        })
    out["boxes"] = boxes
    return out


c = d2o_view(json.load(open(sys.argv[1], encoding="utf-8")))
r = d2o_view(json.load(open(sys.argv[2], encoding="utf-8")))
if c != r:
    print("C:", json.dumps(c, ensure_ascii=False, sort_keys=True, indent=2))
    print("R:", json.dumps(r, ensure_ascii=False, sort_keys=True, indent=2))
    raise SystemExit(1)
print("PASS: full live.json C/Rust match")
PY
