#!/bin/sh
# C/Rust differential: DNS bootstrap (current main runtime/d2k_dns_config.c):
# dns_name_encode / dns_skip_name / dns_response_address и
# d2k_dns_resolve_bootstrap через loopback UDP/53 в unshare -Urn.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_CURRENT_D2O_ROOT:-/mnt/e/d2o-current}
EXPECTED_D2O_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected current D2O main %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-dns-bootstrap.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -I"$D2O_ROOT/runtime" \
    -o "$TEMP/d2o-dns-bootstrap" \
    "$ROOT/crates/r2o-controller/tests/d2o_dns_bootstrap_differential.c" \
    -lpthread 2>"$TEMP/cc.log"
"$TEMP/d2o-dns-bootstrap" >"$TEMP/c-vectors.json"

RUST_BIN=$("$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --lib --no-run --message-format=json 2>/dev/null |
    python3 -c 'import json,sys
for line in sys.stdin:
    try: item=json.loads(line)
    except Exception: continue
    if item.get("reason")=="compiler-artifact" and item.get("executable") and item.get("target",{}).get("name")=="r2k_core":
        print(item["executable"])' | tail -1)
if [ -z "$RUST_BIN" ]; then
    printf 'не найден r2k_core test binary\n' >&2
    exit 1
fi

R2O_DNS_BOOTSTRAP_VECTORS="$TEMP/r-vectors.txt" \
    "$RUST_BIN" --test-threads=1 dns_config::tests::dns_bootstrap_vectors_differential --exact \
    >"$TEMP/r-vectors.log" 2>&1

python3 - "$TEMP/c-vectors.json" "$TEMP/r-vectors.txt" <<'PY'
import json
import sys
c = json.load(open(sys.argv[1], encoding="utf-8"))
lines = []
for e in c["encode"]:
    lines.append("E|%s|%d|%s" % (e["name"], 1 if e["ok"] else 0, e["hex"]))
for s in c["skip"]:
    lines.append("S|%s|%d|%s" % (s["case"], 1 if s["ok"] else 0, s["offset"]))
for r in c["response"]:
    lines.append("R|%s|%d|%s" % (r["case"], 1 if r["ok"] else 0, r["ip"]))
r = open(sys.argv[2], encoding="utf-8").read().splitlines()
if lines != r:
    for left, right in zip(lines, r):
        if left != right:
            print("C:", left)
            print("R:", right)
            break
    raise SystemExit(1)
print("PASS: dns bootstrap encode/skip/response C/Rust match")
PY

cp "$RUST_BIN" "$TEMP/r2k_core_dns_bootstrap"
cat >"$TEMP/loopback.sh" <<EOF
#!/bin/sh
ip link set lo up
"$TEMP/d2o-dns-bootstrap" --loopback >"$TEMP/c-loopback.txt"
R2O_DNS_BOOTSTRAP_LOOPBACK="$TEMP/r-loopback.txt" "$TEMP/r2k_core_dns_bootstrap" --test-threads=1 dns_config::tests::dns_bootstrap_loopback --ignored --exact >"$TEMP/r-loopback.log" 2>&1
EOF
chmod +x "$TEMP/loopback.sh"
if ! unshare -Urn "$TEMP/loopback.sh"; then
    printf 'FAIL: unshare -Urn для loopback UDP/53 недоступен\n' >&2
    exit 2
fi
diff -u "$TEMP/c-loopback.txt" "$TEMP/r-loopback.txt"
printf 'PASS: dns bootstrap loopback A/IP-literal/invalid C/Rust match\n'
printf 'vectors=%s\n' "$(wc -l <"$TEMP/r-vectors.txt")"
