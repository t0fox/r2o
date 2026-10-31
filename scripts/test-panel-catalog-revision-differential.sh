#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP_BASE=${R2O_TEST_TMP:-${ROOT%/*}/r2o-tooling/tmp}
if [ ! -d "$TEMP_BASE" ]; then
    TEMP_BASE=${TMPDIR:-/tmp}
fi
TEMP=$(mktemp -d "$TEMP_BASE/r2o-panel-catalog-revision.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
CC=${CC:-cc}
CARGO=${CARGO:-cargo}

cat > "$TEMP/live.json" <<'JSON'
{
  "linked": true,
  "catalog_at": "fixture",
  "boxes": [
    { "id": "one", "wins": 2 },
    { "id": "two", "wins": 3 }
  ],
  "groups" : [ { "suffix" : "example.test" } ]
}
JSON
"$CC" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-revision" \
    "$ROOT/crates/r2o-panel/tests/d2o_catalog_revision.c"
c_revision=$("$TEMP/d2o-revision" "$TEMP/live.json")

mkdir -p "$TEMP/rust/src"
cat > "$TEMP/rust/Cargo.toml" <<'EOF'
[package]
name = "r2o-panel-catalog-revision-differential"
version = "0.1.0"
edition = "2024"

[dependencies]
serde_json = "1"
EOF
cat > "$TEMP/rust/src/main.rs" <<'EOF'
EOF
sed -n '/^fn catalog_revision(/,/^}/p' "$ROOT/crates/r2o-panel/src/server.rs" \
    >> "$TEMP/rust/src/main.rs"
sed -n '/^fn top_level_raw_value/,/^}/p' "$ROOT/crates/r2o-panel/src/server.rs" \
    >> "$TEMP/rust/src/main.rs"
sed -n '/^fn skip_ws(/,/^}/p' "$ROOT/crates/r2o-panel/src/server.rs" \
    >> "$TEMP/rust/src/main.rs"
sed -n '/^fn scan_string(/,/^}/p' "$ROOT/crates/r2o-panel/src/server.rs" \
    >> "$TEMP/rust/src/main.rs"
sed -n '/^fn scan_json_value(/,/^}/p' "$ROOT/crates/r2o-panel/src/server.rs" \
    >> "$TEMP/rust/src/main.rs"
cat >> "$TEMP/rust/src/main.rs" <<'EOF'

fn main() {
    let raw = std::fs::read(std::env::args_os().nth(1).expect("D2O live path")).unwrap();
    println!("{}", catalog_revision(&raw).unwrap());
}
EOF

manifest=$TEMP/rust/Cargo.toml
live=$TEMP/live.json
if command -v cygpath >/dev/null 2>&1; then
    manifest=$(cygpath -w "$manifest")
    live=$(cygpath -w "$live")
fi
r_revision=$(RUSTFLAGS="${RUSTFLAGS:--Awarnings}" \
    "$CARGO" run --quiet --offline --manifest-path "$manifest" -- "$live")

if [ "$c_revision" != "$r_revision" ]; then
    printf 'RED D2O=%s R2O=%s\n' "$c_revision" "$r_revision" >&2
    exit 1
fi
printf 'REVISION|match|%s\n' "$c_revision"
