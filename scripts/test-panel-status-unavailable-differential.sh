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
TEMP=$(mktemp -d "$TEMP_BASE/r2o-panel-status-unavailable.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
cargo_manifest=$TEMP/rust/Cargo.toml
d2o_json=$TEMP/d2o.json
if command -v cygpath >/dev/null 2>&1; then
    cargo_manifest=$(cygpath -w "$cargo_manifest")
    d2o_json=$(cygpath -w "$d2o_json")
fi

"$CC" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-status" \
    "$ROOT/crates/r2o-panel/tests/d2o_status_unavailable.c"
"$TEMP/d2o-status" "$TEMP/missing-live.json" > "$TEMP/d2o.json"

mkdir -p "$TEMP/rust/src"
cat > "$TEMP/rust/Cargo.toml" <<'EOF'
[package]
name = "r2o-panel-status-unavailable-differential"
version = "0.1.0"
edition = "2024"

[dependencies]
serde_json = "1"
EOF
cat > "$TEMP/rust/src/main.rs" <<'EOF'
use serde_json::{Value, json};

EOF
sed -n '/^fn unavailable_knowledge()/,/^}/p' "$ROOT/crates/r2o-panel/src/server.rs" \
    >> "$TEMP/rust/src/main.rs"
cat >> "$TEMP/rust/src/main.rs" <<'EOF'

fn main() {
    let expected: Value = serde_json::from_slice(
        &std::fs::read(std::env::args_os().nth(1).expect("D2O JSON path")).unwrap(),
    )
    .unwrap();
    let (actual, _, _) = unavailable_knowledge();
    assert_eq!(expected["knowledge"], actual);
    println!("STATUS|match");
}
EOF

RUSTFLAGS="${RUSTFLAGS:--Awarnings}" \
    "$CARGO" run --quiet --offline --manifest-path "$cargo_manifest" -- \
        "$d2o_json"
printf 'C/Rust unavailable panel status JSON matches D2O %s.\n' "$ACTUAL_D2O_SHA"
