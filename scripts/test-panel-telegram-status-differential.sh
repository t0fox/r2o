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
TEMP=$(mktemp -d "$TEMP_BASE/r2o-panel-telegram-status.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
CC=${CC:-cc}
RUSTC=${RUSTC:-rustc}
rust_source=$TEMP/main.rs
rust_binary=$TEMP/telegram-status-rust.exe
rust_source_arg=$rust_source
rust_binary_arg=$rust_binary
status_path=$TEMP/status
pid_path=$TEMP/no.pid

if command -v cygpath >/dev/null 2>&1; then
    rust_source_arg=$(cygpath -w "$rust_source")
    rust_binary_arg=$(cygpath -w "$rust_binary")
fi

"$CC" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-status" \
    "$ROOT/crates/r2o-panel/tests/d2o_telegram_status.c"

cat > "$TEMP/main.rs" <<'EOF'
use std::path::{Path, PathBuf};

struct Config {
    telegram_status_path: PathBuf,
}

fn read_regular_file(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "too large"));
    }
    Ok(bytes)
}

EOF
sed -n '/^fn telegram_status(/,/^}/p' "$ROOT/crates/r2o-panel/src/server.rs" \
    >> "$TEMP/main.rs"
cat >> "$TEMP/main.rs" <<'EOF'

fn main() {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().expect("status path");
    let running = args.next().expect("running flag") == "1";
    let config = Config { telegram_status_path: PathBuf::from(path) };
    println!("{}|{}", telegram_status(&config, true, true, running), u8::from(running));
}
EOF

"$RUSTC" --edition=2024 -Awarnings "$rust_source_arg" -o "$rust_binary_arg"

rust_status_path=$status_path
rust_pid_path=$pid_path
if command -v cygpath >/dev/null 2>&1; then
    rust_status_path=$(cygpath -w "$rust_status_path")
    rust_pid_path=$(cygpath -w "$rust_pid_path")
fi

for state in error not_configured; do
    printf '%s\n' "$state" > "$status_path"
    c_result=$("$TEMP/d2o-status" "$pid_path" "$status_path" 0)
    r_result=$("$rust_binary" "$rust_status_path" 0)
    if [ "$c_result" != "$r_result" ]; then
        printf 'RED stopped_state=%s C=%s Rust=%s\n' "$state" "$c_result" "$r_result" >&2
        exit 1
    fi
    printf 'STATUS|stopped|%s|%s\n' "$state" "$r_result"
done

printf ' connected\n' > "$status_path"
c_result=$("$TEMP/d2o-status" "$pid_path" "$status_path" 1)
r_result=$("$rust_binary" "$rust_status_path" 1)
if [ "$c_result" != "$r_result" ]; then
    printf 'RED running_state=leading-space C=%s Rust=%s\n' "$c_result" "$r_result" >&2
    exit 1
fi
printf 'STATUS|running|leading-space|%s\n' "$r_result"

printf 'C/Rust Telegram status edge cases match D2O %s.\n' "$ACTUAL_D2O_SHA"
