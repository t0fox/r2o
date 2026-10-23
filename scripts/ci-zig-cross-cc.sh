#!/bin/sh
set -eu

test -n "$ZIG" || { echo 'setup-zig action must set ZIG' >&2; exit 1; }
test -n "$ZIG_TARGET" || { echo 'set ZIG_TARGET to the Zig target triple' >&2; exit 1; }

# cc-rs passes the Rust target spelling, which Zig does not always accept.
if [ -n "${ZIG_SYSROOT:-}" ]; then
    set -- "$@" "--sysroot=$ZIG_SYSROOT"
fi
exec "$ZIG" cc "$@" -target "$ZIG_TARGET"
