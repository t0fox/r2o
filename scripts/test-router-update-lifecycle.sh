#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
# Два слота и подменяемые службы проверяются через настоящий Rust CLI.
cargo test --locked -p r2o-manager --test cli router_update_recovers_after_kill_and_preserves_operator_data
