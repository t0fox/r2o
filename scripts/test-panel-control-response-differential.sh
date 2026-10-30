#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_root=${R2O_DONOR_ROOT:-${r2o_script_dir%/*}/d2o}
r2o_expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
r2o_actual_donor_sha=$(git -C "$r2o_donor_root" rev-parse HEAD)
if [ "$r2o_actual_donor_sha" != "$r2o_expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$r2o_expected_donor_sha" "$r2o_actual_donor_sha" >&2
    exit 2
fi

r2o_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-panel-control.XXXXXX")
trap 'rm -rf -- "$r2o_tmp_dir"' EXIT
r2o_service="$r2o_tmp_dir/service"
cat >"$r2o_service" <<'SERVICE'
#!/bin/sh
sleep 1
SERVICE
chmod 700 "$r2o_service"

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$r2o_donor_root/panel" \
    "$r2o_script_dir/crates/r2o-panel/tests/d2o_control_response.c" \
    "$r2o_donor_root/panel/server.c" \
    -o "$r2o_tmp_dir/d2o-panel-control"
R2O_PANEL_CONTROL_SERVICE="$r2o_service" \
    "$r2o_tmp_dir/d2o-panel-control" >"$r2o_tmp_dir/c.trace"

if R2O_PANEL_CONTROL_SERVICE="$r2o_service" \
    R2O_PANEL_CONTROL_C_TRACE="$r2o_tmp_dir/c.trace" \
    R2O_PANEL_CONTROL_TRACE_OUTPUT="$r2o_tmp_dir/rust.trace" \
    cargo test -p r2o-panel --test http --locked --offline \
        d2o_control_action_response_trace -- --ignored --nocapture; then
    r2o_rust_status=0
else
    r2o_rust_status=$?
fi
[ -f "$r2o_tmp_dir/rust.trace" ] || {
    printf 'Rust panel control test produced no trace.\n' >&2
    exit "$r2o_rust_status"
}
[ "$r2o_rust_status" -eq 0 ] || exit "$r2o_rust_status"
printf 'C/Rust panel control responses match d2o %s.\n' \
    "$r2o_actual_donor_sha"
