#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

donor_core="$donor_root/core"
fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_catalog_sync_wire.json"
batch_fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_catalog_sync_batch.json"
area_pending_fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_catalog_sync_area_pending.json"
area_timeout_fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_catalog_sync_area_timeout.json"
area_delete_order_fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_catalog_sync_area_delete_order.json"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-catalog-sync.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

make -s -B -C "$donor_core" test_catalog_sync httpsearch.o httpup_logic.o CC=clang-18
donor_objects=$(make -s -C "$donor_core" \
    --eval='print-donor-objects:;@echo $(SRC:.c=.o)' print-donor-objects)
(
    cd "$donor_core"
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror \
        -Iinclude -I"$donor_root/datapath/include" \
        "$repo_root/crates/r2o-controller/tests/d2o_catalog_sync_wire_fixture.c" \
        $donor_objects httpsearch.o httpup_logic.o libd2k_udp.a -lpthread -o "$tmp_dir/donor-catalog-wire"
)

"$tmp_dir/donor-catalog-wire" "$fixture" 1280 >"$tmp_dir/c.out"
if ! cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    catalog_sync_shared_donor_file_preserves_install_order -- --nocapture >"$tmp_dir/rust.log" 2>&1; then
    cat "$tmp_dir/rust.log" >&2
    exit 1
fi
grep '^D2O_CATALOG_OP=' "$tmp_dir/rust.log" >"$tmp_dir/rust.out"
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
"$tmp_dir/donor-catalog-wire" "$batch_fixture" 1280 --first-batch >"$tmp_dir/c.batch"
if ! cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    catalog_sync_sends_eight_commands_without_waiting_for_ack -- --nocapture \
    >"$tmp_dir/rust.batch.log" 2>&1; then
    cat "$tmp_dir/rust.batch.log" >&2
    exit 1
fi
grep '^D2O_CATALOG_BATCH_OP=' "$tmp_dir/c.batch" >"$tmp_dir/c.batch.ops"
grep '^D2O_CATALOG_BATCH_OP=' "$tmp_dir/rust.batch.log" >"$tmp_dir/rust.batch.ops"
diff -u "$tmp_dir/c.batch.ops" "$tmp_dir/rust.batch.ops"
grep -q '^D2O_CATALOG_BATCH_COUNT=8$' "$tmp_dir/c.batch"
grep -q '^D2O_CATALOG_BATCH_COUNT=8$' "$tmp_dir/rust.batch.log"
"$tmp_dir/donor-catalog-wire" --area-wire >"$tmp_dir/c.area"
if ! cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    catalog_area_command_wire_matches_donor -- --nocapture >"$tmp_dir/rust.area.log" 2>&1; then
    cat "$tmp_dir/rust.area.log" >&2
    exit 1
fi
grep '^D2O_AREA_COMMAND=' "$tmp_dir/rust.area.log" >"$tmp_dir/rust.area"
diff -u "$tmp_dir/c.area" "$tmp_dir/rust.area"
"$tmp_dir/donor-catalog-wire" "$area_pending_fixture" 1280 --area-pending >"$tmp_dir/c.area-pending"
if ! cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    catalog_sync_area_command_yields_pending_like_donor -- --nocapture \
    >"$tmp_dir/rust.area-pending.log" 2>&1; then
    cat "$tmp_dir/rust.area-pending.log" >&2
    exit 1
fi
grep '^D2O_AREA_PENDING=' "$tmp_dir/c.area-pending" >"$tmp_dir/c.area-pending.state"
grep '^D2O_AREA_PENDING=' "$tmp_dir/rust.area-pending.log" >"$tmp_dir/rust.area-pending.state"
grep '^D2O_AREA_COMMAND=' "$tmp_dir/c.area-pending" >"$tmp_dir/c.area-pending.command"
grep '^D2O_AREA_COMMAND=' "$tmp_dir/rust.area-pending.log" >"$tmp_dir/rust.area-pending.command"
diff -u "$tmp_dir/c.area-pending.state" "$tmp_dir/rust.area-pending.state"
diff -u "$tmp_dir/c.area-pending.command" "$tmp_dir/rust.area-pending.command"
"$tmp_dir/donor-catalog-wire" "$area_pending_fixture" 1280 --area-timeout >"$tmp_dir/c.area-timeout"
if ! cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    catalog_sync_area_ack_expires_at_five_seconds_like_donor -- --nocapture \
    >"$tmp_dir/rust.area-timeout.log" 2>&1; then
    cat "$tmp_dir/rust.area-timeout.log" >&2
    exit 1
fi
grep '^D2O_AREA_TIMEOUT=' "$tmp_dir/c.area-timeout" >"$tmp_dir/c.area-timeout.state"
grep '^D2O_AREA_TIMEOUT=' "$tmp_dir/rust.area-timeout.log" >"$tmp_dir/rust.area-timeout.state"
diff -u "$tmp_dir/c.area-timeout.state" "$tmp_dir/rust.area-timeout.state"
"$tmp_dir/donor-catalog-wire" "$area_timeout_fixture" 1280 --area-timeout-delete >"$tmp_dir/c.area-timeout-delete"
if ! cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    catalog_sync_removes_area_after_lost_install_ack_like_donor -- --nocapture \
    >"$tmp_dir/rust.area-timeout-delete.log" 2>&1; then
    cat "$tmp_dir/rust.area-timeout-delete.log" >&2
    exit 1
fi
grep '^D2O_AREA_TIMEOUT_DELETE=' "$tmp_dir/c.area-timeout-delete" >"$tmp_dir/c.area-timeout-delete.state"
grep '^D2O_AREA_TIMEOUT_DELETE=' "$tmp_dir/rust.area-timeout-delete.log" >"$tmp_dir/rust.area-timeout-delete.state"
grep '^D2O_AREA_DELETE_COMMAND=' "$tmp_dir/c.area-timeout-delete" >"$tmp_dir/c.area-timeout-delete.command"
grep '^D2O_AREA_DELETE_COMMAND=' "$tmp_dir/rust.area-timeout-delete.log" >"$tmp_dir/rust.area-timeout-delete.command"
diff -u "$tmp_dir/c.area-timeout-delete.state" "$tmp_dir/rust.area-timeout-delete.state"
diff -u "$tmp_dir/c.area-timeout-delete.command" "$tmp_dir/rust.area-timeout-delete.command"
"$tmp_dir/donor-catalog-wire" "$area_delete_order_fixture" 1280 --area-delete-order >"$tmp_dir/c.area-delete-order"
if ! cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    catalog_sync_delete_ack_order_uses_donor_swap_remove -- --nocapture \
    >"$tmp_dir/rust.area-delete-order.log" 2>&1; then
    cat "$tmp_dir/rust.area-delete-order.log" >&2
    exit 1
fi
grep '^D2O_AREA_DELETE_' "$tmp_dir/c.area-delete-order" >"$tmp_dir/c.area-delete-order.out"
grep '^D2O_AREA_DELETE_' "$tmp_dir/rust.area-delete-order.log" >"$tmp_dir/rust.area-delete-order.out"
diff -u "$tmp_dir/c.area-delete-order.out" "$tmp_dir/rust.area-delete-order.out"
"$tmp_dir/donor-catalog-wire" --http-bound-set >"$tmp_dir/c.http-bound"
if ! cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    confirmed_http_install_returns_before_ack_and_records_exact_late_ack -- --nocapture \
    >"$tmp_dir/rust.http-bound.log" 2>&1; then
    cat "$tmp_dir/rust.http-bound.log" >&2
    exit 1
fi
grep '^D2O_HTTP_BOUND_SET=' "$tmp_dir/rust.http-bound.log" >"$tmp_dir/rust.http-bound"
diff -u "$tmp_dir/c.http-bound" "$tmp_dir/rust.http-bound"
"$tmp_dir/donor-catalog-wire" --http-bound-del >"$tmp_dir/c.http-bound-del"
if ! cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    http_bound_delete_wire_matches_donor -- --nocapture >"$tmp_dir/rust.http-bound-del.log" 2>&1; then
    cat "$tmp_dir/rust.http-bound-del.log" >&2
    exit 1
fi
grep '^D2O_HTTP_BOUND_DEL=' "$tmp_dir/rust.http-bound-del.log" >"$tmp_dir/rust.http-bound-del"
diff -u "$tmp_dir/c.http-bound-del" "$tmp_dir/rust.http-bound-del"
printf 'C d2k_sched_sync_step and Rust catalog install order match on shared fixture\n'
cat "$tmp_dir/c.out"
printf 'C/Rust first catalog batch: 8 commands without waiting for acknowledgements\n'
cat "$tmp_dir/c.batch.ops"
printf 'C/Rust identified area command wire frame matches\n'
cat "$tmp_dir/c.area"
printf 'C/Rust area command remains pending and yields before its ACK\n'
cat "$tmp_dir/c.area-pending"
printf 'C/Rust area ACK deadline is five seconds with the same pending transition\n'
cat "$tmp_dir/c.area-timeout"
printf 'C/Rust uncertain area install is deleted after the catalog disables its group\n'
cat "$tmp_dir/c.area-timeout-delete"
printf 'C/Rust deletion ACKs keep the donor swap-with-last area order\n'
cat "$tmp_dir/c.area-delete-order"
printf 'C/Rust asynchronous HTTP bound-install command frame matches\n'
cat "$tmp_dir/c.http-bound"
printf 'C/Rust conditional HTTP bound-delete command frame matches\n'
cat "$tmp_dir/c.http-bound-del"
