#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
D2O_ROOT=${D2O_ROOT:-"$ROOT/d2o"}
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/target"}
WORK_ROOT=${R2O_TEST_WORK_ROOT:-"$TARGET_DIR/test-work"}

for test_path in "$D2O_ROOT/datapath/sched.c" "$D2O_ROOT/datapath/include/d2k_sched.h" \
    "$SCRIPT_DIR/fixtures/d2o-scheduled-udp-fixture.c"; do
    if [ ! -f "$test_path" ]; then
        echo "не найден исходник differential: $test_path" >&2
        exit 1
    fi
done

mkdir -p "$WORK_ROOT"
WORK=$(mktemp -d "$WORK_ROOT/discord-sched-udp-diff.XXXXXX")
cleanup() {
    test_status=$?
    trap - EXIT HUP INT TERM
    case "$WORK" in
        "$WORK_ROOT"/discord-sched-udp-diff.*)
            if [ "$test_status" -eq 0 ]; then
                rm -rf "$WORK"
            else
                echo "сохранены журналы C/Rust scheduler differential: $WORK" >&2
            fi
            ;;
        *)
            echo "небезопасный временный путь differential: $WORK" >&2
            test_status=1
            ;;
    esac
    exit "$test_status"
}
trap cleanup EXIT HUP INT TERM

cc -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" \
    "$SCRIPT_DIR/fixtures/d2o-scheduled-udp-fixture.c" \
    "$D2O_ROOT/datapath/sched.c" -o "$WORK/d2o-scheduler"
C_RESULT=$("$WORK/d2o-scheduler")
if ! cargo test --locked --offline -p r2o-datapath --lib \
    delayed_udp_emit_survives_observing_the_reverse_packet -- --nocapture \
    >"$WORK/rust.log" 2>&1; then
    cat "$WORK/rust.log" >&2
    exit 1
fi
RUST_RESULT=$(grep -Eo 'RESULT delay_us=15000 packet=[0-9a-f]+' "$WORK/rust.log" | tail -n 1)
if [ -z "$RUST_RESULT" ]; then
    cat "$WORK/rust.log" >&2
    echo "Rust scheduler test did not emit its normalized result" >&2
    exit 1
fi
if [ "$C_RESULT" != "$RUST_RESULT" ]; then
    printf 'D2O: %s\nR2O: %s\n' "$C_RESULT" "$RUST_RESULT" >&2
    exit 1
fi
printf 'D2O: %s\nR2O: %s\n' "$C_RESULT" "$RUST_RESULT"
echo "ПРОЙДЕНО: C и Rust сохранили один UDP emit после обратного пакета"
