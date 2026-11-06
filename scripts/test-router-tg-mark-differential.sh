#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=8e2c98146cf0b712dc967fbec558c7b904666e87
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
}

d2o_socket_mark=$(sed -n 's/^#define TG_OUTBOUND_SOCKET_MARK[[:space:]]\+\(0x[[:xdigit:]]\+\)u$/\1/p' \
    "$D2O_ROOT/telegram/include/tg_config.h")
d2o_firewall_mark=$(sed -n 's/^OUTBOUND_MARK=//p' "$D2O_ROOT/files/d2k-tg-firewall.sh")
r2o_socket_mark=$(sed -n 's/.*with_socket_mark(Some(\(0x[[:xdigit:]]\+\))).*/\1/p' \
    "$ROOT/crates/r2o-telegram/src/config.rs")
r2o_firewall_mark=$(sed -n 's/^OUTBOUND_MARK=//p' "$ROOT/router/r2o-tg-firewall.sh")
r2o_legacy_mark=$(sed -n 's/^LEGACY_OUTBOUND_MARK=//p' "$ROOT/router/r2o-tg-firewall.sh")

for value in "$d2o_socket_mark" "$d2o_firewall_mark" "$r2o_socket_mark" "$r2o_firewall_mark"; do
    [ -n "$value" ] || { echo 'could not read a production Telegram outbound mark' >&2; exit 1; }
done
[ "$d2o_socket_mark" = "$d2o_firewall_mark" ] || {
    printf 'D2O Telegram socket/firewall marks differ: %s vs %s\n' "$d2o_socket_mark" "$d2o_firewall_mark" >&2
    exit 1
}
[ "$d2o_socket_mark" = "$r2o_socket_mark" ] && [ "$d2o_socket_mark" = "$r2o_firewall_mark" ] || {
    printf 'D2O/R2O Telegram marks differ: D2O=%s/%s R2O=%s/%s\n' \
        "$d2o_socket_mark" "$d2o_firewall_mark" "$r2o_socket_mark" "$r2o_firewall_mark" >&2
    exit 1
}
[ "$r2o_legacy_mark" = 0x40000000 ] || {
    printf 'R2O no longer recognizes its previous outbound mark: %s\n' "$r2o_legacy_mark" >&2
    exit 1
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-tg-mark.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
sed -n '/^fw_family_up() (/,/^)/p' "$D2O_ROOT/files/S99d2k" > "$TEMP/d2o-fw.sh"
sed -n '/^xt_family_up() {/,/^}/p' "$ROOT/router/r2o-firewall.sh" > "$TEMP/r2o-fw.sh"
if grep -Eq '0x31|TG_OUTBOUND' "$TEMP/d2o-fw.sh" "$TEMP/r2o-fw.sh"; then
    echo 'main datapath firewall unexpectedly exempts Telegram outbound traffic' >&2
    exit 1
fi

printf 'D2O/R2O Telegram socket and NAT exemption use mark %s; the main datapath queues that traffic and legacy R2O mark cleanup remains enabled.\n' "$d2o_socket_mark"
