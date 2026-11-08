#!/bin/sh
# B10: real-kernel nft differential: C D2O generator and R2O generator are
# applied by the actual nft binary in separate user+network namespaces.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-b10-nft.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

# GitHub runner запрещает unprivileged user namespaces. Под sudo достаточно
# network namespace; локально без root используем user+network namespace.
run_unshare() {
    if [ "$(id -u)" -eq 0 ]; then
        unshare -n "$@"
    else
        unshare -Urn "$@"
    fi
}
run_unshare sh "$ROOT/scripts/fixtures/d2o-nft-real-trace.sh" "$D2O_ROOT" "$TEMP" >"$TEMP/c.out"
run_unshare sh "$ROOT/scripts/fixtures/r2o-nft-real-trace.sh" "$ROOT" "$TEMP" >"$TEMP/r.out"

canonical() {
    rules=$1
    for chain in out in_rules forward input nat_post; do
        case "$chain" in
            forward)
                grep -Eq 'chain (forward|in_forward) \{' "$rules" &&
                    echo "chain forward" || echo "missing-chain forward"
                ;;
            input)
                grep -Eq 'chain (input|in_input) \{' "$rules" &&
                    echo "chain input" || echo "missing-chain input"
                ;;
            *)
                grep -q "chain $chain {" "$rules" &&
                    echo "chain $chain" || echo "missing-chain $chain"
                ;;
        esac
    done
    grep -Fq 'type filter hook postrouting priority mangle;' "$rules" &&
        echo "hook-postrouting" || echo "missing-hook-postrouting"
    grep -Fq 'type filter hook forward priority mangle;' "$rules" &&
        echo "hook-forward" || echo "missing-hook-forward"
    grep -Fq 'type filter hook input priority mangle;' "$rules" &&
        echo "hook-input" || echo "missing-hook-input"
    grep -Fq 'type nat hook postrouting priority srcnat - 1;' "$rules" &&
        echo "hook-nat" || echo "missing-hook-nat"
    echo "queue4=$(grep 'queue flags bypass to 2000' "$rules" | grep -v icmpv6 | wc -l | tr -d ' ')"
    grep -Fq masquerade "$rules" && echo "masquerade=1" || echo "masquerade=0"
    grep -Eq 'meta mark 0x0*2d return' "$rules" && echo "mark-return=1" || echo "mark-return=0"
}

canonical "$TEMP/c-rules" >"$TEMP/c.canon"
canonical "$TEMP/r2o-rules" >"$TEMP/r.canon"

for field in up installed rst_table main_down rst_down main_present rst_present; do
    c_value=$(sed -n "s/^$field=//p" "$TEMP/c.out")
    r_value=$(sed -n "s/^$field=//p" "$TEMP/r.out")
    if [ "$c_value" != "$r_value" ]; then
        printf 'FAIL: %s C=%s Rust=%s\n' "$field" "$c_value" "$r_value" >&2
        exit 1
    fi
done
if ! diff -u "$TEMP/c.canon" "$TEMP/r.canon"; then
    printf 'FAIL: nft postconditions differ\n' >&2
    exit 1
fi
c_queue4=$(sed -n 's/^queue4=//p' "$TEMP/c.canon")
[ "$c_queue4" -gt 0 ] || {
    printf 'FAIL: shared IPv4 queue rules were not installed\n' >&2
    exit 1
}
# IPv6-очередь — расширение R2O (D2O nfq.c привязывает только AF_INET);
# в общий IPv4-контракт она не входит, но должна реально стоять.
r_queue6=$(grep 'queue flags bypass to 2001' "$TEMP/r2o-rules" | wc -l | tr -d ' ')
[ "$r_queue6" -gt 0 ] || {
    printf 'FAIL: R2O IPv6 queue rules were not installed\n' >&2
    exit 1
}

printf 'postconditions: %s ipv6-queue=%s\n' \
    "$(tr '\n' ' ' <"$TEMP/c.canon")" "$r_queue6"
printf 'PASS: real nft accepts both generators; shared IPv4 postconditions match (D2O %s)\n' "$ACTUAL_D2O_SHA"
