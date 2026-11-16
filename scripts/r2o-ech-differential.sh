#!/bin/sh
# C/Rust differential: ECH-контракты core-net.
# C: production tls13.c (d2k_tls_connect_ech/d2k_tls_ech_accepted) + verify.o
#    (d2k_verify_probe_ech_on/d2k_verify_probe_ech_origin_on) на loopback.
# Rust: production r2o_tls_ech_* и r2o_verify_probe_ech_*.
# HTTPS-RR для origin_on отдаёт локальный DNS; фикстура запускается в
# одноразовом network/mount namespace, чтобы 127.0.0.1:53 и /etc/resolv.conf
# не трогали хост.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_D2O_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-gcc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi
for tool in "$CC" "$CARGO" unshare ip mount; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing required command: %s\n' "$tool" >&2
        exit 127
    }
done

TEMP=$(mktemp -d "$TMPDIR/r2o-ech.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

# tls13.c переопределяет _POSIX_C_SOURCE; для fixture это предупреждение.
make -s -C "$D2O_ROOT/core" test_ech CC="$CC" >/dev/null
(
    cd "$D2O_ROOT/core"
    "$CC" -std=gnu11 -O2 -Wall -Wextra \
        -ffunction-sections -fdata-sections \
        -I. -Iinclude -I../datapath/include \
        -o "$TEMP/c" \
        "$ROOT/crates/r2o-controller/tests/d2o_ech_differential.c" \
        verify.o tls12.o p256.o quicconn.o quicwire.o h3.o compose.o \
        measured.o hello.o meas.o link.o tls13core.o x25519.o crypto.o \
        diagnostics.o -Wl,--gc-sections -lpthread -lm >"$TEMP/build.log" 2>&1
) || {
    cat "$TEMP/build.log" >&2
    exit 1
}

printf 'nameserver 127.0.0.1\n' >"$TEMP/resolv.conf"
chmod 644 "$TEMP/resolv.conf"
if [ "${R2O_ECH_PRIVILEGED_NETNS:-0}" = 1 ]; then
    set -- sudo unshare --mount --net --propagation private
else
    set -- unshare -rmn
fi
"$@" sh -c '
    ip link set lo up || exit 1
    mount --bind "$1" /etc/resolv.conf || exit 1
    "$2"
' sh "$TEMP/resolv.conf" "$TEMP/c" >"$TEMP/c.out"

R2O_ECH_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --test d2o_ech_differential \
    ech_contracts_match_c_fixture -- --exact >"$TEMP/rust.log" 2>&1
if [ ! -f "$TEMP/rust.out" ]; then
    cat "$TEMP/rust.log" >&2
    echo "Rust-тест не записал трассу" >&2
    exit 1
fi
diff -u "$TEMP/c.out" "$TEMP/rust.out"
cat "$TEMP/c.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: ECH contracts match C tls13.c/verify.c (D2O %s).\n' "$ACTUAL_D2O_SHA"
