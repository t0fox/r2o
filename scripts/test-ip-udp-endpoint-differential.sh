#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
donor=${R2O_D2K_ROOT:?укажите чистый checkout D2K e5ae90a6}
expected=e5ae90a6c371008db4db14051fd283c40071fcc4
[ "$(git -C "$donor" rev-parse HEAD)" = "$expected" ]
git -C "$donor" diff --quiet HEAD -- core/link.c core/ipfrag.c core/stun.c core/include datapath/include
temp=$(mktemp -d)
trap 'rm -rf -- "$temp"' EXIT HUP INT TERM

# Из production link.c компонуются только функции отправки команд endpoint.
"${CC:-cc}" -std=c11 -O2 -ffunction-sections -fdata-sections -Wl,--gc-sections -DD2K_RELEASE_ID='"endpoint-oracle"' \
    -I"$donor/core/include" -I"$donor/datapath/include" \
    "$root/crates/r2k-core/tests/d2k_udp_endpoint_trace.c" "$donor/core/link.c" \
    -o "$temp/endpoint-c"
"$temp/endpoint-c" > "$temp/oracle.txt"
R2O_D2K_UDP_ENDPOINT_TRACE="$temp/oracle.txt" "${CARGO:-cargo}" test --locked \
    --manifest-path "$root/Cargo.toml" -p r2k-core --test control \
    d2k_udp_endpoint_совпадает_по_ipv4_и_ipv6 -- --ignored

"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -I"$donor/core/include" \
    "$root/crates/r2o-datapath/tests/d2k_stun_fragments.c" "$donor/core/ipfrag.c" \
    -o "$temp/fragments-c"
"$temp/fragments-c" > "$temp/fragments.txt"
R2O_D2K_STUN_FRAGMENTS="$temp/fragments.txt" "${CARGO:-cargo}" test --locked \
    --manifest-path "$root/Cargo.toml" -p r2o-datapath --test stun_endpoint

"${CC:-cc}" -std=c11 -O2 -ffunction-sections -Wl,--gc-sections -I"$donor/core/include" \
    "$root/crates/r2k-core/tests/d2k_stun_binding_trace.c" "$donor/core/stun.c" \
    -o "$temp/stun-binding-c"
R2O_D2K_STUN_BINDING_ORACLE="$temp/stun-binding-c" "${CARGO:-cargo}" test --locked \
    --manifest-path "$root/Cargo.toml" -p r2k-core --test stun проверка_stun_binding_совпадает_с_d2k
