#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor=${R2O_DONOR_DATAPATH:-"${r2o_script_dir%/*}/d2o/datapath"}
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-tcp-payload-stats-$(date +%Y%m%d-%H%M%S).log"
r2o_harness="$r2o_log_dir/r2o-tcp-payload-stats-donor.c"
r2o_oracle="$r2o_log_dir/r2o-tcp-payload-stats-donor-arm64"
mkdir -p "$r2o_log_dir"

r2o_show_log_on_error() {
    r2o_status=$?
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_log" ]; then
        cat "$r2o_log"
    fi
}
trap r2o_show_log_on_error EXIT

if [ ! -d "$r2o_donor" ]; then
    printf 'Не найден каталог исходников донора: %s\n' "$r2o_donor" >&2
    exit 2
fi

cat >"$r2o_harness" <<'C'
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "d2k_session.h"

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static size_t tcp_packet(uint8_t *p, const uint8_t src[4], const uint8_t dst[4],
                         uint16_t sport, uint16_t dport, uint8_t flags,
                         uint32_t seq, const uint8_t *payload, size_t payload_len) {
    size_t total = 40 + payload_len;
    memset(p, 0, total);
    p[0] = 0x45;
    wr16(p + 2, (uint16_t)total);
    p[8] = 64;
    p[9] = 6;
    memcpy(p + 12, src, 4);
    memcpy(p + 16, dst, 4);
    wr16(p + 20, sport);
    wr16(p + 22, dport);
    wr32(p + 24, seq);
    p[32] = 0x50;
    p[33] = flags;
    wr16(p + 34, 4096);
    if (payload_len != 0) memcpy(p + 40, payload, payload_len);
    return total;
}

static uint64_t now_ns = 1;

static void feed(d2k_session *session, const uint8_t src[4], const uint8_t dst[4],
                 uint16_t sport, uint16_t dport, uint8_t flags,
                 uint32_t seq, const uint8_t *payload, size_t payload_len) {
    uint8_t packet[512], output[4096];
    d2k_result result;
    size_t length = tcp_packet(packet, src, dst, sport, dport, flags,
                               seq, payload, payload_len);
    (void)d2k_session_packet(session, packet, length, now_ns++, output,
                             sizeof output, &result);
}

static size_t incomplete_client_hello(uint8_t *p) {
    static const uint8_t host[] = "example.test";
    uint8_t body[96], extensions[32], sni[24], handshake[112];
    size_t sn = 0, en = 0, bn = 0, hn = 0;
    wr16(sni + sn, (uint16_t)(sizeof host - 1 + 3)); sn += 2;
    sni[sn++] = 0;
    wr16(sni + sn, (uint16_t)(sizeof host - 1)); sn += 2;
    memcpy(sni + sn, host, sizeof host - 1); sn += sizeof host - 1;
    wr16(extensions + en, 0); en += 2;
    wr16(extensions + en, (uint16_t)sn); en += 2;
    memcpy(extensions + en, sni, sn); en += sn;
    body[bn++] = 3; body[bn++] = 3;
    memset(body + bn, 0, 32); bn += 32;
    body[bn++] = 0;
    wr16(body + bn, 2); bn += 2;
    body[bn++] = 0x13; body[bn++] = 1;
    body[bn++] = 1; body[bn++] = 0;
    wr16(body + bn, (uint16_t)en); bn += 2;
    memcpy(body + bn, extensions, en); bn += en;
    handshake[hn++] = 1;
    handshake[hn++] = (uint8_t)(bn >> 16);
    handshake[hn++] = (uint8_t)(bn >> 8);
    handshake[hn++] = (uint8_t)bn;
    memcpy(handshake + hn, body, bn); hn += bn;
    p[0] = 0x16; p[1] = 3; p[2] = 3;
    wr16(p + 3, (uint16_t)hn);
    memcpy(p + 5, handshake, hn);
    return 60;
}

static size_t complete_client_hello(uint8_t *p) {
    p[0] = 0x16; p[1] = 3; p[2] = 3; wr16(p + 3, 47);
    p[5] = 1; p[6] = 0; p[7] = 0; p[8] = 43;
    p[9] = 3; p[10] = 3; memset(p + 11, 0, 32);
    p[43] = 0; p[44] = 0; p[45] = 2; p[46] = 0x13; p[47] = 1;
    p[48] = 1; p[49] = 0; p[50] = 0; p[51] = 0;
    return 52;
}

int main(void) {
    static const uint8_t client_a[4] = {192, 0, 2, 10};
    static const uint8_t client_b[4] = {192, 0, 2, 10};
    static const uint8_t client_c[4] = {192, 0, 2, 10};
    static const uint8_t server[4] = {198, 51, 100, 20};
    static const uint8_t not_hello[3] = {0x16, 3, 3};
    static const uint8_t reply[3] = {0x17, 3, 3};
    static const uint8_t later_payload[3] = {1, 2, 3};
    static const uint8_t request[] =
        "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    uint8_t hello[128];
    uint8_t full_hello[64];
    d2k_session *session = d2k_session_new(64, 64);
    if (!session) return 2;

    feed(session, client_a, server, 41000, 443, 0x02, 1000, NULL, 0);
    feed(session, server, client_a, 443, 41000, 0x12, 900, NULL, 0);
    feed(session, client_a, server, 41000, 443, 0x10, 1001, NULL, 0);
    for (uint32_t i = 0; i < 6; i++)
        feed(session, client_a, server, 41000, 443, 0x18, 1001 + i,
             not_hello, sizeof not_hello);
    feed(session, client_a, server, 41000, 443, 0x18, 2000,
         not_hello, sizeof not_hello);
    size_t full_hello_len = complete_client_hello(full_hello);
    feed(session, client_a, server, 41000, 443, 0x18, 2100,
         full_hello, full_hello_len);
    feed(session, server, client_a, 443, 41000, 0x18, 900,
         reply, sizeof reply);

    feed(session, client_b, server, 41001, 443, 0x02, 3000, NULL, 0);
    feed(session, server, client_b, 443, 41001, 0x12, 4000, NULL, 0);
    feed(session, client_b, server, 41001, 443, 0x10, 3001, NULL, 0);
    size_t hello_len = incomplete_client_hello(hello);
    feed(session, client_b, server, 41001, 443, 0x18, 3001, hello, hello_len);
    feed(session, client_b, server, 41001, 443, 0x18, 3061,
         later_payload, sizeof later_payload);

    feed(session, client_c, server, 41002, 80, 0x02, 5000, NULL, 0);
    feed(session, server, client_c, 80, 41002, 0x12, 6000, NULL, 0);
    feed(session, client_c, server, 41002, 80, 0x10, 5001, NULL, 0);
    feed(session, client_c, server, 41002, 80, 0x18, 5001,
         request, sizeof request - 1);

    d2k_payload_stats stats;
    d2k_session_payload_stats(session, &stats);
    printf("СВОДКА %llu %llu %llu %llu %02x %llu\n",
           (unsigned long long)stats.reverse,
           (unsigned long long)stats.after_hello,
           (unsigned long long)stats.late,
           (unsigned long long)stats.not_hello,
           (unsigned)stats.last_first_byte,
           (unsigned long long)stats.sni_next_seg);
    d2k_session_free(session);
    return 0;
}
C

{
    printf 'Сверка TCP-счётчиков C/Rust на ARM64: %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходник донора: %s\n' "$r2o_donor"
    sha256sum "$r2o_donor/session.c" "$r2o_donor/test_session.c" \
        "$r2o_donor/include/d2k_session.h" "$r2o_harness" \
        "$r2o_script_dir/crates/r2o-datapath/src/engine.rs"
} >"$r2o_log"

{
    make -B -C "$r2o_donor" test_session CC=aarch64-linux-gnu-gcc
    qemu-aarch64 -L /usr/aarch64-linux-gnu "$r2o_donor/test_session"
} >>"$r2o_log" 2>&1
aarch64-linux-gnu-gcc -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$r2o_donor/include" -I"$r2o_donor/../core/include" \
    -o "$r2o_oracle" "$r2o_harness" \
    "$r2o_donor/session.o" "$r2o_donor/http80.o" "$r2o_donor/hold.o" \
    "$r2o_donor/capture.o" "$r2o_donor/nat.o" "$r2o_donor/ctq.o" \
    "$r2o_donor/nl.o" "$r2o_donor/track.o" "$r2o_donor/tls.o" \
    "$r2o_donor/wire.o" "$r2o_donor/wire_udp.o" "$r2o_donor/journal.o" \
    "$r2o_donor/plans.o" "$r2o_donor/plan_parse.o" "$r2o_donor/plan_apply.o" \
    "$r2o_donor/core_quic.o" "$r2o_donor/core_quicwire.o" \
    "$r2o_donor/core_quicsnap.o" "$r2o_donor/core_crypto.o" \
    "$r2o_donor/core_ipfrag.o" "$r2o_donor/core_httpup_logic.o" \
    >>"$r2o_log" 2>&1

qemu-aarch64 -L /usr/aarch64-linux-gnu "$r2o_oracle" >"$r2o_log_dir/r2o-tcp-payload-stats-c.out"
env QEMU_LD_PREFIX=/usr/aarch64-linux-gnu \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER='qemu-aarch64 -L /usr/aarch64-linux-gnu' \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    cargo +1.98.0 test --target aarch64-unknown-linux-gnu --locked --offline \
    -p r2o-datapath r2o_tcp_сводка_нагрузки_разделяет_направление_окно_и_sni \
    -- --nocapture >"$r2o_log_dir/r2o-tcp-payload-stats-rust.out" 2>&1

grep '^СВОДКА ' "$r2o_log_dir/r2o-tcp-payload-stats-c.out" >"$r2o_log_dir/r2o-tcp-payload-stats-c.normalized"
grep '^СВОДКА ' "$r2o_log_dir/r2o-tcp-payload-stats-rust.out" >"$r2o_log_dir/r2o-tcp-payload-stats-rust.normalized"
diff -u "$r2o_log_dir/r2o-tcp-payload-stats-c.normalized" \
    "$r2o_log_dir/r2o-tcp-payload-stats-rust.normalized" >>"$r2o_log"
cat "$r2o_log_dir/r2o-tcp-payload-stats-c.normalized" >>"$r2o_log"
printf 'C/Rust-счётчики совпали. Журнал: %s\n' "$r2o_log"
trap - EXIT
