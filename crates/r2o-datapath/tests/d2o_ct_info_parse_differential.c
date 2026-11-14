/* C/Rust differential: d2k_ct_info_parse (datapath/ctq.c:122-156). */
#include <stdio.h>
#include <string.h>

#include "d2k_ctq.h"

static void be64(uint8_t out[8], uint64_t value) {
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(value >> (56 - 8 * i));
}

static void push_attr(uint8_t *body, size_t *used, uint16_t type,
                      const uint8_t *value, size_t length) {
    size_t at = *used;
    uint16_t total = (uint16_t)(4 + length);
    memcpy(body + at, &total, 2);
    memcpy(body + at + 2, &type, 2);
    memcpy(body + at + 4, value, length);
    size_t aligned = (at + total + 3u) & ~(size_t)3u;
    for (size_t i = at + total; i < aligned; i++) body[i] = 0;
    *used = aligned;
}

static size_t counters_message(uint8_t *out, uint32_t seq, uint64_t orig,
                               uint64_t reply, int with_counters) {
    uint8_t body[128];
    size_t used = 4;
    memset(body, 0, sizeof body);
    body[0] = 2;
    if (with_counters) {
        uint8_t nested[16];
        uint8_t value[8];
        size_t nested_used = 0;
        be64(value, orig);
        push_attr(nested, &nested_used, 1, value, 8);
        push_attr(body, &used, 9 | 0x8000, nested, nested_used);
        nested_used = 0;
        be64(value, reply);
        push_attr(nested, &nested_used, 1, value, 8);
        push_attr(body, &used, 10 | 0x8000, nested, nested_used);
    }
    memset(out, 0, 16 + used);
    uint32_t length = (uint32_t)(16 + used);
    memcpy(out, &length, 4);
    uint16_t type = 0x0100;
    memcpy(out + 4, &type, 2);
    memcpy(out + 8, &seq, 4);
    memcpy(out + 16, body, used);
    return length;
}

static size_t error_message(uint8_t *out, uint32_t seq, int32_t errno_value) {
    uint32_t length = 20;
    memset(out, 0, length);
    memcpy(out, &length, 4);
    uint16_t type = 2;
    memcpy(out + 4, &type, 2);
    memcpy(out + 8, &seq, 4);
    memcpy(out + 16, &errno_value, 4);
    return length;
}

static void run(const char *name, const uint8_t *buffer, size_t length, uint32_t seq) {
    d2k_ct_info info;
    memset(&info, 0, sizeof info);
    int rc = d2k_ct_info_parse(buffer, length, seq, &info);
    printf("%s rc=%d", name, rc);
    if (rc == 0) {
        printf(" orig=%llu reply=%llu known=%u state=%u",
               (unsigned long long)info.orig_pkts,
               (unsigned long long)info.reply_pkts,
               info.tcp_state_known, info.tcp_state);
    }
    printf("\n");
}

int main(void) {
    uint8_t buffer[256];
    size_t length = counters_message(buffer, 7, 22, 25, 1);
    run("counters", buffer, length, 7);
    run("wrong_seq", buffer, length, 8);
    length = counters_message(buffer, 7, 0, 0, 0);
    run("no_counters", buffer, length, 7);
    length = error_message(buffer, 7, -2);
    run("reply", buffer, length, 7);
    length = error_message(buffer, 7, 0);
    run("ack", buffer, length, 7);
    return 0;
}
