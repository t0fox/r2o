/* C stdout-differential: static `print_journal` из datapath/d2kd.c.
 *
 * d2kd.c включается в этот файл, чтобы добраться до static-функции. `main`
 * донора переименован; лишние секции выбрасываются --gc-sections. Журнал
 * подменяет `d2k_session_journal`, поэтому настоящая сессия не нужна.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_journal.h"
#include "d2k_session.h"

#define main d2kd_main_unused
#include "d2kd.c"
#undef main

static const d2k_journal *current_journal;

const d2k_journal *d2k_session_journal(const d2k_session *session) {
    (void)session;
    return current_journal;
}

static void ipv4_key(d2k_key *key, uint8_t proto) {
    memset(key, 0, sizeof *key);
    key->family = 4;
    key->proto = proto;
    uint8_t *low = (uint8_t *)&key->low_ip;
    low[0] = 192;
    low[1] = 0;
    low[2] = 2;
    low[3] = 1;
    uint8_t *high = (uint8_t *)&key->high_ip;
    high[0] = 198;
    high[1] = 51;
    high[2] = 100;
    high[3] = 2;
    uint8_t *low_port = (uint8_t *)&key->low_port;
    low_port[0] = 0x1f;
    low_port[1] = 0x90;
    uint8_t *high_port = (uint8_t *)&key->high_port;
    high_port[0] = 0x00;
    high_port[1] = 0x50;
}

static void ipv6_key(d2k_key *key, uint8_t proto) {
    memset(key, 0, sizeof *key);
    key->family = 6;
    key->proto = proto;
    for (unsigned i = 0; i < 16; i++) {
        key->low_ip6[i] = (uint8_t)(0x20 + i);
        key->high_ip6[i] = (uint8_t)(0x30 + i);
    }
    uint8_t *low_port = (uint8_t *)&key->low_port;
    low_port[0] = 0x1f;
    low_port[1] = 0x90;
    uint8_t *high_port = (uint8_t *)&key->high_port;
    high_port[0] = 0x00;
    high_port[1] = 0x50;
}

static void print_one(const char *label, const d2k_journal *journal,
                      uint64_t start) {
    printf("== %s ==\n", label);
    current_journal = journal;
    print_journal(NULL, start);
}

int main(void) {
    const uint64_t start = 1000000000ull;
    const char *name = "example.com";

    d2k_journal *empty = d2k_journal_new(2);
    print_one("empty", empty, start);

    d2k_journal *records = d2k_journal_new(8);
    d2k_key key;
    ipv4_key(&key, 6);
    d2k_journal_add(records, start + 500000000ull, &key, D2K_JRN_HELLO_SNI, 0,
                    0, NULL, (const uint8_t *)name, strlen(name), NULL);
    ipv4_key(&key, 17);
    d2k_journal_add(records, start + 1000000000ull, &key, D2K_JRN_PLAN_REFUSED,
                    0, 0, NULL, NULL, 0, "плана для этой цели нет");
    ipv6_key(&key, 6);
    d2k_journal_add_fate(records, start + 1500000000ull, &key, D2K_JRN_PLAN_DONE,
                         0, NULL, NULL);
    ipv4_key(&key, 6);
    d2k_journal_add(records, start + 1750000000ull, &key, D2K_JRN_HELLO_NONAME,
                    0, 0, NULL, NULL, 0, NULL);
    print_one("records", records, start);

    d2k_journal *ring = d2k_journal_new(2);
    ipv4_key(&key, 6);
    d2k_journal_add(ring, start + 100000000ull, &key, D2K_JRN_HELLO_SNI, 0, 0,
                    NULL, (const uint8_t *)name, strlen(name), NULL);
    d2k_journal_add(ring, start + 200000000ull, &key, D2K_JRN_PLAN_APPLIED, 0, 0,
                    NULL, (const uint8_t *)name, strlen(name), NULL);
    d2k_journal_add(ring, start + 300000000ull, &key, D2K_JRN_SUSPECT, 1, 0,
                    NULL, NULL, 0, NULL);
    print_one("ring", ring, start);

    d2k_journal_free(empty);
    d2k_journal_free(records);
    d2k_journal_free(ring);
    return 0;
}
