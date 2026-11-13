/* C/Rust differential: fp_add (core/sched.c:1703-1730).
 * Каждая строка — JSON с итоговым отпечатком после серии примет. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "sched.c"

static void print_fp(const char *scenario, const d2k_cat_fp *fp) {
    printf("{\"scenario\":\"%s\",\"signals\":[", scenario);
    for (size_t i = 0; i < fp->n_sig; i++) {
        const d2k_cat_signal *s = &fp->sig[i];
        if (i) putchar(',');
        printf("{\"kind\":\"%s\",\"ttl\":%u,\"tos\":%u,\"ipid\":%u,"
               "\"volume\":%d,\"ttl_delta\":%d,\"seen\":%d,\"packets\":%d}",
               s->kind, (unsigned)s->ttl, (unsigned)s->tos, (unsigned)s->ipid,
               s->volume, (int)s->ttl_delta, s->seen, s->packets);
    }
    printf("]}\n");
}

static void add(d2k_cat_fp *fp, const char *kind, unsigned ttl, unsigned tos,
                unsigned ipid, int volume, int seen, int packets) {
    d2k_cat_signal s;
    memset(&s, 0, sizeof s);
    snprintf(s.kind, sizeof s.kind, "%s", kind);
    s.ttl = (uint8_t)ttl;
    s.tos = (uint8_t)tos;
    s.ipid = (uint16_t)ipid;
    s.volume = volume;
    s.seen = seen;
    s.packets = packets;
    fp_add(fp, &s);
}

int main(void) {
    d2k_cat_fp fp;

    memset(&fp, 0, sizeof fp);
    add(&fp, "volume", 0, 0, 0, 20, 1, 0);
    add(&fp, "volume", 0, 0, 0, 19, 1, 5);
    print_fp("volume_in_slack", &fp);

    memset(&fp, 0, sizeof fp);
    add(&fp, "volume", 0, 0, 0, 20, 1, 0);
    add(&fp, "volume", 0, 0, 0, 24, 1, 0);
    print_fp("volume_out_of_slack", &fp);

    memset(&fp, 0, sizeof fp);
    add(&fp, "volume", 0, 0, 0, 20, 1, 0);
    add(&fp, "rx-volume", 0, 0, 0, 20, 1, 0);
    print_fp("volume_other_kind", &fp);

    memset(&fp, 0, sizeof fp);
    add(&fp, "rst", 127, 0x88, 54321, 0, 1, 0);
    add(&fp, "rst", 129, 0x88, 54321, 0, 1, 0);
    print_fp("rst_ttl_in_slack", &fp);

    memset(&fp, 0, sizeof fp);
    add(&fp, "rst", 127, 0x88, 54321, 0, 1, 0);
    add(&fp, "rst", 130, 0x88, 54321, 0, 1, 0);
    print_fp("rst_ttl_out_of_slack", &fp);

    memset(&fp, 0, sizeof fp);
    add(&fp, "rst", 127, 0x88, 54321, 0, 1, 0);
    add(&fp, "rst", 127, 0x89, 54321, 0, 1, 0);
    print_fp("rst_tos_differs", &fp);

    memset(&fp, 0, sizeof fp);
    add(&fp, "rst", 127, 0x88, 54321, 0, 1, 7);
    add(&fp, "rst", 127, 0x88, 54321, 0, 2, 9);
    print_fp("rst_seen_and_packets", &fp);

    memset(&fp, 0, sizeof fp);
    for (int i = 0; i < 9; i++) {
        char kind[16];
        snprintf(kind, sizeof kind, "k%d", i);
        add(&fp, kind, 0, 0, 0, 0, 1, 0);
    }
    print_fp("eight_signal_cap", &fp);

    memset(&fp, 0, sizeof fp);
    add(&fp, "silent", 0, 0, 0, 0, 1, 0);
    add(&fp, "silent", 2, 0, 0, 0, 1, 0);
    print_fp("silent_ttl_in_slack", &fp);

    return 0;
}
