/* C-оракул: production `d2k_quic_assembly_*` (core/quic.c:708-797). */
#include "d2k_quic.h"
#include "test_quic_pq.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Заполненность и crypto_end печатаем отдельно: они не входят в публичный
 * API, но структура видна при включении quic.c; здесь считаем по seen. */
static void emit_full(const char *case_name, int step, int rc, const char *sni,
                      const d2k_quic_assembly *a)
{
    size_t filled = 0;
    while (filled < sizeof a->stream &&
           (a->seen[filled / 8] & (uint8_t)(1u << (filled % 8)))) {
        filled++;
    }
    printf("%s,%d,%d,%s,%d,%zu,%llu\n", case_name, step, rc,
           rc == 1 && sni && sni[0] ? sni : "-",
           d2k_quic_assembly_complete(a), filled,
           (unsigned long long)a->crypto_end);
}

static int feed(const char *case_name, int step, d2k_quic_assembly *a,
                const uint8_t *packet, size_t len)
{
    char sni[256];
    sni[0] = '\0';
    int rc = d2k_quic_assembly_feed(a, packet, len, sni, sizeof sni);
    emit_full(case_name, step, rc, sni, a);
    return rc;
}

int main(void)
{
    const char *inputs_path = getenv("R2O_QUIC_ASSEMBLY_INPUT");
    FILE *inputs = inputs_path ? fopen(inputs_path, "wb") : NULL;

    uint8_t d1[1500], d2[1500], d1s[1500], d2s[1500];
    uint8_t o1[1500], o2[1500];
    size_t l1 = 0, l2 = 0, l1s = 0, l2s = 0, o1l = 0, o2l = 0;
    if (d2k_test_pq_initials("две.датаграммы.example", d1, &l1, d2, &l2) != 0 ||
        d2k_test_pq_initials_sni_first("сни.первый.example", d1s, &l1s, d2s, &l2s) != 0 ||
        d2k_test_pq_initials("другой.полёт.example", o1, &o1l, o2, &o2l) != 0) {
        return 2;
    }
    if (inputs) {
        fprintf(inputs, "d1,"); for (size_t i = 0; i < l1; i++) fprintf(inputs, "%02x", d1[i]); fputc('\n', inputs);
        fprintf(inputs, "d2,"); for (size_t i = 0; i < l2; i++) fprintf(inputs, "%02x", d2[i]); fputc('\n', inputs);
        fprintf(inputs, "d1s,"); for (size_t i = 0; i < l1s; i++) fprintf(inputs, "%02x", d1s[i]); fputc('\n', inputs);
        fprintf(inputs, "d2s,"); for (size_t i = 0; i < l2s; i++) fprintf(inputs, "%02x", d2s[i]); fputc('\n', inputs);
        fprintf(inputs, "o1,"); for (size_t i = 0; i < o1l; i++) fprintf(inputs, "%02x", o1[i]); fputc('\n', inputs);
        fprintf(inputs, "o2,"); for (size_t i = 0; i < o2l; i++) fprintf(inputs, "%02x", o2[i]); fputc('\n', inputs);
        fclose(inputs);
    }

    d2k_quic_assembly a;
    d2k_quic_assembly_init(&a);
    feed("normal", 1, &a, d1, l1);
    feed("normal", 2, &a, d2, l2);

    d2k_quic_assembly_init(&a);
    feed("reverse", 1, &a, d2, l2);
    feed("reverse", 2, &a, d1, l1);

    d2k_quic_assembly_init(&a);
    feed("sni-first", 1, &a, d1s, l1s);
    feed("sni-first", 2, &a, d2s, l2s);

    d2k_quic_assembly_init(&a);
    feed("duplicate", 1, &a, d1, l1);
    feed("duplicate", 2, &a, d1, l1);
    feed("duplicate", 3, &a, d2, l2);

    d2k_quic_assembly_init(&a);
    feed("bad-keeps-state", 1, &a, d1, l1);
    static const uint8_t garbage[20] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    };
    feed("bad-keeps-state", 2, &a, garbage, sizeof garbage);
    feed("bad-keeps-state", 3, &a, d2, l2);

    d2k_quic_assembly_init(&a);
    feed("new-flight", 1, &a, d1, l1);
    feed("new-flight", 2, &a, o1, o1l);
    feed("new-flight", 3, &a, o2, o2l);

    d2k_quic_assembly_init(&a);
    static const uint8_t qsn[] = {'Q', 'S', 'N', 1};
    feed("qsn", 1, &a, qsn, sizeof qsn);

    d2k_quic_assembly_init(&a);
    printf("empty,%d,%d,-,%d,%zu,%llu\n", 0, 0,
           d2k_quic_assembly_complete(&a), (size_t)0, (unsigned long long)0);
    return 0;
}
