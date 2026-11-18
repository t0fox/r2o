/* C-оракул: production `d2k_hs_plan_poisons` и
 * `d2k_httpsearch_measured_poison` (core/httpsearch.c). TU включается целиком,
 * лишнее выбрасывает --gc-sections. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "httpsearch.c"

#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *bytes, size_t n)
{
    for (size_t index = 0; index < n; index++) {
        printf("%02x", bytes[index]);
    }
}

static void dump_plan(const char *label, const char *text)
{
    char specs[8][64];
    size_t n = d2k_hs_plan_poisons(text, specs, 8);
    printf("plan %s n=%zu\n", label, n);
    for (size_t index = 0; index < n; index++) {
        printf("spec %s ", label);
        print_hex((const uint8_t *)specs[index], strlen(specs[index]));
        printf("\n");
    }
}

static void dump_measured(const char *label, d2k_httpsearch *hs, int rc)
{
    printf("add %s rc=%d count=%zu\n", label, rc, hs->n_measured);
    for (size_t index = 0; index < hs->n_measured; index++) {
        printf("key %s ", label);
        print_hex((const uint8_t *)hs->measured[index], strlen(hs->measured[index]));
        printf("\n");
    }
}

/* Строка fake длиной 15+pad; C добавляет пробел, только если fl+1 < 256. */
static void build_edge(char *out, size_t pad)
{
    size_t pos = 0;
    memcpy(out, "fake ", 5);
    pos = 5;
    memset(out + pos, 'a', pad);
    pos += pad;
    memcpy(out + pos, " poison=1", sizeof " poison=1" - 1);
    pos += sizeof " poison=1" - 1;
    out[pos] = '\0';
}

int main(void)
{
    dump_plan("canonical",
              "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 1 ttl=64 badsum\n"
              "poison 2 seqshift=-66000\n"
              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n");
    dump_plan("both",
              "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 1 ttl=64 badsum\n"
              "poison 2 seqshift=-66000\n"
              "fake payload=1 poison=1 poison=2 repeats=1 gap_us=0 place=before\n");
    dump_plan("http",
              "d2k-plan 1 11\nid 00\nproto tcp http\npoison 1 ttl=64 badsum\n"
              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n");
    dump_plan("no-header",
              "d2k-plan 1 11\nid 00\npoison 1 badsum\n"
              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n");
    dump_plan("no-fake",
              "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 1 badsum\n");
    dump_plan("id-zero",
              "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 0 badsum\n"
              "fake payload=1 poison=0 repeats=1 gap_us=0 place=before\n");
    dump_plan("fake-at-start",
              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n"
              "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 1 badsum\n");
    dump_plan("indented",
              "d2k-plan 1 11\nid 00\nproto tcp tls\n  poison 1 badsum\n"
              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n");
    dump_plan("poison1",
              "d2k-plan 1 11\nid 00\nproto tcp tls\npoison1 badsum\n"
              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n");
    dump_plan("no-spec",
              "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 1\n"
              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n");
    dump_plan("eof-spec",
              "d2k-plan 1 11\nid 00\nproto tcp tls\n"
              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n"
              "poison 1 badsum");
    dump_plan("crlf",
              "d2k-plan 1 11\r\nid 00\r\nproto tcp tls\r\npoison 1 badsum\r\n"
              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\r\n");
    dump_plan("dup-id",
              "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 1 badsum\n"
              "poison 1 seqshift=5\n"
              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n");
    dump_plan("fake-poison11",
              "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 1 badsum\n"
              "fake payload=1 poison=11 repeats=1 gap_us=0 place=before\n");

    char spec63[64], spec64[65];
    memset(spec63, 'a', 63);
    spec63[63] = '\0';
    memset(spec64, 'a', 64);
    spec64[64] = '\0';
    char text[512];
    snprintf(text, sizeof text,
             "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 1 %s\n"
             "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n",
             spec63);
    dump_plan("spec63", text);
    snprintf(text, sizeof text,
             "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 1 %s\n"
             "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n",
             spec64);
    dump_plan("spec64", text);

    char edge[320];
    snprintf(text, sizeof text,
             "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 1 badsum\n");
    size_t header_len = strlen(text);
    build_edge(edge, 239);
    snprintf(text + header_len, sizeof text - header_len, "%s\n", edge);
    dump_plan("fake-253", text);
    snprintf(text, sizeof text,
             "d2k-plan 1 11\nid 00\nproto tcp tls\npoison 1 badsum\n");
    build_edge(edge, 240);
    snprintf(text + header_len, sizeof text - header_len, "%s\n", edge);
    dump_plan("fake-254", text);

    d2k_httpsearch *hs = d2k_httpsearch_new(NULL);
    if (!hs) { return 2; }
    static const char *const specs[] = {
        "badsum",
        "seqshift=-66000",
        "badsum",
        "ttl=64 badsum",
        "badsum ttl=64",
        "badsum ttl=9",
        "ttl=64",
        "ttl=256 badsum",
        "ttl=0 badsum",
        "seqshift=0",
        "seqshift=1",
        "ttl=5 seqshift=1",
        "ttl=5 badsum seqshift=1",
        "seqshift=1 badsum",
        "tcpts",
        "badsum badsum",
        "ttl=1+badsum",
        "ttl=16+badsum",
        "ttl=6 badsum",
        "ttl=7 badsum",
        "ttl=64 badsum",
        "ttl=123456789012345 badsum",
        "",
        " \t ",
        "ttl=5\tbadsum",
        "ttl=5 badsum",
    };
    char trunc[128];
    memset(trunc, ' ', sizeof trunc);
    memcpy(trunc, "badsum", 6);
    memcpy(trunc + 66, "ttl=9", 5);
    trunc[71] = '\0';
    for (size_t index = 0; index < sizeof specs / sizeof specs[0]; index++) {
        char label[32];
        snprintf(label, sizeof label, "%zu", index);
        int rc = d2k_httpsearch_measured_poison(hs, specs[index]);
        dump_measured(label, hs, rc);
        if (index == 2) {
            /* 71 байт: C обрезает спеку до 63 и теряет ttl=9. */
            dump_measured("trunc63", hs,
                          d2k_httpsearch_measured_poison(hs, trunc));
        }
    }
    d2k_httpsearch_free(hs);

    /* Композиция d2kc: сортировка по successes, затем регистрация. */
    typedef struct {
        int succ;
        const char *spec;
    } seen;
    static const seen collected[] = {
        {5, "ttl=9 badsum"}, {9, "seqshift=-66000"}, {7, "badsum"},
        {3, "tcpts"},        {2, "ttl=3"},            {1, "ttl=9 badsum"},
    };
    seen sorted[sizeof collected / sizeof collected[0]];
    memcpy(sorted, collected, sizeof sorted);
    for (size_t i = 0; i < sizeof sorted / sizeof sorted[0]; i++) {
        for (size_t j = i + 1; j < sizeof sorted / sizeof sorted[0]; j++) {
            if (sorted[j].succ > sorted[i].succ) {
                seen tmp = sorted[i];
                sorted[i] = sorted[j];
                sorted[j] = tmp;
            }
        }
    }
    d2k_httpsearch *seq = d2k_httpsearch_new(NULL);
    if (!seq) { return 2; }
    for (size_t index = 0; index < sizeof sorted / sizeof sorted[0]; index++) {
        d2k_httpsearch_measured_poison(seq, sorted[index].spec);
    }
    dump_measured("d2kc", seq, 0);
    d2k_httpsearch_free(seq);
    return 0;
}
