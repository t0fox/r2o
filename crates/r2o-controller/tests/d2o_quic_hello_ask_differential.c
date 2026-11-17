/* C-оракул: production `d2k_quic_hello_ask`/`d2k_quic_hello_split`
 * (core/quichello.c:330-437). Заголовки содержат случайный DCID, поэтому
 * сравниваются версия, длина, PN, SNI, ClientHello и открытый plain. */
#include "d2k_quic.h"
#include "d2k_quichello.h"
#include "d2k_quicwire.h"
#include "test_quic_vector.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_hex(const uint8_t *bytes, size_t n)
{
    for (size_t index = 0; index < n; index++) {
        printf("%02x", bytes[index]);
    }
}

static int describe(const char *label, const uint8_t *packet, size_t len)
{
    d2k_qw_hdr h;
    if (d2k_qw_hdr_parse(packet, len, 0, &h) != 0 || !h.long_hdr) {
        printf("%s,-1\n", label);
        return -1;
    }
    uint8_t sec[32];
    d2k_qw_keys keys;
    if (d2k_qw_initial_secret(h.version, packet + h.dcid_off, h.dcid_len,
                              D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(h.version, sec, &keys) != 0) {
        printf("%s,-2\n", label);
        return -1;
    }
    uint8_t plain[1500];
    size_t plain_len = 0;
    uint64_t pn = 0;
    int opens = d2k_qw_open(&keys, &h, packet, 0, plain, &plain_len, &pn) == 0;
    uint8_t ch[8192];
    size_t ch_len = 0;
    int has_ch = d2k_quic_client_hello(packet, len, ch, sizeof ch, &ch_len) == 0;
    char sni[256];
    sni[0] = '\0';
    int has_sni = d2k_quic_sni(packet, len, sni, sizeof sni) == 0;
    printf("%s,%d,%" PRIu32 ",%zu,%" PRIu64 ",%s,%d,%zu,", label, opens, h.version,
           len, pn, has_sni && sni[0] ? sni : "-", has_ch, ch_len);
    if (has_ch) { print_hex(ch, ch_len); } else { printf("-"); }
    printf(",");
    if (opens) { print_hex(plain, plain_len); } else { printf("-"); }
    printf("\n");
    return 0;
}

static void run_ask(const char *label, d2k_quic_ask ask, const char *sni)
{
    uint8_t out[1500];
    size_t out_len = 0;
    int rc = d2k_quic_hello_ask(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                ask, sni, out, sizeof out, &out_len);
    if (rc != 0) {
        printf("%s,-1\n", label);
        return;
    }
    describe(label, out, out_len);
}

static void run_split(const char *label, const char *sni)
{
    uint8_t head[1500], tail[1500];
    size_t head_len = 0, tail_len = 0;
    int rc = d2k_quic_hello_split(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                  sni, head, sizeof head, &head_len,
                                  tail, sizeof tail, &tail_len);
    if (rc != 0) {
        printf("%s-head,-1\n%s-tail,-1\n", label, label);
        return;
    }
    char name[320];
    snprintf(name, sizeof name, "%s-head", label);
    describe(name, head, head_len);
    snprintf(name, sizeof name, "%s-tail", label);
    describe(name, tail, tail_len);
}

int main(void)
{
    const char *sample_path = getenv("R2O_QUIC_ASK_SAMPLE");
    if (sample_path) {
        FILE *f = fopen(sample_path, "wb");
        if (!f) { return 2; }
        for (size_t index = 0; index < sizeof d2k_test_v1_initial; index++) {
            fprintf(f, "%02x", d2k_test_v1_initial[index]);
        }
        fclose(f);
    }

    run_ask("plain-same", D2K_QASK_PLAIN, "example.com");
    run_ask("plain-rename", D2K_QASK_PLAIN, "target.example");
    run_ask("plain-ip", D2K_QASK_PLAIN, "203.0.113.7");
    run_ask("v2", D2K_QASK_VERSION2, "target.example");
    run_ask("split-crypto", D2K_QASK_SPLIT_CRYPTO, "example.com");
    run_ask("split-crypto-ip", D2K_QASK_SPLIT_CRYPTO, "203.0.113.7");
    run_ask("longer", D2K_QASK_LONGER, "target.example");
    run_ask("clear-fixed", D2K_QASK_CLEAR_FIXED_BIT, "target.example");

    run_split("split-dgrams-same", "example.com");
    run_split("split-dgrams-rename", "target.example");
    run_split("split-dgrams-ip", "203.0.113.7");

    static const uint8_t qsn[] = {'Q', 'S', 'N', 1};
    uint8_t out[1500];
    size_t out_len = 0;
    printf("qsn,%d\n",
           d2k_quic_hello_ask(qsn, sizeof qsn, D2K_QASK_PLAIN, "target.example",
                              out, sizeof out, &out_len) == 0);
    printf("empty-sni,%d\n",
           d2k_quic_hello_ask(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                              D2K_QASK_PLAIN, "", out, sizeof out, &out_len) == 0);
    return 0;
}
