/* C-оракул: production `d2k_qsnap_recid` (core/quicsnap_reseal.c:75-134). */
#include "d2k_quic.h"
#include "d2k_quicwire.h"
#include "d2k_quicsnap.h"
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

static size_t make_initial(const uint8_t *dcid, size_t dcid_len,
                           const uint8_t *scid, size_t scid_len,
                           const uint8_t *body, size_t body_len,
                           uint64_t pn, uint8_t *out, size_t cap)
{
    uint8_t hdr[256];
    size_t hlen = d2k_qw_long_hdr(hdr, sizeof hdr, D2K_QW_V1, D2K_QW_LT_INITIAL,
                                  dcid, dcid_len, scid, scid_len, 1, body_len);
    if (hlen == 0) { return 0; }
    uint8_t sec[32];
    d2k_qw_keys keys;
    if (d2k_qw_initial_secret(D2K_QW_V1, dcid, dcid_len, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(D2K_QW_V1, sec, &keys) != 0) {
        return 0;
    }
    return d2k_qw_seal(&keys, 1, hdr, hlen, pn, 1, body, body_len, out, cap);
}

static size_t crypto_body(uint8_t *body, const uint8_t *data, size_t len)
{
    size_t b = 0;
    body[b++] = 0x06;
    b += d2k_qw_varint_write(body + b, 1500 - b, 0);
    b += d2k_qw_varint_write(body + b, 1500 - b, len);
    memcpy(body + b, data, len);
    return b + len;
}

static void describe(const char *label, const uint8_t *qsn, size_t qsn_len)
{
    d2k_qsnap s;
    if (d2k_qsnap_parse(qsn, qsn_len, &s) != 0) {
        printf("%s,-1\n", label);
        return;
    }
    int same = 1;
    /* same_dcid проверяем по реальным байтам после разбора первого. */
    d2k_qw_hdr first;
    if (d2k_qw_hdr_parse(s.dg[0], s.len[0], 0, &first) != 0) {
        printf("%s,-1\n", label);
        return;
    }
    for (size_t i = 1; i < s.n; i++) {
        d2k_qw_hdr h;
        if (d2k_qw_hdr_parse(s.dg[i], s.len[i], 0, &h) != 0 ||
            h.dcid_len != first.dcid_len ||
            memcmp(s.dg[i] + h.dcid_off, s.dg[0] + first.dcid_off, first.dcid_len) != 0) {
            same = 0;
        }
    }
    printf("%s,0,%zu,%d\n", label, s.n, same);
    for (size_t i = 0; i < s.n; i++) {
        d2k_qw_hdr h;
        if (d2k_qw_hdr_parse(s.dg[i], s.len[i], 0, &h) != 0) {
            printf("%s-dg%zu,-1\n", label, i);
            continue;
        }
        uint8_t sec[32];
        d2k_qw_keys keys;
        if (d2k_qw_initial_secret(h.version, s.dg[i] + h.dcid_off, h.dcid_len,
                                  D2K_QW_CLIENT, sec) != 0 ||
            d2k_qw_keys_from_secret(h.version, sec, &keys) != 0) {
            printf("%s-dg%zu,-2\n", label, i);
            continue;
        }
        uint8_t plain[1500];
        size_t plain_len = 0;
        uint64_t pn = 0;
        int opens = d2k_qw_open(&keys, &h, s.dg[i], 0, plain, &plain_len, &pn) == 0;
        printf("%s-dg%zu,%" PRIu32 ",%zu,", label, i, h.version, h.dcid_len);
        print_hex(s.dg[i] + h.scid_off, h.scid_len);
        printf(",%" PRIu64 ",%d,", pn, opens);
        if (opens) { print_hex(plain, plain_len); } else { printf("-"); }
        printf("\n");
    }
}

static void report(const char *label, const uint8_t *qsn, size_t qsn_len,
                   FILE *inputs)
{
    if (inputs) {
        fprintf(inputs, "%s,", label);
        for (size_t index = 0; index < qsn_len; index++) {
            fprintf(inputs, "%02x", qsn[index]);
        }
        fputc('\n', inputs);
    }
    uint8_t out[6144];
    size_t out_len = 0;
    d2k_qsnap s;
    memset(&s, 0, sizeof s);
    d2k_quic_form form;
    memset(&form, 0, sizeof form);
    int parsed = d2k_qsnap_parse(qsn, qsn_len, &s) == 0;
    int form_rc = parsed ? d2k_qsnap_form(&s, &form) : -1;
    printf("%s-form,%d,%u,%u,%u\n", label, form_rc == 0 ? 0 : -1,
           (unsigned)form.n, (unsigned)form.dgram_len, (unsigned)form.ch_len);
    if (!parsed) {
        printf("%s,-1\n", label);
        return;
    }
    if (d2k_qsnap_recid(&s, out, sizeof out, &out_len) != 0) {
        printf("%s,-1\n", label);
        return;
    }
    describe(label, out, out_len);
}

int main(void)
{
    const char *inputs_path = getenv("R2O_QSN_RECID_INPUT");
    FILE *inputs = inputs_path ? fopen(inputs_path, "wb") : NULL;
    if (inputs_path && !inputs) { return 2; }

    static const uint8_t dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    static const uint8_t scid[8] = {9, 10, 11, 12, 13, 14, 15, 16};
    static const uint8_t dcid_other[8] = {21, 22, 23, 24, 25, 26, 27, 28};
    static const uint8_t dcid4[4] = {1, 2, 3, 4};

    uint8_t ch[8192];
    size_t ch_len = 0;
    if (d2k_quic_client_hello(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                              ch, sizeof ch, &ch_len) != 0) {
        return 3;
    }
    uint8_t body[2048], packet[1500], packet2[1500];
    size_t b = crypto_body(body, ch, ch_len);
    size_t p = make_initial(dcid, sizeof dcid, scid, sizeof scid, body, b, 0,
                            packet, sizeof packet);
    uint8_t ping[20];
    memset(ping, 0, sizeof ping);
    ping[0] = 0x01;
    size_t p2 = make_initial(dcid, sizeof dcid, scid, sizeof scid, ping, sizeof ping, 1,
                             packet2, sizeof packet2);

    uint8_t qsn[6144];
    size_t qlen;
    const uint8_t *dg[2];
    size_t len[2];

    dg[0] = packet; len[0] = p;
    qlen = d2k_qsnap_pack(dg, len, 1, qsn, sizeof qsn);
    report("qsn-1", qsn, qlen, inputs);

    dg[0] = packet; len[0] = p; dg[1] = packet2; len[1] = p2;
    qlen = d2k_qsnap_pack(dg, len, 2, qsn, sizeof qsn);
    report("qsn-2", qsn, qlen, inputs);

    size_t p3 = make_initial(dcid_other, sizeof dcid_other, scid, sizeof scid, ping,
                             sizeof ping, 1, packet2, sizeof packet2);
    dg[0] = packet; len[0] = p; dg[1] = packet2; len[1] = p3;
    qlen = d2k_qsnap_pack(dg, len, 2, qsn, sizeof qsn);
    report("qsn-mixed-dcid", qsn, qlen, inputs);

    size_t p4 = make_initial(dcid4, sizeof dcid4, scid, sizeof scid, body, b, 0,
                             packet, sizeof packet);
    dg[0] = packet; len[0] = p4;
    qlen = d2k_qsnap_pack(dg, len, 1, qsn, sizeof qsn);
    report("qsn-dcid4", qsn, qlen, inputs);

    /* QSN с заявленной длиной за пределами буфера. */
    static const uint8_t broken[] = {'Q', 'S', 'N', 1, 0x10, 0x00, 0x01};
    report("qsn-truncated", broken, sizeof broken, inputs);
    static const uint8_t empty[] = {'Q', 'S', 'N', 1};
    report("qsn-empty", empty, sizeof empty, inputs);

    if (inputs) { fclose(inputs); }
    return 0;
}
