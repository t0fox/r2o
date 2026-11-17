/* C-оракул: production `d2k_quic_hello_incomplete` из core/quic.c.
 * Пакеты строятся production-функциями провода с фиксированными ключами. */
#include "d2k_quic.h"
#include "d2k_quicwire.h"
#include "test_quic_vector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t k_dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
static const uint8_t k_scid[8] = {9, 10, 11, 12, 13, 14, 15, 16};

static size_t put_crypto(uint8_t *body, size_t cap, const uint8_t *data, size_t len)
{
    size_t b = 0;
    body[b++] = 0x06;
    b += d2k_qw_varint_write(body + b, cap - b, 0);
    b += d2k_qw_varint_write(body + b, cap - b, len);
    memcpy(body + b, data, len);
    return b + len;
}

static size_t make_initial(const uint8_t *body, size_t body_len,
                           uint8_t *out, size_t cap)
{
    uint8_t hdr[256];
    size_t hlen = d2k_qw_long_hdr(hdr, sizeof hdr, D2K_QW_V1, D2K_QW_LT_INITIAL,
                                  k_dcid, sizeof k_dcid, k_scid, sizeof k_scid,
                                  1, body_len);
    if (hlen == 0) { return 0; }
    uint8_t sec[32];
    d2k_qw_keys keys;
    if (d2k_qw_initial_secret(D2K_QW_V1, k_dcid, sizeof k_dcid, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(D2K_QW_V1, sec, &keys) != 0) {
        return 0;
    }
    return d2k_qw_seal(&keys, 1, hdr, hlen, 0, 1, body, body_len, out, cap);
}

static void emit(const char *label, const uint8_t *packet, size_t len,
                 FILE *packets)
{
    printf("%s,%d\n", label, d2k_quic_hello_incomplete(packet, len));
    if (packets) {
        fprintf(packets, "%s,", label);
        for (size_t index = 0; index < len; index++) {
            fprintf(packets, "%02x", packet[index]);
        }
        fputc('\n', packets);
    }
}

int main(void)
{
    const char *packets_path = getenv("R2O_QUIC_INCOMPLETE_INPUT");
    FILE *packets = packets_path ? fopen(packets_path, "wb") : NULL;
    if (packets_path && !packets) { return 2; }

    uint8_t ch[8192];
    size_t ch_len = 0;
    if (d2k_quic_client_hello(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                              ch, sizeof ch, &ch_len) != 0) {
        return 3;
    }

    uint8_t body[2048];
    uint8_t packet[1500];
    size_t b, p;

    b = put_crypto(body, sizeof body, ch, ch_len);
    p = make_initial(body, b, packet, sizeof packet);
    emit("complete", packet, p, packets);

    b = put_crypto(body, sizeof body, ch, 100);
    p = make_initial(body, b, packet, sizeof packet);
    emit("partial-100", packet, p, packets);

    b = put_crypto(body, sizeof body, ch, 4);
    p = make_initial(body, b, packet, sizeof packet);
    emit("partial-4", packet, p, packets);

    /* Нет CRYPTO — потока нет, «обрезан» = 0. */
    body[0] = 0x01;
    p = make_initial(body, 1, packet, sizeof packet);
    emit("no-crypto", packet, p, packets);

    /* Тип рукопожатия не ClientHello. */
    static const uint8_t not_ch[4] = {0x02, 0x00, 0x00, 0x10};
    b = put_crypto(body, sizeof body, not_ch, sizeof not_ch);
    p = make_initial(body, b, packet, sizeof packet);
    emit("not-ch", packet, p, packets);

    /* Полный CH + PADDING: обрезанным не считается. */
    b = put_crypto(body, sizeof body, ch, ch_len);
    memset(body + b, 0, 32);
    p = make_initial(body, b + 32, packet, sizeof packet);
    emit("complete-padded", packet, p, packets);

    static const uint8_t qsn[] = {'Q', 'S', 'N', 1};
    emit("qsn", qsn, sizeof qsn, packets);

    static const uint8_t garbage[20] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    };
    emit("garbage", garbage, sizeof garbage, packets);
    emit("short", d2k_test_v1_initial, 10, packets);
    emit("empty", NULL, 0, packets);

    if (packets) { fclose(packets); }
    return 0;
}
