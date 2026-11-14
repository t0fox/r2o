/* C-оракул: d2k_nl_packet (datapath/nl.c:79-161) — разбор NFQA-атрибутов.
 *
 * Тело сообщения: 4 байта nfgenmsg + атрибуты netlink (native endian для
 * длины/типа, big endian для значений). Печатаются все поля d2k_nl_pkt.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_nl.h"

static void wh16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void w32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static size_t align4(size_t v) { return (v + 3u) & ~(size_t)3u; }

/* Добавить атрибут с выравниванием; возвращает новый offset. */
static size_t put_attr(uint8_t *body, size_t offset, uint16_t type,
                       const uint8_t *value, size_t length) {
    size_t total = 4 + length;
    wh16(body + offset, (uint16_t)total);
    wh16(body + offset + 2, type);
    if (length) memcpy(body + offset + 4, value, length);
    size_t padded = align4(total);
    for (size_t i = total; i < padded; i++) body[offset + i] = 0;
    return offset + padded;
}

/* Атрибут без выравнивающего хвоста (последний в теле). */
static size_t put_attr_raw(uint8_t *body, size_t offset, uint16_t type,
                           const uint8_t *value, size_t length) {
    size_t total = 4 + length;
    wh16(body + offset, (uint16_t)total);
    wh16(body + offset + 2, type);
    if (length) memcpy(body + offset + 4, value, length);
    return offset + total;
}

static void print_case(const char *name, const uint8_t *body, size_t length) {
    d2k_nl_msg message;
    memset(&message, 0, sizeof message);
    message.body = body;
    message.body_len = length;
    d2k_nl_pkt packet;
    int rc = d2k_nl_packet(&message, &packet);
    printf("%s rc=%d", name, rc);
    if (rc != 0) {
        printf("\n");
        return;
    }
    printf(" ");
    if (packet.have_hdr) {
        printf("id=%08x hw=%04x hook=%u ", packet.id, packet.hw_protocol, packet.hook);
    } else {
        printf("id=- hw=- hook=- ");
    }
    if (packet.have_mark) printf("mark=%x ", packet.mark); else printf("mark=- ");
    printf("cap=%u skb=%u ", packet.cap_len, packet.skb_info);
    if (packet.have_outdev) printf("outdev=%u ", packet.outdev); else printf("outdev=- ");
    if (packet.have_tstamp) printf("ts=%llu ", (unsigned long long)packet.tstamp_ns);
    else printf("ts=- ");
    printf("plen=%zu trunc=%d\n", packet.have_payload ? packet.payload_len : 0,
           packet.truncated);
}

int main(void) {
    uint8_t body[512];
    uint8_t value[32];
    size_t offset;

#define RESET() do { memset(body, 0, sizeof body); offset = D2K_NFGENMSG_LEN; } while (0)

    /* A: все поля. */
    RESET();
    w32be(value, 0x11223344u);
    value[4] = 0x08; value[5] = 0x00; value[6] = 3;
    offset = put_attr(body, offset, D2K_NFQA_PACKET_HDR, value, 7);
    offset = put_attr(body, offset, D2K_NFQA_PAYLOAD, (const uint8_t *)"abc", 3);
    w32be(value, 3);
    offset = put_attr(body, offset, D2K_NFQA_CAP_LEN, value, 4);
    w32be(value, 0x2e);
    offset = put_attr(body, offset, D2K_NFQA_MARK, value, 4);
    w32be(value, 0x100);
    offset = put_attr(body, offset, D2K_NFQA_SKB_INFO, value, 4);
    w32be(value, 7);
    offset = put_attr(body, offset, D2K_NFQA_IFINDEX_OUTDEV, value, 4);
    memset(value, 0, 16);
    w32be(value + 4, 1);
    w32be(value + 12, 500000);
    offset = put_attr(body, offset, D2K_NFQA_TIMESTAMP, value, 16);
    print_case("A all", body, offset);

    /* B: cap_len больше PAYLOAD. */
    RESET();
    offset = put_attr(body, offset, D2K_NFQA_PAYLOAD, (const uint8_t *)"abc", 3);
    w32be(value, 10);
    offset = put_attr(body, offset, D2K_NFQA_CAP_LEN, value, 4);
    print_case("B truncated", body, offset);

    /* C: CAP_LEN без PAYLOAD — C выставляет truncated. */
    RESET();
    w32be(value, 10);
    offset = put_attr(body, offset, D2K_NFQA_CAP_LEN, value, 4);
    print_case("C cap-only", body, offset);

    /* D: CAP_LEN=0 без PAYLOAD — не обрезан. */
    RESET();
    w32be(value, 0);
    offset = put_attr(body, offset, D2K_NFQA_CAP_LEN, value, 4);
    print_case("D cap-zero", body, offset);

    /* E: короткий PACKET_HDR (vlen=6). */
    RESET();
    memset(value, 0x11, 6);
    offset = put_attr(body, offset, D2K_NFQA_PACKET_HDR, value, 6);
    print_case("E short-hdr", body, offset);

    /* F: timestamp sec=0. */
    RESET();
    memset(value, 0, 16);
    w32be(value + 12, 500000);
    offset = put_attr(body, offset, D2K_NFQA_TIMESTAMP, value, 16);
    print_case("F ts-sec-zero", body, offset);

    /* G: usec=1e6. */
    RESET();
    memset(value, 0, 16);
    w32be(value + 4, 1);
    w32be(value + 12, 1000000);
    offset = put_attr(body, offset, D2K_NFQA_TIMESTAMP, value, 16);
    print_case("G ts-usec-big", body, offset);

    /* H: sec=18e9 (граница не включается). */
    RESET();
    memset(value, 0, 16);
    {
        uint64_t sec = 18000000000ull;
        value[0] = (uint8_t)(sec >> 56); value[1] = (uint8_t)(sec >> 48);
        value[2] = (uint8_t)(sec >> 40); value[3] = (uint8_t)(sec >> 32);
        value[4] = (uint8_t)(sec >> 24); value[5] = (uint8_t)(sec >> 16);
        value[6] = (uint8_t)(sec >> 8); value[7] = (uint8_t)sec;
    }
    w32be(value + 12, 500000);
    offset = put_attr(body, offset, D2K_NFQA_TIMESTAMP, value, 16);
    print_case("H ts-sec-big", body, offset);

    /* I: тип с флагом 0x4000 маскируется до PACKET_HDR. */
    RESET();
    w32be(value, 0xAABBCCDDu);
    value[4] = 0x08; value[5] = 0x00; value[6] = 4;
    offset = put_attr(body, offset, 0x4000 | D2K_NFQA_PACKET_HDR, value, 7);
    print_case("I masked-type", body, offset);

    /* J: битая длина после валидного заголовка. */
    RESET();
    w32be(value, 1);
    value[4] = 0x08; value[5] = 0x00; value[6] = 1;
    offset = put_attr(body, offset, D2K_NFQA_PACKET_HDR, value, 7);
    wh16(body + offset, 100);
    wh16(body + offset + 2, D2K_NFQA_MARK);
    offset += 4;
    print_case("J bad-len", body, offset);

    /* K: длина атрибута меньше 4. */
    RESET();
    wh16(body + offset, 2);
    wh16(body + offset + 2, D2K_NFQA_MARK);
    offset += 4;
    print_case("K tiny-len", body, offset);

    /* L: неизвестный атрибут игнорируется, затем MARK. */
    RESET();
    offset = put_attr(body, offset, 99, (const uint8_t *)"zz", 2);
    w32be(value, 0x2e);
    offset = put_attr(body, offset, D2K_NFQA_MARK, value, 4);
    print_case("L unknown", body, offset);

    /* M: тело короче nfgenmsg. */
    RESET();
    print_case("M short-body", body, 3);

    /* N: PAYLOAD без CAP_LEN. */
    RESET();
    offset = put_attr(body, offset, D2K_NFQA_PAYLOAD, (const uint8_t *)"abcd", 4);
    print_case("N payload", body, offset);

    /* O: последний атрибут без выравнивающего хвоста. */
    RESET();
    offset = put_attr(body, offset, D2K_NFQA_PACKET_HDR, value, 7);
    w32be(value, 0x11223344u);
    value[4] = 0x08; value[5] = 0x00; value[6] = 2;
    offset = put_attr(body, offset, D2K_NFQA_PACKET_HDR, value, 7);
    offset = put_attr_raw(body, offset, D2K_NFQA_PAYLOAD, (const uint8_t *)"abc", 3);
    print_case("O unaligned", body, offset);

#undef RESET
    return 0;
}
