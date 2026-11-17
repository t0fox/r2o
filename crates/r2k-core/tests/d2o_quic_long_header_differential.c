/* C-оракул: production `d2k_qw_long_hdr_token_w` из core/quicwire.c. */
#include "quicwire.c"

#include <stdio.h>
#include <string.h>

struct long_case {
    const char *label;
    uint32_t version;
    uint8_t type;
    size_t dcid_len;
    size_t scid_len;
    size_t token_len;
    size_t pn_len;
    size_t payload_len;
    size_t length_width;
    size_t cap;
};

static const struct long_case cases[] = {
    {"v1_initial", 1, 0, 8, 8, 0, 1, 100, 0, 1500},
    {"v1_initial_token", 1, 0, 8, 0, 16, 2, 1200, 0, 4096},
    {"v1_initial_cid0_20", 1, 0, 0, 20, 0, 4, 0, 1, 1500},
    {"v1_initial_cid20_20", 1, 0, 20, 20, 0, 1, 0, 0, 1500},
    {"v2_initial", 0x6b3343cfu, 0, 8, 8, 0, 1, 100, 0, 1500},
    {"v2_0rtt", 0x6b3343cfu, 1, 8, 8, 0, 1, 50, 0, 1500},
    {"v1_handshake", 1, 2, 8, 8, 0, 2, 200, 0, 1500},
    {"v2_handshake", 0x6b3343cfu, 2, 8, 8, 0, 2, 200, 0, 1500},
    {"v1_retry_type", 1, 3, 8, 8, 0, 0, 0, 0, 1500},
    {"v2_retry_type", 0x6b3343cfu, 3, 8, 8, 0, 0, 0, 0, 1500},
    {"v1_0rtt_token", 1, 1, 8, 8, 4, 1, 50, 0, 1500},
    {"v1_initial_dcid21", 1, 0, 21, 8, 0, 1, 100, 0, 1500},
    {"v1_initial_scid21", 1, 0, 8, 21, 0, 1, 100, 0, 1500},
    {"v1_initial_token1", 1, 0, 8, 8, 1, 1, 100, 0, 1500},
    {"v1_width3", 1, 0, 8, 8, 0, 1, 100, 3, 1500},
    {"v1_width1_small", 1, 0, 8, 8, 0, 1, 100, 1, 1500},
    {"v1_width2_1000", 1, 0, 8, 8, 0, 1, 1000, 2, 1500},
    {"v1_cap10", 1, 0, 8, 8, 0, 1, 100, 0, 10},
    {"v1_cap0", 1, 0, 8, 8, 0, 1, 100, 0, 0},
    {"v1_pn1", 1, 0, 8, 8, 0, 1, 1200, 0, 1500},
    {"v1_pn2", 1, 0, 8, 8, 0, 2, 1200, 0, 1500},
    {"v1_pn3", 1, 0, 8, 8, 0, 3, 1200, 0, 1500},
    {"v1_pn4", 1, 0, 8, 8, 0, 4, 1200, 0, 1500},
    {"v1_unknown_version", 0xdeadbeefu, 0, 8, 8, 0, 1, 100, 0, 1500},
    {"v1_unknown_type4", 1, 4, 8, 8, 0, 1, 100, 0, 1500},
    {"v2_unknown_type4", 0x6b3343cfu, 4, 8, 8, 0, 1, 100, 0, 1500},
    {"v1_auto_reserve_cap9", 1, 0, 8, 8, 0, 1, 100, 0, 9},
};

static void print_hex(const uint8_t *bytes, size_t length)
{
    for (size_t index = 0; index < length; index++) {
        printf("%02x", (unsigned)bytes[index]);
    }
}

int main(void)
{
    for (size_t index = 0; index < sizeof cases / sizeof cases[0]; index++) {
        const struct long_case *item = &cases[index];
        uint8_t dcid[D2K_QW_CID_MAX];
        uint8_t scid[D2K_QW_CID_MAX];
        uint8_t token[D2K_QW_MAX_DGRAM];
        uint8_t out[4096];
        for (size_t i = 0; i < sizeof dcid; i++) { dcid[i] = (uint8_t)(0xa0 + i); }
        for (size_t i = 0; i < sizeof scid; i++) { scid[i] = (uint8_t)(0xb0 + i); }
        for (size_t i = 0; i < sizeof token; i++) { token[i] = (uint8_t)(0xc0 + i); }
        size_t length = d2k_qw_long_hdr_token_w(
            out, item->cap, item->version, item->type,
            item->dcid_len ? dcid : NULL, item->dcid_len,
            item->scid_len ? scid : NULL, item->scid_len,
            item->token_len ? token : NULL, item->token_len,
            item->pn_len, item->payload_len, item->length_width);
        printf("%s %zu ", item->label, length);
        if (length) {
            print_hex(out, length);
        } else {
            putchar('-');
        }
        putchar('\n');
    }
    return 0;
}
