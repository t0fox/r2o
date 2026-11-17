/* C-оракул: production `d2k_qw_seal`/`d2k_qw_open` из core/quicwire.c. */
#include "d2k_quicwire.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static d2k_qw_keys keys = {
    .key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    .iv = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
           0xa8, 0xa9, 0xaa, 0xab},
    .hp = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
           0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f},
    .have = 1,
};

static uint8_t effective_type(uint32_t version, uint8_t raw)
{
    if (version != D2K_QW_V2) { return raw; }
    switch (raw) {
    case 1: return 0;
    case 2: return 1;
    case 3: return 2;
    default: return 3;
    }
}

static size_t build_clear_long(uint8_t *out, size_t cap, uint32_t version, uint8_t raw,
                               size_t dcid_len, size_t scid_len, size_t token_len,
                               uint64_t length)
{
    size_t n = 0;
    out[n++] = (uint8_t)(0x80u | (raw << 4));
    out[n++] = (uint8_t)(version >> 24);
    out[n++] = (uint8_t)(version >> 16);
    out[n++] = (uint8_t)(version >> 8);
    out[n++] = (uint8_t)version;
    out[n++] = (uint8_t)dcid_len;
    for (size_t index = 0; index < dcid_len; index++) { out[n++] = (uint8_t)(0x10 + index); }
    out[n++] = (uint8_t)scid_len;
    for (size_t index = 0; index < scid_len; index++) { out[n++] = (uint8_t)(0x40 + index); }
    if (effective_type(version, raw) == D2K_QW_LT_INITIAL) {
        n += d2k_qw_varint_write(out + n, cap - n, token_len);
        for (size_t index = 0; index < token_len; index++) {
            out[n++] = (uint8_t)(0x70 + index);
        }
    }
    n += d2k_qw_varint_write(out + n, cap - n, length);
    return n;
}

static void print_hex(const uint8_t *bytes, size_t n)
{
    if (n == 0) {
        putchar('-');
        return;
    }
    for (size_t index = 0; index < n; index++) { printf("%02x", bytes[index]); }
}

static void run(const char *label, size_t short_len, const uint8_t *clear, size_t clear_len,
                int long_hdr, uint64_t pn, size_t pn_len,
                const uint8_t *payload, size_t payload_len, uint64_t largest)
{
    uint8_t sealed[2048];
    size_t sealed_len = d2k_qw_seal(&keys, long_hdr, clear, clear_len, pn, pn_len,
                                    payload, payload_len, sealed, sizeof sealed);
    d2k_qw_hdr header;
    uint8_t plain[2048];
    size_t plain_len = 0;
    uint64_t opened_pn = 0;
    int status = -1;
    if (sealed_len > 0 &&
        d2k_qw_hdr_parse(sealed, sealed_len, short_len, &header) == 0 &&
        d2k_qw_open(&keys, &header, sealed, largest, plain, &plain_len, &opened_pn) == 0) {
        status = 0;
    }
    printf("%s,%zu,", label, short_len);
    print_hex(clear, clear_len);
    printf(",%" PRIu64 ",%zu,", pn, pn_len);
    print_hex(payload, payload_len);
    printf(",%" PRIu64 ",", largest);
    print_hex(sealed, sealed_len);
    printf(",%d,", status);
    print_hex(plain, status == 0 ? plain_len : 0);
    printf(",%" PRIu64 "\n", status == 0 ? opened_pn : 0);
}

int main(void)
{
    uint8_t clear[2048];
    uint8_t payload[256];
    char label[64];

    for (size_t index = 0; index < sizeof payload; index++) {
        payload[index] = (uint8_t)(0xa0 + index);
    }

    for (int vi = 0; vi < 2; vi++) {
        uint32_t version = vi == 0 ? D2K_QW_V1 : D2K_QW_V2;
        uint8_t raw_initial = vi == 0 ? 0 : 1;
        for (size_t ti = 0; ti < 2; ti++) {
            size_t token_len = ti == 0 ? 0 : 10;
            for (size_t pi = 1; pi <= 3; pi++) {
                for (size_t li = 0; li < 3; li++) {
                    size_t payload_len = li == 0 ? 0 : li == 1 ? 20 : 100;
                    size_t clear_len = build_clear_long(clear, sizeof clear, version,
                                                        raw_initial, 8, 8, token_len,
                                                        pi + payload_len + 16);
                    for (size_t largest = 0; largest <= 100; largest += 100) {
                        snprintf(label, sizeof label, "v%d-i-t%zu-p%zu-l%zu-g%zu",
                                 vi, token_len, pi, payload_len, largest);
                        run(label, 0, clear, clear_len, 1, 0x1234, pi,
                            payload, payload_len, largest);
                    }
                }
            }
        }
        for (int raw = 1; raw <= 2; raw++) {
            size_t clear_len = build_clear_long(clear, sizeof clear, version,
                                                (uint8_t)raw, 8, 8, 0, 2 + 20 + 16);
            snprintf(label, sizeof label, "v%d-k%u", vi, (unsigned)raw);
            run(label, 0, clear, clear_len, 1, 7, 2, payload, 20, 0);
        }
    }

    for (size_t pi = 1; pi <= 3; pi++) {
        for (size_t li = 0; li < 3; li++) {
            size_t payload_len = li == 0 ? 0 : li == 1 ? 20 : 100;
            size_t clear_len = 0;
            clear[clear_len++] = 0x40;
            for (size_t index = 0; index < 8; index++) {
                clear[clear_len++] = (uint8_t)(0x30 + index);
            }
            for (size_t largest = 0; largest <= 100; largest += 100) {
                snprintf(label, sizeof label, "short-p%zu-l%zu-g%zu", pi, payload_len, largest);
                run(label, 8, clear, clear_len, 0, 9, pi, payload, payload_len, largest);
            }
        }
    }

    {
        size_t clear_len = 0;
        clear[clear_len++] = 0x40;
        for (size_t index = 0; index < 8; index++) {
            clear[clear_len++] = (uint8_t)(0x30 + index);
        }
        run("short-nokey", 0, clear, clear_len, 0, 9, 1, payload, 20, 0);
        run("short-len21", 21, clear, clear_len, 0, 9, 1, payload, 20, 0);
    }
    return 0;
}
