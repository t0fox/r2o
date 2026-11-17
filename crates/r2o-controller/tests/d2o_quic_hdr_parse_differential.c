/* C-оракул: production `d2k_qw_hdr_parse` из core/quicwire.c. */
#include "d2k_quicwire.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static size_t put_varint(uint8_t *p, size_t cap, uint64_t value)
{
    return d2k_qw_varint_write(p, cap, value);
}

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

static size_t build_long(uint8_t *out, size_t cap, uint32_t version, uint8_t raw,
                         size_t dcid_len, size_t scid_len, size_t token_len,
                         uint64_t length, size_t extra)
{
    size_t n = 0;
    if (cap < 7) { return 0; }
    out[n++] = (uint8_t)(0x80u | (raw << 4));
    out[n++] = (uint8_t)(version >> 24);
    out[n++] = (uint8_t)(version >> 16);
    out[n++] = (uint8_t)(version >> 8);
    out[n++] = (uint8_t)version;
    out[n++] = (uint8_t)dcid_len;
    for (size_t index = 0; index < dcid_len; index++) { out[n++] = (uint8_t)(0x10 + index); }
    out[n++] = (uint8_t)scid_len;
    for (size_t index = 0; index < scid_len; index++) { out[n++] = (uint8_t)(0x40 + index); }
    uint8_t kind = effective_type(version, raw);
    if (kind == D2K_QW_LT_RETRY) {
        for (size_t index = 0; index < token_len + 16; index++) {
            out[n++] = (uint8_t)(0x70 + index);
        }
        return n;
    }
    if (kind == D2K_QW_LT_INITIAL) {
        n += put_varint(out + n, cap - n, token_len);
        for (size_t index = 0; index < token_len; index++) { out[n++] = (uint8_t)(0x70 + index); }
    }
    n += put_varint(out + n, cap - n, length);
    for (uint64_t index = 0; index < length; index++) { out[n++] = (uint8_t)(0x90 + index); }
    for (size_t index = 0; index < extra; index++) { out[n++] = 0xee; }
    return n;
}

static void emit(const char *label, const uint8_t *bytes, size_t n, size_t dcid_len_short)
{
    d2k_qw_hdr h;
    int rc = d2k_qw_hdr_parse(bytes, n, dcid_len_short, &h);
    printf("%s,", label);
    for (size_t index = 0; index < n; index++) { printf("%02x", bytes[index]); }
    printf(",%zu,", dcid_len_short);
    if (rc != 0) {
        printf("-1\n");
        return;
    }
    printf("%d,%" PRIu32 ",%u,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu\n",
           h.long_hdr, h.version, h.type, h.dcid_off, h.dcid_len,
           h.scid_off, h.scid_len, h.token_off, h.token_len,
           h.pn_offset, h.length_claimed, h.length_width, h.packet_len);
}

int main(void)
{
    uint8_t bytes[4096];
    char label[64];

    for (int version_index = 0; version_index < 2; version_index++) {
        uint32_t version = version_index == 0 ? D2K_QW_V1 : D2K_QW_V2;
        uint8_t raw_initial = version_index == 0 ? 0 : 1;
        for (int variant = 0; variant < 4; variant++) {
            size_t dcid_len = variant == 0 ? 0 : variant == 1 ? 8 : variant == 2 ? 20 : 21;
            size_t scid_len = variant == 0 ? 0 : variant == 1 ? 8 : variant == 2 ? 20 : 21;
            size_t n = build_long(bytes, sizeof bytes, version, raw_initial, dcid_len, scid_len,
                                  0, 40, 0);
            snprintf(label, sizeof label, "v%d-d%zu-s%zu", version_index, dcid_len, scid_len);
            emit(label, bytes, n, 0);
        }
        {
            static const size_t tokens[] = {0, 1, 63, 64, 1000};
            static const uint64_t lengths[] = {17, 18, 40, 100};
            for (size_t ti = 0; ti < sizeof tokens / sizeof tokens[0]; ti++) {
                for (size_t li = 0; li < sizeof lengths / sizeof lengths[0]; li++) {
                    size_t n = build_long(bytes, sizeof bytes, version, raw_initial, 8, 8,
                                          tokens[ti], lengths[li], 0);
                    snprintf(label, sizeof label, "v%d-t%zu-l%" PRIu64, version_index,
                             tokens[ti], lengths[li]);
                    emit(label, bytes, n, 0);
                }
            }
        }
        {
            size_t n = build_long(bytes, sizeof bytes, version, raw_initial, 8, 8, 0, 100, 7);
            snprintf(label, sizeof label, "v%d-extra", version_index);
            emit(label, bytes, n, 0);
            for (size_t cut = 0; cut < n; cut += 7) {
                snprintf(label, sizeof label, "v%d-cut%zu", version_index, cut);
                emit(label, bytes, cut, 0);
            }
            uint8_t mutated[4096];
            memcpy(mutated, bytes, n);
            mutated[0] = (uint8_t)(mutated[0] ^ 0x01);
            snprintf(label, sizeof label, "v%d-pnlen", version_index);
            emit(label, mutated, n, 0);
            mutated[1] = mutated[2] = mutated[3] = mutated[4] = 0;
            snprintf(label, sizeof label, "v%d-zero-version", version_index);
            emit(label, mutated, n, 0);
            emit("short-first", bytes, 1, 0);
        }
        for (uint8_t raw = 0; raw < 4; raw++) {
            size_t n = build_long(bytes, sizeof bytes, version, raw, 8, 8, 10, 40, 0);
            snprintf(label, sizeof label, "v%d-raw%u", version_index, (unsigned)raw);
            emit(label, bytes, n, 0);
        }
    }

    for (uint8_t raw = 0; raw < 4; raw++) {
        size_t n = build_long(bytes, sizeof bytes, 3, raw, 8, 8, 10, 40, 0);
        snprintf(label, sizeof label, "v3-raw%u", (unsigned)raw);
        emit(label, bytes, n, 0);
    }
    {
        size_t n = build_long(bytes, sizeof bytes, 0, 0, 8, 8, 0, 40, 0);
        emit("zero-version", bytes, n, 0);
    }
    {
        size_t n = build_long(bytes, sizeof bytes, D2K_QW_V1, 0, 8, 8, 0, 16, 0);
        emit("v1-length16", bytes, n, 0);
    }

    for (size_t dcid = 0; dcid <= 21; dcid += 1) {
        if (dcid != 0 && dcid != 1 && dcid != 8 && dcid != 20 && dcid != 21) { continue; }
        size_t n = 0;
        bytes[n++] = 0x40;
        for (size_t index = 0; index < dcid; index++) { bytes[n++] = (uint8_t)(0x30 + index); }
        bytes[n++] = 0x00;
        snprintf(label, sizeof label, "short-d%zu", dcid);
        emit(label, bytes, n, dcid);
        emit("short-truncated", bytes, n - 1, dcid);
    }
    {
        size_t n = 0;
        bytes[n++] = 0x40;
        for (size_t index = 0; index < 8; index++) { bytes[n++] = (uint8_t)(0x30 + index); }
        bytes[n++] = 0x00;
        emit("short-dcid0", bytes, n, 0);
        emit("short-dcid21", bytes, n, 21);
    }
    return 0;
}
