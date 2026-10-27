#define _GNU_SOURCE

#include "epoll_proxy.c"

#include <stdio.h>
#include <stdlib.h>

static const uint8_t test_handshake[TG_MTPROTO_HANDSHAKE_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x87,0xae,0xb3,0xfe,0x05,0x9b,0x48,0x07
};

static int decode_hex(const char *hex, uint8_t *out, size_t cap, size_t *len) {
    size_t chars = strlen(hex);
    if ((chars & 1u) || chars / 2u > cap) return -1;
    for (size_t i = 0; i < chars / 2u; ++i) {
        unsigned value;
        if (sscanf(hex + 2u * i, "%2x", &value) != 1) return -1;
        out[i] = (uint8_t)value;
    }
    *len = chars / 2u;
    return 0;
}

static const char *result_name(int result) {
    return result < 0 ? "I" : result > 0 ? "C" : "P";
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *input = fopen(argv[1], "r");
    if (!input) return 2;
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t line_len;
    int failed = 0;
    while ((line_len = getline(&line, &line_cap, input)) >= 0) {
        (void)line_len;
        if (line[0] == '#' || line[0] == '\n') continue;
        char *save = NULL;
        char *name = strtok_r(line, "\t\r\n", &save);
        char *proto_text = strtok_r(NULL, "\t\r\n", &save);
        char *chunks_text = strtok_r(NULL, "\t\r\n", &save);
        char *clear_hex = strtok_r(NULL, "\t\r\n", &save);
        char *expected = strtok_r(NULL, "\t\r\n", &save);
        if (!name || !proto_text || !chunks_text || !clear_hex || !expected) {
            failed = 1;
            break;
        }

        proxy_connection connection = {0};
        connection.wss_proto = (tg_mtproto_proto)strtol(proto_text, NULL, 10);
        if (connection.wss_proto < TG_MTPROTO_ABRIDGED ||
            connection.wss_proto > TG_MTPROTO_PADDED_INTERMEDIATE) {
            failed = 1;
            break;
        }
        connection.response_header_needed =
            connection.wss_proto == TG_MTPROTO_ABRIDGED ? 0u : 4u;

        uint8_t clear[65536];
        size_t clear_len = 0;
        if (decode_hex(clear_hex, clear, sizeof(clear), &clear_len) != 0) {
            failed = 1;
            break;
        }
        tg_mtproto_ctr encrypt = {0};
        if (tg_mtproto_direct_server_stream_cipher(test_handshake, &encrypt) != 0 ||
            tg_mtproto_ctr_xor(&encrypt, clear, clear_len) != 0 ||
            tg_mtproto_direct_server_stream_cipher(test_handshake,
                                                  &connection.server_decrypt) != 0) {
            tg_mtproto_ctr_destroy(&encrypt);
            failed = 1;
            break;
        }
        tg_mtproto_ctr_destroy(&encrypt);

        char encrypted_hex[sizeof(clear) * 2u + 1u];
        for (size_t i = 0; i < clear_len; ++i)
            (void)snprintf(encrypted_hex + 2u * i, 3u, "%02x", clear[i]);
        encrypted_hex[2u * clear_len] = '\0';

        char chunks_copy[512];
        if (strlen(chunks_text) >= sizeof(chunks_copy)) {
            failed = 1;
            tg_mtproto_ctr_destroy(&connection.server_decrypt);
            break;
        }
        strcpy(chunks_copy, chunks_text);
        size_t offset = 0;
        char outcomes[512] = {0};
        size_t outcomes_len = 0;
        char *chunk_save = NULL;
        for (char *part = strtok_r(chunks_copy, ",", &chunk_save); part;
             part = strtok_r(NULL, ",", &chunk_save)) {
            char *end = NULL;
            unsigned long amount = strtoul(part, &end, 10);
            if (!end || *end || !amount || amount > clear_len - offset) {
                failed = 1;
                break;
            }
            int result = observe_mtproto_response(&connection, clear + offset,
                                                  (size_t)amount);
            offset += (size_t)amount;
            const char *label = result_name(result);
            size_t label_len = strlen(label);
            if (outcomes_len + label_len + (outcomes_len ? 1u : 0u) >=
                sizeof(outcomes)) {
                failed = 1;
                break;
            }
            if (outcomes_len) outcomes[outcomes_len++] = ',';
            memcpy(outcomes + outcomes_len, label, label_len);
            outcomes_len += label_len;
            outcomes[outcomes_len] = '\0';
            if (result < 0) break;
        }
        if (offset != clear_len || strcmp(outcomes, expected) != 0) failed = 1;
        if (!failed) {
            fprintf(stderr, "d2o C %s: %s\n", name, outcomes);
            printf("%s\t%s\t%s\t%s\t%s\n", name, proto_text, chunks_text,
                   encrypted_hex, outcomes);
        }
        tg_mtproto_ctr_destroy(&connection.server_decrypt);
        if (failed) break;
    }
    free(line);
    fclose(input);
    return failed ? 1 : 0;
}
