#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef R2O_D2O_EPOLL_PROXY_SOURCE
#error "define R2O_D2O_EPOLL_PROXY_SOURCE to the pinned D2O epoll_proxy.c"
#endif
#include R2O_D2O_EPOLL_PROXY_SOURCE

static const uint8_t test_handshake[64] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x87,0xae,0xb3,0xfe,0x05,0x9b,0x48,0x07
};

static tg_mtproto_proto parse_proto(const char *value) {
    switch (value[0]) {
        case '1': return TG_MTPROTO_ABRIDGED;
        case '2': return TG_MTPROTO_INTERMEDIATE;
        case '3': return TG_MTPROTO_PADDED_INTERMEDIATE;
        default: abort();
    }
}

static size_t decode_hex(const char *hex, uint8_t *output, size_t capacity) {
    size_t length = strlen(hex);
    assert((length & 1u) == 0);
    assert(length / 2 <= capacity);
    for (size_t i = 0; i < length / 2; ++i) {
        unsigned value;
        assert(sscanf(hex + i * 2, "%2x", &value) == 1);
        output[i] = (uint8_t)value;
    }
    return length / 2;
}

static void run_vector(char *line) {
    char *save = NULL;
    char *name = strtok_r(line, "\t\r\n", &save);
    char *proto_text = strtok_r(NULL, "\t\r\n", &save);
    char *chunks_text = strtok_r(NULL, "\t\r\n", &save);
    char *expected = strtok_r(NULL, "\t\r\n", &save);
    assert(name && proto_text && chunks_text && expected);
    assert(strtok_r(NULL, "\t\r\n", &save) == NULL);
    (void)expected;

    proxy_connection connection = {0};
    connection.wss_proto = parse_proto(proto_text);
    connection.response_header_needed =
        connection.wss_proto == TG_MTPROTO_ABRIDGED ? 0u : 4u;
    assert(tg_mtproto_direct_server_stream_cipher(
               test_handshake, &connection.server_decrypt) == 0);
    tg_mtproto_ctr server_encrypt = {0};
    assert(tg_mtproto_direct_server_stream_cipher(test_handshake,
                                                   &server_encrypt) == 0);

    printf("%s\t", name);
    int first = 1;
    char *chunk_save = NULL;
    for (char *chunk = strtok_r(chunks_text, ";", &chunk_save); chunk;
         chunk = strtok_r(NULL, ";", &chunk_save)) {
        uint8_t bytes[16384];
        size_t length = decode_hex(chunk, bytes, sizeof(bytes));
        assert(tg_mtproto_ctr_xor(&server_encrypt, bytes, length) == 0);
        int status = observe_mtproto_response(&connection, bytes, length);
        printf("%s%d", first ? "" : ",", status);
        first = 0;
    }
    putchar('\n');

    tg_mtproto_ctr_destroy(&server_encrypt);
    tg_mtproto_ctr_destroy(&connection.server_decrypt);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    FILE *fixture = fopen(argv[1], "r");
    assert(fixture);
    char line[8192];
    while (fgets(line, sizeof(line), fixture)) {
        if (line[0] != '\n' && line[0] != '#') run_vector(line);
    }
    assert(fclose(fixture) == 0);
    return 0;
}
