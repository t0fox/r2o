/* TG12: C-оракул WebSocket upgrade/reassembly из D2O ws.c/ws_pump.c.
 *
 * Использование:
 *   d2o-ws upgrade
 *   d2o-ws frames DIR CASES_FILE
 */
#define _POSIX_C_SOURCE 200809L
#include "tg_ws.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const upgrade_variants[] = {
    "valid",
    "wrong-accept",
    "missing-accept",
    "upgrade-case",
    "connection-list",
    "connection-missing",
    "missing-upgrade",
    "status-200",
    "subprotocol-missing",
    "subprotocol-wrong",
    "control-char",
    "extra-bytes",
};

static void compute_accept(const char *key, char out[40]) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char source[128];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    int length = snprintf(source, sizeof source, "%s%s", key, guid);
    if (length <= 0 || (size_t)length >= sizeof source) {
        out[0] = '\0';
        return;
    }
    if (EVP_Digest(source, (size_t)length, digest, &digest_len, EVP_sha1(),
                   NULL) != 1 ||
        digest_len != 20 ||
        EVP_EncodeBlock((unsigned char *)out, digest, 20) != 28)
        out[0] = '\0';
    out[28] = '\0';
}

static void append(char *buffer, size_t cap, size_t *used, const char *text) {
    size_t length = strlen(text);
    if (*used + length >= cap) return;
    memcpy(buffer + *used, text, length);
    *used += length;
    buffer[*used] = '\0';
}

static size_t build_response(const char *variant, const char *accept, char *out,
                             size_t cap) {
    char line[512];
    size_t used = 0;
    out[0] = '\0';
    int status_200 = strcmp(variant, "status-200") == 0;
    append(out, cap, &used,
           status_200 ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 101 Switching Protocols\r\n");
    if (strcmp(variant, "missing-upgrade") != 0) {
        append(out, cap, &used, strcmp(variant, "upgrade-case") == 0
                                    ? "Upgrade: WebSocket\r\n"
                                    : "Upgrade: websocket\r\n");
    }
    if (strcmp(variant, "connection-missing") != 0) {
        append(out, cap, &used, strcmp(variant, "connection-list") == 0
                                    ? "Connection: keep-alive, Upgrade\r\n"
                                    : "Connection: Upgrade\r\n");
    }
    if (strcmp(variant, "missing-accept") != 0) {
        snprintf(line, sizeof line, "Sec-WebSocket-Accept: %s%s\r\n", accept,
                 strcmp(variant, "wrong-accept") == 0 ? "x" : "");
        append(out, cap, &used, line);
    }
    if (strcmp(variant, "subprotocol-missing") != 0) {
        append(out, cap, &used,
               strcmp(variant, "subprotocol-wrong") == 0
                   ? "Sec-WebSocket-Protocol: text\r\n"
                   : "Sec-WebSocket-Protocol: binary\r\n");
    }
    if (strcmp(variant, "control-char") == 0)
        append(out, cap, &used, "X-Test: bad\001value\r\n");
    append(out, cap, &used, "\r\n");
    if (strcmp(variant, "extra-bytes") == 0) {
        static const unsigned char frame[] = {0x82, 0x03, 'a', 'b', 'c'};
        if (used + sizeof frame < cap) {
            memcpy(out + used, frame, sizeof frame);
            used += sizeof frame;
            out[used] = '\0';
        }
    }
    return used;
}

static void run_upgrade(void) {
    for (size_t i = 0; i < sizeof upgrade_variants / sizeof upgrade_variants[0];
         ++i) {
        const char *variant = upgrade_variants[i];
        tg_ws_upgrade_state state = {0};
        if (tg_ws_upgrade_start_ex(&state, "relay.test", "/ws", "binary",
                                   "https://web.telegram.org",
                                   "r2o-tg12/1.0") != 0) {
            printf("upgrade %s ok=0\n", variant);
            continue;
        }
        size_t request_len = 0;
        const uint8_t *request = tg_ws_upgrade_pending(&state, &request_len);
        if (!request || tg_ws_upgrade_advance(&state, request_len) != 0) {
            printf("upgrade %s ok=0\n", variant);
            continue;
        }
        char accept[40];
        compute_accept(state.key, accept);
        char response[2048];
        size_t response_len = build_response(variant, accept, response,
                                             sizeof response);
        size_t consumed = 0;
        int rc = tg_ws_upgrade_feed(&state, (const uint8_t *)response,
                                    response_len, &consumed);
        printf("upgrade %s ok=%d\n", variant, rc == 1 ? 1 : 0);
    }
}

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *file = fopen(path, "rb");
    if (!file) return -1;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    long length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    uint8_t *bytes = malloc((size_t)length + 1);
    if (!bytes) {
        fclose(file);
        return -1;
    }
    size_t used = fread(bytes, 1, (size_t)length, file);
    fclose(file);
    if (used != (size_t)length) {
        free(bytes);
        return -1;
    }
    *out = bytes;
    *out_len = used;
    return 0;
}

static unsigned payload_sum(const uint8_t *data, size_t length) {
    unsigned sum = 0;
    for (size_t i = 0; i < length; ++i) sum = (sum + data[i]) & 0xffu;
    return sum;
}

static void run_frames(const char *dir, const char *cases_path) {
    FILE *cases = fopen(cases_path, "r");
    if (!cases) exit(2);
    char name[256];
    while (fgets(name, sizeof name, cases)) {
        size_t name_len = strlen(name);
        while (name_len && (name[name_len - 1] == '\n' || name[name_len - 1] == '\r'))
            name[--name_len] = '\0';
        if (!name_len) continue;
        char path[1024];
        snprintf(path, sizeof path, "%s/%s.bin", dir, name);
        uint8_t *data = NULL;
        size_t length = 0;
        if (read_file(path, &data, &length) != 0) {
            printf("frames %s error\n", name);
            continue;
        }
        tg_ws_reassembly state = {0};
        printf("frames %s", name);
        size_t offset = 0;
        int finished = 0;
        while (offset < length && !finished) {
            uint8_t opcode = 0;
            const uint8_t *payload = NULL;
            size_t payload_len = 0, consumed = 0;
            int ready = tg_ws_reassembly_feed(
                &state, data + offset, length - offset, TG_WS_MAX_MESSAGE,
                &opcode, &payload, &payload_len, &consumed);
            if (ready < 0) {
                printf(" error\n");
                finished = 1;
                break;
            }
            if (ready == 0) {
                printf(" eof\n");
                finished = 1;
                break;
            }
            offset += consumed;
            if (ready == 2) continue;
            if (opcode == TG_WS_BINARY) {
                printf(" binary len=%zu sum=%u", payload_len,
                       payload_sum(payload, payload_len));
            } else if (opcode == TG_WS_TEXT) {
                printf(" error\n");
                finished = 1;
                break;
            } else if (opcode == TG_WS_PING) {
                printf(" ping len=%zu", payload_len);
            } else if (opcode == TG_WS_PONG) {
                printf(" pong len=%zu", payload_len);
            } else if (opcode == TG_WS_CLOSE) {
                printf(" close eof\n");
                finished = 1;
                break;
            }
        }
        if (!finished) printf(" eof\n");
        tg_ws_reassembly_destroy(&state);
        free(data);
    }
    fclose(cases);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (strcmp(argv[1], "upgrade") == 0) {
        run_upgrade();
        return 0;
    }
    if (strcmp(argv[1], "frames") == 0 && argc == 4) {
        run_frames(argv[2], argv[3]);
        return 0;
    }
    return 2;
}
