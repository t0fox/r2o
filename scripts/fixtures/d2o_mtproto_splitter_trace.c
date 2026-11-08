#include "tg_mtproto_splitter.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t bytes[16][256];
    size_t len[16];
    size_t count;
} capture;

static int collect(void *ctx, const uint8_t *packet, size_t len) {
    capture *out = ctx;
    if (!out || !packet || out->count >= 16 || len > sizeof out->bytes[0]) return -1;
    memcpy(out->bytes[out->count], packet, len);
    out->len[out->count++] = len;
    return 0;
}

static void print_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
}

static void run(const char *name, tg_mtproto_proto proto,
                const uint8_t *plain, const size_t *cuts, size_t cut_count,
                int flush) {
    tg_mtproto_splitter splitter;
    tg_mtproto_ctr encrypt = {0};
    uint8_t key[32] = {0}, iv[16] = {0};
    capture out = {0};
    if (tg_mtproto_ctr_init(&encrypt, key, iv) != 0) {
        printf("%s=ctr-error\n", name);
        return;
    }
    if (tg_mtproto_splitter_init(&splitter, proto) != 0) {
        printf("%s=splitter-error\n", name);
        return;
    }
    size_t offset = 0;
    int result = 0;
    for (size_t i = 0; i < cut_count; i++) {
        const size_t len = cuts[i];
        if (len > 0) {
            result = tg_mtproto_splitter_feed(&splitter, &encrypt,
                                              (uint8_t *)plain + offset, len,
                                              collect, &out);
            if (result != 0) break;
        }
        offset += len;
    }
    if (result == 0 && flush) {
        result = tg_mtproto_splitter_flush(&splitter, collect, &out);
    }
    printf("%s=result:%d frames:", name, result);
    for (size_t i = 0; i < out.count; i++) {
        if (i) putchar(',');
        print_hex(out.bytes[i], out.len[i]);
    }
    printf(" error:%d\n", tg_mtproto_splitter_error(&splitter));
    tg_mtproto_splitter_destroy(&splitter);
    tg_mtproto_ctr_destroy(&encrypt);
}

int main(void) {
    {
        const uint8_t packet[] = {8, 0, 0, 0, 'A', 'B', 'C', 'D', 'W', 'X', 'Y', 'Z'};
        const size_t cuts[] = {5, 7};
        run("padded_split", TG_MTPROTO_PADDED_INTERMEDIATE, packet, cuts, 2, 0);
    }
    {
        const uint8_t packets[] = {
            8, 0, 0, 0, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            4, 0, 0, 0, 'W', 'X', 'Y', 'Z',
        };
        const size_t cuts[] = {sizeof packets};
        run("intermediate_two", TG_MTPROTO_INTERMEDIATE, packets, cuts, 1, 0);
    }
    {
        const uint8_t packet[] = {2, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
        const size_t cuts[] = {3, 6};
        run("abridged_short", TG_MTPROTO_ABRIDGED, packet, cuts, 2, 0);
    }
    {
        const uint8_t packet[] = {0x7f, 2, 0, 0, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
        const size_t cuts[] = {4, 8};
        run("abridged_extended", TG_MTPROTO_ABRIDGED, packet, cuts, 2, 0);
    }
    {
        const uint8_t packet[] = {12, 0, 0, 0, 'A', 'B', 'C'};
        const size_t cuts[] = {7};
        run("partial_flush", TG_MTPROTO_INTERMEDIATE, packet, cuts, 1, 1);
    }
    return 0;
}
