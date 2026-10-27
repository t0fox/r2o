#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tg_mtproto_splitter.h"

static size_t emitted;

static int collect(void *context, const uint8_t *packet, size_t len) {
    (void)context;
    (void)packet;
    (void)len;
    ++emitted;
    return 0;
}

int main(void) {
    const size_t too_large = TG_MTPROTO_MAX_PACKET + 1u;
    uint8_t key[32] = {1}, iv[16] = {2}, raw_byte = 0x5a;
    uint8_t zero_header[4] = {0};
    uint8_t *raw = malloc(too_large);
    tg_mtproto_ctr encrypt = {0};
    tg_mtproto_splitter splitter;
    if (!raw) return 2;
    memset(raw, raw_byte, too_large);
    if (tg_mtproto_ctr_init(&encrypt, key, iv) != 0 ||
        tg_mtproto_splitter_init(&splitter, TG_MTPROTO_PADDED_INTERMEDIATE) != 0)
        return 2;
    if (tg_mtproto_splitter_feed(&splitter, &encrypt, zero_header,
                                 sizeof(zero_header), collect, NULL) != 0 ||
        !splitter.disabled || emitted != 1)
        return 1;

    int result = tg_mtproto_splitter_feed(&splitter, &encrypt, raw, too_large,
                                          collect, NULL);
    int unchanged = 1;
    for (size_t i = 0; i < too_large; ++i)
        if (raw[i] != raw_byte) unchanged = 0;
    printf("%d\t%d\t%zu\t%d\n", result, tg_mtproto_splitter_error(&splitter),
           emitted, unchanged);
    tg_mtproto_splitter_destroy(&splitter);
    tg_mtproto_ctr_destroy(&encrypt);
    free(raw);
    return 0;
}
