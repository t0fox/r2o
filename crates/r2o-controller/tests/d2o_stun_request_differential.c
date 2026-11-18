/* C-оракул: production `d2k_stun_request` (core/stun.c:27-45) и
 * `d2k_t13_random` (core/tls13core.c:21-27). stun.c включается как TU,
 * --gc-sections выбрасывает разбор. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "stun.c"

#include <stdio.h>
#include <string.h>

int main(void)
{
    uint8_t request[D2K_STUN_HDR_LEN];
    uint8_t txid[D2K_STUN_TXID_LEN];
    memset(request, 0xee, sizeof request);
    memset(txid, 0xee, sizeof txid);
    size_t made = d2k_stun_request(request, sizeof request, txid);
    printf("request=%zu\n", made);
    printf("header=");
    for (size_t index = 0; index < 8; index++) {
        printf("%02x", request[index]);
    }
    printf("\n");
    printf("txid_len=%d\n", D2K_STUN_TXID_LEN);
    int nonzero = 0;
    for (size_t index = 0; index < D2K_STUN_TXID_LEN; index++) {
        if (txid[index] != 0) { nonzero = 1; }
    }
    printf("txid_nonzero=%d\n", nonzero);

    uint8_t second[D2K_STUN_HDR_LEN];
    uint8_t second_txid[D2K_STUN_TXID_LEN];
    size_t made_second = d2k_stun_request(second, sizeof second, second_txid);
    printf("fresh_requests=%d\n",
           made == D2K_STUN_HDR_LEN && made_second == D2K_STUN_HDR_LEN &&
               memcmp(txid, second_txid, D2K_STUN_TXID_LEN) != 0);

    uint8_t untouched = 0x5a;
    int zero_rc = d2k_t13_random(&untouched, 0);
    printf("zero_rc=%d\n", zero_rc);
    printf("zero_unchanged=%d\n", untouched == 0x5a);

    uint8_t first_random[32];
    uint8_t second_random[32];
    int fill_rc = d2k_t13_random(first_random, sizeof first_random);
    int fill_rc_second = d2k_t13_random(second_random, sizeof second_random);
    printf("fill_rc=%d\n", fill_rc);
    int fill_nonzero = 0;
    for (size_t index = 0; index < sizeof first_random; index++) {
        if (first_random[index] != 0) { fill_nonzero = 1; }
    }
    printf("fill_nonzero=%d\n", fill_nonzero);
    printf("fresh_random=%d\n",
           fill_rc == 0 && fill_rc_second == 0 &&
               memcmp(first_random, second_random, sizeof first_random) != 0);
    return 0;
}
