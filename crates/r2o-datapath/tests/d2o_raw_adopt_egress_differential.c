/* C/Rust differential: d2k_raw_adopt_egress и pick_maxlen (datapath/raw.c).
 *
 * Проверяются реальные MTU интерфейсов текущего ядра: lo (обычно 65536),
 * отсутствующий ifindex и объявленный оператором предел (maxlen_declared),
 * который маршруту противопоставлять нельзя. Привилегий не требуется. */
#include <stdio.h>
#include <string.h>
#include <net/if.h>

#include "raw.c"

static void init_raw(d2k_raw *raw, int declared) {
    memset(raw, 0, sizeof *raw);
    raw->fd = -1;
    raw->fd6 = -1;
    raw->fragment_fd = -1;
    raw->maxlen = pick_maxlen(NULL);
    raw->maxlen_declared = declared;
}

int main(void) {
    printf("pick_null %zu\n", pick_maxlen(NULL));
    printf("pick_lo %zu\n", pick_maxlen("lo"));

    uint32_t lo = if_nametoindex("lo");
    d2k_raw raw;
    init_raw(&raw, 0);
    int rc = d2k_raw_adopt_egress(&raw, &lo, 1, NULL, 0);
    printf("adopt_lo %d maxlen=%zu egress=%zu\n", rc, raw.maxlen, raw.egress_mtu);
    rc = d2k_raw_adopt_egress(&raw, &lo, 1, NULL, 0);
    printf("adopt_lo_again %d maxlen=%zu egress=%zu\n", rc, raw.maxlen, raw.egress_mtu);

    uint32_t missing = 0x7ffffff0u;
    rc = d2k_raw_adopt_egress(&raw, &missing, 1, NULL, 0);
    printf("adopt_missing %d maxlen=%zu\n", rc, raw.maxlen);

    init_raw(&raw, 1);
    rc = d2k_raw_adopt_egress(&raw, &lo, 1, NULL, 0);
    printf("adopt_declared %d maxlen=%zu\n", rc, raw.maxlen);
    return 0;
}
