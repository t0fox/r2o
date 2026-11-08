/* TG8: C resPQ probe против общего fake MTProto DC.
 *
 * Использование: d2o_res_pq_probe PORT
 */
#include "tg_mtproto.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    uint16_t port = (uint16_t)strtoul(argv[1], NULL, 10);
    tg_mtproto_probe_result result;
    tg_mtproto_probe_status status = tg_mtproto_probe_res_pq(
        "127.0.0.1", port, 2, 0, 0, 3000, &result);
    printf("ok=%d\n", status == TG_MTPROTO_PROBE_OK ? 1 : 0);
    return 0;
}
