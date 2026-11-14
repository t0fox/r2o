/* C-оракул: tcp_watch (datapath/session.c:3257-3261).
 *
 * session.c включается целиком: функция статическая. Мусорные секции
 * выбрасываются --gc-sections. */
#include "session.c"

#include <stdio.h>
#include <string.h>

int main(void) {
    for (unsigned mask = 0; mask < 64; mask++) {
        d2k_flow flow;
        memset(&flow, 0, sizeof flow);
        flow.key.proto = 6;
        flow.saw_hello = 1;
        flow.had_sni = !(mask & 1);
        flow.rev_payload_after_hello = (mask & 2) ? 0 : 1;
        flow.suspected = (mask & 4) ? 1 : 0;
        flow.controller_probe = (mask & 8) ? 1 : 0;
        flow.pending_fin = (mask & 16) ? 1 : 0;
        flow.tcp_watch_off = (mask & 32) ? 1 : 0;
        printf("case=%u rc=%d\n", mask, tcp_watch(&flow));
    }
    return 0;
}
