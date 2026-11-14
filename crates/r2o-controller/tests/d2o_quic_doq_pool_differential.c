/* C-оракул DoQ-правила current main 7a5fab9: для port=853 classify_run
 * не вызывает d2k_quic_build_pool (и, значит, resolve hook), а для прочих
 * портов вызывает. Наблюдаем крючок резолвера и ранний выход без контроля.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_quicprobe.h"

static unsigned resolve_calls;

static size_t mock_resolve(const char *sni, char out[][D2K_QUIC_ADDR_LEN],
                           size_t cap)
{
    (void)sni;
    resolve_calls++;
    if (cap == 0) { return 0; }
    snprintf(out[0], D2K_QUIC_ADDR_LEN, "192.0.2.2");
    return cap >= 2 ? 2 : 1;
}

static void run_case(const char *name, const char *ip, uint16_t port)
{
    static const uint8_t trigger_byte[] = {0x01};
    d2k_hello trigger = {.bytes = (uint8_t *)trigger_byte, .len = sizeof trigger_byte};
    d2k_hello control = {0};
    resolve_calls = 0;
    (void)d2k_quic_classify(ip, port, "doq.example", trigger, control, 0);
    printf("case=%s port=%u resolve_calls=%u\n",
           name, (unsigned)port, resolve_calls);
}

int main(void)
{
    d2k_quic_resolve_hook = mock_resolve;
    run_case("doq-v4", "192.0.2.10", 853);
    run_case("regular-v4", "192.0.2.10", 443);
    run_case("doq-v6", "2001:db8::10", 853);
    return 0;
}
