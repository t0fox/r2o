#define main d2kc_unused_main
#include "d2kc.c"
#undef main

#include <stdint.h>
#include <stdio.h>

/* Наблюдаем само решение `http_search_portal`: production-функция d2kc.c
 * вызывает d2k_httpsearch_portal только для класса 3 (портал). Подменяем
 * только приёмник вызова, чтобы посчитать факт вызова. */
static int portal_calls;

void d2k_httpsearch_portal(d2k_httpsearch *hs, const char *host, uint8_t family,
                           const uint8_t *addr, int64_t now)
{
    (void)hs;
    (void)host;
    (void)family;
    (void)addr;
    (void)now;
    portal_calls++;
}

static void run(const char *name, d2k_https_state state)
{
    uint8_t addr[16] = {0};
    portal_calls = 0;
    g_hs = (d2k_httpsearch *)1;
    http_search_portal("portal.example", 4, addr, state, 1000);
    printf("%s=%d\n", name, portal_calls ? 1 : 0);
}

int main(void)
{
    run("served", D2K_HTTPS_SERVED);
    run("tls-blocked", D2K_HTTPS_TLS_BLOCKED);
    run("closed", D2K_HTTPS_CLOSED);
    run("other-name", D2K_HTTPS_OTHER_NAME);
    run("unconfirmed", D2K_HTTPS_UNCONFIRMED);
    run("unknown", D2K_HTTPS_UNKNOWN);
    run("probing", D2K_HTTPS_PROBING);
    return 0;
}
