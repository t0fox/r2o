/* C-оракул: production `signal_human` из core/sched.c. */
#include "sched.c"

#include <stdio.h>
#include <string.h>

static void show(const char *kind, int volume, uint8_t ttl, int ttl_delta,
                 uint8_t tos, uint16_t ipid)
{
    d2k_cat_signal signal;
    memset(&signal, 0, sizeof signal);
    signal.ttl = ttl;
    signal.ttl_delta = ttl_delta;
    signal.tos = tos;
    signal.ipid = ipid;
    signal.volume = volume;
    snprintf(signal.kind, sizeof signal.kind, "%s", kind);
    char out[256];
    signal_human(&signal, out, sizeof out);
    printf("%s\n", out);
}

int main(void)
{
    show("rst", 0, 55, -7, 0x88, 12345);
    show("volume", 40, 0, 0, 0, 0);
    show("rx-volume", 19, 0, 0, 0, 0);
    show("rx-volume-wire", 23, 0, 0, 0, 0);
    show("silent", 0, 0, 0, 0, 0);
    show("repeat", 0, 0, 0, 0, 0);
    show("unknown-kind", 0, 0, 0, 0, 0);
    show("rst", 0, 0, -2147483647 - 1, 255, 65535);
    show("volume", -1, 0, 2147483647, 0, 0);
    return 0;
}
