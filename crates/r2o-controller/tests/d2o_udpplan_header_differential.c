/* C-оракул: production `emit_header_proto` из core/udpplan.c. */
#include "udpplan.c"

#include <stdio.h>

static void run(const char *label, const char *proto)
{
    char buf[256];
    size_t pos = 0;
    int rc = emit_header_proto(buf, sizeof buf, &pos, proto);
    buf[pos] = '\0';
    printf("%s %d %zu ", label, rc, pos);
    for (const unsigned char *p = (const unsigned char *)buf; *p; p++) {
        printf("%02x", (unsigned)*p);
    }
    putchar('\n');
}

int main(void)
{
    run("udp_quic", "udp quic");
    run("tcp_tls", "tcp tls");
    run("empty", "");
    run("long", "udp quic extra words");
    return 0;
}
