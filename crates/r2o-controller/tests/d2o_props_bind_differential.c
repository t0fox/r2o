/* C/Rust differential: d2k_props_bind* (compose.c).
 * Печатает только наблюдаемые свойства bind, без номеров портов. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "compose.c"

static void report(const char *name, int rc, int fd, uint16_t port, int family) {
    int type = 0;
    socklen_t length = sizeof type;
    if (fd >= 0) getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length);
    int v6only = 0;
    if (fd >= 0 && family == 6) {
        socklen_t v6len = sizeof v6only;
        getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &v6len);
    }
    printf("%s rc=%d port_nonzero=%d type=%d v6only=%d\n",
           name, rc, port != 0, type, v6only);
    if (fd >= 0) close(fd);
}

int main(void) {
    int fd = -1;
    uint16_t port = 0;
    int rc = d2k_props_bind(&fd, &port);
    report("tcp4", rc, fd, port, 4);

    fd = -1;
    port = 0;
    rc = d2k_props_bind_family(6, &fd, &port);
    report("tcp6", rc, fd, port, 6);

    fd = -1;
    port = 0;
    rc = d2k_props_bind_udp(&fd, &port);
    report("udp4", rc, fd, port, 4);

    fd = -1;
    port = 0;
    rc = d2k_props_bind_udp_family(6, &fd, &port);
    report("udp6", rc, fd, port, 6);

    fd = -1;
    port = 0;
    rc = d2k_props_bind_family(5, &fd, &port);
    report("invalid", rc, fd, port, 5);
    return 0;
}
