#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sched.c"

static void run_case(uint8_t transport, uint8_t family)
{
    int fd = -1;
    uint16_t sport = 0;
    int rc = bind_default(transport, family, &fd, &sport);
    int type = -1;
    int socket_family = -1;
    int wildcard = 0;
    int port_nonzero = 0;
    if (fd >= 0) {
        socklen_t len = sizeof type;
        (void)getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len);
        struct sockaddr_storage address;
        memset(&address, 0, sizeof address);
        len = sizeof address;
        if (getsockname(fd, (struct sockaddr *)&address, &len) == 0) {
            socket_family = address.ss_family;
            if (address.ss_family == AF_INET) {
                const struct sockaddr_in *in = (const struct sockaddr_in *)&address;
                port_nonzero = in->sin_port != 0;
                wildcard = in->sin_addr.s_addr == 0;
            } else if (address.ss_family == AF_INET6) {
                const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)&address;
                port_nonzero = in6->sin6_port != 0;
                wildcard = !memcmp(&in6->sin6_addr, &in6addr_any, sizeof in6->sin6_addr);
            }
        }
        close(fd);
    }
    printf("transport=%u family=%u rc=%d type=%d socket_family=%d "
           "port_nonzero=%d wildcard=%d\n",
           (unsigned)transport, (unsigned)family, rc, type, socket_family,
           port_nonzero, wildcard);
}

int main(void)
{
    run_case(6, 4);
    run_case(6, 6);
    run_case(17, 4);
    run_case(17, 6);
    return 0;
}
