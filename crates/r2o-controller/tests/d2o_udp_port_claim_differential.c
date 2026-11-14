/* C-оракул: d2k_udp_port_claim (core/meas.c:313-339).
 *
 * Использование: d2o-udp-port-claim PORTS
 * PORTS — по одному номеру UDP-порта в строке; для каждого создаётся
 * AF_INET/SOCK_DGRAM сокет, bind 127.0.0.1:port, claim, close.
 */
#define _POSIX_C_SOURCE 200809L
#include "d2k_meas.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *ports = fopen(argv[1], "r");
    if (!ports) return 3;
    d2k_udp_port_forget_all();
    char line[64];
    while (fgets(line, sizeof line, ports)) {
        unsigned port = 0;
        if (sscanf(line, "%u", &port) != 1) continue;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            printf("%u rc=-1\n", port);
            continue;
        }
        struct sockaddr_in address;
        memset(&address, 0, sizeof address);
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)port);
        address.sin_addr.s_addr = htonl(0x7f000001u);
        if (bind(fd, (struct sockaddr *)&address, sizeof address) != 0) {
            printf("%u bind-error\n", port);
            close(fd);
            continue;
        }
        int rc = d2k_udp_port_claim(fd);
        printf("%u rc=%d\n", port, rc);
        close(fd);
    }
    fclose(ports);
    return 0;
}
