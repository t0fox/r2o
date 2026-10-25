#define _GNU_SOURCE 1
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "d2k_detect.h"

static unsigned char captured[512];
static size_t captured_len;
int64_t d2k_now_ms(void) { return 0; }
static ssize_t capture_sendto(int fd, const void *buffer, size_t length, int flags,
                              const struct sockaddr *address, socklen_t address_len);

#define sendto capture_sendto
#include "raw.c"
#undef sendto
#include "trigger.c"

static ssize_t capture_sendto(int fd, const void *buffer, size_t length, int flags,
                              const struct sockaddr *address, socklen_t address_len)
{
    (void)fd;
    (void)flags;
    (void)address;
    (void)address_len;
    if (length > sizeof(captured)) return -1;
    memcpy(captured, buffer, length);
    captured_len = length;
    return (ssize_t)length;
}

static void print_hex(const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
}

int main(int argc, char **argv)
{
    char line[128];
    unsigned family;
    int offer_ts;
    FILE *fixture;
    if (argc != 2 || !(fixture = fopen(argv[1], "r"))) return 2;
    while (fgets(line, sizeof(line), fixture)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "family=%u offer_ts=%d", &family, &offer_ts) != 2 ||
            (family != 4 && family != 6) || (offer_ts != 0 && offer_ts != 1)) {
            fclose(fixture);
            return 2;
        }
        raw_conn connection = {0};
        connection.family = (uint8_t)family;
        connection.offer_ts = (uint8_t)offer_ts;
        connection.sport = 40000;
        connection.dport = 443;
        connection.seq = 0x12345678;
        int af = family == 6 ? AF_INET6 : AF_INET;
        const char *source = family == 6 ? "2001:db8::1" : "192.0.2.1";
        const char *destination = family == 6 ? "2001:db8::2" : "198.51.100.2";
        if (inet_pton(af, source, connection.src) != 1 ||
            inet_pton(af, destination, connection.dst) != 1) {
            fclose(fixture);
            return 2;
        }
        captured_len = 0;
        size_t ip_header_len = family == 6 ? 40 : 20;
        size_t tcp_header_offset = ip_header_len;
        if (raw_send_syn(&connection) != 0 || captured_len < ip_header_len + 20) {
            fclose(fixture);
            return 1;
        }
        size_t tcp_header_len = (size_t)(captured[tcp_header_offset + 12] >> 4) * 4;
        if (tcp_header_len < 20 || ip_header_len + tcp_header_len > captured_len) {
            fclose(fixture);
            return 1;
        }

        d2k_trigger trigger = {0};
        trigger.client_tcp_known = 1;
        if (offer_ts) {
            memcpy(trigger.client_tcp_options,
                   (uint8_t[]){1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0}, 12);
            trigger.client_tcp_options_len = 12;
        }
        d2k_poison poison = {0};
        poison.tcp_ts = 1;
        printf("RAW_SYN_PROFILE family=%u offer_ts=%d options=", family, offer_ts);
        print_hex(captured + tcp_header_offset + 20, tcp_header_len - 20);
        printf(" allow_ts_poison=%d\n",
               d2k_trigger_allows_poison(&trigger, &poison));
    }
    fclose(fixture);
    return 0;
}
