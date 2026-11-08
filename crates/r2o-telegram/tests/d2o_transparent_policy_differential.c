/* TG16: C-оракул политики прозрачного перехвата.
 *
 * Включает production `transparent.c`, чтобы вызвать static `destination_allowed`
 * с теми же порогами/port/CIDR/self-dial, что использует runtime.
 */
#define _POSIX_C_SOURCE 200809L
#include "transparent.c"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static const uint16_t valid_ports[] = {443, 5222};
static const char *const valid_cidrs[] = {
    "149.154.0.0/16", "2001:67c::/32", "0.0.0.0/0"
};

static void run_case(const char *name, const char *address, uint16_t port,
                     const uint16_t *ports, size_t port_count,
                     const char *const *cidrs, size_t cidr_count) {
    tg_transparent_policy policy = {
        .allowed_ports = ports,
        .allowed_port_count = port_count,
        .allowed_cidrs = cidrs,
        .allowed_cidr_count = cidr_count,
    };
    tg_listener_destination destination = {0};
    destination.port = port;
    if (inet_pton(AF_INET, address, destination.address) == 1) {
        destination.family = AF_INET;
    } else if (inet_pton(AF_INET6, address, destination.address) == 1) {
        destination.family = AF_INET6;
    } else {
        printf("%s invalid-address\n", name);
        return;
    }
    printf("%s allowed=%d\n", name, destination_allowed(&policy, &destination));
}

int main(void) {
    uint16_t ports33[33];
    const char *cidrs65[65];
    for (size_t i = 0; i < 33; i++) ports33[i] = 443;
    for (size_t i = 0; i < 65; i++) cidrs65[i] = "0.0.0.0/0";

    run_case("valid-v4", "149.154.167.51", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("valid-v6", "2001:67c:4e8:f002::a", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("port-80", "149.154.167.51", 80,
             valid_ports, 2, valid_cidrs, 3);
    run_case("port-0", "149.154.167.51", 0,
             valid_ports, 2, valid_cidrs, 3);
    run_case("port-not-listed", "149.154.167.51", 8080,
             valid_ports, 2, valid_cidrs, 3);
    run_case("empty-ports", "149.154.167.51", 443,
             NULL, 0, valid_cidrs, 3);
    run_case("too-many-ports", "149.154.167.51", 443,
             ports33, 33, valid_cidrs, 3);
    run_case("empty-cidrs", "149.154.167.51", 443,
             valid_ports, 2, NULL, 0);
    run_case("too-many-cidrs", "149.154.167.51", 443,
             valid_ports, 2, cidrs65, 65);
    run_case("cidr-miss", "8.8.8.8", 443,
             valid_ports, 2, valid_cidrs, 1);
    run_case("private-v4", "10.0.0.1", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("cgnat", "100.64.0.1", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("loopback", "127.0.0.1", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("link-local", "169.254.1.1", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("multicast", "224.0.0.1", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("broadcast", "255.255.255.255", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("unspecified", "0.0.0.0", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("documentation", "203.0.113.1", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("ula", "fd00::1", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("link-local-v6", "fe80::1", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("documentation-v6", "2001:db8::1", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("mapped-public", "::ffff:149.154.167.51", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("mapped-loopback", "::ffff:127.0.0.1", 443,
             valid_ports, 2, valid_cidrs, 3);
    run_case("invalid-prefix-v4", "149.154.167.51", 443,
             valid_ports, 2, (const char *const[]){ "149.154.0.0/33" }, 1);
    run_case("invalid-prefix-v6", "2001:67c:4e8:f002::a", 443,
             valid_ports, 2, (const char *const[]){ "2001:67c::/129" }, 1);
    run_case("prefix-not-number", "149.154.167.51", 443,
             valid_ports, 2, (const char *const[]){ "149.154.0.0/x" }, 1);
    run_case("prefix-empty", "149.154.167.51", 443,
             valid_ports, 2, (const char *const[]){ "149.154.0.0/" }, 1);
    run_case("exact-ip", "149.154.167.51", 443,
             valid_ports, 2, (const char *const[]){ "149.154.167.51" }, 1);
    return 0;
}
