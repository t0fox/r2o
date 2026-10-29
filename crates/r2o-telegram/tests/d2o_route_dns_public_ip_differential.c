#define _POSIX_C_SOURCE 200809L

#include "tg_route_dns.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

static atomic_int mock_getaddrinfo_error = EAI_NONAME;
static atomic_int mock_getaddrinfo_calls;
static atomic_int mock_socket_calls;

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **results) {
    (void)node;
    (void)service;
    (void)hints;
    if (results) *results = NULL;
    atomic_fetch_add(&mock_getaddrinfo_calls, 1);
    return atomic_load(&mock_getaddrinfo_error);
}

int __wrap_socket(int domain, int type, int protocol) {
    (void)domain;
    (void)type;
    (void)protocol;
    atomic_fetch_add(&mock_socket_calls, 1);
    errno = ECONNREFUSED;
    return -1;
}

static int return_one_address(
    void *opaque, const char *domain,
    tg_listener_destination addresses[TG_ROUTE_DNS_ADDRESS_MAX],
    size_t *count) {
    (void)domain;
    addresses[0] = *(const tg_listener_destination *)opaque;
    *count = 1;
    return 0;
}

static int route_accepts(const tg_listener_destination *address) {
    tg_route_dns *cache =
        tg_route_dns_create(NULL, 0, NULL, return_one_address, (void *)address);
    if (!cache) return -1;
    if (tg_route_dns_prefetch(cache, "edge.example") != 0) {
        tg_route_dns_destroy(cache);
        return -1;
    }

    tg_listener_destination result = {0};
    int status = 1;
    for (unsigned attempt = 0; attempt < 2000 && status == 1; ++attempt) {
        status = tg_route_dns_resolve_status(cache, "edge.example", &result);
        if (status == 1) {
            const struct timespec delay = {.tv_nsec = 1000000L};
            (void)nanosleep(&delay, NULL);
        }
    }
    tg_route_dns_destroy(cache);
    return status == 0 ? 1 : status == -1 ? 0 : -1;
}

static int compare_public_ip_vectors(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char name[64];
        char text[96];
        int expected = 0;
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%63s %95s %d", name, text, &expected) != 3) {
            fclose(file);
            return -1;
        }

        tg_listener_destination address = {.port = 443};
        address.family = strchr(text, ':') ? AF_INET6 : AF_INET;
        if (inet_pton(address.family, text, address.address) != 1) {
            fclose(file);
            return -1;
        }
        int accepted = route_accepts(&address);
        if (accepted < 0 || accepted != expected) {
            fprintf(stderr, "%s: C=%d expected=%d\n", name, accepted, expected);
            fclose(file);
            return -1;
        }
        printf("%s=%d\n", name, accepted);
    }
    fclose(file);
    return 0;
}

static int compare_negative_and_transient_system_dns(void) {
    SSL_CTX *tls = SSL_CTX_new(TLS_client_method());
    if (!tls) return -1;
    tg_route_dns *cache = tg_route_dns_create(tls, 0, NULL, NULL, NULL);
    if (!cache) {
        SSL_CTX_free(tls);
        return -1;
    }

    tg_listener_destination addresses[TG_ROUTE_DNS_ADDRESS_MAX] = {{0}};
    size_t count = 0;
    atomic_store(&mock_getaddrinfo_error, EAI_NONAME);
    atomic_store(&mock_getaddrinfo_calls, 0);
    atomic_store(&mock_socket_calls, 0);
    int negative_status =
        tg_route_dns_lookup_now(cache, "missing.example", addresses, &count);
    if (negative_status == 0 || atomic_load(&mock_getaddrinfo_calls) != 1 ||
        atomic_load(&mock_socket_calls) != 0) {
        tg_route_dns_destroy(cache);
        SSL_CTX_free(tls);
        return -1;
    }
    puts("system-negative=skip");

    atomic_store(&mock_getaddrinfo_error, EAI_AGAIN);
    atomic_store(&mock_getaddrinfo_calls, 0);
    atomic_store(&mock_socket_calls, 0);
    int transient_status =
        tg_route_dns_lookup_now(cache, "offline.example", addresses, &count);
    if (transient_status == 0 || atomic_load(&mock_getaddrinfo_calls) != 1 ||
        atomic_load(&mock_socket_calls) == 0) {
        tg_route_dns_destroy(cache);
        SSL_CTX_free(tls);
        return -1;
    }
    puts("system-transient=fallback");

    tg_route_dns_destroy(cache);
    SSL_CTX_free(tls);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || compare_public_ip_vectors(argv[1]) != 0 ||
        compare_negative_and_transient_system_dns() != 0) {
        fputs("route-DNS donor fixture failed\n", stderr);
        return 1;
    }
    return 0;
}
