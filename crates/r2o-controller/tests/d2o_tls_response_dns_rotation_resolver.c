#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char owned_result[] = "r2o-response-rotate-resolver";
static unsigned long resolutions;

typedef int (*getaddrinfo_fn)(const char *, const char *,
                              const struct addrinfo *, struct addrinfo **);
typedef void (*freeaddrinfo_fn)(struct addrinfo *);

static getaddrinfo_fn next_getaddrinfo(void)
{
    static getaddrinfo_fn function;
    if (function == NULL) {
        *(void **)(&function) = dlsym(RTLD_NEXT, "getaddrinfo");
    }
    return function;
}

static freeaddrinfo_fn next_freeaddrinfo(void)
{
    static freeaddrinfo_fn function;
    if (function == NULL) {
        *(void **)(&function) = dlsym(RTLD_NEXT, "freeaddrinfo");
    }
    return function;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **result)
{
    struct addrinfo *answer;
    struct sockaddr_in *address;
    unsigned long turn;
    char *end;
    unsigned long port;

    if (node == NULL || strcmp(node, "r2o-response-rotate.test") != 0) {
        getaddrinfo_fn function = next_getaddrinfo();
        return function == NULL ? EAI_FAIL : function(node, service, hints, result);
    }
    if (hints != NULL && hints->ai_family != AF_UNSPEC &&
        hints->ai_family != AF_INET) {
        return EAI_FAMILY;
    }
    port = 0;
    if (service != NULL) {
        port = strtoul(service, &end, 10);
        if (*service == '\0' || *end != '\0' || port > 65535) {
            return EAI_SERVICE;
        }
    }

    answer = calloc(1, sizeof(*answer));
    address = calloc(1, sizeof(*address));
    if (answer == NULL || address == NULL) {
        free(answer);
        free(address);
        return EAI_MEMORY;
    }
    turn = __atomic_fetch_add(&resolutions, 1, __ATOMIC_RELAXED);
    answer->ai_flags = hints == NULL ? 0 : hints->ai_flags;
    answer->ai_family = AF_INET;
    answer->ai_socktype = hints == NULL || hints->ai_socktype == 0
        ? SOCK_STREAM : hints->ai_socktype;
    answer->ai_protocol = hints == NULL ? 0 : hints->ai_protocol;
    answer->ai_addrlen = sizeof(*address);
    answer->ai_addr = (struct sockaddr *)address;
    answer->ai_canonname = (char *)owned_result;
    address->sin_family = AF_INET;
    address->sin_port = htons((uint16_t)port);
    address->sin_addr.s_addr = htonl((turn & 1) == 0 ? 0x7f000001U : 0x7f000002U);
    *result = answer;
    return 0;
}

void freeaddrinfo(struct addrinfo *result)
{
    if (result != NULL && result->ai_canonname == owned_result) {
        free(result->ai_addr);
        free(result);
        return;
    }
    {
        freeaddrinfo_fn function = next_freeaddrinfo();
        if (function != NULL) {
            function(result);
        }
    }
}
