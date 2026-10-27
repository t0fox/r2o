#include "d2k_httpsearch.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int open_port(void *ctx, uint8_t family, int *fd, uint16_t *sport_be)
{
    (void)ctx;
    (void)family;
    *fd = 7;
    *sport_be = htons(12345);
    return 0;
}

static d2k_hs_job captured;
static unsigned started;

static void close_port(void *ctx, int fd)
{
    (void)ctx;
    (void)fd;
}

static int start_probe(void *ctx, const d2k_hs_job *job)
{
    (void)ctx;
    captured = *job;
    started++;
    return 0;
}

int main(int argc, char **argv)
{
    static const uint8_t address[4] = {192, 0, 2, 1};
    d2k_hs_ops ops = {
        .open_port = open_port,
        .close_port = close_port,
        .start_probe = start_probe,
    };
    d2k_httpsearch *search;
    char line[128], host[64];
    FILE *fixture;
    unsigned long long tasks = 0;
    int64_t now = 1;

    if (argc != 2 || !(fixture = fopen(argv[1], "r"))) return 2;
    search = d2k_httpsearch_new(&ops);
    if (!search) {
        fclose(fixture);
        return 2;
    }
    while (fgets(line, sizeof(line), fixture)) {
        unsigned index;
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "task=%u", &index) != 1) {
            fclose(fixture);
            d2k_httpsearch_free(search);
            return 2;
        }
        snprintf(host, sizeof(host), "queue-%03u.example", index);
        d2k_httpsearch_portal(search, host, 4, address, (int64_t)index + 1);
        tasks++;
    }
    fclose(fixture);
    if (started != 1) {
        d2k_httpsearch_free(search);
        return 1;
    }
    for (unsigned long long completed = 0;
         d2k_httpsearch_busy(search) && completed < tasks; completed++) {
        const d2k_hs_result result = {
            .answer = D2K_HS_REAL,
            .seq = captured.seq,
            .fd = captured.fd,
        };
        d2k_httpsearch_result(search, &result, ++now);
    }
    if (d2k_httpsearch_busy(search) || started != tasks) {
        d2k_httpsearch_free(search);
        return 1;
    }
    printf("http_queued=%llu\n", tasks - 1);
    d2k_httpsearch_free(search);
    return 0;
}
