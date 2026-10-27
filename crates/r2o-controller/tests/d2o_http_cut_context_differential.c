#include "d2k_httpsearch.h"

#include <stdio.h>

static d2k_hs_job captured;
static int next_fd = 10;
static unsigned started;

static int open_port(void *ctx, uint8_t family, int *fd, uint16_t *sport_be)
{
    (void)ctx;
    (void)family;
    *fd = next_fd++;
    *sport_be = (uint16_t)(next_fd + 1000);
    return 0;
}

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

int main(void)
{
    static const uint8_t address[4] = {192, 0, 2, 10};
    const d2k_hs_ops ops = {
        .open_port = open_port,
        .close_port = close_port,
        .start_probe = start_probe,
    };
    d2k_httpsearch *search = d2k_httpsearch_new(&ops);
    if (!search) return 2;

    d2k_httpsearch_cut(search, "example.com", 4, address, "/watch/first", 33120, 100);
    if (started != 1) return 3;
    d2k_hs_result baseline = {
        .answer = D2K_HS_INJECTED,
        .seq = captured.seq,
        .fd = captured.fd,
    };
    d2k_httpsearch_result(search, &baseline, 200);
    d2k_httpsearch_portal(search, "example.com", 4, address,
                          200 + D2K_HS_RECHECK_MS + 1);
    if (started != 2) return 4;

    const char *path = (captured.cut || captured.repeat_path[0])
        ? captured.repeat_path
        : "/";
    printf("request_path=%s\nbaseline=%s\n",
           path, captured.cut ? "Cut" : "Injected");
    d2k_httpsearch_free(search);
    return 0;
}
