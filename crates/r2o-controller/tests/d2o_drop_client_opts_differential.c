/* C-оракул: production `drop_client_opts` + `client_tcp_profile`
 * из core/sched.c. */
#include "sched.c"

#include <stdio.h>
#include <string.h>

static void run(const char *label, int known, const uint8_t *options, size_t len)
{
    task t;
    memset(&t, 0, sizeof t);
    t.client_opts_known = (uint8_t)known;
    t.client_opts_len = len;
    if (len <= sizeof t.client_opts) {
        memcpy(t.client_opts, options, len);
    }
    unsigned before = (unsigned)client_tcp_profile(&t);
    drop_client_opts(&t);
    unsigned after = (unsigned)client_tcp_profile(&t);
    printf("%s,%u,%u,%d,%zu\n", label, before, after,
           (int)t.client_opts_known, t.client_opts_len);
}

int main(void)
{
    static const uint8_t ts[] = {8, 10, 0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t no_ts[] = {2, 4, 1, 1};
    static const uint8_t empty[] = {0};
    static const uint8_t malformed[] = {8, 10};
    static const uint8_t end[] = {0};

    run("ts", 1, ts, sizeof ts);
    run("no_ts", 1, no_ts, sizeof no_ts);
    run("empty", 1, empty, 0);
    run("malformed", 1, malformed, sizeof malformed);
    run("end", 1, end, sizeof end);
    run("unknown", 0, empty, 0);
    return 0;
}
