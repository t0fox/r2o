/* C-оракул live ctnetlink: d2k_ct_open/probe/query в текущем netns. */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "d2k_ctq.h"

static void query_flow(int fd, const char *name, const char *spec,
                       uint32_t seq) {
    char src[32] = {0}, dst[32] = {0};
    unsigned sport = 0, dport = 0;
    if (!spec || sscanf(spec, "%31s %u %31s %u", src, &sport, dst, &dport) != 4)
        return;
    d2k_ct_tuple tuple;
    memset(&tuple, 0, sizeof tuple);
    tuple.family = 4;
    tuple.proto = 17;
    if (inet_pton(AF_INET, src, tuple.src) != 1 ||
        inet_pton(AF_INET, dst, tuple.dst) != 1)
        return;
    uint16_t sport_be = htons((uint16_t)sport);
    uint16_t dport_be = htons((uint16_t)dport);
    memcpy(tuple.sport_be, &sport_be, 2);
    memcpy(tuple.dport_be, &dport_be, 2);
    uint64_t orig = 0, reply = 0;
    int rc = d2k_ct_query_fd(fd, seq, &tuple, &orig, &reply);
    printf("%s rc=%d orig=%llu reply=%llu\n", name, rc,
           (unsigned long long)orig, (unsigned long long)reply);
}

int main(void) {
    int fd = d2k_ct_open();
    printf("open=%d\n", fd >= 0 ? 1 : 0);
    if (fd < 0) return 0;
    printf("probe=%d\n", d2k_ct_probe_fd(fd, 1, 200));
    d2k_ct_tuple zero;
    memset(&zero, 0, sizeof zero);
    zero.family = 4;
    zero.proto = 17;
    uint64_t orig = 0, reply = 0;
    printf("query_zero=%d\n", d2k_ct_query_fd(fd, 2, &zero, &orig, &reply));
    printf("query_zero_again=%d\n",
           d2k_ct_query_fd(fd, 3, &zero, &orig, &reply));
    query_flow(fd, "flow1", getenv("R2O_CT_LIVE_FLOW1"), 10);
    query_flow(fd, "flow2", getenv("R2O_CT_LIVE_FLOW2"), 11);
    close(fd);
    return 0;
}
