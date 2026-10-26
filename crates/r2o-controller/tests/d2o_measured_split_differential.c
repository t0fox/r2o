#include <stdio.h>

#include "d2k_compose.h"

int main(void) {
    const struct {
        size_t trigger_len;
        unsigned split;
        uint32_t gap_us;
        size_t send_cap;
    } cases[] = {
        {1024, 1, 60000, 0},
        {1024, 1, 60000, 1492},
        {1024, 1, 60000, 1280},
        {1024, 1, 60000, 100},
        {1024, 1, 60000, 72},
        {1024, 0, 60000, 1492},
        {1024, 1024, 60000, 1492},
    };
    const char *verdicts[] = {"prefix", "whole_packet"};

    for (size_t verdict = 0; verdict < sizeof verdicts / sizeof verdicts[0]; verdict++) {
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            char text[4096];
            int rc = d2k_tcp_split_plan(cases[i].trigger_len, cases[i].split,
                                        cases[i].gap_us, cases[i].send_cap,
                                        text, sizeof text);
            printf("%s %zu %u %u %zu %s\n", verdicts[verdict],
                   cases[i].trigger_len, cases[i].split, cases[i].gap_us,
                   cases[i].send_cap, rc == 0 ? "plan" : "skip");
            if (rc == 0) fputs(text, stdout);
            putchar('\n');
        }
    }
    return 0;
}
