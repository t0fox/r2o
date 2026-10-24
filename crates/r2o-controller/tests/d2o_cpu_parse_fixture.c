#include <inttypes.h>
#include <stdio.h>

#include "d2k_sched.h"

int main(void) {
    const char *cases[] = {
        "cpu 18446744073709551615 1 1 0\n",
        "cpu 0 0 0 18446744073709551615 1\n",
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        uint64_t busy = 0;
        uint64_t total = 0;
        int result = d2k_sched_cpu_parse(cases[i], &busy, &total);
        printf("%d %" PRIu64 " %" PRIu64 "\n", result, busy, total);
    }
    return 0;
}
