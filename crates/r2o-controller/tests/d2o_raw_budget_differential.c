#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include "sched.c"

int main(void) {
    const int raw[] = {0, 5, 67, 100};
    const int candidates[] = {0, 1, 66, 67};
    for (unsigned r = 0; r < sizeof raw / sizeof raw[0]; r++) {
        for (unsigned c = 0; c < sizeof candidates / sizeof candidates[0]; c++) {
            task t = {0};
            ask_settle(&t, raw[r]);
            t.probes = candidates[c];
            printf("%d %d %d\n", t.ask_probes, t.probes, sched_probe_cap(&t) - t.probes);
        }
    }
    return 0;
}
