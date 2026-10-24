#define _POSIX_C_SOURCE 200809L

#ifndef D2O_SCHED_SOURCE
#error "D2O_SCHED_SOURCE must name the donor sched.c"
#endif
#include D2O_SCHED_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *fixture = fopen(argv[1], "r");
    if (!fixture) return 2;

    char name[64];
    int network_probe;
    char line[256];
    unsigned rows = 0;
    while (fgets(line, sizeof line, fixture)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%63s %d", name, &network_probe) != 2 ||
            (network_probe != 0 && network_probe != 1)) {
            fclose(fixture);
            return 3;
        }

        task target;
        memset(&target, 0, sizeof target);
        target.net_probing = network_probe;
        printf("%s %d\n", name, sched_probe_cap(&target));
        rows++;
    }
    fclose(fixture);
    return rows == 2 ? 0 : 4;
}
