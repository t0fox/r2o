#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdio.h>

#include "d2k_ctl.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    char err[160];
    d2k_ctl *control = d2k_ctl_open(argv[1], err, sizeof err);
    if (!control) {
        fprintf(stderr, "d2k_ctl_open: %s\n", err);
        return 1;
    }

    const uint8_t body[] = {1, 2, 3, 4};
    d2k_ctl_event(control, D2K_EV_HELLO, body, sizeof body);
    d2k_ctl_event(control, D2K_EV_HELLO, body, sizeof body);
    printf("control_dropped=%" PRIu64 "\n", d2k_ctl_dropped(control));
    d2k_ctl_close(control);
    return 0;
}
