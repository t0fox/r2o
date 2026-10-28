#include "d2k_httpsprobe.h"

#include <stdio.h>

static const char *http_search_action(d2k_https_state state, int response_code,
                                     int live_bound_failure, int probe_pending) {
    if (response_code != 3 || live_bound_failure) { return "queue"; }
    if (state == D2K_HTTPS_UNKNOWN) { return probe_pending ? "wait" : "skip"; }
    if (state == D2K_HTTPS_PROBING) { return "wait"; }
    return d2k_https_upgrade(state) ? "skip" : "queue";
}

int main(void) {
    static const struct {
        const char *name;
        d2k_https_state state;
        int response_code, live_bound_failure, probe_pending;
    } cases[] = {
        {"served", D2K_HTTPS_SERVED, 3, 0, 0},
        {"tls-blocked", D2K_HTTPS_TLS_BLOCKED, 3, 0, 0},
        {"closed", D2K_HTTPS_CLOSED, 3, 0, 0},
        {"other-name", D2K_HTTPS_OTHER_NAME, 3, 0, 0},
        {"unconfirmed", D2K_HTTPS_UNCONFIRMED, 3, 0, 0},
        {"unknown", D2K_HTTPS_UNKNOWN, 3, 0, 0},
        {"probing", D2K_HTTPS_PROBING, 3, 0, 1},
        {"live-served", D2K_HTTPS_SERVED, 3, 1, 0},
        {"cut-served", D2K_HTTPS_SERVED, 4, 0, 0},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        printf("%s=%s\n", cases[i].name,
               http_search_action(cases[i].state, cases[i].response_code,
                                  cases[i].live_bound_failure, cases[i].probe_pending));
    }
    return 0;
}
