#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include "httpsearch.c"

static char outcome[32], reason[64];
static void record_event(void *context, const d2k_diag_event *event) {
    (void)context;
    snprintf(outcome, sizeof outcome, "%s", event->outcome);
    snprintf(reason, sizeof reason, "%s", event->reason);
}

int main(void) {
    d2k_httpsearch *search = d2k_httpsearch_new(NULL);
    if (!search) return 1;
    d2k_httpsearch_diagnostics(search, record_event, NULL);
    search->cur.phase = PH_RUN;
    search->cur.fd = -1;
    search->cur.family = 4;
    search->cur.diagnostic_id = 1;
    search->cur.diagnostic_start = 1000;
    snprintf(search->cur.host, sizeof search->cur.host, "example.com");
    all_failed(search, 1000);
    const rec *record = rec_find(search, "example.com", 4);
    if (!record) return 1;
    printf("cooldown_ms=%lld\n", (long long)(record->no_before_ms - 1000));
    printf("outcome=%s\nreason=%s\n", outcome, reason);
    d2k_httpsearch_free(search);
    return 0;
}
