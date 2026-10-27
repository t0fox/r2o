#include "d2k_diagnostics.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--process-exit")) {
        char proc[512], run[512], pidfile[512];
        if (snprintf(proc, sizeof proc, "%s/proc", argv[2]) >= (int)sizeof proc ||
            snprintf(run, sizeof run, "%s/run", argv[2]) >= (int)sizeof run ||
            snprintf(pidfile, sizeof pidfile, "%s/d2k.pid", run) >= (int)sizeof pidfile) return 1;
        d2k_diag *d = d2k_diag_new();
        if (!d) return 1;
        d2k_diag_counts counts = {0};
        d2k_diag_sample(d, 0, &counts, proc, run);
        if (remove(pidfile)) return 1;
        d2k_diag_sample(d, 60000, &counts, proc, run);
        int result = d2k_diag_write(d, stdout);
        d2k_diag_free(d);
        return result != 0;
    }
    d2k_diag *diagnostics = d2k_diag_new();
    if (!diagnostics) return 1;
    static const char reason[] = "bad\t\001line\n\0ignored";
    const d2k_diag_event event = {
        .id = 77,
        .elapsed_ms = -1,
        .queue_ms = -1,
        .probe_units = -1,
        .family = 4,
        .trigger = 3,
        .shape = 1,
        .target = "example.com",
        .protocol = "http",
        .outcome = "inconclusive",
        .reason = reason,
        .path = "httpsearch",
        .kind = "name",
    };
    const d2k_diag_counts counts = {
        .snapshots = 4,
        .http_records = 5,
        .http_queued = 6,
    };
    d2k_diag_record(diagnostics, &event);
    d2k_diag_sample(diagnostics, 0, &counts, "/nonexistent", "/nonexistent");
    const int result = d2k_diag_write(diagnostics, stdout);
    d2k_diag_free(diagnostics);
    return result != 0;
}
