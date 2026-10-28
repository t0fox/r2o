#define main d2kc_unused_main
#include "d2kc.c"
#undef main

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void d2k_sched_diagnostics(d2k_sched *sched, d2k_diag_observer observer, void *ctx) {
    (void)sched;
    (void)observer;
    (void)ctx;
}

void d2k_httpsearch_diagnostics(d2k_httpsearch *search, d2k_diag_observer observer, void *ctx) {
    (void)search;
    (void)observer;
    (void)ctx;
}

void d2k_sched_diagnostic_counts(d2k_sched *sched, d2k_diag_counts *counts) {
    (void)sched;
    memset(counts, 0, sizeof(*counts));
}

void d2k_httpsearch_diagnostic_counts(d2k_httpsearch *search, d2k_diag_counts *counts) {
    (void)search;
    memset(counts, 0, sizeof(*counts));
}

static int exists(const char *name) {
    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s", D2K_DIAG_DIR, name) >= (int)sizeof(path))
        return 0;
    return access(path, F_OK) == 0;
}

int main(void) {
    diagnostic_tick(NULL, 0);
    printf("disabled_start_dir=%d\n", access(D2K_DIAG_DIR, F_OK) == 0);
    if (d2k_diag_toggle(D2K_DIAG_DIR, 1) != 0)
        return 2;

    diagnostic_tick(NULL, 1000);
    printf("first=%zu report=%d\n", d2k_diag_sample_count(diagnostics), exists("report.json"));
    diagnostic_tick(NULL, 1500);
    printf("subsecond=%zu\n", d2k_diag_sample_count(diagnostics));
    diagnostic_tick(NULL, 61000);
    printf("minute=%zu\n", d2k_diag_sample_count(diagnostics));

    char pending[512];
    if (snprintf(pending, sizeof(pending), "%s/report.new", D2K_DIAG_DIR) >= (int)sizeof(pending))
        return 3;
    int fd = open(pending, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return 4;
    close(fd);
    char enabled[512];
    if (snprintf(enabled, sizeof(enabled), "%s/enabled", D2K_DIAG_DIR) >= (int)sizeof(enabled))
        return 5;
    if (unlink(enabled) != 0)
        return 6;
    diagnostic_tick(NULL, 62000);
    printf("disabled=%d report=%d pending=%d\n", diagnostics == NULL,
           exists("report.json"), exists("report.new"));
    return diagnostics == NULL && !exists("report.json") && !exists("report.new") ? 0 : 7;
}
