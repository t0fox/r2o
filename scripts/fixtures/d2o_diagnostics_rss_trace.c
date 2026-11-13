/* d2o_diagnostics_rss_trace — периодический RSS-сэмпл production diagnostics.c.
 *
 * Включает diagnostics.c напрямую, чтобы прочитать внутренний sample без
 * парсинга JSON: сравниваются те же поля, которые C пишет в отчёт.
 */
#define _POSIX_C_SOURCE 200809L
#include "diagnostics.c"
#include <stdio.h>

static void print_proc(const proc_mem *p) {
    printf("rss=%lld hwm=%lld anon=%lld threads=%lld vm_data=%lld vm_swap=%lld\n",
           (long long)p->rss, (long long)p->hwm, (long long)p->anon,
           (long long)p->threads, (long long)p->vm_data, (long long)p->vm_swap);
}

static void print_detail(const memory_detail *m) {
    printf("detail pid=%ld rss=%lld start=%lld vm=%lld,%lld,%lld,%lld fds=%lld "
           "status=%s source=%s errno=%d rollup=%lld,%lld,%lld,%lld,%lld\n",
           m->pid, (long long)m->rss, (long long)m->start_ticks,
           (long long)m->vm[0], (long long)m->vm[1], (long long)m->vm[2],
           (long long)m->vm[3], (long long)m->fds,
           read_status(m->rollup_status),
           m->rollup_source == 1 ? "smaps_rollup"
                                 : m->rollup_source == 2 ? "smaps-fallback"
                                                         : "unavailable",
           m->rollup_errno,
           (long long)m->rollup[0], (long long)m->rollup[1],
           (long long)m->rollup[2], (long long)m->rollup[3],
           (long long)m->rollup[4]);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    d2k_diag *diag = d2k_diag_new();
    if (!diag) return 2;
    d2k_diag_counts counts;
    memset(&counts, 0, sizeof counts);
    counts.boxes = 2;
    counts.bindings = 3;
    counts.plans = 4;
    d2k_diag_sample(diag, 1000, &counts, argv[1], argv[2]);
    d2k_diag_sample(diag, 61000, &counts, argv[1], argv[2]);
    d2k_diag_sample(diag, 62000, &counts, argv[1], argv[2]);
    printf("samples=%zu\n", diag->ns);
    print_proc(&diag->samples[0].procs[0]);
    print_proc(&diag->samples[1].procs[0]);
    print_detail(&diag->latest[0]);
    d2k_diag_free(diag);
    return 0;
}
