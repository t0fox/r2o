#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_diagnostics.h"

/* Серия снимков ресурсов: те же поля, что Rust Counts в
 * `limit_event_json`. Wall-clock `at` в отчёте не сравнивается — только
 * mono_ms и остальные поля перехода лимита. */
static void record(d2k_diag *d, int64_t mono_ms, const d2k_diag_counts *c)
{
    d2k_diag_record_limit(d, mono_ms, c);
}

int main(void)
{
    d2k_diag *diag = d2k_diag_new();
    if (!diag) {
        perror("d2k_diag_new");
        return 1;
    }
    d2k_diag_counts c;

    /* 1. Ресурсы не измерены: resources_valid=0. */
    memset(&c, 0, sizeof c);
    c.cpu_free_pct = -1;
    record(diag, 1000, &c);

    /* 2. Валидные ресурсы без активного лимита. */
    memset(&c, 0, sizeof c);
    c.resources_valid = 1;
    c.cpu_valid = 1;
    c.mem_valid = 1;
    c.conntrack_valid = 1;
    c.cpu_free_pct = 77;
    c.mem_avail_kb = 120000;
    c.mem_total_kb = 131072;
    c.mem_reserve_kb = 8192;
    c.conntrack_count = 321;
    c.conntrack_max = 65536;
    record(diag, 1250, &c);

    /* 3. CPU. */
    memset(&c, 0, sizeof c);
    c.resources_valid = 1;
    c.cpu_valid = 1;
    c.limiter_mask = D2K_DIAG_LIMIT_CPU;
    c.cpu_free_pct = 12;
    record(diag, 1500, &c);

    /* 4. Память. */
    memset(&c, 0, sizeof c);
    c.resources_valid = 1;
    c.cpu_free_pct = -1;
    c.mem_valid = 1;
    c.limiter_mask = D2K_DIAG_LIMIT_MEMORY;
    c.mem_avail_kb = 90000;
    c.mem_total_kb = 131072;
    c.mem_reserve_kb = 4096;
    record(diag, 1750, &c);

    /* 5. Conntrack. */
    memset(&c, 0, sizeof c);
    c.resources_valid = 1;
    c.cpu_free_pct = -1;
    c.conntrack_valid = 1;
    c.limiter_mask = D2K_DIAG_LIMIT_CONNTRACK;
    c.conntrack_count = 65000;
    c.conntrack_max = 65536;
    record(diag, 2000, &c);

    /* 6. Слоты. */
    memset(&c, 0, sizeof c);
    c.resources_valid = 1;
    c.cpu_free_pct = -1;
    c.limiter_mask = D2K_DIAG_LIMIT_SLOTS;
    record(diag, 2250, &c);

    /* 7. Все лимиты, grow_pending и последовательности. */
    memset(&c, 0, sizeof c);
    c.resources_valid = 1;
    c.cpu_valid = 1;
    c.mem_valid = 1;
    c.conntrack_valid = 1;
    c.grow_pending = 1;
    c.limiter_mask = D2K_DIAG_LIMIT_CPU | D2K_DIAG_LIMIT_MEMORY |
                     D2K_DIAG_LIMIT_CONNTRACK | D2K_DIAG_LIMIT_SLOTS;
    c.cpu_free_pct = 33;
    c.mem_avail_kb = 50000;
    c.mem_total_kb = 131072;
    c.mem_reserve_kb = 2048;
    c.conntrack_count = 40000;
    c.conntrack_max = 65536;
    c.resource_sequence = 14;
    c.limit_sequence = 12;
    c.measurement_limit = 7;
    c.measurement_slots = 12;
    record(diag, 2500, &c);

    /* 8. Маска есть, но память/conntrack не измерены: соответствующие
       поля null, limit_reason по-прежнему перечисляет маску. */
    memset(&c, 0, sizeof c);
    c.resources_valid = 1;
    c.limiter_mask = D2K_DIAG_LIMIT_CPU | D2K_DIAG_LIMIT_MEMORY |
                     D2K_DIAG_LIMIT_CONNTRACK | D2K_DIAG_LIMIT_SLOTS;
    c.cpu_free_pct = -1;
    record(diag, 2750, &c);

    int rc = d2k_diag_write(diag, stdout);
    d2k_diag_free(diag);
    if (rc != 0) {
        fprintf(stderr, "d2k_diag_write failed: %d\n", rc);
        return 1;
    }
    return 0;
}
