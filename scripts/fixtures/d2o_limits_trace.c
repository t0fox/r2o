/* D2O limits/memory budget oracle для TG22. */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "tg_limits.h"
#include "tg_memory_budget.h"

static void max_case(size_t fd, size_t memory, size_t bytes, size_t hedge,
                     size_t configured) {
    printf("max fd=%zu memory=%zu bytes=%zu hedge=%zu configured=%zu => %zu\n",
           fd, memory, bytes, hedge, configured,
           tg_limits_auto_max_connections(fd, memory, bytes, hedge, configured));
}

int main(void) {
    const size_t mib = 1024u * 1024u;
    max_case(128, 16 * mib, 128 * 1024, 0, 512);
    max_case(32, 16 * mib, 128 * 1024, 0, 512);
    max_case(4096, mib, 256 * 1024, 0, 512);
    max_case(SIZE_MAX, SIZE_MAX, 1, 0, 12);
    max_case(SIZE_MAX, SIZE_MAX, 1, 0, 0);
    max_case(48, mib, 128 * 1024, 16, 512);
    max_case(256, mib, 0, 0, 512);
    max_case(256, mib, 128 * 1024, SIZE_MAX, 512);
    max_case(1024, 128 * mib, 282 * 1024, 0, 64);
    max_case(1024, 282 * 1024 * 7, 282 * 1024, 0, 64);

    printf("runtime 512/348 => %zu\n",
           tg_limits_runtime_memory_budget(512 * mib, 348 * mib));
    printf("runtime 64/40 => %zu\n",
           tg_limits_runtime_memory_budget(64 * mib, 40 * mib));
    printf("runtime 2048/1024 => %zu\n",
           tg_limits_runtime_memory_budget(2048 * mib, 1024 * mib));
    printf("runtime 512/0 => %zu\n",
           tg_limits_runtime_memory_budget(512 * mib, 0));

    tg_memory_budget budget = {.limit = 64u * 1024u};
    tg_memory_budget_reserve(&budget, 48u * 1024u);
    printf("budget after48 used=%zu peak=%zu\n", budget.used, budget.peak);
    printf("budget reserve16+1 => %d\n",
           tg_memory_budget_reserve(&budget, 16u * 1024u + 1u));
    printf("budget afterfail used=%zu\n", budget.used);
    printf("budget reserve16 => %d\n",
           tg_memory_budget_reserve(&budget, 16u * 1024u));
    printf("budget full used=%zu peak=%zu\n", budget.used, budget.peak);
    tg_memory_budget_release(&budget, 32u * 1024u);
    printf("budget release32 used=%zu\n", budget.used);
    printf("budget reserve32 => %d\n",
           tg_memory_budget_reserve(&budget, 32u * 1024u));
    printf("budget peak2 used=%zu peak=%zu\n", budget.used, budget.peak);
    tg_memory_budget_release(&budget, budget.limit);
    printf("budget drained used=%zu\n", budget.used);
    return 0;
}
