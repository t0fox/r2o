#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "d2k_quicprobe.h"

int main(void) {
    static const uint32_t budgets[] = {
        0, 1, D2K_QUIC_BOX_BUDGET_PKTS, UINT32_MAX / 2,
        UINT32_MAX / 2 + 1, UINT32_MAX,
    };

    for (size_t index = 0; index < sizeof budgets / sizeof budgets[0]; index++) {
        d2k_qbudget budget;
        d2k_qbudget_init(&budget, (unsigned)budgets[index]);
        printf("budget=%" PRIu32 " need=%u\n", budgets[index], budget.need);
    }
    return 0;
}
