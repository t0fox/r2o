/* C-оракул d2k_qbudget_init/d2k_qbudget_grew из d2k_quicprobe.h. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_quicprobe.h"

static void case_growth(const char *name, unsigned budget,
                        const uint64_t *packets, const uint64_t *progress,
                        const int *status, size_t count)
{
    d2k_qbudget b;
    d2k_qbudget_init(&b, budget);
    printf("budget|%s|need=%u\n", name, b.need);
    for (size_t i = 0; i < count; i++) {
        int grew = d2k_qbudget_grew(&b, packets[i], progress[i], status[i]);
        printf("grew|%s|%zu|%d\n", name, i, grew);
    }
}

int main(void)
{
    {
        static const unsigned values[] = {0, 1, 25, 0x7fffffffu, 0x80000000u, 0xffffffffu};
        for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
            d2k_qbudget b;
            d2k_qbudget_init(&b, values[i]);
            printf("need|%u|%u\n", values[i], b.need);
        }
    }
    {
        static const uint64_t packets[] = {1, 2, 2, 2, 2};
        static const uint64_t progress[] = {100, 100, 100, 120, 130};
        static const int status[] = {200, 200, 200, 200, 0};
        case_growth("grow", 1, packets, progress, status, 5);
    }
    {
        static const uint64_t packets[] = {2, 3, 3};
        static const uint64_t progress[] = {100, 100, 101};
        static const int status[] = {200, 0, 200};
        case_growth("status", 1, packets, progress, status, 3);
    }
    {
        static const uint64_t packets[] = {4, 5};
        static const uint64_t progress[] = {50, 60};
        static const int status[] = {200, 200};
        case_growth("double", 2, packets, progress, status, 2);
    }
    return 0;
}
