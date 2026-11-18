#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "sched.c"

static void run(const char *label, int lead_a, int tier_a, int successes_a,
                int64_t fresh_a, int lead_b, int tier_b, int successes_b,
                int64_t fresh_b)
{
    d2k_cat_plan a;
    d2k_cat_plan b;
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    a.successes = successes_a;
    b.successes = successes_b;
    printf("%s=%d\n", label,
           own_rank_before(lead_a, tier_a, &a, fresh_a,
                           lead_b, tier_b, &b, fresh_b));
}

int main(void)
{
    run("lead", 1, 5, 0, 0, 0, 5, 0, 0);
    run("tier", 0, 1, 0, 0, 0, 2, 0, 0);
    run("tier_reverse", 0, 2, 0, 0, 0, 1, 0, 0);
    run("successes", 0, 1, 5, 0, 0, 1, 3, 0);
    run("successes_reverse", 0, 1, 3, 0, 0, 1, 5, 0);
    run("fresh", 0, 1, 5, 10, 0, 1, 5, 5);
    run("fresh_reverse", 0, 1, 5, 5, 0, 1, 5, 10);
    run("equal", 0, 1, 5, 5, 0, 1, 5, 5);
    return 0;
}
