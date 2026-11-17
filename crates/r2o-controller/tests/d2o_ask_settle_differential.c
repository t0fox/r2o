/* C-оракул: production `ask_settle` из core/sched.c. */
#include "sched.c"

#include <stdio.h>
#include <string.h>

static void run(const char *label, int ask_base, int ask_probes, int run_probes)
{
    task t;
    memset(&t, 0, sizeof t);
    t.ask_base = ask_base;
    t.ask_probes = ask_probes;
    ask_settle(&t, run_probes);
    printf("%s %d\n", label, t.ask_probes);
}

int main(void)
{
    run("empty", 0, 0, 0);
    run("first_run", 0, 0, 3);
    run("progress_undercount", 0, 1, 3);
    run("carry_base", 5, 5, 3);
    run("already_settled", 5, 8, 3);
    run("run_zero", 5, 9, 0);
    run("negative_run", 7, 7, -3);
    run("negative_undercount", 7, 6, -1);
    run("progress_over_run", 1, 100, 50);
    return 0;
}
