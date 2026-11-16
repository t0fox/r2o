/* C/Rust differential остановки службы: d2k_detect_stop_all + stop_asked.
 *
 * Включает production `detect/bridge.c`. Порядок кейсов важен: флаг
 * `g_stop_all` липкий и снимается только смертью процесса. */
#include "d2k_detect.h"

#include <signal.h>
#include <stdio.h>

#ifndef R2O_BRIDGE_C
#error "R2O_BRIDGE_C must point to production detect/bridge.c"
#endif
#include R2O_BRIDGE_C

static void print_case(const char *name, const volatile sig_atomic_t *task)
{
    printf("case=%s global=%d task=%d stop=%d\n", name,
           (int)g_stop_all, task ? (int)*task : -1, stop_asked((void *)task));
}

int main(void)
{
    volatile sig_atomic_t task_idle = 0;
    volatile sig_atomic_t task_stopped = 1;

    print_case("no_flags", &task_idle);
    print_case("task_flag", &task_stopped);
    print_case("null_task", NULL);

    d2k_detect_stop_all();
    print_case("global_only", &task_idle);
    print_case("both_flags", &task_stopped);
    print_case("new_probe_after_global", NULL);
    return 0;
}
