/* C-оракул: production `worker_type` из core/sched.c (static — включаем TU). */
#include "sched.c"

#include <stdio.h>
#include <string.h>

int main(void)
{
    static const int jobs[] = {0, 1, 2, 3, 4, 5, 6, 255};
    static const unsigned transports[] = {6, 17};
    for (size_t ji = 0; ji < sizeof jobs / sizeof jobs[0]; ji++) {
        for (size_t ti = 0; ti < sizeof transports / sizeof transports[0]; ti++) {
            task t;
            memset(&t, 0, sizeof t);
            t.job = (task_job)jobs[ji];
            t.transport = (uint8_t)transports[ti];
            printf("%d,%u,%s\n", jobs[ji], transports[ti], worker_type(&t));
        }
    }
    return 0;
}
