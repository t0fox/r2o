/* C-оракул — production `sched_say` из d2kc.c. Печатает строку журнала и
 * окно `time(NULL)` до/после, чтобы дифференциал выбрал секунду без
 * пересечения границы. */
#define main d2kc_unused_main
#include "d2kc.c"
#undef main

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void)
{
    setenv("TZ", "UTC0", 1);
    tzset();
    time_t before = time(NULL);
    sched_say(NULL, "планировщик: строка журнала");
    time_t after = time(NULL);
    printf("window %lld %lld\n", (long long)before, (long long)after);
    return 0;
}
