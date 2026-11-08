/* Q8: C-оракул backoff-лестницы и active-флага quicdeny из sched.c. */
#include "sched.c"

#include <stdio.h>
#include <string.h>

int main(void) {
    for (unsigned streak = 1; streak <= 5; streak++) {
        printf("case streak-%u\nms=%lld\n", streak,
               (long long)clear_backoff_ms(streak));
    }

    static d2k_sched scheduler;
    memset(&scheduler, 0, sizeof scheduler);
    snprintf(scheduler.quic_deny[0].name,
             sizeof scheduler.quic_deny[0].name, "%s", "media.example");
    scheduler.quic_deny[0].family = 4;
    scheduler.quic_deny[0].used = 1;
    scheduler.quic_deny[0].active = 1;
    printf("case active-yes\nvalue=%d\n",
           quic_deny_active(&scheduler, "media.example", 4));
    scheduler.quic_deny[0].active = 0;
    printf("case active-no\nvalue=%d\n",
           quic_deny_active(&scheduler, "media.example", 4));
    return 0;
}
