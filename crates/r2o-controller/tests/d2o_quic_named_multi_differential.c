/* C/Rust differential: on_shape QUIC state — quic_named reuse 10 мин,
 * quic_multi (обрывок Initial) и quic_split_unfit. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

int main(void)
{
    d2k_sched *s = calloc(1, sizeof *s);
    if (!s) return 1;
    snprintf(s->quic_named[0].name, sizeof s->quic_named[0].name, "%s", "named.example");
    s->quic_named[0].family = 4;
    s->quic_named[0].len = 4;
    memcpy(s->quic_named[0].bytes, "init", 4);
    s->quic_named[0].observed_ms = 1000;
    s->now_ms = 1000;
    printf("named_found=%d\n", quic_named_find(s, "named.example", 4) >= 0);
    s->now_ms = 1000 + 600000;
    printf("named_at_ttl=%d\n", quic_named_find(s, "named.example", 4) >= 0);
    s->now_ms = 1000 + 600001;
    printf("named_expired=%d\n", quic_named_find(s, "named.example", 4) >= 0);
    printf("named_family=%d\n", quic_named_find(s, "named.example", 6) >= 0);

    snprintf(s->quic_multi[0].name, sizeof s->quic_multi[0].name, "%s", "multi.example");
    s->quic_multi[0].family = 4;
    printf("multi_found=%d\n", quic_client_multi(s, "multi.example", 4));
    printf("multi_family=%d\n", quic_client_multi(s, "multi.example", 6));

    task t;
    memset(&t, 0, sizeof t);
    t.transport = 17;
    t.family = 4;
    snprintf(t.name, sizeof t.name, "%s", "multi.example");
    t.by_addr = 0;
    t.trig_snapped = 1;
    t.trig_len = 100;
    printf("split_multi=%d\n", quic_split_unfit(s, &t));
    snprintf(t.name, sizeof t.name, "%s", "clean.example");
    printf("split_snapped=%d\n", quic_split_unfit(s, &t));
    t.trig_snapped = 0;
    t.trig_len = 0;
    printf("split_no_snapshot=%d\n", quic_split_unfit(s, &t));
    t.by_addr = 1;
    t.trig_len = 100;
    t.trig_snapped = 1;
    printf("split_by_addr=%d\n", quic_split_unfit(s, &t));
    free(s);
    return 0;
}
