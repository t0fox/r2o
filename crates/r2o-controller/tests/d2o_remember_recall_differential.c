/* C/Rust differential: remember/recall (core/sched.c:1841-1869). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "sched.c"

static d2k_sched s;

static d2k_ev make_ev(uint16_t sport, const char *name) {
    d2k_ev e;
    memset(&e, 0, sizeof e);
    e.family = 4;
    e.low_ip[0] = 192; e.low_ip[1] = 0; e.low_ip[2] = 2; e.low_ip[3] = 10;
    e.high_ip[0] = 198; e.high_ip[1] = 51; e.high_ip[2] = 100; e.high_ip[3] = 20;
    e.low_port = sport;
    e.high_port = 443;
    e.transport = 6;
    snprintf(e.name, sizeof e.name, "%s", name);
    return e;
}

static void show(const char *tag, uint16_t sport) {
    d2k_ev e = make_ev(sport, "probe");
    const char *name = recall(&s, &e);
    printf("%s=%s\n", tag, name ? name : "-");
}

int main(void) {
    memset(&s, 0, sizeof s);
    s.now_ms = 1000;

    d2k_ev one = make_ev(40000, "one.example");
    remember(&s, &one);
    show("first", 40000);

    d2k_ev updated = make_ev(40000, "two.example");
    remember(&s, &updated);
    show("updated", 40000);

    d2k_ev second = make_ev(40001, "second.example");
    remember(&s, &second);
    show("second", 40001);
    show("absent", 40002);

    memset(&s, 0, sizeof s);
    s.now_ms = 1000;
    d2k_ev first_fill = make_ev(30000, "fill.example");
    for (uint16_t index = 0; index < 512; index++) {
        d2k_ev e = make_ev((uint16_t)(30000 + index), "fill.example");
        remember(&s, &e);
    }
    show("ring_first", 30000);
    d2k_ev overflow = make_ev(31000, "overflow.example");
    remember(&s, &overflow);
    show("ring_after_overflow", 30000);
    show("ring_overflow", 31000);

    (void)first_fill;
    return 0;
}
