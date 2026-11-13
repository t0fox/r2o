/* C/Rust differential: say_quiet (core/sched.c:1615-1632). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "sched.c"

static void say_cb(void *ctx, const char *line) {
    (void)ctx;
    printf("%s\n", line);
}

int main(void) {
    static d2k_sched s;
    memset(&s, 0, sizeof s);
    s.say_fn = say_cb;
    s.now_ms = 1000;

    say_quiet(&s, "a", "a1");
    say_quiet(&s, "a", "a-suppressed");
    s.now_ms = 1000 + 599999;
    say_quiet(&s, "a", "a-still-suppressed");
    s.now_ms = 1000 + 600000;
    say_quiet(&s, "a", "a2");
    say_quiet(&s, "b", "b1");

    memset(&s, 0, sizeof s);
    s.say_fn = say_cb;
    s.now_ms = 5000;
    for (unsigned i = 0; i < 64; i++) {
        char key[16], line[32];
        snprintf(key, sizeof key, "k%u", i);
        snprintf(line, sizeof line, "fill%u", i);
        say_quiet(&s, key, "%s", line);
    }
    say_quiet(&s, "k64", "overflow");
    say_quiet(&s, "k0", "k0-again");
    say_quiet(&s, "k1", "k1-suppressed");
    return 0;
}
