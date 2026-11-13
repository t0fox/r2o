/* C/Rust differential: pause_note (core/verdict.c:74-80). */
#include <stdio.h>

#include "verdict.c"

int main(void) {
    const unsigned gaps[] = {0, 1, 60000, 4294967295u};
    for (unsigned i = 0; i < sizeof gaps / sizeof gaps[0]; i++) {
        char out[96];
        pause_note(out, sizeof out, gaps[i]);
        printf("gap %u %s\n", gaps[i], out);
    }
    return 0;
}
