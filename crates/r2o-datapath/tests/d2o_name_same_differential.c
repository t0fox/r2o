/* C-оракул: name_same (datapath/session.c:369-382).
 *
 * session.c включается целиком: нужна статическая функция. */
#include "session.c"

#include <stdio.h>
#include <string.h>

static void run(const char *name, const uint8_t *a, size_t alen,
                const uint8_t *b, size_t blen) {
    printf("%s result=%d\n", name, name_same(a, alen, b, blen) ? 1 : 0);
}

int main(void) {
    run("equal", (const uint8_t *)"example.com", 11,
        (const uint8_t *)"example.com", 11);
    run("case", (const uint8_t *)"Example.COM", 11,
        (const uint8_t *)"example.com", 11);
    run("short", (const uint8_t *)"example.co", 10,
        (const uint8_t *)"example.com", 11);
    run("trailing-dot", (const uint8_t *)"example.com.", 12,
        (const uint8_t *)"example.com", 11);
    run("digits", (const uint8_t *)"a1-b2.c3", 8,
        (const uint8_t *)"A1-B2.C3", 8);
    run("empty", (const uint8_t *)"", 0, (const uint8_t *)"", 0);
    run("empty-vs-one", (const uint8_t *)"", 0,
        (const uint8_t *)"a", 1);
    {
        static const uint8_t high1[] = {0x80, 'A'};
        static const uint8_t high2[] = {0x80, 'a'};
        static const uint8_t high3[] = {0x81, 'a'};
        run("high-case", high1, 2, high2, 2);
        run("high-diff", high2, 2, high3, 2);
    }
    run("dash-case", (const uint8_t *)"A-B", 3,
        (const uint8_t *)"a-b", 3);
    return 0;
}
