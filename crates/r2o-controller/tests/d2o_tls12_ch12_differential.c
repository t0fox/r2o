/* C-оракул `ch12_build` из core/tls12.c (current main 7a5fab9).
 *
 * tls12.c подключается как единица трансляции: ch12_build статическая, а
 * остальные функции отбрасываются --gc-sections. Сравниваются точные байты
 * ClientHello для разных SNI и want_wire.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "tls12.c"

static void print_case(const char *name, const char *sni, size_t want_wire)
{
    static const uint8_t random[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    uint8_t out[4096];
    size_t n = ch12_build(sni, random, want_wire, out, sizeof out);
    printf("case=%s len=%zu hex=", name, n);
    for (size_t i = 0; i < n; i++) { printf("%02x", out[i]); }
    printf("\n");
}

int main(void)
{
    print_case("none", NULL, 0);
    print_case("empty", "", 0);
    print_case("short", "a", 0);
    print_case("example", "example.test", 0);
    print_case("example-600", "example.test", 600);
    print_case("example-700", "example.test", 700);
    print_case("long-sni", "very-long-name-for-the-tls12-clienthello.example", 1200);
    print_case("max-sni", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0);
    return 0;
}
