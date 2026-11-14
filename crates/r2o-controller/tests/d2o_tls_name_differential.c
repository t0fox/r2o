/* C-оракул `name_matches` из core/tls13core.c (current main 7a5fab9).
 *
 * FQDN с завершающими точками нормализуется до сравнения; проверяются
 * wildcard, пустые и короткие имена. tls13core.c включается как TU, чтобы
 * вызвать статическую функцию; остальные функции отбрасываются --gc-sections.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

#include "tls13core.c"

static void print_case(const char *name, const char *pattern, const char *host)
{
    printf("case=%s match=%d\n", name,
           name_matches(pattern, strlen(pattern), host));
}

int main(void)
{
    print_case("exact", "example.test", "example.test");
    print_case("host-dot", "example.test", "example.test.");
    print_case("pattern-dot", "example.test.", "example.test");
    print_case("both-dot", "example.test.", "example.test.");
    print_case("many-dots", "example.test..", "example.test...");
    print_case("wildcard", "*.example.test", "a.example.test");
    print_case("wildcard-host-dot", "*.example.test", "a.example.test.");
    print_case("wildcard-pattern-dot", "*.example.test.", "a.example.test.");
    print_case("wildcard-both-dot", "*.example.test..", "a.example.test...");
    print_case("wildcard-no-label", "*.example.test.", "example.test.");
    print_case("wildcard-two-labels", "*.example.test", "a.b.example.test");
    print_case("empty-pattern", "", "example.test");
    print_case("empty-host", "example.test", "");
    print_case("only-dots", ".", ".");
    print_case("short-wildcard", "*.", "a.");
    print_case("case-insensitive", "EXAMPLE.TEST.", "example.TEST.");
    return 0;
}
