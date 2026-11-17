/* C-оракул: production `quic_text_is_split` из core/sched.c. */
#include "sched.c"

#include <stdio.h>

static void check(const char *label, const char *text)
{
    printf("%s %d\n", label, quic_text_is_split(text));
}

int main(void)
{
    check("split", "r2o-plan 1 10\nid 0\nproto udp quic\nquicsplit 1\n");
    check("no_newline", "quicsplit 1\n");
    check("leading_newline_only", "\nquicsplit");
    check("no_space", "\nquicsplit1\n");
    check("upper", "\nQUICSPLIT 1\n");
    check("two_spaces", "\nquicsplit  1\n");
    check("tab", "\nquicsplit\t1\n");
    check("empty", "");
    check("plain", "r2o-plan 1 10\nproto udp quic\n");
    check("middle", "a\nquicsplit b\nquicdeny\n");
    check("crlf", "\r\nquicsplit 1\r\n");
    return 0;
}
