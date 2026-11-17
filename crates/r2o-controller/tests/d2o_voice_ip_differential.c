/* C-оракул: production `voice_ip_fmt`/`voice_ip_text`/`voice_ip_text2`
 * из core/sched.c. */
#include "sched.c"

#include <stdio.h>
#include <string.h>

static void case_ip(const char *label, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint32_t ip = 0;
    uint8_t bytes[4] = {a, b, c, d};
    memcpy(&ip, bytes, sizeof ip);
    char buf[INET_ADDRSTRLEN];
    printf("%s fmt=%s text=%s text2=%s\n", label,
           voice_ip_fmt(&ip, buf), voice_ip_text(&ip), voice_ip_text2(&ip));
}

int main(void)
{
    case_ip("any", 0, 0, 0, 0);
    case_ip("loopback", 127, 0, 0, 1);
    case_ip("broadcast", 255, 255, 255, 255);
    case_ip("docnet", 192, 0, 2, 1);
    case_ip("private", 10, 1, 2, 3);
    case_ip("docnet2", 203, 0, 113, 9);
    case_ip("mixed", 1, 2, 3, 4);
    case_ip("high", 200, 100, 50, 25);
    case_ip("utf8ish", 208, 159, 208, 191);
    return 0;
}
