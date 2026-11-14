/* C-оракул: describe_oifs (datapath/d2kd.c:282-294), точный формат/cap. */
#define main d2kd_main
#include "d2kd.c"
#undef main

#include <net/if.h>
#include <stdio.h>

int main(void) {
    char buf[256];
    uint32_t oifs[2] = {if_nametoindex("lo"), 0x7ffffff0u};
    describe_oifs(buf, sizeof buf, oifs, 2, 1);
    printf("lo_unknown <%s>\n", buf);
    describe_oifs(buf, sizeof buf, oifs, 0, 1);
    printf("none <%s>\n", buf);
    describe_oifs(buf, sizeof buf, oifs, 2, 0);
    printf("unknown <%s>\n", buf);
    describe_oifs(buf, 8, oifs, 2, 1);
    printf("cap8 <%s>\n", buf);
    describe_oifs(buf, 1, oifs, 1, 1);
    printf("cap1 <%s>\n", buf);
    return 0;
}
