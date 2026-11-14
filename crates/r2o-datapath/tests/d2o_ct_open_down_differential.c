/* C-оракул: d2k_ct_open при недоступном NETLINK_NETFILTER. */
#include <stdio.h>
#include <unistd.h>

#include "d2k_ctq.h"

int main(void) {
    int fd = d2k_ct_open();
    printf("open=%d\n", fd >= 0 ? 1 : 0);
    if (fd >= 0) close(fd);
    return 0;
}
