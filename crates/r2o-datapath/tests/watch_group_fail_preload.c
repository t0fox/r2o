/* LD_PRELOAD: отказ NETLINK_ADD_MEMBERSHIP для выбранной группы rtnetlink. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <sys/socket.h>

int setsockopt(int fd, int level, int option, const void *value,
               socklen_t length) {
    static int (*real_setsockopt)(int, int, int, const void *, socklen_t);
    if (!real_setsockopt) {
        real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    }
    if (level == SOL_NETLINK && option == NETLINK_ADD_MEMBERSHIP &&
        value != NULL && length == sizeof(int)) {
        const char *fail = getenv("FAKE_WATCH_FAIL_GROUP");
        if (fail && fail[0] && *(const int *)value == atoi(fail)) {
            errno = EPERM;
            return -1;
        }
    }
    return real_setsockopt(fd, level, option, value, length);
}
