#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int (*next_socket)(int, int, int);
static unsigned attempts;

__attribute__((constructor)) static void resolve_socket(void) {
    next_socket = dlsym(RTLD_NEXT, "socket");
}

int socket(int domain, int type, int protocol) {
    if (domain == AF_NETLINK && protocol == NETLINK_NETFILTER) {
        unsigned attempt = __atomic_add_fetch(&attempts, 1, __ATOMIC_RELAXED);
        const char *trace = getenv("R2O_CT_RETRY_TRACE");
        if (trace) {
            int fd = open(trace, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
            if (fd >= 0) {
                char line[64];
                int length = snprintf(line, sizeof line, "ctnetlink socket attempt %u\n", attempt);
                if (length > 0) (void)write(fd, line, (size_t)length);
                (void)close(fd);
            }
        }
        if (attempt == 2) {
            errno = EAFNOSUPPORT;
            return -1;
        }
    }
    return next_socket(domain, type, protocol);
}
