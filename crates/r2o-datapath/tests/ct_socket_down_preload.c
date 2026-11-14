/* LD_PRELOAD: NETLINK_NETFILTER недоступен (ctnetlink down). */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <linux/netlink.h>
#include <sys/socket.h>

int socket(int domain, int type, int protocol) {
    static int (*real_socket)(int, int, int);
    if (!real_socket) {
        real_socket = dlsym(RTLD_NEXT, "socket");
    }
    if (domain == AF_NETLINK && protocol == NETLINK_NETFILTER) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    return real_socket(domain, type, protocol);
}
