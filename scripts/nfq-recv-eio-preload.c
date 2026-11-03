#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NFQUEUE_CONFIG_TYPE ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG)

static _Atomic int nfqueue_fd = -1;
static _Atomic unsigned nfqueue_receives = 0;
static _Atomic int nfqueue_eio_injected = 0;

ssize_t sendto(int fd, const void *buffer, size_t length, int flags,
               const struct sockaddr *address, socklen_t address_length) {
    static ssize_t (*next_sendto)(int, const void *, size_t, int,
                                  const struct sockaddr *, socklen_t);
    if (!next_sendto) {
        next_sendto = (ssize_t (*)(int, const void *, size_t, int,
                                   const struct sockaddr *, socklen_t))
            dlsym(RTLD_NEXT, "sendto");
    }
    if (!next_sendto) {
        errno = ENOSYS;
        return -1;
    }

    if (address && address->sa_family == AF_NETLINK &&
        address_length >= sizeof(struct sockaddr_nl) &&
        length >= sizeof(struct nlmsghdr)) {
        int protocol = 0;
        socklen_t protocol_length = sizeof(protocol);
        struct nlmsghdr header;
        memcpy(&header, buffer, sizeof(header));
        if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &protocol_length) == 0 &&
            protocol == NETLINK_NETFILTER && header.nlmsg_type == NFQUEUE_CONFIG_TYPE) {
            atomic_store_explicit(&nfqueue_fd, fd, memory_order_release);
        }
    }
    return next_sendto(fd, buffer, length, flags, address, address_length);
}

ssize_t recv(int fd, void *buffer, size_t length, int flags) {
    static ssize_t (*next_recv)(int, void *, size_t, int);
    if (!next_recv) {
        next_recv = (ssize_t (*)(int, void *, size_t, int))dlsym(RTLD_NEXT, "recv");
    }
    if (!next_recv) {
        errno = ENOSYS;
        return -1;
    }

    int inject_eio = 0;
    if (fd == atomic_load_explicit(&nfqueue_fd, memory_order_acquire)) {
        const char *trigger_file = getenv("R2O_NFQ_RECV_EIO_TRIGGER_FILE");
        if (trigger_file && trigger_file[0]) {
            inject_eio = access(trigger_file, F_OK) == 0;
        } else {
            inject_eio = atomic_fetch_add_explicit(&nfqueue_receives, 1,
                                                   memory_order_relaxed) == 2;
        }
    }
    if (inject_eio &&
        !atomic_exchange_explicit(&nfqueue_eio_injected, 1, memory_order_relaxed)) {
        static const char message[] = "FAULT-INJECTED recv(EIO) on NFQUEUE socket\n";
        const ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1);
        (void)written;
        errno = EIO;
        return -1;
    }
    return next_recv(fd, buffer, length, flags);
}