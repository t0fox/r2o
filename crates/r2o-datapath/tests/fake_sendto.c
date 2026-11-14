/* LD_PRELOAD fake sendto: сценарии для C/Rust raw-send differential. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int (*real_socket_fn)(int, int, int);
static int (*real_setsockopt_fn)(int, int, int, const void *, socklen_t);
static int (*real_close_fn)(int);

static const char *open_plan(void) {
    return getenv("FAKE_OPEN_PLAN");
}

int socket(int domain, int type, int protocol) {
    if (!open_plan()) {
        if (!real_socket_fn) real_socket_fn = dlsym(RTLD_NEXT, "socket");
        return real_socket_fn(domain, type, protocol);
    }
    if (!real_socket_fn) real_socket_fn = dlsym(RTLD_NEXT, "socket");
    if (!strcmp(open_plan(), "socket_fail")) {
        errno = EPERM;
        return -1;
    }
    /* Тестовый fd: важно лишь, что он валиден и закрывается. */
    return real_socket_fn(domain, SOCK_DGRAM, 0);
}

int setsockopt(int fd, int level, int option, const void *value, socklen_t length) {
    if (!open_plan()) {
        if (!real_setsockopt_fn) real_setsockopt_fn = dlsym(RTLD_NEXT, "setsockopt");
        return real_setsockopt_fn(fd, level, option, value, length);
    }
    if (!strcmp(open_plan(), "hdrincl_fail")) {
        errno = EPERM;
        return -1;
    }
    if (!strcmp(open_plan(), "mark_fail") && level == SOL_SOCKET && option == SO_MARK) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

int close(int fd) {
    if (!real_close_fn) real_close_fn = dlsym(RTLD_NEXT, "close");
    return real_close_fn(fd);
}

static ssize_t (*real_sendto)(int, const void *, size_t, int,
                              const struct sockaddr *, socklen_t);
static int calls;

static const char *next_action(void) {
    static char plan[256];
    static int loaded;
    if (!loaded) {
        const char *value = getenv("FAKE_SENDTO_PLAN");
        snprintf(plan, sizeof plan, "%s", value ? value : "OK");
        loaded = 1;
    }
    char *save = NULL;
    char *token = strtok_r(plan, ",", &save);
    int target = calls++;
    for (int index = 0; token && index < target; index++) {
        token = strtok_r(NULL, ",", &save);
    }
    return token ? token : "OK";
}

ssize_t sendto(int fd, const void *buffer, size_t length, int flags,
               const struct sockaddr *address, socklen_t address_len) {
    if (!getenv("FAKE_SENDTO_PLAN")) {
        if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");
        return real_sendto(fd, buffer, length, flags, address, address_len);
    }
    const char *action = next_action();
    if (!strcmp(action, "EINTR")) { errno = EINTR; return -1; }
    if (!strcmp(action, "ENOBUFS")) { errno = ENOBUFS; return -1; }
    if (!strcmp(action, "EAGAIN")) { errno = EAGAIN; return -1; }
    if (!strcmp(action, "EMSGSIZE")) { errno = EMSGSIZE; return -1; }
    if (!strcmp(action, "EIO")) { errno = EIO; return -1; }
    if (!strcmp(action, "SHORT")) {
        return length > 0 ? (ssize_t)(length - 1) : 0;
    }
    return (ssize_t)length;
}
