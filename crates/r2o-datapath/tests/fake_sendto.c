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
