/* LD_PRELOAD-шим send/getsockopt/setsockopt/nanosleep для UDP plan-send.
 *
 * C `d2k_udp_plan_send` и Rust `r2o_udp_plan_send` используют одни и те же
 * libc-вызовы; шим делает сценарии детерминированными и пишет трассу в
 * R2O_UDP_SEND_SHIM_LOG. Реальный connected UDP-сокет всё равно создаётся,
 * поэтому getsockname/getpeername проверяют настоящий family/src/dst/port.
 */
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>

typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef int (*getsockopt_fn)(int, int, int, void *, socklen_t *);
typedef int (*setsockopt_fn)(int, int, int, const void *, socklen_t);
typedef int (*nanosleep_fn)(const struct timespec *, struct timespec *);

static send_fn real_send;
static getsockopt_fn real_getsockopt;
static setsockopt_fn real_setsockopt;
static nanosleep_fn real_nanosleep;
static int sleep_interrupted;

static const char *scenario(void) {
    const char *value = getenv("R2O_UDP_SEND_SCENARIO");
    return value ? value : "pass4";
}

static void log_line(const char *format, ...) {
    const char *path = getenv("R2O_UDP_SEND_SHIM_LOG");
    if (!path || !*path) {
        return;
    }
    FILE *file = fopen(path, "a");
    if (!file) {
        return;
    }
    va_list arguments;
    va_start(arguments, format);
    vfprintf(file, format, arguments);
    va_end(arguments);
    fputc('\n', file);
    fclose(file);
}

static void log_hex(const char *prefix, const void *data, size_t length) {
    const uint8_t *bytes = data;
    char buffer[131072];
    size_t at = 0;
    at += (size_t)snprintf(buffer + at, sizeof buffer - at, "%s len=%zu hex=",
                           prefix, length);
    for (size_t i = 0; i < length && at + 2 < sizeof buffer; i++) {
        at += (size_t)snprintf(buffer + at, sizeof buffer - at, "%02x", bytes[i]);
    }
    log_line("%s", buffer);
}

static int is_ttl_option(int level, int option) {
    return (level == IPPROTO_IP && option == IP_TTL) ||
           (level == IPPROTO_IPV6 && option == IPV6_UNICAST_HOPS);
}

ssize_t send(int fd, const void *buffer, size_t length, int flags) {
    if (!real_send) {
        real_send = (send_fn)dlsym(RTLD_NEXT, "send");
    }
    log_hex("send", buffer, length);
    if (strcmp(scenario(), "send_refused") == 0) {
        errno = ECONNREFUSED;
        return -1;
    }
    if (strcmp(scenario(), "send_error") == 0) {
        errno = EIO;
        return -1;
    }
    return real_send(fd, buffer, length, flags);
}

int getsockopt(int fd, int level, int option, void *value, socklen_t *length) {
    if (!real_getsockopt) {
        real_getsockopt = (getsockopt_fn)dlsym(RTLD_NEXT, "getsockopt");
    }
    if (is_ttl_option(level, option)) {
        const char *text = getenv("R2O_UDP_SHIM_TTL");
        int ttl = text ? atoi(text) : 47;
        if (value && length && *length >= sizeof ttl) {
            memcpy(value, &ttl, sizeof ttl);
            *length = sizeof ttl;
            log_line("get_ttl=%d", ttl);
        }
        return 0;
    }
    return real_getsockopt(fd, level, option, value, length);
}

int setsockopt(int fd, int level, int option, const void *value, socklen_t length) {
    if (!real_setsockopt) {
        real_setsockopt = (setsockopt_fn)dlsym(RTLD_NEXT, "setsockopt");
    }
    if (is_ttl_option(level, option) && value && length >= sizeof(int)) {
        int ttl = 0;
        memcpy(&ttl, value, sizeof ttl);
        log_line("set_ttl=%d", ttl);
        return 0;
    }
    return real_setsockopt(fd, level, option, value, length);
}

int nanosleep(const struct timespec *request, struct timespec *remaining) {
    if (!real_nanosleep) {
        real_nanosleep = (nanosleep_fn)dlsym(RTLD_NEXT, "nanosleep");
    }
    long microseconds = request
        ? request->tv_sec * 1000000L + request->tv_nsec / 1000L
        : 0;
    log_line("nanosleep=%ld", microseconds);
    if (!sleep_interrupted && strcmp(scenario(), "delay_eintr") == 0) {
        sleep_interrupted = 1;
        errno = EINTR;
        return -1;
    }
    const struct timespec zero = {0, 0};
    if (remaining) {
        *remaining = zero;
    }
    return 0;
}
