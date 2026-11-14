/* LD_PRELOAD-логгер SO_MARK: измеряет реальные setsockopt обеих сторон
 * (C d2kc и Rust r2o-controller) в одном стенде. Не меняет поведение:
 * только пишет значение и вызывает настоящий setsockopt. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>

typedef int (*setsockopt_fn)(int, int, int, const void *, socklen_t);

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    static setsockopt_fn real;
    if (!real) real = (setsockopt_fn)dlsym(RTLD_NEXT, "setsockopt");
    if (level == SOL_SOCKET && optname == SO_MARK && optlen >= sizeof(uint32_t) && optval) {
        const char *path = getenv("R2O_MARK_LOG");
        if (path && *path) {
            FILE *f = fopen(path, "a");
            if (f) {
                fprintf(f, "%u\n", *(const uint32_t *)optval);
                fclose(f);
            }
        }
    }
    return real(fd, level, optname, optval, optlen);
}
