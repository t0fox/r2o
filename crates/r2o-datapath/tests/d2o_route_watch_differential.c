/* C-оракул: d2k_routemark_watch_open (routemark_nl.c:179-211). */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "d2k_routemark.h"

int main(void) {
    const char *scenario = getenv("FAKE_WATCH_SCENARIO");
    if (!scenario) scenario = "ok";
    char error[256] = {0};
    int fd = d2k_routemark_watch_open(error, sizeof error);
    printf("%s success=%d\n", scenario, fd >= 0 ? 1 : 0);
    if (fd >= 0) close(fd);
    return 0;
}
