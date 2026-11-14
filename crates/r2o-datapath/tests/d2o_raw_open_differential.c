/* C/Rust differential: d2k_raw_open success/failure branches (a378). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "raw.c"

int main(void) {
    const char *scenario = getenv("FAKE_OPEN_SCENARIO");
    if (!scenario) scenario = "ok";
    uint32_t mark = strstr(scenario, "mark") ? 1u : 0u;
    char error[160];
    d2k_raw *raw = d2k_raw_open(mark, NULL, error, sizeof error);
    printf("%s rc=%d\n", scenario, raw ? 0 : -1);
    if (raw) {
        close(raw->fd);
        free(raw);
    }
    return 0;
}
