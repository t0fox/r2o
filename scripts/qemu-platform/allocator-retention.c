#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <unistd.h>

enum { KIB = 1024, SLOTS = 1024, ROUNDS = 12 };

static long anonymous_kib(void) {
    FILE *file = fopen("/proc/self/smaps_rollup", "r");
    if (!file)
        file = fopen("/proc/self/smaps", "r");
    if (!file)
        return -1;

    char line[256];
    long value, sum = 0;
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "Anonymous: %ld kB", &value) == 1) {
            sum += value;
            found = 1;
        }
    }
    fclose(file);
    return found ? sum : -1;
}

static int check(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page != EXPECTED_PAGE_SIZE)
        return 1;
    long baseline = anonymous_kib(), first = -1, touched_kib = 0;
    if (baseline < 0)
        return 2;
    void *slots[SLOTS] = {0};
    for (unsigned round = 0; round < ROUNDS; ++round) {
        for (unsigned i = 0; i < SLOTS; ++i) {
            size_t bytes = 1024 + (i % 128) * 512;
            slots[i] = malloc(bytes);
            if (!slots[i])
                return 3;
            // Touch each page through a volatile write so the optimizer cannot remove it.
            volatile unsigned char *memory = slots[i];
            for (size_t n = 0; n < bytes; n += (size_t)page)
                memory[n] = (unsigned char)i;
            memory[bytes - 1] = (unsigned char)round;
        }
        touched_kib = anonymous_kib();
        if (touched_kib - baseline < 8 * KIB)
            return 4;
        for (unsigned i = 0; i < SLOTS; ++i)
            free(slots[(i * 727) % SLOTS]);
        long after = anonymous_kib();
        if (after < 0)
            return 5;
        if (first < 0)
            first = after;
        if (after - baseline > 8 * KIB || after - first > 4 * KIB)
            return 6;
    }
    printf("R2O_ALLOCATOR_OK page=%ld baseline=%ld peak=%ld final=%ld\n",
           page, baseline, touched_kib, anonymous_kib());
    return 0;
}

int main(void) {
    int guest = getpid() == 1;
    if (guest && mount("proc", "/proc", "proc", 0, NULL) < 0)
        return 7;
    int error = check();
    if (error)
        fprintf(stderr, "R2O_ALLOCATION_CHECK_FAILED step=%d\n", error);
    fflush(stdout);
    fflush(stderr);
    if (guest)
        reboot(RB_POWER_OFF);
    return error;
}
