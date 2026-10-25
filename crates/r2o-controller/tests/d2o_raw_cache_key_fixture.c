#include "classify.c"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    char line[128];
    unsigned family;
    int offer_ts;
    FILE *fixture;
    if (argc != 3 || !(fixture = fopen(argv[1], "r"))) return 2;
    while (fgets(line, sizeof(line), fixture)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "family=%u offer_ts=%d", &family, &offer_ts) != 2 ||
            (family != 4 && family != 6) || (offer_ts != 0 && offer_ts != 1)) {
            fclose(fixture);
            return 2;
        }
        printf("RAW_SELFTEST_KEY family=%u offer_ts=%d cache_index=%d\n",
               family, offer_ts, self_ix((uint8_t)family, offer_ts));
    }
    fclose(fixture);

    int error_streak[2] = {0, 0};
    d2k_result result = {0};
    selftest_store(4, 1, 1);
    selftest_store(4, 0, 1);
    selftest_store(6, 1, 1);
    selftest_store(6, 0, 1);
    fixture = fopen(argv[2], "r");
    if (!fixture) return 2;
    while (fgets(line, sizeof(line), fixture)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "family=%u result=error", &family) != 1 ||
            (family != 4 && family != 6)) {
            fclose(fixture);
            return 2;
        }
        int index = family == 6 ? 1 : 0;
        d2k_raw_note_rc(&result, (uint8_t)family, -1);
        error_streak[index]++;
        printf("RAW_SELFTEST_INVALIDATION family=%u errors=%d with_ts=%d without_ts=%d\n",
               family, error_streak[index],
               selftest_cached_age((uint8_t)family, 1) >= 0,
               selftest_cached_age((uint8_t)family, 0) >= 0);
    }
    fclose(fixture);
    return 0;
}
