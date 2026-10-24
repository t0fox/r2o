#define _POSIX_C_SOURCE 200809L

#include "d2k_detect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int d2k_resp_scan12(const uint8_t *buf, size_t have, int *done);
void d2k_resp_decide(int target, int control, int unmeasured, int repeats,
                     d2k_resp_result *res);

static int verdict_value(const char *name, d2k_resp_verdict *out)
{
    if (strcmp(name, "not_applicable") == 0) *out = D2K_RESP_NOT_APPLICABLE;
    else if (strcmp(name, "clear") == 0) *out = D2K_RESP_CLEAR;
    else if (strcmp(name, "blocked") == 0) *out = D2K_RESP_BLOCKED;
    else if (strcmp(name, "flaky") == 0) *out = D2K_RESP_FLAKY;
    else return -1;
    return 0;
}

static int decode_hex(const char *hex, uint8_t **bytes, size_t *length)
{
    size_t n = strlen(hex), i;
    uint8_t *out;
    if ((n & 1U) != 0) return -1;
    out = malloc(n / 2U + 1U);
    if (!out) return -1;
    for (i = 0; i < n; i += 2) {
        unsigned value;
        if (sscanf(hex + i, "%2x", &value) != 1) {
            free(out);
            return -1;
        }
        out[i / 2U] = (uint8_t)value;
    }
    *bytes = out;
    *length = n / 2U;
    return 0;
}

int main(int argc, char **argv)
{
    FILE *file;
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    unsigned cases = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s fixture.tsv\n", argv[0]);
        return 2;
    }
    file = fopen(argv[1], "r");
    if (!file) {
        perror(argv[1]);
        return 2;
    }
    while ((length = getline(&line, &capacity, file)) >= 0) {
        char *fields[8], *cursor, *save = NULL;
        size_t count = 0;
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';
        if (length == 0 || line[0] == '#') continue;
        for (cursor = strtok_r(line, "\t", &save); cursor && count < 8;
             cursor = strtok_r(NULL, "\t", &save)) fields[count++] = cursor;

        if (count == 7 && strcmp(fields[0], "decide") == 0) {
            d2k_resp_result result;
            d2k_resp_verdict expected;
            int target = atoi(fields[1]), control = atoi(fields[2]);
            int unmeasured = atoi(fields[3]), repeats = atoi(fields[4]);
            if (verdict_value(fields[5], &expected) != 0) {
                fprintf(stderr, "unknown verdict in fixture case %u\n", cases + 1);
                return 2;
            }
            d2k_resp_decide(target, control, unmeasured, repeats, &result);
            if (result.verdict != expected || result.target != target ||
                result.control != control || strcmp(result.reason, fields[6]) != 0) {
                fprintf(stderr, "decide case %u differs: %s / target=%d control=%d / %s\n",
                        cases + 1, d2k_resp_name(result.verdict), result.target,
                        result.control, result.reason);
                return 1;
            }
        } else if (count == 3 && strcmp(fields[0], "scan") == 0) {
            uint8_t *bytes = NULL;
            size_t bytes_len = 0;
            int done = 0, rc;
            const char *actual;
            if (decode_hex(fields[1], &bytes, &bytes_len) != 0) {
                fprintf(stderr, "invalid TLS bytes in fixture case %u\n", cases + 1);
                return 2;
            }
            rc = d2k_resp_scan12(bytes, bytes_len, &done);
            free(bytes);
            actual = rc == 0 ? "need_more" : done ? "done" : "fatal_alert";
            if (strcmp(actual, fields[2]) != 0) {
                fprintf(stderr, "scan case %u differs: expected %s, got %s\n",
                        cases + 1, fields[2], actual);
                return 1;
            }
        } else {
            fprintf(stderr, "malformed fixture case %u\n", cases + 1);
            return 2;
        }
        cases++;
    }
    free(line);
    fclose(file);
    printf("d2o response fixture: %u cases match\n", cases);
    return cases == 0 ? 2 : 0;
}
