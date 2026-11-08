/* TG9: C-оракул `route_plan.c`.
 *
 * Использование: d2o-route-plan PLAN_CASES HOSTNAME_CASES
 */
#define _POSIX_C_SOURCE 200809L
#include "tg_route_plan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_int(const char *text, int *out) {
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (!end || *end != '\0') return -1;
    *out = (int)value;
    return 0;
}

/* Разделить строку по табуляции, сохраняя пустые поля (важно для пустого
 * домена в hostname-кейсах). */
static size_t split_tabs(char *line, char *fields[], size_t max) {
    size_t count = 0;
    char *start = line;
    for (char *cursor = line;; ++cursor) {
        char value = *cursor;
        if (value != '\t' && value != '\0') continue;
        *cursor = '\0';
        if (count < max) fields[count] = start;
        ++count;
        if (value == '\0') break;
        start = cursor + 1;
    }
    return count;
}

static void strip_line_end(char *line) {
    size_t length = strlen(line);
    while (length && (line[length - 1] == '\n' || line[length - 1] == '\r'))
        line[--length] = '\0';
}

static void run_plans(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) exit(2);
    char line[4096];
    while (fgets(line, sizeof line, file)) {
        strip_line_end(line);
        char *fields[9] = {0};
        size_t count = split_tabs(line, fields, 9);
        if (count != 8) continue;
        int dc, media, policy, prefer, workers, cf, diag;
        if (parse_int(fields[1], &dc) != 0 || parse_int(fields[2], &media) != 0 ||
            parse_int(fields[3], &policy) != 0 || parse_int(fields[4], &prefer) != 0 ||
            parse_int(fields[5], &workers) != 0 || parse_int(fields[6], &cf) != 0 ||
            parse_int(fields[7], &diag) != 0)
            continue;
        tg_route_plan plan;
        memset(&plan, 0xaa, sizeof plan);
        int rc = tg_route_plan_build((uint32_t)dc, media,
                                     (tg_ws_routing_policy)policy, prefer,
                                     (size_t)workers, (size_t)cf, diag, &plan);
        if (rc != 0) {
            printf("plan %s ok=0\n", fields[0]);
            continue;
        }
        printf("plan %s ok=1 count=%zu steps=", fields[0], plan.count);
        for (size_t i = 0; i < plan.count; i++)
            printf("%s%u:%u", i ? "," : "", (unsigned)plan.steps[i].kind,
                   (unsigned)plan.steps[i].index);
        putchar('\n');
    }
    fclose(file);
}

static void run_hostnames(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) exit(2);
    char line[8192];
    while (fgets(line, sizeof line, file)) {
        strip_line_end(line);
        char *fields[6] = {0};
        size_t count = split_tabs(line, fields, 6);
        if (count != 5) continue;
        int dc, media, capacity;
        if (parse_int(fields[1], &dc) != 0 || parse_int(fields[2], &media) != 0 ||
            parse_int(fields[4], &capacity) != 0)
            continue;
        char hostname[1024];
        memset(hostname, 0, sizeof hostname);
        int rc = tg_route_cf_proxy_hostname((uint32_t)dc, media, fields[3],
                                            hostname, (size_t)capacity);
        if (rc != 0) {
            printf("hostname %s ok=0\n", fields[0]);
            continue;
        }
        printf("hostname %s ok=1 value=%s\n", fields[0], hostname);
    }
    fclose(file);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    run_plans(argv[1]);
    run_hostnames(argv[2]);
    return 0;
}
