/* TG13: C-оракул кэша/парсера CF-доменов D2O.
 *
 * Modes:
 *   d2o-cf parse DIR NAME...
 *   d2o-cf pool NAME CACHE MANUAL
 *   d2o-cf write CACHE
 */
#define _POSIX_C_SOURCE 200809L
#include "tg_cf_domains.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, char **out, size_t *out_len) {
    FILE *file = fopen(path, "rb");
    if (!file) return -1;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    long length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    char *data = malloc((size_t)length + 1);
    if (!data) {
        fclose(file);
        return -1;
    }
    size_t used = fread(data, 1, (size_t)length, file);
    fclose(file);
    if (used != (size_t)length) {
        free(data);
        return -1;
    }
    data[used] = '\0';
    *out = data;
    *out_len = used;
    return 0;
}

static void print_pool(const tg_cf_domain_pool *pool) {
    printf("count=%zu", pool->domain_count);
    for (size_t i = 0; i < pool->domain_count; i++) {
        printf(" %s", pool->domains[i]);
    }
    printf(" fetched=%llu", (unsigned long long)pool->fetched_at);
}

static void parse_mode(char **argv, int argc) {
    const char *dir = argv[2];
    for (int index = 3; index < argc; index++) {
        char path[4096];
        snprintf(path, sizeof path, "%s/%s.txt", dir, argv[index]);
        char *text = NULL;
        size_t length = 0;
        if (read_file(path, &text, &length) != 0) {
            printf("%s ok=-1\n", argv[index]);
            continue;
        }
        char domains[TG_CF_REMOTE_MAX][TG_CF_DOMAIN_LEN] = {{0}};
        size_t count = 0;
        int rc = tg_cf_domain_pool_parse_remote(text, length, domains, &count);
        free(text);
        printf("%s ok=%d", argv[index], rc == 0 ? 1 : 0);
        if (rc == 0) {
            printf(" count=%zu", count);
            for (size_t i = 0; i < count; i++) printf(" %s", domains[i]);
        }
        putchar('\n');
    }
}

static void pool_mode(const char *name, const char *cache_path,
                      const char *manual_text) {
    char manual[TG_CF_MANUAL_MAX][TG_CF_DOMAIN_LEN] = {{0}};
    size_t manual_count = 0;
    if (manual_text && *manual_text) {
        snprintf(manual[0], sizeof manual[0], "%s", manual_text);
        manual_count = 1;
    }
    tg_cf_domain_pool pool;
    int rc = tg_cf_domain_pool_init(&pool, cache_path, &manual[0][0],
                                   manual_count, 1);
    printf("pool %s ok=%d", name, rc == 0 ? 1 : 0);
    if (rc == 0) {
        printf(" ");
        print_pool(&pool);
        tg_cf_domain_pool_destroy(&pool);
    }
    putchar('\n');
}

static void write_mode(const char *cache_path) {
    static const char *const names[] = {
        "alpha.co.uk", "beta.co.uk", "gamma.co.uk"
    };
    char flat[3][TG_CF_DOMAIN_LEN] = {{0}};
    for (size_t i = 0; i < 3; i++) {
        snprintf(flat[i], sizeof flat[i], "%s", names[i]);
    }
    tg_cf_domain_pool pool;
    int rc = tg_cf_domain_pool_init(&pool, cache_path, NULL, 0, 1);
    printf("write init=%d", rc == 0 ? 1 : 0);
    int installed = tg_cf_domain_pool_install_remote(
        &pool, &flat[0][0], 3, 456);
    printf(" install=%d", installed == 0 ? 1 : 0);
    if (rc == 0) {
        printf(" ");
        print_pool(&pool);
        tg_cf_domain_pool_destroy(&pool);
    }
    putchar('\n');
    if (installed == 0) {
        char *bytes = NULL;
        size_t length = 0;
        if (read_file(cache_path, &bytes, &length) != 0) {
            printf("cache=error\n");
            return;
        }
        printf("cache=");
        for (size_t i = 0; i < length; i++) {
            printf("%02x", (unsigned char)bytes[i]);
        }
        putchar('\n');
        free(bytes);
    }
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (strcmp(argv[1], "parse") == 0) {
        parse_mode(argv, argc);
        return 0;
    }
    if (strcmp(argv[1], "pool") == 0 && argc == 5) {
        pool_mode(argv[2], argv[3], argv[4]);
        return 0;
    }
    if (strcmp(argv[1], "write") == 0 && argc == 3) {
        write_mode(argv[2]);
        return 0;
    }
    return 2;
}
