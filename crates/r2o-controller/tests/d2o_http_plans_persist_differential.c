/* C-оракул: d2k_httpsearch_save/load (core/httpsearch.c:1446-1514).
 *
 * httpsearch.c включается целиком: нужны статические rec_get/install.
 * Аргумент — каталог для временных файлов. */
#include "httpsearch.c"

#include <stdio.h>
#include <string.h>

static void write_file(const char *dir, const char *name, const char *text) {
    char path[600];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (!f) { perror("fopen"); return; }
    fputs(text, f);
    fclose(f);
}

static void print_hex(const char *label, const char *dir, const char *name) {
    char path[600];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    printf("%s present=%d hex=", label, f ? 1 : 0);
    if (f) {
        int c;
        while ((c = fgetc(f)) != EOF) printf("%02x", (unsigned)c);
        fclose(f);
    }
    printf("\n");
}

static void load_case(const char *dir, const char *name, const char *text) {
    if (text) write_file(dir, name, text);
    char path[600];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    d2k_httpsearch *hs = d2k_httpsearch_new(NULL);
    size_t n = 0;
    char err[200] = {0};
    int rc = d2k_httpsearch_load(hs, path, &n, err, sizeof err);
    printf("%s rc=%d n=%zu", name, rc, n);
    for (size_t i = 0; i < hs->n_recs; i++) {
        printf(" rec=%s/%u/%s/%lld", hs->recs[i].host, hs->recs[i].family,
               hs->recs[i].key, (long long)hs->recs[i].wall);
    }
    printf("\n");
    d2k_httpsearch_free(hs);
}

static void save_case(const char *dir) {
    d2k_httpsearch *hs = d2k_httpsearch_new(NULL);
    rec *a = rec_get(hs, "alpha.example", 4);
    snprintf(a->key, sizeof a->key, "%s", "split");
    a->wall = 111;
    rec *b = rec_get(hs, "beta.example", 6);
    snprintf(b->key, sizeof b->key, "%s", "fake-badsum");
    b->wall = 0;
    rec *c = rec_get(hs, "gamma.example", 4); /* пустой ключ — пропуск */
    (void)c;
    rec *d = rec_get(hs, "delta.example", 4);
    snprintf(d->key, sizeof d->key, "%s", "disorder");
    d->revoked = 1;
    rec *e = rec_get(hs, "eps.example", 4);
    snprintf(e->key, sizeof e->key, "%s", "fake-seqshift");
    e->wall = -5;

    char path[600];
    snprintf(path, sizeof path, "%s/plans.txt", dir);
    char err[200] = {0};
    int rc = d2k_httpsearch_save(hs, path, 999, err, sizeof err);
    printf("save rc=%d wall-a=%lld wall-b=%lld wall-e=%lld\n", rc,
           (long long)a->wall, (long long)b->wall, (long long)e->wall);
    print_hex("save", dir, "plans.txt");
    d2k_httpsearch_free(hs);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const char *dir = argv[1];
    save_case(dir);
    load_case(dir, "valid.txt",
              "d2k-http-plans 1\nalpha.example 4 split 111\n"
              "beta.example 6 fake-badsum 222\n");
    load_case(dir, "bad-header.txt",
              "d2k-http-plans 2\nalpha.example 4 split 111\n");
    load_case(dir, "no-header-newline.txt", "d2k-http-plans 1");
    load_case(dir, "bad-family.txt",
              "d2k-http-plans 1\nalpha.example 5 split 111\n");
    load_case(dir, "bad-host.txt",
              "d2k-http-plans 1\n_bad.example 4 split 111\n");
    load_case(dir, "unknown-key.txt",
              "d2k-http-plans 1\nalpha.example 4 other 111\n");
    load_case(dir, "extra-token.txt",
              "d2k-http-plans 1\nalpha.example 4 split 111 x\n");
    load_case(dir, "duplicate.txt",
              "d2k-http-plans 1\nalpha.example 4 split 111\n"
              "ALPHA.example 4 disorder 222\n");
    load_case(dir, "blank.txt",
              "d2k-http-plans 1\n\nalpha.example 4 split 111\n\n");
    load_case(dir, "crlf.txt",
              "d2k-http-plans 1\r\nalpha.example 4 split 111\r\n");
    load_case(dir, "negative-wall.txt",
              "d2k-http-plans 1\nalpha.example 4 split -7\n");
    load_case(dir, "missing.txt", NULL);
    return 0;
}
