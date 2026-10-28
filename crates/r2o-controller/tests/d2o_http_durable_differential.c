#define main d2o_httpsearch_suite_main
#include "test_httpsearch.c"
#undef main

static d2k_httpsearch *durable_hs;
static char durable_path[] = "/tmp/d2o-http-confirmedXXXXXX";
static int durable_saved;

static void save_confirmed_http_plan(void *ctx) {
    fake *f = ctx;
    char err[256];
    f->changed_n++;
    if (d2k_httpsearch_save(durable_hs, durable_path, 1700000000, err, sizeof err) == 0) {
        durable_saved = 1;
    }
}

int main(void) {
    int fd = mkstemp(durable_path);
    if (fd < 0) { return 2; }
    close(fd);
    unlink(durable_path);

    fake f = {0};
    d2k_hs_ops ops = ops_of(&f);
    ops.changed = save_confirmed_http_plan;
    durable_hs = d2k_httpsearch_new(&ops);
    if (!durable_hs) { return 2; }

    int64_t now = 1000;
    d2k_httpsearch_portal(durable_hs, "rutracker.org", 4, IP, now);
    base_injected(durable_hs, &f, &now);
    trial(durable_hs, &f, &now, 1, D2K_HS_REAL);
    trial(durable_hs, &f, &now, 1, D2K_HS_REAL);

    int found = 0;
    FILE *saved = fopen(durable_path, "r");
    if (saved) {
        char line[512];
        while (fgets(line, sizeof line, saved)) {
            if (strstr(line, "rutracker.org 4 split ")) { found = 1; }
        }
        fclose(saved);
    }
    d2k_httpsearch_free(durable_hs);
    unlink(durable_path);
    if (!durable_saved || !found || f.changed_n != 1) {
        fprintf(stderr, "donor HTTP plan was not immediately durable\n");
        return 1;
    }
    printf("persisted_before_flush=yes\n");
    return 0;
}
