#define main d2o_httpsearch_suite_main
#include "test_httpsearch.c"
#undef main

static void seed_owned_plan(d2k_httpsearch **search, fake *f, int64_t *now) {
    d2k_hs_ops ops = ops_of(f);
    *search = d2k_httpsearch_new(&ops);
    d2k_httpsearch_portal(*search, "rutracker.org", 4, IP, *now);
    base_injected(*search, f, now);
    trial(*search, f, now, 1, D2K_HS_REAL);
    trial(*search, f, now, 1, D2K_HS_REAL);
}

static void recheck_all_failed(d2k_httpsearch *search, fake *f, int64_t *now,
                               int applied) {
    d2k_httpsearch_portal(search, "rutracker.org", 4, IP,
                          *now += D2K_HS_RECHECK_MS + 1);
    base_injected(search, f, now);
    for (int i = 0; i < 40 && d2k_httpsearch_busy(search); i++) {
        trial(search, f, now, applied, D2K_HS_INJECTED);
        if (!applied) d2k_httpsearch_tick(search, *now += 1000);
    }
}

static void print_state(const char *label, d2k_httpsearch *search, const fake *f) {
    printf("%s:plan_present=%d,del_plan=%d,changed=%d,unknown_delete=%d\n",
           label,
           d2k_httpsearch_plan_of(search, "rutracker.org", 4) != NULL,
           f->del_plan_n, f->changed_n, f->unknown_delete);
}

int main(void) {
    fake judged = {0};
    d2k_httpsearch *search = NULL;
    int64_t now = 1000;
    seed_owned_plan(&search, &judged, &now);
    recheck_all_failed(search, &judged, &now, 1);
    print_state("judged", search, &judged);
    d2k_httpsearch_free(search);

    fake unjudged = {0};
    search = NULL;
    now = 1000;
    seed_owned_plan(&search, &unjudged, &now);
    recheck_all_failed(search, &unjudged, &now, 0);
    print_state("unjudged", search, &unjudged);
    d2k_httpsearch_free(search);

    fake late_ack = {0};
    search = NULL;
    now = 1000;
    seed_owned_plan(&search, &late_ack, &now);
    late_ack.hold_install_ack = 1;
    d2k_httpsearch_push_all(search);
    uint8_t token[16];
    memcpy(token, late_ack.install_id, sizeof token);
    recheck_all_failed(search, &late_ack, &now, 1);
    d2k_httpsearch_install_ack(search, token, 1, &late_ack.binding);
    print_state("late_ack", search, &late_ack);
    d2k_httpsearch_free(search);

    fake late_nack = {0};
    search = NULL;
    now = 1000;
    seed_owned_plan(&search, &late_nack, &now);
    late_nack.hold_install_ack = 1;
    d2k_httpsearch_push_all(search);
    memcpy(token, late_nack.install_id, sizeof token);
    recheck_all_failed(search, &late_nack, &now, 1);
    d2k_httpsearch_install_ack(search, token, 0, &late_nack.binding);
    print_state("late_nack", search, &late_nack);
    d2k_httpsearch_free(search);
    return 0;
}
