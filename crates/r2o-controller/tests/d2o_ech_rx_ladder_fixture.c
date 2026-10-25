#include "sched.c"

static int run_case(int network_probe) {
    d2k_catalog catalog = {0};
    d2k_sched *sched = calloc(1, sizeof *sched);
    task *current = calloc(1, sizeof *current);
    if (!sched || !current) return 2;
    sched->cat = &catalog;
    sched->send_cap = 1492;
    current->transport = 6;
    current->family = 4;
    current->vol.rx_cut = 1;
    current->rx_volume_candidate_pending = 1;
    current->net_probing = network_probe;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, "site.example", current->trig,
                               sizeof current->trig, &current->trig_len) != 0) return 3;

    size_t expected = network_probe ? 16 : D2K_RX_VOLUME_PLAN_VARIANTS;
    size_t batches = network_probe ? 2 : 1;
    size_t seen = 0;
    for (size_t batch = 0; batch < batches; batch++) {
        current->n_plans = 0;
        current->next_plan = 0;
        size_t added = refill_from_fallback(sched, current);
        if (!added || added > SCHED_MAX_PLANS || current->fb_queue || current->fb_next != 0) {
            free(current);
            free(sched);
            return 4;
        }
        for (size_t i = 0; i < added; i++) {
            fputs(current->plans[i], stdout);
            seen++;
        }
    }
    printf("%s %zu %zu %zu\n", network_probe ? "names" : "splits",
           seen, network_probe ? current->net_probe_next : current->rx_volume_next_variant,
           current->fb_next);
    if (seen != expected) {
        free(current);
        free(sched);
        return 5;
    }
    free(current);
    free(sched);
    return 0;
}

int main(void) {
    int rc = run_case(1);
    return rc ? rc : run_case(0);
}
