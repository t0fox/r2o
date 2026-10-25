#include "sched.c"

int main(void) {
    d2k_catalog catalog = {0};
    d2k_sched *sched = calloc(1, sizeof *sched);
    task *current = calloc(1, sizeof *current);
    if (!sched || !current) return 2;
    sched->cat = &catalog;
    sched->send_cap = 1492;
    current->transport = 6;
    current->family = 4;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, "site.example", current->trig,
                               sizeof current->trig, &current->trig_len) != 0) return 3;

    d2k_vres result = {0};
    result.verdict = D2K_V_OPAQUE;
    result.owns_search = 1;
    verdict_to_plans(sched, current, &result);
    if (!current->owned_fallback || current->n_plans != 8) return 4;

    for (size_t i = 0; i < current->n_plans; i++) fputs(current->plans[i], stdout);
    free(current);
    free(sched);
    return 0;
}
