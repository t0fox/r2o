/* C/Rust differential: budget_cut_reject — отметки Binding.budget. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "sched.c"

static const char *PLAN =
    "r2o-plan 1 11\nid 11111111111111111111111111111111\nproto tcp tls\n"
    "split sni_middle +0\n";

static void reset_case(d2k_cat_binding *bd, int budget, const char *target,
                       uint8_t transport, uint8_t family, uint8_t shape,
                       const char *kind, const char *plan_id) {
    memset(bd, 0, sizeof *bd);
    snprintf(bd->plan_id, sizeof bd->plan_id, "%s", plan_id);
    snprintf(bd->target, sizeof bd->target, "%s", target);
    snprintf(bd->kind, sizeof bd->kind, "%s", kind);
    bd->budget = (uint8_t)budget;
    bd->transport = transport;
    bd->family = family;
    bd->shape = shape;
    bd->enabled = 1;
}

int main(void) {
    static d2k_sched s;
    static d2k_catalog cat;
    static d2k_cat_box box;
    static d2k_cat_binding bind;
    static task t;
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    memset(&box, 0, sizeof box);
    memset(&t, 0, sizeof t);
    s.cat = &cat;
    s.now_ms = 5000;
    cat.boxes = &box;
    cat.n_boxes = 1;
    box.binds = &bind;
    box.n_binds = 1;

    char cut_id[40];
    uint8_t cut_wire[D2K_PLAN_ID_LEN];
    plan_ident(PLAN, cut_id, sizeof cut_id, cut_wire);
    fprintf(stderr, "cut_id=%s\n", cut_id);
    snprintf(t.name, sizeof t.name, "cut.example");
    t.transport = 6;
    t.family = 4;
    t.next_plan = 1;
    t.n_plans = 1;
    snprintf(t.plans[0], sizeof t.plans[0], "%s", PLAN);
    t.probes = 1;

    struct {
        const char *name;
        int budget;
        const char *target;
        uint8_t transport, family, shape;
        const char *kind;
    } cases[] = {
        {"passed", D2K_CAT_BUDGET_PASSED, "cut.example", 6, 4, 1, "name"},
        {"unchecked", D2K_CAT_BUDGET_UNCHECKED, "cut.example", 6, 4, 1, "name"},
        {"none", 0, "cut.example", 6, 4, 1, "name"},
        {"already_cut", D2K_CAT_BUDGET_CUT, "cut.example", 6, 4, 1, "name"},
        {"shape", D2K_CAT_BUDGET_PASSED, "cut.example", 6, 4, 2, "name"},
        {"transport", D2K_CAT_BUDGET_PASSED, "cut.example", 17, 4, 1, "name"},
        {"family", D2K_CAT_BUDGET_PASSED, "cut.example", 6, 6, 1, "name"},
        {"target", D2K_CAT_BUDGET_PASSED, "other.example", 6, 4, 1, "name"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        reset_case(&bind, cases[i].budget, cases[i].target, cases[i].transport,
                   cases[i].family, cases[i].shape, cases[i].kind, cut_id);
        t.fp.n_sig = 0;
        t.by_addr = 0;
        budget_cut_reject(&s, &t, s.now_ms);
        printf("%s=%u\n", cases[i].name, (unsigned)bind.budget);
    }
    return 0;
}
