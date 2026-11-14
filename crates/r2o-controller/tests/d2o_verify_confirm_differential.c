/* C/Rust differential: пробелы `verify_confirm` из core-state.md 1615-1640.
 *
 * - group_record(BLOCKED_CONFIRMED) — настоящая C-функция `group_record`;
 * - budget mark PASSED/UNCHECKED/CUT — блок `sched.c:9449-9474`, вынесенный
 *   в `budget_apply` дословно (в C это inline-код verify_confirm);
 * - unfit_here — цикл `sched.c:9346-9365`, вынесенный в `unfit_here`
 *   дословно (в C это inline-код verify_confirm).
 *
 * Rust-сторона: `r2o_group_record_confirmed`, `r2o_store_confirmed_budget`,
 * `R2oDiscoverySearches::plan_unfit`.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_sched s;
static d2k_catalog cat;
static task t;
static int first = 1;

static void dump_string(const char *value) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\') {
            putchar('\\');
            putchar(*p);
        } else if (*p < 0x20) {
            printf("\\u%04x", *p);
        } else {
            putchar(*p);
        }
    }
    putchar('"');
}

static void emit(const char *scenario) {
    printf("%s{\"scenario\":", first ? "" : ",\n");
    first = 0;
    dump_string(scenario);
}

static void dump_groups(void) {
    const d2k_group_state *state = cat.groups;
    printf(",\"observations\":[");
    for (size_t i = 0; state && i < state->n_observations; i++) {
        const d2k_group_observation *o = &state->observations[i];
        printf("%s{\"name\":", i ? "," : "");
        dump_string(o->name);
        printf(",\"plan_id\":");
        dump_string(o->plan_id);
        printf(",\"transport\":%u,\"family\":%u,\"shape\":%u,\"probe_path\":",
               (unsigned)o->key.transport, (unsigned)o->key.family,
               (unsigned)o->key.shape);
        dump_string(o->key.probe_path);
        printf(",\"ech_origin\":");
        dump_string(o->key.ech_origin);
        printf(",\"evidence\":%u,\"at\":%lld}",
               (unsigned)o->evidence, (long long)o->at);
    }
    printf("],\"groups\":[");
    for (size_t i = 0; state && i < state->n_groups; i++) {
        const d2k_domain_group *g = &state->groups[i];
        printf("%s{\"suffix\":", i ? "," : "");
        dump_string(g->suffix);
        printf(",\"plan_id\":");
        dump_string(g->plan_id);
        printf(",\"transport\":%u,\"family\":%u,\"shape\":%u,\"probe_path\":",
               (unsigned)g->key.transport, (unsigned)g->key.family,
               (unsigned)g->key.shape);
        dump_string(g->key.probe_path);
        printf(",\"ech_origin\":");
        dump_string(g->key.ech_origin);
        printf(",\"evidence_count\":%u}", (unsigned)g->evidence_count);
    }
    printf("]}");
}

static d2k_cat_binding budget_binds[4];
static d2k_cat_box budget_box;

/* Дословный перенос тела sched.c:9449-9474 (inline в verify_confirm). */
static void budget_apply(uint8_t mark) {
    for (size_t bi = 0; bi < cat.n_boxes; bi++) {
        d2k_cat_box *b = &cat.boxes[bi];
        if (strcmp(b->id, "box-1")) continue;
        for (size_t j = 0; j < b->n_binds; j++) {
            d2k_cat_binding *bd = &b->binds[j];
            if (!strcmp(bd->target, t.name) && !strcmp(bd->plan_id, "plan-1") &&
                !strcmp(bd->kind, t.by_addr ? "addr" : "name") &&
                (bd->family ? bd->family : 4) == t.family && bd->shape == 1 &&
                bd->transport == t.transport &&
                (mark == D2K_CAT_BUDGET_PASSED || bd->budget == 0 ||
                 (mark == D2K_CAT_BUDGET_CUT && bd->budget != D2K_CAT_BUDGET_PASSED)) &&
                bd->budget != mark) {
                bd->budget = mark;
            }
        }
    }
}

static void dump_budgets(const char *scenario) {
    emit(scenario);
    printf(",\"budgets\":[");
    for (size_t i = 0; i < budget_box.n_binds; i++)
        printf("%s%u", i ? "," : "", (unsigned)budget_binds[i].budget);
    printf("]}");
}

/* Дословный перенос цикла sched.c:9346-9365 (inline в verify_confirm). */
static int unfit_here(const uint8_t plan_id[16], const uint8_t ver_plan_id[16],
                      const uint8_t (*unfit)[16], size_t unfit_seen) {
    for (size_t k = 0; k < unfit_seen; k++) {
        if (memcmp(unfit[k], plan_id, D2K_PLAN_ID_LEN) == 0 ||
            memcmp(unfit[k], ver_plan_id, D2K_PLAN_ID_LEN) == 0) {
            return 1;
        }
    }
    return 0;
}

static void dump_unfit(const char *scenario, const uint8_t plan_id[16],
                       const uint8_t ver_plan_id[16], const uint8_t (*unfit)[16],
                       size_t unfit_seen) {
    emit(scenario);
    printf(",\"unfit\":%s}", unfit_here(plan_id, ver_plan_id, unfit, unfit_seen)
                                  ? "true" : "false");
}

/* Дословный перенос присваивания sched.c:9514-9536 (inline в verify_confirm):
 * имя записывается только при `t->net_probing && next_plan > 0 && name[0]`. */
static void net_case(const char *scenario, const char *name, int rx_cut,
                     int64_t wall_now) {
    d2k_net_whitelist nw;
    memset(&nw, 0, sizeof nw);
    if (name && name[0]) {
        snprintf(nw.name, sizeof nw.name, "%s", name);
        nw.tx_only = rx_cut ? 0 : 1;
        nw.searched = rx_cut ? 1 : 0;
        nw.confirmed_at = wall_now;
    }
    emit(scenario);
    printf(",\"network\":{\"name\":");
    dump_string(nw.name);
    printf(",\"tx_only\":%s,\"searched\":%s,\"confirmed_at\":%lld}}",
           nw.tx_only ? "true" : "false", nw.searched ? "true" : "false",
           (long long)nw.confirmed_at);
}

static void group_case(const char *scenario, int ech, const char *path) {
    memset(&cat, 0, sizeof cat);
    memset(&t, 0, sizeof t);
    s.cat = &cat;
    s.wall_base_s = 2000;
    s.mono_base_ms = 1000;
    snprintf(t.name, sizeof t.name, "media.example.com");
    t.transport = 6;
    t.family = 4;
    t.ech_offer = (uint8_t)ech;
    if (ech) snprintf(t.ech_origin, sizeof t.ech_origin, "edge.example");
    snprintf(t.measure_path, sizeof t.measure_path, "%s", path);
    t.trigger_tcp_profile = 0;
    group_record(&s, &t, D2K_GROUP_BLOCKED_CONFIRMED, "plan-1", 1, 1000);
    snprintf(t.name, sizeof t.name, "a.example.com");
    group_record(&s, &t, D2K_GROUP_BLOCKED_CONFIRMED, "plan-1", 1, 1000);
    snprintf(t.name, sizeof t.name, "b.example.com");
    group_record(&s, &t, D2K_GROUP_BLOCKED_CONFIRMED, "plan-1", 1, 1000);
    emit(scenario);
    dump_groups();
    d2k_catalog_free(&cat);
}

int main(void) {
    printf("[");
    memset(&s, 0, sizeof s);

    group_case("group_path", 0, "/main.css");
    group_case("group_no_path", 0, "");
    group_case("group_ech_origin", 1, "/ech.css");

    memset(&cat, 0, sizeof cat);
    memset(&t, 0, sizeof t);
    memset(budget_binds, 0, sizeof budget_binds);
    memset(&budget_box, 0, sizeof budget_box);
    snprintf(t.name, sizeof t.name, "budget.example");
    t.transport = 6;
    t.family = 4;
    t.by_addr = 0;
    for (size_t i = 0; i < 4; i++) {
        snprintf(budget_binds[i].kind, sizeof budget_binds[i].kind, "name");
        snprintf(budget_binds[i].target, sizeof budget_binds[i].target, "%s", t.name);
        snprintf(budget_binds[i].plan_id, sizeof budget_binds[i].plan_id, "plan-1");
        budget_binds[i].level = 3;
        budget_binds[i].enabled = 1;
        budget_binds[i].transport = 6;
        budget_binds[i].family = 4;
        budget_binds[i].shape = 1;
    }
    budget_binds[1].budget = D2K_CAT_BUDGET_PASSED;
    budget_binds[2].budget = D2K_CAT_BUDGET_CUT;
    budget_binds[3].budget = D2K_CAT_BUDGET_UNCHECKED;
    snprintf(budget_box.id, sizeof budget_box.id, "box-1");
    budget_box.binds = budget_binds;
    budget_box.n_binds = 4;
    cat.boxes = &budget_box;
    cat.n_boxes = 1;
    s.cat = &cat;
    budget_apply(D2K_CAT_BUDGET_CUT);
    dump_budgets("budget_cut");
    budget_apply(D2K_CAT_BUDGET_UNCHECKED);
    dump_budgets("budget_unchecked");
    budget_apply(D2K_CAT_BUDGET_PASSED);
    dump_budgets("budget_passed");

    uint8_t a[16] = {0}, b[16] = {0}, c[16] = {0}, unfit[8][16];
    memset(unfit, 0, sizeof unfit);
    a[0] = 1;
    b[0] = 2;
    c[0] = 3;
    memcpy(unfit[0], a, sizeof a);
    memcpy(unfit[1], b, sizeof b);
    dump_unfit("unfit_a_wire", a, c, unfit, 2);
    dump_unfit("unfit_b_wire", b, c, unfit, 2);
    dump_unfit("unfit_miss", c, c, unfit, 2);
    memset(unfit, 0, sizeof unfit);
    dump_unfit("unfit_zero_plan", a, c, unfit, 1);

    net_case("net_rx_cut", "9gag.com", 1, 2000);
    net_case("net_tx_only", "9gag.com", 0, 2000);

    printf("]\n");
    return 0;
}
