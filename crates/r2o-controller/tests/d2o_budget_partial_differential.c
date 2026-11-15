/* C-оракул частичного обхода budget_cut_reject: partial best по
 * budget_packets/successes, owned_fallback и переход T_PLANNING. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static void print_hex(const char *text) {
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        printf("%02x", *p);
    }
}

int main(void) {
    d2k_sched *s = calloc(1, sizeof *s);
    d2k_catalog *cat = calloc(1, sizeof *cat);
    if (!s || !cat) return 1;
    s->cat = cat;
    cat->boxes = calloc(1, sizeof *cat->boxes);
    if (!cat->boxes) return 1;
    cat->boxes[0].plans = calloc(1, sizeof *cat->boxes[0].plans);
    cat->boxes[0].binds = calloc(1, sizeof *cat->boxes[0].binds);
    if (!cat->boxes[0].plans || !cat->boxes[0].binds) return 1;
    s->now_ms = 100000;
    s->clock_seen = 1;
    if (pthread_mutex_init(&s->mu, NULL)) return 1;

    static const char plan_text[] =
        "d2k-plan 1 1\n"
        "id 00112233445566778899aabbccddeeff\n"
        "proto tcp tls\n"
        "order forward\n";
    char plan_id[40];
    uint8_t wire_id[D2K_PLAN_ID_LEN];
    plan_ident(plan_text, plan_id, sizeof plan_id, wire_id);

    const struct {
        const char *name;
        unsigned pk;
        int succ;
        int search_owned;
        int owned_fallback;
        int own_first;
    } cases[] = {
        {"first", 100, 1, 1, 0, 0},
        {"lower-pk", 50, 9, 1, 0, 0},
        {"tie-better-succ", 100, 5, 1, 0, 0},
        {"tie-worse-succ", 100, 2, 1, 0, 0},
        {"higher-pk", 120, 0, 1, 0, 0},
        {"higher-pk-tie-succ", 120, 5, 1, 0, 0},
        {"own-first-two", 130, 9, 1, 0, 2},
        {"already-owned", 140, 9, 1, 1, 0},
    };
    task t;
    memset(&t, 0, sizeof t);
    snprintf(t.name, sizeof t.name, "partial.example");
    snprintf(t.ip, sizeof t.ip, "198.51.100.90");
    t.transport = 6;
    t.family = 4;
    t.trigger_shape = 1;
    snprintf(t.plans[0], sizeof t.plans[0], "%s", plan_text);
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        t.state = T_VERIFY;
        t.next_plan = 1;
        t.ver.budget_packets = cases[i].pk;
        t.ver.status = 200;
        snprintf(t.box_id, sizeof t.box_id, "box-%zu", i);
        t.search_owned = cases[i].search_owned;
        t.owned_fallback = cases[i].owned_fallback;
        t.own_first = cases[i].own_first;

        cat->n_boxes = 1;
        d2k_cat_plan *plans = cat->boxes[0].plans;
        d2k_cat_binding *binds = cat->boxes[0].binds;
        memset(&cat->boxes[0], 0, sizeof cat->boxes[0]);
        cat->boxes[0].plans = plans;
        cat->boxes[0].binds = binds;
        memset(plans, 0, sizeof *plans);
        memset(binds, 0, sizeof *binds);
        snprintf(cat->boxes[0].id, sizeof cat->boxes[0].id, "box-%zu", i);
        cat->boxes[0].n_plans = 1;
        snprintf(cat->boxes[0].plans[0].id, sizeof cat->boxes[0].plans[0].id, "%s",
                 plan_id);
        cat->boxes[0].plans[0].successes = cases[i].succ;
        cat->boxes[0].plans[0].enabled = 1;
        cat->boxes[0].n_binds = 1;
        d2k_cat_binding *bd = &cat->boxes[0].binds[0];
        memset(bd, 0, sizeof *bd);
        snprintf(bd->plan_id, sizeof bd->plan_id, "%s", plan_id);
        snprintf(bd->target, sizeof bd->target, "%s", t.name);
        snprintf(bd->kind, sizeof bd->kind, "name");
        bd->transport = 6;
        bd->family = 4;
        bd->shape = 1;

        budget_cut_reject(s, &t, s->now_ms);
        printf("case %s valid=%d pk=%u succ=%u text=", cases[i].name,
               t.partial_valid, t.partial_pk, t.partial_succ);
        print_hex(t.partial_text);
        printf(" box=%s owned=%d\n", t.partial_box, t.owned_fallback);
    }
    pthread_mutex_destroy(&s->mu);
    free(cat->boxes[0].plans);
    free(cat->boxes[0].binds);
    free(cat->boxes);
    free(cat);
    free(s);
    return 0;
}
