/* C/Rust differential: d2k_group_learn/d2k_group_restore.
 *
 * Сценарии используют только общую семантику C (evidence 1/2/4/8, без
 * R2O-расширения OPERATOR_REJECT). Печатает состояние после каждого шага
 * в формате, который повторяет examples/groups_trace.rs.
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "d2k_domain.h"
#include "d2k_groups.h"

static d2k_group_key make_key(uint8_t transport, uint8_t family, uint8_t shape) {
    d2k_group_key key;
    memset(&key, 0, sizeof key);
    key.transport = transport;
    key.family = family;
    key.shape = shape;
    return key;
}

static void print_state(const char *scenario, int rc, const d2k_group_state *s) {
    printf("scenario %s rc=%d n_obs=%zu n_groups=%zu frozen=%d disabled=%d disabled_at=%" PRId64 "\n",
           scenario, rc, s->n_observations, s->n_groups, s->frozen, s->disabled,
           s->disabled_at);
    for (size_t i = 0; i < s->n_observations; i++) {
        const d2k_group_observation *o = &s->observations[i];
        printf("obs %zu name=%s plan=%s t=%u f=%u s=%u path=%s origin=%s ev=%u at=%" PRId64 "\n",
               i, o->name, o->plan_id, o->key.transport, o->key.family, o->key.shape,
               o->key.probe_path, o->key.ech_origin, o->evidence, o->at);
    }
    for (size_t i = 0; i < s->n_groups; i++) {
        const d2k_domain_group *g = &s->groups[i];
        printf("group %zu suffix=%s plan=%s t=%u f=%u s=%u path=%s origin=%s count=%u at=%" PRId64 "\n",
               i, g->suffix, g->plan_id, g->key.transport, g->key.family, g->key.shape,
               g->key.probe_path, g->key.ech_origin, g->evidence_count, g->at);
    }
}

static int learn(d2k_group_state *s, const char *name, const char *plan,
                 unsigned evidence, int64_t at) {
    d2k_group_observation o;
    memset(&o, 0, sizeof o);
    snprintf(o.name, sizeof o.name, "%s", name);
    snprintf(o.plan_id, sizeof o.plan_id, "%s", plan);
    o.key = make_key(6, 4, 1);
    o.evidence = evidence;
    o.at = at;
    return d2k_group_learn(s, &o);
}

static int learn_key(d2k_group_state *s, const char *name, const char *plan,
                     unsigned evidence, int64_t at, d2k_group_key key) {
    d2k_group_observation o;
    memset(&o, 0, sizeof o);
    snprintf(o.name, sizeof o.name, "%s", name);
    snprintf(o.plan_id, sizeof o.plan_id, "%s", plan);
    o.key = key;
    o.evidence = evidence;
    o.at = at;
    return d2k_group_learn(s, &o);
}

static void set_obs(d2k_group_state *s, const char *name, const char *plan,
                    unsigned evidence, int64_t at) {
    d2k_group_observation *o = &s->observations[s->n_observations++];
    memset(o, 0, sizeof *o);
    snprintf(o->name, sizeof o->name, "%s", name);
    snprintf(o->plan_id, sizeof o->plan_id, "%s", plan);
    o->key = make_key(6, 4, 1);
    o->evidence = evidence;
    o->at = at;
}

static void scenario_learn_basic(void) {
    static d2k_group_state s;
    memset(&s, 0, sizeof s);
    print_state("A0", 0, &s);
    print_state("A1", learn(&s, "a.example.org", "p1", 1, 10), &s);
    print_state("A2", learn(&s, "b.example.org", "p1", 1, 20), &s);
    print_state("A3", learn(&s, "c.example.org", "p1", 1, 30), &s);
    print_state("A4", learn(&s, "c.example.org", "p1", 1, 25), &s);
    print_state("A5", learn(&s, "c.example.org", "p1", 1, 40), &s);
    print_state("A6", learn(&s, "d.example.org", "p2", 1, 50), &s);
    print_state("A7", learn(&s, "b.example.org", "p1", 4, 60), &s);
    print_state("A8", learn(&s, "e.example.org", "p1", 1, 70), &s);
    print_state("A9", learn(&s, "f.example.org", "p1", 1, 80), &s);
    print_state("A10", learn(&s, "c.example.org", "p1", 2, 90), &s);
    print_state("A11", learn(&s, "e.example.org", "p1", 2, 100), &s);
    print_state("A12", learn(&s, "f.example.org", "p1", 8, 110), &s);
    print_state("A13", learn(&s, "g.example.org", "p1", 8, 120), &s);
    print_state("A14", learn(&s, "g.example.org", "p1", 8, 130), &s);
    print_state("A15", learn_key(&s, "h.example.org", "p1", 1, 140,
                                 make_key(6, 5, 1)),
                &s);
    print_state("A16", learn(&s, "d.example.org", "p3", 2, 150), &s);
}

static void scenario_learn_capacity(void) {
    static d2k_group_state s;
    memset(&s, 0, sizeof s);
    print_state("B0", 0, &s);
    char name[256];
    for (int i = 0; i < D2K_GROUP_OBSERVATION_MAX; i++) {
        snprintf(name, sizeof name, "h%d.example.org", i);
        if (learn(&s, name, "p1", 1, 1000 + i) != 1) {
            printf("B-fill-fail %d\n", i);
            break;
        }
    }
    print_state("B1", 0, &s);
    print_state("B2", learn(&s, "overflow.example.org", "p1", 1, 2000), &s);
    print_state("B3", learn(&s, "overflow2.example.org", "p1", 1, 2001), &s);
}

static void scenario_groups_frozen(void) {
    static d2k_group_state s;
    memset(&s, 0, sizeof s);
    char name[256];
    for (int d = 0; d < D2K_GROUP_MAX; d++) {
        for (int j = 0; j < 3; j++) {
            snprintf(name, sizeof name, "m%d.example%d.org", j, d);
            learn(&s, name, "p1", 1, 1000 + d * 10 + j);
        }
    }
    print_state("C1", 0, &s);
    print_state("C2", learn(&s, "m0.example64.org", "p1", 1, 2000), &s);
    print_state("C3", learn(&s, "m1.example64.org", "p1", 1, 2001), &s);
}

static void scenario_disabled_reenable(void) {
    static d2k_group_state s;
    memset(&s, 0, sizeof s);
    for (int i = 0; i < D2K_GROUP_OBSERVATION_MAX - 1; i++) {
        char name[256];
        snprintf(name, sizeof name, "b%d.example.org", i);
        set_obs(&s, name, "p1", 1, 10);
    }
    set_obs(&s, "p.example.org", "p1", 4, 20);
    s.n_groups = 0;
    s.frozen = 1;
    s.disabled = 1;
    s.disabled_at = 20;
    print_state("D0", 0, &s);
    print_state("D1", learn(&s, "q.example.org", "p1", 4, 30), &s);
}

static void scenario_restore_valid(void) {
    static d2k_group_state s;
    memset(&s, 0, sizeof s);
    set_obs(&s, "a.example.org", "p1", 12, 10);
    set_obs(&s, "b.example.org", "p1", 5, 20);
    set_obs(&s, "c.example.org", "p1", 3, 30);
    set_obs(&s, "d.example.org", "p1", 6, 40);
    set_obs(&s, "e.example.org", "p1", 1, 50);
    set_obs(&s, "f.example.org", "p1", 2, 60);
    set_obs(&s, "g.example.org", "p1", 8, 70);
    int rc = d2k_group_restore(&s);
    print_state("E1", rc, &s);
}

static void scenario_restore_admitted_without_clear(void) {
    static d2k_group_state s;
    memset(&s, 0, sizeof s);
    set_obs(&s, "a.example.org", "p1", 16, 10);
    print_state("E2", d2k_group_restore(&s), &s);
}

static void scenario_restore_duplicate(void) {
    static d2k_group_state s;
    memset(&s, 0, sizeof s);
    set_obs(&s, "a.example.org", "p1", 1, 10);
    set_obs(&s, "a.example.org", "p1", 2, 20);
    print_state("E3", d2k_group_restore(&s), &s);
}

static void scenario_restore_negative_disabled_at(void) {
    static d2k_group_state s;
    memset(&s, 0, sizeof s);
    set_obs(&s, "a.example.org", "p1", 1, 10);
    s.disabled_at = -1;
    print_state("E4", d2k_group_restore(&s), &s);
}

static void scenario_restore_negative_at(void) {
    static d2k_group_state s;
    memset(&s, 0, sizeof s);
    set_obs(&s, "a.example.org", "p1", 1, -1);
    print_state("E5", d2k_group_restore(&s), &s);
}

static void scenario_restore_unknown_tld(void) {
    static d2k_group_state s;
    memset(&s, 0, sizeof s);
    set_obs(&s, "a.example.not-a-real-tld", "p1", 1, 10);
    print_state("E6", d2k_group_restore(&s), &s);
}

int main(void) {
    scenario_learn_basic();
    scenario_learn_capacity();
    scenario_groups_frozen();
    scenario_disabled_reenable();
    scenario_restore_valid();
    scenario_restore_admitted_without_clear();
    scenario_restore_duplicate();
    scenario_restore_negative_disabled_at();
    scenario_restore_negative_at();
    scenario_restore_unknown_tld();
    return 0;
}
