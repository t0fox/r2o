/* C/Rust differential: write_live_groups, несколько состояний install/exception.
 * Каждая строка — JSON {"scenario": "...", "groups": ...}. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_sched s;
static d2k_catalog cat;
static d2k_group_state groups;
static d2k_cat_box box;
static d2k_cat_plan plan;

static void set_key(d2k_group_key *key) {
    memset(key, 0, sizeof *key);
    key->transport = 6;
    key->family = 4;
    key->shape = 1;
}

static void set_obs(size_t index, const char *name, const char *plan_id,
                    unsigned evidence, int64_t at) {
    d2k_group_observation *o = &groups.observations[index];
    memset(o, 0, sizeof *o);
    snprintf(o->name, sizeof o->name, "%s", name);
    snprintf(o->plan_id, sizeof o->plan_id, "%s", plan_id);
    set_key(&o->key);
    o->evidence = evidence;
    o->at = at;
}

static void setup(int plan_enabled) {
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    memset(&groups, 0, sizeof groups);
    memset(&box, 0, sizeof box);
    memset(&plan, 0, sizeof plan);

    snprintf(plan.id, sizeof plan.id, "plan-1");
    snprintf(plan.proto, sizeof plan.proto, "tls");
    plan.text = "plan";
    plan.enabled = plan_enabled;
    plan.successes = 1;
    box.plans = &plan;
    box.n_plans = 1;
    cat.boxes = &box;
    cat.n_boxes = 1;
    cat.groups = &groups;

    groups.n_groups = 1;
    snprintf(groups.groups[0].suffix, sizeof groups.groups[0].suffix, "example.com");
    snprintf(groups.groups[0].plan_id, sizeof groups.groups[0].plan_id, "plan-1");
    set_key(&groups.groups[0].key);
    groups.groups[0].evidence_count = 1;
    groups.groups[0].at = 1;

    set_obs(0, "a.example.com", "plan-1", D2K_GROUP_BLOCKED_CONFIRMED, 1);
    set_obs(1, "b.example.com", "plan-1", D2K_GROUP_DIRECT_CLEAR, 2);
    set_obs(2, "example.com", "plan-1", D2K_GROUP_BLOCKED_CONFIRMED, 3);
    set_obs(3, "d.example.com", "plan-2",
            D2K_GROUP_BLOCKED_CONFIRMED | D2K_GROUP_PLAN_FAILED, 4);
    groups.n_observations = 4;
}

static installed_area area(int kind, const char *name, const char *plan_id,
                           int confirmed, int maybe_active, int remove_pending,
                           int permanent, int retry_count, int reason,
                           unsigned reason_code, const char *detail) {
    installed_area a;
    memset(&a, 0, sizeof a);
    a.kind = (uint8_t)kind;
    snprintf(a.name, sizeof a.name, "%s", name);
    if (plan_id) snprintf(a.plan_id, sizeof a.plan_id, "%s", plan_id);
    a.transport = 6;
    a.shape = 1;
    a.family = 4;
    a.confirmed = (uint8_t)confirmed;
    a.maybe_active = (uint8_t)maybe_active;
    a.remove_pending = (uint8_t)remove_pending;
    a.permanent = (uint8_t)permanent;
    a.retry_count = (uint8_t)retry_count;
    a.reason = (uint8_t)reason;
    a.reason_code = (uint8_t)reason_code;
    snprintf(a.detail, sizeof a.detail, "%s", detail ? detail : "");
    return a;
}

static void emit(const char *name, installed_area *areas, size_t n, int first) {
    s.cat = &cat;
    s.areas = areas;
    s.n_areas = n;
    s.now_ms = 1000;
    char *buf = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);
    write_live_groups(mem, &s);
    fclose(mem);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == ',' ||
                       buf[len - 1] == ' ')) {
        buf[--len] = '\0';
    }
    printf("%s{\"scenario\":\"%s\", %s}", first ? "" : ",", name, buf);
    free(buf);
}

int main(void) {
    printf("[");
    setup(1);
    installed_area active_group =
        area(1, "example.com", "plan-1", 1, 0, 0, 0, 0, 0, 0, "");
    installed_area active_exc =
        area(2, "b.example.com", NULL, 1, 0, 0, 0, 0, 0, 0, "");
    installed_area areas[2] = {active_group, active_exc};
    emit("active", areas, 2, 1);

    installed_area retry_group =
        area(1, "example.com", "plan-1", 0, 1, 0, 0, 2, AREA_REASON_ACK_TIMEOUT,
             0, "ACK не пришёл");
    areas[0] = retry_group;
    emit("retrying", areas, 2, 0);

    installed_area rejected_group =
        area(1, "example.com", "plan-1", 0, 1, 0, 1, 1, AREA_REASON_BAD_PLAN, 17,
             "план не разобрался");
    areas[0] = rejected_group;
    emit("rejected", areas, 2, 0);

    installed_area removing_group =
        area(1, "example.com", "plan-1", 1, 0, 1, 0, 0, 0, 0, "");
    areas[0] = removing_group;
    emit("remove_pending", areas, 2, 0);

    installed_area removing_retry_group =
        area(1, "example.com", "plan-1", 1, 0, 1, 0, 1,
             AREA_REASON_ACK_TIMEOUT, 0, "");
    areas[0] = removing_retry_group;
    emit("remove_pending_retry", areas, 2, 0);

    areas[0] = active_group;
    installed_area retry_exc =
        area(2, "b.example.com", NULL, 0, 1, 0, 0, 1,
             AREA_REASON_ACK_TIMEOUT, 0, "ACK не пришёл");
    areas[1] = retry_exc;
    emit("exception_retrying", areas, 2, 0);

    installed_area rejected_exc =
        area(2, "b.example.com", NULL, 0, 1, 0, 1, 1, AREA_REASON_BAD_ARGS, 9,
             "аргументы команды не разобрались");
    areas[0] = active_group;
    areas[1] = rejected_exc;
    emit("exception_rejected", areas, 2, 0);

    setup(1);
    emit("no_area", areas, 0, 0);

    setup(0);
    areas[0] = active_group;
    areas[1] = active_exc;
    emit("plan_unavailable", areas, 2, 0);

    setup(1);
    groups.n_observations = 1;
    areas[0] = active_group;
    areas[1] = active_exc;
    emit("no_exceptions", areas, 2, 0);

    printf("]\n");
    return 0;
}
