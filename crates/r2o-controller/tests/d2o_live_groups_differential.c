/* C/Rust differential: write_live_groups (sched.c).
 * Строит фиксированный каталог/группу/areas и печатает JSON groups.
 * Rust-сторона сравнивает структуру через live::snapshot_with_areas. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static void set_key(d2k_group_key *key) {
    memset(key, 0, sizeof *key);
    key->transport = 6;
    key->family = 4;
    key->shape = 1;
}

int main(void) {
    static d2k_sched s;
    static d2k_catalog cat;
    static d2k_group_state groups;
    static d2k_cat_box box;
    static d2k_cat_plan plan;
    static installed_area areas[2];
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    memset(&groups, 0, sizeof groups);
    memset(&box, 0, sizeof box);
    memset(&plan, 0, sizeof plan);
    memset(areas, 0, sizeof areas);

    strcpy(plan.id, "plan-1");
    strcpy(plan.proto, "tls");
    plan.text = "plan";
    plan.enabled = 1;
    plan.successes = 1;
    box.plans = &plan;
    box.n_plans = 1;

    cat.boxes = &box;
    cat.n_boxes = 1;
    cat.groups = &groups;

    groups.n_groups = 1;
    strcpy(groups.groups[0].suffix, "example.com");
    strcpy(groups.groups[0].plan_id, "plan-1");
    set_key(&groups.groups[0].key);
    groups.groups[0].evidence_count = 1;
    groups.groups[0].at = 1;

    /* 0: обычное доказательство группы. */
    strcpy(groups.observations[0].name, "a.example.com");
    strcpy(groups.observations[0].plan_id, "plan-1");
    set_key(&groups.observations[0].key);
    groups.observations[0].evidence = D2K_GROUP_BLOCKED_CONFIRMED;
    groups.observations[0].at = 1;
    /* 1: DIRECT_CLEAR-исключение. */
    strcpy(groups.observations[1].name, "b.example.com");
    strcpy(groups.observations[1].plan_id, "plan-1");
    set_key(&groups.observations[1].key);
    groups.observations[1].evidence = D2K_GROUP_DIRECT_CLEAR;
    groups.observations[1].at = 2;
    /* 2: сам suffix с BLOCKED — не должен попасть в evidence. */
    strcpy(groups.observations[2].name, "example.com");
    strcpy(groups.observations[2].plan_id, "plan-1");
    set_key(&groups.observations[2].key);
    groups.observations[2].evidence = D2K_GROUP_BLOCKED_CONFIRMED;
    groups.observations[2].at = 3;
    /* 3: PLAN_FAILED другого плана — в exceptions, но не desired. */
    strcpy(groups.observations[3].name, "d.example.com");
    strcpy(groups.observations[3].plan_id, "plan-2");
    set_key(&groups.observations[3].key);
    groups.observations[3].evidence = D2K_GROUP_BLOCKED_CONFIRMED | D2K_GROUP_PLAN_FAILED;
    groups.observations[3].at = 4;
    groups.n_observations = 4;

    areas[0].kind = 1;
    strcpy(areas[0].name, "example.com");
    strcpy(areas[0].plan_id, "plan-1");
    areas[0].transport = 6;
    areas[0].shape = 1;
    areas[0].family = 4;
    areas[0].confirmed = 1;

    areas[1].kind = 2;
    strcpy(areas[1].name, "b.example.com");
    areas[1].transport = 6;
    areas[1].shape = 1;
    areas[1].family = 4;
    areas[1].confirmed = 1;

    s.cat = &cat;
    s.areas = areas;
    s.n_areas = 2;
    s.now_ms = 1000;

    char *buf = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);
    if (!mem) return 1;
    write_live_groups(mem, &s);
    fclose(mem);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == ',' ||
                       buf[len - 1] == ' ')) {
        buf[--len] = '\0';
    }
    printf("{%s}\n", buf);
    free(buf);
    return 0;
}
