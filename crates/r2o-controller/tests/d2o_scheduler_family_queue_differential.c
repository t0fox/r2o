#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static const char family_plan_text[] =
    "r2o-plan 1 11\n"
    "id 00000000000000000000000000000000\n"
    "proto tcp tls\n"
    "split sni_middle +0\n";

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    FILE *fixture = fopen(argv[1], "r");
    if (!fixture) return 2;

    char line[512];
    unsigned cases = 0;
    while (fgets(line, sizeof line, fixture)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char case_name[64], expected[16], exact_binding_text[8], extra;
        unsigned long long queued_event, confirmed_event;
        if (sscanf(line, "%63s %15s %llu %llu %7s %c", case_name, expected,
                   &queued_event, &confirmed_event, exact_binding_text, &extra) != 5 ||
            (strcmp(expected, "queued") && strcmp(expected, "removed")) ||
            (strcmp(exact_binding_text, "yes") && strcmp(exact_binding_text, "no"))) {
            fclose(fixture);
            return 3;
        }

        d2k_group_state groups = {0};
        groups.n_groups = 1;
        d2k_domain_group *group = &groups.groups[0];
        strcpy(group->suffix, "googlevideo.com");
        strcpy(group->plan_id, "plan-1");
        group->key.transport = 6;
        group->key.family = 4;
        group->key.shape = D2K_SHAPE_MODERN;
        strcpy(group->key.probe_path, "/");
        group->evidence_count = 3;

        d2k_cat_plan plan = {0};
        strcpy(plan.id, "plan-1");
        strcpy(plan.proto, "tls");
        plan.text = (char *)family_plan_text;
        plan.enabled = 1;

        d2k_cat_binding binding = {0};
        strcpy(binding.kind, "name");
        strcpy(binding.target, "video.googlevideo.com");
        strcpy(binding.plan_id, "plan-1");
        binding.level = 3;
        binding.enabled = strcmp(exact_binding_text, "yes") == 0;
        binding.transport = 6;
        binding.family = 4;
        binding.shape = D2K_SHAPE_MODERN;

        d2k_cat_box box = {0};
        strcpy(box.id, "box-1");
        box.plans = &plan;
        box.n_plans = 1;
        box.binds = &binding;
        box.n_binds = binding.enabled ? 1 : 0;

        d2k_catalog catalog = {0};
        catalog.groups = &groups;
        catalog.boxes = &box;
        catalog.n_boxes = 1;

        d2k_sched *scheduler = d2k_sched_new(&catalog, -1, 0);
        if (!scheduler) {
            fclose(fixture);
            return 6;
        }
        scheduler->areas = calloc(D2K_GROUP_MAX + D2K_GROUP_OBSERVATION_MAX,
                                  sizeof *scheduler->areas);
        if (!scheduler->areas) {
            d2k_sched_free(scheduler);
            fclose(fixture);
            return 6;
        }
        scheduler->n_areas = 1;
        installed_area *area = &scheduler->areas[0];
        strcpy(area->name, group->suffix);
        strcpy(area->plan_id, group->plan_id);
        area->kind = 1;
        area->transport = group->key.transport;
        area->family = group->key.family;
        area->shape = group->key.shape;
        area->confirmed = 1;
        area->confirmed_event = (uint64_t)confirmed_event;

        task *queued = &scheduler->tasks[0];
        queued->state = T_QUEUED;
        strcpy(queued->name, "video.googlevideo.com");
        queued->transport = 6;
        queued->family = 4;
        queued->trigger_shape = D2K_SHAPE_MODERN;
        queued->trigger_planned = D2K_LINK_PLANNED_NO;
        queued->queued_ms = 1;
        queued->queued_event = (uint64_t)queued_event;

        (void)d2k_sched_tick(scheduler, 1001);
        const char *actual = queued->state == T_FREE ? "removed" : "queued";
        if (strcmp(actual, expected)) {
            fprintf(stderr, "%s: d2o selected %s, expected %s\n", case_name,
                    actual, expected);
            d2k_sched_free(scheduler);
            fclose(fixture);
            return 4;
        }
        printf("%s %s\n", case_name, actual);
        d2k_sched_free(scheduler);
        cases++;
    }
    fclose(fixture);
    return cases == 3 ? 0 : 5;
}
