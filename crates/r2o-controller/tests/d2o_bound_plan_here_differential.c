#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "sched.c"

int d2k_hello_ech_offer(const uint8_t *bytes, size_t length, uint8_t *config_id)
{
    (void)bytes;
    (void)length;
    (void)config_id;
    return 0;
}

static d2k_sched scheduler;
static d2k_catalog catalog;
static d2k_cat_box box;
static d2k_cat_plan plan;
static d2k_cat_binding binding;
static task probe_task;

static int run_case(const char *label)
{
    char out[40] = "";
    memset(&probe_task, 0, sizeof probe_task);
    probe_task.transport = 17;
    probe_task.family = 4;
    snprintf(probe_task.name, sizeof probe_task.name, "%s", "quic-bound.example");
    snprintf(probe_task.ip, sizeof probe_task.ip, "%s", "198.51.100.11");
    probe_task.port = 443;
    int found = bound_plan_here(&scheduler, &probe_task, D2K_LINK_SHAPE_QUIC, out);
    if (!found) {
        printf("%s=none\n", label);
        return 0;
    }
    printf("%s=%s\n", label, out);
    return 1;
}

int main(void)
{
    memset(&scheduler, 0, sizeof scheduler);
    memset(&catalog, 0, sizeof catalog);
    memset(&box, 0, sizeof box);
    memset(&plan, 0, sizeof plan);
    memset(&binding, 0, sizeof binding);
    scheduler.cat = &catalog;
    catalog.boxes = &box;
    catalog.n_boxes = 1;
    snprintf(box.id, sizeof box.id, "%s", "box");
    box.plans = &plan;
    box.n_plans = 1;
    box.binds = &binding;
    box.n_binds = 1;
    snprintf(plan.id, sizeof plan.id, "%s", "plan");
    snprintf(plan.proto, sizeof plan.proto, "%s", "quic");
    plan.text = "r2o-plan 1 10 proto udp quic";
    plan.enabled = 1;
    snprintf(binding.kind, sizeof binding.kind, "%s", "name");
    snprintf(binding.target, sizeof binding.target, "%s", "quic-bound.example");
    snprintf(binding.plan_id, sizeof binding.plan_id, "%s", "plan");
    binding.level = 3;
    binding.enabled = 1;
    binding.transport = 17;
    binding.family = 4;
    binding.shape = D2K_LINK_SHAPE_QUIC;
    binding.verified_by = D2K_VERBY_PROBE;
    run_case("probe");
    binding.verified_by = D2K_VERBY_CLIENT;
    run_case("client_verified");
    return 0;
}
