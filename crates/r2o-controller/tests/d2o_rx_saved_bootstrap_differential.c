#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "sched.c"

#define MAX_BOXES 8

static d2k_catalog catalog;
static d2k_cat_box boxes[MAX_BOXES];
static d2k_cat_plan plans[MAX_BOXES];
static d2k_cat_binding bindings[MAX_BOXES];
static char plan_texts[MAX_BOXES][256];
static d2k_sched scheduler;
static task probe_task;

static void add_box(size_t index, const char *id, const char *target,
                    uint8_t family, uint8_t shape, int level, int enabled,
                    int recheck, uint8_t transport, const char *plan_id,
                    int plan_enabled)
{
    d2k_cat_box *box = &boxes[index];
    d2k_cat_plan *plan = &plans[index];
    d2k_cat_binding *binding = &bindings[index];
    memset(box, 0, sizeof *box);
    memset(plan, 0, sizeof *plan);
    memset(binding, 0, sizeof *binding);
    snprintf(box->id, sizeof box->id, "%s", id);
    box->plans = plan;
    box->n_plans = 1;
    box->binds = binding;
    box->n_binds = 1;
    snprintf(plan->id, sizeof plan->id, "%s", plan_id);
    snprintf(plan->proto, sizeof plan->proto, "%s", "tls");
    snprintf(plan_texts[index], sizeof plan_texts[index],
             "d2k-plan 1 11\nid 00000000000000000000000000000000\n"
             "proto tcp tls\nsplit sni_middle +%zu\n", index);
    plan->text = plan_texts[index];
    plan->enabled = plan_enabled;
    snprintf(binding->kind, sizeof binding->kind, "%s", "name");
    snprintf(binding->target, sizeof binding->target, "%s", target);
    snprintf(binding->plan_id, sizeof binding->plan_id, "%s", plan_id);
    binding->family = family;
    binding->shape = shape;
    binding->level = level;
    binding->enabled = enabled;
    binding->recheck_since = recheck;
    binding->transport = transport;
    binding->confirmed = (int64_t)index + 1;
}

static void run(const char *label, uint8_t family, int allow_other_family)
{
    memset(&probe_task, 0, sizeof probe_task);
    snprintf(probe_task.name, sizeof probe_task.name, "%s", "boot.example");
    snprintf(probe_task.ip, sizeof probe_task.ip, "%s", "198.51.100.20");
    probe_task.transport = 6;
    probe_task.family = family;
    probe_task.port = 443;
    probe_task.by_addr = 0;
    size_t len = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, probe_task.name,
                               probe_task.trig, sizeof probe_task.trig, &len) != 0) {
        fprintf(stderr, "hello fixture failed\n");
        return;
    }
    probe_task.trig_len = len;
    int found = rx_saved_bootstrap(&scheduler, &probe_task, allow_other_family);
    if (!found) {
        printf("case=%s found=0 plans=0\n", label);
        return;
    }
    char text[512];
    size_t out = 0;
    for (size_t i = 0; probe_task.plans[0][i] && out + 1 < sizeof text; i++) {
        char byte = probe_task.plans[0][i];
        text[out++] = byte == '\n' ? ';' : byte;
    }
    text[out] = '\0';
    printf("case=%s found=1 plans=%zu plan=%s\n", label,
           probe_task.n_plans, text);
}

int main(void)
{
    memset(&scheduler, 0, sizeof scheduler);
    memset(&catalog, 0, sizeof catalog);
    scheduler.cat = &catalog;
    memset(boxes, 0, sizeof boxes);
    memset(plans, 0, sizeof plans);
    memset(bindings, 0, sizeof bindings);
    memset(plan_texts, 0, sizeof plan_texts);
    catalog.boxes = boxes;

    add_box(0, "box-a", "boot.example", 4, D2K_SHAPE_MODERN, 3, 1, 0, 6,
            "plan-a", 1);
    add_box(1, "box-b", "boot.example", 4, D2K_SHAPE_MODERN, 3, 1, 0, 6,
            "plan-b", 1);
    bindings[1].confirmed = 20;
    catalog.n_boxes = 2;

    run("same_family_best", 4, 0);

    add_box(2, "box-c", "boot.example", 6, D2K_SHAPE_MODERN, 3, 1, 0, 6,
            "plan-c", 1);
    bindings[2].confirmed = 99;
    catalog.n_boxes = 3;
    run("exact_family_wins", 4, 0);

    catalog.n_boxes = 1;
    bindings[0].family = 6;
    run("other_family_denied", 4, 0);
    run("other_family_allowed", 4, 1);
    bindings[0].family = 4;

    bindings[0].level = 2;
    run("weak_level", 4, 0);
    bindings[0].level = 3;

    bindings[0].recheck_since = 1;
    run("recheck", 4, 0);
    bindings[0].recheck_since = 0;

    bindings[0].shape = D2K_SHAPE_LEGACY;
    run("wrong_shape", 4, 0);
    bindings[0].shape = D2K_SHAPE_MODERN;

    bindings[0].transport = 17;
    run("quic_transport", 4, 0);
    bindings[0].transport = 6;

    plans[0].enabled = 0;
    run("disabled_plan", 4, 0);
    plans[0].enabled = 1;

    return 0;
}
