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
static d2k_cat_box boxes[2];
static d2k_cat_binding binds[2];

static void run(const char *label, const char *name, uint8_t transport, uint8_t family)
{
    const d2k_cat_binding *binding = binding_for(&scheduler, name, transport, family);
    if (!binding) {
        printf("%s=none\n", label);
        return;
    }
    printf("%s=%s:%s:%u:%u\n", label, binding->target, binding->plan_id,
           (unsigned)binding->input, (unsigned)binding->shape);
}

int main(void)
{
    memset(&scheduler, 0, sizeof scheduler);
    memset(&catalog, 0, sizeof catalog);
    memset(boxes, 0, sizeof boxes);
    memset(binds, 0, sizeof binds);
    scheduler.cat = &catalog;
    catalog.boxes = boxes;
    catalog.n_boxes = 2;
    snprintf(boxes[0].id, sizeof boxes[0].id, "%s", "box-a");
    boxes[0].binds = &binds[0];
    boxes[0].n_binds = 1;
    snprintf(binds[0].kind, sizeof binds[0].kind, "%s", "name");
    snprintf(binds[0].target, sizeof binds[0].target, "%s", "alpha.example");
    snprintf(binds[0].plan_id, sizeof binds[0].plan_id, "%s", "plan-a");
    binds[0].transport = 0;
    binds[0].family = 0;
    binds[0].input = 2;
    binds[0].shape = 8;
    snprintf(boxes[1].id, sizeof boxes[1].id, "%s", "box-b");
    boxes[1].binds = &binds[1];
    boxes[1].n_binds = 1;
    snprintf(binds[1].kind, sizeof binds[1].kind, "%s", "name");
    snprintf(binds[1].target, sizeof binds[1].target, "%s", "alpha.example");
    snprintf(binds[1].plan_id, sizeof binds[1].plan_id, "%s", "plan-b");
    binds[1].transport = 6;
    binds[1].family = 4;
    binds[1].input = 1;
    binds[1].shape = 1;

    run("tcp4", "alpha.example", 6, 4);
    run("quic4", "alpha.example", 17, 4);
    run("tcp6", "alpha.example", 6, 6);
    run("other", "beta.example", 6, 4);
    return 0;
}
