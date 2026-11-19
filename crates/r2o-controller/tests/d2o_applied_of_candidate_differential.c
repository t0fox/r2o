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

static task probe_task;
static d2k_ev event;

static void reset(void)
{
    memset(&probe_task, 0, sizeof probe_task);
    memset(&event, 0, sizeof event);
    probe_task.family = 4;
    probe_task.transport = 6;
    probe_task.port = 443;
    snprintf(probe_task.ip, sizeof probe_task.ip, "%s", "198.51.100.2");
    memset(probe_task.ver_plan_id, 7, sizeof probe_task.ver_plan_id);
    memset(probe_task.addr_probe_trial_id, 8, sizeof probe_task.addr_probe_trial_id);
    event.family = 4;
    event.transport = 6;
    event.low_port = 45000;
    event.high_port = 443;
    event.low_ip[0] = 192;
    event.low_ip[1] = 0;
    event.low_ip[2] = 2;
    event.low_ip[3] = 1;
    event.high_ip[0] = 198;
    event.high_ip[1] = 51;
    event.high_ip[2] = 100;
    event.high_ip[3] = 2;
    memset(event.plan_id, 7, sizeof event.plan_id);
    memset(event.trial_id, 8, sizeof event.trial_id);
}

static void run(const char *label)
{
    printf("%s=%d\n", label, applied_of_candidate(&probe_task, &event));
}

int main(void)
{
    reset();
    run("name_match");
    event.plan_id[0] = 9;
    run("wrong_plan");
    reset();
    event.family = 6;
    run("wrong_family");
    reset();
    event.family = 0;
    run("zero_family");
    reset();
    event.low_ip[3] = 3;
    event.high_ip[3] = 3;
    run("wrong_endpoint");
    reset();
    probe_task.by_addr = 1;
    run("addr_match");
    reset();
    probe_task.by_addr = 1;
    event.trial_id[0] = 9;
    run("addr_wrong_trial");
    return 0;
}
