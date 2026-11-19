#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "sched.c"

static d2k_sched scheduler;
static d2k_catalog catalog;

static void run_case(const char *label, uint8_t budget, int conn_close)
{
    task probe_task;
    memset(&probe_task, 0, sizeof probe_task);
    snprintf(probe_task.name, sizeof probe_task.name, "%s", "ladder.example");
    snprintf(probe_task.ip, sizeof probe_task.ip, "%s", "198.51.100.20");
    probe_task.transport = 6;
    probe_task.family = 4;
    probe_task.port = 443;
    probe_task.state = T_VERIFY;
    probe_task.partial_finishing = 0;
    probe_task.vol.verdict = D2K_VOL_CUT;
    probe_task.vol.rx_cut = 0;
    probe_task.vol.at_kb = 15;
    probe_task.ver.status = 200;
    probe_task.ver.budget = budget;
    probe_task.ver.conn_close = conn_close;
    snprintf(probe_task.ver.budget_note, sizeof probe_task.ver.budget_note,
             "%s", "fixture");
    snprintf(probe_task.net_probe_name[0], sizeof probe_task.net_probe_name[0],
             "%s", "ladder.example");
    snprintf(probe_task.plans[0], sizeof probe_task.plans[0], "%s",
             "d2k-plan 1 11\nid 00000000000000000000000000000000\n"
             "proto tcp tls\nsplit sni_middle +0\n");
    probe_task.n_plans = 1;
    probe_task.next_plan = 1;
    memset(probe_task.ver_plan_id, 0, sizeof probe_task.ver_plan_id);
    probe_task.trial_installed = 0;
    probe_task.probe_fd = -1;
    probe_task.prop_bound_fd = -1;
    verify_confirm(&scheduler, &probe_task, scheduler.now_ms);
    printf("case=%s ladder=%d\n", label, probe_task.ladder_unmeasurable);
}

int main(void)
{
    memset(&scheduler, 0, sizeof scheduler);
    memset(&catalog, 0, sizeof catalog);
    scheduler.cat = &catalog;
    scheduler.now_ms = 100000;
    scheduler.clock_seen = 1;
    scheduler.wake[0] = -1;
    scheduler.wake[1] = -1;
    scheduler.link_fd = -1;
    run_case("not_applicable", D2K_BUDGET_NOT_APPLICABLE, 0);
    run_case("cut", D2K_BUDGET_CUT, 0);
    run_case("unchecked_closed", D2K_BUDGET_NOT_CHECKED, 1);
    return 0;
}
