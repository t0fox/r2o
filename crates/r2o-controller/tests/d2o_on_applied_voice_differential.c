/* C-оракул production `on_applied` для голосового trial → T_VOICE_WATCH. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static const uint8_t plan_id[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};
static const uint8_t trial_id[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static void scenario(const char *label, int wrong_trial, int wrong_port,
                     int wrong_server, uint8_t transport, uint8_t family)
{
    d2k_sched *s = calloc(1, sizeof *s);
    if (!s) return;
    s->now_ms = 1000;
    task *t = &s->tasks[0];
    t->state = T_VOICE_TRIAL;
    t->transport = 17;
    t->family = 4;
    t->by_addr = 0;
    t->ver_plan_id[0] = plan_id[0];
    memcpy(t->ver_plan_id, plan_id, sizeof plan_id);
    memcpy(t->addr_probe_trial_id, trial_id, sizeof trial_id);
    t->addr_probe_identity_valid = 1;
    t->addr_probe_src_port_be = 0;
    t->addr_probe_dst_port_be = htons(19327);
    memcpy(t->addr_probe_src_ip, (uint8_t[]){192, 0, 2, 10}, 4);
    memcpy(t->addr_probe_dst_ip, (uint8_t[]){198, 51, 100, 20}, 4);
    snprintf(t->name, sizeof t->name, "@discord-voice");
    snprintf(t->ip, sizeof t->ip, "198.51.100.20");

    d2k_ev ev;
    memset(&ev, 0, sizeof ev);
    memcpy(ev.plan_id, plan_id, sizeof plan_id);
    memcpy(ev.trial_id, trial_id, sizeof trial_id);
    if (wrong_trial) ev.trial_id[0] ^= 0xff;
    ev.transport = transport;
    ev.family = family;
    memcpy(ev.low_ip, wrong_server ? (uint8_t[]){203, 0, 113, 20}
                                   : (uint8_t[]){198, 51, 100, 20}, 4);
    ev.low_port = wrong_port ? 19328 : 19327;
    memcpy(ev.high_ip, (uint8_t[]){192, 0, 2, 10}, 4);
    ev.high_port = 41000;

    on_applied(s, &ev);
    printf("%s applied=%d\n", label, t->state == T_VOICE_WATCH ? 1 : 0);
    free(s);
}

int main(void)
{
    scenario("voice_match", 0, 0, 0, 17, 4);
    scenario("voice_wrong_trial", 1, 0, 0, 17, 4);
    scenario("voice_wrong_port", 0, 1, 0, 17, 4);
    scenario("voice_wrong_server", 0, 0, 1, 17, 4);
    scenario("voice_wrong_transport", 0, 0, 0, 6, 4);
    scenario("voice_wrong_family", 0, 0, 0, 17, 6);
    return 0;
}
