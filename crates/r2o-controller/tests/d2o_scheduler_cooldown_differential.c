#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

int d2k_hello_ech_offer(const uint8_t *bytes, size_t length, uint8_t *config_id)
{
    (void)bytes;
    (void)length;
    (void)config_id;
    return 0;
}

static int target_blocks(d2k_sched *scheduler, const char *name,
                         uint8_t transport, uint8_t family,
                         const char *ip, uint16_t port, uint8_t signal_code)
{
    int64_t remaining_ms = 0;
    target_cooldown *matched = NULL;
    return cooldown_blocks(scheduler, name, transport, family,
                           ip, port, signal_code,
                           &remaining_ms, &matched);
}

static int challenge_blocks(d2k_sched *scheduler, const char *name,
                            uint8_t transport, uint8_t family)
{
    return target_blocks(scheduler, name, transport, family,
                         "192.0.2.10", 443, D2K_SUSPECT_SILENT);
}

int main(void)
{
    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    if (!scheduler) return 6;
    scheduler->now_ms = 100;

    task tcp_challenge = {0};
    snprintf(tcp_challenge.name, sizeof tcp_challenge.name, "%s", "challenge.example");
    tcp_challenge.transport = 6;
    tcp_challenge.family = 4;
    tcp_challenge.trigger_code = D2K_SUSPECT_RST;
    cooldown_record(scheduler, &tcp_challenge, 1);

    printf("tcp4 %d\n", challenge_blocks(scheduler, "challenge.example", 6, 4));
    printf("quic4_after_tcp %d\n", challenge_blocks(scheduler, "challenge.example", 17, 4));
    printf("tcp6_after_tcp4 %d\n", challenge_blocks(scheduler, "challenge.example", 6, 6));

    task quic_challenge = {0};
    snprintf(quic_challenge.name, sizeof quic_challenge.name, "%s", "challenge.example");
    quic_challenge.transport = 17;
    quic_challenge.family = 4;
    quic_challenge.trigger_code = D2K_SUSPECT_RST;
    cooldown_record(scheduler, &quic_challenge, 1);

    printf("quic4 %d\n", challenge_blocks(scheduler, "challenge.example", 17, 4));
    printf("tcp4_after_quic %d\n", challenge_blocks(scheduler, "challenge.example", 6, 4));

    task direct_clear = {0};
    snprintf(direct_clear.name, sizeof direct_clear.name, "%s", "clear.example");
    snprintf(direct_clear.ip, sizeof direct_clear.ip, "%s", "192.0.2.20");
    direct_clear.port = 443;
    direct_clear.transport = 6;
    direct_clear.family = 4;
    direct_clear.trigger_code = D2K_SUSPECT_RST;
    cooldown_record(scheduler, &direct_clear, 0);

    printf("clear_same %d\n", target_blocks(scheduler, "clear.example", 6, 4,
                                               "192.0.2.20", 443, D2K_SUSPECT_RST));
    printf("clear_other %d\n", target_blocks(scheduler, "clear.example", 6, 4,
                                                "192.0.2.20", 443, D2K_SUSPECT_SILENT));
    /* An admitted different signal that expires before completion leaves the old CLEAR cooldown intact. */
    printf("clear_same_after_expiry %d\n", target_blocks(scheduler, "clear.example", 6, 4,
                                                           "192.0.2.20", 443, D2K_SUSPECT_RST));

    task late_only = direct_clear;
    late_only.trigger_code = D2K_SUSPECT_RST_AFTER_APP;
    cooldown_record(scheduler, &late_only, 3);
    printf("late_only_ordinary %d\n", target_blocks(scheduler, "clear.example", 6, 4,
                                                       "192.0.2.20", 443, D2K_SUSPECT_RST));
    printf("late_only_trigger %d\n", target_blocks(scheduler, "clear.example", 6, 4,
                                                     "192.0.2.20", 443, D2K_SUSPECT_RST_AFTER_APP));

    task exhausted = {0};
    snprintf(exhausted.name, sizeof exhausted.name, "%s", "exhausted.example");
    snprintf(exhausted.ip, sizeof exhausted.ip, "%s", "192.0.2.21");
    exhausted.port = 443;
    exhausted.transport = 6;
    exhausted.family = 4;
    exhausted.trigger_code = D2K_SUSPECT_RST;
    cooldown_record(scheduler, &exhausted, 2);
    exhausted.trigger_code = D2K_SUSPECT_RST_AFTER_APP;
    cooldown_record(scheduler, &exhausted, 3);
    printf("late_only_preserves_exhausted %d\n", target_blocks(scheduler, "exhausted.example", 6, 4,
                                                                 "192.0.2.21", 443, D2K_SUSPECT_RST));
    free(scheduler);
    return 0;
}
