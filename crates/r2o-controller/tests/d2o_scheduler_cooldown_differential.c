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

static int challenge_blocks(d2k_sched *scheduler, const char *name,
                            uint8_t transport, uint8_t family)
{
    int64_t remaining_ms = 0;
    target_cooldown *matched = NULL;
    return cooldown_blocks(scheduler, name, transport, family,
                           "192.0.2.10", 443, D2K_SUSPECT_SILENT,
                           &remaining_ms, &matched);
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
    free(scheduler);
    return 0;
}
