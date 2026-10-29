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

static int ech_witness_proof(int status, d2k_ver_level level,
                             int ech_accepted, int name_ok, int body_complete)
{
    task candidate = {0};
    snprintf(candidate.name, sizeof candidate.name, "%s", "ech-exhausted.example");
    snprintf(candidate.ech_origin, sizeof candidate.ech_origin, "%s", "witness.example");
    candidate.transport = 6;
    candidate.ech_offer = 1;
    candidate.ver.ech_accepted = ech_accepted;
    candidate.ver.name_ok = name_ok;
    candidate.ver.body_complete = body_complete;
    candidate.ver.status = status;
    candidate.ver.level = level;
    return ech_witness_transport_proof(&candidate);
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
    printf("late_only_other_endpoint %d\n", target_blocks(scheduler, "clear.example", 6, 4,
                                                            "192.0.2.22", 443, D2K_SUSPECT_RST_AFTER_APP));

    task ech_witness_exhausted = {0};
    snprintf(ech_witness_exhausted.name, sizeof ech_witness_exhausted.name,
             "%s", "ech-exhausted.example");
    snprintf(ech_witness_exhausted.ip, sizeof ech_witness_exhausted.ip,
             "%s", "192.0.2.23");
    ech_witness_exhausted.port = 443;
    ech_witness_exhausted.transport = 6;
    ech_witness_exhausted.family = 4;
    ech_witness_exhausted.ech_offer = 1;
    ech_witness_exhausted.trigger_code = D2K_SUSPECT_RST_AFTER_APP;
    /* ECH witness exhaustion reaches cooldown_record(..., 3) in the donor. */
    cooldown_record(scheduler, &ech_witness_exhausted, 3);
    printf("ech_exhausted_ordinary %d\n", target_blocks(scheduler, "ech-exhausted.example", 6, 4,
                                                          "192.0.2.23", 443, D2K_SUSPECT_RST));
    printf("ech_exhausted_late %d\n", target_blocks(scheduler, "ech-exhausted.example", 6, 4,
                                                      "192.0.2.23", 443, D2K_SUSPECT_RST_AFTER_APP));
    printf("ech_witness_proof_accepted %d\n", ech_witness_proof(403, D2K_VER_CHALLENGE, 1, 1, 1));
    printf("ech_witness_proof_rate_limit %d\n", ech_witness_proof(429, D2K_VER_CHALLENGE, 1, 1, 1));
    printf("ech_witness_proof_rate_limit_blocked %d\n", ech_witness_proof(429, D2K_VER_BLOCKPAGE, 1, 1, 1));
    printf("ech_witness_proof_rate_limit_denied %d\n", ech_witness_proof(429, D2K_VER_DENIED, 1, 1, 1));
    printf("ech_witness_proof_missing_acceptance %d\n", ech_witness_proof(403, D2K_VER_CHALLENGE, 0, 1, 1));
    printf("ech_witness_proof_wrong_name %d\n", ech_witness_proof(403, D2K_VER_CHALLENGE, 1, 0, 1));
    printf("ech_witness_proof_incomplete %d\n", ech_witness_proof(403, D2K_VER_CHALLENGE, 1, 1, 0));

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
    printf("late_only_preserves_exhausted_trigger %d\n",
           target_blocks(scheduler, "exhausted.example", 6, 4,
                         "192.0.2.21", 443, D2K_SUSPECT_RST_AFTER_APP));
    free(scheduler);

    d2k_sched *ring = calloc(1, sizeof *ring);
    if (!ring) return 7;
    for (unsigned index = 0; index < SCHED_COOLDOWN_SLOTS; index++) {
        task endpoint = {0};
        snprintf(endpoint.name, sizeof endpoint.name, "ring-%03u.example", index);
        snprintf(endpoint.ip, sizeof endpoint.ip, "192.0.2.%u", index + 1);
        endpoint.port = 443;
        endpoint.transport = 6;
        endpoint.family = 4;
        endpoint.trigger_code = D2K_SUSPECT_RST;
        ring->now_ms = 1000 + (int64_t)index;
        cooldown_record(ring, &endpoint, 2);
    }
    ring->now_ms = 2000;
    task challenge = {0};
    snprintf(challenge.name, sizeof challenge.name, "%s", "ring-challenge.example");
    challenge.transport = 6;
    challenge.family = 4;
    challenge.trigger_code = D2K_SUSPECT_RST;
    cooldown_record(ring, &challenge, 1);
    printf("ring_evicted_earliest_endpoint %d\n",
           cooldown_find_endpoint(ring, "ring-000.example", 6, 4,
                                  "192.0.2.1", 443) == NULL);
    printf("ring_kept_next_endpoint %d\n",
           cooldown_find_endpoint(ring, "ring-001.example", 6, 4,
                                  "192.0.2.2", 443) != NULL);
    printf("ring_kept_challenge %d\n",
           cooldown_find_challenge(ring, "ring-challenge.example", 6, 4) != NULL);
    free(ring);

    d2k_sched *expired_ring = calloc(1, sizeof *expired_ring);
    if (!expired_ring) return 8;
    task expired = {0};
    snprintf(expired.name, sizeof expired.name, "%s", "ring-expired.example");
    snprintf(expired.ip, sizeof expired.ip, "%s", "192.0.2.150");
    expired.port = 443;
    expired.transport = 6;
    expired.family = 4;
    expired.trigger_code = D2K_SUSPECT_RST;
    expired_ring->now_ms = 1000;
    cooldown_record(expired_ring, &expired, 2);
    expired_ring->now_ms = 601001;
    for (unsigned index = 0; index < SCHED_COOLDOWN_SLOTS - 1; index++) {
        task challenge_slot = {0};
        snprintf(challenge_slot.name, sizeof challenge_slot.name,
                 "ring-live-challenge-%03u.example", index);
        challenge_slot.transport = 6;
        challenge_slot.family = 4;
        challenge_slot.trigger_code = D2K_SUSPECT_RST;
        cooldown_record(expired_ring, &challenge_slot, 1);
    }
    task replacement = {0};
    snprintf(replacement.name, sizeof replacement.name, "%s", "ring-replacement.example");
    snprintf(replacement.ip, sizeof replacement.ip, "%s", "192.0.2.151");
    replacement.port = 443;
    replacement.transport = 6;
    replacement.family = 4;
    replacement.trigger_code = D2K_SUSPECT_RST;
    cooldown_record(expired_ring, &replacement, 2);
    printf("ring_prefers_expired_over_active_challenges %d\n",
           cooldown_find_endpoint(expired_ring, "ring-expired.example", 6, 4,
                                  "192.0.2.150", 443) == NULL);
    printf("ring_keeps_active_challenge %d\n",
           cooldown_find_challenge(expired_ring, "ring-live-challenge-000.example", 6, 4) != NULL);
    free(expired_ring);

    d2k_sched *challenge_ring = calloc(1, sizeof *challenge_ring);
    if (!challenge_ring) return 9;
    for (unsigned index = 0; index < SCHED_COOLDOWN_SLOTS; index++) {
        task challenge_slot = {0};
        snprintf(challenge_slot.name, sizeof challenge_slot.name,
                 "ring-challenge-only-%03u.example", index);
        challenge_slot.transport = 6;
        challenge_slot.family = 4;
        challenge_slot.trigger_code = D2K_SUSPECT_RST;
        challenge_ring->now_ms = 1000 + (int64_t)index;
        cooldown_record(challenge_ring, &challenge_slot, 1);
    }
    challenge_ring->now_ms = 2000;
    task last_challenge = {0};
    snprintf(last_challenge.name, sizeof last_challenge.name, "%s", "ring-challenge-only-new.example");
    last_challenge.transport = 6;
    last_challenge.family = 4;
    last_challenge.trigger_code = D2K_SUSPECT_RST;
    cooldown_record(challenge_ring, &last_challenge, 1);
    printf("ring_all_challenges_evicts_earliest %d\n",
           cooldown_find_challenge(challenge_ring, "ring-challenge-only-000.example", 6, 4) == NULL);
    printf("ring_all_challenges_keeps_next %d\n",
           cooldown_find_challenge(challenge_ring, "ring-challenge-only-001.example", 6, 4) != NULL);
    printf("ring_all_challenges_keeps_new %d\n",
           cooldown_find_challenge(challenge_ring, "ring-challenge-only-new.example", 6, 4) != NULL);
    free(challenge_ring);

    d2k_sched *challenge_wins = calloc(1, sizeof *challenge_wins);
    if (!challenge_wins) return 10;
    challenge_wins->now_ms = 1000;
    task busy_endpoint = {0};
    snprintf(busy_endpoint.name, sizeof busy_endpoint.name, "%s", "challenge-wins.example");
    snprintf(busy_endpoint.ip, sizeof busy_endpoint.ip, "%s", "192.0.2.180");
    busy_endpoint.port = 443;
    busy_endpoint.transport = 6;
    busy_endpoint.family = 4;
    busy_endpoint.trigger_code = D2K_SUSPECT_RST;
    cooldown_record(challenge_wins, &busy_endpoint, 1);
    cooldown_record(challenge_wins, &busy_endpoint, 2);
    printf("active_challenge_suppresses_endpoint_cooldown %d\n",
           cooldown_find_endpoint(challenge_wins, "challenge-wins.example", 6, 4,
                                  "192.0.2.180", 443) == NULL);
    printf("active_challenge_stays_recorded %d\n",
           cooldown_find_challenge(challenge_wins, "challenge-wins.example", 6, 4) != NULL);
    free(challenge_wins);

    d2k_sched *ech_challenges = calloc(1, sizeof *ech_challenges);
    if (!ech_challenges) return 11;
    ech_challenges->now_ms = 1000;
    for (unsigned index = 0; index < 8; index++) {
        char name[64];
        snprintf(name, sizeof name, "ech-witness-%03u.example", index);
        ech_chal_add(ech_challenges, name);
    }
    /* Re-recording an active name does not advance the donor's ring cursor. */
    ech_chal_add(ech_challenges, "ech-witness-000.example");
    ech_chal_add(ech_challenges, "ech-witness-new.example");
    printf("ech_ring_evicts_oldest %d\n",
           !ech_chal_has(ech_challenges, "ech-witness-000.example"));
    printf("ech_ring_keeps_next %d\n",
           ech_chal_has(ech_challenges, "ech-witness-001.example"));
    printf("ech_ring_keeps_new %d\n",
           ech_chal_has(ech_challenges, "ech-witness-new.example"));
    ech_challenges->now_ms += 1800000;
    printf("ech_ring_expires_at_deadline %d\n",
           ech_chal_has(ech_challenges, "ech-witness-new.example"));
    free(ech_challenges);
    return 0;
}
