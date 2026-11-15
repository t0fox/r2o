/* C/Rust differential: production `verdict_to_plans` для TCP-вердиктов.
 *
 * Сценарии: CLEAR/UNREACHABLE/ADDRESS/RESPONSE/NO_QUIC/LOCAL_ADDRESS (нет
 * кандидатов), PREFIX/WHOLE (измеренный split), OPAQUE+owns_search (запасной
 * перебор). Порядок и тексты планов сравниваются с Rust production-хелперами
 * `r2o_discovery_measured_split_plan` и `r2o_fallback::FallbackQueue`.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static void print_hex(const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
}

static void scenario(const char *label, d2k_verdict verdict, int owns_search,
                     int split_pos, int have_arm, int trig_len)
{
    /* d2k_sched/task слишком велики для стека: calloc, как в test_sched. */
    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    task *target = calloc(1, sizeof *target);
    d2k_vres *result = calloc(1, sizeof *result);
    if (!scheduler || !target || !result) {
        printf("%s\talloc-failed\n", label);
        free(scheduler); free(target); free(result);
        return;
    }
    scheduler->send_cap = 0;
    snprintf(target->name, sizeof target->name, "verdict.example");
    target->transport = 6;
    target->family = 4;
    target->trig_len = (size_t)trig_len;
    target->state = T_ASKING;
    result->verdict = verdict;
    result->owns_search = owns_search;
    result->split_pos = split_pos;
    result->have_arm = have_arm;
    result->split_gap_us = 20000;
    verdict_to_plans(scheduler, target, result);
    for (size_t i = 0; i < target->n_plans; i++) {
        if (!strncmp(target->plans[i], "d2k-plan", 8)) {
            memcpy(target->plans[i], "r2o-plan", 8);
        }
    }
    printf("%s\tn=%zu\tbox=%s\thash=%llu\tpath=%s\tstall=%d\trx_pending=%d\n",
           label, target->n_plans, target->box_id,
           (unsigned long long)target->arm_hash, target->arm_path,
           target->stall_cut, target->rx_volume_candidate_pending);
    for (size_t i = 0; i < target->n_plans; i++) {
        printf("%s\tplan=%zu\tbox=%s\tnet=%s\t", label, i, target->plan_boxes[i],
               target->net_probe_name[i]);
        print_hex((const uint8_t *)target->plans[i], strlen(target->plans[i]));
        printf("\n");
    }
    free(scheduler); free(target); free(result);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    scenario("clear", D2K_V_CLEAR, 0, 0, 0, 16);
    scenario("unreachable", D2K_V_UNREACHABLE, 0, 0, 0, 16);
    scenario("address", D2K_V_ADDRESS, 0, 0, 0, 16);
    scenario("response", D2K_V_RESPONSE, 0, 0, 0, 16);
    scenario("no_quic", D2K_V_NO_QUIC, 0, 0, 0, 16);
    scenario("local_address", D2K_V_LOCAL_ADDRESS, 0, 0, 0, 16);
    scenario("prefix", D2K_V_PREFIX, 1, 7, 0, 16);
    scenario("whole", D2K_V_WHOLE, 1, 7, 0, 16);
    scenario("opaque_fallback", D2K_V_OPAQUE, 1, 0, 0, 0);
    return 0;
}
