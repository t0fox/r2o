#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "d2k_nat.h"
#include "d2k_plan.h"
#include "d2k_session.h"

static int nat4_identity(const char *path, uint8_t proto, uint32_t src,
    uint16_t sport, uint32_t dst, uint16_t dport, uint32_t *outside,
    uint16_t *outside_port) {
    (void)path; (void)dst; (void)dport;
    if (proto != 17) return -1;
    *outside = src; *outside_port = sport;
    return 0;
}

static int nat6_identity(const char *path, uint8_t proto, const uint8_t *src,
    uint16_t sport, const uint8_t *dst, uint16_t dport, uint8_t family,
    uint8_t *outside, uint16_t *outside_port) {
    (void)path; (void)dst; (void)dport;
    if (proto != 17 || family != 6) return -1;
    for (size_t i = 0; i < 16; i++) outside[i] = src[i];
    *outside_port = sport;
    return 0;
}

static int put_u32(uint32_t value) {
    const uint8_t bytes[4] = {
        (uint8_t)(value >> 24), (uint8_t)(value >> 16),
        (uint8_t)(value >> 8), (uint8_t)value,
    };
    return fwrite(bytes, 1, sizeof bytes, stdout) == sizeof bytes ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char *end = NULL;
    long shape = strtol(argv[1], &end, 10);
    if (!end || *end || shape < 1 || shape > 4) return 2;

    uint8_t packet[65536];
    /* Match d2kd.c OUT_BUF (D2K_WIRE_BATCH_MAX * MAX_PKT). */
    uint8_t output[D2K_WIRE_BATCH_MAX * 1600u];
    size_t packet_len = fread(packet, 1, sizeof packet, stdin);
    if (ferror(stdin) || packet_len < 20) return 3;

    uint8_t plan_bytes[] = {
        'D','2','K','P',0,1,0,7,0,0,0,2,
        0,2,0,2,17,2,1,12,0,1,(uint8_t)shape,
    };
    d2k_plan *plan = NULL;
    char error[160];
    if (d2k_plan_load(plan_bytes, sizeof plan_bytes, &plan, error, sizeof error) != 0) {
        fprintf(stderr, "plan load: %s\n", error);
        return 4;
    }
    d2k_session *session = d2k_session_new(16, 16);
    if (!session) { d2k_plan_free(plan); return 5; }
    d2k_session_set_plan(session, plan);

    d2k_nat_fn saved_nat4 = d2k_nat_hook;
    d2k_nat_family_fn saved_nat6 = d2k_nat_family_hook;
    uint8_t family = packet[0] >> 4;
    if (family == 4) d2k_nat_hook = nat4_identity;
    if (family == 6) d2k_nat_family_hook = nat6_identity;

    d2k_result result;
    (void)d2k_session_packet(session, packet, packet_len, 1, output,
                             sizeof output, &result);
    d2k_nat_hook = saved_nat4;
    d2k_nat_family_hook = saved_nat6;
    d2k_session_free(session);

    if (result.n_out > UINT8_MAX) return 6;
    const uint8_t header[] = {
        (uint8_t)result.applied, (uint8_t)result.verdict,
        (uint8_t)result.n_out, result.applied ? result.first_payload : UINT8_MAX,
    };
    if (fwrite(header, 1, sizeof header, stdout) != sizeof header) return 7;
    for (size_t i = 0; i < result.n_out; i++) {
        if (result.out[i].off > sizeof output ||
            result.out[i].len > sizeof output - result.out[i].off ||
            put_u32((uint32_t)result.out[i].len) != 0 ||
            put_u32(result.out[i].delay_us) != 0)
            return 8;
        uint8_t *packet = output + result.out[i].off;
        if (family == 4) {
            packet[4] = packet[5] = packet[10] = packet[11] = 0;
        } else if (family == 6) {
            packet[44] = packet[45] = packet[46] = packet[47] = 0;
        } else {
            return 8;
        }
        if (fwrite(packet, 1, result.out[i].len, stdout) != result.out[i].len) return 8;
    }
    return ferror(stdout) ? 9 : 0;
}
