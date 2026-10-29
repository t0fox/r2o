#include <stdio.h>
#include <string.h>

#include "d2k_detect.h"
#include "d2k_verdict.h"
#include "d2k_sched.h"

static unsigned long raw_dials;

unsigned long d2k_raw_dial_count(void) { return raw_dials; }
unsigned long d2k_raw_rst_fail_count(void) { return 0; }

void d2k_sched_progress_note(const char *question, int pass, int fail)
{
    (void)question;
    (void)pass;
    (void)fail;
}

int d2k_arm_from_poison(const d2k_poison *poison, d2k_arm *arm,
                        char *why, size_t why_capacity)
{
    (void)poison;
    (void)arm;
    (void)why;
    (void)why_capacity;
    return -1;
}

void d2k_classify_run(const char *address, const d2k_trigger *trigger,
                      d2k_opts *options, d2k_result *result)
{
    (void)address;
    (void)trigger;
    (void)options;
    memset(result, 0, sizeof(*result));
    result->verdict = D2K_DV_PREFIX;
    result->split_pos = 5;
    result->probes = 17;
    result->raw_dial_base = 0;
}

d2k_vres d2k_detect_sched_tcp(const char *ip, uint16_t port,
                              d2k_hello trigger, d2k_hello control,
                              uint32_t mark, int repeats, uint32_t gap_us,
                              uint32_t wait_ms,
                              const volatile sig_atomic_t *stop);

static d2k_vres bridge_result(void)
{
    static const uint8_t bytes[] = {0x01, 0x02};
    d2k_hello trigger = {bytes, sizeof(bytes), NULL, 0, 0, 0};
    d2k_hello none = {0};
    return d2k_detect_sched_tcp("192.0.2.1", 443, trigger, none,
                                0x2d, 1, 60000, 6000, NULL);
}

int main(void)
{
    d2k_vres socket_only = bridge_result();
    raw_dials = 1;
    d2k_vres raw_split = bridge_result();
    if (socket_only.verdict != D2K_V_FLAKY || socket_only.split_pos != 0 ||
        !socket_only.owns_search || raw_split.verdict != D2K_V_PREFIX ||
        raw_split.split_pos != 5 || raw_split.probes != 17 || !raw_split.owns_search) {
        return 1;
    }
    printf("socket-only=flaky split=0 owns=1\n");
    printf("raw-split=prefix split=5 owns=1\n");
    return 0;
}
