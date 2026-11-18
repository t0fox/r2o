/* C-оракул: production `reason_set`/`reason_append`/`budget_left`/`qp_outcome`
 * (core/quicprobe.c). Включаем TU, чтобы дотянуться до static. */
#include "quicprobe.c"

#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *bytes, size_t n)
{
    for (size_t index = 0; index < n; index++) {
        printf("%02x", bytes[index]);
    }
}

static void dump_reason(const char *label, const d2k_vres *r)
{
    printf("%s,%zu,", label, strlen(r->reason));
    print_hex((const uint8_t *)r->reason, strlen(r->reason));
    printf("\n");
}

static int hook_calls;
static char hook_q[64];
static int hook_sent;

static void progress_hook(const char *question, int sent)
{
    hook_calls++;
    snprintf(hook_q, sizeof hook_q, "%s", question ? question : "");
    hook_sent = sent;
}

int main(void)
{
    d2k_vres r;
    memset(&r, 0, sizeof r);

    reason_set(&r, "%s", "abc");
    dump_reason("set-abc", &r);

    reason_append(&r, "%s", "-def");
    dump_reason("append-abc-def", &r);

    char long_text[401];
    memset(long_text, 'a', 400);
    long_text[400] = '\0';
    reason_set(&r, "%s", long_text);
    dump_reason("set-long-400", &r);

    char utf8[601];
    for (size_t i = 0; i + 1 < sizeof utf8; i += 2) {
        utf8[i] = (char)0xd1;
        utf8[i + 1] = (char)0x8f; /* я */
    }
    utf8[600] = '\0';
    reason_set(&r, "%s", utf8);
    dump_reason("set-utf8-300", &r);

    char full[401];
    memset(full, 'x', 400);
    full[400] = '\0';
    reason_set(&r, "%s", full);
    reason_append(&r, "%s", "tail");
    dump_reason("append-full", &r);

    char almost[381];
    memset(almost, 'y', 380);
    almost[380] = '\0';
    reason_set(&r, "%s", almost);
    reason_append(&r, "%s", "0123456789");
    dump_reason("append-partial", &r);

    qp_budget b;
    clock_gettime(CLOCK_MONOTONIC, &b.start);
    b.limit_ms = 0;
    printf("budget-zero,%d\n", budget_left(&b));
    b.limit_ms = 100;
    printf("budget-now,%d\n", budget_left(&b));
    b.start.tv_nsec -= 200 * 1000000L;
    if (b.start.tv_nsec < 0) { b.start.tv_nsec += 1000000000L; b.start.tv_sec--; }
    printf("budget-expired,%d\n", budget_left(&b));
    clock_gettime(CLOCK_MONOTONIC, &b.start);
    b.start.tv_nsec -= 99 * 1000000L;
    if (b.start.tv_nsec < 0) { b.start.tv_nsec += 1000000000L; b.start.tv_sec--; }
    b.limit_ms = 100;
    printf("budget-99ms,%d\n", budget_left(&b));

    const struct {
        int pass, err;
    } tallies[] = {{3, 0}, {0, 0}, {1, 0}, {2, 0}, {0, 1}, {2, 1}, {4, 0}};
    for (size_t i = 0; i < sizeof tallies / sizeof tallies[0]; i++) {
        d2k_tally t;
        memset(&t, 0, sizeof t);
        t.pass = tallies[i].pass;
        t.err = tallies[i].err;
        printf("outcome-%d-%d,%d\n", tallies[i].pass, tallies[i].err, qp_outcome(t));
    }

    static const uint32_t rtts[] = {0, 1, 500, 1000, 2000, 3000, 10000};
    for (size_t i = 0; i < sizeof rtts / sizeof rtts[0]; i++) {
        printf("budget-ms-%u,%u\n", rtts[i], d2k_quic_budget_ms(rtts[i]));
    }
    d2k_quic_budget_s = 1;
    printf("budget-ms-s1,%u\n", d2k_quic_budget_ms(1000));
    d2k_quic_budget_s = 5;
    printf("budget-ms-s5,%u\n", d2k_quic_budget_ms(1000));
    d2k_quic_budget_s = 5000000;
    printf("budget-ms-sat,%u\n", d2k_quic_budget_ms(1000));
    d2k_quic_budget_s = D2K_QUIC_BUDGET_DERIVED;

    d2k_quic_progress_hook = progress_hook;
    qp_progress("q0", 0);
    printf("progress-0,%d,%s,%d\n", hook_calls, hook_q[0] ? hook_q : "-", hook_sent);
    qp_progress("q1", 1);
    printf("progress-1,%d,%s,%d\n", hook_calls, hook_q[0] ? hook_q : "-", hook_sent);
    qp_progress("q3", 3);
    printf("progress-3,%d,%s,%d\n", hook_calls, hook_q[0] ? hook_q : "-", hook_sent);
    d2k_quic_progress_hook = NULL;

    int64_t now1 = qp_now_ms();
    usleep(5000);
    int64_t now2 = qp_now_ms();
    printf("qp-now,%d,%d,%d\n", now1 > 0, now2 >= now1, (now2 - now1) < 1000);
    return 0;
}
