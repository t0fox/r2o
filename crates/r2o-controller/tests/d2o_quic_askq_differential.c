/* C-оракул: `ask_q` (core/quicarms.c:30-104) — measured/retry/not_measured
 * для probe/data outcomes. */
#define _POSIX_C_SOURCE 200809L
#include "quicarms.c"

#include <stdio.h>
#include <string.h>

enum { BUDGET, UNSENT, ERR, NO, PARTIAL, YES, NOHANDSHAKE, NOTRUN };

static int scenario;
static int spent_ms;
static int progress_sent;

static d2k_tally probe(const d2k_quic_arm_question *q, void *user, int *sent)
{
    (void)q;
    (void)user;
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    t.pass = (scenario == YES || scenario == NOHANDSHAKE || scenario == NOTRUN)
                 ? D2K_QUIC_REPEATS
                 : scenario == PARTIAL ? 1 : 0;
    t.err = scenario == ERR ? 1 : 0;
    *sent = scenario == UNSENT ? 2 : D2K_QUIC_REPEATS;
    return t;
}

static d2k_quic_arm_data data_stage(const d2k_quic_arm_question *q, void *user)
{
    (void)q;
    (void)user;
    d2k_quic_arm_data d;
    memset(&d, 0, sizeof d);
    d.verdict = scenario == NOHANDSHAKE ? D2K_QAD_NO_HANDSHAKE
              : scenario == NOTRUN     ? D2K_QAD_NOT_RUN
                                       : D2K_QAD_PASS;
    return d;
}

static int can_ask(void *user)
{
    (void)user;
    return scenario != BUDGET;
}

static void spent(void *user, uint32_t ms)
{
    (void)user;
    spent_ms = (int)ms;
}

static void progress(const char *question, int sent)
{
    (void)question;
    progress_sent = sent;
}

static void run(const char *label, int which)
{
    char pool[1][D2K_QUIC_ADDR_LEN];
    memset(pool, 0, sizeof pool);
    snprintf(pool[0], sizeof pool[0], "192.0.2.1");
    d2k_quic_arm_context c;
    memset(&c, 0, sizeof c);
    c.pool = (const char (*)[D2K_QUIC_ADDR_LEN])pool;
    c.n_pool = 1;
    c.probe = probe;
    c.data = data_stage;
    c.can_ask = can_ask;
    c.spent = spent;
    c.marked = 1;
    d2k_quic_arm r;
    memset(&r, 0, sizeof r);
    d2k_quic_arm_question shape;
    memset(&shape, 0, sizeof shape);
    shape.copies = 1;
    int measured = 0, retry = 0;
    spent_ms = 0;
    progress_sent = 0;
    scenario = which;
    d2k_quic_progress_hook = progress;
    int ok = ask_q(&c, &r, &shape, "q", &measured, &retry);
    d2k_quic_progress_hook = NULL;
    int nm = r.n_trace ? r.trace[r.n_trace - 1].not_measured : 0;
    printf("askq %s ok=%d measured=%d retry=%d nm=%d probes=%d trace=%d "
           "spent=%d progress=%d\n",
           label, ok, measured, retry, nm, r.probes, (int)r.n_trace,
           spent_ms, progress_sent);
}

int main(void)
{
    run("budget", BUDGET);
    run("unsent", UNSENT);
    run("err", ERR);
    run("no", NO);
    run("partial", PARTIAL);
    run("yes", YES);
    run("nohandshake", NOHANDSHAKE);
    run("notrun", NOTRUN);
    return 0;
}
