/* C-оракул: `d2k_quic_strategy_arms` (core/quicarms.c:248-396):
 * TTL-lifetime → clearance → split → udplen → frag → original fallback. */
#define _POSIX_C_SOURCE 200809L
#include "quicarms.c"

#include <stdio.h>
#include <string.h>

enum {
    TTL_YES = 1,
    CLEARANCE_YES = 2,
    SPLIT_YES = 3,
    UDPLEN_YES = 4,
    FRAG_YES = 5,
    FALLBACK = 6,
    NO_SPLIT = 7,
};

static int scenario;

static d2k_tally probe(const d2k_quic_arm_question *q, void *user, int *sent)
{
    (void)user;
    printf("ask control=%d frag=%d ttl=%d copies=%d split=%d benign=%d "
           "udplen=%u blob_len=%zu\n",
           q->control, q->frag, q->ttl, q->copies, q->split, q->benign,
           q->udplen, q->blob_len);
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    *sent = D2K_QUIC_REPEATS;
    int yes = 0;
    switch (scenario) {
    case TTL_YES:
        yes = q->ttl == 3 && q->copies == 2 && q->blob_len == 1200;
        break;
    case CLEARANCE_YES:
        yes = q->benign == 1;
        break;
    case SPLIT_YES:
        yes = q->split == 1;
        break;
    case UDPLEN_YES:
        yes = q->udplen == D2K_QUIC_LENGTH_INCREMENT;
        break;
    case FRAG_YES:
        if (q->control) {
            yes = 1;
        } else if (q->frag == 2) {
            yes = 1;
        }
        break;
    default:
        break;
    }
    t.pass = yes ? D2K_QUIC_REPEATS : 0;
    return t;
}

static d2k_quic_arm_data data_stage(const d2k_quic_arm_question *q, void *user)
{
    (void)q;
    (void)user;
    d2k_quic_arm_data d;
    memset(&d, 0, sizeof d);
    d.verdict = D2K_QAD_PASS;
    return d;
}

static const char *strategy_name(int value)
{
    switch (value) {
    case D2K_QS_CLEARANCE: return "clearance";
    case D2K_QS_SPLIT: return "split";
    case D2K_QS_LADDER: return "ladder";
    case D2K_QS_FAKE_SPLIT: return "fake-split";
    case D2K_QS_TTL_LIFETIME: return "ttl-lifetime";
    case D2K_QS_FRAG: return "frag";
    case D2K_QS_LENGTH: return "length";
    case D2K_QS_NONE:
    default: return "none";
    }
}

static const char *kind_name(d2k_quic_arm_kind kind)
{
    switch (kind) {
    case D2K_QA_BLOB: return "blob";
    case D2K_QA_COPIES: return "copies";
    case D2K_QA_TTL: return "ttl";
    case D2K_QA_FRAG: return "frag";
    case D2K_QA_SPLIT: return "split";
    case D2K_QA_UDPLEN: return "udplen";
    case D2K_QA_FLAKY: return "flaky";
    case D2K_QA_NOT_FOUND:
    default: return "none";
    }
}

static void run(const char *label, int which, int need_complete, int no_split)
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
    c.marked = 1;
    c.need_complete = need_complete;
    c.budget_pk = need_complete ? 10 : 0;
    c.no_split = no_split;

    scenario = which;
    printf("scenario %s\n", label);
    d2k_quic_arm arm = d2k_quic_strategy_arms(&c);
    printf("selected %s strategy=%s kind=%s copies=%d ttl=%d frag=%d "
           "udplen=%u blob_len=%zu trace=%d probes=%d\n",
           label, strategy_name(arm.strategy), kind_name(arm.kind), arm.copies,
           arm.ttl, arm.frag_kind, arm.udplen, arm.len, (int)arm.n_trace,
           arm.probes);
}

int main(void)
{
    run("ttl-yes", TTL_YES, 1, 0);
    run("clearance-yes", CLEARANCE_YES, 0, 0);
    run("split-yes", SPLIT_YES, 0, 0);
    run("udplen-yes", UDPLEN_YES, 0, 0);
    run("frag-yes", FRAG_YES, 0, 0);
    run("fallback", FALLBACK, 0, 0);
    run("no-split", NO_SPLIT, 0, 1);
    return 0;
}
