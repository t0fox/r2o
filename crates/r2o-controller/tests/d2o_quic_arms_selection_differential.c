/* C-оракул: `d2k_quic_original_arms` (core/quicarms.c:142-219) — adaptive
 * fake_default×11+split и остановка на первом прошедшем кандидате. */
#define _POSIX_C_SOURCE 200809L
#include "d2k_quic_arms.h"

#include <stdio.h>
#include <string.h>

enum {
    FIRST_SINGLE = 1,
    PAIR_0X6 = 2,
    ADAPTIVE_PASS = 3,
    ADAPTIVE_FAIL = 4,
    NO_ADAPTIVE = 5,
};

static int scenario;
static int asked;

static d2k_tally probe(const d2k_quic_arm_question *q, void *user, int *sent)
{
    (void)user;
    printf("ask %d control=%d frag=%d ttl=%d copies=%d split=%d benign=%d "
           "udplen=%u blob_len=%zu\n",
           asked++, q->control, q->frag, q->ttl, q->copies, q->split,
           q->benign, q->udplen, q->blob_len);
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    *sent = D2K_QUIC_REPEATS;
    int default_11 = q->copies == D2K_QUIC_COPIES_B && !q->split && !q->ttl &&
                     !q->frag && !q->control && q->blob_len == 620;
    switch (scenario) {
    case FIRST_SINGLE:
        if (q->copies == 1 && !q->ttl && !q->frag && !q->split &&
            q->blob_len == 1200) {
            t.pass = D2K_QUIC_REPEATS;
        }
        break;
    case PAIR_0X6:
        if (q->copies == D2K_QUIC_COPIES_A && !q->split && q->blob_len == 1200) {
            t.pass = D2K_QUIC_REPEATS;
        }
        break;
    case ADAPTIVE_PASS:
    case ADAPTIVE_FAIL:
    case NO_ADAPTIVE:
        if (default_11) {
            t.pass = 1; /* частичный ответ включает adaptive */
        } else if (q->split) {
            t.pass = scenario == ADAPTIVE_PASS ? D2K_QUIC_REPEATS : 0;
        }
        break;
    default:
        break;
    }
    return t;
}

static const char *kind_name(d2k_quic_arm_kind kind)
{
    switch (kind) {
    case D2K_QA_BLOB: return "blob";
    case D2K_QA_COPIES: return "copies";
    case D2K_QA_TTL: return "ttl";
    case D2K_QA_FRAG: return "frag";
    case D2K_QA_FLAKY: return "flaky";
    case D2K_QA_SPLIT: return "split";
    case D2K_QA_UDPLEN: return "udplen";
    case D2K_QA_NOT_FOUND:
    default: return "none";
    }
}

static void run(const char *label, int which, int split_failed)
{
    char pool[1][D2K_QUIC_ADDR_LEN];
    memset(pool, 0, sizeof pool);
    snprintf(pool[0], sizeof pool[0], "192.0.2.1");
    d2k_quic_arm_context c;
    memset(&c, 0, sizeof c);
    c.pool = (const char (*)[D2K_QUIC_ADDR_LEN])pool;
    c.n_pool = 1;
    c.probe = probe;
    c.marked = 1;
    c.split_failed = split_failed;

    scenario = which;
    asked = 0;
    printf("scenario %s\n", label);
    d2k_quic_arm arm = d2k_quic_original_arms(&c);
    printf("selected %s kind=%s copies=%d ttl=%d frag=%d blob_len=%zu trace=%d\n",
           label, kind_name(arm.kind), arm.copies, arm.ttl, arm.frag_kind,
           arm.len, (int)arm.n_trace);
}

int main(void)
{
    run("first-single", FIRST_SINGLE, 0);
    run("pair-0x6", PAIR_0X6, 0);
    run("adaptive-pass", ADAPTIVE_PASS, 1);
    run("adaptive-fail", ADAPTIVE_FAIL, 1);
    run("no-adaptive", NO_ADAPTIVE, 0);
    return 0;
}
