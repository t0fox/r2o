/* C-оракул: production `ask`, `ask_frag`, `d2k_quic_original_arms`
 * (core/quicarms.c:125-219). probe-хук только записывает вопрос и отвечает
 * «измерено, 0/3» (контроль — настраиваемо), поэтому видна вся лестница. */
#define _POSIX_C_SOURCE 200809L
#include "d2k_quic_arms.h"

#include <stdio.h>
#include <string.h>

static int control_passes;
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
    t.pass = (q->control && control_passes) ? D2K_QUIC_REPEATS : 0;
    *sent = D2K_QUIC_REPEATS;
    return t;
}

static void run(const char *label, int benign, int ttl_pair, int frag_answered,
                int control_ok)
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
    c.benign_answered = benign;
    c.ttl_pair_answered = ttl_pair;
    c.frag_answered = frag_answered;

    control_passes = control_ok;
    asked = 0;
    printf("scenario %s\n", label);
    d2k_quic_arm arm = d2k_quic_original_arms(&c);
    printf("end %s asked=%d trace=%d\n", label, asked, (int)arm.n_trace);
}

int main(void)
{
    run("base", 0, 0, 0, 1);
    run("benign-ttl", 1, 1, 0, 1);
    run("frag-used", 0, 0, 1, 1);
    run("control-fail", 0, 0, 0, 0);
    return 0;
}
