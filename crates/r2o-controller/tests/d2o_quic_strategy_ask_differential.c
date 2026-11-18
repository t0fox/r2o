/* C-оракул: `strategy_ask` (core/quicarms.c:227-242). Включаем TU, чтобы
 * вызвать static-функцию; probe/data scripted по попыткам. */
#define _POSIX_C_SOURCE 200809L
#include "quicarms.c"

#include <stdio.h>
#include <string.h>

typedef struct {
    int pass, sent, err, data;
} step;

static step script[4];
static int script_len, call;
static int can_ask_value = 1;

static d2k_tally probe(const d2k_quic_arm_question *q, void *user, int *sent)
{
    (void)q;
    (void)user;
    int index = call < script_len ? call : script_len - 1;
    call++;
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    t.pass = script[index].pass;
    t.err = script[index].err;
    *sent = script[index].sent;
    return t;
}

static d2k_quic_arm_data data_stage(const d2k_quic_arm_question *q, void *user)
{
    (void)q;
    (void)user;
    int index = call > 0 ? call - 1 : 0;
    d2k_quic_arm_data d;
    memset(&d, 0, sizeof d);
    d.verdict = (d2k_quic_arm_data_verdict)script[index].data;
    return d;
}

static int can_ask(void *user)
{
    (void)user;
    return can_ask_value;
}

static const char *decision_name(int8_t value)
{
    return value == D2K_PROP_YES ? "YES" : value == D2K_PROP_NO ? "NO" : "UNKNOWN";
}

static void run(const char *label, int steps, const step *steps_data, int can)
{
    memset(script, 0, sizeof script);
    script_len = steps;
    memcpy(script, steps_data, (size_t)steps * sizeof script[0]);
    call = 0;
    can_ask_value = can;

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
    c.marked = 1;

    d2k_quic_arm r;
    memset(&r, 0, sizeof r);
    d2k_quic_arm_question shape;
    memset(&shape, 0, sizeof shape);
    shape.copies = 1;
    int8_t asked = 0;
    int8_t rc = strategy_ask(&c, &r, &shape, "q", &asked);
    printf("strategy %s rc=%s asked=%d probes=%d trace=%d\n", label,
           decision_name(rc), asked, r.probes, (int)r.n_trace);
}

int main(void)
{
    run("pass-data", 1, (const step[]){{3, 3, 0, D2K_QAD_PASS}}, 1);
    run("no", 1, (const step[]){{0, 3, 0, D2K_QAD_NOT_RUN}}, 1);
    run("partial-pass", 2,
        (const step[]){{1, 3, 0, D2K_QAD_NOT_RUN}, {3, 3, 0, D2K_QAD_PASS}}, 1);
    run("unsent-no", 2,
        (const step[]){{0, 2, 0, D2K_QAD_NOT_RUN}, {0, 3, 0, D2K_QAD_NOT_RUN}}, 1);
    run("partial-twice", 2,
        (const step[]){{1, 3, 0, D2K_QAD_NOT_RUN}, {1, 3, 0, D2K_QAD_NOT_RUN}}, 1);
    run("data-nohandshake", 1,
        (const step[]){{3, 3, 0, D2K_QAD_NO_HANDSHAKE}}, 1);
    run("notrun-pass", 2,
        (const step[]){{3, 3, 0, D2K_QAD_NOT_RUN}, {3, 3, 0, D2K_QAD_PASS}}, 1);
    run("budget", 1, (const step[]){{3, 3, 0, D2K_QAD_PASS}}, 0);
    run("err-pass", 2,
        (const step[]){{0, 3, 1, D2K_QAD_NOT_RUN}, {3, 3, 0, D2K_QAD_PASS}}, 1);
    return 0;
}
