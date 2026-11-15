/* C-оракул полного измеренного плана: poison.c + measured.c. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

#include "d2k_detect.h"
#include "measured.c"

int d2k_arm_from_poison(const d2k_poison *, d2k_arm *, char *, size_t);

static uint8_t decoy_bytes[681];
static size_t meta_len = 1536;
static size_t meta_sni_off = 137;
static size_t meta_sni_len = 13;

static void run(const char *name, const d2k_poison *source, size_t decoy_len,
                size_t send_cap)
{
    d2k_poison p = *source;
    d2k_arm arm;
    d2k_arm_input input;
    char why[160] = "";
    char text[8192];
    memset(&input, 0, sizeof input);
    input.trigger_len = meta_len;
    input.sni_off = meta_sni_off;
    input.sni_len = meta_sni_len;
    input.decoy_len = decoy_len;
    if (decoy_len) memcpy(input.decoy, decoy_bytes, decoy_len);
    if (decoy_len) {
        p.decoy = decoy_bytes;
        p.decoy_len = (int)decoy_len;
    } else {
        p.decoy = NULL;
        p.decoy_len = 0;
    }
    int rc = d2k_arm_from_poison(&p, &arm, why, sizeof why);
    if (rc == 0) {
        rc = d2k_arm_plan_measured_cap(&arm, &input, send_cap, text, sizeof text);
    }
    printf("plan|%s|%zu|%zu|%d\n", name, decoy_len, send_cap, rc);
    if (rc == 0) {
        /* Единственное намеренное различие: C печатает d2k-plan, R2O —
         * r2o-plan; оба заголовка принимает парсер. Остальное — байт в байт. */
        if (strncmp(text, "d2k-plan", 8) == 0) text[0] = 'r', text[1] = '2', text[2] = 'o';
        printf("%s", text);
    }
}

int main(void)
{
    d2k_poison p;

    for (size_t i = 0; i < sizeof decoy_bytes; i++) {
        decoy_bytes[i] = (uint8_t)(i * 23 + 5);
    }

    memset(&p, 0, sizeof p);
    run("default", &p, 0, 1500);

    memset(&p, 0, sizeof p);
    p.badsum = 1;
    run("badsum", &p, 0, 1500);

    memset(&p, 0, sizeof p);
    p.badsum = 1;
    p.repeats = 2;
    p.gap_ms = 20;
    run("badsum-x2", &p, 0, 1500);

    memset(&p, 0, sizeof p);
    p.autottl = 1;
    p.autottl_delta = -3;
    p.autottl_min = 2;
    p.autottl_max = 10;
    run("autottl", &p, 0, 1280);

    memset(&p, 0, sizeof p);
    p.tcp_ts = 1;
    p.tcp_ts_up = 1;
    run("ts-up", &p, 0, 1400);

    memset(&p, 0, sizeof p);
    p.seqovl = 1;
    run("seqovl-1", &p, 0, 1500);

    memset(&p, 0, sizeof p);
    p.seqovl_exact = 1;
    p.seqovl = 681;
    run("seqovl-hello", &p, 681, 1280);
    run("seqovl-hello", &p, 681, 1500);

    memset(&p, 0, sizeof p);
    p.seqovl_exact = 1;
    p.seqovl = 681;
    run("seqovl-hello-empty", &p, 0, 1400);

    memset(&p, 0, sizeof p);
    p.decoy_hello = 1;
    p.badsum = 1;
    p.repeats = 7;
    run("decoy-badsum", &p, 681, 1280);
    run("decoy-badsum", &p, 681, 1500);

    memset(&p, 0, sizeof p);
    p.decoy_hello = 1;
    p.tcp_ts = 1;
    p.repeats = 8;
    p.split_pos = 2;
    run("composite-ts", &p, 681, 1500);
    run("composite-ts", &p, 681, 1280);

    memset(&p, 0, sizeof p);
    p.fake_between = 1;
    p.badsum = 1;
    p.repeats = 7;
    p.gap_ms = 300;
    run("between", &p, 0, 1400);

    memset(&p, 0, sizeof p);
    p.disorder = 1;
    p.disorder_pos = 2;
    run("disorder", &p, 0, 1500);

    memset(&p, 0, sizeof p);
    p.oob = 1;
    run("oob", &p, 0, 1500);

    memset(&p, 0, sizeof p);
    p.md5 = 1;
    run("md5", &p, 0, 1280);

    memset(&p, 0, sizeof p);
    p.split_pos = 2;
    run("split", &p, 0, 1400);

    memset(&p, 0, sizeof p);
    p.ip_id_zero = 1;
    run("ipid", &p, 0, 1500);

    memset(&p, 0, sizeof p);
    p.syn_data = 1;
    run("syn-data", &p, 0, 1500);

    memset(&p, 0, sizeof p);
    p.seq_shift = -123;
    run("seq-invalid", &p, 0, 1500);

    memset(&p, 0, sizeof p);
    p.badsum = 1;
    run("badsum", &p, 0, 72);
    run("badsum", &p, 0, 1);
    run("badsum", &p, 0, 65535);
    run("badsum", &p, 0, 1280);
    run("badsum", &p, 0, 1400);
    run("badsum", &p, 0, 1500);

    meta_len = 200;
    meta_sni_off = 0;
    meta_sni_len = 0;
    memset(&p, 0, sizeof p);
    p.badsum = 1;
    run("badsum-nameless", &p, 0, 1400);
    return 0;
}
