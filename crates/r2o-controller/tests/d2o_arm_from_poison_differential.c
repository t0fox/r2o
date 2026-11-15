/* C-оракул d2k_arm_from_poison (detect/poison.c:413-475). */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

#include "poison.c"

static void run(const char *name, const d2k_poison *p)
{
    d2k_arm a;
    char why[160] = "";
    int rc = d2k_arm_from_poison(p, &a, why, sizeof why);
    printf("arm|%s|%d|%s", name, rc, why);
    if (rc == 0) {
        printf("|%u|%d|%d|%u|%u|%d|%u|%d|%u|%d|%d|%u|%u|%d|%d|%d|%d|%d|%d|%d|%u",
               a.seqovl, a.seqovl_hello, a.badsum, a.repeats, a.gap_ms,
               a.disorder, a.disorder_pos, a.between, a.ttl, a.autottl,
               a.autottl_delta, a.autottl_min, a.autottl_max, a.seq_out,
               a.decoy_hello, a.md5, a.tcpts, a.tcpts_up, a.ipidzero,
               a.oob, a.split_pos);
    }
    printf("\n");
}

int main(void)
{
    d2k_poison p;

    memset(&p, 0, sizeof p);
    run("default", &p);

    memset(&p, 0, sizeof p);
    p.ttl = 8;
    run("ttl", &p);

    memset(&p, 0, sizeof p);
    p.seq_shift = -66000;
    run("seq-out", &p);

    memset(&p, 0, sizeof p);
    p.seq_shift = -123;
    run("seq-invalid", &p);

    memset(&p, 0, sizeof p);
    p.disorder = 1;
    p.disorder_pos = 2;
    run("disorder-pos", &p);

    memset(&p, 0, sizeof p);
    p.syn_data = 1;
    run("syn-data", &p);

    memset(&p, 0, sizeof p);
    p.oob = 1;
    run("oob", &p);

    memset(&p, 0, sizeof p);
    p.md5 = 1;
    run("md5", &p);

    memset(&p, 0, sizeof p);
    p.tcp_ts = 1;
    p.decoy_hello = 1;
    p.repeats = 8;
    p.split_pos = 2;
    run("composite", &p);

    memset(&p, 0, sizeof p);
    p.seqovl_exact = 1;
    p.seqovl = 681;
    run("seqovl-exact", &p);

    memset(&p, 0, sizeof p);
    p.seqovl = 5;
    run("seqovl", &p);

    memset(&p, 0, sizeof p);
    p.fake_between = 1;
    p.badsum = 1;
    p.repeats = 7;
    p.gap_ms = 300;
    run("between", &p);

    memset(&p, 0, sizeof p);
    p.autottl = 1;
    p.autottl_delta = -3;
    p.autottl_min = 2;
    p.autottl_max = 10;
    run("autottl", &p);

    memset(&p, 0, sizeof p);
    p.tcp_ts = 1;
    p.tcp_ts_up = 1;
    run("ts-up", &p);

    memset(&p, 0, sizeof p);
    p.repeats = -2;
    p.gap_ms = -5;
    p.ttl = -1;
    p.disorder_pos = -4;
    p.autottl_min = -2;
    p.autottl_max = -3;
    run("negative", &p);

    memset(&p, 0, sizeof p);
    p.badsum = 1;
    p.repeats = 0;
    run("badsum-default-copy", &p);
    return 0;
}
