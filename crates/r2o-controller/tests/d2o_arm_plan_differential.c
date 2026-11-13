/* C/Rust differential: d2k_arm_plan arbitrary field combinations. */
#include <stdio.h>
#include <string.h>

#include "d2k_arm.h"
#include "d2k_compose.h"

static void run(unsigned index, unsigned shape, size_t cap, const d2k_arm *arm) {
    char text[8192];
    int rc = d2k_arm_plan(arm, (d2k_shape)shape, "disk.rzd.ru", cap, text, sizeof text);
    printf("case %u rc=%d\n", index, rc);
    if (rc == 0) {
        fputs(text, stdout);
    }
}

int main(void) {
    d2k_arm a;

    memset(&a, 0, sizeof a);
    a.badsum = 1;
    a.repeats = 1;
    a.tcpts = 1;
    run(0, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.badsum = 1;
    a.repeats = 2;
    a.gap_ms = 20;
    a.ipidzero = 1;
    run(1, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.badsum = 1;
    a.ttl = 10;
    a.tcpts = 1;
    a.ipidzero = 1;
    run(2, 2, 1492, &a);

    memset(&a, 0, sizeof a);
    a.seq_out = 1;
    a.tcpts = 1;
    run(3, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.disorder = 1;
    a.disorder_pos = 2;
    run(4, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.disorder = 1;
    a.disorder_pos = 100;
    run(5, 2, 1492, &a);

    memset(&a, 0, sizeof a);
    a.disorder = 1;
    a.disorder_pos = 2;
    a.seqovl = 4;
    run(6, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.disorder_pos = 2;
    run(7, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.oob = 1;
    run(8, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.oob = 1;
    a.ttl = 10;
    run(9, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.md5 = 1;
    a.badsum = 1;
    run(10, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.seqovl_hello = 1;
    a.badsum = 1;
    a.repeats = 1;
    run(11, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.badsum = 1;
    a.split_pos = 5;
    a.autottl = 1;
    a.tcpts_up = 1;
    run(12, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.repeats = 2;
    run(13, 2, 1492, &a);

    memset(&a, 0, sizeof a);
    a.between = 1;
    a.badsum = 1;
    a.repeats = 7;
    a.gap_ms = 300;
    a.tcpts = 1;
    run(14, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.seq_out = 1;
    run(15, 1, 100, &a);

    memset(&a, 0, sizeof a);
    a.badsum = 1;
    a.repeats = 1;
    run(16, 1, 60, &a);

    memset(&a, 0, sizeof a);
    a.badsum = 1;
    a.repeats = 1;
    a.decoy_hello = 1;
    a.tcpts = 1;
    run(17, 2, 1492, &a);

    memset(&a, 0, sizeof a);
    a.disorder = 1;
    run(18, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.disorder = 1;
    a.disorder_pos = 2048;
    run(19, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.disorder = 1;
    a.disorder_pos = 2049;
    run(20, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.seqovl = 4;
    a.tcpts = 1;
    run(21, 1, 1492, &a);

    memset(&a, 0, sizeof a);
    a.badsum = 1;
    a.repeats = 1;
    a.ttl = 62;
    a.ipidzero = 1;
    run(22, 1, 1200, &a);

    return 0;
}
