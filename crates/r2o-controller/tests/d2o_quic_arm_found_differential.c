/* C-оракул: production `quic_arm_found` из core/udpplan.c. */
#include "udpplan.c"

#include <stdio.h>
#include <string.h>

static void run(const char *label, int kind)
{
    d2k_quic_arm arm;
    memset(&arm, 0, sizeof arm);
    arm.kind = kind;
    printf("%s %d\n", label, quic_arm_found(&arm));
}

int main(void)
{
    run("blob", D2K_QA_BLOB);
    run("copies", D2K_QA_COPIES);
    run("ttl", D2K_QA_TTL);
    run("frag", D2K_QA_FRAG);
    run("not_found", D2K_QA_NOT_FOUND);
    run("flaky", D2K_QA_FLAKY);
    run("split", D2K_QA_SPLIT);
    run("udplen", D2K_QA_UDPLEN);
    printf("null %d\n", quic_arm_found(NULL));
    return 0;
}
