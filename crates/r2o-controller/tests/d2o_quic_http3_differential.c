#include <stdio.h>
#include <string.h>

#include "d2k_quicprobe.h"

static const char *verdict_name(d2k_quic_arm_data_verdict verdict) {
    switch (verdict) {
    case D2K_QAD_PASS: return "Pass";
    case D2K_QAD_CUT: return "Cut";
    case D2K_QAD_NO_HANDSHAKE: return "NoHandshake";
    case D2K_QAD_NOT_RUN: return "NotRun";
    }
    return "Invalid";
}

int main(int argc, char **argv) {
    int status;
    int complete = 1;
    int need_complete = 1;
    uint64_t bytes;
    const char *name;
    if (argc != 2) return 2;
    if (strcmp(argv[1], "budget-next-stream") == 0) {
        d2k_qbudget budget;
        d2k_qbudget_init(&budget, 1);
        (void)d2k_qbudget_ok(&budget, 2, 100, 200, 1000, 1000, 1000);
        int passed = d2k_qbudget_ok(&budget, 2, 120, 200, 1100, 1100, 1000);
        printf("budget-next-stream=%s\n", passed ? "Pass" : "NotRun");
        return passed ? 0 : 1;
    }
    if (strcmp(argv[1], "content-length") == 0) {
        name = "content-length";
        status = 200;
        bytes = 2;
    } else if (strcmp(argv[1], "large-body") == 0) {
        name = "large-body";
        status = 200;
        bytes = 16u * 1024u * 1024u + 1u;
    } else if (strcmp(argv[1], "stream-bytes") == 0) {
        name = "stream-bytes";
        status = 200;
        bytes = D2K_QUIC_ARM_DATA_BYTES;
        complete = 0;
        need_complete = 0;
    } else {
        return 2;
    }

    d2k_quic_arm_data_verdict verdict = d2k_quic_arm_data_judge3(
        1, status, bytes, complete, 0, need_complete, 0, 0);
    printf("%s=%s\n", name, verdict_name(verdict));
    return verdict == D2K_QAD_PASS ? 0 : 1;
}
