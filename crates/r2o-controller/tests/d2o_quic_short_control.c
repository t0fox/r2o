#include <stdio.h>

#include "d2k_quicprobe.h"

static const char *name(d2k_quic_arm_data_verdict verdict) {
    switch (verdict) {
        case D2K_QAD_PASS: return "PASS";
        case D2K_QAD_NOT_RUN: return "NOT_RUN";
        case D2K_QAD_CUT: return "CUT";
        case D2K_QAD_NO_HANDSHAKE: return "NO_HANDSHAKE";
    }
    return "INVALID";
}

int main(void) {
    printf("partial|%s\n", name(d2k_quic_arm_data_judge3(
        1, 200, D2K_QUIC_ARM_DATA_BYTES, 0, 0, 1, 0, 0)));
    printf("complete|%s\n", name(d2k_quic_arm_data_judge3(
        1, 200, 64, 1, 0, 1, 0, 0)));
    printf("stalled|%s\n", name(d2k_quic_arm_data_judge3(
        1, 200, 6144, 0, 1, 1, 0, 0)));
    printf("refused|%s\n", name(d2k_quic_arm_data_judge3(
        1, 451, 64, 1, 0, 1, 0, 0)));
    return 0;
}
