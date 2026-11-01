#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_quic_arms.h"

static const char *verdict_name(d2k_quic_arm_data_verdict verdict) {
    switch (verdict) {
    case D2K_QAD_NOT_RUN: return "NotRun";
    case D2K_QAD_PASS: return "Pass";
    case D2K_QAD_NO_HANDSHAKE: return "NoHandshake";
    case D2K_QAD_CUT: return "Cut";
    }
    return "Invalid";
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    char *end = NULL;
    long port = strtol(argv[2], &end, 10);
    if (!end || *end || port < 1 || port > 65535) return 2;

    d2k_qc_opts options;
    memset(&options, 0, sizeof options);
    options.ip = argv[1];
    options.port = (uint16_t)port;
    options.sni = argv[3];
    options.alpn = "h3";
    options.deadline_ms = 2000;

    char error[200] = {0};
    d2k_qc *connection = NULL;
    if (d2k_qc_connect(&options, &connection, error, sizeof error) != 0) {
        printf("verdict=NoHandshake app_bytes=0 requests=0\n");
        fprintf(stderr, "D2O QUIC connect: %s\n", error);
        return 1;
    }
    d2k_quic_arm_data data = {.verdict = D2K_QAD_NOT_RUN};
    d2k_quic_data_stage(connection, argv[3], argv[4], 0, 0, 1000, &data);
    d2k_qc_close(connection);
    printf("verdict=%s app_bytes=%" PRIu64 " requests=%u\n",
           verdict_name(data.verdict), data.app_bytes, data.requests);
    if (data.verdict != D2K_QAD_PASS) {
        fprintf(stderr, "D2O data stage: %s\n", data.reason);
    }
    return data.verdict == D2K_QAD_PASS ? 0 : 1;
}
