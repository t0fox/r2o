#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_verify.h"

int main(int argc, char **argv)
{
    char *end = NULL;
    unsigned long port;
    unsigned long hello_wire = 0;
    int replay_deadline_ms = 3000;
    d2k_ver_result result;

    if (argc != 5 && argc != 6 && argc != 7) {
        fprintf(stderr, "usage: %s ip port sni tls12|tls13|tls13-rx|tls13-pad|alpn-mqtt|alpn-none|replay [value] [deadline-ms]\n", argv[0]);
        return 2;
    }
    port = strtoul(argv[2], &end, 10);
    if (!end || *end != '\0' || port == 0 || port > UINT16_MAX) {
        fprintf(stderr, "invalid port: %s\n", argv[2]);
        return 2;
    }

    if (strcmp(argv[4], "tls12") == 0) {
        result = d2k_verify_probe12_on(-1, argv[1], (uint16_t)port, argv[3], 3000, 0);
    } else if (strcmp(argv[4], "tls13") == 0) {
        result = d2k_verify_probe(argv[1], (uint16_t)port, argv[3], 3000, 0);
    } else if (strcmp(argv[4], "tls13-rx") == 0) {
        result = d2k_verify_probe_on(-1, argv[1], (uint16_t)port, argv[3], 6000, 0);
    } else if (strcmp(argv[4], "tls13-pad") == 0 && argc == 6) {
        hello_wire = strtoul(argv[5], &end, 10);
        if (!end || *end != '\0' || hello_wire < 6 || hello_wire > 4096) {
            fprintf(stderr, "invalid ClientHello wire length: %s\n", argv[5]);
            return 2;
        }
        result = d2k_verify_probe_on(-1, argv[1], (uint16_t)port, argv[3],
                                     3000, (size_t)hello_wire);
    } else if (strcmp(argv[4], "alpn-mqtt") == 0 && argc == 5) {
        static const uint8_t mqtt[] = {4, 'm', 'q', 't', 't'};
        result = d2k_verify_probe_alpn_on(-1, argv[1], (uint16_t)port, argv[3],
                                          3000, 0, mqtt, sizeof mqtt);
        printf("%d\t%d\n", result.handshake_proof,
               result.level == D2K_VER_HANDSHAKE);
        d2k_verify_close(&result);
        return 0;
    } else if (strcmp(argv[4], "alpn-none") == 0 && argc == 5) {
        result = d2k_verify_probe_alpn_on(-1, argv[1], (uint16_t)port, argv[3],
                                          3000, 0, NULL, 0);
        printf("%d\t%d\n", result.handshake_proof,
               result.level == D2K_VER_HANDSHAKE);
        d2k_verify_close(&result);
        return 0;
    } else if (strcmp(argv[4], "replay") == 0 && (argc == 6 || argc == 7)) {
        uint8_t hello[4096];
        size_t hello_len = strlen(argv[5]);
        if (hello_len < 12 || (hello_len & 1) || hello_len / 2 > sizeof hello) {
            fprintf(stderr, "invalid ClientHello hex length\n");
            return 2;
        }
        hello_len /= 2;
        for (size_t i = 0; i < hello_len; ++i) {
            unsigned value;
            if (sscanf(argv[5] + i * 2, "%2x", &value) != 1) {
                fprintf(stderr, "invalid ClientHello hex\n");
                return 2;
            }
            hello[i] = (uint8_t)value;
        }
        if (argc == 7) {
            char *deadline_end = NULL;
            long parsed_deadline = strtol(argv[6], &deadline_end, 10);
            if (!deadline_end || *deadline_end != '\0' || parsed_deadline < 1 ||
                parsed_deadline > 10000) {
                fprintf(stderr, "invalid replay deadline: %s\n", argv[6]);
                return 2;
            }
            replay_deadline_ms = (int)parsed_deadline;
        }
        result = d2k_verify_replay_on(-1, argv[1], (uint16_t)port,
                                      hello, hello_len, replay_deadline_ms);
        printf("%d\t%d\n", result.replay_proof,
               result.level == D2K_VER_HANDSHAKE);
        d2k_verify_close(&result);
        return 0;
    } else {
        fprintf(stderr, "invalid TLS version: %s\n", argv[4]);
        return 2;
    }
    printf("%d\t%d\t%d\t%d\n",
           result.level == D2K_VER_APPLICATION,
           result.name_ok,
           result.status,
           result.body_complete);
    d2k_verify_close(&result);
    return 0;
}
