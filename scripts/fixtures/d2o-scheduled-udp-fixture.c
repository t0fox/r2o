#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_sched.h"

static void make_udp_packet(uint8_t packet[28], int reverse) {
    static const uint8_t client[4] = {192, 0, 2, 1};
    static const uint8_t server[4] = {198, 51, 100, 2};
    const uint8_t *source = reverse ? server : client;
    const uint8_t *destination = reverse ? client : server;
    const uint16_t source_port = reverse ? 50005 : 40156;
    const uint16_t destination_port = reverse ? 40156 : 50005;

    memset(packet, 0, 28);
    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = 28;
    packet[8] = 64;
    packet[9] = 17;
    memcpy(packet + 12, source, 4);
    memcpy(packet + 16, destination, 4);
    packet[20] = (uint8_t)(source_port >> 8);
    packet[21] = (uint8_t)source_port;
    packet[22] = (uint8_t)(destination_port >> 8);
    packet[23] = (uint8_t)destination_port;
    packet[25] = 8;
}

int main(void) {
    uint8_t request[28], response[28], out[28];
    d2k_key key = {0};
    d2k_sched *scheduled = d2k_sched_new(2, sizeof request);
    d2k_sched *pressure = NULL;
    int refused;
    size_t out_len = 0;
    uint64_t execution = 0;
    int popped;

    if (!scheduled) return 2;
    make_udp_packet(request, 0);
    make_udp_packet(response, 1);
    if (request[12] != response[16] || request[16] != response[12] ||
        request[20] != response[22] || request[22] != response[20]) {
        d2k_sched_free(scheduled);
        return 2;
    }
    if (d2k_sched_push_serial(scheduled, 15000000, request, sizeof request,
                              &key, 1) != 0) {
        d2k_sched_free(scheduled);
        return 2;
    }

    /* The reverse UDP packet is observed while the scheduled send is pending. */
    popped = d2k_sched_pop_due_serial(scheduled, 1000000, out, sizeof out,
                                      &out_len, NULL, &execution);
    if (popped != 0 || d2k_sched_count(scheduled) != 1) {
        d2k_sched_free(scheduled);
        return 1;
    }
    popped = d2k_sched_pop_due_serial(scheduled, 14999999, out, sizeof out,
                                      &out_len, NULL, &execution);
    if (popped != 0 || d2k_sched_count(scheduled) != 1) {
        d2k_sched_free(scheduled);
        return 1;
    }
    popped = d2k_sched_pop_due_serial(scheduled, 15000000, out, sizeof out,
                                      &out_len, NULL, &execution);
    if (popped != 1 || out_len != sizeof request || execution != 1 ||
        memcmp(out, request, sizeof request) != 0) {
        d2k_sched_free(scheduled);
        return 1;
    }

    printf("RESULT delay_us=15000 packet=");
    for (size_t i = 0; i < out_len; i++) printf("%02x", out[i]);
    putchar('\n');

    pressure = d2k_sched_new(1, sizeof request);
    if (!pressure ||
        d2k_sched_push_serial(pressure, 15000000, request, sizeof request, &key, 1) != 0) {
        d2k_sched_free(pressure);
        d2k_sched_free(scheduled);
        return 2;
    }
    refused = d2k_sched_push_serial(pressure, 16000000, request, sizeof request, &key, 2);
    if (refused != -1 || d2k_sched_count(pressure) != 1 ||
        d2k_sched_refusals(pressure) != 1) {
        d2k_sched_free(pressure);
        d2k_sched_free(scheduled);
        return 1;
    }
    printf("METRICS queue=%zu refusals=%llu\n", d2k_sched_count(pressure),
           (unsigned long long)d2k_sched_refusals(pressure));
    d2k_sched_free(pressure);
    d2k_sched_free(scheduled);
    return 0;
}
