#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include "d2k_detect.h"

static int cancelled;
static int cancel_during_sleep;
static int cancel_after_first_send;
static size_t sent_packets;
static unsigned waited_ms;
static uint8_t captured_packets[8][8192];
static size_t captured_lengths[8];

static int stop_requested(void *ctx)
{
    return *(const int *)ctx;
}

int d2k_detect_stopped(const d2k_detect_stop *stop)
{
    return stop && stop->fn && stop->fn(stop->ctx);
}

static void fixture_sleep_ms(int ms)
{
    if (ms > 0) waited_ms += (unsigned)ms;
    if (cancel_during_sleep) cancelled = 1;
}

static ssize_t fixture_sendto(int fd, const void *packet, size_t len, int flags,
                              const struct sockaddr *address, socklen_t address_len)
{
    (void)fd;
    (void)packet;
    (void)flags;
    (void)address;
    (void)address_len;
    if (sent_packets < 8 && len <= sizeof captured_packets[0]) {
        memcpy(captured_packets[sent_packets], packet, len);
        captured_lengths[sent_packets] = len;
    }
    sent_packets++;
    if (cancel_after_first_send && sent_packets == 1) cancelled = 1;
    return (ssize_t)len;
}

static void print_split_packets(void)
{
    for (size_t i = 0; i < sent_packets && i < 8; i++) {
        uint8_t normalized[8192];
        memcpy(normalized, captured_packets[i], captured_lengths[i]);
        if (captured_lengths[i] >= 20 && (normalized[0] >> 4) == 4) {
            normalized[4] = normalized[5] = 0;
            normalized[10] = normalized[11] = 0;
        }
        printf("RAW_SPLIT_PACKET|");
        for (size_t j = 0; j < captured_lengths[i]; j++) {
            printf("%02x", normalized[j]);
        }
        putchar('\n');
    }
}

#define d2k_sleep_ms fixture_sleep_ms
#define sendto fixture_sendto
#include "raw.c"
#undef sendto
#undef d2k_sleep_ms

int main(void)
{
    static const uint8_t payload[] = {
        0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00,
        0x04, 0x03, 0x03, 0x00, 0x00,
    };
    raw_conn connection = {0};
    d2k_trigger trigger = {0};
    d2k_poison poison = {0};
    d2k_detect_stop stop = {stop_requested, &cancelled};
    char error[160] = "";

    connection.family = 4;
    connection.send_fd = 1;
    connection.seq = 0x12345678;
    connection.ack = 0x90abcdef;
    connection.sport = 41000;
    connection.dport = 443;
    memcpy(connection.src, (uint8_t[]){192, 0, 2, 1}, 4);
    memcpy(connection.dst, (uint8_t[]){198, 51, 100, 2}, 4);
    memcpy(trigger.payload, payload, sizeof payload);
    trigger.len = sizeof payload;

    strcpy(poison.name, "tcp-split");
    poison.split_pos = 5;
    poison.gap_ms = 20;
    int split_rc = raw_send_plan(&connection, &trigger, &poison, &stop, error, sizeof error);
    if (split_rc != 0 || sent_packets != 2) {
        fprintf(stderr, "C raw split mismatch: rc=%d packets=%zu error=%s\n",
                split_rc, sent_packets, error);
        return 1;
    }
    print_split_packets();

    sent_packets = 0;
    waited_ms = 0;
    cancelled = 0;
    cancel_after_first_send = 1;
    error[0] = '\0';
    split_rc = raw_send_plan(&connection, &trigger, &poison, &stop, error, sizeof error);
    if (split_rc == 0 || strcmp(error, "context canceled") != 0 || sent_packets != 1 || waited_ms != 0) {
        fprintf(stderr, "C between-span cancellation mismatch: rc=%d packets=%zu waited_ms=%u error=%s\n",
                split_rc, sent_packets, waited_ms, error);
        return 1;
    }
    printf("RAW_SPLIT_CANCEL result=cancelled packets=%zu waited_ms=%u\n", sent_packets, waited_ms);

    sent_packets = 0;
    waited_ms = 0;
    cancelled = 0;
    cancel_after_first_send = 0;
    error[0] = '\0';
    strcpy(poison.name, "badsum-x3-g20");
    poison.badsum = 1;
    poison.repeats = 3;
    poison.gap_ms = 20;

    cancel_during_sleep = 1;
    int rc = raw_send_plan(&connection, &trigger, &poison, &stop, error, sizeof error);
    if (rc == 0 || strcmp(error, "context canceled") != 0 || sent_packets != 2 || waited_ms != 20 || !cancelled) {
        fprintf(stderr, "C emission cancellation mismatch: rc=%d error=%s packets=%zu waited_ms=%u cancelled=%d\n",
                rc, error, sent_packets, waited_ms, cancelled);
        return 1;
    }
    printf("RAW_EMISSION_CANCEL result=cancelled packets=%zu waited_ms=%u\n", sent_packets, waited_ms);
    return 0;
}
