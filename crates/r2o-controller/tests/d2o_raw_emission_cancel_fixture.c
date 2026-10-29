#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include "d2k_detect.h"

static int cancelled;
static int cancel_during_sleep;
static size_t sent_packets;
static unsigned waited_ms;

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
    sent_packets++;
    return (ssize_t)len;
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
