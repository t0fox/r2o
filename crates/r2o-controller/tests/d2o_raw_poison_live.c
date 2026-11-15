/* C production poison family: d2k_raw_probe_poison_family on loopback. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "raw.c"
#include "d2k_hello.h"

int64_t d2k_now_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

int d2k_detect_stopped(const d2k_detect_stop *cancel)
{
    (void)cancel;
    return 0;
}

void d2k_sleep_ms(int ms) { (void)ms; }

int d2k_trigger_accepts(const d2k_trigger *trigger, const uint8_t *bytes, size_t len)
{
    (void)trigger;
    (void)bytes;
    (void)len;
    return 1;
}

static void make_trigger(d2k_trigger *trigger)
{
    memset(trigger, 0, sizeof *trigger);
    size_t length = 0;
    size_t sni_off = 0, sni_len = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, "probe.example",
                               trigger->payload, sizeof trigger->payload,
                               &length) != 0 ||
        d2k_hello_sni(trigger->payload, length, &sni_off, &sni_len) != 0 ||
        length < 2 || length > sizeof trigger->payload) {
        fprintf(stderr, "failed to build modern hello\n");
        exit(2);
    }
    trigger->len = length;
    trigger->sni_off = sni_off;
    trigger->sni_len = sni_len;
    trigger->accept = D2K_ACCEPT_ANY;
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: %s FAMILY ADDRESS PORT TIMEOUT POISON\n", argv[0]);
        return 2;
    }
    uint8_t family = (uint8_t)atoi(argv[1]);
    uint8_t address[16] = {0};
    if (inet_pton(family == 6 ? AF_INET6 : AF_INET, argv[2], address) != 1) {
        fprintf(stderr, "bad address: %s\n", argv[2]);
        return 2;
    }
    const char *name = argv[5];
    d2k_trigger trigger;
    d2k_poison poison;
    char err[160] = "";
    make_trigger(&trigger);
    memset(&poison, 0, sizeof poison);
    snprintf(poison.name, sizeof poison.name, "%s", name);
    if (strcmp(name, "badsum") == 0) {
        poison.badsum = 1;
    } else if (strcmp(name, "split") == 0) {
        poison.split_pos = 1;
        poison.gap_ms = 20;
    } else if (strcmp(name, "seqovl") == 0) {
        poison.seqovl = 1;
    } else if (strcmp(name, "syn_data") == 0) {
        poison.syn_data = 1;
    } else if (strcmp(name, "none") != 0) {
        fprintf(stderr, "unknown poison: %s\n", name);
        return 2;
    }
    int rc = d2k_raw_probe_poison_family(address, family, (uint16_t)atoi(argv[3]),
                                         &trigger, &poison, atoi(argv[4]), 0, NULL,
                                         err, sizeof err);
    printf("poison|%s|%d|err=%s|dials=%lu\n", name, rc, err,
           d2k_raw_dial_count());
    return 0;
}
