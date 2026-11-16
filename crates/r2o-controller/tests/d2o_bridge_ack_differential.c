/* C/Rust differential C-крючка d2k_detect_sched_tcp_ack.
 *
 * Включает production `detect/bridge.c`; единственная подмена — сама проба
 * `d2k_probe_data_ack`, как это делает донорский detect/test_bridge.c.
 * Печатает код (-1/0/1), число соединений и аргументы последнего вызова. */
#include "d2k_detect.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef R2O_BRIDGE_C
#error "R2O_BRIDGE_C must point to production detect/bridge.c"
#endif
#include R2O_BRIDGE_C

static const char *ack_pattern = "-";
static int ack_calls;
static char ack_host[64];
static char ack_port[16];
static uint32_t ack_mark;
static int ack_timeout;

/* C `d2k_opts_defaults` (`detect/classify.c:141-162`) в объёме,
 * который использует крючок. */
void d2k_opts_defaults(d2k_opts *options)
{
    if (options->repeats <= 0) {
        options->repeats = 3;
    }
    if (options->timeout_ms <= 0) {
        options->timeout_ms = 6000;
    }
    if (options->write_gap_ms <= 0) {
        options->write_gap_ms = 60;
    }
    if (options->long_gap_ms <= 0) {
        options->long_gap_ms = 700;
    }
    if (options->mark == 0) {
        options->mark = D2K_BYPASS_MARK;
    }
}

int d2k_probe_data_ack(const char *host, const char *port,
                       const d2k_opts *options, char *err, size_t errcap)
{
    size_t length = strlen(ack_pattern);
    char step = ack_pattern[(size_t)ack_calls < length ? (size_t)ack_calls : length - 1];
    ack_calls++;
    snprintf(ack_host, sizeof ack_host, "%s", host);
    snprintf(ack_port, sizeof ack_port, "%s", port);
    ack_mark = options->mark;
    ack_timeout = options->timeout_ms;
    if (step == 'e') {
        snprintf(err, errcap, "dial failed");
        return -1;
    }
    if (step == 'u') {
        snprintf(err, errcap, "unobservable");
        return -2;
    }
    return step == '+' ? 1 : 0;
}

static void run_case(const char *name, const char *ip, uint16_t port,
                     const char *pattern, int stop_set)
{
    volatile sig_atomic_t stop = stop_set;
    int probes = -1;
    int rc;

    ack_pattern = pattern;
    ack_calls = 0;
    ack_host[0] = '\0';
    ack_port[0] = '\0';
    ack_mark = 0;
    ack_timeout = 0;
    rc = d2k_detect_sched_tcp_ack(ip, port, 0x2f, &stop, &probes);
    printf("case=%s rc=%d probes=%d calls=%d host=%s port=%s mark=%u timeout=%d\n",
           name, rc, probes, ack_calls, ack_host[0] ? ack_host : "-",
           ack_port[0] ? ack_port : "-", ack_mark, ack_timeout);
}

int main(void)
{
    run_case("silent", "192.0.2.1", 443, "-", 0);
    run_case("ack_after_two", "2001:db8::1", 443, "-+", 0);
    run_case("local_error", "192.0.2.1", 443, "e", 0);
    run_case("unsupported", "192.0.2.1", 443, "u", 0);
    run_case("stopped", "192.0.2.1", 443, "-", 1);
    {
        int probes = -1;
        int rc = d2k_detect_sched_tcp_ack("", 443, 0x2f, NULL, &probes);
        printf("case=invalid_ip rc=%d probes=%d calls=0 host=- port=- mark=0 timeout=0\n",
               rc, probes);
        rc = d2k_detect_sched_tcp_ack("192.0.2.1", 0, 0x2f, NULL, &probes);
        printf("case=invalid_port_zero rc=%d probes=%d calls=0 host=- port=- mark=0 timeout=0\n",
               rc, probes);
    }
    return 0;
}
