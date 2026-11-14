/* C-оракул: d2k_udp_out_batch (udp_release.c) — успех/busy/permanent,
 * ошибка вердикта головы/хвоста, ENOSPC и сохранение ACCEPT fallback. */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "d2k_nl.h"
#include "d2k_udp_hold.h"
#include "d2k_udp_release.h"

static uint8_t sent[32];
static size_t sent_n;
static uint32_t verdict_id[32];
static uint32_t verdict_value[32];
static size_t verdict_n;
static uint32_t refused_id[32];
static size_t refused_n;
static int fail_verdict_id;
static int fail_send_id;
static int fail_send_errno;
static int head_verdict_error;

static uint8_t packet_for(uint32_t id) {
    return (uint8_t)(id & 0xff);
}

static void reset_records(void) {
    sent_n = 0;
    verdict_n = 0;
    refused_n = 0;
    fail_verdict_id = -1;
    fail_send_id = -1;
    fail_send_errno = 0;
    head_verdict_error = 0;
}

static int record_verdict(void *ctx, uint32_t id, uint32_t verdict) {
    (void)ctx;
    if (verdict_n < sizeof verdict_id / sizeof verdict_id[0]) {
        verdict_id[verdict_n] = id;
        verdict_value[verdict_n] = verdict;
        verdict_n++;
    }
    if ((int)id == fail_verdict_id) {
        return -1;
    }
    if ((int)id == 10 && head_verdict_error) {
        return -1;
    }
    return 0;
}

static int send_now(void *ctx, const uint8_t *pkt, size_t len) {
    (void)ctx;
    (void)len;
    uint32_t id = pkt[0];
    if (sent_n < sizeof sent / sizeof sent[0]) {
        sent[sent_n++] = (uint8_t)id;
    }
    if ((int)id == fail_send_id) {
        errno = fail_send_errno;
        return -1;
    }
    return 0;
}

static int send_at(void *ctx, uint64_t at, const uint8_t *pkt, size_t len) {
    (void)ctx;
    (void)at;
    (void)pkt;
    (void)len;
    return -1;
}

static void resend_failed(void *ctx, const uint8_t *pkt, size_t len, int err) {
    (void)ctx;
    (void)len;
    (void)err;
    if (refused_n < sizeof refused_id / sizeof refused_id[0]) {
        refused_id[refused_n++] = pkt[0];
    }
}

static void fill_batch(d2k_udp_hold_batch *b) {
    memset(b, 0, sizeof *b);
    b->count = 4;
    for (size_t i = 0; i < b->count; i++) {
        b->ids[i] = (uint32_t)(10 + i);
        b->len[i] = 1;
        b->marks[i] = 0;
        b->packets[i][0] = packet_for(b->ids[i]);
    }
}

static void run(const char *name, int head_error, int fail_tail,
                int fail_send, int fail_errno) {
    reset_records();
    fail_verdict_id = fail_tail;
    fail_send_id = fail_send;
    fail_send_errno = fail_errno;
    head_verdict_error = head_error;
    d2k_udp_hold_batch b;
    fill_batch(&b);
    d2k_udp_follow *follow = d2k_udp_follow_new();
    d2k_udp_out o;
    memset(&o, 0, sizeof o);
    o.verdict = record_verdict;
    o.send_now = send_now;
    o.send_at = send_at;
    o.follow = follow;
    o.can_resend = 1;
    o.resend_failed = resend_failed;
    int vfail = d2k_udp_out_batch(&o, &b, D2K_NF_ACCEPT, 0, 1000, 1000, 0);
    printf("%s vfail=%d sent=", name, vfail);
    for (size_t i = 0; i < sent_n; i++) printf("%s%u", i ? "," : "", sent[i]);
    printf(" verdicts=");
    for (size_t i = 0; i < verdict_n; i++) {
        printf("%s%u:%u", i ? "," : "", verdict_id[i], verdict_value[i]);
    }
    printf(" busy=%llu queue_full=%llu refused=%llu told=",
           (unsigned long long)d2k_udp_follow_busy(follow),
           (unsigned long long)d2k_udp_follow_queue_full(follow),
           (unsigned long long)d2k_udp_follow_refused(follow));
    for (size_t i = 0; i < refused_n; i++) printf("%s%u", i ? "," : "", refused_id[i]);
    printf("\n");
    d2k_udp_follow_free(follow);
}

int main(void) {
    run("A success", 0, -1, -1, 0);
    run("B busy", 0, -1, 12, EAGAIN);
    run("C permanent", 0, -1, 13, EACCES);
    run("D tail-verdict-fail", 0, 12, -1, 0);
    run("E head-verdict-fail", 1, -1, -1, 0);
    run("F enospc", 0, -1, 12, ENOSPC);
    return 0;
}
