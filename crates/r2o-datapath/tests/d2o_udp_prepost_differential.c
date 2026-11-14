/* C/Rust differential: d2k_udp_path_pre/post codes (datapath/udp_path.c:15-60). */
#include <stdio.h>
#include <string.h>

#include "d2k_quichello.h"
#include "d2k_session.h"
#include "d2k_udp_path.h"

static d2k_udp_out out;
static d2k_udp_path path;
static uint32_t last_verdict;
static unsigned verdicts;

static int rec_verdict(void *ctx, uint32_t id, uint32_t verdict) {
    (void)ctx; (void)id;
    last_verdict = verdict;
    verdicts++;
    return 0;
}

static int rec_now(void *ctx, const uint8_t *packet, size_t length) {
    (void)ctx; (void)packet; (void)length;
    return 0;
}

static int rec_routed(const void *routes, uint8_t family, uint32_t mark) {
    (void)routes; (void)family; (void)mark;
    return 0;
}

static size_t build(uint8_t *o, uint32_t id, uint16_t sport, const uint8_t *pay, size_t n) {
    size_t total = 28 + n;
    memset(o, 0, 28);
    o[0] = 0x45;
    o[2] = (uint8_t)(total >> 8);
    o[3] = (uint8_t)total;
    o[4] = (uint8_t)(id >> 8);
    o[5] = (uint8_t)id;
    o[8] = 64;
    o[9] = 17;
    o[12] = 192; o[13] = 168; o[14] = 1; o[15] = 67;
    o[16] = 57; o[17] = 144; o[18] = 248; o[19] = 192;
    o[20] = (uint8_t)(sport >> 8);
    o[21] = (uint8_t)sport;
    o[22] = 0x01; o[23] = 0xBB;
    o[24] = (uint8_t)((8 + n) >> 8);
    o[25] = (uint8_t)(8 + n);
    memcpy(o + 28, pay, n);
    return total;
}

/* QUIC v1 Initial с валидным заголовком, но без собранного ClientHello. */
static size_t unnamed_initial(uint8_t *pay, uint8_t salt) {
    size_t n = 1200;
    memset(pay, salt, n);
    pay[0] = 0xC3; pay[1] = 0; pay[2] = 0; pay[3] = 0; pay[4] = 1;
    pay[5] = 8; memset(pay + 6, 0x11, 8);
    pay[14] = 0;
    pay[15] = 0;
    pay[16] = 0x40 | (uint8_t)((n - 18) >> 8);
    pay[17] = (uint8_t)(n - 18);
    return n;
}

static d2k_session *fresh(d2k_udp_hold **hold, d2k_udp_follow **follow) {
    d2k_session *session = d2k_session_new(64, 32);
    d2k_session_set_hook(session, D2K_HOOK_POSTROUTING);
    *hold = d2k_udp_hold_new();
    *follow = d2k_udp_follow_new();
    memset(&out, 0, sizeof out);
    out.verdict = rec_verdict;
    out.send_now = rec_now;
    out.follow = *follow;
    out.can_resend = 1;
    out.neutral_mark = 0x2e;
    out.routed = rec_routed;
    memset(&path, 0, sizeof path);
    path.sess = session;
    path.hold = *hold;
    path.out = &out;
    last_verdict = 0xffffffffu;
    verdicts = 0;
    return session;
}

static void done(d2k_session *session, d2k_udp_hold *hold, d2k_udp_follow *follow) {
    d2k_udp_hold_free(hold, NULL, NULL);
    d2k_udp_follow_free(follow);
    d2k_session_free(session);
}

int main(void) {
    uint8_t pay[1300], pkt[1400], buf[512];
    d2k_key key;
    d2k_result result;
    d2k_udp_hold_batch batch;

    {
        d2k_udp_hold *h; d2k_udp_follow *f;
        d2k_session *s = fresh(&h, &f);
        size_t pn = unnamed_initial(pay, 1);
        size_t n = build(pkt, 1, 50100, pay, pn);
        int pre = d2k_udp_path_pre(&path, 1, pkt, n, 0, 1000, &key);
        memset(&result, 0, sizeof result);
        (void)d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &result);
        int wait = result.udp_hold_wait;
        int post = d2k_udp_path_post(&path, 1, &key, &result, &batch);
        size_t released = d2k_udp_path_expire(&path, 1000 + D2K_UDP_HOLD_WAIT_NS, 0);
        printf("A pre=%d wait=%d post=%d released=%zu verdict=%u\n",
               pre, wait, post, released, last_verdict);
        done(s, h, f);
    }

    {
        d2k_udp_hold *h; d2k_udp_follow *f;
        d2k_session *s = fresh(&h, &f);
        const uint8_t plain = 'x';
        size_t n = build(pkt, 2, 50101, &plain, 1);
        int pre = d2k_udp_path_pre(&path, 2, pkt, n, 0, 1000, &key);
        memset(&result, 0, sizeof result);
        (void)d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &result);
        int post = d2k_udp_path_post(&path, 0, &key, &result, &batch);
        printf("B pre=%d post=%d\n", pre, post);
        done(s, h, f);
    }

    {
        d2k_udp_hold *h; d2k_udp_follow *f;
        d2k_session *s = fresh(&h, &f);
        size_t pn = unnamed_initial(pay, 1);
        size_t n = build(pkt, 3, 50102, pay, pn);
        int pre = d2k_udp_path_pre(&path, 3, pkt, n, 0, 1000, &key);
        memset(&result, 0, sizeof result);
        (void)d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &result);
        result.udp_hold_wait = 0;
        result.udp_hold_ready = 0;
        int post = d2k_udp_path_post(&path, 1, &key, &result, &batch);
        printf("C pre=%d post=%d verdict=%u\n", pre, post, last_verdict);
        done(s, h, f);
    }

    {
        d2k_udp_hold *h; d2k_udp_follow *f;
        d2k_session *s = fresh(&h, &f);
        size_t pn = unnamed_initial(pay, 1);
        size_t n = build(pkt, 4, 50103, pay, pn);
        int pre = d2k_udp_path_pre(&path, 4, pkt, n, 0, 1000, &key);
        memset(&result, 0, sizeof result);
        (void)d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &result);
        memset(&batch, 0, sizeof batch);
        (void)d2k_udp_hold_take(h, &key, 1000, &batch);
        result.udp_hold_wait = 0;
        result.udp_hold_ready = 1;
        int post = d2k_udp_path_post(&path, 1, &key, &result, &batch);
        printf("D pre=%d post=%d\n", pre, post);
        done(s, h, f);
    }

    return 0;
}
