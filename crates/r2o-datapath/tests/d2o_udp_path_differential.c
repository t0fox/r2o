/* C/Rust differential: d2k_udp_path_passed/planned (datapath/udp_path.c:76-97). */
#include <stdio.h>
#include <string.h>

#include "d2k_udp_path.h"
#include "d2k_session.h"

static d2k_udp_out out;
static d2k_udp_path path;
static unsigned marked_calls;

static int rec_verdict(void *ctx, uint32_t id, uint32_t verdict) {
    (void)ctx; (void)id; (void)verdict;
    return 0;
}

static int rec_now(void *ctx, const uint8_t *packet, size_t length) {
    (void)ctx; (void)packet; (void)length;
    return 0;
}

static int rec_routed(const void *routes, uint8_t family, uint32_t mark) {
    (void)routes; (void)family;
    return mark == 0x3f;
}

static void rec_marked(void *ctx, const uint8_t *packet, size_t length, uint32_t mark) {
    (void)ctx; (void)packet; (void)length; (void)mark;
    marked_calls++;
}

static size_t udp_packet(uint8_t *packet, const uint8_t source[4],
                         const uint8_t destination[4], uint16_t source_port,
                         uint16_t destination_port, uint8_t protocol,
                         uint16_t fragment, size_t payload_len) {
    size_t total = 20 + (protocol == 6 ? 20 : 8) + payload_len;
    memset(packet, 0, total);
    packet[0] = 0x45;
    packet[2] = (uint8_t)(total >> 8);
    packet[3] = (uint8_t)total;
    packet[4] = 0;
    packet[5] = 9;
    packet[6] = (uint8_t)(fragment >> 8);
    packet[7] = (uint8_t)fragment;
    packet[8] = 64;
    packet[9] = protocol;
    memcpy(packet + 12, source, 4);
    memcpy(packet + 16, destination, 4);
    packet[20] = (uint8_t)(source_port >> 8);
    packet[21] = (uint8_t)source_port;
    packet[22] = (uint8_t)(destination_port >> 8);
    packet[23] = (uint8_t)destination_port;
    if (protocol == 17) {
        packet[24] = 0;
        packet[25] = (uint8_t)(8 + payload_len);
    }
    return total;
}

static size_t udp6_packet(uint8_t *packet, size_t payload_len) {
    size_t total = 40 + 8 + payload_len;
    memset(packet, 0, total);
    packet[0] = 0x60;
    packet[4] = (uint8_t)((8 + payload_len) >> 8);
    packet[5] = (uint8_t)(8 + payload_len);
    packet[6] = 17;
    packet[7] = 64;
    packet[8] = 0x20;
    packet[9] = 0x01;
    packet[23] = 1;
    packet[24] = 0x20;
    packet[25] = 0x01;
    packet[39] = 2;
    packet[40] = 0x9c;
    packet[41] = 0x40;
    packet[42] = 0x01;
    packet[43] = 0xbb;
    packet[44] = 0;
    packet[45] = (uint8_t)(8 + payload_len);
    return total;
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
    out.marked = rec_marked;
    memset(&path, 0, sizeof path);
    path.sess = session;
    path.hold = *hold;
    path.out = &out;
    marked_calls = 0;
    return session;
}

static void done(d2k_session *session, d2k_udp_hold *hold, d2k_udp_follow *follow) {
    d2k_udp_hold_free(hold, NULL, NULL);
    d2k_udp_follow_free(follow);
    d2k_session_free(session);
}

static void feed(d2k_session *session, const uint8_t *packet, size_t length,
                 uint64_t now, int times) {
    uint8_t buffer[256];
    d2k_result result;
    for (int index = 0; index < times; index++) {
        memset(&result, 0, sizeof result);
        (void)d2k_session_packet(session, packet, length, now + (uint64_t)index,
                                 buffer, sizeof buffer, &result);
    }
}

int main(void) {
    static const uint8_t client[4] = {192, 0, 2, 1};
    static const uint8_t server[4] = {198, 51, 100, 2};
    static const uint8_t multicast[4] = {239, 1, 1, 1};
    uint8_t packet[1600];
    d2k_udp_hold *hold;
    d2k_udp_follow *follow;
    d2k_session *session;

    session = fresh(&hold, &follow);
    size_t len = udp_packet(packet, client, server, 40000, 443, 17, 0, 4);
    feed(session, packet, len, 1000, 1);
    printf("first_passed rc=%d\n", d2k_udp_path_passed(&path, packet, len, 0, 1001));
    feed(session, packet, len, 1002, 1);
    printf("second_passed rc=%d\n",
           d2k_udp_path_passed(&path, packet, len, 0, 1002));
    done(session, hold, follow);

    session = fresh(&hold, &follow);
    len = udp_packet(packet, client, server, 40000, 443, 17, 0, 4);
    feed(session, packet, len, 1000, 1);
    printf("marked_passed rc=%d\n",
           d2k_udp_path_passed(&path, packet, len, 0x3f, 1001));
    done(session, hold, follow);

    session = fresh(&hold, &follow);
    size_t tcp_len = udp_packet(packet, client, server, 40000, 443, 6, 0, 0);
    feed(session, packet, tcp_len, 1000, 1);
    printf("tcp_passed rc=%d\n",
           d2k_udp_path_passed(&path, packet, tcp_len, 0, 1001));
    done(session, hold, follow);

    session = fresh(&hold, &follow);
    len = udp_packet(packet, client, server, 40000, 443, 17, 0x2000, 4);
    feed(session, packet, len, 1000, 1);
    printf("fragment_passed rc=%d\n",
           d2k_udp_path_passed(&path, packet, len, 0, 1001));
    done(session, hold, follow);

    session = fresh(&hold, &follow);
    size_t v6_len = udp6_packet(packet, 4);
    feed(session, packet, v6_len, 1000, 1);
    printf("ipv6_passed rc=%d\n",
           d2k_udp_path_passed(&path, packet, v6_len, 0, 1001));
    done(session, hold, follow);

    session = fresh(&hold, &follow);
    len = udp_packet(packet, client, multicast, 40000, 443, 17, 0, 4);
    feed(session, packet, len, 1000, 1);
    printf("multicast_passed rc=%d\n",
           d2k_udp_path_passed(&path, packet, len, 0, 1001));
    done(session, hold, follow);

    session = fresh(&hold, &follow);
    len = udp_packet(packet, client, server, 40000, 443, 17, 0, 4);
    feed(session, packet, len, 1000, 1);
    printf("first_planned rc=%d\n",
           d2k_udp_path_planned(&path, packet, len, 0, 1030, 1001));
    done(session, hold, follow);

    session = fresh(&hold, &follow);
    len = udp_packet(packet, client, server, 40000, 443, 17, 0, 4);
    feed(session, packet, len, 1000, 1);
    printf("bad_mark_planned rc=%d\n",
           d2k_udp_path_planned(&path, packet, len, 0x3f, 1030, 1001));
    done(session, hold, follow);

    session = fresh(&hold, &follow);
    printf("short_passed rc=%d\n",
           d2k_udp_path_passed(&path, packet, 19, 0, 1001));
    done(session, hold, follow);
    return 0;
}
