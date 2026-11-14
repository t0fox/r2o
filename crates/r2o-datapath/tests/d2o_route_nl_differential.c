/* C/Rust differential: rtnetlink-запросы и разбор routemark
 * (datapath/routemark.c:36-190) против r2o_route.rs.
 *
 * Покрыты: точные байты RTM_GETRULE/RTM_GETROUTE, разбор правил fwmark
 * (маска, инверсия, неполный дамп, ошибка ядра), разбор маршрута
 * (OIF/multipath/не-unicast/повреждение) и фильтр уведомлений. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_nl.h"
#include "d2k_routemark.h"

/* Те же константы, что локально определены в datapath/routemark.c. */
#define RM_RTM_NEWRULE 32
#define RM_RTM_GETRULE 34
#define RM_NLM_F_DUMP 0x300
#define RM_FIB_HDR 12u
#define RM_FRA_FWMARK 10
#define RM_FRA_FWMASK 16
#define RM_FIB_RULE_INVERT 0x2u
#define RM_RTM_NEWROUTE 24
#define RM_RTM_DELROUTE 25
#define RM_RTM_GETROUTE 26
#define RM_RTM_DELRULE 33
#define RM_RTA_DST 1
#define RM_RTMSG 12u
#define RM_RTA_OIF 4
#define RM_RTA_MULTIPATH 9
#define RM_RTN_UNICAST 1
#define RM_RTNH_LEN 8u

static void wr16(uint8_t *p, uint16_t value) { memcpy(p, &value, 2); }
static void wr32(uint8_t *p, uint32_t value) { memcpy(p, &value, 4); }

static size_t append_message(uint8_t *out, size_t used, uint16_t type,
                             uint16_t flags, uint32_t seq,
                             const uint8_t *body, size_t body_len) {
    size_t length = D2K_NLMSG_HDRLEN + body_len;
    memset(out + used, 0, length);
    wr32(out + used, (uint32_t)length);
    wr16(out + used + 4, type);
    wr16(out + used + 6, flags);
    wr32(out + used + 8, seq);
    if (body_len) {
        memcpy(out + used + D2K_NLMSG_HDRLEN, body, body_len);
    }
    return used + ((length + 3u) & ~(size_t)3u);
}

static size_t append_attr(uint8_t *body, size_t used, uint16_t type,
                          const void *value, size_t value_len) {
    size_t length = D2K_NLA_HDRLEN + value_len;
    wr16(body + used, (uint16_t)length);
    wr16(body + used + 2, type);
    memcpy(body + used + D2K_NLA_HDRLEN, value, value_len);
    size_t aligned = (used + length + 3u) & ~(size_t)3u;
    memset(body + used + length, 0, aligned - (used + length));
    return aligned;
}

static void print_hex(const char *name, const uint8_t *bytes, size_t length) {
    printf("%s ", name);
    for (size_t i = 0; i < length; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

static size_t append_rule(uint8_t *out, size_t used, uint32_t mark,
                          uint32_t mask, int have_mask, uint32_t flags) {
    uint8_t body[64];
    size_t body_len = RM_FIB_HDR;
    memset(body, 0, sizeof body);
    body[0] = 2;
    wr32(body + 8, flags);
    body_len = append_attr(body, body_len, RM_FRA_FWMARK, &mark, 4);
    if (have_mask) {
        body_len = append_attr(body, body_len, RM_FRA_FWMASK, &mask, 4);
    }
    return append_message(out, used, RM_RTM_NEWRULE, D2K_NLM_F_REQUEST, 1,
                          body, body_len);
}

static void print_rules(const char *name, const uint8_t *buffer, size_t length) {
    d2k_fwsel selectors[32];
    size_t found = 0;
    int32_t kerr = 0;
    int rc = d2k_routemark_parse(selectors, 32, &found, buffer, length, &kerr);
    printf("rules %s rc=%d n=%zu kerr=%d", name, rc,
           found < 32 ? found : 32, (int)kerr);
    for (size_t i = 0; i < found && i < 2; i++) {
        printf(" mark%zu=0x%x mask%zu=0x%x family%zu=%u", i, selectors[i].mark,
               i, selectors[i].mask, i, selectors[i].family);
    }
    printf("\n");
}

static size_t append_route(uint8_t *out, size_t used, uint16_t flags,
                           const uint8_t *body, size_t body_len) {
    return append_message(out, used, RM_RTM_NEWROUTE, flags, 1, body, body_len);
}

static void print_lookup(const char *name, const uint8_t *buffer,
                         size_t length) {
    uint32_t oifs[16];
    size_t found = 0;
    int32_t kerr = 0;
    int rc = d2k_routemark_lookup_parse(oifs, 16, &found, buffer, length, &kerr);
    printf("lookup %s rc=%d n=%zu kerr=%d oifs=", name, rc,
           found < 16 ? found : 16, (int)kerr);
    for (size_t i = 0; i < found && i < 16; i++) {
        printf("%s%u", i ? "," : "", oifs[i]);
    }
    printf("\n");
}

int main(void) {
    uint8_t request[128];
    size_t length = d2k_routemark_request(request, sizeof request, 2, 7);
    print_hex("request rules_v4", request, length);
    length = d2k_routemark_request(request, sizeof request, 10, 8);
    print_hex("request rules_v6", request, length);
    length = d2k_routemark_lookup_request(request, sizeof request, 2, 9);
    print_hex("request lookup_v4", request, length);
    length = d2k_routemark_lookup_request(request, sizeof request, 10, 10);
    print_hex("request lookup_v6", request, length);

    uint8_t buffer[512];
    size_t used = 0;
    used = append_rule(buffer, used, 0x1234, 0xff00, 1, 0);
    used = append_rule(buffer, used, 0x200, 0, 0, 0);
    used = append_message(buffer, used, D2K_NLMSG_DONE, 0, 1, NULL, 0);
    print_rules("two", buffer, used);

    used = 0;
    used = append_rule(buffer, used, 0x1234, 0, 1, 0);
    used = append_rule(buffer, used, 0x500, 0xff, 1, RM_FIB_RULE_INVERT);
    used = append_message(buffer, used, D2K_NLMSG_DONE, 0, 1, NULL, 0);
    print_rules("skip", buffer, used);

    used = 0;
    used = append_rule(buffer, used, 0x1234, 0xff00, 1, 0);
    print_rules("incomplete", buffer, used);

    // Только маска без метки: C оставляет mark=0 & mask.
    used = 0;
    {
        uint8_t body[64];
        size_t body_len = RM_FIB_HDR;
        uint32_t mask = 0xff00;
        memset(body, 0, sizeof body);
        body[0] = 2;
        body_len = append_attr(body, body_len, RM_FRA_FWMASK, &mask, 4);
        used = append_message(buffer, used, RM_RTM_NEWRULE, D2K_NLM_F_REQUEST,
                              1, body, body_len);
        used = append_message(buffer, used, D2K_NLMSG_DONE, 0, 1, NULL, 0);
    }
    print_rules("mask_only", buffer, used);

    // FWMARK длиной 8: C читает первые 4 байта, как и Rust.
    used = 0;
    {
        uint8_t body[64];
        size_t body_len = RM_FIB_HDR;
        uint32_t mark = 0x4321;
        uint8_t wide[8] = {0};
        memcpy(wide, &mark, 4);
        memset(body, 0, sizeof body);
        body[0] = 2;
        body_len = append_attr(body, body_len, RM_FRA_FWMARK, wide, 8);
        used = append_message(buffer, used, RM_RTM_NEWRULE, D2K_NLM_F_REQUEST,
                              1, body, body_len);
        used = append_message(buffer, used, D2K_NLMSG_DONE, 0, 1, NULL, 0);
    }
    print_rules("wide_mark", buffer, used);

    // Повреждённый атрибут (длина 3 < заголовка) — отказ разбора.
    used = 0;
    {
        uint8_t body[32];
        memset(body, 0, sizeof body);
        body[0] = 2;
        wr16(body + RM_FIB_HDR, 3);
        wr16(body + RM_FIB_HDR + 2, RM_FRA_FWMARK);
        used = append_message(buffer, used, RM_RTM_NEWRULE, D2K_NLM_F_REQUEST,
                              1, body, RM_FIB_HDR + 4);
    }
    print_rules("malformed", buffer, used);

    // DONE первым: C прекращает разбор и не смотрит на следующие правила.
    used = 0;
    used = append_message(buffer, used, D2K_NLMSG_DONE, 0, 1, NULL, 0);
    used = append_rule(buffer, used, 0x1234, 0xff00, 1, 0);
    print_rules("done_first", buffer, used);

    // Обрезанное сообщение: nlmsg_len больше буфера.
    used = 0;
    memset(buffer, 0, 17);
    wr32(buffer, 32);
    wr16(buffer + 4, RM_RTM_NEWRULE);
    print_rules("truncated", buffer, 17);

    // DONE и 1-3 байта хвоста: это ещё успешный конец дампа.
    used = 0;
    used = append_message(buffer, used, D2K_NLMSG_DONE, 0, 1, NULL, 0);
    buffer[used] = 0;
    buffer[used + 1] = 0;
    buffer[used + 2] = 0;
    print_rules("done_tail", buffer, used + 3);

    // Атрибут обещает 20 байт, а в теле только 8.
    used = 0;
    {
        uint8_t body[32];
        memset(body, 0, sizeof body);
        body[0] = 2;
        wr16(body + RM_FIB_HDR, 20);
        wr16(body + RM_FIB_HDR + 2, RM_FRA_FWMARK);
        used = append_message(buffer, used, RM_RTM_NEWRULE, D2K_NLM_F_REQUEST,
                              1, body, RM_FIB_HDR + 8);
    }
    print_rules("bad_attr", buffer, used);

    // NLMSG_ERROR короче 4 байт: C отдаёт kerr=0 и rc=-1.
    used = 0;
    uint8_t short_error[18];
    memset(short_error, 0, sizeof short_error);
    wr32(short_error, sizeof short_error);
    wr16(short_error + 4, D2K_NLMSG_ERROR);
    used = append_message(buffer, 0, D2K_NLMSG_ERROR, 0, 1,
                          short_error + 16, 2);
    print_rules("short_error", buffer, used);

    used = 0;
    int32_t error = -22;
    used = append_message(buffer, used, D2K_NLMSG_ERROR, 0, 1,
                          (const uint8_t *)&error, sizeof error);
    print_rules("error", buffer, used);

    used = 0;
    uint8_t route[512];
    size_t route_len = RM_RTMSG;
    memset(route, 0, sizeof route);
    route[0] = 2;
    route[7] = RM_RTN_UNICAST;
    uint32_t ifindex = 5;
    route_len = append_attr(route, route_len, RM_RTA_OIF, &ifindex, 4);
    uint8_t multipath[256];
    size_t mp_len = 0;
    uint16_t hop_len = (uint16_t)RM_RTNH_LEN;
    wr16(multipath + mp_len, hop_len);
    wr32(multipath + mp_len + 4, 8);
    mp_len += RM_RTNH_LEN;
    wr16(multipath + mp_len, hop_len);
    wr32(multipath + mp_len + 4, 5);
    mp_len += RM_RTNH_LEN;
    wr16(multipath + mp_len, hop_len);
    wr32(multipath + mp_len + 4, 0);
    mp_len += RM_RTNH_LEN;
    route_len = append_attr(route, route_len, RM_RTA_MULTIPATH, multipath, mp_len);
    used = append_route(buffer, 0, D2K_NLM_F_REQUEST, route, route_len);
    print_lookup("oif_multipath", buffer, used);

    memset(route, 0, sizeof route);
    route[0] = 2;
    route[7] = RM_RTN_UNICAST;
    route_len = RM_RTMSG;
    mp_len = 0;
    for (uint32_t hop = 100; hop < 120; hop++) {
        wr16(multipath + mp_len, hop_len);
        wr32(multipath + mp_len + 4, hop);
        mp_len += RM_RTNH_LEN;
    }
    route_len = append_attr(route, route_len, RM_RTA_MULTIPATH, multipath, mp_len);
    used = append_route(buffer, 0, D2K_NLM_F_REQUEST, route, route_len);
    print_lookup("many_hops", buffer, used);

    memset(route, 0, sizeof route);
    route[0] = 2;
    route[7] = RM_RTN_UNICAST;
    used = append_route(buffer, 0, D2K_NLM_F_REQUEST, route, RM_RTMSG);
    print_lookup("no_device", buffer, used);

    memset(route, 0, sizeof route);
    route[0] = 2;
    route[7] = 7;
    used = append_route(buffer, 0, D2K_NLM_F_REQUEST, route, RM_RTMSG);
    print_lookup("unreachable", buffer, used);

    memset(route, 0, sizeof route);
    route[0] = 2;
    route[7] = RM_RTN_UNICAST;
    route_len = RM_RTMSG;
    uint16_t short_hop = 4;
    wr16(route + route_len, short_hop);
    wr16(route + route_len + 2, RM_RTA_MULTIPATH);
    route_len += 8;
    used = append_route(buffer, 0, D2K_NLM_F_REQUEST, route, route_len);
    print_lookup("bad_multipath", buffer, used);

    // Явно повреждённый hop: длина 4 меньше struct rtnexthop.
    memset(route, 0, sizeof route);
    route[0] = 2;
    route[7] = RM_RTN_UNICAST;
    route_len = RM_RTMSG;
    uint8_t bad_hop[8] = {0};
    wr16(bad_hop, 4);
    route_len = append_attr(route, route_len, RM_RTA_MULTIPATH, bad_hop,
                            sizeof bad_hop);
    used = append_route(buffer, 0, D2K_NLM_F_REQUEST, route, route_len);
    print_lookup("bad_hop", buffer, used);

    // Пустой multipath: маршрут без устройств (rc=1, n=0).
    memset(route, 0, sizeof route);
    route[0] = 2;
    route[7] = RM_RTN_UNICAST;
    route_len = RM_RTMSG;
    uint8_t empty = 0;
    route_len = append_attr(route, route_len, RM_RTA_MULTIPATH, &empty, 0);
    used = append_route(buffer, 0, D2K_NLM_F_REQUEST, route, route_len);
    print_lookup("empty_multipath", buffer, used);

    // Только DONE: ответ неполный (rc=0), а не маршрут.
    used = append_message(buffer, 0, D2K_NLMSG_DONE, 0, 1, NULL, 0);
    print_lookup("done_only", buffer, used);

    // Обрезанный маршрут: nlmsg_len больше буфера.
    used = 0;
    memset(buffer, 0, 20);
    wr32(buffer, 32);
    wr16(buffer + 4, RM_RTM_NEWROUTE);
    print_lookup("truncated", buffer, 20);

    // NLMSG_ERROR короче 4 байт: kerr=0, rc=-1.
    used = 0;
    {
        uint8_t short_body[2] = {0, 0};
        used = append_message(buffer, used, D2K_NLMSG_ERROR, 0, 1, short_body, 2);
    }
    print_lookup("short_error", buffer, used);

    used = 0;
    error = -101;
    used = append_message(buffer, used, D2K_NLMSG_ERROR, 0, 1,
                          (const uint8_t *)&error, sizeof error);
    print_lookup("error", buffer, used);

    used = 0;
    used = append_route(buffer, used, D2K_NLM_F_REQUEST, route, 8);
    print_lookup("incomplete", buffer, used);

    used = 0;
    used = append_message(buffer, used, RM_RTM_NEWRULE, 0, 1, NULL, 0);
    printf("watch rule=%d\n", d2k_routemark_watch_relevant(buffer, used));
    used = 0;
    used = append_route(buffer, used, 0, route, RM_RTMSG);
    printf("watch default_route=%d\n", d2k_routemark_watch_relevant(buffer, used));
    memset(route, 0, sizeof route);
    route[1] = 24;
    used = 0;
    used = append_route(buffer, used, 0, route, RM_RTMSG);
    printf("watch other_route=%d\n", d2k_routemark_watch_relevant(buffer, used));
    printf("watch malformed=%d\n", d2k_routemark_watch_relevant(buffer, 3));
    return 0;
}
