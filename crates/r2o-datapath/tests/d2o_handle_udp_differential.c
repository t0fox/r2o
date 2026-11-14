/* C-оракул: ветви handle_udp — STUN voice, QUIC Initial, серверное
 * направление, отказ таблицы потоков. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_session.h"

static uint8_t buffer[2048];

static void w16be(uint8_t *o, unsigned v) {
    o[0] = (uint8_t)(v >> 8);
    o[1] = (uint8_t)v;
}

static size_t udp_packet(uint8_t *o, const uint8_t *src, const uint8_t *dst,
                         uint16_t sport, uint16_t dport, const uint8_t *payload,
                         size_t payload_len) {
    size_t total = 28 + payload_len;
    memset(o, 0, total);
    o[0] = 0x45;
    w16be(o + 2, (unsigned)total);
    o[8] = 64;
    o[9] = 17;
    memcpy(o + 12, src, 4);
    memcpy(o + 16, dst, 4);
    w16be(o + 20, sport);
    w16be(o + 22, dport);
    w16be(o + 24, (unsigned)(8 + payload_len));
    if (payload_len) memcpy(o + 28, payload, payload_len);
    return total;
}

static void stun_request(uint8_t *o) {
    memset(o, 0, 20);
    o[0] = 0; o[1] = 1; /* Binding request */
    o[4] = 0x21; o[5] = 0x12; o[6] = 0xA4; o[7] = 0x42;
    for (int i = 8; i < 20; i++) o[i] = (uint8_t)(0x40 + i);
}

static void stun_response(uint8_t *o) {
    stun_request(o);
    o[0] = 1; o[1] = 1; /* Binding success response */
}

static void print(const char *name, const d2k_session *session) {
    printf("%s flows=%zu refusals=%llu hellos=%llu with_sni=%llu exchanges=%llu\n",
           name, d2k_session_flows_udp(session),
           (unsigned long long)d2k_session_refusals_udp(session),
           (unsigned long long)d2k_session_hellos(session),
           (unsigned long long)d2k_session_with_sni(session),
           (unsigned long long)d2k_session_exchanges(session));
}

static void print_short(const char *name, const d2k_session *session) {
    printf("%s flows=%zu refusals=%llu exchanges=%llu\n", name,
           d2k_session_flows_udp(session),
           (unsigned long long)d2k_session_refusals_udp(session),
           (unsigned long long)d2k_session_exchanges(session));
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 3;
    uint8_t initial[2048];
    size_t initial_len = fread(initial, 1, sizeof initial, file);
    fclose(file);
    file = fopen(argv[2], "rb");
    if (!file) return 3;
    uint8_t unnamed[2048];
    size_t unnamed_len = fread(unnamed, 1, sizeof unnamed, file);
    fclose(file);

    static const uint8_t client[4] = {192, 0, 2, 10};
    static const uint8_t server[4] = {198, 51, 100, 20};
    uint8_t payload[32];
    uint8_t result_buffer[4096];
    size_t length;
    uint8_t response[32];

    /* QUIC Initial из клиента, ответ сервера, обратный Initial. */
    d2k_session *quic = d2k_session_new(64, 0);
    d2k_session_set_hook(quic, D2K_HOOK_POSTROUTING);
    length = udp_packet(buffer, client, server, 50001, 443, initial, initial_len);
    (void)d2k_session_packet(quic, buffer, length, 1000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print("Q1", quic);
    d2k_session_set_hook(quic, D2K_HOOK_INPUT);
    length = udp_packet(buffer, server, client, 443, 50001, (const uint8_t *)"resp", 4);
    (void)d2k_session_packet(quic, buffer, length, 2000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print("Q2", quic);
    (void)d2k_session_packet(quic, buffer, length, 3000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print("Q3", quic);
    length = udp_packet(buffer, server, client, 443, 50002, initial, initial_len);
    (void)d2k_session_packet(quic, buffer, length, 4000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print("Q4", quic);
    d2k_session_free(quic);

    /* STUN voice: запрос на медиапорт Дискорда, затем два ответа. */
    d2k_session *voice = d2k_session_new(64, 0);
    d2k_session_set_hook(voice, D2K_HOOK_POSTROUTING);
    stun_request(payload);
    length = udp_packet(buffer, client, server, 50000, 50010, payload, 20);
    (void)d2k_session_packet(voice, buffer, length, 1000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    d2k_session_set_hook(voice, D2K_HOOK_INPUT);
    stun_response(response);
    length = udp_packet(buffer, server, client, 50010, 50000, response, 20);
    (void)d2k_session_packet(voice, buffer, length, 2000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print_short("V1", voice);
    (void)d2k_session_packet(voice, buffer, length, 3000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print_short("V2", voice);
    d2k_session_free(voice);


    /* Отказ таблицы: 60 корректных UDP-потоков при 64 слотах (порог 3/4). */
    d2k_session *refusal = d2k_session_new(64, 0);
    d2k_session_set_hook(refusal, D2K_HOOK_POSTROUTING);
    for (unsigned i = 0; i < 60; i++) {
        length = udp_packet(buffer, client, server, (uint16_t)(20000 + i),
                            50010, (const uint8_t *)"x", 1);
        (void)d2k_session_packet(refusal, buffer, length, 1000 + i,
                                 result_buffer, sizeof result_buffer, &(d2k_result){0});
    }
    print_short("R1", refusal);
    d2k_session_free(refusal);

    /* Initial без имени: saw_initial, повтор PTO, затем sweep без ответа. */
    d2k_session *silent = d2k_session_new(64, 0);
    d2k_session_set_hook(silent, D2K_HOOK_POSTROUTING);
    length = udp_packet(buffer, client, server, 50003, 443, unnamed, unnamed_len);
    (void)d2k_session_packet(silent, buffer, length, 1000,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    (void)d2k_session_packet(silent, buffer, length, 1800,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    d2k_session_set_udp_reverse_hook(silent, 1);
    size_t told = d2k_session_sweep(silent, 1000ull + 2000000000ull + 1ull);
    printf("S1 flows=%zu hellos=%llu suspects=%zu\n",
           d2k_session_flows_udp(silent),
           (unsigned long long)d2k_session_hellos(silent), told);
    d2k_session_free(silent);

    /* Ответ после последнего PTO: sweep молчит. */
    d2k_session *answered = d2k_session_new(64, 0);
    d2k_session_set_hook(answered, D2K_HOOK_POSTROUTING);
    length = udp_packet(buffer, client, server, 50004, 443, unnamed, unnamed_len);
    (void)d2k_session_packet(answered, buffer, length, 1000,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    (void)d2k_session_packet(answered, buffer, length, 1800,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    d2k_session_set_hook(answered, D2K_HOOK_INPUT);
    length = udp_packet(buffer, server, client, 443, 50004, (const uint8_t *)"resp", 4);
    (void)d2k_session_packet(answered, buffer, length, 1900,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    d2k_session_set_udp_reverse_hook(answered, 1);
    told = d2k_session_sweep(answered, 1000ull + 2000000000ull + 1ull);
    printf("S2 flows=%zu hellos=%llu suspects=%zu\n",
           d2k_session_flows_udp(answered),
           (unsigned long long)d2k_session_hellos(answered), told);
    d2k_session_free(answered);
    return 0;
}
