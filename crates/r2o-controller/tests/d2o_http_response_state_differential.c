#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_httpsearch.h"
#include "d2k_verify.h"

typedef struct {
    const uint8_t *input;
    size_t input_len;
    size_t offset;
    int eof;
    uint8_t received[8192];
    size_t received_len;
} fixture_reader;

static long fixture_read(void *opaque, uint8_t *out, size_t capacity, int wait_ms,
                         char *err, size_t errcap)
{
    fixture_reader *reader = opaque;
    (void)wait_ms;
    if (reader->offset == reader->input_len) {
        if (reader->eof) return 0;
        snprintf(err, errcap, "HTTP read timeout");
        return -1;
    }
    size_t count = reader->input_len - reader->offset;
    if (count > capacity) count = capacity;
    if (count > sizeof(reader->received) - reader->received_len)
        count = sizeof(reader->received) - reader->received_len;
    if (!count) {
        snprintf(err, errcap, "fixture response exceeds capture limit");
        return -1;
    }
    memcpy(out, reader->input + reader->offset, count);
    memcpy(reader->received + reader->received_len, out, count);
    reader->offset += count;
    reader->received_len += count;
    return (long)count;
}

static const char *answer_name(d2k_hs_answer answer)
{
    switch (answer) {
    case D2K_HS_REAL: return "real";
    case D2K_HS_INJECTED: return "injected";
    case D2K_HS_GARBAGE: return "garbage";
    case D2K_HS_CUT: return "cut";
    case D2K_HS_SILENT: return "silent";
    case D2K_HS_CLOSED: return "closed";
    case D2K_HS_EARLY: return "early";
    case D2K_HS_DECOY: return "decoy";
    default: return "other";
    }
}

static d2k_hs_answer classify_response(const char *host, const uint8_t *input,
                                       size_t input_len, int eof, int *complete)
{
    fixture_reader reader = { .input = input, .input_len = input_len, .eof = eof };
    d2k_http_read_result response;
    char err[160] = "";
    d2k_http_read_response(fixture_read, &reader, 10, &response, err, sizeof(err));
    *complete = response.complete;
    if (!reader.received_len)
        return strstr(err, "timeout") ? D2K_HS_SILENT : D2K_HS_CLOSED;

    size_t judge_len = reader.received_len < 4095 ? reader.received_len : 4095;
    d2k_hs_answer answer = d2k_hs_judge(host, (const char *)reader.received,
                                        judge_len, 98000, 99000);
    if (response.reply.outcome == D2K_HTTP_BLOCKED)
        answer = D2K_HS_INJECTED;
    if (answer != D2K_HS_REAL) return answer;
    if (!response.complete) return D2K_HS_CUT;
    return answer;
}

int main(void)
{
    static const uint8_t portal[] =
        "HTTP/1.1 302 Moved Temporarily\r\n"
        "Location: http://lawfilter.ertelecom.ru/\r\n"
        "Content-Length: 100\r\n\r\nshort";
    static const uint8_t partial_head[] =
        "HTTP/1.1 302 Moved Temporarily\r\n"
        "Location: http://lawfilter.ertelecom.ru";
    static const uint8_t blocked_body[] =
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 21\r\n\r\naccess blocked by rkn";
    static const uint8_t portal_body[] =
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 15\r\n\r\neais.rkn.gov.ru";
    static const uint8_t gzip_body[] =
        "HTTP/1.1 403 Forbidden\r\nContent-Encoding: gzip\r\n"
        "Content-Length: 21\r\n\r\naccess blocked by rkn";
    static const uint8_t upgrade[] =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n";
    static const uint8_t invalid_framing[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 1 2\r\nConnection: close\r\n\r\n";
    static const uint8_t body_decoy[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nsee disk.rzd.ru";
    static const uint8_t both_cl_te[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    static const uint8_t close_delimited[] = "HTTP/1.0 200 OK\r\n\r\nhello";
    static const uint8_t timeout_mid_body[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc";
    static const char large_head[] = "HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n";
    uint8_t large_inside[sizeof large_head - 1 + 5000];
    uint8_t large_outside[sizeof large_head - 1 + 5000];
    memset(large_inside, 'a', sizeof large_inside);
    memset(large_outside, 'a', sizeof large_outside);
    memcpy(large_inside, large_head, sizeof large_head - 1);
    memcpy(large_outside, large_head, sizeof large_head - 1);
    size_t decoy_at = 4096 - (sizeof large_head - 1) - 12;
    memcpy(large_inside + sizeof large_head - 1 + decoy_at, "disk.rzd.ru", 11);
    memcpy(large_outside + sizeof large_head - 1 + decoy_at + 1, "disk.rzd.ru", 11);
    int portal_complete = 1, partial_complete = 1;
    int blocked_complete = 0, portal_body_complete = 0, gzip_complete = 0;
    int upgrade_complete = 1, invalid_complete = 1, body_decoy_complete = 0;
    int both_cl_te_complete = 1, close_complete = 0, timeout_complete = 1;
    int large_inside_complete = 0, large_outside_complete = 0;
    d2k_hs_answer portal_answer = classify_response(
        "rutracker.org", portal, sizeof(portal) - 1, 0, &portal_complete);
    d2k_hs_answer partial_answer = classify_response(
        "rutracker.org", partial_head, sizeof(partial_head) - 1, 0, &partial_complete);
    d2k_hs_answer blocked_answer = classify_response(
        "rutracker.org", blocked_body, sizeof(blocked_body) - 1, 0, &blocked_complete);
    d2k_hs_answer portal_body_answer = classify_response(
        "rutracker.org", portal_body, sizeof(portal_body) - 1, 0, &portal_body_complete);
    d2k_hs_answer gzip_answer = classify_response(
        "rutracker.org", gzip_body, sizeof(gzip_body) - 1, 0, &gzip_complete);
    d2k_hs_answer upgrade_answer = classify_response(
        "rutracker.org", upgrade, sizeof(upgrade) - 1, 0, &upgrade_complete);
    d2k_hs_answer invalid_answer = classify_response(
        "rutracker.org", invalid_framing, sizeof(invalid_framing) - 1, 0, &invalid_complete);
    d2k_hs_answer body_decoy_answer = classify_response(
        "rutracker.org", body_decoy, sizeof(body_decoy) - 1, 0, &body_decoy_complete);
    d2k_hs_answer both_cl_te_answer = classify_response(
        "rutracker.org", both_cl_te, sizeof(both_cl_te) - 1, 1, &both_cl_te_complete);
    d2k_hs_answer close_answer = classify_response(
        "rutracker.org", close_delimited, sizeof(close_delimited) - 1, 1, &close_complete);
    d2k_hs_answer timeout_answer = classify_response(
        "rutracker.org", timeout_mid_body, sizeof(timeout_mid_body) - 1, 0,
        &timeout_complete);
    d2k_hs_answer large_inside_answer = classify_response(
        "rutracker.org", large_inside, sizeof large_inside, 1, &large_inside_complete);
    d2k_hs_answer large_outside_answer = classify_response(
        "rutracker.org", large_outside, sizeof large_outside, 1, &large_outside_complete);

    printf("portal_truncated=%s\npartial_header_timeout=%s\n"
           "blocked_body=%s/%d\nportal_body=%s/%d\ngzip_body=%s/%d\n"
           "upgrade=%s/%d\ninvalid_framing=%s/%d\nbody_decoy=%s/%d\n"
           "both_cl_te=%s/%d\nclose_delimited=%s/%d\ntimeout_mid_body=%s/%d\n"
           "large_inside=%s/%d\nlarge_outside=%s/%d\n",
           answer_name(portal_answer), answer_name(partial_answer),
           answer_name(blocked_answer), blocked_complete,
           answer_name(portal_body_answer), portal_body_complete,
           answer_name(gzip_answer), gzip_complete,
           answer_name(upgrade_answer), upgrade_complete,
           answer_name(invalid_answer), invalid_complete,
           answer_name(body_decoy_answer), body_decoy_complete,
           answer_name(both_cl_te_answer), both_cl_te_complete,
           answer_name(close_answer), close_complete,
           answer_name(timeout_answer), timeout_complete,
           answer_name(large_inside_answer), large_inside_complete,
           answer_name(large_outside_answer), large_outside_complete);
    return portal_answer == D2K_HS_INJECTED && !portal_complete &&
                   partial_answer == D2K_HS_GARBAGE && !partial_complete &&
                   blocked_answer == D2K_HS_INJECTED && blocked_complete &&
                   portal_body_answer == D2K_HS_INJECTED && portal_body_complete &&
                   gzip_answer == D2K_HS_REAL && gzip_complete &&
                   upgrade_answer == D2K_HS_CUT && !upgrade_complete &&
                   invalid_answer == D2K_HS_CUT && !invalid_complete &&
                   body_decoy_answer == D2K_HS_DECOY && body_decoy_complete &&
                   both_cl_te_answer == D2K_HS_CUT && !both_cl_te_complete &&
                   close_answer == D2K_HS_REAL && close_complete &&
                   timeout_answer == D2K_HS_CUT && !timeout_complete &&
                   large_inside_answer == D2K_HS_DECOY && large_inside_complete &&
                   large_outside_answer == D2K_HS_REAL && large_outside_complete ? 0 : 1;
}
