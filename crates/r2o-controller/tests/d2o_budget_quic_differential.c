/* C oracle budget_quic: verify.c + mock quic_budget_io. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "verify.c"

/* Минимальные стабы внешних символов, которые тянет verify.c через
 * h3_* / qb_*. Тела production-функций не копируются. */
size_t d2k_h3_request(const char *host, const char *path, uint8_t *out, size_t cap)
{
    (void)host; (void)path; (void)out; (void)cap;
    return 0;
}
static int mock_h3_status_code;

int d2k_h3_status(const uint8_t *buf, size_t n, int *status)
{
    (void)buf;
    if (status) *status = n && mock_h3_status_code ? mock_h3_status_code : 0;
    return 0;
}
int d2k_qc_stream_send(d2k_qc *c, uint64_t stream_id, const uint8_t *data, size_t n,
                       int fin, char *err, size_t cap)
{
    (void)c; (void)stream_id; (void)data; (void)n; (void)fin; (void)err; (void)cap;
    return -1;
}
long d2k_qc_stream_recv(d2k_qc *c, uint64_t *stream_out, uint8_t *buf, size_t cap,
                        int timeout_ms, char *err, size_t errcap)
{
    (void)c; (void)stream_out; (void)buf; (void)cap; (void)timeout_ms; (void)err; (void)errcap;
    return -1;
}
void d2k_qc_datagrams(const d2k_qc *c, uint64_t *tx, uint64_t *rx)
{
    (void)c;
    if (tx) *tx = 0;
    if (rx) *rx = 0;
}
void d2k_qc_app_progress(const d2k_qc *c, uint64_t *bytes, int *complete)
{
    (void)c;
    if (bytes) *bytes = 0;
    if (complete) *complete = 0;
}

typedef struct {
    long packets[8];
    size_t packet_count;
    size_t packet_index;
    uint64_t progress[8];
    int complete[8];
    size_t progress_count;
    size_t progress_index;
    int request_rc;
    int recv_rc;
    int recv_bytes;
    int h3_status;
} mock_quic;

static int mock_request(void *ctx, uint64_t sid, char *err, size_t cap)
{
    mock_quic *q = ctx;
    (void)sid;
    if (q->request_rc != 0) snprintf(err, cap, "request failed");
    return q->request_rc;
}

static long mock_recv(void *ctx, uint8_t *buf, size_t cap, char *err, size_t cap2)
{
    mock_quic *q = ctx;
    (void)buf; (void)cap;
    if (q->recv_rc < 0) snprintf(err, cap2, "recv failed");
    return q->recv_rc;
}

static void mock_progress(void *ctx, uint64_t *bytes, int *complete)
{
    mock_quic *q = ctx;
    size_t i = q->progress_index < q->progress_count ? q->progress_index : q->progress_count - 1;
    *bytes = q->progress[i];
    *complete = q->complete[i];
    if (q->progress_index + 1 < q->progress_count) q->progress_index++;
}

static long mock_packets(void *ctx)
{
    mock_quic *q = ctx;
    size_t i = q->packet_index < q->packet_count ? q->packet_index : q->packet_count - 1;
    long value = q->packets[i];
    if (q->packet_index + 1 < q->packet_count) q->packet_index++;
    return value;
}

static void run(const char *name, mock_quic *q, int deadline, unsigned budget)
{
    quic_budget_io io = {
        .request = mock_request,
        .recv = mock_recv,
        .progress = mock_progress,
        .packets = mock_packets,
        .ctx = q,
    };
    mock_h3_status_code = q->h3_status;
    d2k_ver_result result;
    memset(&result, 0, sizeof result);
    budget_quic(&io, deadline, budget, &result);
    printf("quic|%s|budget=%d|need=%u|requests=%u|packets=%u|uncountable=%d|reason=%s\n",
           name, (int)result.budget, result.budget_need, result.budget_requests,
           result.budget_packets, result.budget_uncountable, result.reason);
}

int main(void)
{
    {
        mock_quic q = {0};
        q.packets[0] = -1; q.packet_count = 1;
        q.progress[0] = 0; q.progress_count = 1;
        run("packets-negative", &q, 100, 1);
    }
    {
        mock_quic q = {0};
        q.packets[0] = 6; q.packet_count = 1;
        q.progress[0] = 100; q.progress[1] = 120;
        q.complete[0] = 0; q.complete[1] = 1;
        q.progress_count = 2;
        q.recv_rc = 1;
        run("grew", &q, 100, 3);
    }
    {
        mock_quic q = {0};
        q.packets[0] = 0; q.packet_count = 1;
        q.progress[0] = 0; q.progress_count = 1;
        q.complete[0] = 1;
        q.request_rc = -1;
        run("request-error", &q, 100, 2);
    }
    {
        mock_quic q = {0};
        q.packets[0] = 0; q.packet_count = 1;
        q.progress[0] = 0; q.progress_count = 1;
        q.complete[0] = 0;
        q.recv_rc = 0;
        run("silence", &q, 20, 1);
    }
    {
        mock_quic q = {0};
        q.packets[0] = 0; q.packet_count = 1;
        q.progress[0] = 0; q.progress_count = 1;
        q.complete[0] = 0;
        q.recv_rc = -1;
        run("recv-error", &q, 20, 1);
    }
    {
        mock_quic q = {0};
        q.packets[0] = 0; q.packets[1] = 2; q.packets[2] = 2;
        q.packet_count = 3;
        q.progress[0] = 0; q.progress[1] = 120; q.progress[2] = 130;
        q.complete[0] = 1; q.complete[1] = 1; q.complete[2] = 1;
        q.progress_count = 3;
        q.recv_rc = 1;
        q.h3_status = 200;
        run("complete-headers-pass", &q, 100, 1);
    }
    {
        mock_quic q = {0};
        q.packets[0] = 0; q.packet_count = 1;
        q.progress[0] = 0; q.progress_count = 1;
        q.complete[0] = 1;
        q.recv_rc = 1;
        q.h3_status = 0;
        run("complete-headers-unparsed", &q, 100, 1);
    }
    {
        mock_quic q = {0};
        q.packets[0] = 0; q.packet_count = 1;
        q.progress[0] = 0; q.progress_count = 1;
        q.complete[0] = 1;
        q.recv_rc = 0;
        q.h3_status = 0;
        run("complete-headers-silence", &q, 20, 1);
    }
    {
        mock_quic q = {0};
        q.packets[0] = 0; q.packet_count = 1;
        q.progress[0] = 0; q.progress_count = 1;
        q.complete[0] = 1;
        q.recv_rc = -1;
        run("complete-closed", &q, 100, 1);
    }
    return 0;
}
