/* C/Rust differential: ветвь on_suspect «чистое рукопожатие».
 *
 * C `on_suspect` гасит только коды рукопожатия (RST/REPEAT/SILENT) и только
 * для того же клиента (имя + транспорт + семейство + IP клиента), без плана.
 * Сценарии повторяют эту матрицу; Rust-сторона — `R2oCleanHandshakeCache` +
 * `r2o_suspect_clean_handshake_suppressed`.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

int d2k_hello_ech_offer(const uint8_t *bytes, size_t length, uint8_t *config_id)
{
    (void)bytes;
    (void)length;
    (void)config_id;
    return 0;
}

static void make_event(d2k_ev *ev, const uint8_t *client, const uint8_t *server,
                       uint8_t family, uint16_t sport, uint16_t dport,
                       uint8_t code, uint8_t planned)
{
    memset(ev, 0, sizeof *ev);
    ev->family = family;
    ev->transport = 6;
    ev->low_port = sport;
    ev->high_port = dport;
    ev->code = code;
    ev->planned = planned;
    if (family == 6) {
        memcpy(ev->low_ip, client, 16);
        memcpy(ev->high_ip, server, 16);
    } else {
        memcpy(ev->low_ip, client, 4);
        memcpy(ev->high_ip, server, 4);
    }
}

/* Дословный перенос гейта из `on_suspect` (sched.c:8573-8589). */
static int suspect_suppressed(const d2k_sched *s, const char *name,
                              const d2k_ev *ev)
{
    return ev->transport == 6 &&
           ev->planned != D2K_LINK_PLANNED_YES &&
           (ev->code == D2K_SUSPECT_RST ||
            ev->code == D2K_SUSPECT_REPEAT ||
            ev->code == D2K_SUSPECT_SILENT) &&
           clean_handshake_recent((d2k_sched *)s, name, ev);
}

int main(void)
{
    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    if (!scheduler) return 1;
    scheduler->now_ms = 1000;

    const uint8_t client_a[16] = {192, 0, 2, 10};
    const uint8_t client_b[16] = {192, 0, 2, 11};
    const uint8_t server4[16] = {198, 51, 100, 80};
    const uint8_t client6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0x10};
    const uint8_t server6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0x80};
    d2k_ev event;
    make_event(&event, client_a, server4, 4, 45000, 443,
               D2K_SUSPECT_RST, D2K_LINK_PLANNED_NO);
    note_clean_handshake(scheduler, "clean.example", &event);

    make_event(&event, client_a, server4, 4, 45000, 443,
               D2K_SUSPECT_RST, D2K_LINK_PLANNED_NO);
    printf("client_a_rst=%d\n", suspect_suppressed(scheduler, "clean.example", &event));
    event.code = D2K_SUSPECT_REPEAT;
    printf("client_a_repeat=%d\n", suspect_suppressed(scheduler, "clean.example", &event));
    event.code = D2K_SUSPECT_SILENT;
    printf("client_a_silent=%d\n", suspect_suppressed(scheduler, "clean.example", &event));
    event.code = D2K_SUSPECT_RST_CUT;
    printf("client_a_rst_cut=%d\n", suspect_suppressed(scheduler, "clean.example", &event));
    event.code = D2K_SUSPECT_RST_AFTER_APP;
    printf("client_a_rst_after_app=%d\n", suspect_suppressed(scheduler, "clean.example", &event));
    event.code = D2K_SUSPECT_FIN_RETRY;
    printf("client_a_fin_retry=%d\n", suspect_suppressed(scheduler, "clean.example", &event));
    event.code = D2K_SUSPECT_TCP_STALL;
    printf("client_a_tcp_stall=%d\n", suspect_suppressed(scheduler, "clean.example", &event));

    make_event(&event, client_b, server4, 4, 45001, 443,
               D2K_SUSPECT_RST, D2K_LINK_PLANNED_NO);
    printf("client_b_rst=%d\n", suspect_suppressed(scheduler, "clean.example", &event));

    make_event(&event, client_a, server4, 4, 45000, 443,
               D2K_SUSPECT_RST, D2K_LINK_PLANNED_YES);
    printf("client_a_planned=%d\n", suspect_suppressed(scheduler, "clean.example", &event));

    make_event(&event, client_a, server4, 4, 45000, 443,
               D2K_SUSPECT_RST, D2K_LINK_PLANNED_NO);
    printf("other_name=%d\n", suspect_suppressed(scheduler, "other.example", &event));

    make_event(&event, client6, server6, 6, 45000, 443,
               D2K_SUSPECT_RST, D2K_LINK_PLANNED_NO);
    printf("family6=%d\n", suspect_suppressed(scheduler, "clean.example", &event));

    scheduler->now_ms = 1000 + SCHED_CLEAN_HS_MS;
    make_event(&event, client_a, server4, 4, 45000, 443,
               D2K_SUSPECT_RST, D2K_LINK_PLANNED_NO);
    printf("ttl_60s=%d\n", suspect_suppressed(scheduler, "clean.example", &event));
    scheduler->now_ms = 1000 + SCHED_CLEAN_HS_MS + 1;
    printf("ttl_61s=%d\n", suspect_suppressed(scheduler, "clean.example", &event));

    free(scheduler);
    return 0;
}
