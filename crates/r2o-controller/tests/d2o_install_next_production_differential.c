/* C-оракул production `install_next` (core/sched.c): порядок выбора
 * кандидата и наблюдаемые побочные эффекты — probe cap, plan/trial id,
 * bind/mark, проводная команда SET_NAME_PROBE/SET_ADDR_PROBE, refill
 * запасного перебора и стоп-ветви ladder_unmeasurable/family_fast/
 * own_first/rx_bootstrap_only/cached_measure.
 *
 * Задача и `d2k_sched` заполняются как production-объекты. `install_next`
 * вызывается напрямую (она static и доступна через `#include "sched.c"`),
 * без копии тела. Bind/mark подменены крючками `d2k_sched_bind_hook`/
 * `d2k_sched_mark_hook`: первый зовёт настоящий `bind_default`, второй только
 * записывает значение. Кадр управления читается из socketpair — это ровно
 * то, что уехало бы датапату.
 *
 * Rust-сторона (`install_next_production_matches_c`): production-хелперы
 * `r2o_discovery_candidate_wire_plan`, `BoundTcpProbe`/`r2o_props_bind_socket`,
 * `r2o_plan_records_for_wire`, `encode_set_name_probe`/`encode_set_addr_probe`,
 * `FallbackQueue`. Случайные plan/trial id, source port и id внутри TLV
 * нормализуются с обеих сторон. Ветви, у которых в Rust нет одноимённого
 * production-эквивалента, помечены C_ONLY и в JSON-diff не входят.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sched.c"

static const char *PLAN_TEXT =
    "d2k-plan 1 11\n"
    "id 00000000000000000000000000000000\n"
    "proto tcp tls\n"
    "split sni_middle +0\n";

static d2k_sched *g_s;
static d2k_catalog g_cat;
static task *g_t;
static int g_link[2] = {-1, -1};
static int g_bind_calls;
static int g_mark_calls;
static uint32_t g_mark_value;
static int g_bind_fail;
static int g_mark_fail;
static int g_first = 1;

static int recording_bind(uint8_t transport, uint8_t family, int *out_fd,
                          uint16_t *sport_be) {
    g_bind_calls++;
    if (g_bind_fail) {
        *out_fd = -1;
        return -1;
    }
    return bind_default(transport, family, out_fd, sport_be);
}

static int recording_mark(int fd, uint32_t mark) {
    (void)fd;
    g_mark_calls++;
    g_mark_value = mark;
    return g_mark_fail ? -1 : 0;
}

static void begin(const char *name, uint8_t transport, uint8_t family,
                  uint32_t mark, d2k_shape shape) {
    memset(&g_cat, 0, sizeof g_cat);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_link) != 0) {
        fprintf(stderr, "socketpair: %s\n", strerror(errno));
        exit(1);
    }
    g_s = d2k_sched_new(&g_cat, g_link[0], mark);
    if (!g_s) {
        fprintf(stderr, "d2k_sched_new failed\n");
        exit(1);
    }
    g_bind_calls = g_mark_calls = 0;
    g_mark_value = 0;
    g_bind_fail = g_mark_fail = 0;
    g_t = &g_s->tasks[0];
    memset(g_t, 0, sizeof *g_t);
    snprintf(g_t->name, sizeof g_t->name, "%s", name);
    snprintf(g_t->ip, sizeof g_t->ip, "127.0.0.1");
    g_t->transport = transport;
    g_t->family = family;
    g_t->port = 443;
    g_t->state = T_PLANNING;
    g_t->probe_fd = -1;
    g_t->prop_fd = -1;
    g_t->prop_bound_fd = -1;
    g_t->report_id = 1;
    g_t->trigger_shape = (uint8_t)shape;
    g_t->trigger_tcp_profile = 0;
    {
        size_t len = 0;
        if (d2k_hello_from_profile(shape, name, g_t->trig, sizeof g_t->trig,
                                   &len) != 0) {
            fprintf(stderr, "hello fixture failed\n");
            exit(1);
        }
        g_t->trig_len = len;
    }
}

static void finish(void) {
    if (g_t && g_t->probe_fd >= 0) close(g_t->probe_fd);
    d2k_sched_free(g_s);
    close(g_link[0]);
    close(g_link[1]);
    g_s = NULL;
    g_t = NULL;
    g_link[0] = g_link[1] = -1;
}

static int read_full(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n > 0) { got += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static size_t take_frame(uint8_t *out, size_t cap) {
    struct pollfd p = {.fd = g_link[1], .events = POLLIN};
    if (poll(&p, 1, 100) != 1 || !(p.revents & POLLIN)) return 0;
    uint8_t hdr[4];
    if (read_full(g_link[1], hdr, sizeof hdr) != 0) return 0;
    uint32_t plen = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                    ((uint32_t)hdr[2] << 8) | hdr[3];
    if (plen < 2 || plen > cap - 4) return 0;
    if (read_full(g_link[1], out + 4, plen) != 0) return 0;
    memcpy(out, hdr, 4);
    return 4u + plen;
}

/* record 0x0001 (id) — единственное случайное поле TLV. */
static void normalize_records(uint8_t *records, size_t len) {
    if (len < 12) return;
    size_t o = 12;
    while (o + 4 <= len) {
        uint16_t type = (uint16_t)((records[o] << 8) | records[o + 1]);
        uint16_t size = (uint16_t)((records[o + 2] << 8) | records[o + 3]);
        o += 4;
        if (o + size > len) return;
        if (type == 0x0001 && size == 16) memset(records + o, 0, 16);
        o += size;
    }
}

static int plan_id_is_nonzero(const uint8_t *records, size_t len) {
    if (len < 12) return 0;
    size_t o = 12;
    while (o + 4 <= len) {
        uint16_t type = (uint16_t)((records[o] << 8) | records[o + 1]);
        uint16_t size = (uint16_t)((records[o + 2] << 8) | records[o + 3]);
        o += 4;
        if (o + size > len) return 0;
        if (type == 0x0001 && size == 16) {
            for (size_t i = 0; i < 16; i++) if (records[o + i]) return 1;
            return 0;
        }
        o += size;
    }
    return 0;
}

static int bytes_nonzero(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) if (bytes[i]) return 1;
    return 0;
}

static void print_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
}

static void emit(const char *scenario, int rc, int cap, int addr_identity) {
    uint8_t frame[70000];
    size_t frame_len = take_frame(frame, sizeof frame);
    int trial_nonzero = 0;
    int plan_nonzero = 1;
    if (frame_len >= 6) {
        uint16_t cmd = (uint16_t)((frame[4] << 8) | frame[5]);
        uint8_t *body = frame + 6;
        size_t body_len = frame_len - 6;
        if (cmd == D2K_CMD_SET_NAME_PROBE && body_len >= 5) {
            size_t nl = body[0];
            if (3 + nl + 16 + 4 <= body_len) {
                uint8_t *sport = body + 1 + nl + 2;
                sport[0] = sport[1] = 0;
                uint8_t *trial = body + body_len - 16;
                trial_nonzero = bytes_nonzero(trial, 16);
                memset(trial, 0, 16);
                uint8_t *plan = body + 1 + nl + 4;
                size_t plan_len = body_len - (1 + nl + 4) - 16;
                plan_nonzero = plan_id_is_nonzero(plan, plan_len);
                normalize_records(plan, plan_len);
            }
        } else if (cmd == D2K_CMD_SET_ADDR_PROBE && body_len >= 58) {
            uint8_t *sport = body + 33;
            sport[0] = sport[1] = 0;
            uint8_t *trial = body + 38;
            trial_nonzero = bytes_nonzero(trial, 16);
            memset(trial, 0, 16);
            uint8_t *plan = body + 58;
            size_t plan_len = body_len - 58;
            plan_nonzero = plan_id_is_nonzero(plan, plan_len);
            normalize_records(plan, plan_len);
        }
    }
    printf("%s{\"scenario\":\"%s\",\"rc\":%d,\"cap\":%d,"
           "\"installed\":%s,\"next_plan\":%zu,\"n_plans\":%zu,"
           "\"box_id\":\"%s\",\"probes\":%d,\"probes_used\":%llu,"
           "\"sync_pending\":%d,\"bound_plan_id\":\"%s\","
           "\"trial_installed\":%d,"
           "\"trial_shape\":%u,\"addr_identity\":%d,"
           "\"probe_bound\":%s,\"bind_calls\":%d,\"mark_calls\":%d,"
           "\"mark_value\":%u,\"trial_nonzero\":%s,\"plan_id_nonzero\":%s,"
           "\"wire\":",
           g_first ? "" : ",\n", scenario, rc, cap,
           rc == 0 ? "true" : "false", g_t->next_plan, g_t->n_plans,
           g_t->box_id, (int)g_t->probes,
           (unsigned long long)g_s->probes_used, g_s->sync_pending,
           g_t->bound_plan_id, g_t->trial_installed,
           (unsigned)g_t->trial_shape, addr_identity,
           g_t->probe_fd >= 0 ? "true" : "false",
           g_bind_calls, g_mark_calls, g_mark_value,
           trial_nonzero ? "true" : "false",
           plan_nonzero ? "true" : "false");
    if (frame_len) {
        printf("\"");
        print_hex(frame, frame_len);
        printf("\"");
    } else {
        printf("null");
    }
    printf("}");
    g_first = 0;
}

static void run_case(const char *scenario, uint8_t transport, uint8_t family,
                     uint32_t mark, d2k_shape shape, const char *name) {
    begin(name, transport, family, mark, shape);
    g_t->n_plans = 1;
    g_t->next_plan = 0;
    snprintf(g_t->plans[0], sizeof g_t->plans[0], "%s", PLAN_TEXT);
    snprintf(g_t->plan_boxes[0], sizeof g_t->plan_boxes[0], "box-0");
    int cap = sched_probe_cap(g_t);
    int rc = install_next(g_s, g_t);
    emit(scenario, rc, cap, 0);
    finish();
}

int main(void) {
    d2k_sched_bind_fn saved_bind = d2k_sched_bind_hook;
    d2k_sched_mark_fn saved_mark = d2k_sched_mark_hook;
    d2k_sched_bind_hook = recording_bind;
    d2k_sched_mark_hook = recording_mark;
    printf("[\n");

    /* 1. Обычная установка TCP: bind, mark, SET_NAME_PROBE. */
    run_case("tcp_first", 6, 4, 0x2d, D2K_SHAPE_MODERN, "install.example");

    /* 2. Метка 0 — C не зовёт mark hook; Rust не ставит SO_MARK. */
    run_case("mark_zero", 6, 4, 0, D2K_SHAPE_MODERN, "install.example");

    /* 3. Ненулевая метка доезжает до сокета/крючка. */
    run_case("mark_value", 6, 4, 0x99, D2K_SHAPE_MODERN, "install.example");

    /* 4. IPv6: тот же порядок и семейство в команде. */
    run_case("tcp_ipv6", 6, 6, 0x2d, D2K_SHAPE_MODERN, "install.example");

    /* 5. Старый клиент → форма зонда LEGACY (не MODERN). */
    run_case("tcp_legacy_shape", 6, 4, 0x2d, D2K_SHAPE_LEGACY, "install.example");

    /* 6. Бюджет исчерпан: rc -1, ни bind, ни команды. */
    {
        begin("install.example", 6, 4, 0x2d, D2K_SHAPE_MODERN);
        g_t->n_plans = 1;
        g_t->next_plan = 0;
        g_t->probes = SCHED_MAX_PROBES;
        snprintf(g_t->plans[0], sizeof g_t->plans[0], "%s", PLAN_TEXT);
        int cap = sched_probe_cap(g_t);
        int rc = install_next(g_s, g_t);
        emit("cap_exhausted", rc, cap, 0);
        finish();
    }

    /* 7. bind не занял порт: rc -2, команды нет, mark не звался. */
    {
        begin("install.example", 6, 4, 0x2d, D2K_SHAPE_MODERN);
        g_t->n_plans = 1;
        g_t->next_plan = 0;
        snprintf(g_t->plans[0], sizeof g_t->plans[0], "%s", PLAN_TEXT);
        g_bind_fail = 1;
        int cap = sched_probe_cap(g_t);
        int rc = install_next(g_s, g_t);
        emit("bind_invalid_family", rc, cap, 0);
        finish();
    }

    /* 8. QUIC по адресу: SET_ADDR_PROBE, адрес/порт/lease. */
    {
        begin("install.example", 17, 4, 0x2d, D2K_SHAPE_MODERN);
        g_t->by_addr = 1;
        g_t->n_plans = 1;
        g_t->next_plan = 0;
        snprintf(g_t->plans[0], sizeof g_t->plans[0],
                 "d2k-plan 1 9\nid 00000000000000000000000000000000\n"
                 "proto udp quic\nudplen 100\n");
        int cap = sched_probe_cap(g_t);
        int rc = install_next(g_s, g_t);
        emit("quic_by_addr", rc, cap, g_t->addr_probe_identity_valid);
        finish();
    }

    /* 9. Очередь пуста, refill запасного перебора ставит первого кандидата. */
    {
        begin("install.example", 6, 4, 0x2d, D2K_SHAPE_MODERN);
        g_t->n_plans = 0;
        g_t->next_plan = 0;
        g_t->search_owned = 1;
        g_t->owned_fallback = 1;
        int cap = sched_probe_cap(g_t);
        int rc = install_next(g_s, g_t);
        emit("fallback_refill", rc, cap, 0);
        finish();
    }

    /* 10. Отказ SO_MARK: trial не ставится, rc=-2. */
    {
        begin("install.example", 6, 4, 0x2d, D2K_SHAPE_MODERN);
        g_t->n_plans = 1;
        g_t->next_plan = 0;
        snprintf(g_t->plans[0], sizeof g_t->plans[0], "%s", PLAN_TEXT);
        snprintf(g_t->plan_boxes[0], sizeof g_t->plan_boxes[0], "box-1");
        g_mark_fail = 1;
        int cap = sched_probe_cap(g_t);
        int rc = install_next(g_s, g_t);
        emit("mark_failure", rc, cap, 0);
        finish();
    }

    /* --- C_ONLY: ветви без одноимённого production-эквивалента в Rust --- */

    /* 10. ladder_unmeasurable: ступени лестницы пропускаются. */
    {
        begin("install.example", 6, 4, 0x2d, D2K_SHAPE_MODERN);
        g_t->n_plans = 2;
        g_t->next_plan = 0;
        g_t->ladder_unmeasurable = 1;
        snprintf(g_t->net_probe_name[0], sizeof g_t->net_probe_name[0], "ladder.example");
        snprintf(g_t->plans[0], sizeof g_t->plans[0], "%s", PLAN_TEXT);
        snprintf(g_t->plan_boxes[0], sizeof g_t->plan_boxes[0], "box-ladder");
        snprintf(g_t->plans[1], sizeof g_t->plans[1], "%s", PLAN_TEXT);
        snprintf(g_t->plan_boxes[1], sizeof g_t->plan_boxes[1], "box-1");
        int cap = sched_probe_cap(g_t);
        int rc = install_next(g_s, g_t);
        emit("ladder_unmeasurable_skip", rc, cap, 0);
        finish();
    }

    /* 11. Непереводимый план пропускается, ставится следующий. */
    {
        begin("install.example", 6, 4, 0x2d, D2K_SHAPE_MODERN);
        g_t->n_plans = 2;
        g_t->next_plan = 0;
        snprintf(g_t->plans[0], sizeof g_t->plans[0],
                 "d2k-plan 1 3\nid 00000000000000000000000000000000\n"
                 "proto tcp tls\nunknown 1\n");
        snprintf(g_t->plan_boxes[0], sizeof g_t->plan_boxes[0], "box-bad");
        snprintf(g_t->plans[1], sizeof g_t->plans[1], "%s", PLAN_TEXT);
        snprintf(g_t->plan_boxes[1], sizeof g_t->plan_boxes[1], "box-1");
        int cap = sched_probe_cap(g_t);
        int rc = install_next(g_s, g_t);
        emit("bad_plan_skip", rc, cap, 0);
        finish();
    }

    /* 12-15. Стоп-ветви хвоста: пустая очередь не доливается. */
    {
        static const struct {
            const char *scenario;
            int family_fast;
            int own_first;
            int rx_bootstrap;
            int cached;
            int n_known;
        } gates[] = {
            {"family_fast_stop", 1, 0, 0, 0, 0},
            {"own_first_two_stop", 0, 2, 0, 0, 0},
            {"rx_bootstrap_stop", 0, 0, 1, 0, 0},
            {"cached_measure_stop", 0, 0, 0, 1, 1},
        };
        for (size_t i = 0; i < sizeof gates / sizeof gates[0]; i++) {
            begin("install.example", 6, 4, 0x2d, D2K_SHAPE_MODERN);
            g_t->n_plans = 0;
            g_t->next_plan = 0;
            g_t->search_owned = 1;
            g_t->owned_fallback = 1;
            g_t->family_fast = gates[i].family_fast;
            g_t->own_first = gates[i].own_first;
            g_t->rx_bootstrap_only = gates[i].rx_bootstrap;
            g_t->cached_measure_valid = gates[i].cached;
            g_t->n_known = (size_t)gates[i].n_known;
            int cap = sched_probe_cap(g_t);
            int rc = install_next(g_s, g_t);
            emit(gates[i].scenario, rc, cap, 0);
            finish();
        }
    }

    printf("\n]\n");
    d2k_sched_bind_hook = saved_bind;
    d2k_sched_mark_hook = saved_mark;
    return 0;
}
