/* C/Rust differential: полный вход production `on_suspect` (sched.c:8181-8592).
 *
 * Матрица: коды SUSPECT 1..8, свежее подозрение без плана, под планом с
 * применимым решением, без плана при covering-привязке, повторный SUSPECT по
 * уже ждущей цели (hot_event). Отдельно проверяется порядок ранних гейтов:
 * dead address → cooldown → hot_event/covering, включая случаи, где истинны
 * два условия сразу. C-оракул — настоящий `on_suspect` из донора a378;
 * Rust-сторона — production `r2o_handle_legacy_suspect`/`r2o_queue_tcp_suspect`.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sched.c"

/* Код 7 в C — QUIC-ветвь (transport 17). Rust legacy-обработчик строит цель
 * только по TCP HELLO, поэтому строки code7_* остаются C-эталоном и в diff
 * общих кодов не входят. */
typedef struct {
    const char *label;
    uint8_t code;
    uint8_t planned;
    int prequeue;
    uint8_t prequeue_planned;
    int watching;
    int catalog;
    int dead;
    int cooldown;
} scenario;

static int read_exact(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, p + off, n - off);
        if (r > 0) { off += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) { continue; }
        return -1;
    }
    return 0;
}

static int saw_arm_shape(int fd) {
    int arm = 0;
    for (;;) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (poll(&pfd, 1, 0) != 1 || !(pfd.revents & POLLIN)) { break; }
        unsigned char head[4];
        if (read_exact(fd, head, sizeof head) != 0) { break; }
        uint32_t plen = ((uint32_t)head[0] << 24) | ((uint32_t)head[1] << 16) |
                        ((uint32_t)head[2] << 8) | (uint32_t)head[3];
        if (plen < 2 || plen > 65535) { break; }
        unsigned char body[65535];
        if (read_exact(fd, body, plen) != 0) { break; }
        uint16_t cmd = ((uint16_t)body[0] << 8) | body[1];
        if (cmd == D2K_CMD_ARM_SHAPE) { arm = 1; }
    }
    return arm;
}

static void make_event(d2k_ev *ev, uint8_t code, uint8_t planned, uint8_t transport,
                       uint8_t client_shape) {
    memset(ev, 0, sizeof *ev);
    ev->family = 4;
    ev->transport = transport;
    ev->low_port = 40000;
    ev->high_port = 443;
    ev->code = code;
    ev->planned = planned;
    ev->client_shape = client_shape;
    inet_pton(AF_INET, "192.0.2.10", ev->low_ip);
    inet_pton(AF_INET, "198.51.100.20", ev->high_ip);
    snprintf(ev->name, sizeof ev->name, "%s", "suspect.example.com");
}

static const char *block_reason(d2k_sched *s, const char *name, const d2k_ev *ev) {
    char endpoint_ip[INET6_ADDRSTRLEN] = "";
    uint16_t endpoint_port = 0;
    server_of(ev, endpoint_ip, sizeof endpoint_ip, &endpoint_port);
    if (ev->transport == 6) {
        dead_address *d = dead_find(s, name, ev->transport,
                                    ev->family ? ev->family : 4, endpoint_ip);
        if (d && s->now_ms < d->until_ms) { return "dead"; }
    }
    int64_t left = 0;
    target_cooldown *matched = NULL;
    if (cooldown_blocks(s, name, ev->transport, ev->family ? ev->family : 4,
                        endpoint_ip, endpoint_port, ev->code, &left, &matched)) {
        return "cooldown";
    }
    return "none";
}

static void setup_catalog(d2k_catalog *cat, d2k_cat_box *box,
                          d2k_cat_plan *plan, d2k_cat_binding *bind,
                          const char *name) {
    memset(cat, 0, sizeof *cat);
    memset(box, 0, sizeof *box);
    memset(plan, 0, sizeof *plan);
    memset(bind, 0, sizeof *bind);
    snprintf(plan->id, sizeof plan->id, "%s", "plan-suspect");
    snprintf(plan->proto, sizeof plan->proto, "%s", "tls");
    plan->text = "r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n";
    plan->enabled = 1;
    box->plans = plan;
    box->n_plans = 1;
    snprintf(bind->kind, sizeof bind->kind, "%s", "name");
    snprintf(bind->target, sizeof bind->target, "%s", name);
    snprintf(bind->plan_id, sizeof bind->plan_id, "%s", "plan-suspect");
    bind->enabled = 1;
    bind->level = 3;
    bind->transport = 6;
    bind->family = 4;
    bind->shape = D2K_PLAN_SHAPE_MODERN;
    bind->input = D2K_INPUT_PROFILE;
    box->binds = bind;
    box->n_binds = 1;
    cat->boxes = box;
    cat->n_boxes = 1;
}

static void run_scenario(const scenario *sc) {
    d2k_sched *s = calloc(1, sizeof *s);
    if (!s) { exit(3); }
    d2k_catalog cat;
    d2k_cat_box box;
    d2k_cat_plan plan;
    d2k_cat_binding bind;
    const char *name = "suspect.example.com";
    uint8_t transport = sc->code == D2K_SUSPECT_QUIC_STALL ? 17 : 6;
    uint8_t client_shape = transport == 17 ? D2K_LINK_SHAPE_QUIC : D2K_PLAN_SHAPE_MODERN;
    setup_catalog(&cat, &box, &plan, &bind, name);

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) { exit(4); }
    s->link_fd = fds[0];
    s->now_ms = 1000;
    s->clock_seen = 1;
    s->meas_limit = 0; /* любая допущенная задача остаётся T_QUEUED */
    /* C `installed_family_ready` всегда читает s->cat->groups: пустой каталог
     * задаётся нулевым числом коробок, а не NULL-указателем. */
    cat.n_boxes = 0;
    s->cat = &cat;

    d2k_ev first, ev;
    make_event(&first, sc->code, sc->prequeue ? sc->prequeue_planned : sc->planned,
               transport, client_shape);
    remember(s, &first);
    if (sc->watching) {
        task *t = &s->tasks[0];
        snprintf(t->name, sizeof t->name, "%s", name);
        t->transport = transport;
        t->family = 4;
        t->state = T_WATCHING;
    }
    if (sc->prequeue) {
        /* Первое подозрение создаёт ждущую задачу; каталог/адрес/отдых
         * добавляются после него, чтобы проверить именно второй вход. */
        (void)on_suspect(s, &first, 0);
    }
    if (sc->catalog) { cat.n_boxes = 1; }
    if (sc->dead) {
        task tmp = {0};
        snprintf(tmp.name, sizeof tmp.name, "%s", name);
        snprintf(tmp.ip, sizeof tmp.ip, "%s", "198.51.100.20");
        tmp.port = 443;
        tmp.transport = transport;
        tmp.family = 4;
        (void)dead_step(s, &tmp);
    }
    if (sc->cooldown) {
        task tmp = {0};
        snprintf(tmp.name, sizeof tmp.name, "%s", name);
        snprintf(tmp.ip, sizeof tmp.ip, "%s", "198.51.100.20");
        tmp.port = 443;
        tmp.transport = transport;
        tmp.family = 4;
        tmp.trigger_code = sc->code;
        cooldown_record(s, &tmp, 2);
    }

    make_event(&ev, sc->code, sc->planned, transport, client_shape);
    const char *block = block_reason(s, name, &ev);
    (void)on_suspect(s, &ev, 0);
    task *t = task_of(s, name, transport, 4);
    int admitted = t && t->state != T_FREE;
    int queued = t && t->state == T_QUEUED;
    int watching = t && t->state == T_WATCHING;
    unsigned hot = t ? t->hot_count : 0;
    int trigger = t && t->trigger_planned == D2K_LINK_PLANNED_YES;
    int report = t && t->report_id != 0;
    int arm = saw_arm_shape(fds[1]);
    int pending = t && t->watch_shape_pending;
    printf("%s code=%u block=%s queued=%d admitted=%d watching=%d hot=%u "
           "trigger=%d report=%d arm=%d pending=%d\n",
           sc->label, (unsigned)sc->code, block, queued, admitted, watching,
           hot, trigger, report, arm, pending);

    close(fds[0]);
    close(fds[1]);
    free(s);
}

int main(void) {
    char labels[8][64];
    for (unsigned code = 1; code <= 8; code++) {
        snprintf(labels[code - 1], sizeof labels[code - 1], "code%u_fresh_noplan", code);
        scenario fresh = {.label = labels[code - 1], .code = (uint8_t)code,
                          .planned = D2K_LINK_PLANNED_NO};
        run_scenario(&fresh);

        snprintf(labels[code - 1], sizeof labels[code - 1], "code%u_planned_solution", code);
        scenario planned = {.label = labels[code - 1], .code = (uint8_t)code,
                            .planned = D2K_LINK_PLANNED_YES, .catalog = 1};
        run_scenario(&planned);

        snprintf(labels[code - 1], sizeof labels[code - 1], "code%u_unplanned_covering", code);
        scenario covering = {.label = labels[code - 1], .code = (uint8_t)code,
                             .planned = D2K_LINK_PLANNED_NO, .catalog = 1};
        run_scenario(&covering);

        snprintf(labels[code - 1], sizeof labels[code - 1], "code%u_repeat", code);
        scenario repeat = {.label = labels[code - 1], .code = (uint8_t)code,
                           .planned = D2K_LINK_PLANNED_NO, .prequeue = 1,
                           .prequeue_planned = D2K_LINK_PLANNED_NO};
        run_scenario(&repeat);
    }

    scenario order_dead_covering = {
        .label = "order_dead_before_covering", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_NO, .catalog = 1, .dead = 1};
    run_scenario(&order_dead_covering);
    scenario order_cooldown_covering = {
        .label = "order_cooldown_before_covering", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_NO, .catalog = 1, .cooldown = 1};
    run_scenario(&order_cooldown_covering);
    scenario order_dead_cooldown = {
        .label = "order_dead_before_cooldown", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_NO, .dead = 1, .cooldown = 1};
    run_scenario(&order_dead_cooldown);
    scenario hot_covering = {
        .label = "order_hot_event_before_covering", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_NO, .prequeue = 1,
        .prequeue_planned = D2K_LINK_PLANNED_NO, .catalog = 1};
    run_scenario(&hot_covering);
    scenario hot_dead = {
        .label = "order_dead_before_hot_event", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_NO, .prequeue = 1,
        .prequeue_planned = D2K_LINK_PLANNED_NO, .dead = 1};
    run_scenario(&hot_dead);
    scenario hot_cooldown = {
        .label = "order_cooldown_before_hot_event", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_NO, .prequeue = 1,
        .prequeue_planned = D2K_LINK_PLANNED_NO, .cooldown = 1};
    run_scenario(&hot_cooldown);
    scenario hot_promote = {
        .label = "repeat_planned_promotion", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_YES, .prequeue = 1,
        .prequeue_planned = D2K_LINK_PLANNED_NO};
    run_scenario(&hot_promote);
    scenario watch_dead = {
        .label = "watch_dead_before_arm", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_NO, .watching = 1, .dead = 1};
    run_scenario(&watch_dead);
    scenario watch_cooldown = {
        .label = "watch_cooldown_before_arm", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_NO, .watching = 1, .cooldown = 1};
    run_scenario(&watch_cooldown);
    scenario watch_arm = {
        .label = "watch_arm_with_covering", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_NO, .watching = 1, .catalog = 1};
    run_scenario(&watch_arm);
    /* C task_done у наблюдаемой цели: planned=YES — новый замер; UNKNOWN —
     * снять наблюдение (поздние 5/6/8 — новый замер). */
    scenario watch_planned_yes = {
        .label = "watch_planned_yes_new_search", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_YES, .watching = 1};
    run_scenario(&watch_planned_yes);
    scenario watch_unknown = {
        .label = "watch_planned_unknown_stop", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_UNKNOWN, .watching = 1};
    run_scenario(&watch_unknown);
    scenario watch_unknown_late = {
        .label = "watch_planned_unknown_late_recheck", .code = D2K_SUSPECT_RST_AFTER_APP,
        .planned = D2K_LINK_PLANNED_UNKNOWN, .watching = 1};
    run_scenario(&watch_unknown_late);
    scenario unknown_fresh = {
        .label = "planned_unknown_fresh_queue", .code = D2K_SUSPECT_RST,
        .planned = D2K_LINK_PLANNED_UNKNOWN};
    run_scenario(&unknown_fresh);
    return 0;
}
