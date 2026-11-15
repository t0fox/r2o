/* C-оракул `on_exchange` (sched.c:10626-10649) для внешнего типа записи 23:
 * T_WATCHING освобождается только ЧУЖИМ потоком; собственный зонд
 * (`t->ver_flow`) и неподтверждённая задача остаются на месте. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static int report_seen;
static d2k_diag_event observed;

static void observe(void *context, const d2k_diag_event *event) {
    (void)context;
    observed = *event;
    report_seen = 1;
}

static const char *state_name(int state) {
    switch (state) {
    case T_FREE: return "free";
    case T_WATCHING: return "watching";
    default: return "other";
    }
}

/* Один сценарий: задача в `task_state`, кольцо `seen` знает имя (или нет),
 * событие приходит по своему (`same_flow`) или чужому потоку. `family` 4/6
 * проверяет ту же неупорядоченную пару адрес:порт на IPv6. */
static void scenario(d2k_sched *s, const char *label, uint8_t family,
                     task_state initial_state, int known_name, int same_flow,
                     uint8_t seen_types, uint8_t planned, int with_ver_flow) {
    static const uint8_t client4[4] = {192, 0, 2, 10};
    static const uint8_t server4[4] = {198, 51, 100, 10};
    static const uint8_t client6[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    };
    static const uint8_t server6[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
    };
    const uint8_t *client = family == 6 ? client6 : client4;
    const uint8_t *server = family == 6 ? server6 : server4;
    size_t ip_len = family == 6 ? 16 : 4;
    memset(s->seen, 0, sizeof s->seen);
    memset(&s->tasks[0], 0, sizeof s->tasks[0]);
    report_seen = 0;
    memset(&observed, 0, sizeof observed);

    if (known_name) {
        seen_name *seen = &s->seen[0];
        seen->used = 1;
        seen->family = family;
        seen->transport = 6;
        memcpy(seen->low_ip, client, ip_len);
        memcpy(seen->high_ip, server, ip_len);
        seen->low_port = same_flow ? 40000 : 40001;
        seen->high_port = 443;
        snprintf(seen->name, sizeof seen->name, "watch.example");
    }

    task *t = &s->tasks[0];
    snprintf(t->name, sizeof t->name, "watch.example");
    snprintf(t->ip, sizeof t->ip, family == 6 ? "2001:db8::20" : "198.51.100.10");
    t->family = family;
    t->transport = 6;
    t->state = initial_state;
    t->report_id = 7;
    t->trigger_code = 3;
    t->trigger_shape = (uint8_t)D2K_SHAPE_MODERN;
    t->report_admitted_ms = 90000;
    snprintf(t->res.reason, sizeof t->res.reason, "подтверждено");
    if (with_ver_flow) {
        t->ver_flow.family = family;
        memcpy(t->ver_flow.a_ip, client, ip_len);
        memcpy(t->ver_flow.b_ip, server, ip_len);
        t->ver_flow.a_port = 40000;
        t->ver_flow.b_port = 443;
        t->ver_flow.transport = 6;
    }

    d2k_ev ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = D2K_EV_EXCHANGE;
    ev.family = family;
    memcpy(ev.low_ip, client, ip_len);
    memcpy(ev.high_ip, server, ip_len);
    ev.low_port = same_flow ? 40000 : 40001;
    ev.high_port = 443;
    ev.transport = 6;
    ev.code = D2K_TLS_APPLICATION_DATA;
    ev.num = 1234;
    ev.seen_types = seen_types;
    ev.server_hello = 0;
    ev.planned = planned;

    on_exchange(s, &ev);
    printf("%s state=%s report=%s\n", label, state_name(s->tasks[0].state),
           report_seen ? observed.outcome : "-");
}

int main(void) {
    d2k_sched *s = calloc(1, sizeof *s);
    if (!s) return 1;
    s->wake[0] = -1;
    s->wake[1] = -1;
    s->now_ms = 100000;
    s->clock_seen = 1;
    s->send_cap = 0;
    s->diagnostic = observe;
    if (pthread_mutex_init(&s->mu, NULL)) return 1;

    const uint8_t appdata = (uint8_t)(1u << (D2K_TLS_APPLICATION_DATA - 20));
    const uint8_t handshake_only =
        (uint8_t)(1u << (D2K_TLS_HANDSHAKE - 20));

    scenario(s, "foreign_flow", 4, T_WATCHING, 1, 0, appdata,
             D2K_LINK_PLANNED_NO, 1);
    scenario(s, "own_probe_flow", 4, T_WATCHING, 1, 1, appdata,
             D2K_LINK_PLANNED_NO, 1);
    scenario(s, "foreign_flow_planned_yes", 4, T_WATCHING, 1, 0, appdata,
             D2K_LINK_PLANNED_YES, 1);
    scenario(s, "not_watching", 4, T_PLANNING, 1, 0, appdata,
             D2K_LINK_PLANNED_NO, 1);
    scenario(s, "no_ver_flow_foreign", 4, T_WATCHING, 1, 0, appdata,
             D2K_LINK_PLANNED_NO, 0);
    scenario(s, "unknown_name", 4, T_WATCHING, 0, 0, appdata,
             D2K_LINK_PLANNED_NO, 1);
    scenario(s, "non_appdata", 4, T_WATCHING, 1, 0, handshake_only,
             D2K_LINK_PLANNED_NO, 1);
    scenario(s, "foreign_flow_v6", 6, T_WATCHING, 1, 0, appdata,
             D2K_LINK_PLANNED_NO, 1);
    scenario(s, "own_probe_flow_v6", 6, T_WATCHING, 1, 1, appdata,
             D2K_LINK_PLANNED_NO, 1);
    d2k_sched_free(s);
    return 0;
}
