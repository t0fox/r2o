/* C/Rust differential: позднее закрытие и полоса TCP-stall из C on_suspect.
 * C-оракул — production `is_late_volume_suspicion`, `late_close_what`,
 * `tcp_stall_in_name_band`. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "sched.c"

static void cat_signal(d2k_cat_signal *out, const char *kind, int packets) {
    memset(out, 0, sizeof *out);
    snprintf(out->kind, sizeof out->kind, "%s", kind);
    out->packets = packets;
}

static void binding(d2k_cat_binding *out, const char *target, int enabled) {
    memset(out, 0, sizeof *out);
    snprintf(out->kind, sizeof out->kind, "name");
    snprintf(out->target, sizeof out->target, "%s", target);
    out->enabled = enabled;
    out->transport = 6;
    out->family = 4;
}

static d2k_sched *voice_sched;

static void set_voice_task(d2k_sched *s, task *t, task_state state,
                           const char *server, uint16_t port, const char *client) {
    task_reset(s, t);
    snprintf(t->name, sizeof t->name, "%s", D2K_LINK_VOICE_CLASS);
    t->transport = 17;
    t->family = 4;
    t->state = state;
    t->addr_probe_identity_valid = 1;
    t->addr_probe_src_port_be = 0;
    t->addr_probe_dst_port_be = htons(port);
    inet_pton(AF_INET, server, t->addr_probe_dst_ip);
    inet_pton(AF_INET, client, t->addr_probe_src_ip);
    snprintf(t->ip, sizeof t->ip, "%s", server);
    t->port = port;
}

static void voice_event(d2k_sched *s, d2k_ev *ev, const char *client, uint16_t cport,
                        const char *server, uint16_t sport) {
    memset(ev, 0, sizeof *ev);
    ev->kind = D2K_EV_SUSPECT;
    snprintf(ev->name, sizeof ev->name, "%s", D2K_LINK_VOICE_CLASS);
    ev->transport = 17;
    ev->family = 4;
    ev->code = D2K_SUSPECT_RST;
    ev->planned = D2K_LINK_PLANNED_YES;
    inet_pton(AF_INET, client, ev->low_ip);
    inet_pton(AF_INET, server, ev->high_ip);
    ev->low_port = cport;
    ev->high_port = sport;
    remember(s, ev);
}

int main(void) {
    d2k_catalog cat;
    d2k_cat_box boxes[3];
    d2k_cat_binding binds[3];
    d2k_cat_signal sig[3];
    memset(&cat, 0, sizeof cat);
    memset(boxes, 0, sizeof boxes);
    memset(binds, 0, sizeof binds);
    memset(sig, 0, sizeof sig);

    cat_signal(&sig[0], "rx-volume", 29);
    boxes[0].fp.n_sig = 1;
    boxes[0].fp.sig[0] = sig[0];
    binding(&binds[0], "band.example", 1);
    boxes[0].binds = &binds[0];
    boxes[0].n_binds = 1;

    cat_signal(&sig[1], "rx-volume-wire", 45);
    boxes[1].fp.n_sig = 1;
    boxes[1].fp.sig[0] = sig[1];
    binding(&binds[1], "band.example", 1);
    boxes[1].binds = &binds[1];
    boxes[1].n_binds = 1;

    cat_signal(&sig[2], "rx-volume", 60);
    boxes[2].fp.n_sig = 1;
    boxes[2].fp.sig[0] = sig[2];
    binding(&binds[2], "disabled.example", 0);
    boxes[2].binds = &binds[2];
    boxes[2].n_binds = 1;

    cat.boxes = boxes;
    cat.n_boxes = 3;
    d2k_sched *s = d2k_sched_new(&cat, -1, 0);
    if (!s) return 1;
    s->now_ms = 5000;

    for (unsigned code = 0; code <= 9; code++) {
        printf("late_%u=%s\n", code,
               is_late_volume_suspicion((uint8_t)code) ? "true" : "false");
    }
    const unsigned packets[] = {0, 27, 28, 29, 30, 31, 43, 44, 45, 46, 47, 100};
    for (size_t i = 0; i < sizeof packets / sizeof packets[0]; i++) {
        d2k_ev ev;
        memset(&ev, 0, sizeof ev);
        ev.num = packets[i];
        printf("band_%u=%s\n", packets[i],
               tcp_stall_in_name_band(s, "band.example", &ev) ? "true"
                                                               : "false");
    }
    const unsigned other_packets[] = {0, 29, 100};
    for (size_t i = 0; i < sizeof other_packets / sizeof other_packets[0]; i++) {
        d2k_ev ev;
        memset(&ev, 0, sizeof ev);
        ev.num = other_packets[i];
        printf("other_%u=%s\n", other_packets[i],
               tcp_stall_in_name_band(s, "other.example", &ev) ? "true"
                                                                : "false");
    }
    fprintf(stderr, "late_close_what_5=%s\nlate_close_what_6=%s\nlate_close_what_8=%s\n",
            late_close_what(D2K_SUSPECT_RST_AFTER_APP),
            late_close_what(D2K_SUSPECT_FIN_RETRY),
            late_close_what(D2K_SUSPECT_TCP_STALL));

    /* Voice pending из on_suspect: latest wins, same context не очередь. */
    voice_sched = s;
    d2k_ev voice_ev;
    task *vt = &s->tasks[0];
    set_voice_task(s, vt, T_VOICE_TRIAL, "198.51.100.20", 50004, "192.0.2.10");
    voice_event(s, &voice_ev, "192.0.2.10", 40000, "198.51.100.20", 50004);
    s->pending_voice_suspect_valid = 0;
    on_suspect(s, &voice_ev, 0);
    printf("voice_same_context_pending=%d\n", s->pending_voice_suspect_valid);

    set_voice_task(s, vt, T_VOICE_TRIAL, "198.51.100.20", 50004, "192.0.2.10");
    voice_event(s, &voice_ev, "192.0.2.10", 40001, "198.51.100.20", 50005);
    s->pending_voice_suspect_valid = 0;
    on_suspect(s, &voice_ev, 0);
    printf("voice_new_server_pending=%d\n", s->pending_voice_suspect_valid);
    printf("voice_new_server_port=%u\n", (unsigned)s->pending_voice_suspect.high_port);

    set_voice_task(s, vt, T_VOICE_TRIAL, "198.51.100.20", 50004, "192.0.2.10");
    voice_event(s, &voice_ev, "192.0.2.11", 40002, "198.51.100.20", 50004);
    s->pending_voice_suspect_valid = 0;
    on_suspect(s, &voice_ev, 0);
    printf("voice_new_client_pending=%d\n", s->pending_voice_suspect_valid);

    set_voice_task(s, vt, T_WATCHING, "198.51.100.20", 50004, "192.0.2.10");
    voice_event(s, &voice_ev, "192.0.2.10", 40003, "198.51.100.20", 50006);
    s->pending_voice_suspect_valid = 0;
    on_suspect(s, &voice_ev, 0);
    printf("voice_watching_no_pending=%d\n", s->pending_voice_suspect_valid);

    d2k_sched_free(s);
    return 0;
}
