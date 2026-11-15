/* C/Rust differential: production on_shape для T_SHAPE_WAIT.
 *
 * Сценарии: снимок своего имени будит задачу и ставит её в очередь;
 * чужое имя, чужой транспорт и чужое семейство ожидание не трогают;
 * истечение срока закрывает задачу как task_done (T_FREE), без плана.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "sched.c"
#include "test_quic_vector.h"

static int build_hello(const char *name, uint8_t *out, size_t cap, size_t *len)
{
    return d2k_hello_from_profile(D2K_SHAPE_MODERN, name, out, cap, len);
}

static int build_quic_snapshot(d2k_ev *ev, const char *name)
{
    memset(ev, 0, sizeof *ev);
    ev->kind = D2K_EV_SHAPE;
    ev->transport = 17;
    return d2k_quic_hello_rename(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                 name, ev->shape, sizeof ev->shape, &ev->shape_len);
}

static void reset_wait(d2k_sched *s, uint8_t transport, uint8_t family,
                       int64_t started_ms, const char *name)
{
    task *t = &s->tasks[0];
    memset(t, 0, sizeof *t);
    snprintf(t->name, sizeof t->name, "%s", name);
    t->transport = transport;
    t->family = family;
    t->state = T_SHAPE_WAIT;
    t->started_ms = started_ms;
    t->report_id = ++s->report_sequence;
    t->report_closed = 0;
}

static void print_case(const char *label, const d2k_sched *s)
{
    const task *t = &s->tasks[0];
    printf("%s matched=%d snapped=%d trig_any=%d wait=%d done=%d\n",
           label,
           t->state != T_SHAPE_WAIT && t->state != T_FREE,
           t->trig_snapped,
           t->trig_len != 0,
           t->state == T_SHAPE_WAIT,
           t->state == T_FREE);
}

int main(void)
{
    uint8_t hello[2048];
    size_t hello_len = 0;
    if (build_hello("shape-wait.example.com", hello, sizeof hello, &hello_len) != 0) {
        return 2;
    }

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 2;
    d2k_catalog cat;
    memset(&cat, 0, sizeof cat);
    d2k_sched *s = d2k_sched_new(&cat, fds[0], 0x2d);
    if (!s) return 2;
    s->meas_limit = 0;
    s->clock_seen = 1;
    s->now_ms = 5000;

    d2k_ev ev;
    memset(&ev, 0, sizeof ev);
    ev.transport = 6;
    ev.family = 4;
    ev.shape_len = hello_len;
    memcpy(ev.shape, hello, hello_len);

    // Своё имя QUIC: production on_shape берёт имя из Initial, кладёт снимок
    // в trig и зовёт launch_or_queue.
    if (build_quic_snapshot(&ev, "shape-wait.example.com") != 0) return 2;
    ev.family = 4;
    reset_wait(s, 17, 4, s->now_ms, "shape-wait.example.com");
    on_shape(s, &ev);
    print_case("own_quic", s);

    // Чужое имя QUIC — ожидание не трогается.
    if (build_quic_snapshot(&ev, "other.example.com") != 0) return 2;
    ev.family = 4;
    reset_wait(s, 17, 4, s->now_ms, "shape-wait.example.com");
    on_shape(s, &ev);
    print_case("foreign_name", s);

    // Чужой транспорт: ждём QUIC, приходит TCP-снимок того же имени.
    ev.transport = 6;
    ev.family = 4;
    ev.shape_len = hello_len;
    memcpy(ev.shape, hello, hello_len);
    reset_wait(s, 17, 4, s->now_ms, "shape-wait.example.com");
    on_shape(s, &ev);
    print_case("foreign_transport", s);

    // Чужое семейство: ждём IPv4, приходит IPv6-снимок.
    if (build_quic_snapshot(&ev, "shape-wait.example.com") != 0) return 2;
    ev.family = 6;
    reset_wait(s, 17, 4, s->now_ms, "shape-wait.example.com");
    on_shape(s, &ev);
    print_case("foreign_family", s);

    // Срок вышел: lifetime-ветка тика закрывает задачу как task_done.
    if (build_quic_snapshot(&ev, "shape-wait.example.com") != 0) return 2;
    ev.family = 4;
    reset_wait(s, 17, 4, s->now_ms - SCHED_TASK_LIFE_MS - 1,
               "shape-wait.example.com");
    d2k_sched_tick(s, s->now_ms);
    print_case("timeout", s);

    d2k_sched_free(s);
    close(fds[0]);
    close(fds[1]);
    return 0;
}
