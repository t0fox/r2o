/* C/Rust differential: production on_applied/on_exchange для вопроса
 * о свойствах (T_PROPS_WAIT): plan_id/flow, reply-before-applied,
 * ServerHello и обновление DpiProps.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static const uint8_t plan_id[16] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
};
static const uint8_t foreign_plan[16] = {
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
};
static const uint8_t trial_id[16] = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
};

static void reset_task(task *t, int question, uint16_t local_port)
{
    memset(t, 0, sizeof *t);
    snprintf(t->name, sizeof t->name, "props.example.com");
    snprintf(t->ip, sizeof t->ip, "198.51.100.20");
    t->transport = 6;
    t->family = 4;
    t->state = T_PROPS_WAIT;
    t->prop_q = question;
    memcpy(t->prop_plan_id, plan_id, sizeof plan_id);
    t->prop_flow.family = 4;
    memcpy(t->prop_flow.a_ip, (uint8_t[]){192, 0, 2, 10}, 4);
    memcpy(t->prop_flow.b_ip, (uint8_t[]){198, 51, 100, 20}, 4);
    t->prop_flow.a_port = local_port;
    t->prop_flow.b_port = 443;
    t->prop_flow.transport = 6;
    t->prop_fd = -1;
    t->prop_bound_fd = -1;
    t->res.verdict = D2K_V_CLEAR;
}

static void make_event(d2k_ev *ev, const uint8_t *event_plan, uint16_t local_port,
                       int server_hello)
{
    memset(ev, 0, sizeof *ev);
    ev->transport = 6;
    ev->family = 4;
    memcpy(ev->plan_id, event_plan, sizeof plan_id);
    memcpy(ev->trial_id, trial_id, sizeof trial_id);
    memcpy(ev->low_ip, (uint8_t[]){192, 0, 2, 10}, 4);
    memcpy(ev->high_ip, (uint8_t[]){198, 51, 100, 20}, 4);
    ev->low_port = local_port;
    ev->high_port = 443;
    ev->server_hello = server_hello;
    ev->planned = D2K_LINK_PLANNED_NO;
}

static void print_case(d2k_sched *s, const char *label)
{
    task *t = &s->tasks[0];
    printf("%s applied=%d reply=%d passed=%d q=%d state=%d left=%d reorder=%d "
           "checksum=%d parse=%d dup=%d\n",
           label, t->prop_applied, t->prop_reply_seen,
           t->state == T_PLANNING, t->prop_q, (int)t->state,
           (int)t->props.tolerates_left_overlap,
           (int)t->props.tolerates_reorder,
           (int)t->props.validates_checksum,
           (int)t->props.parses_l7,
           (int)t->props.counts_duplicates);
}

int main(void)
{
    d2k_sched *s = calloc(1, sizeof *s);
    if (!s) return 2;
    s->now_ms = 1000;
    s->link_fd = -1;
    d2k_ev ev;

    reset_task(&s->tasks[0], 0, 40000);
    make_event(&ev, plan_id, 40000, 1);
    on_applied(s, &ev);
    on_exchange(s, &ev);
    print_case(s, "applied_then_exchange");

    reset_task(&s->tasks[0], 0, 40000);
    make_event(&ev, plan_id, 40000, 1);
    on_exchange(s, &ev);
    on_applied(s, &ev);
    print_case(s, "reply_before_applied");

    reset_task(&s->tasks[0], 0, 40000);
    make_event(&ev, foreign_plan, 40000, 1);
    on_applied(s, &ev);
    on_exchange(s, &ev);
    print_case(s, "foreign_plan");

    reset_task(&s->tasks[0], 0, 40000);
    make_event(&ev, plan_id, 40001, 1);
    on_applied(s, &ev);
    on_exchange(s, &ev);
    print_case(s, "foreign_flow");

    reset_task(&s->tasks[0], 0, 40000);
    make_event(&ev, plan_id, 40000, 0);
    on_applied(s, &ev);
    on_exchange(s, &ev);
    print_case(s, "no_server_hello");

    reset_task(&s->tasks[0], 3, 40000);
    make_event(&ev, plan_id, 40000, 1);
    on_applied(s, &ev);
    on_exchange(s, &ev);
    print_case(s, "question_parse");

    free(s);
    return 0;
}
