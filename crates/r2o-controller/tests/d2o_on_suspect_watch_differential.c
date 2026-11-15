/* C/Rust differential: on_suspect T_WATCHING planned=NO — ARM_SHAPE и
 * watch_shape_pending. C-оракул — production on_suspect (link arm). */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sched.c"

int main(void) {
    static d2k_sched s;
    static d2k_catalog cat;
    d2k_cat_box box;
    d2k_cat_plan plan;
    d2k_cat_binding bind;
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    memset(&box, 0, sizeof box);
    memset(&plan, 0, sizeof plan);
    memset(&bind, 0, sizeof bind);

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 1;
    s.link_fd = fds[0];
    s.now_ms = 5000;

    snprintf(plan.id, sizeof plan.id, "plan-watch");
    snprintf(plan.proto, sizeof plan.proto, "tls");
    plan.text = "r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n";
    plan.enabled = 1;
    box.plans = &plan;
    box.n_plans = 1;
    snprintf(bind.kind, sizeof bind.kind, "name");
    snprintf(bind.target, sizeof bind.target, "watch.example.com");
    snprintf(bind.plan_id, sizeof bind.plan_id, "plan-watch");
    bind.enabled = 1;
    bind.level = 3;
    bind.transport = 6;
    bind.family = 4;
    bind.shape = 1;
    bind.input = D2K_INPUT_PROFILE;
    box.binds = &bind;
    box.n_binds = 1;
    cat.boxes = &box;
    cat.n_boxes = 1;
    s.cat = &cat;

    task *t = &s.tasks[0];
    snprintf(t->name, sizeof t->name, "watch.example.com");
    t->transport = 6;
    t->family = 4;
    t->state = T_WATCHING;

    d2k_ev ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = D2K_EV_SUSPECT;
    snprintf(ev.name, sizeof ev.name, "watch.example.com");
    ev.transport = 6;
    ev.family = 4;
    ev.code = D2K_SUSPECT_RST;
    ev.planned = D2K_LINK_PLANNED_NO;
    ev.client_shape = D2K_PLAN_SHAPE_MODERN;
    inet_pton(AF_INET, "192.0.2.10", ev.low_ip);
    inet_pton(AF_INET, "198.51.100.20", ev.high_ip);
    ev.low_port = 40000;
    ev.high_port = 443;
    remember(&s, &ev);

    on_suspect(&s, &ev, 0);

    int arm = 0;
    struct pollfd pfd = {.fd = fds[1], .events = POLLIN};
    if (poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN)) {
        unsigned char head[6];
        if (read(fds[1], head, sizeof head) == (ssize_t)sizeof head) {
            arm = head[4] == (D2K_CMD_ARM_SHAPE >> 8) &&
                  head[5] == (D2K_CMD_ARM_SHAPE & 0xff);
        }
    }
    printf("watch_pending=%d arm_sent=%d queued=%d\n",
           t->watch_shape_pending, arm, t->state == T_QUEUED);
    close(fds[0]);
    close(fds[1]);
    return 0;
}
