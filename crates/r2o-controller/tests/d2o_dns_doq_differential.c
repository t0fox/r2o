/* C/Rust differential: DoQ DNS task-ячейка в live-секции current D2O main
 * 7a5fab9. Проверяются checking и bypass_ok по реальным полям C `task`:
 * dns_protocol=doq, name/ip/port, ver_ok, ver.dns_reply, ver.level. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_sched s;
static d2k_catalog cat;
static int first = 1;

static void emit(const char *scenario) {
    printf("%s{\"scenario\":\"%s\",", first ? "" : ",\n", scenario);
    first = 0;
    write_live_dns_services(stdout, &s);
    printf("\"end\":true}");
}

int main(void) {
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    s.cat = &cat;
    s.now_ms = 5000;
    s.mono_base_ms = 0;
    s.wall_base_s = 2000;

    d2k_dns_service service;
    memset(&service, 0, sizeof service);
    snprintf(service.protocol, sizeof service.protocol, "doq");
    snprintf(service.host, sizeof service.host, "2001:db8::1");
    snprintf(service.path, sizeof service.path, "/");
    snprintf(service.source, sizeof service.source, "doqd");
    service.port = 853;
    d2k_sched_set_dns_services(&s, &service, 1);
    printf("[");
    emit("configured");

    task *t = &s.tasks[0];
    memset(t, 0, sizeof *t);
    t->state = T_VERIFY;
    snprintf(t->dns_protocol, sizeof t->dns_protocol, "doq");
    snprintf(t->name, sizeof t->name, "2001:db8::1");
    snprintf(t->ip, sizeof t->ip, "2001:db8::1");
    t->port = 853;
    t->transport = 17;
    t->family = 6;
    t->ver_ok = 0;
    t->ver.level = D2K_VER_TRANSPORT;
    emit("checking");

    t->state = T_VERIFY;
    t->ver_ok = 1;
    t->ver.dns_reply = 1;
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 0;
    emit("bypass_ok");

    t->state = T_RESTING;
    t->ver_ok = 0;
    t->ver.dns_reply = 0;
    t->ver.level = D2K_VER_TRANSPORT;
    snprintf(t->ver.reason, sizeof t->ver.reason,
             "DoQ: ни один кандидат не подтвердил DNS-ответ");
    emit("no_bypass");

    printf("]\n");
    return 0;
}
