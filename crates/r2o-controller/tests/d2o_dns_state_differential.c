/* C/Rust differential: dns_service_observe / dns_service_note_applied и
 * live-состояние current D2O main 7a5fab9. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_sched s;
static d2k_catalog cat;
static d2k_ev ev;
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
    memset(&ev, 0, sizeof ev);
    s.cat = &cat;
    s.now_ms = 5000;
    s.mono_base_ms = 0;
    s.wall_base_s = 2000;

    d2k_dns_service service;
    memset(&service, 0, sizeof service);
    snprintf(service.protocol, sizeof service.protocol, "doh");
    snprintf(service.host, sizeof service.host, "198.51.100.80");
    snprintf(service.sni, sizeof service.sni, "dns.example");
    snprintf(service.path, sizeof service.path, "/dns-query?x=1");
    snprintf(service.source, sizeof service.source, "https-dns-proxy");
    service.port = 443;
    d2k_sched_set_dns_services(&s, &service, 1);
    printf("[");
    emit("configured");

    ev.family = 4;
    ev.transport = 6;
    ev.low_ip[0] = 127;
    ev.low_ip[3] = 1;
    ev.high_ip[0] = 198;
    ev.high_ip[1] = 51;
    ev.high_ip[2] = 100;
    ev.high_ip[3] = 80;
    ev.low_port = 40000;
    ev.high_port = 443;
    snprintf(ev.name, sizeof ev.name, "dns.example");
    dns_service_observe(&s, &ev, ev.name);
    emit("observed");

    ev.plan_id[0] = 0x11;
    dns_service_note_applied(&s, &ev);
    emit("applied");

    ev.high_ip[3] = 81;
    dns_service_observe(&s, &ev, ev.name);
    emit("ip_changed");

    s.dns_service_live[0].checked_ms = 5000;
    s.dns_service_live[0].tcp_reachable = 1;
    s.dns_service_live[0].tls_handshake = 1;
    s.dns_service_live[0].http_status = 200;
    s.dns_service_live[0].dns_answer = 1;
    s.dns_service_live[0].state = DNS_SERVICE_DIRECT_OK;
    s.dns_service_live[0].attempts = 2;
    snprintf(s.dns_service_live[0].reason, sizeof s.dns_service_live[0].reason,
             "DoH: получен корректный DNS-ответ");
    emit("health_success");

    s.dns_service_live[0].checked_ms = 5001;
    s.dns_service_live[0].tcp_reachable = 1;
    s.dns_service_live[0].tls_handshake = 0;
    s.dns_service_live[0].http_status = 413;
    s.dns_service_live[0].dns_answer = 0;
    s.dns_service_live[0].state = DNS_SERVICE_FAILED;
    s.dns_service_live[0].attempts = 3;
    snprintf(s.dns_service_live[0].reason, sizeof s.dns_service_live[0].reason,
             "HTTP 413: это ошибка endpoint, а не доказательство DPI; подбор не запускается.");
    emit("health_413");

    // План применён к живому DNS-соединению, DNS-ответ прямого health-зонда
    // есть: без task-candidate C оставляет state plan_applied.
    s.dns_service_live[0].state = DNS_SERVICE_DETECTED;
    s.dns_service_live[0].plan_applied = 1;
    s.dns_service_live[0].plan_applied_ms = 5000;
    snprintf(s.dns_service_live[0].applied_plan_id,
             sizeof s.dns_service_live[0].applied_plan_id, "abababababababababababababababab");
    s.dns_service_live[0].dns_answer = 1;
    emit("plan_applied_with_answer");

    // Task-candidate: plan применён к пробному DNS-соединению и получен
    // DNS-ответ — bypass_ok.
    task *t = &s.tasks[0];
    memset(t, 0, sizeof *t);
    t->state = T_VERIFY;
    snprintf(t->dns_protocol, sizeof t->dns_protocol, "doh");
    snprintf(t->name, sizeof t->name, "dns.example");
    t->port = 443;
    t->ver_ok = 1;
    t->ver.dns_reply = 1;
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;
    emit("bypass_ok");

    printf("]\n");
    return 0;
}
