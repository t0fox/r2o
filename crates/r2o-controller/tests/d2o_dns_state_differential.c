/* C/Rust differential: dns_service_observe / dns_service_note_applied,
 * task-ячейки DNS (T_VERIFY/T_VERIFY_WAIT/T_TRIAL_SETTLE/T_WATCHING/
 * T_RESTING/T_DNS_HEALTH) и live-состояние current D2O main 7a5fab9. */
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

    // plan_applied + failed: writer добавляет «Автопроверка: …» с точностью
    // C `%.100s` (байты, не символы).
    s.dns_service_live[0].state = DNS_SERVICE_FAILED;
    s.dns_service_live[0].checked_ms = 5001;
    snprintf(s.dns_service_live[0].reason, sizeof s.dns_service_live[0].reason,
             "HTTP 413: это ошибка endpoint, а не доказательство DPI; подбор не запускается.");
    emit("plan_applied_failed");

    // Task-candidate: plan применён к пробному DNS-соединению и получен
    // DNS-ответ — bypass_ok. live.dns_answer сброшен, чтобы доказать, что
    // ответ пришёл из t->ver.dns_reply, а не из health-пробы.
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
    s.dns_service_live[0].state = DNS_SERVICE_DETECTED;
    s.dns_service_live[0].plan_applied = 0;
    s.dns_service_live[0].applied_plan_id[0] = '\0';
    s.dns_service_live[0].plan_applied_ms = 0;
    s.dns_service_live[0].dns_answer = 0;
    s.dns_service_live[0].checked_ms = 0;
    s.dns_service_live[0].tcp_reachable = 0;
    s.dns_service_live[0].tls_handshake = 0;
    s.dns_service_live[0].http_status = 0;
    emit("bypass_ok");

    // Кандидат применён, но DNS-ответа нет: не bypass, а checking с
    // причиной кандидата; candidate_plan_applied=1, via_plan=0.
    t->ver.dns_reply = 0;
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;
    emit("candidate_without_answer");

    // Зонд вернулся, ждём применения плана к его потоку.
    t->state = T_VERIFY_WAIT;
    t->ver_ok = 0;
    t->ver.level = D2K_VER_TRANSPORT;
    t->ver.status = 0;
    t->ver.dns_reply = 0;
    snprintf(t->ver.reason, sizeof t->ver.reason, "проба не завершилась: таймаут");
    emit("verify_wait");

    // План записан в сокет, ждём принятия датапатом.
    t->state = T_TRIAL_SETTLE;
    t->ver_ok = 1;
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;
    t->ver.dns_reply = 0;
    emit("trial_settle");

    // Task перекрывает health-поля live: tcp/tls/http берутся из t->ver.
    t->state = T_VERIFY;
    t->ver_ok = 0;
    t->ver.level = D2K_VER_TRANSPORT;
    t->ver.status = 0;
    s.dns_service_live[0].tcp_reachable = 1;
    s.dns_service_live[0].tls_handshake = 1;
    s.dns_service_live[0].http_status = 200;
    emit("task_overrides_health");

    // Подтверждённая задача в T_WATCHING без плана live и без ответа:
    // общая ветка «Подозрение передано в штатный конвейер D2O».
    t->state = T_WATCHING;
    t->ver_ok = 1;
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;
    t->ver.dns_reply = 0;
    s.dns_service_live[0].tcp_reachable = 0;
    s.dns_service_live[0].tls_handshake = 0;
    s.dns_service_live[0].http_status = 0;
    emit("generic_watching");

    // T_RESTING после исчерпанного поиска: no_bypass с собственным
    // t->ver.reason.
    t->state = T_RESTING;
    t->ver_ok = 0;
    t->ver.dns_reply = 0;
    t->ver.status = 0;
    t->ver.level = 0;
    snprintf(t->ver.reason, sizeof t->ver.reason,
             "Поиск завершён: подходящего плана нет.");
    emit("no_bypass");

    // Пустой ver.reason — C-текст по умолчанию.
    t->ver.reason[0] = '\0';
    emit("no_bypass_default");

    // T_DNS_HEALTH не участвует в отборе writer: live отдаёт detected.
    memset(t, 0, sizeof *t);
    t->state = T_DNS_HEALTH;
    t->dns_health_probe = 1;
    snprintf(t->dns_protocol, sizeof t->dns_protocol, "doh");
    snprintf(t->name, sizeof t->name, "dns.example");
    t->port = 443;
    t->ver_ok = 1;
    t->ver.dns_reply = 1;
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;
    s.dns_service_live[0].state = DNS_SERVICE_DETECTED;
    s.dns_service_live[0].plan_applied = 0;
    s.dns_service_live[0].applied_plan_id[0] = '\0';
    s.dns_service_live[0].plan_applied_ms = 0;
    s.dns_service_live[0].dns_answer = 0;
    s.dns_service_live[0].checked_ms = 0;
    s.dns_service_live[0].tcp_reachable = 0;
    s.dns_service_live[0].tls_handshake = 0;
    s.dns_service_live[0].http_status = 0;
    emit("task_health_ignored");

    printf("]\n");
    return 0;
}
