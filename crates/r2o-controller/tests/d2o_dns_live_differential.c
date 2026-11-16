/* C/Rust differential: live-секция dns_services D2O current main 7a5fab9.
 *
 * Вызывает настоящие `d2k_sched_set_dns_services` + `write_live_dns_services`
 * на синтетическом планировщике. Health-проб нет: состояния Detected/
 * DirectOk/Failed и task-ячейки (T_VERIFY/T_RESTING) подаются напрямую, как
 * их оставляет production. Проверяются DoH/DoT/DoQ, known_plan_id по
 * binding, candidate-without-answer и no_bypass/plan_applied. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_sched s;
static d2k_catalog cat;
static d2k_cat_box box;
static d2k_cat_binding bindings[3];
static d2k_cat_plan plans[3];
static int first = 1;

static void service(d2k_dns_service *out, const char *protocol, const char *host,
                    const char *sni, const char *path, const char *source,
                    uint16_t port) {
    memset(out, 0, sizeof *out);
    snprintf(out->protocol, sizeof out->protocol, "%s", protocol);
    snprintf(out->host, sizeof out->host, "%s", host);
    snprintf(out->sni, sizeof out->sni, "%s", sni);
    snprintf(out->path, sizeof out->path, "%s", path);
    snprintf(out->source, sizeof out->source, "%s", source);
    out->port = port;
}

static void emit(const char *scenario) {
    printf("%s{\"scenario\":\"%s\",", first ? "" : ",\n", scenario);
    first = 0;
    write_live_dns_services(stdout, &s);
    printf("\"end\":true}");
}

static void reset_live(size_t index) {
    dns_service_live *live = &s.dns_service_live[index];
    live->state = DNS_SERVICE_DETECTED;
    live->tcp_reachable = live->tls_handshake = live->http_status = live->dns_answer = 0;
    live->plan_applied = 0;
    live->applied_plan_id[0] = '\0';
    live->plan_applied_ms = 0;
    live->checked_ms = 0;
    live->attempts = 0;
    live->reason[0] = '\0';
}

static void set_task(size_t slot, const char *protocol, const char *name, uint16_t port,
                     int ver_ok, int level, int status, int dns_reply,
                     const char *reason) {
    task *t = &s.tasks[slot];
    memset(t, 0, sizeof *t);
    t->state = T_VERIFY;
    snprintf(t->dns_protocol, sizeof t->dns_protocol, "%s", protocol);
    snprintf(t->name, sizeof t->name, "%s", name);
    t->port = port;
    t->ver_ok = ver_ok;
    t->ver.level = level;
    t->ver.status = status;
    t->ver.dns_reply = dns_reply;
    snprintf(t->ver.reason, sizeof t->ver.reason, "%s", reason);
}

int main(void) {
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    memset(&box, 0, sizeof box);
    memset(bindings, 0, sizeof bindings);
    memset(plans, 0, sizeof plans);
    s.wall_base_s = 2000;

    snprintf(plans[0].id, sizeof plans[0].id, "plan-dns");
    snprintf(plans[0].proto, sizeof plans[0].proto, "tls");
    plans[0].text = "r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n";
    plans[0].enabled = 1;
    plans[0].successes = 1;
    snprintf(plans[1].id, sizeof plans[1].id, "plan-dot");
    snprintf(plans[1].proto, sizeof plans[1].proto, "tls");
    plans[1].text = plans[0].text;
    plans[1].enabled = 1;
    plans[1].successes = 1;
    snprintf(plans[2].id, sizeof plans[2].id, "plan-doq");
    snprintf(plans[2].proto, sizeof plans[2].proto, "tls");
    plans[2].text = plans[0].text;
    plans[2].enabled = 1;
    plans[2].successes = 1;
    box.plans = plans;
    box.n_plans = 3;

    snprintf(bindings[0].kind, sizeof bindings[0].kind, "name");
    snprintf(bindings[0].target, sizeof bindings[0].target, "dns.example");
    snprintf(bindings[0].plan_id, sizeof bindings[0].plan_id, "plan-dns");
    bindings[0].level = 3;
    bindings[0].enabled = 1;
    bindings[0].transport = 6;
    bindings[0].family = 4;
    bindings[0].shape = 1;

    snprintf(bindings[1].kind, sizeof bindings[1].kind, "name");
    snprintf(bindings[1].target, sizeof bindings[1].target, "1.1.1.1");
    snprintf(bindings[1].plan_id, sizeof bindings[1].plan_id, "plan-dot");
    bindings[1].level = 3;
    bindings[1].enabled = 1;
    bindings[1].transport = 6;
    bindings[1].family = 4;
    bindings[1].shape = 1;

    snprintf(bindings[2].kind, sizeof bindings[2].kind, "name");
    snprintf(bindings[2].target, sizeof bindings[2].target, "2001:db8::1");
    snprintf(bindings[2].plan_id, sizeof bindings[2].plan_id, "plan-doq");
    bindings[2].level = 3;
    bindings[2].enabled = 1;
    bindings[2].transport = 17;
    bindings[2].family = 6;
    bindings[2].shape = 1;

    box.binds = bindings;
    box.n_binds = 3;
    snprintf(box.id, sizeof box.id, "box-dns");
    cat.boxes = &box;
    cat.n_boxes = 1;
    s.cat = &cat;

    d2k_dns_service services[3];
    service(&services[0], "doh", "dns.example", "dns.example",
            "/dns-query?token=secret", "https-dns-proxy", 443);
    service(&services[1], "dot", "1.1.1.1", "", "/", "dnsproxy", 853);
    service(&services[2], "doq", "2001:db8::1", "", "/", "doqd", 853);
    d2k_sched_set_dns_services(&s, services, 3);

    printf("[");
    emit("configured");

    // DoT: health-проба прямого потока получила ответ, binding DoT виден.
    s.dns_service_live[1].state = DNS_SERVICE_DIRECT_OK;
    s.dns_service_live[1].checked_ms = 5000;
    s.dns_service_live[1].tcp_reachable = 1;
    s.dns_service_live[1].tls_handshake = 1;
    s.dns_service_live[1].http_status = 200;
    s.dns_service_live[1].dns_answer = 1;
    s.dns_service_live[1].attempts = 2;
    snprintf(s.dns_service_live[1].reason, sizeof s.dns_service_live[1].reason,
             "DoT: получен корректный DNS-ответ");
    emit("dot_health_success");

    // DoQ IPv6: health-проба получила 413, binding DoQ (transport 17/family 6).
    s.dns_service_live[2].state = DNS_SERVICE_FAILED;
    s.dns_service_live[2].checked_ms = 5001;
    s.dns_service_live[2].tcp_reachable = 1;
    s.dns_service_live[2].tls_handshake = 0;
    s.dns_service_live[2].http_status = 413;
    s.dns_service_live[2].dns_answer = 0;
    s.dns_service_live[2].attempts = 3;
    snprintf(s.dns_service_live[2].reason, sizeof s.dns_service_live[2].reason,
             "HTTP 413: это ошибка endpoint, а не доказательство DPI; подбор не запускается.");
    emit("doq_health_failed");

    // DoH-кандидат применён, DNS-ответа нет: checking с причиной кандидата.
    reset_live(0);
    set_task(0, "doh", "dns.example", 443, 1, D2K_VER_APPLICATION, 200, 0,
             "Кандидат применён, но DNS-ответ не получен.");
    emit("doh_candidate_without_answer");

    // Тот же кандидат с DNS-ответом: bypass_ok.
    s.tasks[0].ver.dns_reply = 1;
    emit("doh_candidate_bypass");

    // DoQ-кандидат применён без ответа: task по имени 2001:db8::1 и doq.
    s.tasks[0].state = T_FREE;
    set_task(1, "doq", "2001:db8::1", 853, 1, D2K_VER_APPLICATION, 200, 0,
             "DoQ: кандидат применён, DNS-ответ не получен.");
    emit("doq_candidate_without_answer");

    // План live применён, task в T_RESTING с применённым кандидатом без
    // ответа: plan_applied раньше no_bypass, candidate=1, via_plan=0.
    s.tasks[1].state = T_FREE;
    reset_live(0);
    s.dns_service_live[0].plan_applied = 1;
    s.dns_service_live[0].plan_applied_ms = 5000;
    snprintf(s.dns_service_live[0].applied_plan_id,
             sizeof s.dns_service_live[0].applied_plan_id, "abababababababababababababababab");
    set_task(0, "doh", "dns.example", 443, 1, D2K_VER_APPLICATION, 200, 0,
             "Кандидат применён, но DNS-ответ не получен.");
    s.tasks[0].state = T_RESTING;
    emit("doh_plan_applied_task_resting");

    printf("]\n");
    return 0;
}
