/* C/Rust differential: production `dns_health_start_due`/`dns_health_finish`
 * current D2O main 7a5fab9.
 *
 * Health-проба здесь настоящая только в ветке start_due: локальный порт 1
 * закрыт, поэтому worker завершается сразу. Результаты finish подаются
 * напрямую в поля задачи (как это делает worker), включая mock resolved_ip
 * для bootstrap-сценария. Проверяются переходы
 * Detected→Checking→DirectOk/Failed, next_check_ms, generation/IP reset,
 * одна проба за раз и точные C-тексты причин.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sched.c"

static d2k_catalog cat;
static int first = 1;

static const char *task_state_name(task_state state) {
    switch (state) {
    case T_FREE: return "free";
    case T_QUEUED: return "queued";
    case T_ASKING: return "asking";
    case T_SHAPE_WAIT: return "shape_wait";
    case T_PROPS_CONTACT: return "props_contact";
    case T_PROPS_WAIT: return "props_wait";
    case T_PLANNING: return "planning";
    case T_TRIAL_SETTLE: return "trial_settle";
    case T_VERIFY: return "verify";
    case T_VERIFY_WAIT: return "verify_wait";
    case T_WATCHING: return "watching";
    case T_RESTING: return "resting";
    case T_VOICE_MEASURE: return "voice_measure";
    case T_VOICE_TRIAL: return "voice_trial";
    case T_VOICE_WATCH: return "voice_watch";
    case T_DNS_HEALTH: return "dns_health";
    }
    return "unknown";
}

static void emit_task(const d2k_sched *s) {
    const task *t = NULL;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        if (s->tasks[i].state != T_FREE) { t = &s->tasks[i]; break; }
    }
    if (!t) { fputs("\"task\":null", stdout); return; }
    printf("\"task\":{\"state\":\"%s\",\"generation\":%llu,\"ip\":",
           task_state_name(t->state), (unsigned long long)t->dns_service_generation);
    json_str(stdout, t->ip);
    fputs(",\"name\":", stdout); json_str(stdout, t->name);
    fputs(",\"protocol\":", stdout); json_str(stdout, t->dns_protocol);
    fputs(",\"host\":", stdout); json_str(stdout, t->dns_host);
    fputs(",\"path\":", stdout); json_str(stdout, t->doh_path);
    fputs(",\"bootstrap\":", stdout); json_str(stdout, t->dns_bootstrap);
    printf(",\"transport\":%u,\"family\":%u,\"port\":%u}",
           (unsigned)t->transport, (unsigned)t->family, (unsigned)t->port);
}

static void emit(const char *scenario, d2k_sched *s) {
    printf("%s{\"scenario\":\"%s\",", first ? "" : ",\n", scenario);
    first = 0;
    write_live_dns_services(stdout, s);
    emit_task(s);
    fputc('}', stdout);
}

static d2k_sched *make(const char *protocol, const char *host, const char *sni,
                       const char *path, const char *bootstrap, uint16_t port) {
    d2k_sched *s = d2k_sched_new(&cat, -1, 0);
    if (!s) { perror("d2k_sched_new"); _exit(2); }
    s->now_ms = 5000;
    s->mono_base_ms = 0;
    s->wall_base_s = 2000;
    d2k_dns_service service;
    memset(&service, 0, sizeof service);
    snprintf(service.protocol, sizeof service.protocol, "%s", protocol);
    snprintf(service.host, sizeof service.host, "%s", host);
    snprintf(service.sni, sizeof service.sni, "%s", sni);
    snprintf(service.path, sizeof service.path, "%s", path);
    snprintf(service.bootstrap_dns, sizeof service.bootstrap_dns, "%s", bootstrap);
    snprintf(service.source, sizeof service.source, "test");
    service.port = port;
    d2k_sched_set_dns_services(s, &service, 1);
    return s;
}

static void fill_service(d2k_dns_service *service, const char *protocol,
                         const char *host, const char *sni, const char *path,
                         uint16_t port) {
    memset(service, 0, sizeof *service);
    snprintf(service->protocol, sizeof service->protocol, "%s", protocol);
    snprintf(service->host, sizeof service->host, "%s", host);
    snprintf(service->sni, sizeof service->sni, "%s", sni);
    snprintf(service->path, sizeof service->path, "%s", path);
    snprintf(service->source, sizeof service->source, "test");
    service->port = port;
}

static task *health_task(d2k_sched *s) {
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++)
        if (s->tasks[i].state == T_DNS_HEALTH) return &s->tasks[i];
    return NULL;
}

static void wait_ready(task *t) {
    for (int i = 0; i < 800; i++) {
        pthread_mutex_lock(&((d2k_sched *)t->worker_owner)->mu);
        int ready = t->res_ready;
        pthread_mutex_unlock(&((d2k_sched *)t->worker_owner)->mu);
        if (ready) return;
        usleep(10000);
    }
}

/* Start_due занимает worker; снимок «checking» делается сразу после вызова,
 * до finish, поэтому состояние live ещё не подменено результатом. */
static void start_and_cleanup(d2k_sched *s, const char *scenario) {
    dns_health_start_due(s, 5000);
    emit(scenario, s);
    task *t = health_task(s);
    if (t) {
        wait_ready(t);
        dns_health_finish(s, t, 5100);
    }
    d2k_sched_free(s);
}

static void fill_health(task *t, uint64_t generation, const char *ip,
                        const char *bootstrap, int level, int status,
                        int dns_reply, const char *reason) {
    memset(t, 0, sizeof *t);
    t->state = T_DNS_HEALTH;
    t->dns_health_probe = 1;
    t->dns_service_generation = generation;
    t->transport = 6;
    t->family = 4;
    t->port = 443;
    if (ip) snprintf(t->ip, sizeof t->ip, "%s", ip);
    snprintf(t->name, sizeof t->name, "dns.example");
    snprintf(t->dns_protocol, sizeof t->dns_protocol, "doh");
    snprintf(t->dns_host, sizeof t->dns_host, "dns.example");
    snprintf(t->doh_path, sizeof t->doh_path, "/dns-query");
    if (bootstrap) snprintf(t->dns_bootstrap, sizeof t->dns_bootstrap, "%s", bootstrap);
    t->ver.level = level;
    t->ver.status = status;
    t->ver.dns_reply = dns_reply;
    t->ver.fd = -1;
    snprintf(t->ver.reason, sizeof t->ver.reason, "%s", reason);
    t->res_ready = 1;
}

int main(void) {
    memset(&cat, 0, sizeof cat);
    printf("[");

    /* 1. DoH: старт пробы по закрытому порту → checking, задача занята. */
    start_and_cleanup(make("doh", "127.0.0.1", "dns.example", "/dns-query?x=1", "", 1),
                      "start_due_doh");

    /* 2. Bootstrap настроен и IP уже известен: C всё равно печатает
     *    bootstrap-причину, а worker затем идёт по известному IP. */
    {
        d2k_sched *s = make("doh", "dns.example", "dns.example", "/dns-query",
                            "127.0.0.1:1", 1);
        snprintf(s->dns_service_live[0].ip, sizeof s->dns_service_live[0].ip,
                 "127.0.0.1");
        start_and_cleanup(s, "start_due_bootstrap_known_ip");
    }

    /* 3. DoT: транспорт 6, protocol dot, sni пуст → имя — host. */
    start_and_cleanup(make("dot", "127.0.0.1", "", "", "", 1), "start_due_dot");

    /* 4. DoQ: транспорт 17 (порт 1 закрыт, IPv4 — стенд без IPv6). */
    start_and_cleanup(make("doq", "127.0.0.1", "", "", "", 1), "start_due_doq");

    /* 5. Уже checking — новой пробы нет. */
    {
        d2k_sched *s = make("doh", "127.0.0.1", "dns.example", "/dns-query", "", 1);
        s->dns_service_live[0].state = DNS_SERVICE_CHECKING;
        dns_health_start_due(s, 5000);
        emit("start_due_skip_checking", s);
        d2k_sched_free(s);
    }

    /* 6. next_check_ms в будущем — пробы нет. */
    {
        d2k_sched *s = make("doh", "127.0.0.1", "dns.example", "/dns-query", "", 1);
        s->dns_service_live[0].next_check_ms = 65000;
        dns_health_start_due(s, 5000);
        emit("start_due_skip_future", s);
        d2k_sched_free(s);
    }

    /* 7. Ни IP, ни bootstrap — пробы нет. */
    {
        d2k_sched *s = make("doh", "dns.example", "dns.example", "/dns-query", "", 1);
        dns_health_start_due(s, 5000);
        emit("start_due_skip_no_ip", s);
        d2k_sched_free(s);
    }

    /* 8. Две готовые службы — start_due занимает только одну T_DNS_HEALTH. */
    {
        d2k_sched *s = d2k_sched_new(&cat, -1, 0);
        if (!s) { perror("d2k_sched_new"); _exit(2); }
        s->now_ms = 5000;
        s->mono_base_ms = 0;
        s->wall_base_s = 2000;
        d2k_dns_service pair[2];
        fill_service(&pair[0], "doh", "127.0.0.1", "dns.example", "/dns-query", 1);
        fill_service(&pair[1], "doh", "127.0.0.1", "dns2.example", "/dns-query", 1);
        d2k_sched_set_dns_services(s, pair, 2);
        dns_health_start_due(s, 5000);
        emit("start_due_one_at_a_time", s);
        task *t = health_task(s);
        if (t) {
            wait_ready(t);
            dns_health_finish(s, t, 5100);
        }
        d2k_sched_free(s);
    }

    /* 9. Finish: успешный ответ поднимает DirectOk и ставит 5-минутный срок. */
    {
        d2k_sched *s = make("doh", "127.0.0.1", "dns.example", "/dns-query", "", 443);
        fill_health(&s->tasks[0], s->dns_service_live[0].generation, "127.0.0.1", "",
                    D2K_VER_APPLICATION, 200, 1,
                    "DoH: корректный RFC 8484 DNS-ответ");
        dns_health_finish(s, &s->tasks[0], 5100);
        emit("finish_direct_ok", s);
        d2k_sched_free(s);
    }

    /* 11. Finish: HTTP 413 — failed с отдельным текстом и минутным сроком. */
    {
        d2k_sched *s = make("doh", "127.0.0.1", "dns.example", "/dns-query", "", 443);
        fill_health(&s->tasks[0], s->dns_service_live[0].generation, "127.0.0.1", "",
                    D2K_VER_TRANSPORT, 413, 0, "HTTP 413");
        dns_health_finish(s, &s->tasks[0], 5100);
        emit("finish_failed_413", s);
        d2k_sched_free(s);
    }

    /* 12. Bootstrap получает IP: live.ip заполняется, план сброшен. */
    {
        d2k_sched *s = make("doh", "dns.example", "dns.example", "/dns-query",
                            "10.0.0.1", 443);
        s->dns_service_live[0].plan_applied = 1;
        snprintf(s->dns_service_live[0].applied_plan_id,
                 sizeof s->dns_service_live[0].applied_plan_id, "abababababababababababababababab");
        s->dns_service_live[0].plan_applied_ms = 5000;
        fill_health(&s->tasks[0], s->dns_service_live[0].generation, "203.0.113.9",
                    "10.0.0.1", D2K_VER_APPLICATION, 200, 1,
                    "DoH: корректный RFC 8484 DNS-ответ");
        dns_health_finish(s, &s->tasks[0], 5100);
        emit("finish_ip_change_bootstrap", s);
        d2k_sched_free(s);
    }

    /* 13. IP не совпал — результат чужой, live не меняется. */
    {
        d2k_sched *s = make("doh", "198.51.100.80", "dns.example", "/dns-query", "", 443);
        fill_health(&s->tasks[0], s->dns_service_live[0].generation, "198.51.100.81", "",
                    D2K_VER_APPLICATION, 200, 1,
                    "DoH: корректный RFC 8484 DNS-ответ");
        dns_health_finish(s, &s->tasks[0], 5100);
        emit("finish_ip_mismatch", s);
        d2k_sched_free(s);
    }

    /* 14. Старая generation: live не найден, ячейка освобождена. */
    {
        d2k_sched *s = make("doh", "198.51.100.80", "dns.example", "/dns-query", "", 443);
        fill_health(&s->tasks[0], s->dns_service_live[0].generation + 7,
                    "198.51.100.80", "", D2K_VER_APPLICATION, 200, 1,
                    "DoH: корректный RFC 8484 DNS-ответ");
        dns_health_finish(s, &s->tasks[0], 5100);
        emit("finish_stale_generation", s);
        d2k_sched_free(s);
    }

    printf("]\n");
    return 0;
}
