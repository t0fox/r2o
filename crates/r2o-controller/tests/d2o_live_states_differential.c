/* C/Rust differential: полный live.json в семи состояниях.
 *
 * Состояние передаётся argv[1]: empty, boxes, bindings, groups,
 * measurements, tasks, dns. C-оракул — production d2k_sched_write_live
 * current main 7a5fab9. Каждое состояние печатает один полный JSON.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_sched s;
static d2k_catalog cat;
static d2k_group_state groups;
static d2k_cat_box boxes[1];
static d2k_cat_plan plans[2];
static d2k_cat_binding binds[7];
static d2k_cat_signal signals[7];
static installed_area areas[1];

static void reset(void) {
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    memset(&groups, 0, sizeof groups);
    memset(&boxes, 0, sizeof boxes);
    memset(&plans, 0, sizeof plans);
    memset(&binds, 0, sizeof binds);
    memset(&signals, 0, sizeof signals);
    memset(&areas, 0, sizeof areas);
    s.cat = &cat;
    s.now_ms = 5000;
    s.wall_base_s = 2000;
    s.mono_base_ms = 1000;
    s.meas_limit = 3;
}

static void set_suspect(const char *name) {
    s.event_sequence = 10;
    s.suspect_events = 5;
    snprintf(s.last_suspect_name, sizeof s.last_suspect_name, "%s", name);
    s.last_suspect_transport = 6;
    s.last_suspect_family = 4;
}

/* Все ветви C `signal_human`: rst, volume, rx-volume, rx-volume-wire,
   silent, repeat и неизвестный kind. */
static void all_signals(void) {
    snprintf(signals[0].kind, sizeof signals[0].kind, "rst");
    signals[0].ttl = 64;
    signals[0].ttl_delta = -3;
    signals[0].tos = 0x88;
    signals[0].ipid = 1234;
    signals[0].seen = 1;
    snprintf(signals[1].kind, sizeof signals[1].kind, "volume");
    signals[1].volume = 40;
    signals[1].seen = 2;
    snprintf(signals[2].kind, sizeof signals[2].kind, "rx-volume");
    signals[2].volume = 16;
    signals[2].packets = 22;
    signals[2].seen = 3;
    snprintf(signals[3].kind, sizeof signals[3].kind, "rx-volume-wire");
    signals[3].volume = 12;
    signals[3].seen = 4;
    snprintf(signals[4].kind, sizeof signals[4].kind, "silent");
    signals[4].seen = 5;
    snprintf(signals[5].kind, sizeof signals[5].kind, "repeat");
    signals[5].seen = 6;
    snprintf(signals[6].kind, sizeof signals[6].kind, "custom-kind");
    signals[6].seen = 7;
    boxes[0].fp.method = 2;
    boxes[0].fp.n_sig = 7;
    memcpy(boxes[0].fp.sig, signals, sizeof signals);
}

static void one_plan(const char *id, const char *proto, const char *text,
                     int successes, int enabled) {
    snprintf(plans[0].id, sizeof plans[0].id, "%s", id);
    snprintf(plans[0].proto, sizeof plans[0].proto, "%s", proto);
    plans[0].text = (char *)text;
    plans[0].added = 1100;
    plans[0].successes = successes;
    plans[0].enabled = enabled;
    boxes[0].plans = plans;
    boxes[0].n_plans = 1;
}

static void binding(d2k_cat_binding *b, const char *target, const char *plan,
                    const char *kind, uint8_t transport, uint8_t family,
                    uint8_t shape, int level, int enabled, int recheck) {
    snprintf(b->kind, sizeof b->kind, "%s", kind);
    snprintf(b->target, sizeof b->target, "%s", target);
    snprintf(b->plan_id, sizeof b->plan_id, "%s", plan);
    b->level = level;
    b->confirmed = 1500;
    b->successes = 1;
    b->enabled = enabled;
    b->transport = transport;
    b->family = family;
    b->shape = shape;
    b->tcp_profile = 0;
    b->verified_by = 1;
    b->input = 2;
    snprintf(b->probe_path, sizeof b->probe_path, "/probe.css");
    snprintf(b->ech_origin, sizeof b->ech_origin, "edge.example");
    b->budget = 3;
    b->recheck_since = recheck;
}

static void base_box(void) {
    snprintf(boxes[0].id, sizeof boxes[0].id, "box-1");
    boxes[0].created = 1000;
    boxes[0].updated = 2000;
}

static void emit_boxes(void) {
    base_box();
    all_signals();
    one_plan("plan-1", "tls",
             "r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n", 5, 1);
    cat.boxes = boxes;
    cat.n_boxes = 1;
}

static void emit_bindings(void) {
    emit_boxes();
    binding(&binds[0], "perm.example", "plan-1", "name", 6, 4, 1, 3, 1, 0);
    binding(&binds[1], "temp.example", "plan-1", "name", 6, 4, 1, 2, 0, 1);
    binding(&binds[2], "quic.example", "plan-1", "name", 17, 4, 3, 3, 1, 0);
    binding(&binds[3], "addr.example", "plan-1", "addr", 6, 6, 2, 1, 1, 0);
    /* legacy transport/family 0: C live печатает 6/4; уровни 0,4,5. */
    binding(&binds[4], "legacy.example", "plan-1", "name", 0, 0, 0, 0, 1, 0);
    binding(&binds[5], "level4.example", "plan-1", "addr", 6, 4, 1, 4, 1, 0);
    binding(&binds[6], "level5.example", "plan-1", "addr", 6, 4, 1, 5, 1, 0);
    for (size_t i = 0; i < 7; i++) {
        binds[i].confirmed = 1500 + (int64_t)i;
        binds[i].successes = (int)i + 1;
    }
    boxes[0].binds = binds;
    boxes[0].n_binds = 7;
}

static void emit_groups(void) {
    emit_boxes();
    cat.groups = &groups;
    groups.n_groups = 1;
    snprintf(groups.groups[0].suffix, sizeof groups.groups[0].suffix, "example.com");
    snprintf(groups.groups[0].plan_id, sizeof groups.groups[0].plan_id, "plan-1");
    groups.groups[0].key.transport = 6;
    groups.groups[0].key.family = 4;
    groups.groups[0].key.shape = 1;
    groups.groups[0].evidence_count = 2;
    groups.groups[0].at = 1500;
    groups.n_observations = 1;
    snprintf(groups.observations[0].name, sizeof groups.observations[0].name,
             "a.example.com");
    snprintf(groups.observations[0].plan_id,
             sizeof groups.observations[0].plan_id, "plan-1");
    groups.observations[0].key.transport = 6;
    groups.observations[0].key.family = 4;
    groups.observations[0].key.shape = 1;
    groups.observations[0].evidence = D2K_GROUP_BLOCKED_CONFIRMED;
    groups.observations[0].at = 1400;
    snprintf(areas[0].name, sizeof areas[0].name, "example.com");
    snprintf(areas[0].plan_id, sizeof areas[0].plan_id, "plan-1");
    areas[0].kind = 1;
    areas[0].transport = 6;
    areas[0].shape = 1;
    areas[0].family = 4;
    areas[0].confirmed = 1;
    s.areas = areas;
    s.n_areas = 1;
    set_suspect("target.example");
    /* Активный challenge-cooldown: autopick печатает остаток секунд. */
    s.cooldowns[0].used = 1;
    s.cooldowns[0].challenge = 1;
    s.cooldowns[0].transport = 6;
    s.cooldowns[0].family = 4;
    s.cooldowns[0].until_ms = 6000;
    snprintf(s.cooldowns[0].name, sizeof s.cooldowns[0].name, "target.example");
    s.confirms = 7;
    s.probes_used = 42;
    s.unfit_client = 3;
}

static void emit_measurements(void) {
    s.cpu_valid = 1;
    s.cpu_cores = 4;
    s.cpu_free_u = 750000;
    s.mem_valid = 1;
    s.mem_avail_kb = 512000;
    s.mem_total_kb = 1048576;
    s.ct_valid = 1;
    s.ct_count = 100;
    s.ct_max = 1000;
    s.limiter = MEAS_LIM_CPU;
    set_suspect("target.example");
    s.confirms = 7;
    s.probes_used = 42;
    s.unfit_client = 3;
}

static task *task_slot(size_t index) { return &s.tasks[index]; }

static void emit_tasks(void) {
    set_suspect("target.example");
    task *t = task_slot(0);
    snprintf(t->name, sizeof t->name, "ask.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.10");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_ASKING;
    t->began_ms = 2000;
    t->probes = 2;
    t->ask_probes = 1;
    snprintf(t->ask_question, sizeof t->ask_question, "вопрос");

    t = task_slot(1);
    snprintf(t->name, sizeof t->name, "verify.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.11");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_VERIFY;
    t->began_ms = 3000;
    t->probes = 3;
    t->next_plan = 1;
    t->n_plans = 2;
    t->n_known = 1;

    t = task_slot(2);
    snprintf(t->name, sizeof t->name, "verifywait.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.12");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_VERIFY_WAIT;
    t->began_ms = 4000;
    t->probes = 4;
    t->next_plan = 2;
    t->n_plans = 2;

    t = task_slot(3);
    snprintf(t->name, sizeof t->name, "trial.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.13");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_TRIAL_SETTLE;
    t->began_ms = 5000;
    t->probes = 5;
    t->next_plan = 2;
    t->n_plans = 3;
    t->fb_queue = 1;
    t->fb_from = 1;

    t = task_slot(4);
    snprintf(t->name, sizeof t->name, "watching.example");
    t->state = T_WATCHING;

    t = task_slot(5);
    snprintf(t->name, sizeof t->name, "resting.example");
    t->state = T_RESTING;

    /* Остальные phase-строки C `task_phase` и since из queued_ms. */
    t = task_slot(6);
    snprintf(t->name, sizeof t->name, "queued.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.14");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_QUEUED;
    t->queued_ms = 3500;
    t->next_plan = 0;

    t = task_slot(7);
    snprintf(t->name, sizeof t->name, "shapewait.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.15");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_SHAPE_WAIT;
    t->began_ms = 2500;
    t->probes = 1;

    t = task_slot(8);
    snprintf(t->name, sizeof t->name, "propscontact.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.16");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_PROPS_CONTACT;
    t->began_ms = 2600;
    t->probes = 1;

    t = task_slot(9);
    snprintf(t->name, sizeof t->name, "propswait.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.17");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_PROPS_WAIT;
    t->began_ms = 2700;
    t->probes = 1;

    t = task_slot(10);
    snprintf(t->name, sizeof t->name, "planning.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.18");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_PLANNING;
    t->began_ms = 2800;
    t->probes = 2;

    t = task_slot(11);
    snprintf(t->name, sizeof t->name, "voicemeasure.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.19");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_VOICE_MEASURE;
    t->began_ms = 2900;
    t->probes = 1;

    t = task_slot(12);
    snprintf(t->name, sizeof t->name, "voicetrial.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.20");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_VOICE_TRIAL;
    t->began_ms = 3000;

    t = task_slot(13);
    snprintf(t->name, sizeof t->name, "voicewatch.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.21");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_VOICE_WATCH;
    t->began_ms = 3100;

    t = task_slot(14);
    snprintf(t->name, sizeof t->name, "dnshealth.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.22");
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = T_DNS_HEALTH;
    t->began_ms = 3200;
    t->probes = 1;
}

static void dns_service(d2k_dns_service *out, const char *protocol,
                        const char *host, const char *sni, const char *path,
                        const char *source, uint16_t port) {
    memset(out, 0, sizeof *out);
    snprintf(out->protocol, sizeof out->protocol, "%s", protocol);
    snprintf(out->host, sizeof out->host, "%s", host);
    snprintf(out->sni, sizeof out->sni, "%s", sni);
    snprintf(out->path, sizeof out->path, "%s", path);
    snprintf(out->source, sizeof out->source, "%s", source);
    out->port = port;
}

static void dns_catalog(void) {
    memset(&cat, 0, sizeof cat);
    s.cat = &cat;
    memset(boxes, 0, sizeof boxes);
    memset(plans, 0, sizeof plans);
    memset(binds, 0, sizeof binds);
    snprintf(boxes[0].id, sizeof boxes[0].id, "box-dns");
    snprintf(plans[0].id, sizeof plans[0].id, "plan-doh");
    snprintf(plans[0].proto, sizeof plans[0].proto, "tls");
    plans[0].text = (char *)"r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n";
    plans[0].enabled = 1;
    snprintf(plans[1].id, sizeof plans[1].id, "plan-doq");
    snprintf(plans[1].proto, sizeof plans[1].proto, "quic");
    plans[1].text = (char *)"r2o-plan 2 11\nproto quic h3\nsplit sni_middle +0\n";
    plans[1].enabled = 1;
    boxes[0].plans = plans;
    boxes[0].n_plans = 2;
    binding(&binds[0], "checking.example", "plan-doh", "name", 6, 4, 1, 3, 1, 0);
    binding(&binds[1], "bypass.example", "plan-doh", "name", 6, 4, 1, 3, 1, 0);
    binding(&binds[2], "candidate.example", "plan-doh", "name", 6, 4, 1, 3, 1, 0);
    binding(&binds[3], "2001:db8::1", "plan-doq", "name", 17, 6, 3, 3, 1, 0);
    boxes[0].binds = binds;
    boxes[0].n_binds = 4;
    cat.boxes = boxes;
    cat.n_boxes = 1;
}

static task *dns_task(size_t index, const char *name, const char *ip,
                      task_state state) {
    task *t = task_slot(index);
    snprintf(t->name, sizeof t->name, "%s", name);
    snprintf(t->ip, sizeof t->ip, "%s", ip);
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    snprintf(t->dns_protocol, sizeof t->dns_protocol, "doh");
    t->state = state;
    return t;
}

static void emit_dns(void) {
    dns_catalog();
    d2k_dns_service services[16];
    dns_service(&services[0], "doh", "detected.example", "detected.example",
                "/dns-query?token=secret", "https-dns-proxy", 443);
    dns_service(&services[1], "dot", "1.1.1.1", "", "/", "dnsproxy", 853);
    dns_service(&services[2], "doh", "checking.example", "checking.example",
                "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[3], "doh", "direct.example", "direct.example",
                "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[4], "doh", "applied.example", "applied.example",
                "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[5], "doh", "bypass.example", "bypass.example",
                "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[6], "doh", "nobypass.example", "nobypass.example",
                "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[7], "doh", "failed.example", "failed.example",
                "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[8], "doh", "candidate.example", "candidate.example",
                "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[9], "doq", "2001:db8::1", "", "/", "doqd", 853);
    dns_service(&services[10], "doh", "appliedfailed.example",
                "appliedfailed.example", "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[11], "doh", "split.example", "split.example",
                "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[12], "doh", "liveanswer.example",
                "liveanswer.example", "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[13], "doh", "noreason.example",
                "noreason.example", "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[14], "doh", "taskother.example",
                "taskother.example", "/dns-query", "https-dns-proxy", 443);
    dns_service(&services[15], "doh", "verifyplain.example",
                "verifyplain.example", "/dns-query", "https-dns-proxy", 443);
    d2k_sched_set_dns_services(&s, services, 16);

    dns_service_live *live = s.dns_service_live;
    snprintf(live[2].ip, sizeof live[2].ip, "198.51.100.20");
    live[2].state = DNS_SERVICE_CHECKING;
    snprintf(live[2].reason, sizeof live[2].reason,
             "Проверяем прямой HTTPS-ответ endpoint.");
    live[2].attempts = 2;
    live[2].checked_ms = 3000;

    snprintf(live[3].ip, sizeof live[3].ip, "198.51.100.21");
    live[3].state = DNS_SERVICE_DIRECT_OK;
    snprintf(live[3].reason, sizeof live[3].reason,
             "Прямой HTTPS-ответ endpoint получен.");
    live[3].tcp_reachable = 1;
    live[3].tls_handshake = 1;
    live[3].http_status = 200;
    live[3].dns_answer = 1;
    live[3].attempts = 3;
    live[3].checked_ms = 3500;

    snprintf(live[4].ip, sizeof live[4].ip, "198.51.100.22");
    live[4].plan_applied = 1;
    snprintf(live[4].applied_plan_id, sizeof live[4].applied_plan_id,
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    live[4].plan_applied_ms = 4000;

    snprintf(live[5].ip, sizeof live[5].ip, "198.51.100.23");
    snprintf(live[6].ip, sizeof live[6].ip, "198.51.100.24");
    snprintf(live[7].ip, sizeof live[7].ip, "198.51.100.25");
    live[7].state = DNS_SERVICE_FAILED;
    snprintf(live[7].reason, sizeof live[7].reason,
             "Прямая проверка endpoint не удалась.");
    live[7].attempts = 4;
    live[7].checked_ms = 4500;
    snprintf(live[8].ip, sizeof live[8].ip, "198.51.100.26");

    snprintf(live[10].ip, sizeof live[10].ip, "198.51.100.27");
    live[10].state = DNS_SERVICE_FAILED;
    live[10].plan_applied = 1;
    snprintf(live[10].applied_plan_id, sizeof live[10].applied_plan_id,
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    snprintf(live[10].reason, sizeof live[10].reason,
             "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
             "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
             "abcdefghijklmnopqrstuvwxyz");
    live[10].attempts = 5;
    live[10].checked_ms = 5000;
    live[10].plan_applied_ms = 5000;

    /* 99 ASCII-байт и «б»: C %.100s обрывает UTF-8 посередине символа.
       Панель читает такой JSON с U+FFFD; Rust обязан дать тот же вид. */
    snprintf(live[11].ip, sizeof live[11].ip, "198.51.100.28");
    live[11].state = DNS_SERVICE_FAILED;
    live[11].plan_applied = 1;
    snprintf(live[11].applied_plan_id, sizeof live[11].applied_plan_id,
             "cccccccccccccccccccccccccccccccc");
    memset(live[11].reason, 'a', 99);
    memcpy(live[11].reason + 99, "б", 3);
    live[11].attempts = 6;
    live[11].checked_ms = 5000;
    live[11].plan_applied_ms = 5000;

    snprintf(live[12].ip, sizeof live[12].ip, "198.51.100.29");
    live[12].dns_answer = 1;
    snprintf(live[13].ip, sizeof live[13].ip, "198.51.100.30");
    snprintf(live[14].ip, sizeof live[14].ip, "198.51.100.31");
    snprintf(live[15].ip, sizeof live[15].ip, "198.51.100.32");

    task *t = dns_task(0, "bypass.example", "198.51.100.23", T_VERIFY);
    t->began_ms = 2000;
    t->probes = 2;
    t->next_plan = 1;
    t->n_plans = 2;
    t->n_known = 1;
    t->ver_ok = 1;
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;
    t->ver.dns_reply = 1;

    t = dns_task(1, "nobypass.example", "198.51.100.24", T_RESTING);
    snprintf(t->ver.reason, sizeof t->ver.reason,
             "Подбор завершён без подтверждённого плана.");

    t = dns_task(2, "candidate.example", "198.51.100.26", T_TRIAL_SETTLE);
    t->began_ms = 3000;
    t->probes = 1;
    t->next_plan = 1;
    t->n_plans = 1;
    t->ver_ok = 1;
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;

    /* live->dns_answer уже true, задача без DNS-ответа: bypass_ok по OR. */
    t = dns_task(3, "liveanswer.example", "198.51.100.29", T_VERIFY);
    t->began_ms = 4000;
    t->probes = 1;
    t->next_plan = 1;
    t->n_plans = 1;
    t->ver_ok = 1;
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;

    /* no_bypass без ver.reason: C подставляет свою строку. */
    t = dns_task(4, "noreason.example", "198.51.100.30", T_RESTING);

    /* Задача вне VERIFY/TRIAL/RESTING: общий checking-конвейер. */
    t = dns_task(5, "taskother.example", "198.51.100.31", T_ASKING);
    t->began_ms = 4500;
    t->probes = 2;

    /* VERIFY без применённого плана: вторая ветка checking-причины. */
    t = dns_task(6, "verifyplain.example", "198.51.100.32", T_VERIFY);
    t->began_ms = 4600;
    t->probes = 2;
    t->next_plan = 2;
    t->n_plans = 2;
}

static int emit(const char *mode) {
    reset();
    if (!strcmp(mode, "empty")) {
        /* пусто */
    } else if (!strcmp(mode, "boxes")) {
        emit_boxes();
    } else if (!strcmp(mode, "bindings")) {
        emit_bindings();
    } else if (!strcmp(mode, "groups")) {
        emit_groups();
    } else if (!strcmp(mode, "measurements")) {
        emit_measurements();
    } else if (!strcmp(mode, "tasks")) {
        emit_tasks();
    } else if (!strcmp(mode, "dns")) {
        emit_dns();
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    char path[256];
    snprintf(path, sizeof path, "/tmp/d2o-live-states-%ld.json", (long)getpid());
    if (d2k_sched_write_live(&s, path, "catalog.json") != 0) return 1;
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    char body[262144];
    size_t got = fread(body, 1, sizeof body - 1, f);
    body[got] = 0;
    fclose(f);
    remove(path);
    fputs(body, stdout);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    return emit(argv[1]);
}
