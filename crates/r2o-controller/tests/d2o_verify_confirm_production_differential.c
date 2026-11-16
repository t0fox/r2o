/* C-оракул production `verify_confirm` (core/sched.c): полный исход
 * подтверждения кандидата — решение, привязка каталога, обучение области,
 * белое имя сети и терминальное состояние задачи.
 *
 * Задача и `d2k_sched` заполняются так, как их приносит реальный путь
 * `T_VERIFY_WAIT`: `t->ver` — исход собственного зонда, `t->plans[next_plan-1]`
 * — испытанный текст, `t->ver_plan_id`/`t->unfit_plan_id` — идентификаторы с
 * провода. Сценарии — реальные ветви `verify_confirm`, а не копии его тела.
 *
 * Rust-сторона (`verify_confirm_production_matches_c`): production
 * `r2o_confirm_discovery_outcome`/`..._checked`, `apply_discovery_outcome`,
 * `add_confirmed_quic_address_binding`, `r2o_update_network_whitelist`.
 * Сверяются наблюдаемые поля: подтверждён/отклонён, привязка, бюджет,
 * доказательство, область, белое имя. Идентификаторы планов нормализуются
 * (`PLAN`, `ID`): C зовёт их `plan-%08x` по FNV-1a, Rust — стабильным
 * 32-hex id. `verify_confirm` же требует control/verify
 * fd/link только для проталкивания адресного плана в постоянную таблицу;
 * здесь `link_fd` закрыт, и этот побочный эффект намеренно не проверяется.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_sched s;
static d2k_catalog cat;
static task *t;
static d2k_diag_event observed;
static int report_seen;
static int first = 1;
static int failures;
static const char *g_scenario = "";

static const char *PLAN_TEXT =
    "r2o-plan 1 11\n"
    "id 00000000000000000000000000000000\n"
    "proto tcp tls\n"
    "split sni_middle +0\n";
static const char *QUIC_TEXT =
    "r2o-plan 1 9\n"
    "id 00000000000000000000000000000000\n"
    "proto udp quic\n"
    "udplen 100\n";
/* План разреза CRYPTO: C `quic_text_is_split` ищет ровно "\nquicsplit ". */
static const char *QUIC_SPLIT_TEXT =
    "r2o-plan 1 10\n"
    "id 00000000000000000000000000000000\n"
    "proto udp quic\n"
    "quicsplit 1\n";
/* Лучший частичный обход, который берёт `partial_finish`. */
static const char *PARTIAL_TEXT =
    "d2k-plan 1 1\n"
    "id 11111111111111111111111111111111\n"
    "proto tcp tls\n"
    "order forward\n";

#define CHECK(cond, what)                                                       \
    do {                                                                        \
        if (!(cond)) {                                                          \
            fprintf(stderr, "FAIL: %s: %s\n", g_scenario, what);                \
            failures++;                                                         \
        }                                                                       \
    } while (0)

static void observe(void *context, const d2k_diag_event *event) {
    (void)context;
    observed = *event;
    report_seen = 1;
}

static void dump_string(const char *value) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\') {
            putchar('\\');
            putchar(*p);
        } else if (*p < 0x20) {
            printf("\\u%04x", *p);
        } else {
            putchar(*p);
        }
    }
    putchar('"');
}

/* Нормализация идентификатора: план C — `plan-%08x`, Rust — 32 hex.
   Текст плана тоже несёт id; сверяем его отдельно от конкретного значения. */
static void dump_plan_text(const char *text) {
    putchar('"');
    for (const char *p = text; *p; p++) {
        if (p == text || p[-1] == '\n') {
            if (strncmp(p, "id ", 3) == 0) {
                printf("id ID");
                p += 2;
                while (p[1] && p[1] != '\n') p++;
                continue;
            }
        }
        if (*p == '"' || *p == '\\') {
            putchar('\\');
            putchar(*p);
        } else if (*p == '\n') {
            printf("\\n");
        } else if ((unsigned char)*p < 0x20) {
            printf("\\u%04x", (unsigned)(unsigned char)*p);
        } else {
            putchar(*p);
        }
    }
    putchar('"');
}

static void emit(const char *scenario) {
    printf("%s{\"scenario\":", first ? "" : ",\n");
    first = 0;
    dump_string(scenario);
}

static void reset(const char *scenario, const char *name, uint8_t transport,
                  const char *text) {
    if (t) {
        d2k_catalog_free(&cat);
        pthread_mutex_destroy(&s.mu);
    }
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    memset(&observed, 0, sizeof observed);
    report_seen = 0;
    s.wake[0] = -1;
    s.wake[1] = -1;
    s.now_ms = 100000;
    s.clock_seen = 1;
    s.send_cap = 0;
    s.diagnostic = observe;
    s.wall_base_s = 2000;
    s.mono_base_ms = 1000;
    s.link_fd = -1;
    s.cat = &cat;
    if (pthread_mutex_init(&s.mu, NULL) != 0) {
        fprintf(stderr, "mutex init failed\n");
        exit(1);
    }
    t = &s.tasks[0];
    memset(t, 0, sizeof *t);
    if (scenario) snprintf(t->name, sizeof t->name, "%s", name);
    snprintf(t->ip, sizeof t->ip, "198.51.100.8");
    t->transport = transport;
    t->family = 4;
    t->port = 443;
    t->state = T_VERIFY_WAIT;
    t->ver.fd = -1;
    t->probe_fd = -1;
    t->prop_fd = -1;
    t->prop_bound_fd = -1;
    t->report_id = 7;
    t->report_admitted_ms = 90000;
    t->trigger_code = 3;
    t->trigger_shape = (uint8_t)D2K_SHAPE_MODERN;
    t->trigger_tcp_profile = 0;
    t->n_plans = 1;
    t->next_plan = 1;
    snprintf(t->plans[0], sizeof t->plans[0], "%s", text);
    t->res.verdict = D2K_V_OPAQUE;
    snprintf(t->res.reason, sizeof t->res.reason, "подтверждено зондом");
}

/* Общая часть успешного HTTPS-ответа собственного зонда. */
static void https_ok(int status) {
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = status;
    t->ver.name_ok = 1;
    t->ver.body_complete = 1;
    t->ver.body_expected = 512;
    t->ver.body_bytes = 512;
    t->ver.replay_proof = 0;
    t->ver.handshake_proof = 0;
}

static void set_ver_plan_id(void) {
    char id[40];
    plan_ident(t->plans[0], id, sizeof id, t->ver_plan_id);
}

static void dump_bindings(void) {
    printf(",\"bindings\":[");
    int bfirst = 1;
    for (size_t bi = 0; bi < cat.n_boxes; bi++) {
        const d2k_cat_box *box = &cat.boxes[bi];
        for (size_t j = 0; j < box->n_binds; j++) {
            const d2k_cat_binding *bd = &box->binds[j];
            printf("%s{\"kind\":", bfirst ? "" : ",");
            bfirst = 0;
            dump_string(bd->kind);
            printf(",\"target\":");
            dump_string(bd->target);
            printf(",\"plan\":\"PLAN\",\"transport\":%u,\"family\":%u,"
                   "\"shape\":%u,\"tcp_profile\":%u,\"verified_by\":%u,"
                   "\"input\":%u,\"budget\":%u,\"probe_path\":",
                   (unsigned)bd->transport, (unsigned)bd->family,
                   (unsigned)bd->shape, (unsigned)bd->tcp_profile,
                   (unsigned)bd->verified_by, (unsigned)bd->input,
                   (unsigned)bd->budget);
            dump_string(bd->probe_path);
            printf(",\"ech_origin\":");
            dump_string(bd->ech_origin);
            printf(",\"level\":%d,\"successes\":%d,\"enabled\":%s}",
                   bd->level, bd->successes, bd->enabled ? "true" : "false");
        }
    }
    printf("]");
}

static void dump_plan_record(void) {
    if (cat.n_boxes == 0 || cat.boxes[0].n_plans == 0) {
        printf(",\"plan\":null");
        return;
    }
    const d2k_cat_box *box = &cat.boxes[0];
    const d2k_cat_plan *plan = &box->plans[0];
    printf(",\"plan\":{\"proto\":");
    dump_string(plan->proto);
    printf(",\"text\":");
    dump_plan_text(plan->text ? plan->text : "");
    printf(",\"added\":%lld,\"successes\":%d,\"enabled\":%s}",
           (long long)plan->added, plan->successes,
           plan->enabled ? "true" : "false");
    printf(",\"box\":{\"created\":%lld,\"updated\":%lld,\"plans\":%zu}",
           (long long)box->created, (long long)box->updated, box->n_plans);
}

static void dump_groups(void) {
    const d2k_group_state *state = cat.groups;
    printf(",\"observations\":[");
    for (size_t i = 0; state && i < state->n_observations; i++) {
        const d2k_group_observation *o = &state->observations[i];
        printf("%s{\"name\":", i ? "," : "");
        dump_string(o->name);
        printf(",\"plan\":\"PLAN\",\"transport\":%u,\"family\":%u,\"shape\":%u,"
               "\"probe_path\":",
               (unsigned)o->key.transport, (unsigned)o->key.family,
               (unsigned)o->key.shape);
        dump_string(o->key.probe_path);
        printf(",\"ech_origin\":");
        dump_string(o->key.ech_origin);
        printf(",\"evidence\":%u,\"at\":%lld}",
               (unsigned)o->evidence, (long long)o->at);
    }
    printf("],\"groups\":[");
    for (size_t i = 0; state && i < state->n_groups; i++) {
        const d2k_domain_group *g = &state->groups[i];
        printf("%s{\"suffix\":", i ? "," : "");
        dump_string(g->suffix);
        printf(",\"plan\":\"PLAN\",\"transport\":%u,\"family\":%u,\"shape\":%u,"
               "\"probe_path\":",
               (unsigned)g->key.transport, (unsigned)g->key.family,
               (unsigned)g->key.shape);
        dump_string(g->key.probe_path);
        printf(",\"ech_origin\":");
        dump_string(g->key.ech_origin);
        printf(",\"evidence_count\":%u}", (unsigned)g->evidence_count);
    }
    printf("]");
}

static void dump_network(void) {
    printf(",\"network\":{\"name\":");
    dump_string(cat.net.name);
    printf(",\"tx_only\":%s,\"searched\":%s,\"confirmed_at\":%lld}",
           cat.net.tx_only ? "true" : "false",
           cat.net.searched ? "true" : "false",
           (long long)cat.net.confirmed_at);
}

static void dump_decision(const char *scenario, int confirmed) {
    emit(scenario);
    printf(",\"confirmed\":%s", confirmed ? "true" : "false");
    dump_bindings();
    dump_plan_record();
    dump_groups();
    dump_network();
    printf("}");
}

static void run_confirm(const char *scenario, int expect_confirmed,
                        const char *expect_report) {
    g_scenario = scenario;
    report_seen = 0;
    memset(&observed, 0, sizeof observed);
    verify_confirm(&s, t, s.now_ms);
    int confirmed = cat.n_boxes > 0 && cat.boxes[0].n_binds > 0;
    CHECK(confirmed == expect_confirmed, "решение verify_confirm не совпало");
    CHECK((t->state == T_WATCHING) == expect_confirmed,
          "терминальное состояние задачи не совпало");
    CHECK((s.confirms > 0) == expect_confirmed, "счётчик подтверждений не совпал");
    CHECK((s.sync_pending > 0) == expect_confirmed,
          "запрос синхронизации каталога не совпал");
    if (expect_confirmed) {
        CHECK(report_seen && strcmp(observed.outcome, expect_report) == 0,
              "итоговый отчёт поиска не совпал");
        CHECK(t->box_id[0] != '\0', "владелец подтверждённого плана не записан");
        CHECK(t->partial_valid == 0, "полный обход не сбросил частичный признак");
    } else {
        CHECK(!report_seen, "отклонённый кандидат закрыл отчёт поиска");
        CHECK(t->box_id[0] == '\0', "отклонённый кандидат записал владельца плана");
    }
    dump_decision(scenario, confirmed);
}

/* Общая сверка исхода для ветвей, которые не подтверждают кандидата, но
   закрывают отчёт (`task_fail` диспетчера). `expect_sync` = -1 — вывести из
   `expect_confirmed`; `expect_ladder` = -1 — не сверять. */
static void check_decision(const char *scenario, int expect_confirmed,
                           const char *expect_report, const char *expect_path,
                           int expect_state, int expect_sync,
                           int expect_ladder) {
    g_scenario = scenario;
    int confirmed = cat.n_boxes > 0 && cat.boxes[0].n_binds > 0;
    CHECK(confirmed == expect_confirmed, "решение не совпало");
    CHECK((int)t->state == expect_state, "состояние задачи не совпало");
    CHECK((s.confirms > 0) == expect_confirmed, "счётчик подтверждений не совпал");
    if (expect_sync < 0) expect_sync = expect_confirmed;
    CHECK((s.sync_pending > 0) == expect_sync,
          "запрос синхронизации каталога не совпал");
    if (expect_report) {
        CHECK(report_seen && strcmp(observed.outcome, expect_report) == 0,
              "итоговый отчёт поиска не совпал");
    } else {
        CHECK(!report_seen, "исход не должен был закрывать отчёт поиска");
    }
    if (expect_report && expect_path)
        CHECK(strcmp(observed.path, expect_path) == 0, "путь отчёта поиска не совпал");
    if (expect_confirmed) {
        CHECK(t->box_id[0] != '\0', "владелец подтверждённого плана не записан");
        CHECK(t->partial_valid == 0, "полный обход не сбросил частичный признак");
    } else {
        CHECK(t->box_id[0] == '\0', "отклонённый кандидат записал владельца плана");
        CHECK(t->trial_installed == 0, "отклонённый кандидат оставил пробную установку");
        CHECK(t->ver.fd == -1, "отклонённый кандидат оставил сокет зонда");
    }
    if (expect_ladder >= 0)
        CHECK(t->ladder_unmeasurable == expect_ladder,
              "признак неизмеримой лестницы не совпал");
    dump_decision(scenario, confirmed);
}

/* Диспетчер `T_VERIFY` без рабочего потока: `res_ready=1`, `th_live=0`,
   `join_worker` возвращает 0 — дальше идут настоящие гейты `d2k_sched_tick`. */
static void run_tick(const char *scenario, int expect_confirmed,
                     const char *expect_report, const char *expect_path,
                     int expect_state, int expect_sync) {
    memset(&observed, 0, sizeof observed);
    report_seen = 0;
    t->state = T_VERIFY;
    t->th_live = 0;
    t->res_ready = 1;
    t->trial_installed = 0;
    /* Гейт `T_PLANNING` того же тика (`sched.c:12518`) не должен запускать
       установку следующего кандидата: сверяем исход гейтов `T_VERIFY`, а не
       продолжение планировщика. */
    t->rx_retry_after_ms = s.now_ms + 60000;
    d2k_sched_tick(&s, s.now_ms);
    check_decision(scenario, expect_confirmed, expect_report, expect_path,
                   expect_state, expect_sync, -1);
}

int main(void) {
    printf("[");
    t = NULL;

    /* 1. Полный HTTPS-ответ + APPLIED, бюджет пройден, вход — байты клиента. */
    reset("https_full_applied_passed", "media.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "media.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->trig_snapped = 1;
    t->ver.budget = D2K_BUDGET_PASSED;
    t->ver.budget_packets = 50;
    t->ver.budget_need = 50;
    t->ver.budget_requests = 3;
    snprintf(t->ver.budget_note, sizeof t->ver.budget_note,
             "50 пакетов с данными из нужных 50 за 3 запроса");
    snprintf(t->measure_path, sizeof t->measure_path, "/main.css");
    {
        /* Постусловие `yield_to_own_plan` (`sched.c:10018-10033`): чужой
           `T_ASKING` без готового замера уступает место подтверждённому
           плану из каталога. */
        task *other = &s.tasks[1];
        memset(other, 0, sizeof *other);
        snprintf(other->name, sizeof other->name, "yield.example.com");
        other->transport = 6;
        other->family = 4;
        other->state = T_ASKING;
        other->th_live = 1;
        other->res_ready = 0;
        other->own_first = 0;
    }
    run_confirm("https_full_applied_passed", 1, "probe-confirmed");
    CHECK(s.tasks[1].yield_to_own_plan == 1,
          "чужой T_ASKING не уступил подтверждённому плану");
    CHECK(s.tasks[1].stop == 1, "уступка не остановила чужой замер");

    /* 2. Полный HTTPS + APPLIED, бюджет «не применимо» (заготовка, не снимок). */
    reset("https_full_applied_unchecked", "profile.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "profile.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->ver.budget = D2K_BUDGET_NOT_APPLICABLE;
    t->ver.budget_uncountable = 1;
    snprintf(t->ver.budget_note, sizeof t->ver.budget_note,
             "ядро не отдаёт TCP_INFO data_segs");
    run_confirm("https_full_applied_unchecked", 1, "probe-confirmed");
    CHECK(s.budget_uncountable_said == 1,
          "разовая строка о выключенной проверке бюджета не прозвучала");

    /* 3. Полный HTTPS + APPLIED, доказанный блок → обучение области. */
    reset("https_full_group_proven", "media.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "media.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->group_block_proven = 1;
    t->ver.budget = D2K_BUDGET_PASSED;
    snprintf(t->measure_path, sizeof t->measure_path, "/main.css");
    run_confirm("https_full_group_proven", 1, "probe-confirmed");

    /* 4. ECH принят, имя origin совпало, ответ приложения полный. */
    reset("ech_accepted_application", "ech.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "ech.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->ech_offer = 1;
    snprintf(t->ech_origin, sizeof t->ech_origin, "origin.example");
    t->ver.ech_accepted = 1;
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.budget = D2K_BUDGET_PASSED;
    run_confirm("ech_accepted_application", 1, "probe-confirmed");

    /* 5. ECH принят, но внешнее имя не совпало с запрошенным. */
    reset("ech_negative_outer_name", "ech-wrong.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "ech-wrong.example.com");
    https_ok(200);
    t->ech_offer = 1;
    snprintf(t->ech_origin, sizeof t->ech_origin, "origin.example");
    t->ver.ech_accepted = 1;
    t->ver.name_ok = 0;
    t->ver.budget = D2K_BUDGET_PASSED;
    run_confirm("ech_negative_outer_name", 0, NULL);

    /* 6. ECH принят и имя совпало, но тело ответа не дочитано. */
    reset("ech_negative_incomplete", "ech-cut.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "ech-cut.example.com");
    https_ok(200);
    t->ech_offer = 1;
    snprintf(t->ech_origin, sizeof t->ech_origin, "origin.example");
    t->ver.ech_accepted = 1;
    t->ver.body_complete = 0;
    t->ver.budget = D2K_BUDGET_PASSED;
    run_confirm("ech_negative_incomplete", 0, NULL);

    /* 7. Повтор ECH-приветствия клиента: доказано рукопожатие, бюджет не применим. */
    reset("ech_replay_handshake_proof", "ech-replay.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "ech-replay.example.com");
    set_ver_plan_id();
    t->ech_offer = 1;
    t->ech_replay = 1;
    t->trig_snapped = 1;
    snprintf(t->ech_origin, sizeof t->ech_origin, "origin.example");
    t->ver.level = D2K_VER_HANDSHAKE;
    t->ver.replay_proof = 1;
    t->ver.status = 0;
    t->ver.budget = D2K_BUDGET_NOT_APPLICABLE;
    snprintf(t->ver.budget_note, sizeof t->ver.budget_note,
             "ключей клиента нет, прикладной уровень не измерен");
    run_confirm("ech_replay_handshake_proof", 1, "probe-confirmed");

    /* 8. Повтор ECH без ServerHello на байты клиента — не доказательство. */
    reset("ech_replay_without_proof", "ech-noreplay.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "ech-noreplay.example.com");
    set_ver_plan_id();
    t->ech_offer = 1;
    t->ech_replay = 1;
    t->trig_snapped = 1;
    snprintf(t->ech_origin, sizeof t->ech_origin, "origin.example");
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;
    t->ver.replay_proof = 0;
    t->ver.budget = D2K_BUDGET_PASSED;
    run_confirm("ech_replay_without_proof", 0, NULL);

    /* 9. План подозрения: ответ был, бюджет не проверен — подозрение не снято. */
    reset("own_plan_budget_unchecked", "suspicion.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "suspicion.example.com");
    {
        char plan_id[40];
        uint8_t wire[D2K_PLAN_ID_LEN];
        plan_ident(PLAN_TEXT, plan_id, sizeof plan_id, wire);
        snprintf(t->bound_plan_id, sizeof t->bound_plan_id, "%s", plan_id);
    }
    https_ok(200);
    t->own_first = 2;
    t->ver.budget = D2K_BUDGET_NOT_APPLICABLE;
    run_confirm("own_plan_budget_unchecked", 0, NULL);

    /* 10. Рукопожатие с ALPN клиента завершено: приложения нет, бюджет не проверялся. */
    reset("tcp_handshake_proof", "alpn.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "alpn.example.com");
    set_ver_plan_id();
    t->ver.level = D2K_VER_HANDSHAKE;
    t->ver.handshake_proof = 1;
    t->ver.status = 0;
    t->ver.budget = D2K_BUDGET_NOT_CHECKED;
    snprintf(t->ver.budget_note, sizeof t->ver.budget_note,
             "протокол клиента не HTTP");
    run_confirm("tcp_handshake_proof", 1, "probe-confirmed");

    /* 11. QUIC по адресу: повтор пачки клиента доказал применение. */
    reset("quic_addr_replay", "203.0.113.8", 17, QUIC_TEXT);
    snprintf(t->name, sizeof t->name, "203.0.113.8");
    snprintf(t->ip, sizeof t->ip, "203.0.113.8");
    t->by_addr = 1;
    t->quic_ech = 1;
    t->trig_snapped = 1;
    t->ver.level = D2K_VER_HANDSHAKE;
    t->ver.replay_proof = 1;
    t->ver.status = 0;
    t->ver.budget = D2K_BUDGET_NOT_APPLICABLE;
    snprintf(t->ver.budget_note, sizeof t->ver.budget_note,
             "QUIC-повтор без прикладного ответа");
    run_confirm("quic_addr_replay", 1, "probe-confirmed");

    /* 12. Подбор белого имени: план снял RX-обрыв, имя запоминается как свойство. */
    reset("net_whitelist_rx", "hcaptcha.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "hcaptcha.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->net_probing = 1;
    snprintf(t->net_probe_name[0], sizeof t->net_probe_name[0], "white.example");
    t->vol.rx_cut = 1;
    t->vol.rx_at_kb = 16;
    t->ver.budget = D2K_BUDGET_PASSED;
    run_confirm("net_whitelist_rx", 1, "probe-confirmed");

    /* 13. Подбор белого имени: пройден только исходящий обрыв — подбор открыт. */
    reset("net_whitelist_tx", "hcaptcha2.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "hcaptcha2.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->net_probing = 1;
    snprintf(t->net_probe_name[0], sizeof t->net_probe_name[0], "white.example");
    t->vol.rx_cut = 0;
    t->ver.budget = D2K_BUDGET_PASSED;
    run_confirm("net_whitelist_tx", 1, "probe-confirmed");

    /* 14. Тот же план уже не подошёл потоку клиента (FLOW_UNFIT). */
    reset("unfit_here", "unfit.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "unfit.example.com");
    {
        char id[40];
        plan_ident(t->plans[0], id, sizeof id, t->unfit_plan_id[0]);
    }
    t->unfit_seen = 1;
    https_ok(200);
    t->ver.budget = D2K_BUDGET_PASSED;
    run_confirm("unfit_here", 0, NULL);

    /* 15. Несовпадение имени сертификата без ECH — диагностический признак,
       а не отказ (`sched.c:9644-9649`): план подтверждается. */
    reset("name_ok_diagnostic_only", "name-mismatch.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "name-mismatch.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->ver.name_ok = 0;
    t->ver.budget = D2K_BUDGET_PASSED;
    run_confirm("name_ok_diagnostic_only", 1, "probe-confirmed");

    /* 16. Гейт объёмной лестницы (`sched.c:9593-9605`): обрыв исходящей
       лестницы измерен, RX-обрыва нет, план — ступень лестницы, бюджет
       «не применимо»; кандидат не подтверждается, лестница объявляется
       неизмеримой, подбор белого имени прекращается. */
    reset("ladder_pre_gate_unchecked", "ladder.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "ladder.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->vol.verdict = D2K_VOL_CUT;
    t->vol.at_kb = 19;
    t->vol.rx_cut = 0;
    t->ver.budget = D2K_BUDGET_NOT_APPLICABLE;
    snprintf(t->net_probe_name[0], sizeof t->net_probe_name[0], "white.example");
    t->net_probing = 1;
    t->rx_volume_candidate_pending = 1;
    memset(&observed, 0, sizeof observed);
    report_seen = 0;
    verify_confirm(&s, t, s.now_ms);
    check_decision("ladder_pre_gate_unchecked", 0, NULL, NULL, T_PLANNING, 0, 1);
    CHECK(t->net_probing == 0, "неизмеримая лестница оставила подбор белого имени");
    CHECK(t->rx_volume_candidate_pending == 0,
          "неизмеримая лестница оставила кандидата объёмного обхода");

    /* 17. Тот же гейт при бюджете «оборван»: кандидат отклоняется, но
       лестница НЕ объявляется неизмеримой (C сбрасывает флаги только при
       бюджете, отличном от CUT). */
    reset("ladder_pre_gate_cut", "ladder-cut.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "ladder-cut.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->vol.verdict = D2K_VOL_CUT;
    t->vol.at_kb = 19;
    t->vol.rx_cut = 0;
    t->ver.budget = D2K_BUDGET_CUT;
    snprintf(t->net_probe_name[0], sizeof t->net_probe_name[0], "white.example");
    t->net_probing = 1;
    t->rx_volume_candidate_pending = 1;
    memset(&observed, 0, sizeof observed);
    report_seen = 0;
    verify_confirm(&s, t, s.now_ms);
    check_decision("ladder_pre_gate_cut", 0, NULL, NULL, T_PLANNING, 0, 0);
    CHECK(t->net_probing == 1, "CUT ошибочно прекратил подбор белого имени");
    CHECK(t->rx_volume_candidate_pending == 1,
          "CUT ошибочно снял кандидата объёмного обхода");

    /* 18. Бюджет не проверялся, соединение закрывается: обрыв не доказан,
       но и бюджет не пройден — кандидат не подтверждается. */
    reset("ladder_pre_gate_conn_close", "ladder-close.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "ladder-close.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->vol.verdict = D2K_VOL_CUT;
    t->vol.at_kb = 19;
    t->vol.rx_cut = 0;
    t->ver.budget = D2K_BUDGET_NOT_CHECKED;
    t->ver.conn_close = 1;
    snprintf(t->net_probe_name[0], sizeof t->net_probe_name[0], "white.example");
    t->net_probing = 1;
    t->rx_volume_candidate_pending = 1;
    memset(&observed, 0, sizeof observed);
    report_seen = 0;
    verify_confirm(&s, t, s.now_ms);
    check_decision("ladder_pre_gate_conn_close", 0, NULL, NULL, T_PLANNING, 0, 1);
    CHECK(t->net_probing == 0, "закрытие соединения оставило подбор белого имени");

    /* 19. Бюджет не проверялся, соединение остаётся открытым: это не обрыв,
       кандидат подтверждается без отметки бюджета. */
    reset("ladder_pre_gate_unproven", "ladder-open.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "ladder-open.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->vol.verdict = D2K_VOL_CUT;
    t->vol.at_kb = 19;
    t->vol.rx_cut = 0;
    t->ver.budget = D2K_BUDGET_NOT_CHECKED;
    t->ver.conn_close = 0;
    snprintf(t->net_probe_name[0], sizeof t->net_probe_name[0], "white.example");
    t->rx_volume_candidate_pending = 1;
    run_confirm("ladder_pre_gate_unproven", 1, "probe-confirmed");
    CHECK(cat.boxes[0].binds[0].budget == 0,
          "непроверенный бюджет записался отметкой");

    /* 20. Тот же гейт при пройденном бюджете: подтверждение и отметка PASSED. */
    reset("ladder_pre_gate_passed", "ladder-passed.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "ladder-passed.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->vol.verdict = D2K_VOL_CUT;
    t->vol.at_kb = 19;
    t->vol.rx_cut = 0;
    t->ver.budget = D2K_BUDGET_PASSED;
    t->ver.budget_packets = 50;
    t->ver.budget_need = 50;
    t->ver.budget_requests = 3;
    snprintf(t->net_probe_name[0], sizeof t->net_probe_name[0], "white.example");
    run_confirm("ladder_pre_gate_passed", 1, "probe-confirmed");
    CHECK(cat.boxes[0].binds[0].budget == D2K_CAT_BUDGET_PASSED,
          "пройденный бюджет не записался отметкой");

    /* 21. `partial_finish` (`sched.c:9668-9689`): объёмный блок берёт лучший
       частичный обход, ставит `partial_finishing=1` и подтверждает его через
       общий `verify_confirm`. Гейт объёмной лестницы пропускается, бюджет
       остаётся «оборван», отчёт — `probe-partial`. */
    reset("partial_finish_budget_cut", "partial.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "partial.example.com");
    snprintf(t->partial_text, sizeof t->partial_text, "%s", PARTIAL_TEXT);
    snprintf(t->partial_box, sizeof t->partial_box, "box-partial");
    t->partial_valid = 1;
    t->partial_pk = 100;
    t->partial_ver.level = D2K_VER_APPLICATION;
    t->partial_ver.status = 200;
    t->partial_ver.name_ok = 1;
    t->partial_ver.body_complete = 1;
    t->partial_ver.body_expected = 512;
    t->partial_ver.body_bytes = 512;
    t->partial_ver.budget = D2K_BUDGET_CUT;
    t->partial_ver.budget_packets = 100;
    t->partial_ver.budget_need = 250;
    snprintf(t->partial_ver.budget_note, sizeof t->partial_ver.budget_note,
             "поток режется после 100 пакетов из нужных 250");
    t->vol.verdict = D2K_VOL_CUT;
    t->vol.at_kb = 19;
    /* Путь находки берётся из `rx_hashes` (`candidate_path`): план пришёл из
       RX-лестницы, поэтому отчёт называет путь `ladder`. */
    t->rx_hashes[0] = fnv1a(PARTIAL_TEXT);
    t->n_rx_hashes = 1;
    memset(&observed, 0, sizeof observed);
    report_seen = 0;
    CHECK(partial_finish(&s, t, s.now_ms) == 1,
          "partial_finish не взял лучший частичный обход");
    check_decision("partial_finish_budget_cut", 1, "probe-partial", "ladder",
                   T_WATCHING, 1, -1);
    CHECK(cat.boxes[0].binds[0].budget == D2K_CAT_BUDGET_CUT,
          "частичный обход не помечен бюджетом «оборван»");
    CHECK(strcmp(cat.boxes[0].plans[0].text, PARTIAL_TEXT) == 0,
          "частичный обход не стал единственным планом");

    /* 22. QUIC с ECH: нет ответа на повтор пачки клиента — подтверждения нет
       (`sched.c:9621-9627`). */
    reset("quic_ech_without_replay", "quic-ech.example.com", 17, QUIC_TEXT);
    snprintf(t->name, sizeof t->name, "quic-ech.example.com");
    t->quic_ech = 1;
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;
    t->ver.body_complete = 1;
    t->ver.replay_proof = 0;
    t->ver.budget = D2K_BUDGET_PASSED;
    run_confirm("quic_ech_without_replay", 0, NULL);

    /* 23. Разрез CRYPTO, который клиент этой цели исполнить не может:
       ClientHello шире датаграммы (`quic_split_unfit`, `sched.c:9650-9660`). */
    reset("quic_split_unfit", "split.example.com", 17, QUIC_SPLIT_TEXT);
    snprintf(t->name, sizeof t->name, "split.example.com");
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;
    t->ver.body_complete = 1;
    t->ver.budget = D2K_BUDGET_PASSED;
    snprintf(s.quic_multi[0].name, sizeof s.quic_multi[0].name, "split.example.com");
    s.quic_multi[0].family = 4;
    run_confirm("quic_split_unfit", 0, NULL);

    /* 24. Cloudflare challenge по уровню зонда: гейт диспетчера `T_VERIFY`
       (`sched.c:12209-12237`) до `verify_confirm` не доходит — поиск
       закрывается `failed`, каталог не трогается. */
    reset("cf_challenge_dispatcher", "cf.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "cf.example.com");
    t->ver.level = D2K_VER_CHALLENGE;
    t->ver.status = 403;
    t->ver.cloudflare_challenge = 1;
    snprintf(t->ver.reason, sizeof t->ver.reason, "cf-mitigated: challenge");
    run_tick("cf_challenge_dispatcher", 0, "failed", "property", T_RESTING, 1);

    /* 25. Cloudflare challenge, распознанный по заголовку при полном
       прикладном уровне: тот же гейт диспетчера. */
    reset("cf_header_dispatcher", "cf-header.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "cf-header.example.com");
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 403;
    t->ver.cloudflare_challenge = 1;
    run_tick("cf_header_dispatcher", 0, "failed", "property", T_RESTING, 1);

    /* 26. HTTP 451: юридический отказ, гейт диспетчера `D2K_VER_DENIED`. */
    reset("legal_denial_dispatcher", "legal.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "legal.example.com");
    t->ver.level = D2K_VER_DENIED;
    t->ver.status = 451;
    t->ver.http_outcome = D2K_HTTP_LEGAL_DENIAL;
    run_tick("legal_denial_dispatcher", 0, "failed", "property", T_RESTING, 1);

    /* 27. Явная страница блокировки: `wire_proof` диспетчера не признаёт
       `D2K_VER_BLOCKPAGE` доказательством — следующий кандидат, без отчёта. */
    reset("blocked_page_dispatcher", "blocked.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "blocked.example.com");
    t->ver.level = D2K_VER_BLOCKPAGE;
    t->ver.status = 403;
    t->ver.http_outcome = D2K_HTTP_BLOCKED;
    run_tick("blocked_page_dispatcher", 0, NULL, NULL, T_PLANNING, 0);

    /* 28. `PLAN_FAILED`/`family_fast` (`sched.c:12506-12512`): применённый
       поток зонда не дошёл до приложения по нашей ошибке чтения, и отказ
       записывается в семейство как неудача ПЛАНА, а не коробки. */
    reset("plan_failed_group", "plan-failed.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "plan-failed.example.com");
    t->ver.level = D2K_VER_TRANSPORT;
    t->ver.status = 0;
    t->ver.local_ip4[0] = 198;
    t->ver.local_ip4[1] = 51;
    t->ver.local_ip4[2] = 100;
    t->ver.local_ip4[3] = 9;
    t->ver.local_port = 41000;
    memset(&t->ver_early[0], 0, sizeof t->ver_early[0]);
    memcpy(t->ver_early[0].a_ip, t->ver.local_ip4, 4);
    t->ver_early[0].a_port = t->ver.local_port;
    inet_pton(AF_INET, t->ip, t->ver_early[0].b_ip);
    t->ver_early[0].b_port = t->port;
    t->ver_early[0].transport = 6;
    t->ver_early[0].family = 4;
    t->ver_seen = 1;
    t->family_fast = 1;
    t->asked_shape = (uint8_t)D2K_SHAPE_MODERN;
    run_tick("plan_failed_group", 0, NULL, NULL, T_PLANNING, 1);
    CHECK(cat.groups && cat.groups->n_observations == 1,
          "PLAN_FAILED не записал наблюдение семейства");
    CHECK(cat.groups && cat.groups->observations[0].evidence == D2K_GROUP_PLAN_FAILED,
          "наблюдение семейства записано не как PLAN_FAILED");

    /* 29. Снимок клиента пришёл, пока шло испытание: подтверждение не оставляет
       привязку заготовкой — хвост `verify_confirm` (`sched.c:10035-10042`)
       запускает перемер снятыми байтами. В стенде `s.meas_limit=0`, поэтому
       `launch_or_queue` ставит задачу в ограниченную очередь (T_QUEUED). */
    reset("remeasure_after_confirm", "remeasure.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "remeasure.example.com");
    set_ver_plan_id();
    https_ok(200);
    t->ver.budget = D2K_BUDGET_PASSED;
    snprintf(s.tcp_shape_name[0], sizeof s.tcp_shape_name[0], "remeasure.example.com");
    s.tcp_shape_len[0] = 16;
    memset(s.tcp_shape[0], 0x16, s.tcp_shape_len[0]);
    memset(&observed, 0, sizeof observed);
    report_seen = 0;
    verify_confirm(&s, t, s.now_ms);
    check_decision("remeasure_after_confirm", 1, "probe-confirmed", "property",
                   T_QUEUED, 1, -1);
    CHECK(t->reasked == 1, "хвост подтверждения не заказал перемер снимком");
    CHECK(t->trig_snapped == 1, "перемер не перешёл на байты снимка");
    CHECK(t->trig_len == s.tcp_shape_len[0], "перемер взял не тот снимок");

    /* 30. План потока подозрения переподтверждён ПРОЙДЕННЫМ бюджетом:
       подозрение было ложным, вход привязки — TRANSFER, `own_first=3`. */
    reset("own_plan_budget_passed", "own-passed.example.com", 6, PLAN_TEXT);
    snprintf(t->name, sizeof t->name, "own-passed.example.com");
    {
        char plan_id[40];
        uint8_t wire[D2K_PLAN_ID_LEN];
        plan_ident(PLAN_TEXT, plan_id, sizeof plan_id, wire);
        snprintf(t->bound_plan_id, sizeof t->bound_plan_id, "%s", plan_id);
        memcpy(t->ver_plan_id, wire, sizeof t->ver_plan_id);
    }
    https_ok(200);
    t->own_first = 2;
    t->ver.budget = D2K_BUDGET_PASSED;
    t->ver.budget_packets = 50;
    t->ver.budget_need = 50;
    t->ver.budget_requests = 2;
    run_confirm("own_plan_budget_passed", 1, "probe-confirmed");
    CHECK(t->own_first == 3, "переподтверждённый свой план не закрыл классификацию");
    CHECK(cat.boxes[0].binds[0].input == D2K_INPUT_TRANSFER,
          "вход переподтверждённого своего плана записан не как TRANSFER");

    printf("]\n");
    d2k_catalog_free(&cat);
    pthread_mutex_destroy(&s.mu);
    if (failures) {
        fprintf(stderr, "%d C invariant(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "C verify_confirm production fixture: invariants PASS\n");
    return 0;
}
