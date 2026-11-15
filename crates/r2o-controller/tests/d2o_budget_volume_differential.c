/* C-оракул budget_cut_reject: объёмный блок (volume_block) и partial_finish.
 *
 * `t->vol.rx_cut=1` означает измеренный обрыв входящего объёма: перебор по
 * этому бюджету прекращается, лучший частичный обход подтверждается одним
 * планом с отметкой бюджета «оборван» (production `partial_finish`).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static const char plan_text[] =
    "d2k-plan 1 1\n"
    "id 00112233445566778899aabbccddeeff\n"
    "proto tcp tls\n"
    "order forward\n";

static const char preset_text[] =
    "d2k-plan 1 7\n"
    "id 8899aabbccddeeff0011223344556677\n"
    "proto tcp tls\n"
    "order reverse\n";

static void print_hex(const char *text)
{
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) printf("%02x", *p);
}

/* preset_pk > 0 — до объёмного отказа уже был сохранён partial с этим
   числом пакетов; проверяется, что finish берёт именно лучший.
   shared=1 печатает только поля, которые моделирует Rust-хелпер; полный
   вывод C (state/trial/verfd/revision) пишется отдельным прогоном. */
static void scenario(const char *label, unsigned preset_pk, unsigned preset_succ,
                     int shared)
{
    d2k_sched *s = calloc(1, sizeof *s);
    d2k_catalog *cat = calloc(1, sizeof *cat);
    if (!s || !cat) return;
    cat->boxes = calloc(1, sizeof *cat->boxes);
    if (!cat->boxes) return;
    cat->boxes[0].plans = calloc(1, sizeof *cat->boxes[0].plans);
    cat->boxes[0].binds = calloc(1, sizeof *cat->boxes[0].binds);
    if (!cat->boxes[0].plans || !cat->boxes[0].binds) return;
    s->cat = cat;
    s->now_ms = 100000;
    s->clock_seen = 1;
    s->link_fd = -1;
    if (pthread_mutex_init(&s->mu, NULL)) return;

    char plan_id[40];
    uint8_t wire_id[D2K_PLAN_ID_LEN];
    plan_ident(plan_text, plan_id, sizeof plan_id, wire_id);

    task *t = &s->tasks[0];
    memset(t, 0, sizeof *t);
    snprintf(t->name, sizeof t->name, "volume.example");
    snprintf(t->ip, sizeof t->ip, "198.51.100.91");
    t->transport = 6;
    t->family = 4;
    t->state = T_VERIFY;
    t->next_plan = 1;
    t->n_plans = 1;
    snprintf(t->plans[0], sizeof t->plans[0], "%s", plan_text);
    snprintf(t->box_id, sizeof t->box_id, "box-vol");
    t->ver.level = D2K_VER_APPLICATION;
    t->ver.status = 200;
    t->ver.body_complete = 1;
    t->ver.name_ok = 1;
    t->ver.budget = D2K_BUDGET_CUT;
    t->ver.budget_packets = 100;
    t->ver.budget_need = 50;
    t->vol.rx_cut = 1;
    t->vol.at_kb = 17;
    t->vol.rx_at_kb = 17;
    t->vol.verdict = D2K_VOL_CUT;
    t->search_owned = 1;
    t->trial_installed = 1;
    if (preset_pk) {
        t->partial_valid = 1;
        t->partial_pk = preset_pk;
        t->partial_succ = preset_succ;
        snprintf(t->partial_text, sizeof t->partial_text, "%s", preset_text);
        snprintf(t->partial_box, sizeof t->partial_box, "box-preset");
        t->partial_ver = t->ver;
        t->partial_ver.fd = -1;
    }

    cat->n_boxes = 1;
    snprintf(cat->boxes[0].id, sizeof cat->boxes[0].id, "box-vol");
    cat->boxes[0].n_plans = 1;
    snprintf(cat->boxes[0].plans[0].id, sizeof cat->boxes[0].plans[0].id, "%s", plan_id);
    cat->boxes[0].plans[0].text = strdup(plan_text);
    snprintf(cat->boxes[0].plans[0].proto, sizeof cat->boxes[0].plans[0].proto, "tls");
    cat->boxes[0].plans[0].enabled = 1;
    cat->boxes[0].plans[0].successes = 1;
    cat->boxes[0].n_binds = 1;
    d2k_cat_binding *bd = &cat->boxes[0].binds[0];
    snprintf(bd->plan_id, sizeof bd->plan_id, "%s", plan_id);
    snprintf(bd->target, sizeof bd->target, "%s", t->name);
    snprintf(bd->kind, sizeof bd->kind, "name");
    bd->transport = 6;
    bd->family = 4;
    bd->shape = 1;
    bd->level = 3;
    bd->enabled = 1;

    budget_cut_reject(s, t, s->now_ms);
    if (shared) {
        printf("%s plan=", label);
        if (t->n_plans) print_hex(t->plans[0]);
        printf(" planbox=%s plans=%zu next=%zu budget=%u owned=%d volume=%d\n",
               t->plan_boxes[0], t->n_plans, t->next_plan, (unsigned)bd->budget,
               t->owned_fallback, t->vol.rx_cut);
    } else {
        printf("%s state=%d plans=%zu next=%zu box=%s binds=%zu budget=%u revision=%zu "
               "sync=%d owned=%d trial=%d verfd=%d partial=%d\n",
               label, (int)t->state, t->n_plans, t->next_plan, t->box_id,
               cat->boxes[0].n_binds, (unsigned)bd->budget, cat->revision,
               s->sync_pending, t->owned_fallback, t->trial_installed, t->ver.fd,
               t->partial_valid);
        printf("%s plan=", label);
        if (t->n_plans) print_hex(t->plans[0]);
        printf(" planbox=%s\n", t->plan_boxes[0]);
    }
    pthread_mutex_destroy(&s->mu);
    free(cat->boxes[0].plans[0].text);
    free(cat->boxes[0].plans);
    free(cat->boxes[0].binds);
    free(cat->boxes);
    free(cat);
    free(s);
}

int main(int argc, char **argv)
{
    int shared = argc > 1 && strcmp(argv[1], "shared") == 0;
    scenario("volume_current", 0, 0, shared);
    scenario("volume_preset_better", 150, 9, shared);
    scenario("volume_preset_worse", 50, 9, shared);
    return 0;
}
