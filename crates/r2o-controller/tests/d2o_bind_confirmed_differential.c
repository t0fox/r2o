/* C/Rust differential: `bind_confirmed` (core/sched.c:3463-3571).
 *
 * Каждый шаг печатает нормализованный каталог: коробки, планы и привязки.
 * Rust-сторона повторяет те же вызовы через
 * `r2o_controller::discovery::bind_confirmed`. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_catalog cat;
static int first = 1;

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

static void dump(const char *step) {
    printf("%s{\"step\":", first ? "" : ",\n");
    first = 0;
    dump_string(step);
    printf(",\"boxes\":[");
    for (size_t i = 0; i < cat.n_boxes; i++) {
        const d2k_cat_box *box = &cat.boxes[i];
        printf("%s{\"id\":", i ? "," : "");
        dump_string(box->id);
        printf(",\"created\":%lld,\"updated\":%lld,\"plans\":[",
               (long long)box->created, (long long)box->updated);
        for (size_t j = 0; j < box->n_plans; j++) {
            const d2k_cat_plan *plan = &box->plans[j];
            printf("%s{\"id\":", j ? "," : "");
            dump_string(plan->id);
            printf(",\"proto\":");
            dump_string(plan->proto);
            printf(",\"text\":");
            dump_string(plan->text ? plan->text : "");
            printf(",\"added\":%lld,\"successes\":%d,\"enabled\":%s}",
                   (long long)plan->added, plan->successes,
                   plan->enabled ? "true" : "false");
        }
        printf("],\"bindings\":[");
        for (size_t j = 0; j < box->n_binds; j++) {
            const d2k_cat_binding *bd = &box->binds[j];
            printf("%s{\"kind\":", j ? "," : "");
            dump_string(bd->kind);
            printf(",\"target\":");
            dump_string(bd->target);
            printf(",\"plan_id\":");
            dump_string(bd->plan_id);
            printf(",\"level\":%d,\"confirmed\":%lld,\"successes\":%d,\"enabled\":%s",
                   bd->level, (long long)bd->confirmed, bd->successes,
                   bd->enabled ? "true" : "false");
            printf(",\"transport\":%u,\"family\":%u,\"shape\":%u,\"tcp_profile\":%u",
                   (unsigned)bd->transport, (unsigned)bd->family,
                   (unsigned)bd->shape, (unsigned)bd->tcp_profile);
            printf(",\"verified_by\":%u,\"input\":%u,\"probe_path\":",
                   (unsigned)bd->verified_by, (unsigned)bd->input);
            dump_string(bd->probe_path);
            printf(",\"ech_origin\":");
            dump_string(bd->ech_origin);
            printf(",\"recheck_since\":%lld,\"budget\":%u}",
                   (long long)bd->recheck_since, (unsigned)bd->budget);
        }
        printf("]}");
    }
    printf("]}");
}

static void do_bind(const char *box, const char *plan_id, const char *text,
                 const char *proto, const char *target, const char *kind,
                 uint8_t transport, uint8_t family, uint8_t shape,
                 uint8_t tcp_profile, uint8_t verified_by, uint8_t input,
                 int64_t at, const d2k_cat_fp *fp) {
    if (bind_confirmed(&cat, box, plan_id, text, proto, target, kind, transport,
                       family, shape, tcp_profile, verified_by, input, at, fp) != 0) {
        fprintf(stderr, "bind_confirmed failed\n");
        exit(1);
    }
}

int main(void) {
    memset(&cat, 0, sizeof cat);
    printf("[");

    do_bind("box-1", "plan-1", "old text", "tls", "example.com", "name", 6, 4, 0,
         0, 2, 1, 20, NULL);
    dump("new_binding");

    do_bind("box-1", "plan-1", "new text", "tls", "example.com", "name", 6, 4, 1,
         0, 1, 2, 40, NULL);
    dump("update_same_plan");

    /* Старое состояние файла: уровень выше, привязка выключена, отметки
       пути/ECH/бюджета уже стоят, повторная проверка запрошена. */
    d2k_cat_binding *bd = &cat.boxes[0].binds[0];
    bd->level = 5;
    bd->enabled = 0;
    bd->budget = 3;
    bd->recheck_since = 30;
    snprintf(bd->probe_path, sizeof bd->probe_path, "/main.css");
    snprintf(bd->ech_origin, sizeof bd->ech_origin, "edge.example");
    do_bind("box-1", "plan-1", "new text", "tls", "example.com", "name", 6, 4, 1,
         0, 1, 1, 50, NULL);
    dump("update_preserves_state");

    do_bind("box-1", "plan-2", "second text", "tls", "example.com", "name", 6, 4,
         1, 0, 1, 2, 60, NULL);
    dump("new_plan_resets_budget");

    do_bind("box-2", "plan-1", "old text", "tls", "example.com", "name", 6, 4, 1,
         0, 1, 2, 70, NULL);
    dump("second_box_new_success_one");

    d2k_cat_fp observed;
    memset(&observed, 0, sizeof observed);
    observed.method = 2;
    observed.n_sig = 2;
    snprintf(observed.sig[0].kind, sizeof observed.sig[0].kind, "rx-volume");
    observed.sig[0].volume = 16;
    observed.sig[0].seen = 3;
    observed.sig[0].packets = 30;
    snprintf(observed.sig[1].kind, sizeof observed.sig[1].kind, "volume");
    observed.sig[1].volume = 40;
    observed.sig[1].seen = 2;
    observed.sig[1].packets = 99;
    do_bind("box-3", "plan-3", "text", "tls", "fp.example.com", "name", 6, 4, 1,
         0, 1, 2, 80, &observed);
    dump("fingerprint_seeded");

    d2k_cat_fp observed2;
    memset(&observed2, 0, sizeof observed2);
    observed2.method = 2;
    observed2.n_sig = 2;
    snprintf(observed2.sig[0].kind, sizeof observed2.sig[0].kind, "rx-volume");
    observed2.sig[0].volume = 19;
    observed2.sig[0].seen = 4;
    observed2.sig[0].packets = 22;
    snprintf(observed2.sig[1].kind, sizeof observed2.sig[1].kind, "volume");
    observed2.sig[1].volume = 40;
    observed2.sig[1].seen = 2;
    observed2.sig[1].packets = 99;
    do_bind("box-3", "plan-3", "text", "tls", "fp.example.com", "name", 6, 4, 1,
         0, 1, 2, 90, &observed2);
    dump("fingerprint_packets_only");

    do_bind("box-4", "plan-4", "text", "tls", "shape.example.com", "name", 6, 4, 1,
         0, 1, 2, 100, NULL);
    do_bind("box-4", "plan-4", "text", "tls", "shape.example.com", "name", 6, 4, 2,
         0, 1, 2, 101, NULL);
    dump("shape_mismatch_new_binding");

    /* Старый каталог: family=0 совместим с family=4, но при обновлении C
       поле family не переписывает. */
    do_bind("box-5", "plan-5", "text", "tls", "legacy.example.com", "name", 6, 4,
         1, 0, 1, 2, 110, NULL);
    cat.boxes[4].binds[0].family = 0;
    do_bind("box-5", "plan-5", "text", "tls", "legacy.example.com", "name", 6, 4,
         1, 0, 1, 2, 111, NULL);
    dump("legacy_family_zero_kept");

    printf("]\n");
    d2k_catalog_free(&cat);
    return 0;
}
