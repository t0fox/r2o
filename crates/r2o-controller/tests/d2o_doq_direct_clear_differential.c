/* C/Rust differential: DoQ direct CLEAR —
 * clear_backoff_ms(1/2/3) и QUIC-привязка forget_clear_target_bindings
 * (первая пометка, затем удаление при независимом повторе). */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

/* link.c не линкуется; снятие с провода для теста не важно. */
int d2k_link_del_name_family(int fd, const char *name, uint8_t transport,
                             uint8_t shape, uint8_t family,
                             char *err, size_t errcap)
{
    (void)fd; (void)name; (void)transport; (void)shape; (void)family;
    if (errcap) err[0] = '\0';
    return 0;
}

int main(void)
{
    printf("backoff_1=%lld\n", (long long)clear_backoff_ms(1));
    printf("backoff_2=%lld\n", (long long)clear_backoff_ms(2));
    printf("backoff_3=%lld\n", (long long)clear_backoff_ms(3));

    d2k_catalog *cat = calloc(1, sizeof *cat);
    d2k_cat_box *box = calloc(1, sizeof *box);
    d2k_cat_binding *bd = calloc(1, sizeof *bd);
    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    task *target = calloc(1, sizeof *target);
    if (!cat || !box || !bd || !scheduler || !target) return 2;
    snprintf(bd->kind, sizeof bd->kind, "%s", "name");
    snprintf(bd->target, sizeof bd->target, "%s", "doq.example");
    bd->enabled = 1;
    bd->level = 3;
    bd->transport = 17;
    bd->family = 4;
    bd->shape = D2K_LINK_SHAPE_QUIC;
    box->binds = bd;
    box->n_binds = 1;
    cat->boxes = box;
    cat->n_boxes = 1;

    scheduler->cat = cat;
    scheduler->link_fd = -1;
    scheduler->now_ms = 1000;
    snprintf(target->name, sizeof target->name, "%s", "doq.example");
    target->transport = 17;
    target->family = 4;
    target->trigger_code = D2K_SUSPECT_RST;

    forget_clear_target_bindings(scheduler, target, 1000);
    printf("quic_marked=%d\n", bd->recheck_since != 0);
    printf("quic_binds_after_first=%zu\n", box->n_binds);
    /* Пометка пережила рестарт: recheck_mono_ms == 0 — второй независимый
       прямой проход удаляет привязку. */
    bd->recheck_mono_ms = 0;
    bd->recheck_since = 1;
    forget_clear_target_bindings(scheduler, target, 2000);
    printf("quic_binds_after_second=%zu\n", box->n_binds);
    /* DoQ-задача не заполняет t->vol и не входит в TCP ECH-trial:
       direct-clear гейты остаются выключенными. */
    target->transport = 17;
    printf("doq_volume_proven=%d\n",
           target->vol.verdict == D2K_VOL_CUT || target->vol.rx_cut);
    printf("doq_ech_trial=%d\n", target->ech_trial);
    printf("doq_rx_partial=%d\n",
           target->vol.rx_partial_bytes != 0 ||
           target->vol.rx_partial_wire_bytes != 0);
    printf("doq_rx_direct_complete=%d\n", target->vol.rx_direct_complete);
    free(cat); free(box); free(bd); free(scheduler); free(target);
    return 0;
}
