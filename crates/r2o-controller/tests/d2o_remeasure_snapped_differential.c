/* C/Rust differential: C `remeasure_snapped` сбрасывает состояние прошлого
 * поиска до запуска нового. Сравниваются только долговременные курсоры,
 * которые в R2O переживают отдельный job: tried/next_candidate/probes/plans/
 * rx-cursor. Остальные поля C — task-local и в R2O являются переменными
 * нового запуска; они печатаются в stderr для протокола. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "sched.c"

int main(void) {
    d2k_catalog cat;
    memset(&cat, 0, sizeof cat);
    d2k_sched *s = d2k_sched_new(&cat, -1, 0);
    if (!s) return 1;
    s->now_ms = 5000;
    s->meas_limit = 0; /* новый поиск только в очередь, без сетевого потока */

    task t;
    memset(&t, 0, sizeof t);
    snprintf(t.name, sizeof t.name, "remeasure.example");
    t.transport = 6;
    t.family = 4;
    t.state = T_WATCHING;
    t.n_plans = 3;
    t.next_plan = 2;
    t.probes = 5;
    t.ask_probes = 4;
    t.n_tried = 2;
    t.tried[0] = 0x1111;
    t.tried[1] = 0x2222;
    t.fb_next = 7;
    t.n_own_seen = 2;
    t.own_seen_full = 1;
    t.own_probed = 1;
    t.rx_bootstrap_only = 1;
    t.family_reuse = 1;
    t.ech_grease = 1;
    t.rx_volume_next_variant = 3;
    t.net_probing = 1;
    t.net_probe_next = 2;
    t.exec_refused = 1;
    t.exec_probed = 1;
    t.researched = 1;
    t.family_fast = 1;
    t.own_first = 2;
    t.seed_use = 1;
    t.seed.valid = 1;
    t.trig_len = 5;
    memcpy(t.trig, "hello", 5);
    t.snap_len = 5;
    t.snap_stop = 1;
    t.ctrl_len = 7;

    const uint8_t bytes[] = "world";
    remeasure_snapped(s, &t, bytes, sizeof bytes - 1);

    /* stderr: полный C-reset для протокола. */
    fprintf(stderr,
            "c_only next_plan=%zu probes=%d ask_probes=%d n_tried=%zu fb_next=%zu "
            "n_plans=%zu n_own_seen=%zu own_seen_full=%d own_probed=%u "
            "rx_bootstrap_only=%u family_reuse=%u ech_grease=%u "
            "rx_volume_next_variant=%u net_probing=%u net_probe_next=%zu "
            "exec_refused=%u exec_probed=%u researched=%u family_fast=%u "
            "own_first=%u seed_use=%u seed_valid=%u trig_snapped=%u reasked=%u "
            "snap_len=%zu snap_stop=%u ctrl_len=%zu state=%d trig_len=%zu\n",
            t.next_plan, t.probes, t.ask_probes, t.n_tried, t.fb_next,
            t.n_plans, t.n_own_seen, t.own_seen_full, t.own_probed,
            t.rx_bootstrap_only, t.family_reuse, t.ech_grease,
            t.rx_volume_next_variant, t.net_probing, t.net_probe_next,
            t.exec_refused, t.exec_probed, t.researched, t.family_fast,
            t.own_first, t.seed_use, t.seed.valid, t.trig_snapped, t.reasked,
            t.snap_len, t.snap_stop, t.ctrl_len, (int)t.state, t.trig_len);

    printf("{\n");
    printf("  \"candidate_cursor_cleared\": %s,\n",
           t.fb_next == 0 && t.next_plan == 0 ? "true" : "false");
    printf("  \"tried_cleared\": %s,\n", t.n_tried == 0 ? "true" : "false");
    printf("  \"probes_cleared\": %s,\n",
           t.probes == 0 && t.ask_probes == 0 ? "true" : "false");
    printf("  \"plans_cleared\": %s,\n", t.n_plans == 0 ? "true" : "false");
    printf("  \"rx_cursor_cleared\": %s\n",
           t.rx_volume_next_variant == 0 && t.net_probe_next == 0 &&
                   !t.net_probing
               ? "true"
               : "false");
    printf("}\n");
    d2k_sched_free(s);
    return 0;
}
