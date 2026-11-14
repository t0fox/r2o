/* C/Rust differential: полный `d2k_sched_write_live` без активных поисков.
 *
 * Сверяются boxes/groups/measurements/autopick/targets/confirms/probes_used/
 * client_unfit. Rust-сторона — `r2o_controller::live::snapshot_with_areas`.
 * Поля расширения R2O (binding.probe_path/plan_id и т.п.) в сравнение не
 * входят: D2O их в live.json не пишет. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_sched s;
static d2k_catalog cat;
static d2k_group_state groups;
static d2k_cat_box boxes[2];
static d2k_cat_plan plans[3];
static d2k_cat_binding binds[3];
static d2k_cat_signal signals[2];
static installed_area areas[1];

static void set_key(d2k_group_key *key) {
    memset(key, 0, sizeof *key);
    key->transport = 6;
    key->family = 4;
    key->shape = 1;
}

int main(void) {
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    memset(&groups, 0, sizeof groups);
    memset(boxes, 0, sizeof boxes);
    memset(plans, 0, sizeof plans);
    memset(binds, 0, sizeof binds);
    memset(signals, 0, sizeof signals);
    memset(areas, 0, sizeof areas);

    snprintf(signals[0].kind, sizeof signals[0].kind, "volume");
    signals[0].volume = 40;
    signals[0].seen = 2;
    snprintf(signals[1].kind, sizeof signals[1].kind, "rx-volume");
    signals[1].volume = 16;
    signals[1].seen = 3;
    signals[1].packets = 22;

    snprintf(boxes[0].id, sizeof boxes[0].id, "box-1");
    boxes[0].created = 1000;
    boxes[0].updated = 2000;
    boxes[0].fp.method = 2;
    boxes[0].fp.n_sig = 2;
    boxes[0].fp.sig[0] = signals[0];
    boxes[0].fp.sig[1] = signals[1];

    snprintf(plans[0].id, sizeof plans[0].id, "plan-1");
    snprintf(plans[0].proto, sizeof plans[0].proto, "tls");
    plans[0].text = "r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n";
    plans[0].added = 1100;
    plans[0].successes = 5;
    plans[0].enabled = 1;
    snprintf(plans[1].id, sizeof plans[1].id, "plan-2");
    snprintf(plans[1].proto, sizeof plans[1].proto, "http");
    plans[1].text = "r2o-plan 1 5\nproto tcp http\nsegment 1400\n";
    plans[1].added = 1200;
    plans[1].successes = 1;
    plans[1].enabled = 1;
    plans[2] = plans[0];
    snprintf(plans[2].id, sizeof plans[2].id, "plan-3");
    plans[2].successes = 2;
    plans[2].enabled = 0;

    snprintf(binds[0].kind, sizeof binds[0].kind, "name");
    snprintf(binds[0].target, sizeof binds[0].target, "example.com");
    snprintf(binds[0].plan_id, sizeof binds[0].plan_id, "plan-1");
    binds[0].level = 3;
    binds[0].confirmed = 1500;
    binds[0].successes = 4;
    binds[0].enabled = 1;
    binds[0].transport = 6;
    binds[0].family = 4;
    binds[0].shape = 1;
    binds[0].tcp_profile = 0;
    binds[0].verified_by = 1;
    binds[0].input = 2;
    snprintf(binds[0].probe_path, sizeof binds[0].probe_path, "/main.css");
    binds[0].budget = 3;

    snprintf(binds[1].kind, sizeof binds[1].kind, "name");
    snprintf(binds[1].target, sizeof binds[1].target, "other.example");
    snprintf(binds[1].plan_id, sizeof binds[1].plan_id, "plan-3");
    binds[1].level = 1;
    binds[1].confirmed = 1600;
    binds[1].successes = 1;
    binds[1].enabled = 0;
    binds[1].transport = 6;
    binds[1].family = 6;
    binds[1].shape = 0;
    binds[1].recheck_since = 1700;

    boxes[0].plans = &plans[0];
    boxes[0].n_plans = 2;
    boxes[0].binds = &binds[0];
    boxes[0].n_binds = 2;

    snprintf(boxes[1].id, sizeof boxes[1].id, "box-2");
    boxes[1].created = 3000;
    boxes[1].updated = 3000;
    boxes[1].fp.method = 2;
    boxes[1].fp.n_sig = 1;
    boxes[1].fp.sig[0] = signals[0];
    boxes[1].plans = &plans[2];
    boxes[1].n_plans = 1;
    boxes[1].binds = &binds[2];
    boxes[1].n_binds = 1;
    snprintf(binds[2].kind, sizeof binds[2].kind, "addr");
    snprintf(binds[2].target, sizeof binds[2].target, "198.51.100.80");
    snprintf(binds[2].plan_id, sizeof binds[2].plan_id, "plan-3");
    binds[2].level = 3;
    binds[2].confirmed = 3000;
    binds[2].successes = 2;
    binds[2].enabled = 1;
    binds[2].transport = 6;
    binds[2].family = 4;
    binds[2].shape = 1;

    cat.boxes = boxes;
    cat.n_boxes = 2;
    cat.groups = &groups;

    groups.n_groups = 1;
    snprintf(groups.groups[0].suffix, sizeof groups.groups[0].suffix, "example.com");
    snprintf(groups.groups[0].plan_id, sizeof groups.groups[0].plan_id, "plan-1");
    set_key(&groups.groups[0].key);
    groups.groups[0].evidence_count = 2;
    groups.groups[0].at = 1500;
    groups.n_observations = 2;
    snprintf(groups.observations[0].name, sizeof groups.observations[0].name,
             "a.example.com");
    snprintf(groups.observations[0].plan_id, sizeof groups.observations[0].plan_id,
             "plan-1");
    set_key(&groups.observations[0].key);
    groups.observations[0].evidence = D2K_GROUP_BLOCKED_CONFIRMED;
    groups.observations[0].at = 1400;
    snprintf(groups.observations[1].name, sizeof groups.observations[1].name,
             "b.example.com");
    snprintf(groups.observations[1].plan_id, sizeof groups.observations[1].plan_id,
             "plan-1");
    set_key(&groups.observations[1].key);
    groups.observations[1].evidence = D2K_GROUP_DIRECT_CLEAR;
    groups.observations[1].at = 1450;

    snprintf(areas[0].name, sizeof areas[0].name, "example.com");
    snprintf(areas[0].plan_id, sizeof areas[0].plan_id, "plan-1");
    areas[0].kind = 1;
    areas[0].transport = 6;
    areas[0].shape = 1;
    areas[0].family = 4;
    areas[0].confirmed = 1;

    s.cat = &cat;
    s.areas = areas;
    s.n_areas = 1;
    s.now_ms = 5000;
    s.wall_base_s = 2000;
    s.mono_base_ms = 1000;
    s.meas_limit = 3;
    s.tasks[0].state = T_ASKING;
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
    s.event_sequence = 10;
    s.suspect_events = 5;
    snprintf(s.last_suspect_name, sizeof s.last_suspect_name, "target.example");
    s.last_suspect_transport = 6;
    s.last_suspect_family = 4;
    s.confirms = 7;
    s.probes_used = 42;
    s.unfit_client = 3;

    char path[] = "/tmp/d2o-live-snapshot-differential.json";
    if (d2k_sched_write_live(&s, path, "catalog.json") != 0) {
        fprintf(stderr, "d2k_sched_write_live failed\n");
        return 1;
    }
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    char body[65536];
    size_t got = fread(body, 1, sizeof body - 1, f);
    body[got] = 0;
    fclose(f);
    fputs(body, stdout);
    remove(path);
    return 0;
}
