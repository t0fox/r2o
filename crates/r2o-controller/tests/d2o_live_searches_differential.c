/* C/Rust differential: production-builder `searches` для live.json.
 * Один state со всеми шестью task-state; T_WATCHING/T_RESTING C исключает. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static task *slot(d2k_sched *s, size_t index, const char *name, const char *ip,
                  task_state state) {
    task *t = &s->tasks[index];
    memset(t, 0, sizeof *t);
    snprintf(t->name, sizeof t->name, "%s", name);
    snprintf(t->ip, sizeof t->ip, "%s", ip);
    t->port = 443;
    t->family = 4;
    t->transport = 6;
    t->state = state;
    return t;
}

int main(void) {
    static d2k_sched s;
    static d2k_catalog cat;
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    s.cat = &cat;
    s.now_ms = 5000;
    s.wall_base_s = 2000;
    s.mono_base_ms = 1000;
    s.meas_limit = 0;

    task *t = slot(&s, 0, "verify.example", "198.51.100.11", T_VERIFY);
    t->began_ms = 4000;
    t->probes = 3;
    t->next_plan = 1;
    t->n_plans = 1;
    t->n_known = 1;

    t = slot(&s, 1, "ask.example", "198.51.100.10", T_ASKING);
    t->began_ms = 2000;
    t->probes = 2;
    t->ask_probes = 1;
    snprintf(t->ask_question, sizeof t->ask_question, "вопрос");

    t = slot(&s, 2, "queued.example", "198.51.100.12", T_QUEUED);
    t->queued_ms = 3500;

    t = slot(&s, 3, "planning.example", "198.51.100.13", T_PLANNING);
    t->began_ms = 3000;
    t->probes = 2;

    t = slot(&s, 4, "watching.example", "198.51.100.14", T_WATCHING);
    t->began_ms = 2500;
    t->probes = 1;

    t = slot(&s, 5, "resting.example", "198.51.100.15", T_RESTING);
    t->began_ms = 2500;

    char path[] = "/tmp/d2o-live-searches.json";
    if (d2k_sched_write_live(&s, path, "catalog.json") != 0) return 1;
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    char body[131072];
    size_t got = fread(body, 1, sizeof body - 1, f);
    body[got] = 0;
    fclose(f);
    remove(path);
    fputs(body, stdout);
    return 0;
}
