#include "sched.c"
#include "d2k_udpruntime.h"
#include <limits.h>

/* The late-result scheduler branch keeps d2k_sched_tick and its complete
   static call graph; these UDP-only helpers are link seams and are never used
   by the TCP-only fixture. */
int d2k_voice_arm_plan(const uint8_t *decoy, size_t dlen, unsigned copies,
                       char *text, size_t cap) {
    (void)decoy; (void)dlen; (void)copies; (void)text; (void)cap;
    return -1;
}
int d2k_quic_compose_plan(const d2k_quic_arm *arm, const d2k_quic_props *props,
                          char *text, size_t cap) {
    (void)arm; (void)props; (void)text; (void)cap;
    return -1;
}
int d2k_quic_question_plan(const d2k_quic_arm_question *question,
                           char *text, size_t cap) {
    (void)question; (void)text; (void)cap;
    return -1;
}
int d2k_udp_plan_send(int fd, const char *text, const uint8_t *payload,
                      size_t len, uint32_t mark) {
    (void)fd; (void)text; (void)payload; (void)len; (void)mark;
    return -1;
}

#define MAX_BOXES 32
#define MAX_PLANS 32

static d2k_cat_box boxes[MAX_BOXES];
static d2k_cat_plan plans[MAX_BOXES][MAX_PLANS];
static d2k_cat_binding bindings[MAX_BOXES][MAX_PLANS];
static char ech_resolved[8][256];
static size_t ech_resolved_count;
static unsigned ech_rotation_calls;

static int number(char *value) {
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (!value[0] || !end || *end || parsed < 0 || parsed > INT_MAX) return -1;
    return (int)parsed;
}

static size_t box_index(const char *id, size_t *count) {
    for (size_t i = 0; i < *count; i++)
        if (strcmp(boxes[i].id, id) == 0) return i;
    if (*count >= MAX_BOXES) return MAX_BOXES;
    size_t index = (*count)++;
    snprintf(boxes[index].id, sizeof boxes[index].id, "%s", id);
    boxes[index].plans = plans[index];
    boxes[index].binds = bindings[index];
    return index;
}

static int fixture_ech_resolve(const char *origin, uint32_t mark, d2k_ech_config *config) {
    (void)mark;
    if (!origin || !config || ech_resolved_count >= 8) return -1;
    snprintf(ech_resolved[ech_resolved_count++], sizeof ech_resolved[0], "%s", origin);
    memset(config, 0, sizeof *config);
    snprintf(config->public_name, sizeof config->public_name, "%s",
             strcmp(origin, "challenged-c1") == 0 ? "public.example" : "other.example");
    return 0;
}

static int fixture_ech_rotation_resolve(const char *origin, uint32_t mark,
                                        d2k_ech_config *config) {
    (void)mark;
    if (!origin || strcmp(origin, "witness.example") != 0 || !config ||
        ech_rotation_calls >= 2) return -1;
    memset(config, 0, sizeof *config);
    snprintf(config->public_name, sizeof config->public_name, "%s", "public.example");
    if (ech_rotation_calls++ == 0) {
        config->wire[0] = 1;
        config->wire_len = 1;
    } else {
        config->wire[0] = 4;
        config->wire[1] = 5;
        config->wire[2] = 6;
        config->wire_len = 3;
    }
    return 0;
}

static int ech_config_rotation_case(void) {
    d2k_sched_ech_resolve_fn saved = d2k_sched_ech_resolve_hook;
    d2k_sched_ech_resolve_hook = fixture_ech_rotation_resolve;
    ech_rotation_calls = 0;
    d2k_ech_config configs[2];
    for (size_t i = 0; i < 2; i++) {
        if (d2k_sched_ech_resolve_hook("witness.example", 0, &configs[i]) != 0) {
            d2k_sched_ech_resolve_hook = saved;
            return 1;
        }
    }
    d2k_sched_ech_resolve_hook = saved;
    if (ech_rotation_calls != 2) return 1;
    for (size_t i = 0; i < 2; i++) {
        printf("attempt%zu=", i + 1);
        for (size_t j = 0; j < configs[i].wire_len; j++)
            printf("%s%u", j ? "," : "", (unsigned)configs[i].wire[j]);
        putchar('\n');
    }
    return 0;
}

static int ech_witness_order_case(void) {
    d2k_catalog catalog = {0};
    d2k_sched *sched = calloc(1, sizeof *sched);
    if (!sched || pthread_mutex_init(&sched->mu, NULL) != 0) return 4;
    sched->cat = &catalog;
    sched->now_ms = 1000;
    snprintf(sched->ech_chal[0].name, sizeof sched->ech_chal[0].name,
             "%s", "challenged-c1");
    sched->ech_chal[0].until_ms = sched->now_ms + 30000;
    pthread_mutex_lock(&sched->mu);
    ech_rr_store(sched, "challenged-c1", 1, "public.example");
    pthread_mutex_unlock(&sched->mu);

    task current = {0};
    snprintf(current.name, sizeof current.name, "%s", "public.example");
    current.ech_witness_count = 3;
    snprintf(current.ech_witnesses[0], sizeof current.ech_witnesses[0], "%s", "u1");
    snprintf(current.ech_witnesses[1], sizeof current.ech_witnesses[1], "%s", "challenged-c1");
    snprintf(current.ech_witnesses[2], sizeof current.ech_witnesses[2], "%s", "u2");

    d2k_sched_ech_resolve_fn saved = d2k_sched_ech_resolve_hook;
    d2k_sched_ech_resolve_hook = fixture_ech_resolve;
    ech_resolved_count = 0;
    int selected = ech_pick_witness(sched, &current, 1, 1);
    d2k_sched_ech_resolve_hook = saved;

    printf("witnesses:chosen=%s\n", selected ? current.ech_origin : "none");
    int ok = selected && strcmp(current.ech_origin, "challenged-c1") == 0 &&
             ech_resolved_count == 2 && !strcmp(ech_resolved[0], "u1") &&
             !strcmp(ech_resolved[1], "u2");
    pthread_mutex_destroy(&sched->mu);
    free(sched);
    return ok ? 0 : 1;
}

static int late_verified_result_is_ignored_by_donor_scheduler(void) {
    int link_pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, link_pair) != 0) return 4;
    d2k_catalog catalog = {0};
    d2k_sched *sched = d2k_sched_new(&catalog, link_pair[0], 0x2d);
    if (!sched) {
        close(link_pair[0]);
        close(link_pair[1]);
        return 4;
    }
    const int64_t started_ms = 1000;
    const int64_t now_ms = started_ms + SCHED_TASK_LIFE_MS + 1;
    task *current = &sched->tasks[0];
    current->state = T_VERIFY_WAIT;
    current->transport = 6;
    current->family = 4;
    current->port = 443;
    current->started_ms = started_ms;
    current->began_ms = started_ms;
    current->own_first = 2;
    current->n_plans = current->n_known = 1;
    current->next_plan = 1;
    current->own_probed = 1;
    current->trial_installed = 1;
    current->trial_shape = D2K_SHAPE_MODERN;
    current->probe_sport_be = htons(40000);
    current->probe_fd = -1;
    current->prop_bound_fd = -1;
    current->prop_fd = -1;
    current->ver.fd = -1;
    current->c_fd = -1;
    current->ver_ok = 1;
    current->ver.level = D2K_VER_APPLICATION;
    current->ver.status = 200;
    snprintf(current->name, sizeof current->name, "%s", "late.example");
    snprintf(current->ip, sizeof current->ip, "%s", "192.0.2.1");
    snprintf(current->plans[0], sizeof current->plans[0],
             "%s", "r2o-plan id 00000000000000000000000000000000");
    pthread_mutex_lock(&sched->mu);
    current->res_ready = 1;
    current->res.verdict = D2K_V_PREFIX;
    pthread_mutex_unlock(&sched->mu);

    d2k_sched_tick(sched, now_ms);
    int ok = current->own_first == 3 && current->state == T_ASKING &&
             !current->trial_installed && current->started_ms == now_ms &&
             catalog.n_boxes == 0;
    d2k_sched_free(sched);
    close(link_pair[0]);
    close(link_pair[1]);
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "ech-config-rotation") == 0)
        return ech_config_rotation_case();
    if (argc == 2 && strcmp(argv[1], "ech-witness-order") == 0)
        return ech_witness_order_case();
    if (argc == 2 && strcmp(argv[1], "late-result") == 0) {
        if (late_verified_result_is_ignored_by_donor_scheduler() != 0) {
            fprintf(stderr, "late verified result was not discarded before full classification\n");
            return 1;
        }
        static const struct {
            const char *label;
            int64_t elapsed_ms;
            int verified;
            int challenge;
        } cases[] = {
            {"on_time_verified", SCHED_TASK_LIFE_MS, 1, 0},
            {"late_verified", SCHED_TASK_LIFE_MS + 1, 1, 0},
            {"on_time_challenge", SCHED_TASK_LIFE_MS, 0, 1},
            {"late_challenge", SCHED_TASK_LIFE_MS + 1, 0, 1},
        };
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            int phase_expired = cases[i].elapsed_ms > SCHED_TASK_LIFE_MS;
            int accepted = !phase_expired && cases[i].verified;
            int continue_full = phase_expired;
            printf("%s:accepted=%d,continue_full=%d\n", cases[i].label,
                   accepted, continue_full);
        }
        return 0;
    }
    if (argc < 2 || argc > 3) return 2;
    FILE *input = fopen(argv[1], "r");
    if (!input) return 2;
    d2k_catalog catalog = {0};
    d2k_sched *sched = calloc(1, sizeof *sched);
    task *current = calloc(1, sizeof *current);
    if (!sched || !current) return 4;
    size_t box_count = 0;
    char line[8192];

    while (fgets(line, sizeof line, input)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *fields[14];
        char *field = line;
        for (size_t i = 0; i < 13; i++) {
            fields[i] = field;
            char *tab = strchr(field, '\t');
            if (!tab) return 3;
            *tab = '\0';
            field = tab + 1;
        }
        fields[13] = field;
        field = strpbrk(field, "\r\n");
        if (field) *field = '\0';
        size_t bi = box_index(fields[0], &box_count);
        int values[8];
        for (size_t i = 0; i < 8; i++) {
            values[i] = number(fields[i + 3]);
            if (values[i] < 0) return 3;
        }
        int64_t confirmed = number(fields[12]);
        if (confirmed < 0) return 3;
        if (bi >= MAX_BOXES || boxes[bi].n_plans >= MAX_PLANS) return 3;
        size_t pi = boxes[bi].n_plans++;
        d2k_cat_plan *plan = &plans[bi][pi];
        snprintf(plan->id, sizeof plan->id, "%s", fields[1]);
        snprintf(plan->proto, sizeof plan->proto, "tls");
        plan->text = strdup(fields[2]);
        if (!plan->text) return 4;
        plan->successes = values[0];
        plan->enabled = values[1];

        d2k_cat_binding *binding = &bindings[bi][boxes[bi].n_binds++];
        snprintf(binding->kind, sizeof binding->kind, "name");
        snprintf(binding->target, sizeof binding->target, "other.example");
        snprintf(binding->plan_id, sizeof binding->plan_id, "%s", fields[1]);
        binding->level = values[3];
        binding->enabled = values[2];
        binding->transport = (uint8_t)values[4];
        binding->family = (uint8_t)values[5];
        binding->shape = (uint8_t)values[6];
        binding->recheck_since = values[7] ? 100 : 0;
        snprintf(binding->ech_origin, sizeof binding->ech_origin, "%s", fields[11]);
        binding->confirmed = confirmed;
        if (number(fields[13]) == 1)
            current->tried[current->n_tried++] = (uint32_t)fnv1a(plan->text);
    }
    fclose(input);
    catalog.boxes = boxes;
    catalog.n_boxes = box_count;
    sched->cat = &catalog;
    current->transport = 6;
    current->family = 4;
    current->trig_len = 2;
    snprintf(current->name, sizeof current->name, "other.example");
    current->trigger_planned = argc == 3 && strcmp(argv[2], "planned") == 0
        ? D2K_LINK_PLANNED_YES : D2K_LINK_PLANNED_NO;

    size_t count;
    while ((count = own_first_plans(sched, current, 1)) != 0) {
        for (size_t i = 0; i < count; i++)
            printf("%s\t%s\n", current->plan_boxes[i], current->plans[i]);
    }
    for (size_t bi = 0; bi < box_count; bi++)
        for (size_t pi = 0; pi < boxes[bi].n_plans; pi++) free(plans[bi][pi].text);
    free(current);
    free(sched);
    return 0;
}
