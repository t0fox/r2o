#include "sched.c"
#include <limits.h>

#define MAX_BOXES 32
#define MAX_PLANS 32

static d2k_cat_box boxes[MAX_BOXES];
static d2k_cat_plan plans[MAX_BOXES][MAX_PLANS];
static d2k_cat_binding bindings[MAX_BOXES][MAX_PLANS];

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

int main(int argc, char **argv) {
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
