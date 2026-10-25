#include "sched.c"
#include <limits.h>

#define CASE_CAP 8
#define BOX_CAP 16
#define PLAN_CAP 16

typedef struct {
    char id[32];
    d2k_cat_box boxes[BOX_CAP];
    d2k_cat_plan plans[BOX_CAP][PLAN_CAP];
    d2k_cat_signal signals[BOX_CAP][8];
    d2k_catalog catalog;
    d2k_sched sched;
    task current;
} fixture_case;

static fixture_case cases[CASE_CAP];
static size_t case_count;

static int number(const char *text, int *value) {
    char *end = NULL;
    long parsed = strtol(text, &end, 10);
    if (!text[0] || !end || *end || parsed < INT_MIN || parsed > INT_MAX) return -1;
    *value = (int)parsed;
    return 0;
}

static fixture_case *case_for(const char *id) {
    for (size_t i = 0; i < case_count; i++)
        if (strcmp(cases[i].id, id) == 0) return &cases[i];
    if (case_count >= CASE_CAP) return NULL;
    fixture_case *entry = &cases[case_count++];
    snprintf(entry->id, sizeof entry->id, "%s", id);
    entry->catalog.boxes = entry->boxes;
    entry->sched.cat = &entry->catalog;
    entry->current.fp.method = D2K_FP_METHOD;
    return entry;
}

static d2k_cat_box *box_for(fixture_case *entry, const char *id) {
    for (size_t i = 0; i < entry->catalog.n_boxes; i++)
        if (strcmp(entry->boxes[i].id, id) == 0) return &entry->boxes[i];
    if (entry->catalog.n_boxes >= BOX_CAP) return NULL;
    size_t index = entry->catalog.n_boxes++;
    d2k_cat_box *box = &entry->boxes[index];
    snprintf(box->id, sizeof box->id, "%s", id);
    box->fp.method = D2K_FP_METHOD;
    box->plans = entry->plans[index];
    return box;
}

static void add_signal(d2k_cat_fp *fp, const char *kind, int ttl, int tos,
                       int ipid, int volume) {
    if (strcmp(kind, "-") == 0) return;
    d2k_cat_signal signal = {0};
    snprintf(signal.kind, sizeof signal.kind, "%s", kind);
    signal.ttl = (uint8_t)ttl;
    signal.tos = (uint8_t)tos;
    signal.ipid = (uint16_t)ipid;
    signal.volume = volume;
    signal.seen = 1;
    fp_add(fp, &signal);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *input = fopen(argv[1], "r");
    if (!input) return 2;
    char line[8192];
    while (fgets(line, sizeof line, input)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *fields[21];
        char *field = line;
        for (size_t i = 0; i < 20; i++) {
            fields[i] = field;
            char *tab = strchr(field, '\t');
            if (!tab) return 3;
            *tab = '\0';
            field = tab + 1;
        }
        fields[20] = field;
        field = strpbrk(fields[20], "\r\n");
        if (field) *field = '\0';
        fixture_case *entry = case_for(fields[0]);
        if (!entry) return 4;
        int values[14];
        const size_t numeric_columns[] = {5, 6, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 20};
        for (size_t i = 0; i < sizeof numeric_columns / sizeof numeric_columns[0]; i++) {
            if (number(fields[numeric_columns[i]], &values[i]) != 0) return 3;
        }
        entry->current.transport = (uint8_t)values[10];
        entry->current.fp.method = values[13];
        add_signal(&entry->current.fp, fields[12], values[6], values[7], values[8], values[9]);
        if (fields[1][0]) {
            d2k_cat_box *box = box_for(entry, fields[1]);
            if (!box) return 4;
            box->fp.method = values[12];
            add_signal(&box->fp, fields[7], values[2], values[3], values[4], values[5]);
            if (fields[2][0]) {
                size_t index = 0;
                while (index < box->n_plans && strcmp(box->plans[index].id, fields[2]) != 0)
                    index++;
                if (index == box->n_plans) {
                    if (index >= PLAN_CAP) return 4;
                    d2k_cat_plan *plan = &box->plans[index];
                    box->n_plans++;
                    snprintf(plan->id, sizeof plan->id, "%s", fields[2]);
                    snprintf(plan->proto, sizeof plan->proto, "%s", fields[3]);
                    plan->text = strdup(fields[4]);
                    if (!plan->text) return 4;
                    plan->successes = values[0];
                    plan->enabled = values[1];
                }
                if (values[11]) entry->current.tried[entry->current.n_tried++] = (uint32_t)fnv1a(fields[4]);
            }
        }
    }
    fclose(input);
    for (size_t i = 0; i < case_count; i++) {
        fixture_case *entry = &cases[i];
        size_t count = known_plans(&entry->sched, &entry->current);
        for (size_t j = 0; j < count; j++)
            printf("%s\t%s\t%s\n", entry->id, entry->current.plan_boxes[j], entry->current.plans[j]);
    }
    for (size_t i = 0; i < case_count; i++)
        for (size_t bi = 0; bi < cases[i].catalog.n_boxes; bi++)
            for (size_t pi = 0; pi < cases[i].boxes[bi].n_plans; pi++)
                free(cases[i].plans[bi][pi].text);
    return 0;
}
