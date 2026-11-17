/* C-оракул: production `progress_seen` из detect/bridge.c.
 *
 * `d2k_sched_progress_note` подменён записывающей заглушкой: сравнивается
 * именно решение progress_seen, а не сама запись в live (она покрыта
 * отдельным differential d2k_sched_progress_note). */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static char seen_question[16][160];
static int seen_pass[16];
static int seen_fail[16];
static size_t seen_count;

void d2k_sched_progress_note(const char *question, int pass, int fail)
{
    if (seen_count >= 16) { return; }
    snprintf(seen_question[seen_count], sizeof seen_question[0], "%s", question);
    seen_pass[seen_count] = pass;
    seen_fail[seen_count] = fail;
    seen_count++;
}

#include "bridge.c"

static void run(const char *label, int seeded, int has_ctx,
                const char *probe, int pass, int fail)
{
    d2k_obs obs;
    memset(&obs, 0, sizeof obs);
    snprintf(obs.probe, sizeof obs.probe, "%s", probe);
    obs.pass = pass;
    obs.fail = fail;
    int flag = seeded;
    seen_count = 0;
    progress_seen(has_ctx ? &flag : NULL, &obs);
    printf("%s %zu", label, seen_count);
    for (size_t index = 0; index < seen_count; index++) {
        printf(" %s %d %d", seen_question[index], seen_pass[index], seen_fail[index]);
    }
    putchar('\n');
}

int main(void)
{
    run("seeded_whole", 1, 1, "whole", 5, 0);
    run("seeded_split", 1, 1, "split", 3, 2);
    run("unseeded_whole", 0, 1, "whole", 1, 1);
    run("null_whole", 0, 0, "whole", 1, 1);
    run("empty_probe", 1, 1, "", 4, 0);
    run("seeded_property", 1, 1, "свойство:порядок", 0, 3);
    return 0;
}
