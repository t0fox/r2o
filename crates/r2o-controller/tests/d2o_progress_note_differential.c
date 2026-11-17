/* C-оракул: production `d2k_sched_progress_note` из core/sched.c. */
#include "sched.c"

#include <stdio.h>
#include <string.h>

static d2k_sched progress_sched;
static task progress_task;

static void run(const char *label, const char *question, int pass, int fail)
{
    memset(&progress_task, 0, sizeof progress_task);
    g_progress_sink.s = &progress_sched;
    g_progress_sink.t = &progress_task;
    d2k_sched_progress_note(question, pass, fail);
    printf("%s %d ", label, progress_task.ask_probes);
    if (progress_task.ask_question[0] == '\0') {
        putchar('-');
    } else {
        for (const unsigned char *p = (const unsigned char *)progress_task.ask_question;
             *p; p++) {
            printf("%02x", (unsigned)*p);
        }
    }
    putchar('\n');
}

int main(void)
{
    pthread_mutex_init(&progress_sched.mu, NULL);
    char ascii95[96];
    char ascii96[97];
    char ascii200[201];
    char cyrillic[101];
    char mixed[104];
    char emoji[121];
    memset(ascii95, 'a', 95); ascii95[95] = '\0';
    memset(ascii96, 'a', 96); ascii96[96] = '\0';
    memset(ascii200, 'b', 200); ascii200[200] = '\0';
    for (size_t index = 0; index < 50; index++) {
        cyrillic[index * 2] = (char)0xd1;
        cyrillic[index * 2 + 1] = (char)0x8f;
    }
    cyrillic[100] = '\0';
    memcpy(mixed, "abc", 3);
    for (size_t index = 0; index < 50; index++) {
        mixed[3 + index * 2] = (char)0xd1;
        mixed[3 + index * 2 + 1] = (char)0x8f;
    }
    mixed[103] = '\0';
    for (size_t index = 0; index < 30; index++) {
        emoji[index * 4] = (char)0xf0;
        emoji[index * 4 + 1] = (char)0x9f;
        emoji[index * 4 + 2] = (char)0x98;
        emoji[index * 4 + 3] = (char)0x80;
    }
    emoji[120] = '\0';

    run("empty", "", 0, 0);
    run("whole", "whole", 3, 4);
    run("fail_only", "poison:seqovl", 0, 5);
    run("pass_only", "property:order", 7, 0);
    run("exact95", ascii95, 0, 1);
    run("ascii96", ascii96, 0, 0);
    run("ascii200", ascii200, 2, 3);
    run("cyrillic50", cyrillic, 1, 1);
    run("mixed", mixed, 0, 0);
    run("emoji30", emoji, 4, 0);
    run("spaces", "   ", 0, 1);
    return 0;
}
