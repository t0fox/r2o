/* C-оракул: production `sched_quic_progress` из core/sched.c. */
#include "sched.c"

#include <stdio.h>
#include <string.h>

static d2k_sched progress_sched;
static task progress_task;

static void run(const char *label, const char *question, int probes)
{
    memset(&progress_task, 0, sizeof progress_task);
    g_progress_sink.s = &progress_sched;
    g_progress_sink.t = &progress_task;
    sched_quic_progress(question, probes);
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
    char cyrillic[121];
    memset(cyrillic, 0, sizeof cyrillic);
    for (size_t index = 0; index < 60; index++) {
        cyrillic[index * 2] = (char)0xd1;
        cyrillic[index * 2 + 1] = (char)0x8f;
    }
    char ascii[201];
    memset(ascii, 'c', 200);
    ascii[200] = '\0';

    run("control", "контроль живости", 3);
    run("direct", "прямой зонд", 1);
    run("h3", "прямой запрос HTTP/3", 3);
    run("empty", "", 2);
    run("zero_sent", "согласование версии", 0);
    run("cyrillic", cyrillic, 4);
    run("ascii200", ascii, 5);
    return 0;
}
