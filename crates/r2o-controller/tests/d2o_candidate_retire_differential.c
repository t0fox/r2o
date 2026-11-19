#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sched.c"

static d2k_sched scheduler;
static d2k_catalog catalog;
static int link_pair[2];

static void run_case(const char *name, uint8_t family, uint8_t shape,
                     uint16_t sport, int installed)
{
    task probe_task;
    memset(&probe_task, 0, sizeof probe_task);
    snprintf(probe_task.name, sizeof probe_task.name, "%s", name);
    snprintf(probe_task.ip, sizeof probe_task.ip, "%s",
             family == 6 ? "2001:db8::20" : "198.51.100.20");
    probe_task.transport = 6;
    probe_task.family = family;
    probe_task.port = 443;
    probe_task.trial_installed = installed;
    probe_task.trial_shape = shape;
    probe_task.probe_sport_be = htons(sport);
    probe_task.probe_fd = -1;
    candidate_retire(&scheduler, &probe_task);
    if (!installed) {
        printf("name=%s installed=0 frame=none\n", name);
        return;
    }

    uint8_t frame[512];
    ssize_t length = read(link_pair[1], frame, sizeof frame);
    if (length <= 0) {
        printf("name=%s installed=%d frame=none\n", name, installed);
        return;
    }
    printf("name=%s installed=%d frame=", name, installed);
    for (ssize_t i = 0; i < length; i++) {
        printf("%02x", frame[i]);
    }
    printf("\n");
}

int main(void)
{
    memset(&scheduler, 0, sizeof scheduler);
    memset(&catalog, 0, sizeof catalog);
    scheduler.cat = &catalog;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, link_pair) != 0) {
        perror("socketpair");
        return 1;
    }
    scheduler.link_fd = link_pair[0];
    run_case("retire.example", 4, D2K_SHAPE_MODERN, 40123, 1);
    run_case("retire.example", 6, D2K_SHAPE_LEGACY, 40200, 1);
    run_case("retire.example", 4, D2K_SHAPE_MODERN, 40123, 0);
    close(link_pair[0]);
    close(link_pair[1]);
    return 0;
}
