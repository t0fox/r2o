#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sched.c"

static d2k_sched scheduler;
static d2k_catalog catalog;
static int link_pair[2];

static void print_frames(void)
{
    uint8_t frame[512];
    int printed = 0;
    for (;;) {
        ssize_t length = recv(link_pair[1], frame, sizeof frame, MSG_DONTWAIT);
        if (length <= 0) {
            if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }
            break;
        }
        if (printed) {
            printf(",");
        }
        for (ssize_t i = 0; i < length; i++) {
            printf("%02x", frame[i]);
        }
        printed = 1;
    }
    if (!printed) {
        printf("none");
    }
}

static void run_case(const char *label, int question, int trial)
{
    task probe_task;
    memset(&probe_task, 0, sizeof probe_task);
    snprintf(probe_task.name, sizeof probe_task.name, "%s", "retire.example");
    snprintf(probe_task.ip, sizeof probe_task.ip, "%s", "198.51.100.20");
    probe_task.transport = 6;
    probe_task.family = 4;
    probe_task.port = 443;
    probe_task.prop_installed = question;
    probe_task.prop_sport_be = htons(41000);
    probe_task.trial_installed = trial;
    probe_task.trial_shape = D2K_SHAPE_MODERN;
    probe_task.probe_sport_be = htons(40123);
    probe_task.probe_fd = -1;
    probe_task.prop_bound_fd = -1;
    size_t length = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, probe_task.name,
                               probe_task.trig, sizeof probe_task.trig, &length) != 0) {
        fprintf(stderr, "hello fixture failed\n");
        return;
    }
    probe_task.trig_len = length;
    trial_retire(&scheduler, &probe_task);
    printf("case=%s frames=", label);
    print_frames();
    printf("\n");
}


static void run_addr_case(const char *label, uint8_t family, const char *src,
                          const char *dst, uint8_t trial_byte)
{
    task probe_task;
    memset(&probe_task, 0, sizeof probe_task);
    snprintf(probe_task.name, sizeof probe_task.name, "%s", "retire.example");
    snprintf(probe_task.ip, sizeof probe_task.ip, "%s",
             family == 6 ? "2001:db8::20" : "198.51.100.20");
    probe_task.transport = 6;
    probe_task.family = family;
    probe_task.port = 443;
    probe_task.by_addr = 1;
    probe_task.addr_probe_identity_valid = 1;
    probe_task.trial_installed = 1;
    probe_task.probe_fd = -1;
    probe_task.prop_bound_fd = -1;
    memset(probe_task.addr_probe_trial_id, trial_byte,
           sizeof probe_task.addr_probe_trial_id);
    if (family == 6) {
        struct sockaddr_in6 s6, d6;
        memset(&s6, 0, sizeof s6);
        memset(&d6, 0, sizeof d6);
        if (inet_pton(AF_INET6, src, &s6.sin6_addr) != 1 ||
            inet_pton(AF_INET6, dst, &d6.sin6_addr) != 1) {
            fprintf(stderr, "addr6 fixture failed\n");
            return;
        }
        memcpy(probe_task.addr_probe_src_ip, &s6.sin6_addr, 16);
        memcpy(probe_task.addr_probe_dst_ip, &d6.sin6_addr, 16);
        probe_task.addr_probe_src_port_be = htons(40001);
        probe_task.addr_probe_dst_port_be = htons(443);
    } else {
        struct in_addr s4, d4;
        if (inet_pton(AF_INET, src, &s4) != 1 ||
            inet_pton(AF_INET, dst, &d4) != 1) {
            fprintf(stderr, "addr4 fixture failed\n");
            return;
        }
        memcpy(probe_task.addr_probe_src_ip, &s4, 4);
        memcpy(probe_task.addr_probe_dst_ip, &d4, 4);
        probe_task.addr_probe_src_port_be = htons(40000);
        probe_task.addr_probe_dst_port_be = htons(443);
    }
    trial_retire(&scheduler, &probe_task);
    printf("case=%s frames=", label);
    print_frames();
    printf("\n");
}

int main(void)
{
    memset(&scheduler, 0, sizeof scheduler);
    memset(&catalog, 0, sizeof catalog);
    scheduler.cat = &catalog;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, link_pair) != 0) {
        perror("socketpair");
        return 1;
    }
    scheduler.link_fd = link_pair[0];
    run_case("both", 1, 1);
    run_case("question", 1, 0);
    run_case("candidate", 0, 1);
    run_case("none", 0, 0);
    run_addr_case("addr4", 4, "192.0.2.10", "198.51.100.20", 8);
    run_addr_case("addr6", 6, "2001:db8::10", "2001:db8::20", 9);
    close(link_pair[0]);
    close(link_pair[1]);
    return 0;
}
