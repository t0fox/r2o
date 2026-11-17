/* C-оракул: production `voice_trial_same_context` из core/sched.c. */
#include "sched.c"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static void run(const char *label, uint8_t family,
                const uint8_t server[4], uint16_t server_port,
                const uint8_t client[4],
                const uint8_t low_ip[4], uint16_t low_port,
                const uint8_t high_ip[4], uint16_t high_port)
{
    static task t;
    static d2k_ev ev;
    memset(&t, 0, sizeof t);
    memset(&ev, 0, sizeof ev);
    t.family = 4;
    memcpy(t.addr_probe_dst_ip, server, 4);
    memcpy(t.addr_probe_src_ip, client, 4);
    t.addr_probe_dst_port_be = htons(server_port);
    ev.family = family;
    memcpy(ev.low_ip, low_ip, 4);
    memcpy(ev.high_ip, high_ip, 4);
    ev.low_port = low_port;
    ev.high_port = high_port;
    printf("%s %d\n", label, voice_trial_same_context(&t, &ev));
}

static const uint8_t srv[4] = {203, 0, 113, 9};
static const uint8_t cli[4] = {192, 0, 2, 7};
static const uint8_t other[4] = {198, 51, 100, 4};

int main(void)
{
    run("forward_match", 4, srv, 50000, cli, srv, 50000, cli, 1234);
    run("reverse_match", 4, srv, 50000, cli, cli, 1234, srv, 50000);
    run("wrong_client", 4, srv, 50000, cli, srv, 50000, other, 1234);
    run("wrong_port", 4, srv, 50000, cli, srv, 50001, cli, 1234);
    run("family6", 6, srv, 50000, cli, srv, 50000, cli, 1234);
    run("family0_as4", 0, srv, 50000, cli, srv, 50000, cli, 1234);
    run("neither", 4, srv, 50000, cli, other, 1, other, 2);
    run("low_server_wrong_client", 4, srv, 50000, cli, srv, 50000, other, 1);
    run("high_server_wrong_client", 4, srv, 50000, cli, other, 1, srv, 50000);
    run("client_port_ignored", 4, srv, 50000, cli, cli, 0, srv, 50000);
    run("client_same_ip", 4, srv, 50000, srv, srv, 50000, srv, 1234);
    run("server_port_zero", 4, srv, 0, cli, srv, 0, cli, 1234);
    run("reverse_client_port_ignored", 4, srv, 50000, cli, cli, 65535, srv, 50000);
    return 0;
}
