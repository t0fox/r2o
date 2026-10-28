#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "d2k_quic.h"
#include "d2k_quic_arms.h"
#include "d2k_quichello.h"
#include "d2k_quicprobe.h"

static int control_pass;
static int control_sent;
static int residual_control_pass;
static int residual_control_err;
static int trigger_pass;
static int trigger_err;
static int trigger_sent;
static int control_calls;
static int trigger_calls;
static int direct_arm_calls;
static int direct_data_calls;
static d2k_quic_arm_data_verdict direct_data_verdicts[D2K_QUIC_REPEATS];
static int direct_data_verdict_count;
static int alternate_address_available;
static char direct_arm_address[D2K_QUIC_ADDR_LEN];

static size_t no_extra_addresses(const char *sni,
                                 char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    (void)sni; (void)out; (void)cap;
    return 0;
}

static size_t optional_alternate_address(const char *sni,
                                         char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    (void)sni;
    if (!alternate_address_available || cap == 0) return 0;
    (void)strncpy(out[0], "203.0.113.8", D2K_QUIC_ADDR_LEN - 1);
    return 1;
}

struct local_server {
    int fd;
    uint16_t source_ports[D2K_QUIC_REPEATS];
    int received;
    uint8_t first_request[2048];
    size_t first_request_len;
};

static d2k_tally mock_control(const char *addr, uint16_t port,
                              const uint8_t *prefix, size_t prefix_len,
                              d2k_hello hello, uint32_t wait_ms, uint32_t mark,
                              int repeats, uint32_t *rtt_ms, int *refused,
                              int *sent, uint8_t *ttl_in);
static d2k_tally mock_trigger(const char *addr, uint16_t port,
                              const uint8_t *prefix, size_t prefix_len,
                              d2k_hello hello, uint32_t wait_ms, uint32_t mark,
                              int repeats, uint32_t *rtt_ms, int *refused,
                              int *sent, uint8_t *ttl_in);

static void *serve_version_negotiation(void *opaque) {
    struct local_server *server = opaque;
    static const uint8_t version_negotiation[] = {0x80, 0, 0, 0, 0, 0, 0};
    struct sockaddr_in peers[D2K_QUIC_REPEATS];
    socklen_t peer_lengths[D2K_QUIC_REPEATS];
    for (int i = 0; i < D2K_QUIC_REPEATS; i++) {
        uint8_t request[2048];
        memset(&peers[i], 0, sizeof peers[i]);
        peer_lengths[i] = sizeof peers[i];
        ssize_t n = recvfrom(server->fd, request, sizeof request, 0,
                             (struct sockaddr *)&peers[i], &peer_lengths[i]);
        if (n <= 0) break;
        if (server->received == 0) {
            server->first_request_len = (size_t)n;
            memcpy(server->first_request, request, (size_t)n);
        }
        server->source_ports[server->received++] = ntohs(peers[i].sin_port);
    }
    for (int i = 0; i < server->received; i++) {
        if (sendto(server->fd, version_negotiation, sizeof version_negotiation, 0,
                   (struct sockaddr *)&peers[i], peer_lengths[i]) !=
            (ssize_t)sizeof version_negotiation) break;
    }
    return NULL;
}

static int print_version_negotiation_results(void) {
    struct sockaddr_in local;
    memset(&local, 0, sizeof local);
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&local, sizeof local) != 0) return 1;
    struct timeval receive_timeout = {.tv_sec = 3};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout,
                   sizeof receive_timeout) != 0) return 1;
    socklen_t local_len = sizeof local;
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0) return 1;

    struct local_server server = {.fd = fd};
    pthread_t thread;
    if (pthread_create(&thread, NULL, serve_version_negotiation, &server) != 0) return 1;
    uint8_t initial[2048];
    size_t initial_len = 0;
    if (d2k_quic_probe_initial("blocked.example", initial, sizeof initial,
                               &initial_len) != 0) return 1;
    const uint8_t control_byte[] = {0x02};
    d2k_hello trigger = {.bytes = initial, .len = initial_len};
    d2k_hello control = {.bytes = control_byte, .len = sizeof control_byte};
    control_pass = 0;
    control_sent = D2K_QUIC_REPEATS;
    control_calls = trigger_calls = 0;
    d2k_quic_ask_control_hook = mock_control;
    d2k_quic_ask_hook = mock_trigger;
    d2k_quic_resolve_hook = no_extra_addresses;
    d2k_quic_allow_local = 1;
    uint32_t saved_wait_ms = d2k_quic_wait_ms;
    d2k_quic_wait_ms = 1000;
    d2k_vres result = d2k_quic_run("127.0.0.1", ntohs(local.sin_port),
                                   "blocked.example", trigger, control, 0, NULL);
    d2k_quic_wait_ms = saved_wait_ms;
    (void)pthread_join(thread, NULL);
    close(fd);

    const uint8_t *packet = server.first_request;
    size_t length = server.first_request_len;
    int zero_padding = length >= 24;
    for (size_t i = 24; zero_padding && i < length; i++) {
        if (packet[i] != 0) zero_padding = 0;
    }
    const char *verdict = result.verdict == D2K_V_NO_QUIC ? "no_quic" : "other";
    int sent = result.probes - control_sent;
    printf("received=%d\nlen=%zu\nfirst=%02x\nversion=%u\ndcid_len=%u\n"
           "scid_len=%u\ntoken=%u\nzero_padding=%d\nanswer=%d\nsent=%d\n"
           "verdict=%s\nprobes=%d\ntrigger_calls=%d\n",
           server.received, length, length > 0 ? packet[0] : 0,
           length >= 5 ? ((uint32_t)packet[1] << 24 | (uint32_t)packet[2] << 16 |
                          (uint32_t)packet[3] << 8 | packet[4]) : 0,
           length > 5 ? packet[5] : 0,
           length > 14 ? packet[14] : 0,
           length > 23 ? packet[23] : 0,
           zero_padding, result.verdict == D2K_V_NO_QUIC,
           sent, verdict, result.probes, trigger_calls);
    return server.received != D2K_QUIC_REPEATS || length != 1200 || packet[0] != 0xc0 ||
           result.verdict != D2K_V_NO_QUIC || sent != D2K_QUIC_REPEATS ||
           result.probes != 2 * D2K_QUIC_REPEATS || control_calls != 1 ||
           trigger_calls != 0 || !zero_padding;
}

static int print_parallel_control_results(void) {
    struct sockaddr_in local;
    memset(&local, 0, sizeof local);
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&local, sizeof local) != 0) return 1;
    struct timeval receive_timeout = {.tv_sec = 3};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout,
                   sizeof receive_timeout) != 0) return 1;
    socklen_t local_len = sizeof local;
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0) return 1;

    struct local_server server = {.fd = fd};
    pthread_t thread;
    if (pthread_create(&thread, NULL, serve_version_negotiation, &server) != 0) return 1;
    d2k_quic_allow_local = 1;
    uint8_t placeholder[] = {0};
    d2k_hello control = {.bytes = placeholder, .len = sizeof placeholder};
    int refused = 0, sent = 0;
    uint32_t rtt_ms = 0;
    d2k_tally tally = d2k_quic_ask_control_hook(
        "127.0.0.1", ntohs(local.sin_port), NULL, 0, control, 1000, 0,
        D2K_QUIC_REPEATS, &rtt_ms, &refused, &sent, NULL);
    (void)pthread_join(thread, NULL);
    close(fd);

    int unique = server.received == D2K_QUIC_REPEATS;
    for (int i = 0; unique && i < D2K_QUIC_REPEATS; i++) {
        for (int j = i + 1; j < D2K_QUIC_REPEATS; j++) {
            if (server.source_ports[i] == server.source_ports[j]) unique = 0;
        }
    }
    printf("pass=%d\nerr=%d\nsent=%d\nmarked=%d\nunique_ports=%d\n",
           tally.pass, tally.err, sent, tally.marked, unique);
    return tally.pass != D2K_QUIC_REPEATS || tally.err != 0 ||
           sent != D2K_QUIC_REPEATS || !tally.marked || !unique;
}

static d2k_tally mock_control(const char *addr, uint16_t port,
                              const uint8_t *prefix, size_t prefix_len,
                              d2k_hello hello, uint32_t wait_ms, uint32_t mark,
                              int repeats, uint32_t *rtt_ms, int *refused,
                              int *sent, uint8_t *ttl_in) {
    (void)addr; (void)port; (void)prefix; (void)prefix_len; (void)hello;
    (void)wait_ms; (void)mark; (void)repeats;
    int call = control_calls++;
    int pass = call == 0 ? control_pass : residual_control_pass;
    int err = call == 0 ? 0 : residual_control_err;
    if (rtt_ms) *rtt_ms = 10;
    if (refused) *refused = 0;
    if (sent) *sent = control_sent;
    if (ttl_in) *ttl_in = 40;
    return (d2k_tally){
        .pass = pass,
        .fail = D2K_QUIC_REPEATS - pass - err,
        .marked = 1,
        .err = err,
    };
}

static d2k_tally mock_trigger(const char *addr, uint16_t port,
                              const uint8_t *prefix, size_t prefix_len,
                              d2k_hello hello, uint32_t wait_ms, uint32_t mark,
                              int repeats, uint32_t *rtt_ms, int *refused,
                              int *sent, uint8_t *ttl_in) {
    (void)addr; (void)port; (void)prefix; (void)prefix_len; (void)hello;
    (void)wait_ms; (void)mark; (void)repeats; (void)rtt_ms; (void)refused;
    (void)ttl_in;
    trigger_calls++;
    if (sent) *sent = trigger_sent;
    return (d2k_tally){
        .pass = trigger_pass,
        .fail = D2K_QUIC_REPEATS - trigger_pass - trigger_err,
        .marked = 1,
        .err = trigger_err,
    };
}

static d2k_tally mock_direct_arm(const d2k_quic_arm_question *question,
                                const char *sni, uint16_t port, uint32_t wait_ms,
                                uint32_t mark, int *sent) {
    (void)sni; (void)port; (void)wait_ms; (void)mark;
    direct_arm_calls++;
    if (direct_arm_calls == 1 && question && question->addr) {
        (void)strncpy(direct_arm_address, question->addr, sizeof direct_arm_address - 1);
    }
    if (sent) *sent = D2K_QUIC_REPEATS;
    return (d2k_tally){.fail = D2K_QUIC_REPEATS, .marked = 1};
}

static d2k_quic_arm_data mock_direct_data(const d2k_quic_arm_question *question,
                                          const char *sni, const char *path,
                                          uint16_t port, uint32_t wait_ms,
                                          uint32_t mark) {
    (void)question; (void)sni; (void)path; (void)port; (void)wait_ms; (void)mark;
    int call = direct_data_calls++;
    d2k_quic_arm_data_verdict verdict = call < direct_data_verdict_count
        ? direct_data_verdicts[call] : D2K_QAD_PASS;
    return (d2k_quic_arm_data){
        .verdict = verdict,
        .app_bytes = D2K_QUIC_ARM_DATA_BYTES,
    };
}

static int print_direct_data_results(void) {
    static const struct {
        const char *name;
        d2k_quic_arm_data_verdict first;
        d2k_quic_arm_data_verdict second;
        int has_second;
        const char *expected;
        int expected_calls;
    } cases[] = {
        {"pass", D2K_QAD_PASS, D2K_QAD_NOT_RUN, 0, "clear", 1},
        {"cut-pass", D2K_QAD_CUT, D2K_QAD_PASS, 1, "flaky", 2},
        {"cut-not-run", D2K_QAD_CUT, D2K_QAD_NOT_RUN, 1, "inconclusive", 2},
        {"cut-no-handshake", D2K_QAD_CUT, D2K_QAD_NO_HANDSHAKE, 1, "inconclusive", 2},
        {"no-handshake", D2K_QAD_NO_HANDSHAKE, D2K_QAD_NOT_RUN, 0, "inconclusive", 1},
        {"cut-cut", D2K_QAD_CUT, D2K_QAD_CUT, 1, "cut-confirmed", 2},
    };
    uint8_t initial[2048];
    size_t initial_len = 0;
    if (d2k_quic_probe_initial("blocked.example", initial, sizeof initial,
                               &initial_len) != 0) return 1;
    const uint8_t control_byte[] = {0x02};
    d2k_hello trigger = {.bytes = initial, .len = initial_len};
    d2k_hello control = {.bytes = control_byte, .len = sizeof control_byte};
    d2k_quic_ask_control_hook = mock_control;
    d2k_quic_ask_hook = mock_trigger;
    d2k_quic_arm_data_hook = mock_direct_data;
    d2k_quic_resolve_hook = no_extra_addresses;
    d2k_quic_allow_local = 1;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        control_pass = control_sent = D2K_QUIC_REPEATS;
        trigger_pass = trigger_sent = D2K_QUIC_REPEATS;
        trigger_err = residual_control_err = 0;
        residual_control_pass = D2K_QUIC_REPEATS;
        direct_data_verdicts[0] = cases[i].first;
        direct_data_verdicts[1] = cases[i].second;
        direct_data_verdict_count = cases[i].has_second ? 2 : 1;
        control_calls = trigger_calls = direct_data_calls = 0;
        d2k_quic_arm arm = {.data_cut = 2};
        d2k_vres result = d2k_quic_run("203.0.113.7", 443, "blocked.example",
                                       trigger, control, 0, &arm);
        const char *verdict = result.verdict == D2K_V_CLEAR ? "clear" :
                              result.verdict == D2K_V_FLAKY ? "flaky" :
                              result.verdict == D2K_V_OPAQUE ? "cut-confirmed" :
                              result.verdict == D2K_V_INCONCLUSIVE ? "inconclusive" : "other";
        printf("case=%s verdict=%s direct_data_calls=%d probes=%d data_cut_seen=%d\n",
               cases[i].name, verdict, direct_data_calls, result.probes,
               arm.data_cut_seen);
        if (strcmp(verdict, cases[i].expected) != 0 ||
            direct_data_calls != cases[i].expected_calls ||
            result.probes != 2 * D2K_QUIC_REPEATS + cases[i].expected_calls ||
            arm.data_cut_seen != (strcmp(cases[i].name, "cut-cut") == 0)) return 1;
    }
    return 0;
}

static int print_direct_action_results(void) {
    static const struct {
        int pass;
        int err;
    } cases[] = {{0, 0}, {1, 0}, {2, 0}, {3, 0}, {0, 1}};
    static const char *const expected[] = {
        "candidates", "stop", "stop", "data", "stop",
    };
    uint8_t initial[2048];
    size_t initial_len = 0;
    if (d2k_quic_probe_initial("blocked.example", initial, sizeof initial,
                               &initial_len) != 0) return 1;
    const uint8_t control_byte[] = {0x02};
    d2k_hello trigger = {.bytes = initial, .len = initial_len};
    d2k_hello control = {.bytes = control_byte, .len = sizeof control_byte};
    d2k_quic_ask_control_hook = mock_control;
    d2k_quic_ask_hook = mock_trigger;
    d2k_quic_ask_arm_hook = mock_direct_arm;
    d2k_quic_arm_data_hook = mock_direct_data;
    d2k_quic_resolve_hook = no_extra_addresses;
    d2k_quic_allow_local = 1;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        control_pass = D2K_QUIC_REPEATS;
        control_sent = D2K_QUIC_REPEATS;
        residual_control_pass = D2K_QUIC_REPEATS;
        residual_control_err = 0;
        trigger_pass = cases[i].pass;
        trigger_err = cases[i].err;
        trigger_sent = D2K_QUIC_REPEATS;
        control_calls = trigger_calls = direct_arm_calls = direct_data_calls = 0;
        d2k_quic_arm arm = {.data_cut = 1};
        (void)d2k_quic_run("203.0.113.7", 443, "blocked.example",
                           trigger, control, 0x2d, &arm);
        const char *next = direct_data_calls ? "data" :
                           direct_arm_calls ? "candidates" : "stop";
        printf("pass=%d err=%d next=%s\n", cases[i].pass, cases[i].err, next);
        if (strcmp(next, expected[i]) != 0) return 1;
    }
    return 0;
}

static int print_residual_action_results(void) {
    static const struct {
        int same_pass;
        int same_err;
        int alternate;
        const char *expected;
    } cases[] = {
        {3, 0, 0, "pinned"},
        {0, 0, 0, "unasked"},
        {0, 0, 1, "fresh"},
        {0, 1, 1, "stop"},
    };
    uint8_t initial[2048];
    size_t initial_len = 0;
    if (d2k_quic_probe_initial("blocked.example", initial, sizeof initial,
                               &initial_len) != 0) return 1;
    const uint8_t control_byte[] = {0x02};
    d2k_hello trigger = {.bytes = initial, .len = initial_len};
    d2k_hello control = {.bytes = control_byte, .len = sizeof control_byte};
    d2k_quic_ask_control_hook = mock_control;
    d2k_quic_ask_hook = mock_trigger;
    d2k_quic_ask_arm_hook = mock_direct_arm;
    d2k_quic_arm_data_hook = mock_direct_data;
    d2k_quic_resolve_hook = optional_alternate_address;
    d2k_quic_allow_local = 1;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        control_pass = D2K_QUIC_REPEATS;
        control_sent = D2K_QUIC_REPEATS;
        residual_control_pass = cases[i].same_pass;
        residual_control_err = cases[i].same_err;
        trigger_pass = 0;
        trigger_err = 0;
        trigger_sent = D2K_QUIC_REPEATS;
        alternate_address_available = cases[i].alternate;
        control_calls = trigger_calls = direct_arm_calls = direct_data_calls = 0;
        memset(direct_arm_address, 0, sizeof direct_arm_address);
        d2k_quic_arm arm = {.data_cut = 1};
        (void)d2k_quic_run("203.0.113.7", 443, "blocked.example",
                           trigger, control, 0x2d, &arm);
        const char *next = cases[i].same_err ? "stop" :
                           direct_arm_calls == 0 ? "unasked" :
                           strcmp(direct_arm_address, "203.0.113.7") == 0 ? "pinned" : "fresh";
        printf("same_pass=%d err=%d next=%s\n",
               cases[i].same_pass, cases[i].same_err, next);
        if (strcmp(next, cases[i].expected) != 0) return 1;
    }
    return 0;
}

static int run_case(const char *name, int ctl_pass, int ctl_sent,
                    int trig_pass, int trig_err, int trig_sent) {
    static const uint8_t trigger_bytes[] = {0x01};
    static const uint8_t control_bytes[] = {0x02};
    d2k_hello trigger = {.bytes = trigger_bytes, .len = sizeof trigger_bytes};
    d2k_hello control = {.bytes = control_bytes, .len = sizeof control_bytes};
    control_pass = ctl_pass;
    control_sent = ctl_sent;
    trigger_pass = trig_pass;
    trigger_err = trig_err;
    trigger_sent = trig_sent;
    control_calls = trigger_calls = 0;

    d2k_vres result = d2k_quic_base("10.0.0.1", 443, "10.0.0.1",
                                   trigger, control, 0);
    printf("case=%s\nclear=%d\nbase_blocked=%d\nprobes=%d\n"
           "control_calls=%d\ntrigger_calls=%d\nreason=%s\n",
           name, result.verdict == D2K_V_CLEAR, result.base_blocked,
           result.probes, control_calls, trigger_calls, result.reason);
    return result.probes != ctl_sent + (trigger_calls ? trig_sent : 0) ||
           control_calls != 1 || trigger_calls != (ctl_pass ? 1 : 0);
}

static int print_normalized_profile(void) {
    uint8_t initial[1200];
    uint8_t client_hello[1200];
    size_t initial_len = 0;
    size_t client_hello_len = 0;
    if (d2k_quic_probe_initial("disk.rzd.ru", initial, sizeof initial,
                               &initial_len) != 0 ||
        d2k_quic_client_hello(initial, initial_len, client_hello,
                              sizeof client_hello, &client_hello_len) != 0 ||
        client_hello_len < 271) {
        return 1;
    }
    memset(client_hello + 6, 0, 32);
    memset(client_hello + 138, 0, 8);
    memset(client_hello + 239, 0, 32);
    for (size_t i = 0; i < client_hello_len; i++) {
        printf("%02x", client_hello[i]);
    }
    putchar('\n');
    return 0;
}

static int print_donor_verifier_results(void) {
    uint8_t client[2048];
    FILE *file = fopen("crates/r2k-core/tests/fixtures/quic_v1_initial.bin", "rb");
    if (!file) return 1;
    size_t client_len = fread(client, 1, sizeof client, file);
    int read_error = ferror(file);
    fclose(file);
    if (read_error || client_len == 0 || client_len == sizeof client) return 1;

    const uint8_t vn[] = {0x80, 0, 0, 0, 0, 0, 0};
    const uint8_t retry_v1[] = {0xf0, 0, 0, 0, 1, 0, 0};
    const uint8_t foreign_version[] = {0xc0, 0, 0, 0, 2, 0, 0};
    const uint8_t short_header[] = {0x40, 0, 0, 0, 1, 0, 0};
    const struct {
        const char *name;
        const uint8_t *packet;
        size_t length;
    } cases[] = {
        {"vn", vn, sizeof vn},
        {"retry_v1", retry_v1, sizeof retry_v1},
        {"foreign", foreign_version, sizeof foreign_version},
        {"short", short_header, sizeof short_header},
    };
    d2k_hello hello = {.bytes = client, .len = client_len};
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        printf("%s=%d\n", cases[i].name,
               d2k_quic_verify_response(cases[i].packet, cases[i].length, hello) == 0);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "decision") == 0) {
        return print_direct_action_results();
    }
    if (argc == 2 && strcmp(argv[1], "data") == 0) {
        return print_direct_data_results();
    }
    if (argc == 2 && strcmp(argv[1], "residual") == 0) {
        return print_residual_action_results();
    }
    if (argc == 2 && strcmp(argv[1], "parallel") == 0) {
        return print_parallel_control_results();
    }
    if (argc == 2 && strcmp(argv[1], "vn") == 0) {
        return print_version_negotiation_results();
    }
    if (argc == 2 && strcmp(argv[1], "profile") == 0) {
        return print_normalized_profile();
    }
    if (argc == 2 && strcmp(argv[1], "verify") == 0) {
        return print_donor_verifier_results();
    }
    d2k_quic_allow_local = 1;
    d2k_quic_ask_control_hook = mock_control;
    d2k_quic_ask_hook = mock_trigger;
    int failed = 0;
    failed |= run_case("blocked", 3, 3, 0, 0, 3);
    failed |= run_case("clear", 1, 3, 3, 0, 3);
    failed |= run_case("control-silent", 0, 3, 3, 0, 3);
    failed |= run_case("target-error", 3, 3, 0, 1, 3);
    return failed;
}
