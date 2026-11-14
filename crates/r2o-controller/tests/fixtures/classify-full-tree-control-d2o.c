#define _POSIX_C_SOURCE 200809L
#include <sys/socket.h>
#include <time.h>

#define main donor_test_repeats_main
#include "test_repeats.c"
#undef main

#define main d2o_cli_main
#include "main.c"
#undef main

static int accepted_connections;
static int close_after_connections = 6;
static int force_connect_deadline;
static int force_first_connect_error;
static int respond_serverhello;
static int slow_reply_ms;
static const char *response_probe_scenario;
static int response_probe_case;
static int response_target_attempts;
static int response_control_attempts;
static int connect_count;
static int poll_timeout_count;
static int poll_timeouts[16];
static int capture_progress_events;
extern int __real_accept(int, struct sockaddr *, socklen_t *);
extern int __real_connect(int, const struct sockaddr *, socklen_t);
extern int __real_poll(struct pollfd *, nfds_t, int);
extern ssize_t __real_recv(int, void *, size_t, int);
extern ssize_t __real_send(int, const void *, size_t, int);
extern int __real_close(int);

/* Дерево зондов на петле: модель разреза и сценарные ответы. */
#define TREE_MODEL_NONE 0
#define TREE_MODEL_PREFIX 1
#define TREE_MODEL_WHOLE 2
static int tree_model;
static int tree_boundary;
static int tree_reassembles;
static const char *tree_target_pat;
static int tree_send_fail_call = -1;
static int tree_send_calls;
static int tree_recv_calls;
static int tree_repeats;
/* Флаг принадлежит потоку: сервер шлёт ответ из своего потока, клиент
 * пишет зонд из основного. Общий флаг глушил бы учёт сегментов. */
static __thread int tree_suppress_send;
static int tree_payload_len;
/* Первый send после connect — это зонд целиком или его первый сегмент.
 * Массив индексируется fd и сбрасывается в __wrap_connect. */
static unsigned char tree_send_pending[1024];

static struct {
    int fd;
    int active;
    int control;
    int response_probe;
    int response_target;
    int trigger;
    int call_index;
    int first_len;
} server_clients[32];

static char tree_pat_char(const char *pat, int index)
{
    size_t length;
    if (!pat || !pat[0]) return '-';
    length = strlen(pat);
    return pat[(size_t)index < length ? (size_t)index : length - 1];
}

static int contains_bytes(const void *buffer, size_t length, const char *needle)
{
    const unsigned char *bytes = buffer;
    size_t needle_len = strlen(needle), i;

    if (needle_len > length) return 0;
    for (i = 0; i <= length - needle_len; i++) {
        if (memcmp(bytes + i, needle, needle_len) == 0) return 1;
    }
    return 0;
}

static int response_completes(int target, int attempt)
{
    if (!response_probe_scenario) return 0;
    if (strcmp(response_probe_scenario, "clear") == 0) return 1;
    if (strcmp(response_probe_scenario, "blocked") == 0) return !target;
    if (strcmp(response_probe_scenario, "flaky") == 0) return !target || attempt == 0;
    if (strcmp(response_probe_scenario, "not-applicable") == 0) return target;
    return 0;
}

static void print_progress_event(void *ctx, const d2k_obs *observation)
{
    (void)ctx;
    printf("PROGRESS|%s|%d|%d\n", observation->probe, observation->pass, observation->fail);
}

static int accept_composed_only(const d2k_poison *poison, void *ctx)
{
    (void)ctx;
    return strncmp(poison->name, "СОБРАНО: ", strlen("СОБРАНО: ")) == 0;
}

static const script_ent S_COMPOSE_JSON[] = {
    {"badsum+hello", "+"}, {"СОБРАНО: всё сразу", "+"}, {NULL, NULL}};
static const scenario SC_COMPOSE_JSON = {
    "compose-json", S_COMPOSE_JSON, "-", "+", "+", 0, "+", 0, 0,
};

static void run_serverhello_scenario(const scenario *scenario, d2k_result *result)
{
    d2k_opts options = {0};
    d2k_trigger trigger = {0};

    options.allow_loopback = 1;
    options.repeats = 3;
    options.timeout_ms = 400;
    options.write_gap_ms = 2;
    options.long_gap_ms = 10;
    options.control_vouched = scenario->vouched;
    options.accept = g_accept;
    memcpy(options.control.name, "control", sizeof("control"));
    memcpy(options.control.payload, CTL, sizeof(CTL) - 1);
    options.control.len = sizeof(CTL) - 1;
    options.control.accept = D2K_ACCEPT_ANY;

    trigger.client_tcp_known = scenario->no_ts;
    snprintf(trigger.name, sizeof(trigger.name), "%s",
             response_probe_case ? "tls:youtube.com" : "test");
    memcpy(trigger.payload, PAY, sizeof(PAY) - 1);
    trigger.len = sizeof(PAY) - 1;
    trigger.accept = D2K_ACCEPT_SERVERHELLO;

    g_script = scenario->script;
    g_default = scenario->dflt ? scenario->dflt : "-";
    g_selftest = scenario->selftest ? scenario->selftest : "+";
    g_ctl_pat = scenario->ctl ? scenario->ctl : "+";
    g_ctl_calls = 0;
    g_ack_pat = scenario->ack ? scenario->ack : "+";
    g_ack_calls = 0;
    g_res = result;
    g_ask = -1;
    g_hs_calls = 0;
    g_poison_calls = 0;
    d2k_classify_run(g_addr, &trigger, &options, result);
}

int __wrap_accept(int fd, struct sockaddr *address, socklen_t *length)
{
    if (close_after_connections > 0 && accepted_connections >= close_after_connections) {
        return -1;
    }
    int client = __real_accept(fd, address, length);
    if (client >= 0) {
        int i;
        accepted_connections++;
        for (i = 0; i < (int)(sizeof(server_clients) / sizeof(server_clients[0])); i++) {
            if (!server_clients[i].active) {
                server_clients[i].fd = client;
                server_clients[i].active = 1;
                server_clients[i].control = 0;
                server_clients[i].response_probe = 0;
                server_clients[i].response_target = 0;
                server_clients[i].trigger = 0;
                server_clients[i].call_index = -1;
                server_clients[i].first_len = 0;
                break;
            }
        }
        if (close_after_connections > 0 && accepted_connections == close_after_connections) {
            close(fd);
            g_srv_fd = -1;
        }
    }
    return client;
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    if (force_first_connect_error && connect_count++ == 0) {
        errno = ECONNREFUSED;
        return -1;
    }
    if (force_connect_deadline) {
        (void)fd;
        (void)address;
        (void)length;
        errno = EINPROGRESS;
        return -1;
    }
    int rc = __real_connect(fd, address, length);
    if ((rc == 0 || errno == EINPROGRESS) && fd >= 0 &&
        fd < (int)(sizeof(tree_send_pending))) {
        tree_send_pending[fd] = 1;
    }
    return rc;
}

int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    if (force_connect_deadline) {
        (void)fds;
        (void)count;
        if (poll_timeout_count < (int)(sizeof(poll_timeouts) / sizeof(poll_timeouts[0]))) {
            poll_timeouts[poll_timeout_count] = timeout;
        }
        poll_timeout_count++;
        return 0;
    }
    int tree_rc = __real_poll(fds, count, timeout);
    return tree_rc;
}

ssize_t __wrap_send(int fd, const void *buffer, size_t length, int flags)
{
    if (!tree_suppress_send && length > 0 && fd >= 0 &&
        fd < (int)(sizeof(tree_send_pending)) && tree_send_pending[fd]) {
        int control = length == sizeof(CTL) - 1 &&
                      memcmp(buffer, CTL, sizeof(CTL) - 1) == 0;
        int response = length >= 2 && ((const uint8_t *)buffer)[0] == 0x16 &&
                       ((const uint8_t *)buffer)[1] == 0x03;
        tree_send_pending[fd] = 0;
        if (!control && !response) {
            int call = tree_send_calls++;
            if (tree_send_fail_call == call) {
                errno = EPIPE;
                return -1;
            }
        }
    }
    return __real_send(fd, buffer, length, flags);
}

ssize_t __wrap_recv(int fd, void *buffer, size_t length, int flags)
{
    ssize_t received = __real_recv(fd, buffer, length, flags);
    int i;
    for (i = 0; received > 0 &&
                i < (int)(sizeof(server_clients) / sizeof(server_clients[0])); i++) {
        if (server_clients[i].active && server_clients[i].fd == fd) {
            if (received >= 2 && ((const uint8_t *)buffer)[0] == 0x16 &&
                ((const uint8_t *)buffer)[1] == 0x03) {
                server_clients[i].response_probe = 1;
                server_clients[i].response_target =
                    contains_bytes(buffer, (size_t)received, "youtube.com");
            }
            if (received == (ssize_t)(sizeof(CTL) - 1) &&
                memcmp(buffer, CTL, sizeof(CTL) - 1) == 0) {
                server_clients[i].control = 1;
            } else if (!server_clients[i].trigger &&
                       !server_clients[i].response_probe) {
                server_clients[i].trigger = 1;
                server_clients[i].call_index = tree_recv_calls++;
                server_clients[i].first_len = (int)received;
            }
            break;
        }
    }
    return received;
}
int __wrap_close(int fd)
{
    static const uint8_t alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
    static const uint8_t serverhello[] = {0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00};
    static const uint8_t server_hello_done[] = {
        0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00
    };
    int i;
    for (i = 0; i < (int)(sizeof(server_clients) / sizeof(server_clients[0])); i++) {
        if (server_clients[i].active && server_clients[i].fd == fd) {
            int tree_pass = -1;
            if (server_clients[i].trigger && !server_clients[i].control &&
                !server_clients[i].response_probe) {
                if (tree_target_pat) {
                    tree_pass = tree_pat_char(tree_target_pat,
                                              server_clients[i].call_index) == 'A';
                } else if (tree_model != TREE_MODEL_NONE) {
                    int partial = server_clients[i].first_len > 0 &&
                                  server_clients[i].first_len < tree_payload_len;
                    if (tree_model == TREE_MODEL_PREFIX) {
                        tree_pass = partial &&
                                    server_clients[i].first_len < tree_boundary;
                    } else {
                        tree_pass = partial;
                    }
                    /* Разрез с длинной паузой идёт сразу после короткого:
                     * повторяет повторы базы и разреза. */
                    if (tree_pass && tree_reassembles &&
                        server_clients[i].call_index >= 2 * tree_repeats &&
                        server_clients[i].call_index < 3 * tree_repeats) {
                        tree_pass = 0;
                    }
                }
            }
            if (tree_pass >= 0) {
                const uint8_t *reply = tree_pass ? serverhello : alert;
                size_t reply_len = tree_pass ? sizeof(serverhello) : sizeof(alert);
                server_clients[i].active = 0;
                tree_suppress_send = 1;
                (void)__real_send(fd, reply, reply_len, MSG_NOSIGNAL);
                tree_suppress_send = 0;
                return __real_close(fd);
            }
            server_clients[i].active = 0;
            tree_suppress_send = 1;
            if (server_clients[i].response_probe) {
                int attempt = server_clients[i].response_target
                    ? response_target_attempts++ : response_control_attempts++;
                int complete = response_completes(server_clients[i].response_target, attempt);
                const uint8_t *reply = complete ? server_hello_done : alert;
                size_t reply_len = complete ? sizeof(server_hello_done) : sizeof(alert);
                (void)send(fd, reply, reply_len, MSG_NOSIGNAL);
            } else if (!server_clients[i].control) {
                const uint8_t *reply = respond_serverhello ? serverhello : alert;
                size_t reply_len = respond_serverhello ? sizeof(serverhello) : sizeof(alert);
                if (slow_reply_ms > 0) {
                    struct timespec delay = {
                        .tv_sec = slow_reply_ms / 1000,
                        .tv_nsec = (long)(slow_reply_ms % 1000) * 1000000L,
                    };
                    (void)nanosleep(&delay, NULL);
                }
                (void)send(fd, reply, reply_len, MSG_NOSIGNAL);
            }
            tree_suppress_send = 0;
            break;
        }
    }
    return __real_close(fd);
}
static const char *tree_tri(d2k_tri value)
{
    if (value == D2K_TRI_TRUE) return "1";
    if (value == D2K_TRI_FALSE) return "0";
    return "u";
}

static void tree_print_result(const char *name, const d2k_result *result, int include_trace)
{
    int i;
    printf("CASE|%s|%s|%d|%d|%s|%s|%d|%d|%s|%s",
           name, d2k_verdict_name(result->verdict), result->boundary,
           result->split_pos, tree_tri(result->reassembles),
           result->path[0] ? result->path : "-",
           result->composed, result->raw_usable, result->strategy,
           result->has_hit ? result->hit.name : "-");
    if (include_trace) printf("|%d", result->probes);
    printf("\n");
    printf("REASON|%s|%s\n", name, result->reason);
    for (i = 0; i < result->nnotes; i++) {
        printf("NOTE|%s|%s\n", name, result->notes[i]);
    }
    if (result->has_response) {
        printf("RESP|%s|%s|%d|%d|%s\n", name,
               d2k_resp_name(result->response.verdict),
               result->response.target, result->response.control,
               result->response.reason);
    }
    if (!include_trace) return;
    for (i = 0; i < result->ntrace; i++) {
        const d2k_obs *observation = &result->trace[i];
        char cuts[64];
        int j, used = 0;
        if (observation->ncuts == 0) {
            snprintf(cuts, sizeof cuts, "-");
        } else {
            used += snprintf(cuts + used, sizeof cuts - (size_t)used, "[");
            for (j = 0; j < observation->ncuts && used < (int)sizeof cuts; j++) {
                used += snprintf(cuts + used, sizeof cuts - (size_t)used, "%s%d",
                                 j ? " " : "", observation->cuts[j]);
            }
            snprintf(cuts + used, sizeof cuts - (size_t)used, "]");
        }
        printf("TRACE|%s|%s|%s|%d|%d|%d|%s\n", name, observation->probe, cuts,
               observation->delay_ms, observation->pass, observation->fail,
               observation->err);
    }
}

static void tree_run(const char *name, const char *target_pat, int model,
                     int boundary, int reassembles, int fail_call, int repeats,
                     int no_raw, const char *control_pat, const char *ack_pat,
                     int with_control, int vouched, int tls12, int gap_ms,
                     int long_ms, int include_trace, const script_ent *script,
                     const char *dflt, const char *selftest,
                     const char *trigger_name)
{
    d2k_opts options = {0};
    d2k_trigger trigger = {0};
    d2k_result result;

    options.allow_loopback = 1;
    options.repeats = repeats;
    options.timeout_ms = 400;
    options.write_gap_ms = gap_ms;
    options.long_gap_ms = long_ms;
    options.no_raw = no_raw;
    options.control_vouched = vouched;
    options.cross_check_tls12 = tls12;
    if (with_control) {
        snprintf(options.control.name, sizeof options.control.name, "control");
        memcpy(options.control.payload, CTL, sizeof(CTL) - 1);
        options.control.len = sizeof(CTL) - 1;
        options.control.accept = D2K_ACCEPT_ANY;
    }
    snprintf(trigger.name, sizeof trigger.name, "%s", trigger_name);
    memcpy(trigger.payload, PAY, sizeof(PAY) - 1);
    trigger.len = sizeof(PAY) - 1;
    trigger.accept = D2K_ACCEPT_SERVERHELLO;

    close_after_connections = 0;
    force_connect_deadline = 0;
    force_first_connect_error = 0;
    respond_serverhello = 0;
    slow_reply_ms = 0;
    response_probe_case = 0;
    response_probe_scenario = NULL;
    capture_progress_events = 0;
    accepted_connections = 0;
    memset(server_clients, 0, sizeof server_clients);
    g_script = script;
    g_default = dflt ? dflt : "-";
    g_selftest = selftest ? selftest : "+";
    g_ctl_pat = control_pat ? control_pat : "+";
    g_ctl_calls = 0;
    g_ack_pat = ack_pat ? ack_pat : "e";
    g_ack_calls = 0;
    g_res = &result;
    g_ask = -1;
    g_hs_calls = 0;
    g_poison_calls = 0;
    g_split_success = 0;
    g_split_calls = 0;
    g_split_gaps = 0;
    g_split_connect_failures = 0;
    g_split_response_failures = 0;
    tree_model = model;
    tree_boundary = boundary;
    tree_reassembles = reassembles;
    tree_target_pat = target_pat;
    tree_send_fail_call = fail_call;
    tree_send_calls = 0;
    tree_recv_calls = 0;
    tree_repeats = repeats;
    tree_suppress_send = 0;
    tree_payload_len = (int)(sizeof(PAY) - 1);
    memset(tree_send_pending, 0, sizeof tree_send_pending);

    d2k_classify_run(g_addr, &trigger, &options, &result);
    tree_print_result(name, &result, include_trace);
}

static void run_tree_differential(void)
{
    static const script_ent S_PROP_HIT[] = {{"badsum+hello", "+"}, {NULL, NULL}};

    srv_start();

    tree_run("no-sni-clear", "AAA", TREE_MODEL_NONE, 0, 0, -1, 3, 1,
             "+", "e", 0, 0, 0, 2, 10, 1, NULL, "-", "+", "");
    tree_run("whole-packet", NULL, TREE_MODEL_WHOLE, 0, 0, -1, 3, 1,
             "+", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("prefix", NULL, TREE_MODEL_PREFIX, 10, 0, -1, 3, 1,
             "+", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("prefix-reassemble", NULL, TREE_MODEL_PREFIX, 5, 1, -1, 3, 1,
             "+", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("prefix-gaps", NULL, TREE_MODEL_PREFIX, 10, 0, -1, 3, 1,
             "+", "e", 1, 0, 0, 7, 13, 1, NULL, "-", "+", "test");
    tree_run("prefix-cross-tls12", NULL, TREE_MODEL_PREFIX, 10, 0, -1, 3, 1,
             "+", "e", 1, 0, 1, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("prefix-r1", NULL, TREE_MODEL_PREFIX, 10, 0, -1, 1, 1,
             "+", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("prefix-r2", NULL, TREE_MODEL_PREFIX, 10, 0, -1, 2, 1,
             "+", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("partial-base", "ARA", TREE_MODEL_NONE, 0, 0, -1, 3, 1,
             "+", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("partial-split", "RRRARA", TREE_MODEL_NONE, 0, 0, -1, 3, 1,
             "+", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("split-error", "RRR", TREE_MODEL_NONE, 0, 0, 3, 3, 1,
             "+", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("long-error", "RRRAAA", TREE_MODEL_NONE, 0, 0, 6, 3, 1,
             "+", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("last-error", "RRRAAAAAA", TREE_MODEL_NONE, 0, 0, 9, 3, 1,
             "+", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("mid-partial", "RRRAAAAAARRRARA", TREE_MODEL_NONE, 0, 0, -1, 3, 1,
             "+", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("no-control", "RRRRRR", TREE_MODEL_NONE, 0, 0, -1, 3, 1,
             "-", "e", 0, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("control-dead", "RRRRRR", TREE_MODEL_NONE, 0, 0, -1, 3, 1,
             "-", "---", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("control-dead-vouched", "RRRRRR", TREE_MODEL_NONE, 0, 0, -1, 3, 1,
             "-", "---", 1, 1, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("ack-late", "RRRRRR", TREE_MODEL_NONE, 0, 0, -1, 3, 1,
             "-", "-+", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("ack-unseen", "RRRRRR", TREE_MODEL_NONE, 0, 0, -1, 3, 1,
             "-", "u", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("ack-error", "RRRRRR", TREE_MODEL_NONE, 0, 0, -1, 3, 1,
             "-", "e", 1, 0, 0, 2, 10, 1, NULL, "-", "+", "test");
    tree_run("raw-selftest-fail", "RRRRRR", TREE_MODEL_NONE, 0, 0, -1, 3, 0,
             "+", "e", 1, 0, 0, 2, 10, 0, NULL, "-", "e", "test");
    tree_run("raw-hit", "RRRRRR", TREE_MODEL_NONE, 0, 0, -1, 3, 0,
             "+", "e", 1, 0, 0, 2, 10, 0, S_PROP_HIT, "-", "+", "test");
    tree_run("raw-miss", "RRRRRR", TREE_MODEL_NONE, 0, 0, -1, 3, 0,
             "+", "e", 1, 0, 0, 2, 10, 0, NULL, "-", "+", "test");
    tree_run("raw-control-dead-hit", "RRRRRR", TREE_MODEL_NONE, 0, 0, -1, 3, 0,
             "-", "+", 1, 0, 0, 2, 10, 0, S_PROP_HIT, "-", "+", "test");
}

static void run_display_differential(void)
{
    d2k_result result;
    d2k_trigger trigger = {0};

    memset(&result, 0, sizeof result);
    snprintf(result.target, sizeof result.target, "example.com:443");
    result.verdict = D2K_DV_PREFIX;
    snprintf(result.reason, sizeof result.reason,
             "причина \"x\" \\ \001 префикс");
    result.repeats = 3;
    result.probes = 9;
    result.duration_ms = 42;
    result.trigger_len = 41;
    result.boundary = 7;
    result.split_pos = 1;
    result.reassembles = D2K_TRI_TRUE;
    snprintf(result.strategy, sizeof result.strategy,
             "--lua-desync=multisplit:payload=unknown:dir=out:pos=1");
    snprintf(result.notes[0], sizeof result.notes[0],
             "оговорка с \"кавычкой\" и \\ обратной");
    snprintf(result.notes[1], sizeof result.notes[1], "вторая оговорка");
    result.nnotes = 2;
    result.covers_tls12 = D2K_TRI_FALSE;
    result.has_response = 1;
    result.response.verdict = D2K_RESP_CLEAR;
    snprintf(result.response.reason, sizeof result.response.reason,
             "ответное направление чисто");
    result.response.target = 3;
    result.response.control = 2;
    result.props.reassembles = D2K_TRI_TRUE;
    result.props.parses_l7 = D2K_TRI_FALSE;
    result.props.validates_checksum = D2K_TRI_TRUE;
    result.props.tolerates_reorder = D2K_TRI_UNSET;
    result.props.hop_ttl = 5;
    snprintf(result.path, sizeof result.path, "перебор");
    result.composed = 1;
    result.raw_usable = 1;
    snprintf(result.trace[0].probe, sizeof result.trace[0].probe, "whole");
    result.trace[0].delay_ms = 60;
    result.trace[0].pass = 3;
    result.trace[0].fail = 0;
    snprintf(result.trace[1].probe, sizeof result.trace[1].probe, "split");
    result.trace[1].cuts[0] = 1;
    result.trace[1].cuts[1] = 2;
    result.trace[1].ncuts = 2;
    result.trace[1].delay_ms = 60;
    result.trace[1].pass = 2;
    result.trace[1].fail = 1;
    snprintf(result.trace[1].err, sizeof result.trace[1].err, "write: ошибка");
    result.ntrace = 2;

    snprintf(trigger.name, sizeof trigger.name, "tls:example.com");
    trigger.len = 41;
    trigger.accept = D2K_ACCEPT_SERVERHELLO;

    print_json(&result);
    print_human(&result, &trigger);
}

int main(int argc, char **argv)
{
    d2k_opts options = {0};
    d2k_trigger trigger = {0};
    d2k_result result;

    if (argc != 2) {
        return 2;
    }
    if (strcmp(argv[1], "tree-diff") == 0) {
        run_tree_differential();
        return 0;
    }
    if (strcmp(argv[1], "display-diff") == 0) {
        run_display_differential();
        return 0;
    }
    if (strcmp(argv[1], "transport-error") == 0) {
        close_after_connections = 6;
        g_ack_pat = "e";
    } else if (strcmp(argv[1], "control-pass") == 0 ||
               strcmp(argv[1], "control-pass-progress") == 0) {
        close_after_connections = 0;
        g_ctl_pat = "-+";
        g_ack_pat = "e";
        capture_progress_events = strcmp(argv[1], "control-pass-progress") == 0;
    } else if (strcmp(argv[1], "control-unproven") == 0) {
        close_after_connections = 0;
        g_ctl_pat = "+";
        g_ack_pat = "---";
    } else if (strcmp(argv[1], "neutral-ack-progress") == 0) {
        close_after_connections = 0;
        g_ctl_pat = "---";
        g_ack_pat = "-+";
        capture_progress_events = 1;
    } else if (strcmp(argv[1], "target-unproven") == 0) {
        close_after_connections = 0;
        g_ctl_pat = "+";
        g_ack_pat = "e";
    } else if (strcmp(argv[1], "baseline-deadline") == 0) {
        close_after_connections = 0;
        force_connect_deadline = 1;
        g_ack_pat = "e";
    } else if (strcmp(argv[1], "baseline-mixed-error") == 0) {
        close_after_connections = 0;
        force_first_connect_error = 1;
        g_ack_pat = "e";
    } else if (strcmp(argv[1], "slow-response") == 0) {
        close_after_connections = 0;
        respond_serverhello = 1;
        slow_reply_ms = 5500;
        g_ack_pat = "e";
    } else if (strcmp(argv[1], "baseline-clear") == 0 ||
               strcmp(argv[1], "baseline-clear-progress") == 0 ||
               strcmp(argv[1], "baseline-clear-json") == 0) {
        close_after_connections = 0;
        respond_serverhello = 1;
        g_ack_pat = "e";
        capture_progress_events = strcmp(argv[1], "baseline-clear-progress") == 0;
    } else if (strncmp(argv[1], "response-", 9) == 0) {
        response_probe_case = 1;
        response_probe_scenario = argv[1] + 9;
        if (strcmp(response_probe_scenario, "clear") != 0 &&
            strcmp(response_probe_scenario, "blocked") != 0 &&
            strcmp(response_probe_scenario, "flaky") != 0 &&
            strcmp(response_probe_scenario, "not-applicable") != 0) {
            return 2;
        }
        close_after_connections = 0;
        respond_serverhello = 1;
        g_ack_pat = "e";
    } else if (strcmp(argv[1], "compose-json") == 0) {
        close_after_connections = 0;
    } else {
        return 2;
    }

    srv_start();
    if (strcmp(argv[1], "compose-json") == 0) {
        g_accept = accept_composed_only;
        run_serverhello_scenario(&SC_COMPOSE_JSON, &result);
        if (result.verdict != D2K_DV_POISONABLE || !result.composed ||
            strcmp(result.path, "собрано") != 0) {
            int i;
            fprintf(stderr, "compose-json: %s path=%s composed=%d reason=%s\n",
                    d2k_verdict_name(result.verdict), result.path, result.composed, result.reason);
            for (i = 0; i < result.ntrace; i++) {
                fprintf(stderr, "  %s %d/%d %s\n", result.trace[i].probe,
                        result.trace[i].pass, result.trace[i].fail, result.trace[i].err);
            }
        }
        print_json(&result);
        return result.verdict == D2K_DV_POISONABLE && result.composed &&
                       strcmp(result.path, "собрано") == 0
                   ? 0
                   : 1;
    }
    if (strcmp(argv[1], "baseline-clear-json") == 0) {
        char raw_hex[(sizeof(PAY) - 1) * 2 + 1];
        char *cli_argv[] = {
            "d2k-detect", "classify", g_addr, "--raw", raw_hex,
            "--allow-loopback", "--no-raw", "--json",
        };
        size_t i;
        for (i = 0; i < sizeof(PAY) - 1; i++) {
            snprintf(raw_hex + i * 2, 3, "%02x", (unsigned char)PAY[i]);
        }
        return d2o_cli_main((int)(sizeof(cli_argv) / sizeof(cli_argv[0])), cli_argv);
    }
    options.allow_loopback = 1;
    options.repeats = strcmp(argv[1], "slow-response") == 0 ? 1 : 3;
    options.timeout_ms = strcmp(argv[1], "slow-response") == 0 ? 7000 : 400;
    options.write_gap_ms = 2;
    options.long_gap_ms = 10;
    options.no_raw = 1;
    if (capture_progress_events) {
        options.on_obs = print_progress_event;
    }
    options.control.accept = strcmp(argv[1], "control-unproven") == 0
        ? D2K_ACCEPT_TLSRECORD : D2K_ACCEPT_ANY;
    memcpy(options.control.name, "control", sizeof("control"));
    memcpy(options.control.payload, CTL, sizeof(CTL) - 1);
    options.control.len = sizeof(CTL) - 1;
    if (response_probe_case) {
        snprintf(trigger.name, sizeof(trigger.name), "tls:youtube.com");
    }
    trigger.accept = D2K_ACCEPT_SERVERHELLO;
    memcpy(trigger.payload, PAY, sizeof(PAY) - 1);
    trigger.len = sizeof(PAY) - 1;

    d2k_classify_run(g_addr, &trigger, &options, &result);
    if (strcmp(argv[1], "slow-response") == 0) {
        const char *verdict = result.verdict == D2K_DV_CLEAR ? "accepted" : "rejected";
        printf("probe_verdict=%s\n", verdict);
        return result.verdict == D2K_DV_CLEAR && result.probes == 1 &&
                       accepted_connections == 1
                   ? 0
                   : 1;
    }
    if (response_probe_case) {
        d2k_verdict_t expected_overall =
            strcmp(response_probe_scenario, "blocked") == 0
                ? D2K_DV_RESPONSE : D2K_DV_CLEAR;
        d2k_resp_verdict expected_response =
            strcmp(response_probe_scenario, "blocked") == 0 ? D2K_RESP_BLOCKED :
            strcmp(response_probe_scenario, "flaky") == 0 ? D2K_RESP_FLAKY :
            strcmp(response_probe_scenario, "not-applicable") == 0
                ? D2K_RESP_NOT_APPLICABLE : D2K_RESP_CLEAR;
        int expected_target =
            strcmp(response_probe_scenario, "blocked") == 0 ? 0 :
            strcmp(response_probe_scenario, "flaky") == 0 ? 1 : 3;
        int expected_control =
            strcmp(response_probe_scenario, "not-applicable") == 0 ? 0 : 3;
        int expected_visible = strcmp(response_probe_scenario, "clear") != 0;
        int visible = result.has_response &&
            strstr(result.reason, result.response.reason) != NULL;

        printf("%s|%d|%s|%d|%d|%d\n",
               d2k_verdict_name(result.verdict), result.probes,
               d2k_resp_name(result.response.verdict),
               result.response.target, result.response.control, visible);
        return result.verdict == expected_overall &&
               result.probes == 9 &&
               result.has_response &&
               result.response.verdict == expected_response &&
               result.response.target == expected_target &&
               result.response.control == expected_control &&
               visible == expected_visible &&
               accepted_connections == 9 &&
               response_target_attempts == 3 &&
               response_control_attempts == 3 ? 0 : 1;
    }
    if (strcmp(argv[1], "baseline-deadline") == 0) {
        int valid = poll_timeout_count == 6;
        int i;
        for (i = 0; i < 6 && i < poll_timeout_count; i++) {
            int expected = i < 3 ? 400 : 800;
            if (poll_timeouts[i] != expected) valid = 0;
        }
        printf("Flaky|%d|0|", result.probes);
        for (i = 0; i < poll_timeout_count && i < 6; i++) {
            printf("%s%d", i == 0 ? "" : ",", poll_timeouts[i]);
        }
        printf("\n");
        return valid && result.verdict == D2K_DV_FLAKY && result.probes == 6 ? 0 : 1;
    }
    if (strcmp(argv[1], "baseline-mixed-error") == 0) {
        printf("Unreachable|%d|0\n", result.probes);
        return result.verdict == D2K_DV_UNREACHABLE && result.probes == 3 &&
               accepted_connections == 2 ? 0 : 1;
    }
    if (strcmp(argv[1], "baseline-clear") == 0 ||
        strcmp(argv[1], "baseline-clear-progress") == 0) {
        int expected_probes = 3;
        printf("Clear|%d|0\n", result.probes);
        return result.verdict == D2K_DV_CLEAR && result.probes == expected_probes &&
               accepted_connections == expected_probes ? 0 : 1;
    }
    if (strcmp(argv[1], "transport-error") == 0) {
        printf("Inconclusive|%d|%d\n", result.probes, g_ack_calls);
        return result.verdict == D2K_DV_INCONCLUSIVE && result.probes == 10 &&
               g_ack_calls == 1 && accepted_connections == 6 ? 0 : 1;
    }
    if (strcmp(argv[1], "control-pass") == 0 ||
        strcmp(argv[1], "control-pass-progress") == 0) {
        printf("Opaque|%d|%d\n", result.probes, g_ack_calls);
        return result.verdict == D2K_DV_OPAQUE && result.probes == 8 &&
               g_ack_calls == 0 && accepted_connections == 8 ? 0 : 1;
    }
    if (strcmp(argv[1], "neutral-ack-progress") == 0) {
        printf("NeutralAck|%d|%d\n", result.probes, g_ack_calls);
        return 0;
    }
    if (strcmp(argv[1], "target-unproven") == 0) {
        printf("Opaque|%d|%d\n", result.probes, g_ack_calls);
        return result.verdict == D2K_DV_OPAQUE && result.probes == 7 &&
               g_ack_calls == 0 && accepted_connections == 7 ? 0 : 1;
    }
    printf("Address|%d|%d\n", result.probes, g_ack_calls);
    return result.verdict == D2K_DV_ADDRESS && result.probes == 12 &&
           g_ack_calls == 3 && accepted_connections == 9 ? 0 : 1;
}
