/* Run the donor's own deterministic scheduler helpers against a narrow
 * A -> B Discord voice lifecycle, without modifying the donor checkout. */
#define main d2o_test_sched_unused_main
#include "test_sched.c"
#undef main

static void trace_check(int ok, const char *message) {
    if (!ok) {
        fprintf(stderr, "voice lifecycle C fixture: %s\n", message);
        exit(1);
    }
}

static int parse_last_probe(uint16_t *server_port, uint8_t trial[D2K_TRIAL_ID_LEN]) {
    int found = 0;
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *frame = sentbuf + off;
        uint32_t n = ((uint32_t)frame[0] << 24) | ((uint32_t)frame[1] << 16) |
                     ((uint32_t)frame[2] << 8) | frame[3];
        if (n < 2 || n > sent_len - off - 4) { break; }
        uint16_t type = (uint16_t)(((uint16_t)frame[4] << 8) | frame[5]);
        if (type == D2K_CMD_SET_ADDR_PROBE && n >= 2 + 38 + D2K_TRIAL_ID_LEN + 4) {
            memcpy(server_port, frame + 6 + 35, 2);
            memcpy(trial, frame + 6 + 38, D2K_TRIAL_ID_LEN);
            found = 1;
        }
        off += 4 + n;
    }
    return found;
}

int main(void) {
    int sv[2];
    trace_check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
    drain_fd = sv[1];
    int flags = fcntl(drain_fd, F_GETFL, 0);
    trace_check(flags >= 0 && fcntl(drain_fd, F_SETFL, flags | O_NONBLOCK) == 0,
                "nonblocking drain setup failed");

    d2k_sched_mark_hook = stub_mark;
    d2k_sched_spawn_hook = stub_spawn;
    d2k_sched_cpu_hook = stub_cpu;
    d2k_sched_mem_hook = stub_mem;
    d2k_sched_ct_hook = stub_ct;
    d2k_sched_voice_hook = stub_voice;
    voice_discovery_fixture = 1;
    d2k_sched *sched;
    d2k_catalog cat = {0};
    d2k_sched_voice_fn saved_voice = d2k_sched_voice_hook;

    g_server_port = 50004;
    sched = d2k_sched_new(&cat, sv[0], 0x2d);
    trace_check(sched != NULL, "scheduler creation failed");
    d2k_sched_set_say(sched, collect_say, NULL);
    d2k_ev hello = ev_hello(17, 52040, D2K_LINK_VOICE_CLASS);
    d2k_sched_event(sched, &hello);
    d2k_ev suspect = ev_suspect(17, 52040);
    d2k_sched_event(sched, &suspect);
    spin(sched, 20);
    uint16_t port_be = 0;
    uint8_t trial_a[D2K_TRIAL_ID_LEN];
    trace_check(parse_last_probe(&port_be, trial_a) && ntohs(port_be) == 50004,
                "A trial was not installed at endpoint A");
    printf("install A without waiting for success ACK\n");

    forget_sent();
    skip_ahead(sched, 61 * 1000);
    uint8_t renewed_a[D2K_TRIAL_ID_LEN];
    trace_check(parse_last_probe(&port_be, renewed_a) && ntohs(port_be) == 50004 &&
                memcmp(trial_a, renewed_a, sizeof trial_a) == 0,
                "A lease renewal changed endpoint or trial ID");
    printf("renew A same-trial\n");

    g_server_port = 50008;
    hello = ev_hello(17, 52041, D2K_LINK_VOICE_CLASS);
    d2k_sched_event(sched, &hello);
    suspect = ev_suspect(17, 52041);
    d2k_sched_event(sched, &suspect);
    spin(sched, 400);
    hello = ev_hello(17, 52042, D2K_LINK_VOICE_CLASS);
    d2k_sched_event(sched, &hello);
    suspect = ev_suspect(17, 52042);
    d2k_sched_event(sched, &suspect);
    spin(sched, 20);
    trace_check(voice_calls == 1 && sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0) == 0,
                "B was not coalesced behind the active A trial");
    printf("queue B latest\n");

    forget_sent();
    skip_ahead(sched, 2 * 60 * 1000 + 1);
    spin(sched, 20);
    uint8_t trial_b[D2K_TRIAL_ID_LEN];
    int have_b = parse_last_probe(&port_be, trial_b);
    if (voice_calls != 2 || sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0) != 1 ||
        !have_b || ntohs(port_be) != 50008 ||
        (have_b && memcmp(trial_a, trial_b, sizeof trial_a) == 0)) {
        fprintf(stderr, "voice lifecycle C fixture: B transition voice_calls=%d del=%zu have=%d port=%u\n",
                voice_calls, sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0),
                have_b, ntohs(port_be));
        trace_check(0, "queued B did not replace expired A with a fresh trial");
    }
    printf("expire A; install B fresh-trial\n");

    d2k_ev applied = ev_applied(17, 52043);
    d2k_sched_event(sched, &applied);
    d2k_ev exchange = ev_exchange(17, 52043, 0);
    exchange.code = D2K_UDP_PROOF_VOICE_DISCOVERY;
    d2k_sched_event(sched, &exchange);
    spin(sched, 20);
    const d2k_cat_binding *binding = binding_of(&cat, "127.0.0.1", 17);
    trace_check(binding != NULL && strcmp(binding->kind, "addr") == 0 &&
                binding->verified_by == D2K_VERBY_VOICE_DISCOVERY &&
                sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 1,
                "matching APPLIED plus Discovery proof did not persist B");
    printf("applied B; discovery proof; persist B\n");

    d2k_sched_free(sched);
    sched = d2k_sched_new(&cat, sv[0], 0x2d);
    trace_check(sched != NULL, "scheduler restart failed");
    forget_sent();
    trace_check(d2k_sched_sync(sched) >= 0, "catalog sync failed");
    sync_out(sched);
    trace_check(sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 1,
                "persisted B was not reapplied after scheduler restart");
    printf("restart reapplies B\n");

    d2k_sched_free(sched);
    d2k_catalog_free(&cat);
    d2k_sched_voice_hook = saved_voice;
    close(sv[0]);
    close(sv[1]);
    return 0;
}
