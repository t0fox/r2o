#include "sched.c"

typedef struct {
    int status;
    int body_complete;
    int body_encoding;
    int body_framing_valid;
    int body_has_length;
    int body_chunked;
    uint64_t body_expected;
    uint64_t body_bytes;
} fixture_observation;

static int read_observations(const char *path, fixture_observation observations[3]) {
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    char line[256];
    size_t count = 0;
    while (fgets(line, sizeof line, file)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (count == 3) {
            fclose(file);
            return -1;
        }
        fixture_observation *observation = &observations[count];
        unsigned long long body_expected = 0, body_bytes = 0;
        if (sscanf(line, "%d %d %d %d %d %d %llu %llu",
                &observation->status, &observation->body_complete,
                &observation->body_encoding, &observation->body_framing_valid,
                &observation->body_has_length, &observation->body_chunked,
                &body_expected, &body_bytes) != 8) {
            fclose(file);
            return -1;
        }
        observation->body_expected = body_expected;
        observation->body_bytes = body_bytes;
        count++;
    }
    fclose(file);
    return count == 3 ? 0 : -1;
}

static void set_ver_result(d2k_ver_result *result, const fixture_observation *input) {
    memset(result, 0, sizeof *result);
    result->fd = -1;
    result->level = input->body_complete ? D2K_VER_APPLICATION : D2K_VER_HANDSHAKE;
    result->http_outcome = D2K_HTTP_NEUTRAL;
    result->status = input->status;
    result->body_complete = input->body_complete;
    result->body_encoding = (uint8_t)input->body_encoding;
    result->body_framing_valid = input->body_framing_valid;
    result->body_has_length = input->body_has_length;
    result->body_chunked = input->body_chunked;
    result->body_expected = input->body_expected;
    result->body_bytes = input->body_bytes;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    fixture_observation observations[3];
    if (read_observations(argv[1], observations) != 0) return 3;

    d2k_sched *sched = calloc(1, sizeof *sched);
    task *candidate = calloc(1, sizeof *candidate);
    if (!sched || !candidate) return 4;
    sched->link_fd = -1;
    candidate->transport = 6;
    candidate->family = 4;
    candidate->own_first = 2;
    candidate->res.verdict = D2K_V_OPAQUE;
    candidate->vol.rx_tls_unavailable = 1;
    candidate->next_plan = 1;
    candidate->probe_fd = -1;
    candidate->prop_bound_fd = -1;
    candidate->prop_fd = -1;
    candidate->ver.fd = -1;
    candidate->ver_seen = 1;
    candidate->ver_flow.family = 4;
    candidate->ver_flow.transport = 6;
    candidate->ver_flow.a_port = 41000;
    candidate->ver_flow.b_port = 443;
    candidate->ver_early[0] = candidate->ver_flow;
    snprintf(candidate->name, sizeof candidate->name, "layered-rx.example");
    uint8_t hello[SCHED_TRIG_MAX];
    size_t hello_len = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, candidate->name, hello,
                               sizeof hello, &hello_len) != 0) return 4;
    memcpy(candidate->trig, hello, hello_len);
    candidate->trig_len = hello_len;

    char encodings[sizeof "identity,identity,gzip"] = {0};
    size_t used = 0;
    for (size_t i = 0; i < 3; i++) {
        candidate->next_plan = 1;
        int phase = candidate->rx_phase;
        int gzip = phase == 2;
        if (observations[i].body_encoding != gzip) return 5;
        int n = snprintf(encodings + used, sizeof encodings - used,
                         "%s%s", i ? "," : "", gzip ? "gzip" : "identity");
        if (n < 0 || (size_t)n >= sizeof encodings - used) return 6;
        used += (size_t)n;
        set_ver_result(&candidate->ver, &observations[i]);
        if (!layered_rx_result(sched, candidate, (int64_t)(500 * (i + 1)))) return 7;
    }
    if (!candidate->vol.rx_cut || candidate->rx_phase != 0 || candidate->state != T_PLANNING)
        return 8;
    printf("encodings=%s;cut=1;handled=1\n", encodings);
    free(candidate);
    free(sched);
    return 0;
}
