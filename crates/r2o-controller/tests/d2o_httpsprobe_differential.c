/* CL13: C-оракул HTTPS-зонда и кэша состояний.
 *
 * Использование: d2o-httpsprobe DIR CASES OUTDIR
 */
#define _POSIX_C_SOURCE 200809L
#include "d2k_httpsprobe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static d2k_https_state fake_probe(uint8_t family, const uint8_t *addr,
                                  const char *host, uint32_t mark, char *why,
                                  size_t why_cap) {
    (void)family;
    (void)addr;
    (void)host;
    (void)mark;
    (void)why;
    (void)why_cap;
    return D2K_HTTPS_UNCONFIRMED;
}

static void print_file(const char *name, const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) {
        printf("file %s <open-error>\n", name);
        return;
    }
    char line[2048];
    while (fgets(line, sizeof line, file)) {
        printf("file %s %s", name, line);
    }
    fclose(file);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        return 2;
    }
    const char *dir = argv[1];
    const char *cases_path = argv[2];
    const char *out_dir = argv[3];

    for (int connect = 0; connect <= 3; connect++) {
        for (int server_tls = 0; server_tls <= 1; server_tls++) {
            for (int tls_ok = 0; tls_ok <= 1; tls_ok++) {
                for (int peer_name = -1; peer_name <= 1; peer_name++) {
                    d2k_https_state state = d2k_https_classify(
                        connect, server_tls, tls_ok, peer_name);
                    printf("classify cr=%d st=%d tls=%d pn=%d -> %s\n",
                           connect, server_tls, tls_ok, peer_name,
                           d2k_https_state_name(state));
                }
            }
        }
    }
    for (int state = 0; state <= 7; state++) {
        printf("state %d upgrade=%d ttl=%u name=%s\n", state,
               d2k_https_upgrade((d2k_https_state)state),
               (unsigned)d2k_https_ttl((d2k_https_state)state),
               d2k_https_state_name((d2k_https_state)state));
    }

    FILE *cases = fopen(cases_path, "r");
    if (!cases) {
        return 3;
    }
    char name[256];
    while (fgets(name, sizeof name, cases)) {
        size_t length = strlen(name);
        while (length && (name[length - 1] == '\n' || name[length - 1] == '\r')) {
            name[--length] = '\0';
        }
        if (!length) {
            continue;
        }
        char path[4096];
        char out_path[4096];
        snprintf(path, sizeof path, "%s/%s.txt", dir, name);
        snprintf(out_path, sizeof out_path, "%s/%s.txt", out_dir, name);

        d2k_httpsprobe *probe = d2k_httpsprobe_new(0, fake_probe);
        if (!probe) {
            printf("load %s probe-new-failed\n", name);
            continue;
        }
        d2k_httpsprobe_result push[128];
        size_t n_push = 0, n_loaded = 0;
        char err[512] = "";
        int rc = d2k_httpsprobe_load(probe, path, 1000000, 1700000000, push,
                                     128, &n_push, &n_loaded, err, sizeof err);
        printf("load %s rc=%d loaded=%zu push=%zu\n", name, rc, n_loaded,
               n_push);
        for (size_t i = 0; i < n_push; i++) {
            printf("push %s %s %s %u\n", name, push[i].host,
                   d2k_https_state_name(push[i].state), push[i].ttl_s);
        }
        if (rc == 0) {
            err[0] = '\0';
            int saved = d2k_httpsprobe_save(probe, out_path, 1010000,
                                            1700000010, err, sizeof err);
            printf("save %s rc=%d\n", name, saved);
            print_file(name, out_path);
        }
        d2k_httpsprobe_free(probe);
    }
    fclose(cases);
    return 0;
}
