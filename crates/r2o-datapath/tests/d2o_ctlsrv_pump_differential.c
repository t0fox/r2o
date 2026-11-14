/* C/Rust differential: d2k_ctlsrv_pump journal→v22 frames (a378). */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "d2k_ctl.h"
#include "d2k_ctlsrv.h"
#include "d2k_journal.h"
#include "d2k_session.h"

static const char *SOCK = "/tmp/d2k-pump-differential.sock";

static int dial(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address;
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, SOCK);
    if (connect(fd, (struct sockaddr *)&address, sizeof address) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(void) {
    unlink(SOCK);
    char error[160];
    d2k_ctl *ctl = d2k_ctl_open(SOCK, error, sizeof error);
    if (!ctl) { fprintf(stderr, "ctl: %s\n", error); return 2; }
    int client = dial();
    if (client < 0) return 2;
    d2k_ctl_accept(ctl);

    d2k_session *session = d2k_session_new(16, 16);
    d2k_journal *journal = (d2k_journal *)d2k_session_journal(session);
    d2k_key key;
    memset(&key, 0, sizeof key);
    key.family = 4;
    key.low_ip = 0x010200c0u;
    key.high_ip = 0x146433c6u;
    key.low_port = 0x409cu;
    key.high_port = 0xbb01u;
    key.proto = 6;

    const uint8_t plan_id[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    const uint8_t trial_id[16] = {16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    d2k_journal_add(journal, 100, &key, D2K_JRN_HELLO_SNI, 0, 0, NULL,
                    (const uint8_t *)"example.com", 11, NULL);
    d2k_jrn_detail detail;
    memset(&detail, 0, sizeof detail);
    detail.ttl = 63;
    detail.ref_ttl = 64;
    detail.tos = 46;
    detail.ipid = 0x1234;
    detail.planned = 1;
    detail.client_shape = 1;
    d2k_journal_add(journal, 101, &key, D2K_JRN_SUSPECT, 3, 1000, &detail, NULL, 0, NULL);
    d2k_journal_add_applied(journal, 102, &key, plan_id, trial_id);
    d2k_journal_add_fate(journal, 103, &key, D2K_JRN_PLAN_DONE, 0, plan_id, trial_id);
    d2k_journal_add_refused(journal, 104, &key, 5, plan_id, trial_id, NULL);
    d2k_journal_add_fate(journal, 105, &key, D2K_JRN_PLAN_UNSENT, 1, plan_id, trial_id);
    d2k_journal_add_fate(journal, 106, &key, D2K_JRN_PLAN_DAMAGED, 4, plan_id, trial_id);
    memset(&detail, 0, sizeof detail);
    detail.tos = 0x0f;
    detail.server_hello = 1;
    detail.planned = 2;
    d2k_journal_add(journal, 107, &key, D2K_JRN_EXCHANGE, 22, 500, &detail, NULL, 0, NULL);

    uint64_t seen = 0;
    d2k_ctlsrv_pump(ctl, session, &seen);
    d2k_ctl_flush(ctl);

    int flags = fcntl(client, F_GETFL, 0);
    fcntl(client, F_SETFL, flags | O_NONBLOCK);
    uint8_t frame[65536];
    size_t used = 0;
    for (;;) {
        ssize_t n = recv(client, frame + used, sizeof frame - used, 0);
        if (n > 0) { used += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        break;
    }
    size_t offset = 0;
    while (offset + 6 <= used) {
        uint32_t plen = (uint32_t)frame[offset] << 24 |
                        (uint32_t)frame[offset + 1] << 16 |
                        (uint32_t)frame[offset + 2] << 8 |
                        frame[offset + 3];
        uint16_t type = (uint16_t)frame[offset + 4] << 8 | frame[offset + 5];
        if (plen < 2 || offset + 4 + plen > used) break;
        size_t body_len = plen - 2;
        printf("frame type=%04x body=", type);
        for (size_t i = 0; i < body_len; i++) printf("%02x", frame[offset + 6 + i]);
        printf("\n");
        offset += 4 + plen;
    }
    close(client);
    d2k_ctl_close(ctl);
    unlink(SOCK);
    return 0;
}
