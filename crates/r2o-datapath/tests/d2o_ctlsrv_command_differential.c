/* C/Rust differential: d2k_ctlsrv_command ACK results (a378). */
#include <stdio.h>
#include <string.h>

#include "d2k_ctlsrv.h"
#include "d2k_http80.h"
#include "d2k_plan.h"
#include "d2k_session.h"

static d2k_ctlsrv cx;

static void run(const char *name, uint16_t type, const uint8_t *body, size_t len) {
    uint64_t ok_before = cx.ok_cmds, bad_before = cx.bad_cmds;
    d2k_ctlsrv_command(&cx, type, body, len);
    (void)bad_before;
    printf("%s ok=%llu\n", name,
           (unsigned long long)(cx.ok_cmds - ok_before));
}

int main(void) {
    d2k_session *session = d2k_session_new(16, 0);
    d2k_http80 *http80 = d2k_http80_new();
    memset(&cx, 0, sizeof cx);
    cx.sess = session;
    cx.http80 = http80;
    cx.now_ns = 1000ull * 1000000000ull;

    uint8_t https[64];
    const char *host = "RuTracker.org";
    size_t host_len = strlen(host);
    https[0] = (uint8_t)host_len;
    memcpy(https + 1, host, host_len);
    https[1 + host_len] = 0;
    https[2 + host_len] = 0;
    https[3 + host_len] = 0;
    https[4 + host_len] = 60;
    run("https", D2K_CMD_SET_HTTPS, https, 1 + host_len + 4);
    run("https_bad", D2K_CMD_SET_HTTPS, https, host_len + 4);
    https[1] = ' ';
    run("https_bad_name", D2K_CMD_SET_HTTPS, https, 1 + host_len + 4);
    https[1] = 'R';

    static const uint8_t tls_plan[] = {
        'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
        0x00, 0x02, 0x00, 0x02, 6, 1,
        0x01, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00
    };
    uint8_t command[128];
    size_t length = 0;
    command[length++] = (uint8_t)host_len;
    memcpy(command + length, host, host_len);
    length += host_len;
    command[length++] = 1;
    command[length++] = 4;
    memcpy(command + length, tls_plan, sizeof tls_plan);
    length += sizeof tls_plan;
    run("set_name", D2K_CMD_SET_NAME, command, length);

    size_t truncated = length - 1;
    run("set_name_bad_plan", D2K_CMD_SET_NAME, command, truncated);

    uint8_t delete_body[64];
    size_t delete_len = 0;
    delete_body[delete_len++] = (uint8_t)host_len;
    memcpy(delete_body + delete_len, host, host_len);
    delete_len += host_len;
    delete_body[delete_len++] = 6;
    delete_body[delete_len++] = 1;
    delete_body[delete_len++] = 4;
    run("delete_name", D2K_CMD_DEL_NAME, delete_body, delete_len);
    run("delete_name_again", D2K_CMD_DEL_NAME, delete_body, delete_len);

    command[1 + host_len] = 1;
    command[2 + host_len] = 5;
    run("set_name_bad_family", D2K_CMD_SET_NAME, command, 3 + host_len + sizeof tls_plan);
    d2k_http80_free(http80);
    return 0;
}
