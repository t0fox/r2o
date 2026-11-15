/* C-оракул решения raw_sendto (detect/raw.c:773): короткая запись
 * принимается для IPv4 и отвергается для IPv6. */
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

#include "raw.c"

int64_t d2k_now_ms(void) { return 0; }

static ssize_t fake_rc;

ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *addr, socklen_t alen)
{
    (void)fd;
    (void)buf;
    (void)len;
    (void)flags;
    (void)addr;
    (void)alen;
    return fake_rc;
}

static void run(const char *name, int family, ssize_t rc, size_t len)
{
    raw_conn conn;
    uint8_t packet[64] = {0};
    static const uint8_t v4[] = {127, 0, 0, 1};
    static const uint8_t v6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    memset(&conn, 0, sizeof conn);
    conn.family = (uint8_t)family;
    conn.send_fd = 0;
    conn.dport = 443;
    if (family == 6) memcpy(conn.dst, v6, sizeof v6);
    else memcpy(conn.dst, v4, sizeof v4);
    fake_rc = rc;
    printf("%s|%d\n", name, raw_sendto(&conn, packet, len));
}

int main(void)
{
    run("v4-short", 4, 10, 20);
    run("v4-full", 4, 20, 20);
    run("v4-error", 4, -1, 20);
    run("v6-short", 6, 10, 20);
    run("v6-full", 6, 20, 20);
    run("v6-error", 6, -1, 20);
    return 0;
}
