/* C-оракул: flow_tracked (datapath/session.c:678-777) без live-netns.
 *
 * session.c включается целиком: функция статическая. d2k_nat_hook подменён
 * сценарным ответом; проверяются nat_state 0/1/3, три попытки, SYN-ACK,
 * first-packet и счётчики g_nat_ok/miss/none/retried. */
#include "session.c"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int plan[8];
static int plan_len;
static int plan_at;
static int calls;

static int fake_nat(const char *path, uint8_t proto, uint32_t src, uint16_t sport,
                    uint32_t dst, uint16_t dport, uint32_t *out,
                    uint16_t *out_port) {
    (void)path; (void)proto; (void)src; (void)sport; (void)dst; (void)dport;
    int rc = plan_len ? plan[plan_at < plan_len ? plan_at : plan_len - 1] : 0;
    plan_at++;
    calls++;
    if (rc == 0) {
        *out = 0xcb007109u; /* 203.0.113.9 */
        *out_port = htons(62000);
    }
    return rc;
}

static int fake_nat6(const char *path, uint8_t proto, const uint8_t *src,
                     uint16_t sport, const uint8_t *dst, uint16_t dport,
                     uint8_t family, uint8_t *out, uint16_t *out_port) {
    (void)path; (void)proto; (void)src; (void)sport; (void)dst; (void)dport;
    (void)family;
    int rc = plan_len ? plan[plan_at < plan_len ? plan_at : plan_len - 1] : 0;
    plan_at++;
    calls++;
    if (rc == 0) {
        out[0] = 203; out[1] = 0; out[2] = 113; out[3] = 9;
        *out_port = htons(62000);
    }
    return rc;
}

static void run(const char *name, uint8_t proto, int first, int synack,
                uint8_t preset, const int *answers, int count) {
    d2k_flow flow;
    memset(&flow, 0, sizeof flow);
    flow.nat_state = preset;
    flow.saw_synack = synack;
    d2k_conn conn;
    memset(&conn, 0, sizeof conn);
    conn.family = 4;
    conn.src_ip = 0x0a000001u;
    conn.dst_ip = 0xcb007102u;
    conn.src_port = htons(40000);
    conn.dst_port = htons(443);

    g_nat_ok = g_nat_miss = g_nat_none = g_nat_retried = 0;
    memset(plan, 0, sizeof plan);
    for (int i = 0; i < count && i < 8; i++) plan[i] = answers[i];
    plan_len = count;
    plan_at = 0;
    calls = 0;
    int rc = flow_tracked(&flow, &conn, proto, first);
    printf("%s rc=%d state=%u ok=%llu miss=%llu none=%llu retried=%llu calls=%d\n",
           name, rc, (unsigned)flow.nat_state,
           (unsigned long long)g_nat_ok, (unsigned long long)g_nat_miss,
           (unsigned long long)g_nat_none, (unsigned long long)g_nat_retried,
           calls);
}

int main(void) {
    d2k_nat_hook = fake_nat;
    d2k_nat_family_hook = fake_nat6;

    run("first_missing", 17, 1, 0, 0, (const int[]){-1}, 1);
    run("found", 17, 0, 0, 0, (const int[]){0}, 1);
    run("table_missing", 17, 0, 0, 0, (const int[]){1}, 1);
    run("miss", 17, 0, 0, 0, (const int[]){-1, -1, -1}, 3);
    run("retry_found", 17, 0, 0, 0, (const int[]){-1, 0}, 2);
    run("retry_table_missing", 17, 0, 0, 0, (const int[]){-1, 1}, 2);
    run("synack", 6, 0, 1, 0, (const int[]){-1}, 1);
    run("preset_known", 17, 0, 0, 1, (const int[]){-1}, 1);
    run("preset_no_table", 17, 0, 0, 3, (const int[]){-1}, 1);
    run("first_with_known", 17, 1, 0, 1, (const int[]){-1}, 1);
    run("tcp_retry", 6, 0, 0, 0, (const int[]){-1, 0}, 2);
    return 0;
}
