/* C-оракул метки verifier-сокета планировщика D2O.
 *
 * Прямо вызывает static `install_next` из `core/sched.c` с задачей-кандидатом:
 * именно этот путь в C ставит SO_MARK на зарезервированный сокет зонда
 * (`sched.c:4627-4634`) перед SET_NAME_PROBE. Значение берётся из
 * конструктора `d2k_sched_new(..., 0x2e)`, а `d2k_sched_set_measure_mark`
 * отдельно задаёт 0x2f для измерений.
 *
 * Стенд не ходит в сеть и не требует root: bind/mark/link-хуки подменены.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sched.c"

static int mark_seen;
static uint32_t mark_value;

static int stub_mark(int fd, uint32_t mark) {
    (void)fd;
    mark_seen++;
    mark_value = mark;
    return 0;
}

static int stub_bind(uint8_t transport, uint8_t family, int *out_fd,
                     uint16_t *sport_be) {
    (void)transport;
    (void)family;
    *out_fd = dup(STDIN_FILENO);
    *sport_be = htons(40000);
    return *out_fd < 0 ? -1 : 0;
}

int d2k_link_del_name_probe_family(int fd, const char *name, uint8_t transport,
                                   uint8_t shape, uint16_t sport_be, uint8_t family,
                                   char *err, size_t errcap) {
    (void)fd; (void)name; (void)transport; (void)shape; (void)sport_be;
    (void)family; (void)err; (void)errcap;
    return 0;
}

int d2k_link_del_addr_probe_family(int fd, const uint8_t *src, uint16_t src_port_be,
                                   const uint8_t *dst, uint16_t dst_port_be,
                                   uint8_t transport, uint8_t family,
                                   const uint8_t trial_id[D2K_TRIAL_ID_LEN],
                                   char *err, size_t errcap) {
    (void)fd; (void)src; (void)src_port_be; (void)dst; (void)dst_port_be;
    (void)transport; (void)family; (void)trial_id; (void)err; (void)errcap;
    return 0;
}

int d2k_link_set_name_probe_trial(int fd, const char *name, uint8_t transport,
                                  const char *plan_text, uint8_t shape,
                                  uint16_t sport_be, uint8_t family,
                                  const uint8_t trial_id[D2K_TRIAL_ID_LEN],
                                  char *err, size_t errcap) {
    (void)fd; (void)name; (void)transport; (void)plan_text; (void)shape;
    (void)sport_be; (void)family; (void)trial_id; (void)err; (void)errcap;
    return 0;
}

int d2k_link_set_addr_probe_family(int fd, const uint8_t *src, uint16_t src_port_be,
                                   const uint8_t *dst, uint16_t dst_port_be,
                                   uint8_t transport, uint8_t family,
                                   const uint8_t trial_id[D2K_TRIAL_ID_LEN],
                                   uint32_t lease_ms, const char *plan_hex,
                                   char *err, size_t errcap) {
    (void)fd; (void)src; (void)src_port_be; (void)dst; (void)dst_port_be;
    (void)transport; (void)family; (void)trial_id; (void)lease_ms;
    (void)plan_hex; (void)err; (void)errcap;
    return 0;
}

int d2k_props_bind_udp_family(uint8_t family, int *out_fd, uint16_t *sport_be) {
    (void)family; (void)out_fd; (void)sport_be;
    return -1;
}

int d2k_props_bind_family(uint8_t family, int *out_fd, uint16_t *sport_be) {
    (void)family; (void)out_fd; (void)sport_be;
    return -1;
}

static int stub_mark_hook(int fd, uint32_t mark) {
    (void)fd; (void)mark;
    return 0;
}
d2k_mark_fn d2k_mark_hook = stub_mark_hook;

d2k_shape d2k_hello_shape(const uint8_t *b, size_t n) {
    (void)b; (void)n;
    return D2K_SHAPE_MODERN;
}

size_t d2k_fallback_arms(void) { return 0; }

int d2k_fallback_plan(size_t idx, d2k_shape shape, const char *decoy,
                      size_t send_cap, char *buf, size_t cap) {
    (void)idx; (void)shape; (void)decoy; (void)send_cap; (void)buf; (void)cap;
    return -1;
}

size_t d2k_net_whitelist_count(void) { return 0; }
const char *d2k_net_whitelist_name(size_t i) { (void)i; return NULL; }

int d2k_rx_volume_plan_client(unsigned variant, d2k_shape shape, size_t send_cap,
                              const char *name, int client_has_ts,
                              char *buf, size_t cap) {
    (void)variant; (void)shape; (void)send_cap; (void)name;
    (void)client_has_ts; (void)buf; (void)cap;
    return -1;
}

int d2k_quic_hello_incomplete(const uint8_t *p, size_t n) {
    (void)p; (void)n;
    return 0;
}

int d2k_plan_text_to_hex(const char *text, char *out, size_t cap,
                         char *err, size_t errcap) {
    (void)text; (void)err; (void)errcap;
    if (cap < 3) return -1;
    out[0] = '0';
    out[1] = '0';
    out[2] = '\0';
    return 0;
}

int main(void) {
    static d2k_sched s;
    static d2k_catalog cat;
    static task t;
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    memset(&t, 0, sizeof t);
    s.cat = &cat;
    s.link_fd = -1;
    s.mark = 0x2e;
    s.measure_mark = 0x2f;
    s.now_ms = 1000;
    s.wall_base_s = 1000;
    s.mono_base_ms = 0;
    t.state = T_PLANNING;
    t.transport = 6;
    t.family = 4;
    snprintf(t.name, sizeof t.name, "example.com");
    snprintf(t.ip, sizeof t.ip, "93.184.216.34");
    t.port = 443;
    t.probe_fd = -1;
    t.next_plan = 0;
    t.n_plans = 1;
    snprintf(t.plans[0], sizeof t.plans[0],
             "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
             "proto tcp tls\nsplit payload_start +1\norder forward\n");
    d2k_sched_mark_fn saved_mark = d2k_sched_mark_hook;
    d2k_sched_bind_fn saved_bind = d2k_sched_bind_hook;
    d2k_sched_mark_hook = stub_mark;
    d2k_sched_bind_hook = stub_bind;
    int rc = install_next(&s, &t);
    d2k_sched_mark_hook = saved_mark;
    d2k_sched_bind_hook = saved_bind;
    printf("install_rc=%d mark_seen=%d verifier_mark=0x%x measure_mark=0x%x\n",
           rc, mark_seen, (unsigned)mark_value, (unsigned)s.measure_mark);
    return rc == 0 && mark_seen > 0 && mark_value == 0x2e && s.measure_mark == 0x2f
               ? 0
               : 1;
}
