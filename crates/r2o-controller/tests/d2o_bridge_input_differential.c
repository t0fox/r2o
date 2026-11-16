/* C/Rust differential входа моста планировщика.
 *
 * Включает production `detect/bridge.c` (gc-sections выбрасывает остальные
 * функции) и вызывает его static `bridge_input` теми же входами, что Rust
 * `r2o_bridge_input`. Печатает ровно те поля d2k_trigger/d2k_opts/адреса,
 * которые обязан заполнить мост. */
#include "d2k_detect.h"
#include "d2k_hello.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef R2O_BRIDGE_C
#error "R2O_BRIDGE_C must point to production detect/bridge.c"
#endif
#include R2O_BRIDGE_C

#define HELLO_CAP 4096

static uint8_t hello_buf[HELLO_CAP];
static uint8_t control_buf[HELLO_CAP];
static uint8_t white_buf[HELLO_CAP];
static char long_name[257];

static int build_hello(d2k_shape shape, const char *name,
                       uint8_t out[HELLO_CAP], size_t *len)
{
    memset(out, 0, HELLO_CAP);
    *len = 0;
    return d2k_hello_from_profile(shape, name, out, HELLO_CAP, len);
}

static int build_variant(const char *variant, int control,
                         uint8_t out[HELLO_CAP], size_t *len)
{
    size_t offset = 0, name_len = 0;
    if (strcmp(variant, "none") == 0) {
        return 0;
    }
    if (strcmp(variant, "short") == 0) {
        out[0] = 0x16;
        out[1] = 0x03;
        *len = 2;
        return 0;
    }
    if (strcmp(variant, "tiny") == 0) {
        out[0] = 0x16;
        *len = 1;
        return 0;
    }
    if (strcmp(variant, "sni_256") == 0) {
        memset(long_name, 'a', 256);
        long_name[256] = '\0';
        return build_hello(D2K_SHAPE_LEGACY, long_name, out, len);
    }
    if (build_hello(control ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN,
                    control ? "disk.rzd.ru" : "target.example", out, len) != 0) {
        return -1;
    }
    if (strcmp(variant, "wrong_type") == 0) {
        out[0] = 0x17;
    } else if (strcmp(variant, "without_sni") == 0) {
        if (d2k_hello_sni(out, *len, &offset, &name_len) != 0 || offset < 3) {
            return -1;
        }
        out[offset - 3] = 1;
    } else if (strcmp(variant, "nul_sni") == 0) {
        if (d2k_hello_sni(out, *len, &offset, &name_len) != 0 || !name_len) {
            return -1;
        }
        out[offset] = 0;
    }
    return 0;
}

static void print_hex(const uint8_t *bytes, size_t len)
{
    size_t i;
    if (!bytes || len == 0) {
        putchar('-');
        return;
    }
    for (i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
}

static void print_trigger_hex(const d2k_trigger *trigger)
{
    print_hex(trigger->payload, trigger->len);
}

static void print_case(const char *name, const char *ip, uint16_t port,
                       const char *trigger_variant,
                       const char *control_variant,
                       const char *white_variant,
                       int snapped, int tcp_known, int tcp_large,
                       uint32_t mark, int repeats,
                       uint32_t gap_us, uint32_t wait_ms,
                       int task_stop)
{
    static const uint8_t tcp_options[] = {
        0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x08, 0x0a,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    };
    static const uint8_t large_options[41] = {0};
    volatile sig_atomic_t stop_flag = task_stop;
    d2k_hello trigger = {0}, control = {0}, white = {0};
    d2k_trigger tr;
    d2k_opts opt;
    d2k_vres out;
    char addr[96] = "";
    size_t trigger_len = 0, control_len = 0, white_len = 0;
    int rc;

    if (build_variant(trigger_variant, 0, hello_buf, &trigger_len) != 0) {
        fprintf(stderr, "case %s: trigger build failed\n", name);
        return;
    }
    if (build_variant(control_variant, 1, control_buf, &control_len) != 0) {
        fprintf(stderr, "case %s: control build failed\n", name);
        return;
    }
    if (build_variant(white_variant, 0, white_buf, &white_len) != 0) {
        fprintf(stderr, "case %s: white build failed\n", name);
        return;
    }
    if (trigger_len) {
        trigger.bytes = hello_buf;
        trigger.len = trigger_len;
        trigger.snapped = snapped;
        if (tcp_known) {
            trigger.tcp_known = 1;
            if (tcp_large) {
                trigger.tcp_options = large_options;
                trigger.tcp_options_len = sizeof large_options;
            } else {
                trigger.tcp_options = tcp_options;
                trigger.tcp_options_len = sizeof tcp_options;
            }
        }
    }
    if (control_len) {
        control.bytes = control_buf;
        control.len = control_len;
    }
    if (white_len) {
        white.bytes = white_buf;
        white.len = white_len;
    }

    memset(&tr, 0xa5, sizeof tr);
    memset(&opt, 0xa5, sizeof opt);
    memset(&out, 0xa5, sizeof out);
    rc = bridge_input(ip, port, trigger, control, white, mark, repeats,
                      gap_us, wait_ms, &stop_flag, &tr, &opt, addr, &out);

    printf("case=%s rc=%d owns=%d verdict=%d reason=%s addr=%s",
           name, rc, out.owns_search, (int)out.verdict,
           out.reason[0] ? out.reason : "-", addr[0] ? addr : "-");
    printf(" tr_len=%zu tr_accept=%d tr_name=%s tr_sni_off=%d tr_sni_len=%d",
           tr.len, (int)tr.accept, tr.name[0] ? tr.name : "-",
           tr.sni_off, tr.sni_len);
    printf(" tr_tcp_known=%d tr_tcp_len=%zu tr_tcp_offers_ts=%d tr_tcp=",
           tr.client_tcp_known, tr.client_tcp_options_len,
           tr.client_tcp_known ? d2k_trigger_offers_ts(&tr) : -1);
    print_hex(tr.client_tcp_options, tr.client_tcp_options_len);
    printf(" tr_hex=");
    print_trigger_hex(&tr);
    printf(" ctl_len=%zu ctl_accept=%d ctl_name=%s ctl_vouched=%d ctl_hex=",
           opt.control.len, (int)opt.control.accept,
           opt.control.name[0] ? opt.control.name : "-",
           opt.control_vouched);
    print_trigger_hex(&opt.control);
    printf(" white_len=%zu white_accept=%d white_name=%s white_hex=",
           opt.white.len, (int)opt.white.accept,
           opt.white.name[0] ? opt.white.name : "-");
    print_trigger_hex(&opt.white);
    printf(" decoy_len=%zu decoy_type=%02x decoy_accept=%d decoy_hex=",
           opt.decoy.len, opt.decoy.len ? opt.decoy.payload[0] : 0,
           (int)opt.decoy.accept);
    print_trigger_hex(&opt.decoy);
    printf(" repeats=%d gap_ms=%d timeout_ms=%d mark=%u"
           " cancel_set=%d cancel_task=%d cancel_null=%d\n",
           opt.repeats, opt.write_gap_ms, opt.timeout_ms, opt.mark,
           opt.cancel.ctx != NULL,
           opt.cancel.fn ? opt.cancel.fn(opt.cancel.ctx) : 0,
           opt.cancel.fn ? opt.cancel.fn(NULL) : 0);
}

int main(void)
{
    print_case("error_empty", "192.0.2.1", 443, "none", "none", "none",
               0, 0, 0, 0x2f, 3, 60000, 6000, 0);
    print_case("error_tiny", "192.0.2.1", 443, "tiny", "none", "none",
               0, 0, 0, 0x2f, 3, 60000, 6000, 0);
    print_case("minimal", "192.0.2.1", 443, "short", "none", "none",
               0, 0, 0, 0x2f, 4, 12345, 321, 0);
    print_case("full_clone", "192.0.2.1", 443, "modern", "legacy",
               "modern", 1, 1, 0, 0x2d, 2, 7000, 1500, 0);
    print_case("tcp_options_overflow", "192.0.2.1", 443, "modern",
               "none", "none", 0, 1, 1, 0x2f, 3, 60000, 6000, 0);
    print_case("control_missing", "192.0.2.1", 443, "modern", "none",
               "none", 1, 0, 0, 0x2f, 3, 60000, 6000, 0);
    print_case("control_short", "192.0.2.1", 443, "modern", "short",
               "none", 1, 0, 0, 0x2f, 3, 60000, 6000, 0);
    print_case("control_without_sni", "192.0.2.1", 443, "modern",
               "without_sni", "none", 1, 0, 0, 0x2f, 3, 60000, 6000, 0);
    print_case("control_nul_sni", "2001:db8::1", 8443, "modern",
               "nul_sni", "none", 1, 0, 0, 0x2f, 3, 60000, 6000, 0);
    print_case("control_sni_256", "192.0.2.1", 443, "modern", "sni_256",
               "none", 1, 0, 0, 0x2f, 3, 60000, 6000, 0);
    print_case("snapped_wrong_type", "192.0.2.1", 443, "wrong_type",
               "legacy", "none", 1, 0, 0, 0x2f, 3, 60000, 6000, 0);
    print_case("task_stop", "192.0.2.1", 443, "modern", "legacy", "none",
               1, 0, 0, 0, 0, 0, 0, 1);
    return 0;
}
