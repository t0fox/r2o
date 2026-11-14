/* C/Rust differential: DEL_NAME_BOUND frame, d2k_ctl_binding_read и ACK.
 *
 * Оракулы:
 *  - отправитель   — core/link.c `d2k_link_del_name_bound`;
 *  - чтение        — datapath/include/d2k_ctl.h `d2k_ctl_binding_read`;
 *  - приёмник      — datapath/ctlsrv.c `D2K_CMD_DEL_NAME_BOUND`.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_ctlsrv.h"
#include "d2k_http80.h"
#include "d2k_link.h"
#include "d2k_plan.h"
#include "d2k_session.h"

static d2k_ctlsrv cx;

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", bytes[i]);
    }
}

static d2k_binding_context make_binding(uint64_t generation, uint8_t kind,
                                        uint8_t family, uint8_t shape,
                                        uint8_t temporary, uint8_t epoch_fill) {
    d2k_binding_context binding;
    memset(&binding, 0, sizeof binding);
    binding.generation = generation;
    binding.kind = kind;
    binding.family = family;
    binding.shape = shape;
    binding.temporary = temporary;
    memset(binding.epoch, epoch_fill, sizeof binding.epoch);
    return binding;
}

static void send_binding(const char *label, const char *name, uint8_t transport,
                         uint64_t generation, uint8_t kind, uint8_t family,
                         uint8_t shape, uint8_t temporary, uint8_t epoch_fill) {
    d2k_binding_context binding =
        make_binding(generation, kind, family, shape, temporary, epoch_fill);
    char error[128];
    int pair[2];
    uint8_t frame[1024];
    size_t total = 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
        perror("socketpair");
        exit(1);
    }
    int rc = d2k_link_del_name_bound(pair[0], name, transport, &binding,
                                     error, sizeof error);
    close(pair[0]);
    if (rc == 0) {
        for (;;) {
            ssize_t got = recv(pair[1], frame + total, sizeof frame - total, 0);
            if (got <= 0) {
                break;
            }
            total += (size_t)got;
        }
    }
    close(pair[1]);
    printf("send %s rc=%d", label, rc);
    if (rc == 0) {
        printf(" bytes=");
        print_hex(frame, total);
    }
    printf("\n");
}

static void send_epoch_sequence(const char *label, const char *name,
                                uint8_t transport, uint64_t generation) {
    d2k_binding_context binding =
        make_binding(generation, 1, 6, 13, 0, 0);
    for (unsigned i = 0; i < 16; i++) {
        binding.epoch[i] = (uint8_t)i;
    }
    char error[128];
    int pair[2];
    uint8_t frame[1024];
    size_t total = 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
        perror("socketpair");
        exit(1);
    }
    int rc = d2k_link_del_name_bound(pair[0], name, transport, &binding,
                                     error, sizeof error);
    close(pair[0]);
    if (rc == 0) {
        for (;;) {
            ssize_t got = recv(pair[1], frame + total, sizeof frame - total, 0);
            if (got <= 0) {
                break;
            }
            total += (size_t)got;
        }
    }
    close(pair[1]);
    printf("send %s rc=%d", label, rc);
    if (rc == 0) {
        printf(" bytes=");
        print_hex(frame, total);
    }
    printf("\n");
}

static void base_context(uint8_t context[D2K_CTL_BINDING_LEN]) {
    uint64_t generation = 0x1122334455667788ull;
    for (unsigned i = 0; i < 8; i++) {
        context[i] = (uint8_t)(generation >> (56 - 8 * i));
    }
    context[8] = 1;
    context[9] = 4;
    context[10] = 1;
    context[11] = 0;
    for (unsigned i = 0; i < 16; i++) {
        context[12 + i] = (uint8_t)i;
    }
}

static void read_case(const char *label, const uint8_t *context, size_t length) {
    d2k_binding_context binding;
    memset(&binding, 0, sizeof binding);
    int rc = d2k_ctl_binding_read(&binding, context, length);
    printf("read %s rc=%d", label, rc);
    if (rc == 0) {
        printf(" gen=%016llx kind=%u family=%u shape=%u temp=%u epoch=",
               (unsigned long long)binding.generation, binding.kind,
               binding.family, binding.shape, binding.temporary);
        print_hex(binding.epoch, sizeof binding.epoch);
    }
    printf("\n");
}

static void install_http(d2k_binding_context *binding) {
    static const uint8_t plan_bytes[] = {
        'D', '2', 'K', 'P', 0, 1, 0, 11, 0, 0, 0, 2,
        0x00, 0x01, 0x00, 0x10,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x00, 0x02, 0x00, 0x02, 0x06, 0x04,
    };
    static const char host[] = "example.test";
    char why[200];
    d2k_plan *plan = NULL;
    if (d2k_plan_load(plan_bytes, sizeof plan_bytes, &plan, why, sizeof why) !=
        0) {
        fprintf(stderr, "HTTP-план не разобран: %s\n", why);
        exit(1);
    }
    d2k_plantab *table = d2k_session_plans(cx.sess);
    int rc = d2k_plantab_set_name_family(
        table, (const uint8_t *)host, strlen(host), cx.now_ns, plan,
        D2K_PLAN_SHAPE_HTTP, 0, 4);
    if (rc != 0) {
        fprintf(stderr, "HTTP-план не установился: rc=%d\n", rc);
        exit(1);
    }
    if (!d2k_plantab_binding(table, plan, binding)) {
        fprintf(stderr, "привязка установленного плана не читается\n");
        exit(1);
    }
}

typedef void (*binding_mutator)(d2k_binding_context *);

static void mutate_generation_plus1(d2k_binding_context *binding) {
    binding->generation += 1;
}

static void mutate_generation_zero(d2k_binding_context *binding) {
    binding->generation = 0;
}

static void mutate_epoch_changed(d2k_binding_context *binding) {
    binding->epoch[15] ^= 1;
}

static void mutate_epoch_zero(d2k_binding_context *binding) {
    memset(binding->epoch, 0, sizeof binding->epoch);
}

static void mutate_kind0(d2k_binding_context *binding) { binding->kind = 0; }
static void mutate_kind2(d2k_binding_context *binding) { binding->kind = 2; }
static void mutate_kind5(d2k_binding_context *binding) { binding->kind = 5; }
static void mutate_temporary(d2k_binding_context *binding) {
    binding->temporary = 1;
}
static void mutate_temporary2(d2k_binding_context *binding) {
    binding->temporary = 2;
}
static void mutate_family0(d2k_binding_context *binding) { binding->family = 0; }
static void mutate_family6(d2k_binding_context *binding) { binding->family = 6; }
static void mutate_family5(d2k_binding_context *binding) { binding->family = 5; }
static void mutate_shape0(d2k_binding_context *binding) { binding->shape = 0; }
static void mutate_shape13(d2k_binding_context *binding) { binding->shape = 13; }
static void mutate_shape14(d2k_binding_context *binding) { binding->shape = 14; }

static void delete_case(const char *label, const char *name, size_t name_len,
                        uint8_t transport, binding_mutator mutate,
                        int context_delta) {
    d2k_session *session = d2k_session_new(16, 0);
    d2k_http80 *http80 = d2k_http80_new();
    if (!session || !http80) {
        fprintf(stderr, "нет памяти под сессию\n");
        exit(1);
    }
    memset(&cx, 0, sizeof cx);
    cx.sess = session;
    cx.http80 = http80;
    cx.now_ns = 1000ull * 1000000000ull;
    d2k_plantab *table = d2k_session_plans(session);
    d2k_binding_context expected;
    install_http(&expected);
    if (mutate) {
        mutate(&expected);
    }
    uint8_t body[512];
    size_t length = 0;
    body[length++] = (uint8_t)name_len;
    memcpy(body + length, name, name_len);
    length += name_len;
    body[length++] = transport;
    d2k_ctl_binding_write(body + length, &expected);
    length += D2K_CTL_BINDING_LEN;
    if (context_delta < 0) {
        length -= 1;
    } else if (context_delta > 0) {
        body[length++] = 0;
    }
    uint64_t before = cx.ok_cmds;
    d2k_ctlsrv_command(&cx, D2K_CMD_DEL_NAME_BOUND, body, length);
    printf("del %s ok=%llu live=%zu\n", label,
           (unsigned long long)(cx.ok_cmds - before), d2k_plantab_count(table));
    d2k_http80_free(http80);
    d2k_session_free(session);
}

int main(void) {
    // C `d2k_link_del_name_bound`: точные байты кадра и отказы отправителя.
    send_binding("name1_tcp", "a", 6, 1, 1, 4, 1, 0, 0xAB);
    static char name255[256];
    memset(name255, 'n', 255);
    name255[255] = '\0';
    send_epoch_sequence("name255_udp", name255, 17, 0x1122334455667788ull);
    send_binding("name0", "", 6, 1, 1, 4, 1, 0, 0xAB);
    static char name256[257];
    memset(name256, 'n', 256);
    name256[256] = '\0';
    send_binding("name256", name256, 6, 1, 1, 4, 1, 0, 0xAB);
    send_binding("transport0", "a", 0, 1, 1, 4, 1, 0, 0xAB);
    send_binding("transport5", "a", 5, 1, 1, 4, 1, 0, 0xAB);
    send_binding("generation0", "a", 6, 0, 1, 4, 1, 0, 0xAB);
    send_binding("epoch0", "a", 6, 1, 1, 4, 1, 0, 0);
    send_binding("kind0", "a", 6, 1, 0, 4, 1, 0, 0xAB);
    send_binding("kind2", "a", 6, 1, 2, 4, 1, 0, 0xAB);
    send_binding("temporary", "a", 6, 1, 1, 4, 1, 1, 0xAB);
    send_binding("family0_shape0", "a", 6, 1, 1, 0, 0, 0, 0xAB);
    send_binding("shape7", "a", 6, 1, 1, 4, 7, 0, 0xAB);
    send_binding("shape14", "a", 6, 1, 1, 4, 14, 0, 0xAB);
    send_epoch_sequence("generation_max", "a", 6, UINT64_MAX);

    // C `d2k_ctl_binding_read`: длина, поля и границы.
    uint8_t base[D2K_CTL_BINDING_LEN];
    base_context(base);
    read_case("len27", base, D2K_CTL_BINDING_LEN - 1);
    read_case("len28_base", base, D2K_CTL_BINDING_LEN);
    uint8_t longer[D2K_CTL_BINDING_LEN + 1];
    memcpy(longer, base, sizeof base);
    longer[D2K_CTL_BINDING_LEN] = 0;
    read_case("len29", longer, sizeof longer);
    static const struct {
        const char *label;
        unsigned index;
        uint8_t value;
    } fields[] = {
        {"kind0", 8, 0},       {"kind4", 8, 4},       {"kind5", 8, 5},
        {"family0", 9, 0},     {"family4", 9, 4},     {"family6", 9, 6},
        {"family5", 9, 5},     {"family255", 9, 255}, {"shape0", 10, 0},
        {"shape7", 10, 7},     {"shape13", 10, 13},   {"shape14", 10, 14},
        {"shape255", 10, 255}, {"temp0", 11, 0},      {"temp1", 11, 1},
        {"temp2", 11, 2},      {"temp255", 11, 255},
    };
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++) {
        uint8_t context[D2K_CTL_BINDING_LEN];
        memcpy(context, base, sizeof context);
        context[fields[i].index] = fields[i].value;
        read_case(fields[i].label, context, sizeof context);
    }
    uint8_t unknown[D2K_CTL_BINDING_LEN];
    memcpy(unknown, base, sizeof unknown);
    memset(unknown, 0, 8);
    read_case("generation0", unknown, sizeof unknown);
    uint8_t no_epoch[D2K_CTL_BINDING_LEN];
    memcpy(no_epoch, base, sizeof no_epoch);
    memset(no_epoch + 12, 0, 16);
    read_case("epoch0", no_epoch, sizeof no_epoch);

    // Приёмник DEL_NAME_BOUND: ACK и снятие/неснятие записи.
    delete_case("match", "example.test", strlen("example.test"), 6, NULL, 0);
    delete_case("generation_plus1", "example.test", strlen("example.test"), 6,
                mutate_generation_plus1, 0);
    delete_case("generation0", "example.test", strlen("example.test"), 6,
                mutate_generation_zero, 0);
    delete_case("epoch_changed", "example.test", strlen("example.test"), 6,
                mutate_epoch_changed, 0);
    delete_case("epoch0", "example.test", strlen("example.test"), 6,
                mutate_epoch_zero, 0);
    delete_case("kind0", "example.test", strlen("example.test"), 6, mutate_kind0,
                0);
    delete_case("kind2", "example.test", strlen("example.test"), 6, mutate_kind2,
                0);
    delete_case("temporary", "example.test", strlen("example.test"), 6,
                mutate_temporary, 0);
    delete_case("family0", "example.test", strlen("example.test"), 6,
                mutate_family0, 0);
    delete_case("family6", "example.test", strlen("example.test"), 6,
                mutate_family6, 0);
    delete_case("shape0", "example.test", strlen("example.test"), 6,
                mutate_shape0, 0);
    delete_case("shape13", "example.test", strlen("example.test"), 6,
                mutate_shape13, 0);
    delete_case("transport17", "example.test", strlen("example.test"), 17, NULL,
                0);
    delete_case("name_other", "other.test", strlen("other.test"), 6, NULL, 0);
    delete_case("name_upper", "EXAMPLE.TEST", strlen("EXAMPLE.TEST"), 6, NULL,
                0);
    delete_case("invalid_kind5", "example.test", strlen("example.test"), 6,
                mutate_kind5, 0);
    delete_case("invalid_family5", "example.test", strlen("example.test"), 6,
                mutate_family5, 0);
    delete_case("invalid_shape14", "example.test", strlen("example.test"), 6,
                mutate_shape14, 0);
    delete_case("invalid_temp2", "example.test", strlen("example.test"), 6,
                mutate_temporary2, 0);
    delete_case("invalid_transport0", "example.test", strlen("example.test"), 0,
                NULL, 0);
    delete_case("invalid_len27", "example.test", strlen("example.test"), 6, NULL,
                -1);
    delete_case("invalid_len29", "example.test", strlen("example.test"), 6, NULL,
                1);
    delete_case("invalid_name0", "", 0, 6, NULL, 0);
    delete_case("invalid_name256", name256, 256, 6, NULL, 0);
    return 0;
}
