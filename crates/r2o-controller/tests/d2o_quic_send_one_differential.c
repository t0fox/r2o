/* C-оракул qp_send_one/qp_arm_first_send/qp_send_fragmented.
 *
 * Включает production core/quicprobe.c и mock-I/O из core/test_udp_runtime.c:
 * socket/connect/bind/close/setsockopt/send перехвачены в этом TU, поэтому
 * QUIC handshake и root не нужны. Каждая отправленная датаграмма печатается
 * вместе с TTL; Rust-сторона обязана дать тот же trace.
 *
 * argv[1] — имя кейса, argv[2] — QSN-снимок, подготовленный Rust-тестом.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define main udp_runtime_gate_main
#include "test_udp_runtime.c"
#undef main

/* TTL меняет только IP_TTL/IPV6_UNICAST_HOPS; IP_RECVTTL и прочие опции
 * не должны подменять сохранённый TTL сокета. */
static int send_one_setsockopt(int fd, int level, int option,
                               const void *value, socklen_t length)
{
    if ((level == IPPROTO_IP && option == IP_TTL) ||
        (level == IPPROTO_IPV6 && option == IPV6_UNICAST_HOPS)) {
        return mock_set(fd, level, option, value, length);
    }
    return 0;
}

static int send_one_socket(int family, int type, int protocol)
{
    (void)family;
    (void)type;
    (void)protocol;
    return 42;
}

static int send_one_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

static int send_one_bind(int fd, const struct sockaddr *address, socklen_t length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

static int send_one_close(int fd)
{
    (void)fd;
    return 0;
}

static int send_one_send_errno;
static int trace_local_port;

static ssize_t send_one_send(int fd, const void *bytes, size_t length, int flags)
{
    if (send_one_send_errno) {
        errno = send_one_send_errno;
        return -1;
    }
    return mock_send(fd, bytes, length, flags);
}

#define getsockname mock_local
#define getpeername mock_peer
#define getsockopt mock_get
#define setsockopt send_one_setsockopt
#define socket send_one_socket
#define connect send_one_connect
#define bind send_one_bind
#define close send_one_close
#define send send_one_send
#include "quicprobe.c"
#undef getsockname
#undef getpeername
#undef getsockopt
#undef setsockopt
#undef socket
#undef connect
#undef bind
#undef close
#undef send

/* Фрагментный sink: production d2k_udp_plan_send зовёт эти две функции,
 * вместо raw-сокета. */
struct raw_capture {
    uint8_t bytes[4096];
    size_t len;
    int ttl;
};

static struct raw_capture raw_cap[192];
static unsigned raw_cap_n;

static int raw_capture_prepare(udp_raw_sink *sink, const uint8_t *packet,
                               size_t length, uint32_t mark)
{
    (void)sink;
    (void)packet;
    (void)length;
    (void)mark;
    return 0;
}

static int raw_capture_send(udp_raw_sink *sink, const uint8_t *packet,
                            size_t length, uint32_t mark)
{
    (void)sink;
    (void)mark;
    if (raw_cap_n >= 192 || length > sizeof raw_cap[0].bytes) {
        return -1;
    }
    memcpy(raw_cap[raw_cap_n].bytes, packet, length);
    raw_cap[raw_cap_n].len = length;
    raw_cap[raw_cap_n].ttl = (packet[0] >> 4) == 6 ? packet[7] : packet[8];
    raw_cap_n++;
    return 0;
}

static void print_hex(const uint8_t *bytes, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        putchar(digits[bytes[i] >> 4]);
        putchar(digits[bytes[i] & 0x0f]);
    }
}

static void print_trace(const char *name, int code, int marked,
                        const struct raw_capture *packets, unsigned count,
                        int restored_ttl)
{
    printf("case|%s|code=%d|marked=%d|n=%u|restored=%d\n",
           name, code, marked, count, restored_ttl);
    for (unsigned i = 0; i < count; i++) {
        printf("dg|%s|%u|len=%zu|ttl=%d|hex=", name, i,
               packets[i].len, packets[i].ttl);
        print_hex(packets[i].bytes, packets[i].len);
        putchar('\n');
    }
}

static size_t read_snapshot(const char *path, uint8_t *out, size_t capacity)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        return 0;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 0;
    }
    long size = ftell(file);
    if (size <= 0 || (size_t)size > capacity || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }
    size_t got = fread(out, 1, (size_t)size, file);
    fclose(file);
    return got == (size_t)size ? got : 0;
}

static void reset_case(void)
{
    ctx(4);
    current_ttl = 47;
    sent_count = 0;
    lower_count = 0;
    elapsed = 0;
    fail_send = 0;
    send_one_send_errno = 0;
    raw_cap_n = 0;
    udp_prepare_io = raw_capture_prepare;
    udp_send_io = raw_capture_send;
    udp_fragment_id_io = fixed_id;
}

static void load_fragment_ports(void)
{
    const char *path = getenv("R2O_QUIC_SEND_ONE_FRAG_META");
    if (!path || !*path) {
        return;
    }
    FILE *file = fopen(path, "r");
    unsigned source = 0, peer = 0;
    if (file && fscanf(file, "%u %u", &source, &peer) == 2) {
        context.src_port = htons((uint16_t)source);
        context.dst_port = htons((uint16_t)peer);
    }
    if (file) {
        fclose(file);
    }
    inet_pton(AF_INET, "127.0.0.1", &context.src_ip);
    inet_pton(AF_INET, "127.0.0.1", &context.dst_ip);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <case> <snapshot.qsn>\n", argv[0]);
        return 2;
    }
    const char *name = argv[1];
    static uint8_t snapshot[65536];
    size_t snapshot_len = read_snapshot(argv[2], snapshot, sizeof snapshot);
    if (!snapshot_len) {
        fprintf(stderr, "не прочитан снимок %s\n", argv[2]);
        return 2;
    }

    static struct raw_capture trace[192];
    unsigned trace_count = 0;
    int code = -1;
    int marked = 0;
    const uint8_t prefix[4] = {0xaa, 0xbb, 0xcc, 0xdd};

    reset_case();
    trace_local_port = 0;
    if (strcmp(name, "srcport") == 0) {
        int fd = qp_send_one("127.0.0.1", 443, NULL, 0, 0, 0, 45000,
                             (d2k_hello){snapshot, snapshot_len, NULL, 0, 0, 0},
                             0, &marked, 0, 0);
        code = fd >= 0 ? 0 : fd;
        if (fd >= 0) {
            struct sockaddr_storage local;
            socklen_t local_len = sizeof local;
            memset(&local, 0, sizeof local);
            if (getsockname(fd, (struct sockaddr *)&local, &local_len) == 0 &&
                local.ss_family == AF_INET) {
                trace_local_port = ntohs(((struct sockaddr_in *)&local)->sin_port);
            }
            close(fd);
        }
        trace_count = sent_count;
        for (unsigned i = 0; i < trace_count; i++) {
            memcpy(trace[i].bytes, sent[i].bytes, sent[i].len);
            trace[i].len = sent[i].len;
            trace[i].ttl = sent[i].ttl;
        }
    } else if (strcmp(name, "plain") == 0 || strcmp(name, "tail") == 0 ||
        strcmp(name, "refused") == 0) {
        if (strcmp(name, "refused") == 0) {
            send_one_send_errno = ECONNREFUSED;
        }
        int fd = qp_send_one("127.0.0.1", 443, NULL, 0, 0, 0, 0,
                             (d2k_hello){snapshot, snapshot_len, NULL, 0, 0, 0},
                             0, &marked, 0, 0);
        code = fd >= 0 ? 0 : fd;
        trace_count = sent_count;
        for (unsigned i = 0; i < trace_count; i++) {
            memcpy(trace[i].bytes, sent[i].bytes, sent[i].len);
            trace[i].len = sent[i].len;
            trace[i].ttl = sent[i].ttl;
        }
    } else if (strcmp(name, "ttl") == 0) {
        int fd = qp_send_one("127.0.0.1", 443, prefix, sizeof prefix, 3, 2, 0,
                             (d2k_hello){snapshot, snapshot_len, NULL, 0, 0, 0},
                             0, &marked, 0, 0);
        code = fd >= 0 ? 0 : fd;
        trace_count = sent_count;
        for (unsigned i = 0; i < trace_count; i++) {
            memcpy(trace[i].bytes, sent[i].bytes, sent[i].len);
            trace[i].len = sent[i].len;
            trace[i].ttl = sent[i].ttl;
        }
    } else if (strcmp(name, "split") == 0) {
        int fd = qp_send_one("127.0.0.1", 443, NULL, 0, 0, 0, 0,
                             (d2k_hello){snapshot, snapshot_len, NULL, 0, 0, 0},
                             0, &marked, 1, 0);
        code = fd >= 0 ? 0 : fd;
        trace_count = sent_count;
        for (unsigned i = 0; i < trace_count; i++) {
            memcpy(trace[i].bytes, sent[i].bytes, sent[i].len);
            trace[i].len = sent[i].len;
            trace[i].ttl = sent[i].ttl;
        }
    } else if (strcmp(name, "arm-ttl") == 0) {
        d2k_qsnap pack;
        if (d2k_qsnap_parse(snapshot, snapshot_len, &pack) != 0) {
            fprintf(stderr, "снимок не QSN\n");
            return 2;
        }
        d2k_quic_arm_question question;
        memset(&question, 0, sizeof question);
        question.blob = prefix;
        question.blob_len = sizeof prefix;
        question.ttl = 3;
        question.copies = 2;
        qp_arm_action action;
        memset(&action, 0, sizeof action);
        action.q = &question;
        action.family = AF_INET;
        action.mark = 0;
        int rc = qp_arm_first_send(42, pack.dg[0], pack.len[0], &action);
        code = rc > 0 ? 0 : -1;
        marked = 1;
        trace_count = sent_count;
        for (unsigned i = 0; i < trace_count; i++) {
            memcpy(trace[i].bytes, sent[i].bytes, sent[i].len);
            trace[i].len = sent[i].len;
            trace[i].ttl = sent[i].ttl;
        }
    } else if (strncmp(name, "frag", 4) == 0 && name[4] >= '1' &&
               name[4] <= '4' && name[5] == '\0') {
        int shape = name[4] - '0';
        d2k_qsnap pack;
        if (d2k_qsnap_parse(snapshot, snapshot_len, &pack) != 0) {
            fprintf(stderr, "снимок не QSN\n");
            return 2;
        }
        d2k_ipfrag_plan plan;
        if (d2k_ipfrag_shape(shape, &plan) != 0) {
            fprintf(stderr, "форма ipfrag %d не собрана\n", shape);
            return 2;
        }
        load_fragment_ports();
        int fd = qp_send_fragmented(
            "127.0.0.1", 443,
            (d2k_hello){pack.dg[0], pack.len[0], NULL, 0, 0, 0},
            &plan, 0, &marked);
        code = fd >= 0 ? 0 : -1;
        trace_count = raw_cap_n;
        memcpy(trace, raw_cap, sizeof raw_cap[0] * raw_cap_n);
    } else {
        fprintf(stderr, "неизвестный кейс %s\n", name);
        return 2;
    }
    print_trace(name, code, marked, trace, trace_count, current_ttl);
    return 0;
}
