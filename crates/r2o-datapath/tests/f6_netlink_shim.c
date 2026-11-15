/* LD_PRELOAD-инъекция rtnetlink для d2k_f6_route/d2k_f6_neighbor.
 *
 * Перехватывает socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE), sendto,
 * recvfrom, setsockopt и close. Сценарий задаёт R2O_F6_SCENARIO. Запрос
 * проверяется побайтно: family, dst_len/src_len=128, RTA_DST/RTA_SRC/RTA_MARK;
 * для neighbor — NLM_F_DUMP, family, ifindex. Результат проверки пишется в
 * R2O_F6_SHIM_LOG, чтобы C/Rust можно было сравнить отдельно от ответа.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int (*socket_fn)(int, int, int);
typedef int (*setsockopt_fn)(int, int, int, const void *, socklen_t);
typedef ssize_t (*sendto_fn)(int, const void *, size_t, int,
                             const struct sockaddr *, socklen_t);
typedef ssize_t (*recvfrom_fn)(int, void *, size_t, int, struct sockaddr *,
                               socklen_t *);
typedef int (*close_fn)(int);

static socket_fn real_socket;
static setsockopt_fn real_setsockopt;
static sendto_fn real_sendto;
static recvfrom_fn real_recvfrom;
static close_fn real_close;

static int fake_fd = -1;
static int request_type;
static unsigned request_ifindex;
static int neighbor_calls;
static int route_req_ok;
static int neighbor_req_ok;
static const char *scenario;

static const uint8_t expected_src[16] = {
    0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t expected_dst[16] = {
    0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
static const uint32_t expected_mark = 0x2e;
static const unsigned expected_ifindex = 7;
static const uint8_t expected_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t success_gateway[16] = {
    0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe};
static uint8_t resolved_gateway[16];

static int starts_with(const char *text, const char *prefix) {
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

static void write_log(void) {
    const char *path = getenv("R2O_F6_SHIM_LOG");
    if (!path || !*path) {
        return;
    }
    FILE *file = fopen(path, "a");
    if (!file) {
        return;
    }
    fprintf(file, "route_req_ok=%d neighbor_req_ok=%d\n",
            route_req_ok, neighbor_req_ok);
    fclose(file);
}

static size_t put_attr(uint8_t *base, size_t offset, unsigned type,
                       const void *data, size_t length) {
    struct rtattr *attr = (struct rtattr *)(base + offset);
    size_t total = RTA_LENGTH(length);
    attr->rta_type = (unsigned short)type;
    attr->rta_len = (unsigned short)total;
    if (length) {
        memcpy(RTA_DATA(attr), data, length);
    }
    return offset + RTA_ALIGN(total);
}

static int validate_route(const struct nlmsghdr *header, size_t length) {
    if (length < NLMSG_LENGTH(sizeof(struct rtmsg)) ||
        header->nlmsg_type != RTM_GETROUTE ||
        header->nlmsg_flags != NLM_F_REQUEST || header->nlmsg_seq != 1) {
        return 0;
    }
    const struct rtmsg *route = NLMSG_DATA(header);
    if (route->rtm_family != AF_INET6 || route->rtm_dst_len != 128 ||
        route->rtm_src_len != 128) {
        return 0;
    }
    int have_dst = 0, have_src = 0, have_mark = 0;
    int left = (int)RTM_PAYLOAD(header);
    for (const struct rtattr *attr = RTM_RTA(route); RTA_OK(attr, left);
         attr = RTA_NEXT(attr, left)) {
        if (attr->rta_type == RTA_DST && RTA_PAYLOAD(attr) == 16 &&
            memcmp(RTA_DATA(attr), expected_dst, 16) == 0) {
            have_dst = 1;
        } else if (attr->rta_type == RTA_SRC && RTA_PAYLOAD(attr) == 16 &&
                   memcmp(RTA_DATA(attr), expected_src, 16) == 0) {
            have_src = 1;
        } else if (attr->rta_type == RTA_MARK && RTA_PAYLOAD(attr) == 4) {
            uint32_t mark = 0;
            memcpy(&mark, RTA_DATA(attr), sizeof mark);
            have_mark = mark == expected_mark;
        }
    }
    return have_dst && have_src && have_mark;
}

static int validate_neighbor(const struct nlmsghdr *header, size_t length) {
    if (length < NLMSG_LENGTH(sizeof(struct ndmsg)) ||
        header->nlmsg_type != RTM_GETNEIGH ||
        header->nlmsg_flags != (NLM_F_REQUEST | NLM_F_DUMP) ||
        header->nlmsg_seq != 1) {
        return 0;
    }
    const struct ndmsg *neighbor = NLMSG_DATA(header);
    if (neighbor->ndm_family != AF_INET6 ||
        neighbor->ndm_ifindex != (int)expected_ifindex) {
        return 0;
    }
    request_ifindex = (unsigned)neighbor->ndm_ifindex;
    return 1;
}

static size_t build_route_reply(uint8_t *buffer) {
    struct nlmsghdr *header = (struct nlmsghdr *)buffer;
    memset(buffer, 0, 128);
    header->nlmsg_type = RTM_NEWROUTE;
    header->nlmsg_seq = 1;
    header->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    struct rtmsg *route = NLMSG_DATA(header);
    route->rtm_family = AF_INET6;
    route->rtm_dst_len = 128;
    route->rtm_src_len = 128;
    route->rtm_type = starts_with(scenario, "route_local") ? RTN_LOCAL
                                                           : RTN_UNICAST;
    if (starts_with(scenario, "route_nonipv6")) {
        route->rtm_family = AF_INET;
    }
    if (starts_with(scenario, "route_nonunicast")) {
        route->rtm_type = RTN_BLACKHOLE;
    }
    if (starts_with(scenario, "route_wrong_seq")) {
        header->nlmsg_seq = 2;
    }
    size_t offset = NLMSG_ALIGN(header->nlmsg_len);
    if (!starts_with(scenario, "route_no_oif")) {
        if (starts_with(scenario, "route_short_oif")) {
            struct rtattr *attr = (struct rtattr *)(buffer + offset);
            attr->rta_type = RTA_OIF;
            attr->rta_len = 6;
            uint16_t short_value = (uint16_t)expected_ifindex;
            memcpy(RTA_DATA(attr), &short_value, sizeof short_value);
            offset += RTA_ALIGN(attr->rta_len);
        } else {
            uint32_t ifindex = expected_ifindex;
            offset = put_attr(buffer, offset, RTA_OIF, &ifindex, sizeof ifindex);
        }
    }
    if (!starts_with(scenario, "route_no_gateway") &&
        !starts_with(scenario, "route_local") &&
        !starts_with(scenario, "route_short_oif")) {
        if (starts_with(scenario, "route_short_gateway")) {
            const uint8_t short_gateway[8] = {0xfd, 0x00, 0, 0, 0, 0, 0, 0xfe};
            memcpy(resolved_gateway, expected_dst, 16);
            offset = put_attr(buffer, offset, RTA_GATEWAY, short_gateway,
                              sizeof short_gateway);
        } else {
            memcpy(resolved_gateway, success_gateway, 16);
            offset = put_attr(buffer, offset, RTA_GATEWAY, success_gateway, 16);
        }
    } else {
        memcpy(resolved_gateway, expected_dst, 16);
    }
    header->nlmsg_len = (uint32_t)offset;
    return offset;
}

static size_t build_neighbor_reply(uint8_t *buffer) {
    struct nlmsghdr *header = (struct nlmsghdr *)buffer;
    memset(buffer, 0, 128);
    header->nlmsg_type = RTM_NEWNEIGH;
    header->nlmsg_seq = 1;
    header->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    struct ndmsg *neighbor = NLMSG_DATA(header);
    neighbor->ndm_family = AF_INET6;
    neighbor->ndm_ifindex = (int)expected_ifindex;
    neighbor->ndm_state = starts_with(scenario, "neighbor_delay") ? NUD_DELAY
                          : starts_with(scenario, "neighbor_probe") ? NUD_PROBE
                          : starts_with(scenario, "neighbor_permanent") ? NUD_PERMANENT
                          : starts_with(scenario, "neighbor_reachable") ? NUD_REACHABLE
                          : starts_with(scenario, "neighbor_incomplete") ? NUD_INCOMPLETE
                                                                        : NUD_STALE;
    if (starts_with(scenario, "neighbor_wrong_ifindex")) {
        neighbor->ndm_ifindex = (int)expected_ifindex + 1;
    }
    if (starts_with(scenario, "neighbor_nonipv6")) {
        neighbor->ndm_family = AF_INET;
    }
    size_t offset = NLMSG_ALIGN(header->nlmsg_len);
    if (starts_with(scenario, "neighbor_dst_short")) {
        const uint8_t short_dst[8] = {0xfd, 0x00, 0, 0, 0, 0, 0, 2};
        offset = put_attr(buffer, offset, NDA_DST, short_dst, sizeof short_dst);
    } else {
        offset = put_attr(buffer, offset, NDA_DST,
                          resolved_gateway[0] ? resolved_gateway : expected_dst, 16);
    }
    if (!starts_with(scenario, "neighbor_no_lladdr") &&
        !starts_with(scenario, "neighbor_short_lladdr")) {
        offset = put_attr(buffer, offset, NDA_LLADDR, expected_mac, 6);
    } else if (starts_with(scenario, "neighbor_short_lladdr")) {
        const uint8_t short_mac[4] = {0x02, 0x11, 0x22, 0x33};
        offset = put_attr(buffer, offset, NDA_LLADDR, short_mac, 4);
    }
    header->nlmsg_len = (uint32_t)offset;
    return offset;
}

static size_t build_neighbor_error(uint8_t *buffer) {
    struct nlmsghdr *header = (struct nlmsghdr *)buffer;
    memset(buffer, 0, 128);
    header->nlmsg_type = NLMSG_ERROR;
    header->nlmsg_seq = 1;
    header->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
    struct nlmsgerr *error = NLMSG_DATA(header);
    error->error = -EHOSTUNREACH;
    return header->nlmsg_len;
}

static size_t build_done(uint8_t *buffer) {
    struct nlmsghdr *header = (struct nlmsghdr *)buffer;
    memset(buffer, 0, 64);
    header->nlmsg_type = NLMSG_DONE;
    header->nlmsg_seq = 1;
    header->nlmsg_len = NLMSG_LENGTH(0);
    return header->nlmsg_len;
}

static ssize_t fake_recv(void *buffer, size_t capacity) {
    (void)capacity;
    if (request_type == RTM_GETROUTE) {
        if (starts_with(scenario, "route_recv_eintr")) {
            errno = EINTR;
            return -1;
        }
        if (starts_with(scenario, "route_eagain")) {
            errno = EAGAIN;
            return -1;
        }
        if (starts_with(scenario, "route_error_short")) {
            struct nlmsghdr *header = (struct nlmsghdr *)buffer;
            memset(buffer, 0, 64);
            header->nlmsg_type = NLMSG_ERROR;
            header->nlmsg_seq = 1;
            header->nlmsg_len = NLMSG_LENGTH(sizeof(int));
            int error = -ENETUNREACH;
            memcpy(NLMSG_DATA(header), &error, sizeof error);
            return header->nlmsg_len;
        }
        if (starts_with(scenario, "route_error_positive")) {
            struct nlmsghdr *header = (struct nlmsghdr *)buffer;
            memset(buffer, 0, 128);
            header->nlmsg_type = NLMSG_ERROR;
            header->nlmsg_seq = 1;
            header->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
            struct nlmsgerr *error = NLMSG_DATA(header);
            error->error = EACCES;
            return header->nlmsg_len;
        }
        if (starts_with(scenario, "route_error")) {
            struct nlmsghdr *header = (struct nlmsghdr *)buffer;
            memset(buffer, 0, 128);
            header->nlmsg_type = NLMSG_ERROR;
            header->nlmsg_seq = 1;
            header->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
            struct nlmsgerr *error = NLMSG_DATA(header);
            error->error = -ENETUNREACH;
            return header->nlmsg_len;
        }
        if (starts_with(scenario, "route_empty")) {
            return 0;
        }
        return (ssize_t)build_route_reply(buffer);
    }
    if (request_type == RTM_GETNEIGH) {
        neighbor_calls++;
        if (starts_with(scenario, "neighbor_recv_eintr")) {
            errno = EINTR;
            return -1;
        }
        if (starts_with(scenario, "neighbor_error")) {
            return (ssize_t)build_neighbor_error(buffer);
        }
        if (starts_with(scenario, "neighbor_done")) {
            return (ssize_t)build_done(buffer);
        }
        if (starts_with(scenario, "neighbor_eagain")) {
            errno = EAGAIN;
            return -1;
        }
        if (starts_with(scenario, "neighbor_timeout")) {
            usleep(10000);
            return 0;
        }
        if (starts_with(scenario, "neighbor_empty")) {
            return 0;
        }
        if (starts_with(scenario, "neighbor_batch64")) {
            if (neighbor_calls < 64) {
                return 0;
            }
            return (ssize_t)build_neighbor_reply(buffer);
        }
        if (neighbor_calls > 1 &&
            (starts_with(scenario, "neighbor_no_lladdr") ||
             starts_with(scenario, "neighbor_short_lladdr") ||
             starts_with(scenario, "neighbor_wrong_ifindex"))) {
            return 0;
        }
        return (ssize_t)build_neighbor_reply(buffer);
    }
    errno = EAGAIN;
    return -1;
}

int socket(int domain, int type, int protocol) {
    if (!real_socket) {
        real_socket = (socket_fn)dlsym(RTLD_NEXT, "socket");
    }
    if (domain == AF_NETLINK && protocol == NETLINK_ROUTE) {
        fake_fd = dup(STDIN_FILENO);
        scenario = getenv("R2O_F6_SCENARIO");
        if (!scenario) {
            scenario = "route_success";
        }
        return fake_fd;
    }
    return real_socket(domain, type, protocol);
}

int setsockopt(int fd, int level, int option, const void *value,
               socklen_t length) {
    if (!real_setsockopt) {
        real_setsockopt = (setsockopt_fn)dlsym(RTLD_NEXT, "setsockopt");
    }
    if (fd == fake_fd && level == SOL_SOCKET) {
        return 0;
    }
    return real_setsockopt(fd, level, option, value, length);
}

ssize_t sendto(int fd, const void *buffer, size_t length, int flags,
               const struct sockaddr *address, socklen_t address_length) {
    if (!real_sendto) {
        real_sendto = (sendto_fn)dlsym(RTLD_NEXT, "sendto");
    }
    if (fd != fake_fd) {
        return real_sendto(fd, buffer, length, flags, address, address_length);
    }
    const struct nlmsghdr *header = buffer;
    request_type = header->nlmsg_type;
    if (request_type == RTM_GETROUTE &&
        starts_with(scenario, "route_send_eintr")) {
        write_log();
        errno = EINTR;
        return -1;
    }
    if (request_type == RTM_GETROUTE) {
        route_req_ok = validate_route(header, length);
    } else if (request_type == RTM_GETNEIGH) {
        neighbor_req_ok = validate_neighbor(header, length);
        neighbor_calls = 0;
    }
    write_log();
    return (ssize_t)length;
}

ssize_t recvfrom(int fd, void *buffer, size_t capacity, int flags,
                 struct sockaddr *address, socklen_t *address_length) {
    if (!real_recvfrom) {
        real_recvfrom = (recvfrom_fn)dlsym(RTLD_NEXT, "recvfrom");
    }
    if (fd != fake_fd) {
        return real_recvfrom(fd, buffer, capacity, flags, address,
                             address_length);
    }
    if (address && address_length &&
        *address_length >= (socklen_t)sizeof(struct sockaddr_nl)) {
        struct sockaddr_nl *source = (struct sockaddr_nl *)address;
        memset(source, 0, sizeof *source);
        source->nl_family = AF_NETLINK;
        source->nl_pid =
            ((request_type == RTM_GETROUTE &&
              strstr(scenario, "route_bad_source")) ||
             (request_type == RTM_GETNEIGH &&
              strstr(scenario, "neighbor_bad_source")))
                ? 1
                : 0;
        *address_length = sizeof *source;
    }
    return fake_recv(buffer, capacity);
}

int close(int fd) {
    if (!real_close) {
        real_close = (close_fn)dlsym(RTLD_NEXT, "close");
    }
    if (fd == fake_fd) {
        fake_fd = -1;
    }
    return real_close(fd);
}
