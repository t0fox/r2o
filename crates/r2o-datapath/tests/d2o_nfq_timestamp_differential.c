/* C-оракул: SO_TIMESTAMP на сокете NETLINK_NETFILTER, как d2kd.c:1313-1319.
 *
 * Ядро ставит NFQA_TIMESTAMP в пакеты очереди только когда этот параметр
 * включён. Отказ не смертелен: датапат считает RTT по своим часам. */
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/netlink.h>

static int enable(int fd) {
    int one = 1;
    return setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof one);
}

int main(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (fd < 0) {
        printf("set=0 readback=-1 bad=0\n");
        return 0;
    }
    int set = enable(fd) == 0;
    int value = 0;
    socklen_t length = sizeof value;
    int read = getsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &value, &length);
    int bad = enable(-1) != 0;
    printf("set=%d readback=%d bad=%d\n", set, read == 0 ? value : -1, bad);
    close(fd);
    return 0;
}
