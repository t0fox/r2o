/* C-оракул multi-fd poll: NFQUEUE + два произвольных fd.
 *
 * Семантика: timeout/EINTR -> пусто; readiness любого fd; маски revents
 * каждого fd; NFQUEUE читается только при POLLIN. */
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void pair(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) {
        perror("socketpair");
        exit(2);
    }
}

static void send_byte(int fd, char byte) {
    if (send(fd, &byte, 1, 0) != 1) {
        perror("send");
        exit(2);
    }
}

int main(void) {
    const char *scenario = getenv("R2O_MULTIPOLL_SCENARIO");
    if (!scenario) scenario = "both";
    int nfq[2], e1[2], e2[2], pipefd[2] = {-1, -1};
    pair(nfq);
    pair(e1);
    if (!strcmp(scenario, "hup")) {
        if (pipe(pipefd) != 0) {
            perror("pipe");
            return 2;
        }
        close(pipefd[1]);
    } else {
        pair(e2);
    }
    int e2fd = !strcmp(scenario, "hup") ? pipefd[0] : e2[0];

    if (!strcmp(scenario, "both")) {
        send_byte(nfq[1], 'n');
        send_byte(e2[1], '2');
    } else if (!strcmp(scenario, "extra_only")) {
        send_byte(e1[1], '1');
    }

    struct pollfd descriptors[3];
    descriptors[0] = (struct pollfd){.fd = nfq[0], .events = POLLIN};
    descriptors[1] = (struct pollfd){.fd = e1[0], .events = POLLIN};
    descriptors[2] = (struct pollfd){.fd = e2fd, .events = POLLIN};
    int ready = poll(descriptors, 3, 100);
    int received = 0;
    char payload = '-';
    if (ready > 0 && (descriptors[0].revents & POLLIN)) {
        if (recv(nfq[0], &payload, 1, 0) == 1) received = 1;
    }
    printf("%s ready=%d nfq=%d payload=%c e0=%d e1=%d\n", scenario,
           ready > 0 ? 1 : 0, received, payload,
           (int)descriptors[1].revents, (int)descriptors[2].revents);
    return 0;
}
