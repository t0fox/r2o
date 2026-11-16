#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "meas.c"

static int make_listener(struct sockaddr_in *address)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(address, 0, sizeof *address);
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address->sin_port = 0;
    if (bind(fd, (struct sockaddr *)address, sizeof *address) != 0) {
        close(fd);
        return -1;
    }
    socklen_t length = sizeof *address;
    if (getsockname(fd, (struct sockaddr *)address, &length) != 0 ||
        listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(void)
{
    struct sockaddr_in address;
    int listener = make_listener(&address);
    if (listener < 0) {
        perror("listener");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    int rc = connect_bounded(fd, (struct sockaddr *)&address, sizeof address, 1000);
    printf("success %d\n", rc == 0 ? 1 : -1);
    close(fd);
    close(listener);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    rc = connect_bounded(fd, (struct sockaddr *)&address, sizeof address, 1000);
    printf("refused %d\n", rc == 0 ? 1 : -1);
    close(fd);

    printf("badfd %d\n",
           connect_bounded(-1, (struct sockaddr *)&address, sizeof address, 1000) == 0 ? 1 : -1);
    return 0;
}
