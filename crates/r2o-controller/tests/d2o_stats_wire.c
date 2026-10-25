#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "d2k_link.h"
#include "d2k_ctlsrv.h"

/* Exercise the actual sender and parser, including d2kd.c's zero-key body. */
int main(void) {
    char directory[] = "/tmp/r2o-stats-wire.XXXXXX";
    if (!mkdtemp(directory)) return 2;
    char path[108], error[256] = {0};
    snprintf(path, sizeof path, "%s/control", directory);
    d2k_ctl *sender = d2k_ctl_open(path, error, sizeof error);
    if (!sender) return 3;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 4;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof address)) return 5;
    d2k_ctl_accept(sender);
    if (d2k_ctl_peer_fd(sender) < 0) return 6;
    const unsigned families[] = {0, 4, 6};
    for (unsigned i = 0; i < sizeof families / sizeof families[0]; i++) {
        uint8_t body[D2K_KEY_WIRE_LEN + 8] = {0};
        body[0] = (uint8_t)families[i];
        body[D2K_KEY_WIRE_LEN + 3] = 7;
        body[D2K_KEY_WIRE_LEN + 7] = 19;
        d2k_ctl_event(sender, D2K_EV_STATS, body, sizeof body);
        d2k_ctl_flush(sender);
        d2k_ev event;
        int result = d2k_link_next(fd, &event, 100, error, sizeof error);
        printf("family=%u result=%d dropped=%u sent=%u\n",
               families[i], result, event.dropped, event.sent);
        if (result != (families[i] ? 0 : -1)) return 7;
        if (families[i] && (event.dropped != 7 || event.sent != 19)) return 8;
    }
    close(fd);
    d2k_ctl_close(sender);
    return rmdir(directory) ? 9 : 0;
}
