#define _POSIX_C_SOURCE 200809L

#include <stdio.h>

#include "server.c"

int main(int argc, char **argv)
{
    d2k_panel_config config = {
        .telegram_pid_path = argc > 1 ? argv[1] : NULL,
        .telegram_status_path = argc > 2 ? argv[2] : NULL,
    };
    char status[24];
    int running = 0;

    if (argc != 3)
        return 2;
    telegram_status_value(&config, 1, 1, &running, status);
    printf("%s|%d\n", status, running);
    return 0;
}
