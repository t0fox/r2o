#define _POSIX_C_SOURCE 200809L
#define main d2o_panel_main_for_known_keys
#include "main.c"
#undef main

#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char mode[32] = "observe";
    char listen[256] = "127.0.0.1:8090";
    char state_dir[512] = "/opt/r2o/state";
    char unknown[UNKNOWN_MAX][UNKNOWN_KEY_MAX];
    size_t unknown_count = 0;
    int queue = 2000;
    int exists = 0;
    int result = read_config(argv[1], mode, sizeof mode, listen, sizeof listen,
                             state_dir, sizeof state_dir, &queue,
                             0, 0, 0, 0, unknown, &unknown_count, &exists);
    printf("result=%d mode=%s listen=%s state=%s queue=%d exists=%d unknown=",
           result, mode, listen, state_dir, queue, exists);
    for (size_t i = 0; i < unknown_count; i++) {
        if (i) putchar(',');
        fputs(unknown[i], stdout);
    }
    putchar('\n');
    return 0;
}
