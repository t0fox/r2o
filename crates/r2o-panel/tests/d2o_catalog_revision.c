#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>

#include "server.c"

int main(int argc, char **argv)
{
    char *json = NULL;
    size_t length = 0;
    char revision[17];

    if (argc != 2 || json_object_file(argv[1], &json, &length) != 0)
        return 2;
    if (!catalog_revision(json, revision)) {
        free(json);
        return 3;
    }
    puts(revision);
    free(json);
    return 0;
}
