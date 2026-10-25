#include <stdio.h>

#include "d2k_catalog.h"

int main(int argc, char **argv) {
    d2k_catalog catalog = {0};
    char error[256];
    if (argc != 2) return 2;
    if (d2k_catalog_load(argv[1], &catalog, error, sizeof error) != 0) {
        fprintf(stderr, "d2k_catalog_load: %s\n", error);
        return 3;
    }
    printf("%s %d %d %lld\n", catalog.net.name, catalog.net.searched,
           catalog.net.tx_only, (long long)catalog.net.confirmed_at);
    d2k_catalog_free(&catalog);
    return 0;
}
