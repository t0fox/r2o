#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_catalog.h"

static int save_box(const char *path, const char *id)
{
    d2k_catalog catalog = {0};
    char err[256];
    catalog.boxes = calloc(1, sizeof(*catalog.boxes));
    if (!catalog.boxes) return -1;
    catalog.n_boxes = 1;
    snprintf(catalog.boxes[0].id, sizeof(catalog.boxes[0].id), "%s", id);
    int result = d2k_catalog_save_atomic(&catalog, path, err, sizeof err);
    if (result != 0) fprintf(stderr, "d2k_catalog_save_atomic: %s\n", err);
    d2k_catalog_free(&catalog);
    return result;
}

int main(int argc, char **argv)
{
    char local_id[40], external_id[40], extra;
    d2k_catalog saved = {0};
    char err[256];
    if (argc != 3) return 2;
    FILE *fixture = fopen(argv[1], "r");
    if (!fixture) return 3;
    char line[128];
    int found = 0;
    while (fgets(line, sizeof line, fixture)) {
        if (line[0] == '#') continue;
        if (sscanf(line, "%39s %39s %c", local_id, external_id, &extra) != 2) {
            fclose(fixture);
            return 4;
        }
        found = 1;
        break;
    }
    fclose(fixture);
    if (!found) return 5;

    /* The file contains a concurrent writer's state when d2kc persists its
       own changed in-memory catalog. The donor writes its own snapshot. */
    if (save_box(argv[2], external_id) != 0 || save_box(argv[2], local_id) != 0)
        return 6;
    if (d2k_catalog_load(argv[2], &saved, err, sizeof err) != 0) {
        fprintf(stderr, "d2k_catalog_load: %s\n", err);
        return 7;
    }
    for (size_t i = 0; i < saved.n_boxes; i++) puts(saved.boxes[i].id);
    d2k_catalog_free(&saved);
    return 0;
}
