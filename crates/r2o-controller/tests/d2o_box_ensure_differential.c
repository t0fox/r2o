#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

int main(void)
{
    d2k_catalog catalog;
    memset(&catalog, 0, sizeof catalog);

    d2k_cat_box *first = box_ensure(&catalog, "box-a");
    d2k_cat_box *same = box_ensure(&catalog, "box-a");
    d2k_cat_box *second = box_ensure(&catalog, "box-b");
    printf("count=%zu\n", catalog.n_boxes);
    printf("same=%d\n", first == same);
    printf("ids=%s,%s\n", catalog.boxes[0].id, catalog.boxes[1].id);
    printf("fresh_zero=%d\n",
           second->created == 0 && second->updated == 0 &&
           second->fp.n_sig == 0 && second->n_plans == 0 &&
           second->n_binds == 0);
    free(catalog.boxes);
    return 0;
}
