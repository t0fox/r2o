/* C/Rust differential: box_id_for (core/sched.c:7648-7729). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "sched.c"

static const char *TEXT =
    "r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n";

static void fp_one(d2k_cat_fp *fp, const char *kind, int volume, uint8_t ttl,
                   uint8_t tos, uint16_t ipid) {
    memset(fp, 0, sizeof *fp);
    fp->method = 2;
    fp->n_sig = 1;
    snprintf(fp->sig[0].kind, sizeof fp->sig[0].kind, "%s", kind);
    fp->sig[0].volume = volume;
    fp->sig[0].ttl = ttl;
    fp->sig[0].tos = tos;
    fp->sig[0].ipid = ipid;
}

static void box(d2k_cat_box *b, const char *id, const d2k_cat_fp *fp) {
    memset(b, 0, sizeof *b);
    snprintf(b->id, sizeof b->id, "%s", id);
    b->fp = *fp;
}

int main(void) {
    static d2k_sched s;
    static d2k_catalog cat;
    static task t;
    static d2k_cat_box boxes[4];
    static d2k_cat_fp fp;
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    memset(&t, 0, sizeof t);
    memset(boxes, 0, sizeof boxes);
    s.cat = &cat;
    cat.boxes = boxes;
    cat.n_boxes = 0;
    t.fp = fp;

    char id[64];
    memset(&fp, 0, sizeof fp);
    t.fp = fp;
    box_id_for(&s, &t, TEXT, id, sizeof id);
    printf("case1_no_fp=%s\n", id);

    fp_one(&fp, "volume", 40, 0, 0, 0);
    box(&boxes[0], "box-existing", &fp);
    cat.n_boxes = 1;
    t.fp = fp;
    box_id_for(&s, &t, TEXT, id, sizeof id);
    printf("case2_one_fp=%s\n", id);

    box(&boxes[1], "box-second", &fp);
    cat.n_boxes = 2;
    box_id_for(&s, &t, TEXT, id, sizeof id);
    printf("case3_multi_fp=%s\n", id);
    char base[64];
    snprintf(base, sizeof base, "%s", id);

    cat.n_boxes = 0;
    snprintf(t.box_id, sizeof t.box_id, "box-preferred");
    box_id_for(&s, &t, TEXT, id, sizeof id);
    printf("case4_preferred=%s\n", id);
    t.box_id[0] = '\0';

    d2k_cat_fp other;
    fp_one(&other, "rst", 0, 1, 0x88, 7);
    box(&boxes[0], base, &other);
    cat.n_boxes = 1;
    t.fp = fp;
    box_id_for(&s, &t, TEXT, id, sizeof id);
    printf("case5_conflict=%s\n", id);
    char salt1[64];
    snprintf(salt1, sizeof salt1, "%s", id);

    box(&boxes[1], salt1, &other);
    cat.n_boxes = 2;
    box_id_for(&s, &t, TEXT, id, sizeof id);
    printf("case6_salt2=%s\n", id);

    box(&boxes[0], "box-empty", &other);
    memset(&boxes[0].fp, 0, sizeof boxes[0].fp);
    cat.n_boxes = 1;
    box_id_for(&s, &t, TEXT, id, sizeof id);
    printf("case7_empty_clash=%s\n", id);

    cat.n_boxes = 0;
    box_id_for(&s, &t,
               "r2o-plan 1 11\nproto tcp tls\nsplit payload_start +1\n", id,
               sizeof id);
    printf("case8_other_text=%s\n", id);

    cat.n_boxes = 0;
    fp_one(&fp, "volume", 80, 0, 0, 0);
    t.fp = fp;
    box_id_for(&s, &t, TEXT, id, sizeof id);
    printf("case9_bucket=%s\n", id);

    cat.revision = 99;
    fp_one(&fp, "volume", 40, 0, 0, 0);
    t.fp = fp;
    box_id_for(&s, &t, TEXT, id, sizeof id);
    printf("case10_revision=%s\n", id);
    return 0;
}
