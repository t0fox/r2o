/* C/Rust differential: d2k_plan_apply on simple plans (a378). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_plan.h"
#include "d2k_plantlv.h"

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
}

static char *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);
    char *bytes = calloc(1, (size_t)size + 1);
    if (!bytes) { fclose(file); return NULL; }
    if (fread(bytes, 1, (size_t)size, file) != (size_t)size) {
        free(bytes); fclose(file); return NULL;
    }
    fclose(file);
    *length = (size_t)size;
    return bytes;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    const char *name = strrchr(argv[1], '/');
    name = name ? name + 1 : argv[1];
    size_t text_len = 0;
    char *text = read_file(argv[1], &text_len);
    if (!text) return 2;
    uint8_t tlv[8192];
    size_t tlv_len = 0;
    char error[256];
    if (d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tlv_len, error, sizeof error) != 0) {
        printf("case %s to_tlv=%s\n", argv[1], error);
        free(text);
        return 1;
    }
    FILE *binary = fopen(argv[2], "wb");
    if (!binary) { free(text); return 2; }
    fwrite(tlv, 1, tlv_len, binary);
    fclose(binary);
    free(text);

    d2k_plan *plan = NULL;
    if (d2k_plan_load(tlv, tlv_len, &plan, error, sizeof error) != 0) {
        printf("case %s load=%s\n", argv[1], error);
        return 1;
    }
    const uint8_t payload[] = "abcdefghij";
    d2k_pkt input;
    memset(&input, 0, sizeof input);
    input.payload = payload;
    input.payload_len = sizeof payload - 1;
    input.seq = 1000;
    input.have_sni = 1;
    input.is_tls13 = 0;
    input.sni_off = 2;
    input.sni_len = 4;
    input.segment_cap = 1400;
    d2k_actions actions;
    memset(&actions, 0, sizeof actions);
    int rc = d2k_plan_apply(plan, NULL, &input, &actions);
    printf("case %s rc=%d fate=%d n=%zu why=%s\n", name, rc,
           actions.fate, actions.n, actions.refuse_why ? actions.refuse_why : "");
    for (size_t i = 0; i < actions.n; i++) {
        const d2k_emit *emit = &actions.v[i];
        printf("emit %zu kind=%u delay=%u seq=%u ttl=%u ts_up=%u poison=%u seq_shift=%d pre=%zu len=%zu bytes=",
               i, emit->kind, emit->delay_us, emit->seq, emit->ttl, emit->ts_up,
               emit->poison, emit->seq_shift, emit->pre_len, emit->len);
        if (emit->pre_len) print_hex(emit->pre, emit->pre_len);
        printf("/");
        print_hex(emit->bytes, emit->len);
        printf("\n");
    }
    d2k_actions_free(&actions);
    d2k_plan_free(plan);
    return 0;
}
