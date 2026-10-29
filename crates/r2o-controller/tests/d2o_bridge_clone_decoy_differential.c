#include "d2k_hello.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HELLO_CAP 4096

static int build_hello(d2k_shape shape, const char *name,
                       uint8_t out[HELLO_CAP], size_t *len)
{
    return d2k_hello_from_profile(shape, name, out, HELLO_CAP, len);
}

static int build_variant(const char *variant, int control,
                         uint8_t out[HELLO_CAP], size_t *len)
{
    size_t off = 0, name_len = 0;
    char long_name[257];
    memset(out, 0, HELLO_CAP);
    *len = 0;

    if (strcmp(variant, "none") == 0) {
        return 0;
    }
    if (strcmp(variant, "short") == 0) {
        out[0] = 0x16;
        out[1] = 0x03;
        *len = 2;
        return 0;
    }
    if (strcmp(variant, "sni_255") == 0 || strcmp(variant, "sni_256") == 0) {
        size_t n = strcmp(variant, "sni_255") == 0 ? 255 : 256;
        memset(long_name, 'a', n);
        long_name[n] = '\0';
        return build_hello(control ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN,
                           long_name, out, len);
    }

    if (build_hello(control ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN,
                    control ? "disk.rzd.ru" : "target.example", out, len) != 0) {
        return -1;
    }
    if (!control && strcmp(variant, "truncated") == 0) {
        (*len)--;
    } else if (!control && strcmp(variant, "padded") == 0) {
        static const uint8_t padding[] = {0xde, 0xad, 0xbe, 0xef};
        size_t record_len = (size_t)((unsigned)out[3] << 8 | out[4]) + sizeof padding;
        memcpy(out + *len, padding, sizeof padding);
        *len += sizeof padding;
        out[3] = (uint8_t)(record_len >> 8);
        out[4] = (uint8_t)record_len;
    } else if (!control && strcmp(variant, "wrong_record_type") == 0) {
        out[0] = 0x17;
    } else if (strcmp(variant, "without_sni") == 0) {
        if (d2k_hello_sni(out, *len, &off, &name_len) != 0 || off < 3) {
            return -1;
        }
        out[off - 3] = 1;
    } else if (control && strcmp(variant, "nul_sni") == 0) {
        if (d2k_hello_sni(out, *len, &off, &name_len) != 0 || !name_len) {
            return -1;
        }
        out[off] = 0;
    }
    return 0;
}

/* Mirror bridge_input's clone and the d2k_opts_decoy control fallback. */
static size_t select_decoy(const uint8_t *trigger, size_t trigger_len, int snapped,
                           const uint8_t *control, size_t control_len,
                           uint8_t out[HELLO_CAP])
{
    size_t off = 0, name_len = 0, cloned_len = 0;
    if (snapped && trigger_len > 5 && trigger[0] == 0x16 &&
        control && control_len >= 2) {
        char benign[256];
        if (d2k_hello_sni(control, control_len, &off, &name_len) == 0 &&
            name_len > 0 && name_len < sizeof benign &&
            !memchr(control + off, 0, name_len)) {
            memcpy(benign, control + off, name_len);
            benign[name_len] = '\0';
            if (d2k_hello_rename(trigger + 5, trigger_len - 5, benign,
                                 out + 5, HELLO_CAP - 5, &cloned_len) == 0 &&
                cloned_len <= 0xffff) {
                memcpy(out, trigger, 3);
                out[3] = (uint8_t)(cloned_len >> 8);
                out[4] = (uint8_t)cloned_len;
                return cloned_len + 5;
            }
        }
    }

    if (control && control_len >= 2) {
        memcpy(out, control, control_len);
        return control_len;
    }
    return 0;
}

static void print_hex(const uint8_t *bytes, size_t len)
{
    size_t i;
    if (!len) {
        putchar('-');
        return;
    }
    for (i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
}

int main(int argc, char **argv)
{
    FILE *fixture;
    char line[256];
    if (argc != 2 || !(fixture = fopen(argv[1], "r"))) {
        fprintf(stderr, "usage: %s fixture.tsv\n", argv[0]);
        return 2;
    }
    while (fgets(line, sizeof line, fixture)) {
        char name[64], trigger_variant[64], control_variant[64];
        int snapped;
        uint8_t trigger[HELLO_CAP], control[HELLO_CAP], decoy[HELLO_CAP];
        size_t trigger_len = 0, control_len = 0, decoy_len;
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        if (sscanf(line, "%63s %d %63s %63s", name, &snapped,
                   trigger_variant, control_variant) != 4) {
            fprintf(stderr, "invalid fixture row: %s", line);
            fclose(fixture);
            return 2;
        }
        if (build_variant(trigger_variant, 0, trigger, &trigger_len) != 0 ||
            build_variant(control_variant, 1, control, &control_len) != 0) {
            fprintf(stderr, "could not build fixture row %s\n", name);
            fclose(fixture);
            return 2;
        }
        decoy_len = select_decoy(trigger, trigger_len, snapped, control,
                                 control_len, decoy);
        printf("%s\t", name);
        print_hex(decoy, decoy_len);
        putchar('\n');
    }
    fclose(fixture);
    return 0;
}
