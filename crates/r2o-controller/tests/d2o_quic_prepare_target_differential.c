/* C-оракул: production `d2k_quic_prepare_target` (core/quichello.c:287-310),
 * `d2k_quic_hello_rename` (:312-321) и `d2k_quic_probe_initial` (:276-279). */
#include "d2k_hello.h"
#include "d2k_quic.h"
#include "d2k_quichello.h"
#include "d2k_quicwire.h"
#include "test_quic_vector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_hex(const uint8_t *bytes, size_t n)
{
    for (size_t index = 0; index < n; index++) {
        printf("%02x", bytes[index]);
    }
}

static void emit(const char *label, int rc, int used)
{
    printf("%s,%d,%d,", label, rc, used);
    if (rc != 0) {
        printf("-\n");
        return;
    }
    /* Вызывающий передаёт выход в out; печать делает case_* ниже. */
}

static int case_prepare(const char *label, const uint8_t *sample, size_t sample_len,
                        const char *sni, int print_hello)
{
    uint8_t out[1500];
    size_t out_len = 0;
    int used = 0;
    int rc = d2k_quic_prepare_target(sample, sample_len, sni, out, sizeof out,
                                     &out_len, &used);
    emit(label, rc, used);
    if (rc != 0) {
        return 0;
    }
    uint8_t ch[8192];
    size_t ch_len = 0;
    if (d2k_quic_client_hello(out, out_len, ch, sizeof ch, &ch_len) != 0) {
        printf("nohello\n");
        return 0;
    }
    char name[256];
    name[0] = '\0';
    int has_name = d2k_quic_sni(out, out_len, name, sizeof name) == 0;
    printf("%s,%zu,", has_name && name[0] ? name : "-", ch_len);
    if (print_hello) {
        print_hex(ch, ch_len);
    } else {
        printf("-");
    }
    printf("\n");
    return 0;
}

int main(void)
{
    const char *sample_path = getenv("R2O_QUIC_PREPARE_SAMPLE");
    if (sample_path) {
        FILE *f = fopen(sample_path, "wb");
        if (!f) { return 2; }
        for (size_t index = 0; index < sizeof d2k_test_v1_initial; index++) {
            fprintf(f, "%02x", d2k_test_v1_initial[index]);
        }
        fclose(f);
    }

    /* Переименование снимка: CH детерминирован, сравниваем побайтово. */
    case_prepare("sample-name", d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                 "target.example", 1);
    case_prepare("sample-same", d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                 "example.com", 1);
    case_prepare("sample-ip", d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                 "203.0.113.7", 1);

    /* Пачка QSN не пересобирается. */
    static const uint8_t qsn[] = {'Q', 'S', 'N', 1};
    case_prepare("qsn", qsn, sizeof qsn, "target.example", 0);

    /* Непригодный снимок: свежий донорский PROFILE (used_sample=0). */
    case_prepare("truncated", d2k_test_v1_initial, 100, "target.example", 0);
    static const uint8_t garbage[20] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    };
    case_prepare("garbage", garbage, sizeof garbage, "target.example", 0);
    case_prepare("null", NULL, 0, "target.example", 0);

    /* Пустой SNI — отказ до свежего профиля. */
    case_prepare("empty-sni", d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                 "", 0);
    return 0;
}
