#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t rd24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static void wr16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void wr24(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 16);
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)value;
}

static int find_bytes(const uint8_t *buf, size_t length, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (needle_len > length) return -1;
    for (size_t i = 0; i + needle_len <= length; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0) return (int)i;
    }
    return -1;
}

/* В modern-шаблоне есть padding, где тоже встречается строка http/1.1;
   настоящий ALPN ищем по записи REC_ALPN (0x0010) перед protocol_len. */
static int find_alpn(const uint8_t *buf, size_t length)
{
    size_t start = 0;
    while (start + 8 <= length) {
        int found = find_bytes(buf + start, length - start, "http/1.1");
        if (found < 0) return -1;
        size_t pos = start + (size_t)found;
        /* type(2)+len(2)+list_len(2)+h2(3)+proto_len(1) = 10 байт
           до protocol "http/1.1" в modern-шаблоне. */
        if (pos >= 10 && rd16(buf + pos - 10) == 0x0010) return (int)pos;
        start = pos + 1;
    }
    return -1;
}

static void to_hex(const uint8_t *bytes, size_t length, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        out[2 * i] = digits[bytes[i] >> 4];
        out[2 * i + 1] = digits[bytes[i] & 0x0f];
    }
    out[2 * length] = '\0';
}

/* Убрать расширение ALPN из modern-шаблона: шаблон содержит h2+http/1.1,
   а для C-ветки «клиент без ALPN» нужен тот же ClientHello без ext 0x0010. */
static int strip_alpn(uint8_t *buf, size_t *length)
{
    int pos = find_alpn(buf, *length);
    if (pos < 10) return -1;
    size_t ext = (size_t)pos - 10; /* type/len/list_len/h2/proto_len */
    if (rd16(buf + ext) != 0x0010) return -1;
    size_t ext_total = 4 + rd16(buf + ext + 2);
    if (ext + ext_total > *length) return -1;

    size_t off = 9 + 2 + 32;
    if (off >= *length) return -1;
    off += 1 + buf[off];
    if (off + 2 > *length) return -1;
    off += 2 + rd16(buf + off);
    if (off >= *length) return -1;
    off += 1 + buf[off];
    if (off + 2 > *length) return -1;
    size_t exts_len_off = off;

    memmove(buf + ext, buf + ext + ext_total, *length - (ext + ext_total));
    *length -= ext_total;
    wr16(buf + exts_len_off, rd16(buf + exts_len_off) - (uint16_t)ext_total);
    wr24(buf + 6, rd24(buf + 6) - (uint32_t)ext_total);
    wr16(buf + 3, rd16(buf + 3) - (uint16_t)ext_total);
    return 0;
}

static void run_case(const char *label, const uint8_t *hello, size_t hello_len,
                     d2k_verdict verdict, int rx_cut, const char *measure_path,
                     int ech_offer)
{
    task t;
    memset(&t, 0, sizeof t);
    t.transport = 6;
    if (hello_len > sizeof t.trig) return;
    memcpy(t.trig, hello, hello_len);
    t.trig_len = hello_len;
    t.res.verdict = verdict;
    t.vol.rx_cut = (uint8_t)rx_cut;
    t.ech_offer = (uint8_t)ech_offer;
    snprintf(t.measure_path, sizeof t.measure_path, "%s", measure_path);
    uint8_t list[256];
    size_t list_len = 0;
    int allowed = client_alpn_nonhttp(&t, list, sizeof list, &list_len);
    printf("%s %d\n", label, allowed ? 1 : 0);
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    uint8_t hello[4096];
    size_t hello_len = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, "example.test", hello,
                               sizeof hello, &hello_len) != 0) {
        fprintf(stderr, "hello profile failed\n");
        return 2;
    }
    if (d2k_hello_shape(hello, hello_len) != D2K_SHAPE_MODERN) {
        fprintf(stderr, "profile is not MODERN\n");
        return 2;
    }

    uint8_t mqtt[4096];
    memcpy(mqtt, hello, hello_len);
    size_t mqtt_len = hello_len;
    int http_pos = find_alpn(mqtt, mqtt_len);
    if (http_pos < 4) {
        fprintf(stderr, "http ALPN missing\n");
        return 2;
    }
    memcpy(mqtt + http_pos, "mqtt/1.1", 8);
    /* В шаблоне первым идёт h2; заменяем и его, иначе d2k_alpn_is_http
       увидит h2 и отнесёт клиента к HTTP. */
    memcpy(mqtt + http_pos - 4, "\x02h3", 3);

    uint8_t no_alpn[4096];
    memcpy(no_alpn, hello, hello_len);
    size_t no_alpn_len = hello_len;
    if (strip_alpn(no_alpn, &no_alpn_len) != 0) {
        fprintf(stderr, "strip ALPN failed\n");
        return 2;
    }
    size_t alpn_len = 0;
    if (d2k_hello_alpn(no_alpn, no_alpn_len, NULL, 0, &alpn_len) != 0) {
        fprintf(stderr, "stripped hello still has ALPN\n");
        return 2;
    }

    FILE *variants = fopen(argv[1], "w");
    if (!variants) {
        perror(argv[1]);
        return 2;
    }
    char hex[8193];
    to_hex(hello, hello_len, hex);
    fprintf(variants, "http %s\n", hex);
    to_hex(mqtt, mqtt_len, hex);
    fprintf(variants, "mqtt %s\n", hex);
    to_hex(no_alpn, no_alpn_len, hex);
    fprintf(variants, "no_alpn %s\n", hex);
    fclose(variants);

    run_case("http", hello, hello_len, D2K_V_PREFIX, 0, "", 0);
    run_case("mqtt", mqtt, mqtt_len, D2K_V_PREFIX, 0, "", 0);
    run_case("no_alpn", no_alpn, no_alpn_len, D2K_V_PREFIX, 0, "", 0);
    run_case("clear", hello, hello_len, D2K_V_CLEAR, 0, "", 0);
    run_case("rx_cut", hello, hello_len, D2K_V_PREFIX, 1, "", 0);
    run_case("measure_path", hello, hello_len, D2K_V_PREFIX, 0, "/x", 0);
    return 0;
}
