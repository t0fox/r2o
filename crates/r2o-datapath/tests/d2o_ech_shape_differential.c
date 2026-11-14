/* C-оракул: ECH/ANY-ветвь d2k_session_packet (session.c:2320-2338).
 *
 * Здесь нет сессии: проверяются ровно те функции, которые вызывает ветвь —
 * d2k_plantab_has_ech_target и d2k_plantab_find_target, — на тех же формах,
 * что вычисляет session.c. Печатается id выбранного плана или "-".
 */
#include <stdio.h>
#include <string.h>

#include "d2k_plan.h"
#include "d2k_plans.h"
#include "d2k_tls.h"

static size_t put_tlv(uint8_t *o, size_t off, uint16_t kind,
                      const uint8_t *value, size_t length) {
    o[off] = (uint8_t)(kind >> 8);
    o[off + 1] = (uint8_t)kind;
    o[off + 2] = (uint8_t)(length >> 8);
    o[off + 3] = (uint8_t)length;
    memcpy(o + off + 4, value, length);
    return off + 4 + length;
}

/* План с фиксированным id: REC_ID + REC_PROTO + REC_PAYLOAD + REC_FAKE. */
static size_t plan_blob(uint8_t *o, uint8_t marker) {
    uint8_t id[16];
    memset(id, marker, sizeof id);
    static const uint8_t transport[] = {6, 1};
    uint8_t payload[6] = {0, 1, 'P', 'L', '0' + (char)(marker % 10), '!'};
    static const uint8_t fake[] = {0, 1, 0, 0, 1, 0, 0, 0, 0, 0};
    memcpy(o, "D2KP", 4);
    o[4] = 0; o[5] = 1;
    o[6] = 0; o[7] = 0;
    o[8] = 0; o[9] = 0;
    o[10] = 0; o[11] = 4;
    size_t off = 12;
    off = put_tlv(o, off, 0x0001, id, sizeof id);
    off = put_tlv(o, off, 0x0002, transport, sizeof transport);
    off = put_tlv(o, off, 0x0010, payload, sizeof payload);
    off = put_tlv(o, off, 0x0101, fake, sizeof fake);
    return off;
}

static d2k_plan *load(uint8_t marker) {
    uint8_t blob[128];
    size_t length = plan_blob(blob, marker);
    d2k_plan *plan = NULL;
    char error[200];
    if (d2k_plan_load(blob, length, &plan, error, sizeof error) != 0) {
        fprintf(stderr, "plan %u: %s\n", marker, error);
        return NULL;
    }
    return plan;
}

static void print_plan(const char *name, const d2k_plan *plan) {
    printf("%s ", name);
    if (!plan) {
        printf("-\n");
        return;
    }
    const uint8_t *id = d2k_plan_id(plan);
    for (size_t i = 0; i < 16; i++) printf("%02x", id[i]);
    printf("\n");
}

/* --- Байты: полный и оборванный ClientHello TLS 1.3 --------------------- */

static size_t put16(uint8_t *o, size_t off, unsigned value) {
    o[off] = (uint8_t)(value >> 8);
    o[off + 1] = (uint8_t)value;
    return off + 2;
}

/* SNI "example.com" + supported_versions 0x0304; ext_len_claim и rec_len_claim
 * позволяют оборвать блок расширений, оставив supported_versions целиком. */
static size_t client_hello(uint8_t *o, size_t ext_len_claim, size_t rec_len_claim,
                           size_t hs_len_claim, int with_tls13) {
    static const char host[] = "example.com";
    const size_t host_len = sizeof host - 1;
    for (size_t i = 0; i < 256; i++) o[i] = 0;
    size_t off = 0;
    o[off++] = 0x16; o[off++] = 0x03; o[off++] = 0x03;
    off = put16(o, off, (unsigned)rec_len_claim);
    o[off++] = 0x01;
    o[off++] = (uint8_t)(hs_len_claim >> 16);
    o[off++] = (uint8_t)(hs_len_claim >> 8);
    o[off++] = (uint8_t)hs_len_claim;
    o[off++] = 0x03; o[off++] = 0x03;
    for (int i = 0; i < 32; i++) o[off++] = (uint8_t)(0x20 + i);
    o[off++] = 0; /* session id */
    off = put16(o, off, 2);
    o[off++] = 0x13; o[off++] = 0x01;
    o[off++] = 1; o[off++] = 0;
    const size_t ext_len_at = off;
    off = put16(o, off, (unsigned)ext_len_claim);
    /* server_name */
    off = put16(o, off, 0x0000);
    off = put16(o, off, (unsigned)(2 + 1 + 2 + host_len));
    off = put16(o, off, (unsigned)(1 + 2 + host_len));
    o[off++] = 0;
    off = put16(o, off, (unsigned)host_len);
    memcpy(o + off, host, host_len);
    off += host_len;
    if (with_tls13) {
        off = put16(o, off, 0x002b);
        off = put16(o, off, 3);
        o[off++] = 2;
        off = put16(o, off, 0x0304);
    }
    (void)ext_len_at;
    return off;
}

/* Форма из session.c:2320-2338 — дословно те же условия. */
static uint8_t session_shape(const uint8_t *payload, size_t len,
                             d2k_plantab *table, const uint8_t *addr,
                             uint8_t family, uint16_t probe_port) {
    d2k_tls_info tls;
    memset(&tls, 0, sizeof tls);
    (void)d2k_tls_parse(payload, len, &tls);
    uint8_t shape = D2K_PLAN_SHAPE_ANY;
    if (tls.is_client_hello && tls.have_sni) {
        if (tls.is_tls13) {
            shape = tls.ech_offer ? D2K_PLAN_SHAPE_ECH_TCP : D2K_PLAN_SHAPE_MODERN;
            if (!tls.ech_offer && tls.exts_truncated &&
                d2k_plantab_has_ech_target(table, payload + tls.sni_off, tls.sni_len,
                                           addr, family, probe_port)) {
                shape = D2K_PLAN_SHAPE_ANY;
            }
        } else if (!tls.exts_truncated) {
            shape = D2K_PLAN_SHAPE_LEGACY;
        }
    }
    return shape;
}

static void decision(const char *name, d2k_plantab *table, const uint8_t *payload,
                     size_t len, const uint8_t *addr, uint8_t family,
                     uint16_t probe_port) {
    uint8_t shape = session_shape(payload, len, table, addr, family, probe_port);
    size_t sni_off = 0, sni_len = 0;
    d2k_tls_info tls;
    memset(&tls, 0, sizeof tls);
    (void)d2k_tls_parse(payload, len, &tls);
    if (tls.have_sni) { sni_off = tls.sni_off; sni_len = tls.sni_len; }
    const d2k_plan *plan = d2k_plantab_find_target(
        table, sni_len ? payload + sni_off : NULL, sni_len, addr, family, 1000, shape,
        probe_port);
    printf("%s ", name);
    (void)shape;
    if (!plan) {
        printf("-\n");
        return;
    }
    const uint8_t *id = d2k_plan_id(plan);
    for (size_t i = 0; i < 16; i++) printf("%02x", id[i]);
    printf("\n");
}

int main(void) {
    static const uint8_t host[] = "example.com";
    static const uint8_t addr[4] = {198, 51, 100, 20};
    uint8_t hello[256];

    /* --- 1. has_ech_target: точное имя, форма, suffix, addr, проба. --- */
    {
        d2k_plantab *t = d2k_plantab_new(64);
        d2k_plan *ech = load(0xE1);
        d2k_plan *modern = load(0x22);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, modern,
                                          D2K_PLAN_SHAPE_MODERN, 0, 4);
        printf("H1 modern-only %d\n",
               d2k_plantab_has_ech_target(t, host, sizeof host - 1, addr, 4, 0));
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, ech,
                                          D2K_PLAN_SHAPE_ECH_TCP, 0, 4);
        printf("H2 ech-name %d\n",
               d2k_plantab_has_ech_target(t, host, sizeof host - 1, addr, 4, 0));
        printf("H3 ech-other-name %d\n",
               d2k_plantab_has_ech_target(t, (const uint8_t *)"other.example",
                                          sizeof "other.example" - 1, addr, 4, 0));
        d2k_plantab_free(t);
    }
    {
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_suffix_family(t, (const uint8_t *)"example.com",
                                            sizeof "example.com" - 1, 1000, load(0xE2),
                                            D2K_PLAN_SHAPE_ECH_TCP, 4);
        printf("H4 ech-suffix %d\n",
               d2k_plantab_has_ech_target(t, host, sizeof host - 1, addr, 4, 0));
        d2k_plantab_free(t);
    }
    {
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_addr_shaped(t, addr, 4, 1000, load(0xE3),
                                          D2K_PLAN_SHAPE_ECH_TCP);
        printf("H5 ech-addr %d\n",
               d2k_plantab_has_ech_target(t, host, sizeof host - 1, addr, 4, 0));
        printf("H6 ech-addr-other %d\n",
               d2k_plantab_has_ech_target(t, host, sizeof host - 1,
                                          (const uint8_t *)"\x01\x02\x03\x04", 4, 0));
        d2k_plantab_free(t);
    }
    {
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0xE4),
                                          D2K_PLAN_SHAPE_ECH_TCP, 40000, 4);
        printf("H7 ech-probe %d\n",
               d2k_plantab_has_ech_target(t, host, sizeof host - 1, addr, 4, 40000));
        printf("H8 ech-probe-other-port %d\n",
               d2k_plantab_has_ech_target(t, host, sizeof host - 1, addr, 4, 40001));
        printf("H9 ech-probe-no-port %d\n",
               d2k_plantab_has_ech_target(t, host, sizeof host - 1, addr, 4, 0));
        d2k_plantab_free(t);
    }

    /* --- 2. find_target: ANY не берёт ECH-запись, MODERN берёт MODERN. --- */
    {
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0xE5),
                                          D2K_PLAN_SHAPE_ECH_TCP, 0, 4);
        print_plan("F1 any-ech-name",
                   d2k_plantab_find_target(t, host, sizeof host - 1, addr, 4, 1000, 0, 0));
        print_plan("F2 modern-ech-name",
                   d2k_plantab_find_target(t, host, sizeof host - 1, addr, 4, 1000,
                                           D2K_PLAN_SHAPE_MODERN, 0));
        print_plan("F3 ech-ech-name",
                   d2k_plantab_find_target(t, host, sizeof host - 1, addr, 4, 1000,
                                           D2K_PLAN_SHAPE_ECH_TCP, 0));
        d2k_plantab_free(t);
    }
    {
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0x33),
                                          D2K_PLAN_SHAPE_MODERN, 0, 4);
        print_plan("F4 any-modern-name",
                   d2k_plantab_find_target(t, host, sizeof host - 1, addr, 4, 1000, 0, 0));
        print_plan("F5 modern-modern-name",
                   d2k_plantab_find_target(t, host, sizeof host - 1, addr, 4, 1000,
                                           D2K_PLAN_SHAPE_MODERN, 0));
        d2k_plantab_free(t);
    }
    {
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0x44),
                                          D2K_PLAN_SHAPE_GRANDFATHER, 0, 4);
        print_plan("F6 any-grandfather",
                   d2k_plantab_find_target(t, host, sizeof host - 1, addr, 4, 1000, 0, 0));
        d2k_plantab_free(t);
    }
    {
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_suffix_family(t, (const uint8_t *)"example.com",
                                            sizeof "example.com" - 1, 1000, load(0xE6),
                                            D2K_PLAN_SHAPE_ECH_TCP, 4);
        print_plan("F7 any-ech-suffix",
                   d2k_plantab_find_target(t, host, sizeof host - 1, addr, 4, 1000, 0, 0));
        print_plan("F8 ech-ech-suffix",
                   d2k_plantab_find_target(t, host, sizeof host - 1, addr, 4, 1000,
                                           D2K_PLAN_SHAPE_ECH_TCP, 0));
        d2k_plantab_free(t);
    }

    /* --- 3. Решение по реальным байтам ClientHello. --- */
    {
        /* Оборванный TLS 1.3, ECH-запись имени: форма ANY, ECH-план не
         * применяется — используется план по умолчанию. */
        size_t len = client_hello(hello, 300, 400, 390, 1);
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0xE7),
                                          D2K_PLAN_SHAPE_ECH_TCP, 0, 4);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0x77),
                                          D2K_PLAN_SHAPE_MODERN, 0, 4);
        decision("D1 truncated-ech", t, hello, len, addr, 4, 0);
        d2k_plantab_free(t);
    }
    {
        /* Тот же оборванный hello без ECH-записи: MODERN-план применяется. */
        size_t len = client_hello(hello, 300, 400, 390, 1);
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0x78),
                                          D2K_PLAN_SHAPE_MODERN, 0, 4);
        decision("D2 truncated-no-ech", t, hello, len, addr, 4, 0);
        d2k_plantab_free(t);
    }
    {
        /* Полный TLS 1.3 при ECH-записи: форма MODERN, MODERN-план. */
        size_t len = client_hello(hello, 0, 0, 0, 1);
        /* Пересчитать точные длины: ext_len_claim=0 означает «как есть». */
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0xE8),
                                          D2K_PLAN_SHAPE_ECH_TCP, 0, 4);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0x79),
                                          D2K_PLAN_SHAPE_MODERN, 0, 4);
        /* Пакет с честными длинами: хвост 5+4+34+1+4+2 = 52; расширения 20+7. */
        size_t total = 52 + 20 + 7;
        hello[3] = (uint8_t)((total - 5) >> 8);
        hello[4] = (uint8_t)(total - 5);
        hello[6] = (uint8_t)((total - 9) >> 16);
        hello[7] = (uint8_t)((total - 9) >> 8);
        hello[8] = (uint8_t)(total - 9);
        hello[50] = 0; hello[51] = 27;
        (void)len;
        decision("D3 complete-ech", t, hello, total, addr, 4, 0);
        d2k_plantab_free(t);
    }
    {
        /* Оборванный ClientHello без TLS 1.3: формы нет, MODERN не берётся. */
        size_t len = client_hello(hello, 300, 400, 390, 0);
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0x7A),
                                          D2K_PLAN_SHAPE_LEGACY, 0, 4);
        decision("D4 truncated-no-tls13", t, hello, len, addr, 4, 0);
        d2k_plantab_free(t);
    }
    {
        /* Оборванный TLS 1.3, ECH-запись только по адресу. */
        size_t len = client_hello(hello, 300, 400, 390, 1);
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_addr_shaped(t, addr, 4, 1000, load(0xE9),
                                          D2K_PLAN_SHAPE_ECH_TCP);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0x7B),
                                          D2K_PLAN_SHAPE_MODERN, 0, 4);
        decision("D5 truncated-ech-addr", t, hello, len, addr, 4, 0);
        d2k_plantab_free(t);
    }
    {
        /* Управляющая проба: ECH-проба того же порта при форме ANY. */
        size_t len = client_hello(hello, 300, 400, 390, 1);
        d2k_plantab *t = d2k_plantab_new(64);
        (void)d2k_plantab_set_name_family(t, host, sizeof host - 1, 1000, load(0xEA),
                                          D2K_PLAN_SHAPE_ECH_TCP, 40000, 4);
        decision("D6 truncated-ech-probe", t, hello, len, addr, 4, 40000);
        d2k_plantab_free(t);
    }
    return 0;
}
