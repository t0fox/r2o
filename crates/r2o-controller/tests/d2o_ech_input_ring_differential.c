/* C/Rust differential: on_shape ech_inputs[8] -> fill_hellos.
 * C-сторона кладёт ECH-снимок в production ring и вызывает production
 * fill_hellos; Rust — R2oEchInputCache + queue_with_planned.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static int ech_offer_hello_sized(const char *name, size_t payload, uint8_t *out,
                                 size_t cap, size_t *len)
{
    size_t n = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, name, out, cap, &n) != 0) return -1;
    size_t p = 9 + 2 + 32;
    p += 1 + out[p];
    p += 2 + ((size_t)out[p] << 8 | out[p + 1]);
    p += 1 + out[p];
    size_t ext_len_off = p;
    const size_t enc = 32, elen = 10 + enc + payload;
    if (n + 4 + elen > cap) return -1;
    uint8_t *e = out + n;
    e[0] = 0xfe; e[1] = 0x0d; e[2] = (uint8_t)(elen >> 8); e[3] = (uint8_t)elen;
    e[4] = 0; e[5] = 0; e[6] = 1; e[7] = 0; e[8] = 1; e[9] = 0x5a;
    e[10] = 0; e[11] = (uint8_t)enc;
    for (size_t i = 0; i < enc; i++) e[12 + i] = (uint8_t)(i * 7 + 3);
    e[12 + enc] = (uint8_t)(payload >> 8); e[13 + enc] = (uint8_t)payload;
    for (size_t i = 0; i < payload; i++) e[14 + enc + i] = (uint8_t)(i * 13 + 1);
    n += 4 + elen;
    size_t ext = ((size_t)out[ext_len_off] << 8 | out[ext_len_off + 1]) + 4 + elen;
    out[ext_len_off] = (uint8_t)(ext >> 8); out[ext_len_off + 1] = (uint8_t)ext;
    size_t hs = n - 9, rec = n - 5;
    out[6] = (uint8_t)(hs >> 16); out[7] = (uint8_t)(hs >> 8); out[8] = (uint8_t)hs;
    out[3] = (uint8_t)(rec >> 8); out[4] = (uint8_t)rec;
    *len = n;
    return 0;
}

int main(void)
{
    d2k_sched *s = calloc(1, sizeof *s);
    task *t = calloc(1, sizeof *t);
    if (!s || !t) return 2;
    s->now_ms = 1000;
    uint8_t hello[2048];
    size_t hello_len = 0;
    if (ech_offer_hello_sized("ech-ring.example.com", 144, hello,
                              sizeof hello, &hello_len) != 0) return 3;
    snprintf(s->ech_inputs[0].name, sizeof s->ech_inputs[0].name,
             "%s", "ech-ring.example.com");
    memcpy(s->ech_inputs[0].bytes, hello, hello_len);
    s->ech_inputs[0].len = hello_len;
    s->ech_inputs[0].family = 4;
    s->ech_inputs[0].observed_ms = 1000;
    s->ech_inputs[0].opts_known = 1;
    memcpy(s->ech_inputs[0].opts, (uint8_t[]){1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0}, 12);
    s->ech_inputs[0].opts_len = 12;

    snprintf(t->name, sizeof t->name, "%s", "ech-ring.example.com");
    t->transport = 6;
    t->family = 4;
    t->trigger_shape = D2K_LINK_SHAPE_ECH_TCP;
    int rc = fill_hellos(s, t);
    printf("fill_rc=%d\n", rc);
    printf("trig_set=%d\n", t->trig_len != 0);
    printf("ech_offer=%d\n", d2k_hello_ech_offer(t->trig, t->trig_len, NULL));
    printf("opts_known=%d\n", t->client_opts_known);
    free(s); free(t);
    return 0;
}
