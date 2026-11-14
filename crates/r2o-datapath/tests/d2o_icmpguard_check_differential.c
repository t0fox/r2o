/* C-оракул: d2k_icmpguard_note/check (datapath/icmpguard.c:49-110).
 *
 * Один свежий guard на кейс: сначала note на «фальшивку» с пониженным TTL,
 * затем check на ICMP time-exceeded с цитатой. Печатаются note/check и
 * счётчики noted/dropped.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_icmpguard.h"

static void w16(uint8_t *p, unsigned v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* IPv4 + 8 байт L4. Возвращает длину; ip_len_override!=0 подменяет поле. */
static size_t inner4(uint8_t *o, uint8_t proto, uint8_t ttl, uint16_t id,
                     uint16_t sport, uint16_t dport, uint16_t w0, uint16_t w1,
                     uint16_t ip_len_override) {
    size_t total = 28;
    memset(o, 0, total);
    o[0] = 0x45;
    w16(o + 2, ip_len_override ? ip_len_override : (unsigned)total);
    w16(o + 4, id);
    o[8] = ttl;
    o[9] = proto;
    o[12] = 192; o[13] = 0; o[14] = 2; o[15] = 10;
    o[16] = 198; o[17] = 51; o[18] = 100; o[19] = 20;
    w16(o + 20, sport);
    w16(o + 22, dport);
    w16(o + 24, w0);
    w16(o + 26, w1);
    return total;
}

static size_t inner4_fragment(uint8_t *o) {
    size_t total = inner4(o, 6, 63, 0x1234, 50000, 443, 1, 2, 0);
    w16(o + 6, 1); /* fragment offset 1 — не первый фрагмент */
    return total;
}

static size_t inner4_wrong_proto(uint8_t *o) {
    return inner4(o, 1, 63, 0x1234, 50000, 443, 1, 2, 0);
}

static size_t icmp4(uint8_t *o, uint8_t type, uint8_t code,
                    const uint8_t *quote, size_t quote_len) {
    size_t total = 20 + 8 + quote_len;
    memset(o, 0, total);
    o[0] = 0x45;
    w16(o + 2, (unsigned)total);
    o[8] = 64;
    o[9] = 1;
    o[12] = 203; o[13] = 0; o[14] = 113; o[15] = 9;
    o[16] = 192; o[17] = 0; o[18] = 2; o[19] = 10;
    o[20] = type; o[21] = code;
    if (quote_len) memcpy(o + 28, quote, quote_len);
    return total;
}

static size_t icmp4_fragment(uint8_t *o, const uint8_t *quote, size_t quote_len) {
    size_t total = icmp4(o, 11, 0, quote, quote_len);
    w16(o + 6, 1); /* outer fragment: не первый */
    return total;
}

static size_t inner6(uint8_t *o, uint8_t proto, uint8_t ttl,
                     uint16_t sport, uint16_t dport, uint16_t w0, uint16_t w1) {
    size_t total = 48;
    memset(o, 0, total);
    o[0] = 0x60;
    w16(o + 4, 8);
    o[6] = proto;
    o[7] = ttl;
    o[8] = 0x20; o[9] = 0x01; o[10] = 0x0d; o[11] = 0xb8;
    o[23] = 1;
    o[24] = 0x20; o[25] = 0x01; o[26] = 0x0d; o[27] = 0xb8;
    o[39] = 2;
    w16(o + 40, sport);
    w16(o + 42, dport);
    w16(o + 44, w0);
    w16(o + 46, w1);
    return total;
}

static size_t icmp6(uint8_t *o, uint8_t type, uint8_t code,
                    const uint8_t *quote, size_t quote_len) {
    size_t total = 40 + 8 + quote_len;
    memset(o, 0, total);
    o[0] = 0x60;
    w16(o + 4, (unsigned)(8 + quote_len));
    o[6] = 58;
    o[7] = 64;
    o[8] = 0x20; o[9] = 0x01; o[10] = 0x0d; o[11] = 0xb8;
    o[23] = 9;
    o[24] = 0x20; o[25] = 0x01; o[26] = 0x0d; o[27] = 0xb8;
    o[39] = 1;
    o[40] = type; o[41] = code;
    if (quote_len) memcpy(o + 48, quote, quote_len);
    return total;
}

static void run(const char *name, const uint8_t *fake, size_t fake_len,
                uint8_t orig_ttl, uint64_t note_now, const uint8_t *icmp,
                size_t icmp_len, uint64_t check_now) {
    d2k_icmpguard guard;
    memset(&guard, 0, sizeof guard);
    int noted = d2k_icmpguard_note(&guard, fake, fake_len, orig_ttl, note_now);
    int checked = d2k_icmpguard_check(&guard, icmp, icmp_len, check_now);
    printf("%s note=%d check=%d noted=%llu dropped=%llu\n", name, noted, checked,
           (unsigned long long)d2k_icmpguard_noted(&guard),
           (unsigned long long)d2k_icmpguard_dropped(&guard));
}

int main(void) {
    uint8_t fake[128];
    uint8_t quote[128];
    uint8_t icmp[256];
    size_t fake_len;
    size_t quote_len;
    size_t icmp_len;

    fake_len = inner4(fake, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    quote_len = inner4(quote, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("A tcp-exact", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    fake_len = inner4(fake, 17, 63, 0x1234, 50000, 443, 0x0010, 0x0000, 0);
    quote_len = inner4(quote, 17, 63, 0x1234, 50000, 443, 0x0010, 0x0000, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("B udp-exact", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    fake_len = inner4(fake, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    quote_len = inner4(quote, 6, 63, 0x1234, 50000, 443, 0x0103, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("C seq-diff", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    quote_len = inner4(quote, 6, 64, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("D ttl-greater", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    quote_len = inner4(quote, 6, 62, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("E ttl-lower", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    quote_len = inner4(quote, 6, 63, 0x1234, 50001, 443, 0x0102, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("F sport-diff", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    quote_len = inner4(quote, 6, 63, 0x1234, 50000, 444, 0x0102, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("G dport-diff", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    quote_len = inner4(quote, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 29);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("H iplen-diff", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    quote_len = inner4(quote, 6, 63, 0x9999, 50000, 443, 0x0102, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("I ipid-diff", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    quote_len = inner4(quote, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("J orig-ttl-equal", fake, fake_len, 63, 1000, icmp, icmp_len, 1000);

    fake_len = inner4(fake, 6, 63, 0, 50000, 443, 0x0102, 0x0304, 0);
    quote_len = inner4(quote, 6, 63, 0x9999, 50000, 443, 0x0102, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("K ipid-zero", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    fake_len = inner4(fake, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    quote_len = inner4(quote, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("L expired", fake, fake_len, 64, 1000, icmp, icmp_len,
        1000ull + 5000000000ull + 1ull);
    run("M kept-5s", fake, fake_len, 64, 1000, icmp, icmp_len,
        1000ull + 5000000000ull);

    icmp_len = icmp4(icmp, 3, 0, quote, quote_len);
    run("N icmp-type", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    fake_len = inner4(fake, 17, 63, 0x1234, 50000, 443, 0x0010, 0x1111, 0);
    quote_len = inner4(quote, 17, 63, 0x1234, 50000, 443, 0x0010, 0x2222, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("O udp-checksum-ignored", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    quote_len = inner4(quote, 17, 63, 0x1234, 50000, 443, 0x0011, 0x2222, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("P udp-len-diff", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    fake_len = inner4(fake, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    quote_len = inner6(quote, 6, 63, 50000, 443, 1, 2);
    icmp_len = icmp6(icmp, 3, 0, quote, quote_len);
    run("Q v6-exact", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    fake_len = inner6(fake, 6, 63, 50000, 443, 1, 2);
    quote_len = inner6(quote, 6, 63, 50000, 443, 1, 2);
    icmp_len = icmp6(icmp, 3, 0, quote, quote_len);
    run("R v6-real", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    quote_len = inner6(quote, 6, 63, 50000, 443, 1, 2);
    quote[39] = 3; /* другой адрес назначения */
    icmp_len = icmp6(icmp, 3, 0, quote, quote_len);
    run("S v6-dst-diff", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    quote_len = inner4(quote, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("T family-mismatch", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    fake_len = inner4(fake, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    quote_len = inner4(quote, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    icmp_len = icmp4_fragment(icmp, quote, quote_len);
    run("U outer-fragment", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("V outer-short", fake, fake_len, 64, 1000, icmp, 27, 1000);

    fake_len = inner4_fragment(fake);
    run("W inner-fragment", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    fake_len = inner4_wrong_proto(fake);
    run("X inner-proto", fake, fake_len, 64, 1000, icmp, icmp_len, 1000);

    fake_len = inner4(fake, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    quote_len = inner4(quote, 6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    icmp_len = icmp4(icmp, 11, 0, quote, quote_len);
    run("Y note-at-zero", fake, fake_len, 64, 0, icmp, icmp_len, 1);
    return 0;
}
