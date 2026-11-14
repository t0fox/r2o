/* C-оракул: icmp_step (datapath/d2kd.c:220-248).
 *
 * d2kd.c и icmpguard.c включаются целиком: icmp_step статическая.
 * d2k_nfq_verdict подменён заглушкой — проверяется решение handled/drop и
 * счётчики, а не проводная отправка вердикта (её покрывает отдельный тест).
 * Неиспользуемые секции выбрасываются --gc-sections. */
#define main d2kd_main
#include "d2kd.c"
#undef main
#include "icmpguard.c"

#include <stdio.h>
#include <string.h>

static const uint8_t fake4_packet[] = {
    0x45,0x70,0x04,0xcc,0x00,0x01,0x40,0x00,0x03,0x11,0x16,0x59,
    0xc0,0xa8,0x01,0x43,0x68,0x15,0x34,0x57,
    0xd8,0x8b,0x01,0xbb,0x04,0xb8,0x34,0x8e,
};

static const uint8_t field_icmp[] = {
    0x45,0x70,0x00,0x38,0x00,0x00,0x00,0x00,0xfb,0x01,0x2d,0x19,0x3e,0x73,0x91,0xdd,
    0xc0,0xa8,0x01,0x43,0x0b,0x00,0xe1,0x72,0x00,0x00,0x00,0x00,0x45,0x70,0x04,0xcc,
    0x00,0x01,0x40,0x00,0x01,0x11,0x16,0x59,0xc0,0xa8,0x01,0x43,0x68,0x15,0x34,0x57,
    0xd8,0x8b,0x01,0xbb,0x04,0xb8,0x34,0x8e,
};

static size_t fake4(uint8_t *packet) {
    const size_t len = 1228;
    memset(packet, 0, len);
    memcpy(packet, fake4_packet, 28);
    packet[2] = (uint8_t)(len >> 8);
    packet[3] = (uint8_t)len;
    packet[24] = (uint8_t)((len - 20) >> 8);
    packet[25] = (uint8_t)(len - 20);
    return len;
}

static uint32_t g_verdict;

int d2k_nfq_verdict(d2k_nfq *q, uint32_t pkt_id, uint32_t verdict,
                    char *err, size_t errcap) {
    (void)q;
    (void)pkt_id;
    (void)err;
    (void)errcap;
    g_verdict = verdict;
    return 0;
}

static void reset(void) {
    d2k_icmpguard_init(&icmpg);
    memset(&st, 0, sizeof st);
    g_verdict = 0;
}

static void run(const char *name, const uint8_t *payload, size_t len,
                uint8_t hook, int with_fake) {
    reset();
    uint8_t fake[2048];
    if (with_fake) {
        size_t fake_len = fake4(fake);
        (void)d2k_icmpguard_note(&icmpg, fake, fake_len, 64, 1000000000ull);
    }
    d2k_nl_pkt np;
    memset(&np, 0, sizeof np);
    np.have_payload = payload != NULL;
    np.payload = payload;
    np.payload_len = len;
    np.hook = hook;
    np.id = 7;
    int handled = icmp_step(NULL, &np, 1000000000ull);
    int drop = handled && g_verdict == D2K_NF_DROP;
    printf("%s handled=%d drop=%d seen=%llu noted=%llu dropped=%llu\n",
           name, handled, drop, (unsigned long long)st.icmp_seen,
           (unsigned long long)d2k_icmpguard_noted(&icmpg),
           (unsigned long long)d2k_icmpguard_dropped(&icmpg));
}

int main(void) {
    static const uint8_t short_packet[1] = {0x45};
    static const uint8_t v4_tcp[20] = {0x45,0,0,20,0,0,0,0,64,6};
    static const uint8_t v6_tcp[40] = {0x60,0,0,0,0,0,6,64};
    uint8_t quote_mutated[sizeof field_icmp];

    run("A no-payload", NULL, 0, D2K_HOOK_FORWARD, 1);
    run("B one-byte", short_packet, 1, D2K_HOOK_FORWARD, 1);
    run("C v4-non-icmp", v4_tcp, sizeof v4_tcp, D2K_HOOK_FORWARD, 1);
    run("D v6-non-icmp", v6_tcp, sizeof v6_tcp, D2K_HOOK_FORWARD, 1);
    run("E v4-no-fake", field_icmp, sizeof field_icmp, D2K_HOOK_FORWARD, 0);
    run("F v4-forward", field_icmp, sizeof field_icmp, D2K_HOOK_FORWARD, 1);
    run("G v4-input", field_icmp, sizeof field_icmp, D2K_HOOK_INPUT, 1);
    run("H v4-postrouting", field_icmp, sizeof field_icmp,
        D2K_HOOK_POSTROUTING, 1);
    run("I v4-prerouting", field_icmp, sizeof field_icmp, 0, 1);
    memcpy(quote_mutated, field_icmp, sizeof field_icmp);
    quote_mutated[48] ^= 1;
    run("J v4-mutated", quote_mutated, sizeof quote_mutated,
        D2K_HOOK_FORWARD, 1);
    return 0;
}
