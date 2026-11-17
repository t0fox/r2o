/* C-оракул: production `d2k_quic_probe_initial`/`_longer`
 * (core/quichello.c:276-285): свежий донорский профиль 1200/1300. */
#include "d2k_quic.h"
#include "d2k_quichello.h"

#include <stdio.h>
#include <string.h>

static void emit(const char *label, int rc, const uint8_t *packet, size_t len)
{
    if (rc != 0) {
        printf("%s,-1\n", label);
        return;
    }
    uint8_t ch[8192];
    size_t ch_len = 0;
    int has_ch = d2k_quic_client_hello(packet, len, ch, sizeof ch, &ch_len) == 0;
    char sni[256];
    sni[0] = '\0';
    int has_sni = d2k_quic_sni(packet, len, sni, sizeof sni) == 0;
    printf("%s,0,%zu,%s,%d,%zu,%d\n", label, len, has_sni && sni[0] ? sni : "-",
           has_ch, has_ch ? ch_len : 0, d2k_quic_hello_incomplete(packet, len));
}

int main(void)
{
    uint8_t packet[1500];
    size_t len = 0;
    int rc = d2k_quic_probe_initial("target.example", packet, sizeof packet, &len);
    emit("profile-1200", rc, packet, len);
    rc = d2k_quic_probe_initial_longer("target.example", packet, sizeof packet, &len);
    emit("profile-1300", rc, packet, len);
    rc = d2k_quic_probe_initial("203.0.113.7", packet, sizeof packet, &len);
    emit("profile-ip", rc, packet, len);
    rc = d2k_quic_probe_initial("", packet, sizeof packet, &len);
    emit("profile-empty", rc, packet, len);
    return 0;
}
