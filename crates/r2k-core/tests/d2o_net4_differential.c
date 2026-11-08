/* M5: C-оракул net4.c — IPv4 parse/text/private и IPv6 private. */
#include "d2k_net4.h"

#include <stdio.h>
#include <string.h>

static void print_parse(const char *text) {
    uint32_t address = 0;
    int result = d2k_ip4_parse(text, &address);
    printf("case parse-%s\n", text[0] ? text : "empty");
    if (result != 0) {
        printf("result err\n");
        return;
    }
    char output[24];
    d2k_ip4_text(address, output, sizeof output);
    printf("result ok text=%s\n", output);
}

static void print_private(const char *text) {
    uint32_t address = 0;
    if (d2k_ip4_parse(text, &address) != 0) {
        return;
    }
    printf("case private4-%s\nvalue=%d\n", text, d2k_ip4_private(address));
}

static void print_private6(const char *text, const uint8_t address[16]) {
    printf("case private6-%s\nvalue=%d\n", text, d2k_ip6_private(address));
}

int main(void) {
    static const char *valid[] = {
        "0.0.0.0", "127.0.0.1", "192.168.1.1", "255.255.255.255",
    };
    static const char *invalid[] = {
        "", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1..2.3", "a.b.c.d",
    };
    for (size_t i = 0; i < sizeof valid / sizeof valid[0]; i++) {
        print_parse(valid[i]);
    }
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
        print_parse(invalid[i]);
    }

    static const char *private4[] = {
        "0.0.0.0", "10.0.0.1", "127.0.0.1", "172.16.0.1",
        "172.31.255.255", "172.32.0.1", "192.168.1.1", "169.254.1.1",
        "100.64.0.1", "100.127.255.255", "100.128.0.1", "8.8.8.8",
    };
    for (size_t i = 0; i < sizeof private4 / sizeof private4[0]; i++) {
        print_private(private4[i]);
    }

    static const uint8_t v6_unspecified[16] = {0};
    static const uint8_t v6_loopback[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    };
    static const uint8_t v6_fc[16] = {
        0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    };
    static const uint8_t v6_fe80[16] = {
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    };
    static const uint8_t v6_ff[16] = {
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    };
    static const uint8_t v6_mapped_private[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1,
    };
    static const uint8_t v6_mapped_public[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8,
    };
    static const uint8_t v6_public[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    };
    print_private6("unspecified", v6_unspecified);
    print_private6("loopback", v6_loopback);
    print_private6("fc00", v6_fc);
    print_private6("fe80", v6_fe80);
    print_private6("ff02", v6_ff);
    print_private6("mapped-private", v6_mapped_private);
    print_private6("mapped-public", v6_mapped_public);
    print_private6("public", v6_public);
    return 0;
}
