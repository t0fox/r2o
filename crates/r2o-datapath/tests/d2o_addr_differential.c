/* D18: C-оракул addr helpers. */
#include "d2k_addr.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", bytes[i]);
    }
}

int main(void) {
    static const struct {
        const char *name;
        const char *text;
    } cases[] = {
        { "v4-zero", "0.0.0.0" },
        { "v4-loop", "127.0.0.1" },
        { "v4-doc", "192.0.2.1" },
        { "v4-broadcast", "255.255.255.255" },
        { "v4-leading-zero", "192.000.002.001" },
        { "v4-short", "192.0.2" },
        { "v4-long", "192.0.2.1.5" },
        { "v4-big", "256.0.0.1" },
        { "v4-garbage", "abc" },
        { "v4-empty", "" },
        { "v4-zone", "192.0.2.1%eth0" },
        { "v6-zero", "::" },
        { "v6-loop", "::1" },
        { "v6-doc", "2001:db8::1" },
        { "v6-link", "fe80::1" },
        { "v6-full", "2001:0db8:0000:0000:0000:0000:0000:0001" },
        { "v6-mapped", "::ffff:192.0.2.1" },
        { "v6-zone", "fe80::1%lo" },
        { "v6-bad", "2001:db8::g" },
    };
    d2k_addr parsed[sizeof cases / sizeof cases[0]];
    int ok[sizeof cases / sizeof cases[0]];
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        memset(&parsed[i], 0, sizeof parsed[i]);
        ok[i] = d2k_addr_parse(cases[i].text, &parsed[i]) == 0;
        printf("parse %s ok=%d", cases[i].name, ok[i]);
        if (ok[i]) {
            printf(" family=%u bytes=", parsed[i].family);
            print_hex(parsed[i].bytes, parsed[i].family == 4 ? 4 : 16);
        }
        printf("\n");
        if (ok[i]) {
            char text[64];
            size_t length = d2k_addr_text(&parsed[i], text, sizeof text);
            printf("text %s ok=%zu text=%s\n", cases[i].name, length, text);
        }
    }
    static const struct {
        const char *left;
        const char *right;
    } pairs[] = {
        { "v4-zero", "v4-zero" },
        { "v4-loop", "v4-doc" },
        { "v6-doc", "v6-doc" },
        { "v6-mapped", "v4-doc" },
        { "v6-loop", "v6-zero" },
    };
    for (size_t i = 0; i < sizeof pairs / sizeof pairs[0]; i++) {
        size_t left = 0, right = 0;
        for (size_t j = 0; j < sizeof cases / sizeof cases[0]; j++) {
            if (!strcmp(cases[j].name, pairs[i].left)) left = j;
            if (!strcmp(cases[j].name, pairs[i].right)) right = j;
        }
        int equal = ok[left] && ok[right] && d2k_addr_equal(&parsed[left], &parsed[right]);
        printf("equal %s %s =%d\n", pairs[i].left, pairs[i].right, equal);
    }
    return 0;
}
