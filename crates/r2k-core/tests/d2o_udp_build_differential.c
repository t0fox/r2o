/* C/Rust differential: d2k_wire_build_udp (datapath/wire_udp.c). */
#include <stdio.h>
#include <string.h>

#include "d2k_plan.h"
#include "d2k_wire.h"

static const unsigned char payload[] = {0xde, 0xad, 0xbe, 0xef, 0x52, 0x32};

static void run(unsigned index, size_t cap, const d2k_conn *c, const d2k_emit *e) {
    unsigned char out[512];
    size_t len = d2k_wire_build_udp(c, e, out, cap);
    printf("case %u len %zu\n", index, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", out[i]);
    }
    if (len) {
        printf("\n");
    }
}

int main(void) {
    d2k_conn c;
    d2k_emit e;

    memset(&c, 0, sizeof c);
    c.src_ip = 0x010200c0u;
    c.dst_ip = 0x146433c6u;
    c.src_port = 0x409cu;
    c.dst_port = 0xbb01u;
    c.ttl = 64;
    c.ip_id = 0x1234;
    c.family = 4;
    c.traffic_class = 0x2e;

    memset(&e, 0, sizeof e);
    e.bytes = payload;
    e.len = sizeof payload;
    run(0, 512, &c, &e);

    e.poison = D2K_POISON_IPID_ZERO;
    run(1, 512, &c, &e);
    e.poison = 0;

    e.ttl = 5;
    run(2, 512, &c, &e);
    e.ttl = 0;

    c.ttl = 0;
    run(3, 512, &c, &e);

    c.ttl = 48;
    run(4, 512, &c, &e);

    c.family = 6;
    c.ttl = 64;
    c.src_ip6[0] = 0x20; c.src_ip6[1] = 0x01;
    c.src_ip6[15] = 1;
    c.dst_ip6[0] = 0x20; c.dst_ip6[1] = 0x01;
    c.dst_ip6[15] = 2;
    c.flow_label = 0xabcde;
    run(5, 512, &c, &e);

    e.poison = D2K_POISON_IPID_ZERO;
    run(6, 512, &c, &e);
    e.poison = 0;

    c.family = 4;
    c.ttl = 64;
    e.poison = D2K_POISON_BADSUM;
    run(7, 512, &c, &e);
    e.poison = D2K_POISON_TCPTS_BACK;
    run(8, 512, &c, &e);
    e.poison = 0;

    e.seq_shift = 1;
    run(9, 512, &c, &e);
    e.seq_shift = 0;

    e.pre = payload;
    e.pre_len = 1;
    run(10, 512, &c, &e);
    e.pre = NULL;
    e.pre_len = 0;

    e.wire_profile = 1;
    run(11, 512, &c, &e);
    e.wire_profile = 0;

    e.ipfrag = 1;
    run(12, 512, &c, &e);
    e.ipfrag = 0;

    e.len = 0;
    run(13, 512, &c, &e);

    e.len = sizeof payload;
    run(14, 20 + 8 + sizeof payload - 1, &c, &e);

    c.family = 6;
    e.poison = D2K_POISON_BADSUM;
    run(15, 512, &c, &e);
    e.poison = 0;

    c.family = 0;
    run(16, 512, &c, &e);

    c.family = 4;
    e.poison = D2K_POISON_MD5;
    run(17, 512, &c, &e);
    e.poison = 0;

    e.ttl = 1;
    run(18, 512, &c, &e);
    e.ttl = 0;

    c.family = 6;
    e.ttl = 5;
    run(19, 512, &c, &e);

    return 0;
}
