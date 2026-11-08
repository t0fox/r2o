/* M5: C-оракул volume.c — чистые RX-вердикты (partial/pair/repeat/evidence). */
#include "volume.c"

#include <stdio.h>
#include <string.h>

static d2k_ver_result result(void) {
    d2k_ver_result value;
    memset(&value, 0, sizeof value);
    return value;
}

static void print_partial(const char *name, const d2k_ver_result *value) {
    printf("case %s\nvalue=%d\n", name, d2k_volume_rx_partial(value));
}

static void print_pair(const char *name, const d2k_ver_result *a,
                       const d2k_ver_result *b) {
    printf("case %s\nvalue=%d\n", name, d2k_volume_rx_pair_agrees(a, b));
}

static void print_repeat(const char *name, const d2k_ver_result *a,
                         const d2k_ver_result *b) {
    printf("case %s\nvalue=%d\n", name, d2k_volume_rx_needs_repeat(a, b));
}

static void print_evidence(const char *name, const d2k_ver_result *a,
                           const d2k_ver_result *b, const d2k_ver_result *gzip) {
    d2k_vol_result out;
    memset(&out, 0, sizeof out);
    int value = d2k_volume_rx_evidence(a, b, gzip, &out);
    printf("case %s\nvalue=%d\n", name, value);
    if (value) {
        printf("cut=%d basis=%d at_kb=%d expected_kb=%d packets=%d compressed=%d\n",
               out.rx_cut, out.rx_wire_basis, out.rx_at_kb, out.rx_expected_kb,
               out.rx_cut_packets, out.rx_compressed_complete);
    }
}

int main(void) {
    d2k_ver_result body_a = result();
    body_a.level = D2K_VER_APPLICATION;
    body_a.name_ok = 1;
    body_a.status = 200;
    body_a.body_framing_valid = 1;
    body_a.body_has_length = 1;
    body_a.body_bytes = 20000;
    body_a.body_expected = 100000;
    body_a.data_packets = 10;

    d2k_ver_result body_b = body_a;
    body_b.body_bytes = 20100;
    body_b.data_packets = 12;

    d2k_ver_result chunked = result();
    chunked.level = D2K_VER_APPLICATION;
    chunked.name_ok = 1;
    chunked.status = 200;
    chunked.body_framing_valid = 1;
    chunked.body_chunked = 1;
    chunked.body_bytes = 20000;
    chunked.body_expected = 30000;

    d2k_ver_result wire_a = result();
    wire_a.level = D2K_VER_HANDSHAKE;
    wire_a.name_ok = 1;
    wire_a.negotiated_tls = 0x0304;
    wire_a.rx_tls_wire_bytes = 20000;
    wire_a.rx_tls_record_missing = 1;
    wire_a.data_packets = 10;

    d2k_ver_result wire_b = wire_a;
    wire_b.rx_tls_wire_bytes = 20100;
    wire_b.data_packets = 12;

    d2k_ver_result complete = body_a;
    complete.body_complete = 1;
    complete.body_bytes = complete.body_expected = 20000;

    d2k_ver_result small = body_a;
    small.body_bytes = 1000;

    d2k_ver_result gzip = result();
    gzip.level = D2K_VER_APPLICATION;
    gzip.name_ok = 1;
    gzip.status = 200;
    gzip.body_complete = 1;
    gzip.body_framing_valid = 1;
    gzip.body_encoding = 1;
    gzip.body_bytes = 5000;

    d2k_ver_result gzip_wire = gzip;
    gzip_wire.negotiated_tls = 0x0304;
    gzip_wire.rx_tls_wire_bytes = 10000;

    print_partial("partial-body", &body_a);
    print_partial("partial-chunked", &chunked);
    print_partial("partial-wire", &wire_a);
    print_partial("partial-complete", &complete);
    print_partial("partial-small", &small);
    print_pair("pair-body", &body_a, &body_b);
    print_pair("pair-mixed", &body_a, &wire_a);
    print_pair("pair-wire", &wire_a, &wire_b);
    print_repeat("repeat-yes", &body_a, &complete);
    print_repeat("repeat-no-small", &body_a, &small);
    print_evidence("evidence-body", &body_a, &body_b, &gzip);
    print_evidence("evidence-wire", &wire_a, &wire_b, &gzip_wire);
    gzip.body_encoding = 0;
    print_evidence("evidence-reject", &wire_a, &wire_b, &gzip);
    return 0;
}
