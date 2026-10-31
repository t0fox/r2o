#include <stdio.h>
#include <string.h>

#include "d2k_detect.h"

int d2k_white_decoy_hello(const char *name, unsigned char *out, size_t cap, size_t *len);

static void print_trigger(const char *label, const d2k_trigger *trigger)
{
    const char *accept = trigger->accept == D2K_ACCEPT_ANY ? "any" :
                         trigger->accept == D2K_ACCEPT_SERVERHELLO ? "server-hello" :
                         "tls-record";
    printf("%s name=%s accept=%s bytes=", label, trigger->name, accept);
    for (size_t i = 0; i < trigger->len; i++) {
        printf("%02x", trigger->payload[i]);
    }
    putchar('\n');
}

static int print_hello(const char *name)
{
    unsigned char hello[4096];
    size_t length = 0;

    if (d2k_white_decoy_hello(name, hello, sizeof(hello), &length) != 0) {
        fprintf(stderr, "D2O white decoy failed for %s\n", name);
        return 1;
    }
    printf("%s=", name);
    for (size_t i = 0; i < length; i++) {
        printf("%02x", hello[i]);
    }
    putchar('\n');
    return 0;
}

int main(void)
{
    d2k_trigger control;
    char error[256];

    if (print_hello("hcaptcha.com") || print_hello("video.edge.example.net")) {
        return 1;
    }
    if (d2k_trigger_control("d2k", &control, error, sizeof(error)) != 0) {
        fprintf(stderr, "D2O default control failed: %s\n", error);
        return 1;
    }
    print_trigger("CONTROL_DEFAULT", &control);
    if (d2k_trigger_tls("example.com", 0, &control, error, sizeof(error)) != 0) {
        fprintf(stderr, "D2O custom control failed: %s\n", error);
        return 1;
    }
    snprintf(control.name, sizeof(control.name), "control:example.com");
    control.accept = D2K_ACCEPT_TLSRECORD;
    print_trigger("CONTROL_CUSTOM", &control);
    if (d2k_trigger_raw_hex("57 41:06-03", &control, error, sizeof(error)) != 0) {
        fprintf(stderr, "D2O raw control failed: %s\n", error);
        return 1;
    }
    print_trigger("TARGET_RAW", &control);
    snprintf(control.name, sizeof(control.name), "control");
    control.accept = D2K_ACCEPT_TLSRECORD;
    print_trigger("CONTROL_RAW", &control);
    return 0;
}
