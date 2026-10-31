#include <stdio.h>
#include <string.h>

int d2k_white_decoy_hello(const char *name, unsigned char *out, size_t cap, size_t *len);

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
    return print_hello("hcaptcha.com") || print_hello("video.edge.example.net");
}
