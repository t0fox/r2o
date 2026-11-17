/* C-оракул: production `put16`/`get16` из TLS-файла, заданного TLS_SOURCE.
 * Компилируется дважды: tls13.c и tls13core.c. */
#include TLS_SOURCE

#include <stdio.h>

int main(void)
{
    for (unsigned value = 0; value <= 65535; value++) {
        unsigned char bytes[2];
        put16(bytes, (uint16_t)value);
        printf("%u %u %u %u\n", value, bytes[0], bytes[1],
               get16(bytes));
    }
    return 0;
}
