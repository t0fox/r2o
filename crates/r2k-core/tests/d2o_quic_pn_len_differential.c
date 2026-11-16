/* C-оракул: production `d2k_qw_pn_len` из core/quicwire.c. */
#include <inttypes.h>
#include <stdio.h>

#include "quicwire.c"

int main(void)
{
    static const struct {
        uint64_t pn;
        int64_t largest;
    } cases[] = {
        {0, -1},
        {1, -1},
        {127, -1},
        {128, -1},
        {255, -1},
        {256, -1},
        {16383, -1},
        {16384, -1},
        {65535, -1},
        {65536, -1},
        {0xac5c02, 0xabe8b3},
        {0xace8fe, 0xabe8b3},
        {0, 0},
        {5, 10},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        printf("%" PRIu64 " %" PRId64 " %zu\n", cases[i].pn, cases[i].largest,
               d2k_qw_pn_len(cases[i].pn, cases[i].largest));
    }
    return 0;
}
