/* C-оракул: production `props_text` из core/sched.c (static — включаем TU). */
#include "sched.c"

#include <stdio.h>

int main(void)
{
    for (int a = 0; a < 3; a++) {
        for (int b = 0; b < 3; b++) {
            for (int c = 0; c < 3; c++) {
                for (int d = 0; d < 3; d++) {
                    for (int e = 0; e < 3; e++) {
                        d2k_props p;
                        char out[400];
                        p.tolerates_left_overlap = (d2k_pval)a;
                        p.counts_duplicates = (d2k_pval)b;
                        p.tolerates_reorder = (d2k_pval)c;
                        p.validates_checksum = (d2k_pval)d;
                        p.parses_l7 = (d2k_pval)e;
                        props_text(&p, out, sizeof out);
                        printf("%d%d%d%d%d|%s\n", a, b, c, d, e, out);
                    }
                }
            }
        }
    }
    return 0;
}
