/* C/Rust differential: d2k_hr_field (datapath/include/d2k_http_response.h:35-42). */
#include <stdio.h>
#include <string.h>

#include "d2k_http_response.h"

int main(void) {
    static const char *const cases[] = {
        "",
        "Host",
        ": value",
        "Host: value",
        "Host : value",
        "Host:\tvalue",
        "Host: a\x01",
        "Host: a\x7f",
        "Host: a\tb",
        "Bad@Name: x",
        "Content-Length: 10",
        "X-Empty:",
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        printf("field %zu=%d\n", i, d2k_hr_field(cases[i], strlen(cases[i])));
    }
    return 0;
}
