/* C/Rust differential: публичный список кандидатов HTTP-поиска,
 * стабильный id и имена исходов. Включает httpsearch.c, чтобы дотянуться
 * до static stable_id; линковка с gc-sections выбрасывает остальное. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "httpsearch.c"
#include <stdio.h>

static void print_hex(const char *label, const uint8_t id[16]) {
    printf("%s=", label);
    for (size_t i = 0; i < 16; i++) printf("%02x", id[i]);
    printf("\n");
}

int main(void) {
    printf("count=%zu\n", d2k_hs_candidate_count());
    for (size_t i = 0; i < d2k_hs_candidate_count(); i++)
        printf("candidate %zu=%s\n", i, d2k_hs_candidate_key(i));
    printf("candidate out_of_range=%s\n",
           d2k_hs_candidate_key(d2k_hs_candidate_count()) ? "some" : "null");

    uint8_t id[16];
    stable_id("split", id);
    print_hex("stable split", id);
    stable_id("disorder", id);
    print_hex("stable disorder", id);
    stable_id("fake-badsum", id);
    print_hex("stable fake-badsum", id);
    stable_id("fake:ttl=5+badsum", id);
    print_hex("stable fake-spec", id);

    uint8_t plan_id[16];
    for (size_t i = 0; i < sizeof plan_id; i++) plan_id[i] = (uint8_t)i;
    const char *keys[] = {
        "split", "disorder", "fake-badsum", "fake-badsum-whole",
        "fake-seqshift", "fake:ttl=5+badsum", "nope",
    };
    char plan[2048];
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        int rc = d2k_hs_candidate_text(keys[i], plan_id, plan, sizeof plan);
        printf("plan %s rc=%d\n", keys[i], rc);
        if (rc == 0) fputs(plan, stdout);
    }

    for (int answer = 0; answer <= 11; answer++)
        printf("answer %d=%s\n", answer,
               d2k_hs_answer_name((d2k_hs_answer)answer));
    return 0;
}
