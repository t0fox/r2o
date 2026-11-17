/* C-оракул: production `client_tcp_profile` из core/sched.c. */
#include "sched.c"

#include <stdio.h>
#include <string.h>

static uint32_t state = 0x12345678u;

static uint32_t next(void)
{
    state = state * 1103515245u + 12345u;
    return state;
}

static void print_case(const char *label, int known, const uint8_t *options, size_t len)
{
    task t;
    memset(&t, 0, sizeof t);
    t.client_opts_known = (uint8_t)known;
    t.client_opts_len = len;
    if (len <= sizeof t.client_opts) {
        memcpy(t.client_opts, options, len);
    }
    printf("%s,%d,%zu,", label, known, len);
    for (size_t index = 0; index < len; index++) {
        printf("%02x", options[index]);
    }
    printf(",%u\n", (unsigned)client_tcp_profile(&t));
}

int main(void)
{
    static const uint8_t empty[] = {0};
    static const uint8_t end[] = {0};
    static const uint8_t nop[] = {1, 1};
    static const uint8_t ts[] = {8, 10, 0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t ts_short[] = {8, 10, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t ts_len2[] = {8, 10};
    static const uint8_t ts_badlen[] = {8, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t nop_then_ts[] = {1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t zero_then_ts[] = {0, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t unknown_kind[] = {2, 4, 1, 1};
    static const uint8_t bad_kind_len[] = {2, 1};
    static const uint8_t zero_len[] = {2, 0};
    static const uint8_t too_long[] = {2, 5, 1};
    static const uint8_t nops[40] = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    };
    static const uint8_t overflow[41] = {0};

    print_case("known0", 0, empty, 0);
    print_case("empty", 1, empty, 0);
    print_case("end", 1, end, sizeof end);
    print_case("nop", 1, nop, sizeof nop);
    print_case("ts", 1, ts, sizeof ts);
    print_case("ts_short", 1, ts_short, sizeof ts_short);
    print_case("ts_len2", 1, ts_len2, sizeof ts_len2);
    print_case("ts_badlen", 1, ts_badlen, sizeof ts_badlen);
    print_case("nop_then_ts", 1, nop_then_ts, sizeof nop_then_ts);
    print_case("zero_then_ts", 1, zero_then_ts, sizeof zero_then_ts);
    print_case("unknown_kind", 1, unknown_kind, sizeof unknown_kind);
    print_case("bad_kind_len", 1, bad_kind_len, sizeof bad_kind_len);
    print_case("zero_len", 1, zero_len, sizeof zero_len);
    print_case("too_long", 1, too_long, sizeof too_long);
    print_case("nops40", 1, nops, sizeof nops);
    print_case("overflow41", 1, overflow, 41);

    for (unsigned index = 0; index < 4096; index++) {
        uint8_t options[40];
        int known = (int)(next() & 1u);
        size_t len = next() % 41u;
        for (size_t offset = 0; offset < len; offset++) {
            options[offset] = (uint8_t)(next() >> 16);
        }
        char label[16];
        snprintf(label, sizeof label, "r%u", index);
        print_case(label, known, options, len);
    }
    return 0;
}
