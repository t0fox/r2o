/* C/Rust differential: d2k_http80_set_https/d2k_http80_https (a378). */
#include <stdio.h>
#include <string.h>

#include "d2k_http80.h"

#define TTL_MAX 604800u
#define NS 1000000000ull

static d2k_http80 *h;
static uint64_t now = 1000000000ull;

static void set(const char *label, const char *name, size_t length, uint32_t ttl) {
    if (ttl > TTL_MAX) { ttl = TTL_MAX; }
    uint64_t expires = ttl ? now + (uint64_t)ttl * NS : 0;
    int rc = d2k_http80_set_https(h, name, length, expires);
    if (strcmp(label, "filler") != 0 && strcmp(label, "tie_filler") != 0) {
        printf("set %s rc=%d\n", label, rc < 0 ? -1 : 0);
    }
}

static void has(const char *label, const char *name, uint64_t at) {
    printf("%s=%d\n", label, d2k_http80_https(h, name, at));
}

int main(void) {
    h = d2k_http80_new();
    set("example", "Example.COM.", strlen("Example.COM."), 7200);
    has("example_now", "example.com", now + 1);
    has("example_case", "EXAMPLE.com.", now + 1);
    has("example_last", "example.com", now + 7199 * NS);
    has("example_expired", "example.com", now + 7200 * NS);

    set("single_label", "localhost", strlen("localhost"), 100);
    has("single_label", "localhost", now + 1);
    set("numeric", "1.2.3.4", strlen("1.2.3.4"), 100);
    has("numeric", "1.2.3.4", now + 1);
    set("dash", "-bad", strlen("-bad"), 100);
    has("dash", "-bad", now + 1);
    set("empty_label", "a..b", strlen("a..b"), 100);
    has("empty_label", "a..b", now + 1);
    set("invalid_char", "bad_name", strlen("bad_name"), 100);
    set("empty", "", 0, 100);

    set("gone_first", "gone", strlen("gone"), 100);
    set("gone_remove", "gone", strlen("gone"), 0);
    has("removed", "gone", now + 1);
    set("up_first", "up", strlen("up"), 100);
    set("up_second", "up", strlen("up"), 1000);
    has("updated", "up", now + 500 * NS);

    set("clamped", "clamped", strlen("clamped"), 1000000000u);
    has("clamped_last", "clamped", now + 604799 * NS);
    has("clamped_expired", "clamped", now + 604800 * NS);

    d2k_http80_free(h);
    h = d2k_http80_new();
    char name[32];
    for (unsigned index = 0; index < 256; index++) {
        snprintf(name, sizeof name, "n%u", index);
        set("filler", name, strlen(name), 100 + index);
    }
    set("overflow", "overflow", strlen("overflow"), 500);
    has("n0", "n0", now + 1);
    has("n1", "n1", now + 1);
    has("overflow", "overflow", now + 1);

    set("n5_remove", "n5", strlen("n5"), 0);
    set("late", "late", strlen("late"), 50);
    set("overflow2", "overflow2", strlen("overflow2"), 600);
    has("late", "late", now + 1);
    has("overflow2", "overflow2", now + 1);
    has("n1_after", "n1", now + 1);

    d2k_http80_free(h);
    h = d2k_http80_new();
    for (unsigned index = 0; index < 256; index++) {
        snprintf(name, sizeof name, "e%u", index);
        set("tie_filler", name, strlen(name), 100);
    }
    set("tie_overflow", "tie-overflow", strlen("tie-overflow"), 100);
    has("tie_e0", "e0", now + 1);
    has("tie_e1", "e1", now + 1);
    has("tie_overflow", "tie-overflow", now + 1);

    d2k_http80_free(h);
    return 0;
}
