/* C-оракул: production `build_cands`, `build_fallback`, `add_cand` и порядок
 * вопросов `next_candidate` (core/httpsearch.c). TU включается целиком,
 * лишнее выбрасывает --gc-sections. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "httpsearch.c"

#include <stdio.h>
#include <string.h>

static rec *put_rec(d2k_httpsearch *hs, const char *host, const char *key,
                    uint64_t seq, int revoked)
{
    rec *r = rec_get(hs, host, 4);
    if (!r) { return NULL; }
    snprintf(r->key, sizeof r->key, "%s", key);
    r->seq = seq;
    r->revoked = revoked;
    return r;
}

/* Старт поиска: next_candidate проходит OWN с build_cands, затем HQ_SPLIT,
 * HQ_CHECKSUM, HQ_PRODUCT и HQ_FALLBACK. Флаги split_no/checksum_no на старте
 * нулевые, поэтому порядок добавления фиксирован. */
static void finish_ladder(d2k_httpsearch *hs)
{
    add_cand(hs, "split");
    add_cand(hs, "fake-badsum-whole");
    add_cand(hs, "fake-badsum");
    build_fallback(hs);
}

static void dump(const char *label, const d2k_httpsearch *hs)
{
    printf("ladder %s n=%zu\n", label, hs->cur.n_cands);
    for (size_t index = 0; index < hs->cur.n_cands; index++) {
        printf("cand %s %s\n", label, hs->cur.cands[index]);
    }
}

static void set_own(d2k_httpsearch *hs, const char *host)
{
    snprintf(hs->cur.host, sizeof hs->cur.host, "%s", host);
    hs->cur.family = 4;
}

int main(void)
{
    d2k_httpsearch *hs = d2k_httpsearch_new(NULL);
    if (!hs) { return 2; }
    set_own(hs, "none.example");
    build_cands(hs);
    finish_ladder(hs);
    dump("empty", hs);
    d2k_httpsearch_free(hs);

    hs = d2k_httpsearch_new(NULL);
    if (!hs) { return 2; }
    put_rec(hs, "own.example", "disorder", 1, 0);
    set_own(hs, "own.example");
    build_cands(hs);
    finish_ladder(hs);
    dump("own-only", hs);
    d2k_httpsearch_free(hs);

    hs = d2k_httpsearch_new(NULL);
    if (!hs) { return 2; }
    put_rec(hs, "own.example", "fake:ttl=5+badsum", 1, 0);
    put_rec(hs, "newer.example", "disorder", 3, 0);
    put_rec(hs, "older.example", "split", 2, 0);
    put_rec(hs, "revoked.example", "fake-seqshift", 4, 1);
    set_own(hs, "own.example");
    build_cands(hs);
    finish_ladder(hs);
    dump("own-saved-revoked", hs);
    d2k_httpsearch_free(hs);

    hs = d2k_httpsearch_new(NULL);
    if (!hs) { return 2; }
    put_rec(hs, "own.example", "fake:ttl=5+badsum", 1, 1);
    put_rec(hs, "newer.example", "disorder", 3, 0);
    put_rec(hs, "older.example", "split", 2, 0);
    set_own(hs, "own.example");
    build_cands(hs);
    finish_ladder(hs);
    dump("own-revoked", hs);
    d2k_httpsearch_free(hs);

    hs = d2k_httpsearch_new(NULL);
    if (!hs) { return 2; }
    put_rec(hs, "own.example", "split", 1, 0);
    put_rec(hs, "other-a.example", "split", 3, 0);
    put_rec(hs, "other-b.example", "disorder", 2, 0);
    set_own(hs, "own.example");
    build_cands(hs);
    finish_ladder(hs);
    dump("build-dedupe", hs);
    d2k_httpsearch_free(hs);

    hs = d2k_httpsearch_new(NULL);
    if (!hs) { return 2; }
    set_own(hs, "none.example");
    if (d2k_httpsearch_measured_poison(hs, "ttl=9 badsum") != 0 ||
        d2k_httpsearch_measured_poison(hs, "seqshift=-66000") != 0) {
        return 2;
    }
    build_cands(hs);
    finish_ladder(hs);
    dump("measured", hs);
    d2k_httpsearch_free(hs);

    hs = d2k_httpsearch_new(NULL);
    if (!hs) { return 2; }
    set_own(hs, "none.example");
    if (d2k_httpsearch_measured_poison(hs, "badsum") != 0) { return 2; }
    build_cands(hs);
    finish_ladder(hs);
    dump("measured-alias", hs);
    d2k_httpsearch_free(hs);

    hs = d2k_httpsearch_new(NULL);
    if (!hs) { return 2; }
    put_rec(hs, "own.example", "split", 1, 0);
    put_rec(hs, "other-a.example", "disorder", 3, 0);
    put_rec(hs, "other-b.example", "split", 2, 0);
    put_rec(hs, "other-c.example", "fake-badsum-whole", 2, 0);
    set_own(hs, "own.example");
    build_cands(hs);
    finish_ladder(hs);
    dump("own-saved-dedupe", hs);
    d2k_httpsearch_free(hs);
    return 0;
}
