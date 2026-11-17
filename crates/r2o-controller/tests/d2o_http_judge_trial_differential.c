/* C-оракул production `judge_trial` из core/httpsearch.c.
 *
 * Скрипт копирует httpsearch.c во временный каталог и переименовывает
 * только определения побочных `next_candidate` и `confirmed`, чтобы
 * differential видел решение judge_trial, а не весь цикл поиска.
 * `trial_executed`, `say` и разбор ответа остаются production.
 */
#include <stdint.h>

/* <stdint.h> уже подтянул glibc features.h и определил эти макросы;
 * httpsearch.c задаёт свои значения — снимаем прежние, чтобы не было
 * -Wmacro-redefined под -Werror. */
#undef _POSIX_C_SOURCE
#undef _DEFAULT_SOURCE

struct d2k_httpsearch;
static void next_candidate(struct d2k_httpsearch *hs, int64_t now);
static void confirmed(struct d2k_httpsearch *hs, int64_t now);

#include "httpsearch.c"

#include <stdio.h>
#include <string.h>

static int next_calls;
static int confirmed_calls;
static size_t idx_before;

static void next_candidate(d2k_httpsearch *hs, int64_t now)
{
    (void)hs;
    (void)now;
    next_calls++;
}

static void confirmed(d2k_httpsearch *hs, int64_t now)
{
    (void)hs;
    (void)now;
    confirmed_calls++;
}

static const char *action(size_t idx_after)
{
    if (confirmed_calls) return "confirmed";
    if (next_calls && idx_after == idx_before) return "repeat";
    return "next";
}

static void run(const char *name, d2k_hs_answer answer, unsigned requests,
                unsigned complete, int applied, int ok, int had_real,
                int retried, int question, const char *key)
{
    d2k_httpsearch hs;
    memset(&hs, 0, sizeof hs);
    hs.cur.family = 4;
    snprintf(hs.cur.host, sizeof hs.cur.host, "%s", "judge.example");
    hs.cur.n_cands = 1;
    hs.cur.idx = 0;
    snprintf(hs.cur.cands[0], sizeof hs.cur.cands[0], "%s", key);
    hs.cur.ok = ok;
    hs.cur.cand_had_real = had_real;
    hs.cur.cand_retried_cut = retried;
    hs.cur.question = question;
    hs.cur.next_question = HQ_FALLBACK;
    hs.cur.applied = applied;
    hs.cur.proof_sport = 4444;
    memset(hs.cur.proof_client, 0, sizeof hs.cur.proof_client);
    hs.cur.proof_client[0] = 127;
    hs.cur.proof_client[3] = 1;

    d2k_hs_result result;
    memset(&result, 0, sizeof result);
    result.answer = answer;
    result.requests_sent = requests;
    result.complete_responses = complete;
    result.local_port = 4444;
    result.local_ip[0] = 127;
    result.local_ip[3] = 1;

    next_calls = 0;
    confirmed_calls = 0;
    idx_before = hs.cur.idx;
    judge_trial(&hs, &result, 1000);

    printf("%s action=%s ok=%d had=%d retried=%d split_no=%d checksum_no=%d nextq=%d\n",
           name, action(hs.cur.idx), hs.cur.ok, hs.cur.cand_had_real,
           hs.cur.cand_retried_cut, hs.cur.split_no, hs.cur.checksum_no,
           hs.cur.next_question);
}

int main(void)
{
    run("not_executed", D2K_HS_REAL, 2, 2, 0, 0, 0, 0, HQ_OWN, "split");
    run("real_first", D2K_HS_REAL, 2, 2, 2, 0, 0, 0, HQ_OWN, "split");
    run("real_second", D2K_HS_REAL, 2, 2, 2, 1, 1, 0, HQ_OWN, "split");
    run("real_once", D2K_HS_REAL, 1, 1, 2, 0, 0, 0, HQ_OWN, "split");
    run("injected", D2K_HS_INJECTED, 2, 2, 2, 0, 0, 0, HQ_SPLIT, "split");
    run("early", D2K_HS_EARLY, 2, 1, 2, 0, 0, 0, HQ_OWN, "split");
    run("garbage", D2K_HS_GARBAGE, 2, 1, 2, 0, 0, 0, HQ_OWN, "split");
    run("decoy", D2K_HS_DECOY, 2, 1, 2, 0, 0, 0, HQ_OWN, "split");
    run("cut_first", D2K_HS_CUT, 2, 1, 2, 0, 0, 0, HQ_OWN, "split");
    run("cut_retry", D2K_HS_CUT, 2, 1, 2, 1, 1, 0, HQ_CHECKSUM,
        "fake-badsum-whole");
    run("cut_after_retry", D2K_HS_CUT, 2, 1, 2, 0, 1, 1, HQ_CHECKSUM,
        "fake-badsum-whole");
    run("none", D2K_HS_NONE, 2, 0, 2, 0, 0, 0, HQ_OWN, "split");
    run("connect_fail", D2K_HS_CONNECT_FAIL, 2, 0, 2, 0, 0, 0, HQ_OWN, "split");
    return 0;
}
