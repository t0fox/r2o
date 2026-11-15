/* C oracle rows for properties local_err / md5-err / stop. */
#define main d2o_test_repeats_main
#include "test_repeats.c"
#undef main

#include <stdio.h>
#include <string.h>

static int stop_seen;
static int stop_limit;
static int stop_cancel(void *ctx)
{
    (void)ctx;
    return stop_seen >= stop_limit;
}
static void stop_observe(void *ctx, const d2k_obs *obs)
{
    (void)ctx;
    (void)obs;
    stop_seen++;
}

int main(void)
{
    fresh_process();
    srv_start();

    {
        d2k_result r;
        d2k_opts opt;
        d2k_trigger tr;
        d2k_poison hit;
        memset(&r, 0, sizeof r);
        memset(&opt, 0, sizeof opt);
        memset(&tr, 0, sizeof tr);
        memset(&hit, 0, sizeof hit);
        opt.repeats = 3;
        opt.white.len = 2;
        tr.len = 2049;
        tr.sni_off = 100;
        tr.sni_len = 11;
        g_script = NULL;
        g_default = "e";
        g_res = &r;
        g_ask = -1;
        int rc = d2k_run_properties((uint8_t[]){192, 0, 2, 1}, 443, &tr, &opt, &r, &hit);
        d2k_dprops zero;
        memset(&zero, 0, sizeof zero);
        printf("LOCAL rc=%d props_zero=%d answered=%d hit=%d\n", rc,
               memcmp(&r.props, &zero, sizeof zero) == 0, r.nanswered,
               hit.name[0] != '\0');
    }

    {
        static const script_ent S_MD5_ERR[] = {{"md5", "e"}, {NULL, NULL}};
        static const scenario err = {"md5-err", S_MD5_ERR, "-", NULL, NULL, 0, NULL, 0, 0};
        d2k_result r;
        fresh_process();
        memset(&r, 0, sizeof r);
        run(&err, &r);
        printf("MD5_ERR poison_md5=%d\n",
               find_obs(&r, "poison:md5") != NULL);
    }

    {
        d2k_result r;
        d2k_opts opt;
        d2k_trigger tr;
        d2k_poison hit;
        memset(&r, 0, sizeof r);
        memset(&opt, 0, sizeof opt);
        memset(&tr, 0, sizeof tr);
        memset(&hit, 0, sizeof hit);
        opt.repeats = 1;
        opt.white.len = 2;
        tr.len = 300;
        tr.sni_off = 100;
        tr.sni_len = 11;
        g_script = NULL;
        g_default = "-";
        g_res = &r;
        g_ask = -1;
        stop_seen = 0;
        stop_limit = 2;
        opt.on_obs = stop_observe;
        opt.on_obs_ctx = &stop_seen;
        opt.cancel.fn = stop_cancel;
        int rc = d2k_run_properties((uint8_t[]){192, 0, 2, 1}, 443, &tr, &opt, &r, &hit);
        printf("STOP rc=%d obs=%d probes=%d stopped=%d\n", rc, stop_seen, r.probes,
               stop_seen >= stop_limit);
    }
    return 0;
}
