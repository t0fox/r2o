#define main d2o_test_repeats_main
#include "test_repeats.c"
#undef main

int main(void) {
    static const script_ent white_script[] = {
        {"white-hello-ts", "+"}, {NULL, NULL}
    };
    static const char expected_probe[] =
        "свойство:ECH-приветствие под битой суммой";
    scenario test_case = {
        "white-ts-noopts", white_script, "-", NULL, NULL, 0, NULL, 1, 1
    };
    d2k_result result;
    srv_start();
    memset(&result, 0, sizeof(result));
    run(&test_case, &result);

    const d2k_obs *observation = find_obs(&result, expected_probe);
    if (!result.has_hit || strcmp(result.hit.name, "white-hello-ts") != 0 ||
        result.hit.tcp_ts || !result.hit.badsum || !result.hit.decoy_hello ||
        result.hit.repeats != 8 || result.hit.split_pos != 2 || !observation ||
        result.props.parses_l7 != D2K_TRI_TRUE ||
        result.props.validates_checksum != D2K_TRI_FALSE ||
        result.props.validates_timestamps != D2K_TRI_UNSET) {
        fputs("D2O white-hello-ts no-timestamp scenario diverged\n", stderr);
        return 1;
    }

    printf("WHITE_TS_NO_CLIENT_TIMESTAMPS name=%s probe=%s tcp_ts=%d badsum=%d "
           "decoy_hello=%d repeats=%d split_pos=%d parses_l7=%d "
           "validates_checksum_false=%d validates_timestamps_unset=%d\n",
           result.hit.name, observation->probe, result.hit.tcp_ts, result.hit.badsum,
           result.hit.decoy_hello, result.hit.repeats, result.hit.split_pos,
           result.props.parses_l7 == D2K_TRI_TRUE,
           result.props.validates_checksum == D2K_TRI_FALSE,
           result.props.validates_timestamps == D2K_TRI_UNSET);

    d2k_result recheck_state = {0};
    recheck_state.raw_probes_err = 3;
    int cold_three_errors = raw_doubted(&recheck_state);
    recheck_state.raw_selftest_cached = 1;
    recheck_state.raw_probes_err = 2;
    int cached_two_errors = raw_doubted(&recheck_state);
    recheck_state.raw_probes_ok = 1;
    recheck_state.raw_probes_err = 3;
    int cached_with_success = raw_doubted(&recheck_state);
    printf("RAW_SELFTEST_RECHECK cold_three_errors=%d cached_two_errors=%d "
           "cached_with_success=%d\n",
           cold_three_errors, cached_two_errors, cached_with_success);
    return 0;
}
