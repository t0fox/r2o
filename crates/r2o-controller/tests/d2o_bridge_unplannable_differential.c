#define main d2o_test_bridge_main
#include "test_bridge.c"
#undef main

int main(void)
{
    static const char *const only_unplannable[] = {"syndata", NULL};
    uint8_t trigger_bytes[300], control_bytes[] = {0x16, 0x03, 0x01};
    d2k_hello trigger = {trigger_bytes, 0, NULL, 0, 0, 0};
    d2k_hello control = {control_bytes, sizeof control_bytes, NULL, 0, 0, 0};
    d2k_vres result;
    const char *verdict;

    trigger.len = build_hello(trigger_bytes, "rutracker.org");
    memset(&answer, 0, sizeof answer);
    sweep_pass = only_unplannable;
    dialled = 1;
    result = d2k_detect_sched_tcp("192.0.2.1", 443, trigger, control,
                                  0x2d, 2, 12000, 321, NULL);
    verdict = result.verdict == D2K_V_OPAQUE ? "opaque" : "other";

    printf("verdict=%s plan=%u owns_search=%u content=%u poison=%u syn=%u\n",
           verdict, (unsigned)result.have_arm, (unsigned)result.owns_search,
           (unsigned)(strstr(result.reason, "буфер травится") != NULL),
           (unsigned)(strstr(result.reason, "syndata") != NULL),
           (unsigned)(strstr(result.reason, "SYN") != NULL));
    return strcmp(verdict, "opaque") == 0 && !result.have_arm &&
                   result.owns_search && strstr(result.reason, "буфер травится") &&
                   strstr(result.reason, "syndata") && strstr(result.reason, "SYN")
               ? 0
               : 1;
}
