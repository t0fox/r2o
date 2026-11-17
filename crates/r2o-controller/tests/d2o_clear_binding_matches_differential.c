/* C-оракул: production `clear_binding_matches` из core/sched.c. */
#include "sched.c"

#include <stdio.h>
#include <string.h>

static const char *kinds[] = {"name", "addr"};
static const uint8_t transports[] = {0, 6, 17};
static const uint8_t families[] = {0, 4, 6};
static const uint8_t profiles[] = {0, 1};
static const uint8_t shapes[] = {0, 1, 2, 6};
static const uint8_t measured_shapes[] = {0, 1, 2, 6};

int main(void)
{
    for (size_t ki = 0; ki < sizeof kinds / sizeof kinds[0]; ki++) {
        for (int target_eq = 0; target_eq <= 1; target_eq++) {
            for (size_t bi = 0; bi < sizeof transports / sizeof transports[0]; bi++) {
                for (size_t fi = 0; fi < sizeof families / sizeof families[0]; fi++) {
                    for (size_t pi = 0; pi < sizeof profiles / sizeof profiles[0]; pi++) {
                        for (size_t si = 0; si < sizeof shapes / sizeof shapes[0]; si++) {
                            for (size_t mi = 0; mi < sizeof measured_shapes / sizeof measured_shapes[0]; mi++) {
                                for (size_t ti = 0; ti < 2; ti++) {
                                    uint8_t target_transport = ti == 0 ? 6 : 17;
                                    for (size_t tfi = 0; tfi < 2; tfi++) {
                                        uint8_t target_family = tfi == 0 ? 4 : 6;
                                        for (size_t tpi = 0; tpi < 2; tpi++) {
                                            uint8_t target_profile = (uint8_t)tpi;
                                            task t;
                                            memset(&t, 0, sizeof t);
                                            snprintf(t.name, sizeof t.name, "%s", "example.com");
                                            t.transport = target_transport;
                                            t.family = target_family;
                                            t.trigger_tcp_profile = target_profile;
                                            d2k_cat_binding bd;
                                            memset(&bd, 0, sizeof bd);
                                            snprintf(bd.kind, sizeof bd.kind, "%s", kinds[ki]);
                                            snprintf(bd.target, sizeof bd.target, "%s",
                                                     target_eq ? "example.com" : "other.com");
                                            bd.transport = transports[bi];
                                            bd.family = families[fi];
                                            bd.tcp_profile = profiles[pi];
                                            bd.shape = shapes[si];
                                            printf("%s,%d,%u,%u,%u,%u,%u,%u,%u,%u,%d\n",
                                                   kinds[ki], target_eq, transports[bi],
                                                   families[fi], profiles[pi], shapes[si],
                                                   target_transport, target_family,
                                                   target_profile, measured_shapes[mi],
                                                   clear_binding_matches(&bd, &t,
                                                                       measured_shapes[mi]));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}
