#include "sched.c"

static void emit_case(const char *name, d2k_sched *sched, task *current,
                      const char *white_name, int searched, int tx_only,
                      int rx_cut) {
    memset(&sched->cat->net, 0, sizeof sched->cat->net);
    if (white_name) {
        snprintf(sched->cat->net.name, sizeof sched->cat->net.name, "%s", white_name);
    }
    sched->cat->net.searched = searched;
    sched->cat->net.tx_only = tx_only;
    current->vol.rx_cut = rx_cut;
    printf("%s %d\n", name, net_whitelist_needs_probe(sched, current));
}

int main(void) {
    d2k_catalog catalog = {0};
    d2k_sched sched = {0};
    task current = {0};
    sched.cat = &catalog;

    emit_case("unresolved", &sched, &current, NULL, 0, 0, 1);
    emit_case("known_rx", &sched, &current, "learned-white.example", 1, 0, 1);
    emit_case("tx_only_rx", &sched, &current, "learned-white.example", 0, 1, 1);
    emit_case("tx_only_tx", &sched, &current, "learned-white.example", 0, 1, 0);
    return 0;
}
