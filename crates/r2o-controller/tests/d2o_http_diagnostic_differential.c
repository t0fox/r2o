#include "d2k_diagnostics.h"
#include "d2k_httpsearch.h"

static void record_event(void *context, const d2k_diag_event *event) {
    d2k_diag_record(context, event);
}

int main(void) {
    const uint8_t address[16] = {192, 0, 2, 10};
    const d2k_hs_ops ops = {0};
    d2k_diag *diagnostics = d2k_diag_new();
    d2k_httpsearch *search = d2k_httpsearch_new(&ops);
    if (!diagnostics || !search) return 1;
    d2k_httpsearch_diagnostics(search, record_event, diagnostics);
    d2k_httpsearch_portal(search, "http-diagnostic.example", 4, address, 100);
    if (d2k_diag_event_count(diagnostics) != 1) return 1;
    const int result = d2k_diag_write(diagnostics, stdout);
    d2k_httpsearch_free(search);
    d2k_diag_free(diagnostics);
    return result != 0;
}
