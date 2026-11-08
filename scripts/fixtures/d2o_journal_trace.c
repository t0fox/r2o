/* d2o_journal_trace — печатает кольцо production `datapath/journal.c`. */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "d2k_journal.h"
#include "d2k_plans.h"

static const char *kind_name(uint8_t kind) {
    switch (kind) {
    case D2K_JRN_HELLO_SNI:    return "приветствие";
    case D2K_JRN_HELLO_NONAME: return "приветствие без имени";
    case D2K_JRN_PLAN_APPLIED: return "план применён";
    case D2K_JRN_PLAN_REFUSED: return "план не применён";
    case D2K_JRN_EXCHANGE:     return "обмен пошёл";
    case D2K_JRN_SHAPE:        return "снята форма приветствия";
    case D2K_JRN_SUSPECT:      return "подозрение";
    case D2K_JRN_PLAN_DONE:    return "";
    case D2K_JRN_PLAN_UNSENT:  return "посылка не ушла";
    case D2K_JRN_PLAN_DAMAGED: return "поток испорчен";
    default:                   return "запись неизвестного вида";
    }
}

static void print_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
}

int main(void) {
    d2k_journal *retention = d2k_journal_new(3);
    if (!retention) return 2;
    d2k_key key;
    memset(&key, 0, sizeof key);
    key.proto = 6;
    key.family = 4;
    key.low_ip = 0x0100007f;
    key.high_ip = 0x0200007f;
    key.low_port = 0xbb01;
    key.high_port = 0x01bb;
    for (uint64_t at = 100; at <= 500; at += 100) {
        d2k_journal_add(retention, at, &key, D2K_JRN_HELLO_SNI, 0, 0, NULL,
                        NULL, 0, NULL);
    }
    printf("retention count=%zu added=%" PRIu64 " dropped=%" PRIu64 "\n",
           d2k_journal_count(retention), d2k_journal_added(retention),
           d2k_journal_dropped(retention));
    d2k_journal_free(retention);

    d2k_journal *journal = d2k_journal_new(10);
    if (!journal) return 2;

    static const uint8_t plan_id[16] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    static const uint8_t trial_id[16] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
                                         0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f};
    static const uint8_t name[] = {'e','x','a','\1','m','p','l','e','.','c','o','m'};

    d2k_journal_add(journal, 1000, &key, D2K_JRN_HELLO_SNI, 0, 0, NULL,
                    name, sizeof name, NULL);
    d2k_journal_add_applied(journal, 2000, &key, plan_id, trial_id);
    d2k_journal_add_refused(journal, 3000, &key, D2K_REFUSE_NOT_APPLIED,
                            plan_id, trial_id, "своя причина");
    d2k_jrn_detail exchange;
    memset(&exchange, 0, sizeof exchange);
    exchange.tos = 0x88;
    exchange.server_hello = 1;
    exchange.planned = D2K_PLANNED_NO;
    d2k_journal_add(journal, 4000, &key, D2K_JRN_EXCHANGE, 22, 1234, &exchange,
                    NULL, 0, NULL);
    d2k_journal_add(journal, 5000, &key, D2K_JRN_SHAPE, 0, 0, NULL, NULL, 0, NULL);
    d2k_jrn_detail suspect;
    memset(&suspect, 0, sizeof suspect);
    suspect.ttl = 63;
    suspect.ref_ttl = 64;
    suspect.tos = 0x88;
    suspect.ipid = 0x4321;
    suspect.planned = D2K_PLANNED_YES;
    suspect.client_shape = 8;
    d2k_journal_add(journal, 6000, &key, D2K_JRN_SUSPECT, D2K_SUSPECT_RST,
                    0, &suspect, NULL, 0, NULL);
    d2k_binding_context binding;
    memset(&binding, 0, sizeof binding);
    binding.generation = 0x0102030405060708ull;
    binding.kind = D2K_BIND_NAME;
    binding.family = 4;
    binding.shape = D2K_PLAN_SHAPE_MODERN;
    binding.temporary = 0;
    memset(binding.epoch, 0x11, sizeof binding.epoch);
    d2k_journal_add_fate_bound(journal, 7000, &key, D2K_JRN_PLAN_DONE,
                               D2K_REFUSE_NONE, plan_id, trial_id,
                               0x1122334455667788ull, &binding);
    d2k_journal_add_fate(journal, 8000, &key, D2K_JRN_PLAN_UNSENT,
                         D2K_REFUSE_TOO_LONG, plan_id, trial_id);
    d2k_journal_add_fate(journal, 9000, &key, D2K_JRN_PLAN_DAMAGED,
                         D2K_REFUSE_DAMAGED, plan_id, trial_id);

    printf("summary count=%zu added=%" PRIu64 " dropped=%" PRIu64 "\n",
           d2k_journal_count(journal), d2k_journal_added(journal),
           d2k_journal_dropped(journal));
    for (size_t i = 0; i < d2k_journal_count(journal); i++) {
        const d2k_jrn_entry *entry = d2k_journal_at(journal, i);
        if (!entry) continue;
        printf("entry at=%" PRIu64 " kind=%s code=%u name=",
               entry->at_ns, kind_name(entry->kind), entry->code);
        for (uint8_t n = 0; n < entry->name_len; n++) putchar(entry->name[n]);
        printf(" note=%s plan=", entry->note ? entry->note : "");
        print_hex(entry->plan_id, sizeof entry->plan_id);
        printf(" trial=");
        print_hex(entry->trial_id, sizeof entry->trial_id);
        printf(" exec=%" PRIu64 " binding=%" PRIu64 "/%u/%u/%u/%u/",
               entry->execution_id, entry->binding.generation,
               entry->binding.kind, entry->binding.family, entry->binding.shape,
               entry->binding.temporary);
        print_hex(entry->binding.epoch, sizeof entry->binding.epoch);
        printf("\n");
    }
    d2k_journal_free(journal);
    return 0;
}
