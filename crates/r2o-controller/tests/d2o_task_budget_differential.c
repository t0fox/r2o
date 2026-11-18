#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

int d2k_hello_ech_offer(const uint8_t *bytes, size_t length, uint8_t *config_id)
{
    (void)bytes;
    (void)length;
    (void)config_id;
    return 0;
}

static d2k_sched scheduler;
static d2k_catalog catalog;
static d2k_cat_box box;
static task t;

static void add_signal(d2k_cat_fp *fp, const char *kind, int packets)
{
    d2k_cat_signal *sig = &fp->sig[fp->n_sig++];
    memset(sig, 0, sizeof *sig);
    snprintf(sig->kind, sizeof sig->kind, "%s", kind);
    sig->packets = packets;
}

static void case_budget(const char *label)
{
    unsigned budget = task_budget(&scheduler, &t);
    printf("%s|%u|%s\n", label, budget, t.budget_src);
}

int main(void)
{
    scheduler.cat = &catalog;
    snprintf(box.id, sizeof box.id, "%s", "box-1");
    add_signal(&box.fp, "rx-volume", 64);
    catalog.boxes = &box;
    catalog.n_boxes = 1;

    t.transport = 6;
    add_signal(&t.fp, "rx-volume", 120);
    case_budget("own_signal");

    memset(&t, 0, sizeof t);
    t.transport = 6;
    t.vol.rx_cut_packets = 80;
    case_budget("own_cut");

    memset(&t, 0, sizeof t);
    t.transport = 6;
    snprintf(t.box_id, sizeof t.box_id, "%s", "box-1");
    case_budget("box_signal");

    memset(&t, 0, sizeof t);
    t.transport = 6;
    case_budget("field");

    memset(&t, 0, sizeof t);
    t.transport = 17;
    t.vol.rx_cut_packets = 80;
    case_budget("udp_cut");

    memset(&t, 0, sizeof t);
    t.transport = 6;
    add_signal(&t.fp, "rx-volume", 0);
    snprintf(t.box_id, sizeof t.box_id, "%s", "box-1");
    case_budget("zero_signal_box");

    memset(&t, 0, sizeof t);
    t.transport = 6;
    add_signal(&t.fp, "volume", 120);
    case_budget("non_rx_kind");
    return 0;
}
