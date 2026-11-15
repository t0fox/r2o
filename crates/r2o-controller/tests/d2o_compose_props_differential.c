/* C-оракул detect/props.c: prop_probes, apply_set и compose_from_props.
 *
 * props.c включается как TU; d2k_run_properties_family не вызывается и
 * выбрасывается --gc-sections. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

#include "props.c"

static const char *set_name(prop_set set)
{
    switch (set) {
    case SET_LEFT_OVERLAP: return "LEFT_OVERLAP";
    case SET_REORDER: return "REORDER";
    case SET_CHECKSUM: return "CHECKSUM";
    case SET_PARSES_L7: return "PARSES_L7";
    case SET_DUPLICATES: return "DUPLICATES";
    case SET_SYN: return "SYN";
    case SET_MD5: return "MD5";
    case SET_SEQ_WINDOW: return "SEQ_WINDOW";
    case SET_TIMESTAMPS: return "TIMESTAMPS";
    case SET_OVERLAP_SNI: return "OVERLAP_SNI";
    case SET_DUP_DENSE: return "DUP_DENSE";
    case SET_WHITE_TS: return "WHITE_TS";
    }
    return "?";
}

static const char *tri(d2k_tri value)
{
    return value == D2K_TRI_TRUE ? "1" : value == D2K_TRI_FALSE ? "0" : "u";
}

static void print_poison(const d2k_poison *p)
{
    printf("|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d",
           p->name, p->ttl, p->badsum, p->seq_shift, p->md5, p->decoy_hello,
           p->disorder, p->disorder_pos, p->tcp_ts, p->ip_id_zero, p->autottl,
           p->gap_ms, p->syn_data, p->oob, p->fake_between, p->repeats,
           p->seqovl_exact, p->seqovl, p->split_pos);
}

static void print_props(const d2k_dprops *p)
{
    printf("|%s%s%s%s%s%s%s%s%s%s%s|%d",
           tri(p->reassembles), tri(p->parses_l7), tri(p->validates_checksum),
           tri(p->tolerates_reorder), tri(p->tolerates_left_overlap),
           tri(p->counts_duplicates), tri(p->inspects_syn), tri(p->validates_md5),
           tri(p->validates_seq_window), tri(p->validates_timestamps),
           tri(p->overlap_covers_sni), p->hop_ttl);
}

static void print_compose(const char *name, const d2k_dprops *props,
                          const uint8_t *control, size_t control_len)
{
    d2k_poison out[8];
    int n = d2k_compose_from_props(props, control, control_len, out, 8);
    printf("compose|%s|%d", name, n);
    for (int i = 0; i < n; i++) print_poison(&out[i]);
    printf("\n");
}

int main(void)
{
    prop_probe probes[PROP_QUESTIONS];
    int n = prop_probes(probes, PROP_QUESTIONS);
    printf("props|%d\n", n);
    for (int i = 0; i < n; i++) {
        printf("prop|%d|%s|%s", i, probes[i].label, set_name(probes[i].set));
        print_poison(&probes[i].p);
        printf("\n");
    }

    for (int set = 0; set < 12; set++) {
        for (int ok = 0; ok <= 1; ok++) {
            d2k_dprops props;
            memset(&props, 0, sizeof props);
            apply_set(&props, (prop_set)set, ok, NULL);
            printf("apply|%s|%d", set_name((prop_set)set), ok);
            print_props(&props);
            printf("\n");
        }
    }

    d2k_dprops empty;
    memset(&empty, 0, sizeof empty);
    print_compose("empty-none", &empty, NULL, 0);
    static const uint8_t control[] = "BENIGN-CONTROL-PAYLOAD";
    print_compose("empty-control", &empty, control, sizeof control - 1);

    d2k_dprops duplicates = empty;
    duplicates.counts_duplicates = D2K_TRI_TRUE;
    print_compose("duplicates", &duplicates, NULL, 0);

    d2k_dprops all = empty;
    all.counts_duplicates = D2K_TRI_TRUE;
    all.tolerates_left_overlap = D2K_TRI_FALSE;
    all.tolerates_reorder = D2K_TRI_FALSE;
    print_compose("all", &all, NULL, 0);

    d2k_dprops overlap = empty;
    overlap.tolerates_left_overlap = D2K_TRI_FALSE;
    print_compose("overlap", &overlap, NULL, 0);

    d2k_dprops reorder = empty;
    reorder.tolerates_reorder = D2K_TRI_FALSE;
    print_compose("reorder", &reorder, NULL, 0);
    return 0;
}
