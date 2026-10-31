#define main donor_test_repeats_main
#include "test_repeats.c"
#undef main

#include <stdio.h>
#include <string.h>

static void print_selected(const char *label, const d2k_opts *options)
{
    const d2k_poison *poisons;
    int count;
    int i;
    int printed = 0;

    printf("%s|properties=%d\n", label, options->only[0] == '\0');
    printf("%s|raw=%d\n", label, !options->no_raw);
    poisons = d2k_poisons(&count);
    for (i = 0; i < count; i++) {
        if (options->only[0] != '\0' && strcmp(options->only, poisons[i].name) != 0) {
            continue;
        }
        if (d2k_opts_skipped(options, poisons[i].name)) {
            continue;
        }
        printf("%s|%s\n", label, poisons[i].name);
        printed++;
    }
    if (printed == 0) {
        printf("%s|empty\n", label);
    }
}

int main(void)
{
    d2k_opts options = {0};

    print_selected("all", &options);

    snprintf(options.only, sizeof(options.only), "%s", "seqovl-1");
    print_selected("only", &options);

    options.only[0] = '\0';
    snprintf(options.skip[0], sizeof(options.skip[0]), "%s", "seqovl-1");
    snprintf(options.skip[1], sizeof(options.skip[1]), "%s", "badsum-x2-g20");
    options.nskip = 2;
    print_selected("skip", &options);

    snprintf(options.only, sizeof(options.only), "%s", "seqovl-1");
    print_selected("only-skipped", &options);

    snprintf(options.only, sizeof(options.only), "%s", "unknown-poison");
    options.nskip = 0;
    print_selected("only-unknown", &options);

    options.only[0] = '\0';
    options.no_raw = 1;
    print_selected("no-raw", &options);
    return 0;
}
