#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "raw.c"

static char captured[512];

static int capture_rule(const char *command)
{
    snprintf(captured, sizeof(captured), "%s", command);
    return 0;
}

static const char *field(const char *fixture, const char *name, char *storage, size_t cap)
{
    FILE *file = fopen(fixture, "r");
    char line[1024], prefix[64];
    snprintf(prefix, sizeof(prefix), "%s=", name);
    if (!file) return NULL;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, prefix, strlen(prefix)) != 0) continue;
        char *value = line + strlen(prefix);
        value[strcspn(value, "\r\n")] = '\0';
        snprintf(storage, cap, "%s", value);
        fclose(file);
        return storage;
    }
    fclose(file);
    return NULL;
}

int main(int argc, char **argv)
{
    char firewall[16], source_port[32], destination[64], destination_port[32];
    char expected_add[256], expected_delete[256], expected_command[320];
    if (argc != 2 || !field(argv[1], "source_port", source_port, sizeof(source_port)) ||
        !field(argv[1], "firewall", firewall, sizeof(firewall)) ||
        !field(argv[1], "destination", destination, sizeof(destination)) ||
        !field(argv[1], "destination_port", destination_port, sizeof(destination_port)) ||
        !field(argv[1], "c_add", expected_add, sizeof(expected_add)) ||
        !field(argv[1], "c_delete", expected_delete, sizeof(expected_delete))) {
        fprintf(stderr, "invalid fixture\n");
        return 2;
    }
    rst_key key = {0};
    key.sport = (uint16_t)strtoul(source_port, NULL, 10);
    key.dport = (uint16_t)strtoul(destination_port, NULL, 10);
    key.family = 4;
    if (inet_pton(AF_INET, destination, key.dst) != 1 ||
        setenv("D2K_FW", firewall, 1) != 0)
        return 2;
    d2k_raw_rule_hook = capture_rule;

    if (snprintf(expected_command, sizeof(expected_command),
                 "%s >/dev/null 2>&1", expected_add) >= (int)sizeof(expected_command))
        return 2;
    if (rst_rule_cmd_form("-I", &key, 1) != 0 ||
        strcmp(captured, expected_command) != 0) return 1;
    printf("C %s\n", expected_add);

    if (snprintf(expected_command, sizeof(expected_command),
                 "%s >/dev/null 2>&1", expected_delete) >= (int)sizeof(expected_command))
        return 2;
    if (rst_rule_cmd_form("-D", &key, 1) != 0 ||
        strcmp(captured, expected_command) != 0) return 1;
    printf("C %s\n", expected_delete);
    return 0;
}

int64_t d2k_now_ms(void)
{
    return 0;
}
