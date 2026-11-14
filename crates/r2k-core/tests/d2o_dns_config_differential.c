/* C-оракул: d2k_dns_uri_parse и d2k_dns_service_match из current main
 * `runtime/d2k_dns_config.c`. Файл включается целиком: функции внешние, но
 * зависят только от libc; чтение конфигураций не вызывается. */
#include "d2k_dns_config.c"

#include <stdio.h>
#include <string.h>

static void fill(d2k_dns_service *item, const char *protocol, const char *host,
                 const char *sni, uint16_t port) {
    memset(item, 0, sizeof *item);
    snprintf(item->protocol, sizeof item->protocol, "%s", protocol);
    snprintf(item->host, sizeof item->host, "%s", host);
    snprintf(item->sni, sizeof item->sni, "%s", sni);
    snprintf(item->path, sizeof item->path, "/");
    snprintf(item->source, sizeof item->source, "test");
    item->port = port;
}

int main(void) {
    static const char *uris[] = {
        "https://dns.example/Path?x=1#frag",
        "TLS://1.1.1.1:8853",
        "quic://[2001:db8::1]",
        "https://[fe80::1%25eth0]:8443",
        "https://user@dns.example:8443/a",
        "https://dns.example?x=1",
        "https://dns.example#frag",
        "https://dns.example/",
        "https://dns.example:+443",
        "https://dns.example: 443",
        "https://dns.example:000443",
        "https://dns.example:-0",
        "https://dns.example/a b",
        "https://dns.example/a\\b",
        "https://dns.example/a\"b",
        "https://dns.example:0",
        "https://dns.example:65536",
        "https://dns.example:abc",
        "http://dns.example",
        "https://",
        "https://[2001:db8::1",
        "https://[2001:db8::1]x",
    };

    for (size_t index = 0; index < sizeof uris / sizeof uris[0]; index++) {
        d2k_dns_service parsed;
        if (!d2k_dns_uri_parse(uris[index], "SrC", &parsed)) {
            printf("P%zu fail\n", index);
            continue;
        }
        printf("P%zu ok %s|%s|%s|%s|%u|%s|%s\n", index, parsed.protocol,
               parsed.host, parsed.sni, parsed.path, (unsigned)parsed.port,
               parsed.source, parsed.bootstrap_dns);
    }

    d2k_dns_service items[4];
    fill(&items[0], "dot", "dot.example", "dot.example", 853);
    fill(&items[1], "doh", "doh.example", "doh.example", 443);
    fill(&items[2], "doq", "doq.example", "doq.example", 853);
    fill(&items[3], "doh", "1.1.1.1", "", 443);

    struct {
        const char *name;
        const char *query;
        const char *ip;
        uint16_t port;
        uint8_t transport;
    } cases[] = {
        {"M0", "DOH.EXAMPLE", NULL, 443, 6},
        {"M1", "DOQ.EXAMPLE", NULL, 853, 17},
        {"M2", "DOQ.EXAMPLE", NULL, 853, 6},
        {"M3", NULL, "1.1.1.1", 443, 6},
        {"M4", "dot.example", NULL, 853, 6},
        {"M5", NULL, NULL, 443, 6},
        {"M6", "dot.example", NULL, 0, 6},
        {"M7", "dot.example", NULL, 853, 1},
        {"M8", "unknown", NULL, 443, 6},
    };
    for (size_t index = 0; index < sizeof cases / sizeof cases[0]; index++) {
        const d2k_dns_service *found = d2k_dns_service_match(
            items, sizeof items / sizeof items[0], cases[index].query,
            cases[index].ip, cases[index].port, cases[index].transport);
        if (!found) {
            printf("%s none\n", cases[index].name);
        } else {
            printf("%s %s\n", cases[index].name, found->host);
        }
    }
    return 0;
}
