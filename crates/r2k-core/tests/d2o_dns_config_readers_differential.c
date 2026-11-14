/* C-оракул: чтение https-dns-proxy/dnsproxy/doqd/Keenetic из current
 * main `runtime/d2k_dns_config.c`. Файл включается целиком: читатели
 * статические; временные файлы создаются в /tmp. */
#include "d2k_dns_config.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char HTTPS_FIXTURE[] =
    "\n"
    "config https-dns-proxy 'a'\n"
    "    option enabled '1'\n"
    "    option bootstrap_dns '1.1.1.1,8.8.8.8'\n"
    "    option resolver_url 'https://dns.example/dns-query'\n"
    "    option resolver_url 'tls://dot.example'\n"
    "\n"
    "config https-dns-proxy 'b'\n"
    "    option enabled '0'\n"
    "    option resolver_url 'https://disabled.example/dns-query'\n"
    "\n"
    "config other 'x'\n";

static const char DNSPROXY_FIXTURE[] =
    "\n"
    "config dnsproxy 'global'\n"
    "    option enabled '1'\n"
    "\n"
    "config dnsproxy 'servers'\n"
    "    list bootstrap '1.1.1.1'\n"
    "    list bootstrap '[2001:db8::1]:53'\n"
    "    list bootstrap 'not-an-ip'\n"
    "    list upstream 'https://dns.example/dns-query'\n"
    "    list upstream 'tls://dot.example'\n"
    "    list upstream 'https://dns.example/dns-query'\n";

static const char DOQD_FIXTURE[] =
    "\n"
    "upstream https://dns.example/dns-query\n"
    "fallback 'tls://dot.example'\n"
    "upstream \"quic://[2001:db8::1]\"\n"
    "# upstream https://ignored.example/\n";

static const char KEENETIC_FIXTURE[] =
    "\n"
    "proxy-tls:\n"
    "server-tls:\n"
    "  address: 1.1.1.1\n"
    "  port: 853\n"
    "  sni: dot.example\n"
    "server-tls:\n"
    "  address: 2001:db8::1\n"
    "proxy-https:\n"
    "server-https:\n"
    "  address: 9.9.9.9\n"
    "  uri: https://keenetic.example/dns-query\n"
    "proxy-https-filters:\n"
    "server-https:\n"
    "  address: ignored.example\n"
    "  uri: https://after-filter.example/dns-query\n";

static int write_file(const char *path, const char *text) {
    FILE *file = fopen(path, "w");
    if (!file) return -1;
    int ok = fputs(text, file) >= 0;
    fclose(file);
    return ok ? 0 : -1;
}

static void print_services(char prefix, const d2k_dns_service *items,
                           size_t count) {
    for (size_t i = 0; i < count; i++) {
        const d2k_dns_service *s = &items[i];
        printf("%c%zu %s|%s|%s|%s|%s|%s|%u\n", prefix, i, s->protocol, s->host,
               s->sni, s->path, s->bootstrap_dns, s->source,
               (unsigned)s->port);
    }
}

int main(void) {
    char directory[] = "/tmp/r2o-dns-readers-XXXXXX";
    char https_path[256], dnsproxy_path[256], doqd_path[256];
    d2k_dns_service items[D2K_DNS_SERVICE_MAX];
    size_t count = 0;
    if (!mkdtemp(directory)) return 2;
    snprintf(https_path, sizeof https_path, "%s/https", directory);
    snprintf(dnsproxy_path, sizeof dnsproxy_path, "%s/dnsproxy", directory);
    snprintf(doqd_path, sizeof doqd_path, "%s/doqd", directory);
    if (write_file(https_path, HTTPS_FIXTURE) != 0 ||
        write_file(dnsproxy_path, DNSPROXY_FIXTURE) != 0 ||
        write_file(doqd_path, DOQD_FIXTURE) != 0)
        return 3;

    count = 0;
    read_https(https_path, items, D2K_DNS_SERVICE_MAX, &count);
    print_services('A', items, count);

    count = 0;
    read_dnsproxy(dnsproxy_path, items, D2K_DNS_SERVICE_MAX, &count);
    print_services('B', items, count);

    count = 0;
    read_doqd(doqd_path, "doqd", items, D2K_DNS_SERVICE_MAX, &count);
    print_services('C', items, count);

    count = 0;
    read_keenetic(KEENETIC_FIXTURE, items, D2K_DNS_SERVICE_MAX, &count);
    print_services('D', items, count);

    count = 0;
    d2k_dns_services_read(https_path, dnsproxy_path, doqd_path, "doqd",
                          KEENETIC_FIXTURE, items, D2K_DNS_SERVICE_MAX,
                          &count);
    print_services('E', items, count);

    unlink(https_path);
    unlink(dnsproxy_path);
    unlink(doqd_path);
    rmdir(directory);
    return 0;
}
