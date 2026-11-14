/* C/Rust differential: live-секция dns_services D2O current main 7a5fab9.
 *
 * Вызывает настоящий `d2k_sched_set_dns_services` +
 * `write_live_dns_services` на синтетическом планировщике. Health-проб нет:
 * проверяется начальное состояние detected и поля конфигурации. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_sched s;
static d2k_catalog cat;
static d2k_cat_box box;
static d2k_cat_binding binding;
static d2k_cat_plan plan;

static void service(d2k_dns_service *out, const char *protocol, const char *host,
                    const char *sni, const char *path, const char *source,
                    uint16_t port) {
    memset(out, 0, sizeof *out);
    snprintf(out->protocol, sizeof out->protocol, "%s", protocol);
    snprintf(out->host, sizeof out->host, "%s", host);
    snprintf(out->sni, sizeof out->sni, "%s", sni);
    snprintf(out->path, sizeof out->path, "%s", path);
    snprintf(out->source, sizeof out->source, "%s", source);
    out->port = port;
}

int main(void) {
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    memset(&box, 0, sizeof box);
    memset(&binding, 0, sizeof binding);
    memset(&plan, 0, sizeof plan);

    snprintf(plan.id, sizeof plan.id, "plan-dns");
    snprintf(plan.proto, sizeof plan.proto, "tls");
    plan.text = "r2o-plan 1 11\nproto tcp tls\nsplit sni_middle +0\n";
    plan.enabled = 1;
    plan.successes = 1;
    box.plans = &plan;
    box.n_plans = 1;
    snprintf(binding.kind, sizeof binding.kind, "name");
    snprintf(binding.target, sizeof binding.target, "dns.example");
    snprintf(binding.plan_id, sizeof binding.plan_id, "plan-dns");
    binding.level = 3;
    binding.enabled = 1;
    binding.transport = 6;
    binding.family = 4;
    binding.shape = 1;
    box.binds = &binding;
    box.n_binds = 1;
    snprintf(box.id, sizeof box.id, "box-dns");
    cat.boxes = &box;
    cat.n_boxes = 1;
    s.cat = &cat;

    d2k_dns_service services[3];
    service(&services[0], "doh", "dns.example", "dns.example",
            "/dns-query?token=secret", "https-dns-proxy", 443);
    service(&services[1], "dot", "1.1.1.1", "", "/", "dnsproxy", 853);
    service(&services[2], "doq", "2001:db8::1", "", "/", "doqd", 853);
    d2k_sched_set_dns_services(&s, services, 3);

    printf("{");
    write_live_dns_services(stdout, &s);
    printf("\"end\": true}\n");
    return 0;
}
