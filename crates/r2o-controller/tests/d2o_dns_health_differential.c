/* C-оракул DNS health из core/verify.c current main 7a5fab9.
 *
 * verify.c включается как TU: dns_probe_reply статическая. Печатаются
 * DNS-wire запрос, проверки crafted A/AAAA/TC/rcode/compression/лишних
 * answers и результаты d2k_verify_doh_response_parse.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

#include "verify.c"

static void print_hex(const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
}

static void print_dns_case(const char *name, const uint8_t *msg, size_t len,
                           unsigned id)
{
    printf("dns case=%s result=%d\n", name, dns_probe_reply(msg, len, id));
}

static void build_header(uint8_t *msg, uint16_t id, uint16_t flags,
                         uint16_t answers)
{
    memset(msg, 0, 12);
    msg[0] = (uint8_t)(id >> 8); msg[1] = (uint8_t)id;
    msg[2] = (uint8_t)(flags >> 8); msg[3] = (uint8_t)flags;
    msg[4] = 0; msg[5] = 1;
    msg[6] = (uint8_t)(answers >> 8); msg[7] = (uint8_t)answers;
}

static size_t append_question(uint8_t *msg)
{
    static const uint8_t question[] = {
        7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0, 0, 1, 0, 1
    };
    memcpy(msg + 12, question, sizeof question);
    return 12 + sizeof question;
}

static size_t append_answer(uint8_t *msg, size_t pos, uint16_t type,
                            uint16_t cls, uint16_t rdlen, uint8_t fill)
{
    msg[pos++] = 0xc0; msg[pos++] = 12;
    msg[pos++] = (uint8_t)(type >> 8); msg[pos++] = (uint8_t)type;
    msg[pos++] = (uint8_t)(cls >> 8); msg[pos++] = (uint8_t)cls;
    memset(msg + pos, 0, 4); pos += 4; /* TTL */
    msg[pos++] = (uint8_t)(rdlen >> 8); msg[pos++] = (uint8_t)rdlen;
    memset(msg + pos, fill, rdlen); pos += rdlen;
    return pos;
}

static size_t valid_a(uint8_t *msg, uint16_t flags, uint16_t answers,
                      uint16_t type, uint16_t cls, uint16_t rdlen)
{
    build_header(msg, 0x1234, flags, answers);
    size_t pos = append_question(msg);
    return append_answer(msg, pos, type, cls, rdlen, 0x7f);
}

static void print_doh_case(const char *name, const uint8_t *response,
                           size_t length)
{
    d2k_ver_result result;
    memset(&result, 0, sizeof result);
    int rc = d2k_verify_doh_response_parse(response, length, 0x1234, &result);
    int state = rc > 0 ? 1 : (!result.unsupported ? 0 : 2);
    printf("doh case=%s state=%d rc=%d status=%d dns=%d unsupported=%d "
           "complete=%d chunked=%d has_length=%d body=%llu\n",
           name, state, rc, result.status, result.dns_reply, result.unsupported,
           result.body_complete, result.body_chunked, result.body_has_length,
           (unsigned long long)result.body_bytes);
}

int main(void)
{
    static const uint8_t query[] = {
        0, 29, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0, 0, 1, 0, 1
    };
    uint8_t msg[8192];
    printf("query hex="); print_hex(query, sizeof query); printf("\n");

    size_t n = valid_a(msg, 0x8180, 1, 1, 1, 4);
    print_dns_case("valid-a", msg, n, 0x1234);
    n = valid_a(msg, 0x8180, 1, 28, 1, 16);
    print_dns_case("aaaa-only", msg, n, 0x1234);
    n = valid_a(msg, 0x8380, 1, 1, 1, 4);
    print_dns_case("tc", msg, n, 0x1234);
    n = valid_a(msg, 0x8183, 1, 1, 1, 4);
    print_dns_case("rcode", msg, n, 0x1234);
    n = valid_a(msg, 0x8980, 1, 1, 1, 4);
    print_dns_case("opcode", msg, n, 0x1234);
    n = valid_a(msg, 0x8180, 1, 1, 2, 4);
    print_dns_case("wrong-class", msg, n, 0x1234);
    n = valid_a(msg, 0x8180, 1, 1, 1, 3);
    print_dns_case("short-a", msg, n, 0x1234);
    build_header(msg, 0x1234, 0x8180, 2);
    n = append_question(msg);
    n = append_answer(msg, n, 1, 1, 4, 0x7f);
    n = append_answer(msg, n, 28, 1, 16, 0x7f);
    print_dns_case("extra-answers", msg, n, 0x1234);
    build_header(msg, 0x1234, 0x8180, 1);
    memcpy(msg + 12, "\x03www\x07example\x03com\x00\x00\x01\x00\x01", 21);
    n = 12 + 21;
    n = append_answer(msg, n, 1, 1, 4, 0x7f);
    print_dns_case("wrong-question", msg, n, 0x1234);

    /* DoH-векторы: тело — валидный DNS-ответ. */
    uint8_t dns[512];
    size_t dns_len = valid_a(dns, 0x8180, 1, 1, 1, 4);
    const char *head =
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
        "Content-Length: %zu\r\n\r\n";
    int hlen = snprintf((char *)msg, sizeof msg, head, dns_len);
    memcpy(msg + hlen, dns, dns_len);
    print_doh_case("length", msg, (size_t)hlen + dns_len);

    hlen = snprintf((char *)msg, sizeof msg,
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
        "Transfer-Encoding: chunked\r\n\r\n%zx\r\n", dns_len);
    memcpy(msg + hlen, dns, dns_len);
    hlen += (int)dns_len;
    memcpy(msg + hlen, "\r\n0\r\n\r\n", 7);
    print_doh_case("chunked", msg, (size_t)hlen + 7);

    memset(msg, 0, sizeof msg);
    memcpy(msg, dns, dns_len);
    hlen = snprintf((char *)msg, sizeof msg,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\n");
    msg[hlen] = 'x';
    print_doh_case("wrong-type", msg, (size_t)hlen + 1);

    hlen = snprintf((char *)msg, sizeof msg,
        "HTTP/1.1 413 Too Large\r\nContent-Type: application/dns-message\r\n"
        "Content-Length: 1\r\n\r\nx");
    print_doh_case("http-413", msg, (size_t)hlen);

    hlen = snprintf((char *)msg, sizeof msg,
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
        "Content-Length: 5000\r\n\r\n");
    print_doh_case("too-big", msg, (size_t)hlen);

    hlen = snprintf((char *)msg, sizeof msg,
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
        "Content-Length: %zu\r\n\r\n", dns_len);
    memcpy(msg + hlen, dns, 3);
    print_doh_case("incomplete", msg, (size_t)hlen + 3);

    return 0;
}
