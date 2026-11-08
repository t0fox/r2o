/* TG11: C-оракул TLS-проверки Meta edge с нейтральным SNI.
 *
 * Использование:
 *   d2o_tls_sni_differential CERT KEY GOOD_CA OTHER_CA
 *
 * Печатает `case ok=0|1 sni=<name>` в формате Rust-теста
 * `meta_edge::tests::d2o_tls_sni_and_hostname_verification_matches_c_trace`.
 */
#define _POSIX_C_SOURCE 200809L
#include "tg_tls.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    int listener;
    const char *cert;
    const char *key;
    char sni[256];
} server_args;

static int capture_sni(SSL *ssl, int *alert, void *opaque) {
    (void)alert;
    server_args *args = opaque;
    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (name && *name) snprintf(args->sni, sizeof(args->sni), "%s", name);
    return SSL_TLSEXT_ERR_OK;
}

static void *serve_one(void *opaque) {
    server_args *args = opaque;
    int fd = accept(args->listener, NULL, NULL);
    if (fd < 0) return NULL;
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());
    if (context) {
        SSL_CTX_use_certificate_file(context, args->cert, SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(context, args->key, SSL_FILETYPE_PEM);
        SSL_CTX_set_tlsext_servername_callback(context, capture_sni);
        SSL_CTX_set_tlsext_servername_arg(context, args);
        SSL *ssl = SSL_new(context);
        if (ssl) {
            SSL_set_fd(ssl, fd);
            (void)SSL_accept(ssl);
            SSL_free(ssl);
        }
        SSL_CTX_free(context);
    }
    close(fd);
    return NULL;
}

static int listen_loopback(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&address, sizeof address) != 0 ||
        listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    socklen_t length = sizeof address;
    if (getsockname(fd, (struct sockaddr *)&address, &length) != 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(address.sin_port);
    return fd;
}

static int connect_loopback(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&address, sizeof address) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void run_case(const char *name, const char *cert, const char *key,
                     const char *ca, const char *verify_name) {
    server_args args = {0};
    args.cert = cert;
    args.key = key;
    uint16_t port = 0;
    args.listener = listen_loopback(&port);
    if (args.listener < 0) {
        printf("%s ok=0 sni=\n", name);
        return;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, serve_one, &args) != 0) {
        close(args.listener);
        printf("%s ok=0 sni=\n", name);
        return;
    }
    SSL_CTX *context = tg_tls_client_context(ca);
    int fd = context ? connect_loopback(port) : -1;
    SSL *ssl =
        context && fd >= 0
            ? tg_tls_connect_fd_sni(context, fd, verify_name, "example.com")
            : NULL;
    int ok = ssl != NULL;
    if (ssl) SSL_free(ssl);
    if (fd >= 0) close(fd);
    if (context) SSL_CTX_free(context);
    pthread_join(thread, NULL);
    close(args.listener);
    printf("%s ok=%d sni=%s\n", name, ok, args.sni);
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    signal(SIGPIPE, SIG_IGN);
    run_case("valid", argv[1], argv[2], argv[3], "instagram.com");
    run_case("wrong-name", argv[1], argv[2], argv[3], "api.instagram.com");
    run_case("untrusted", argv[1], argv[2], argv[4], "instagram.com");
    return 0;
}
