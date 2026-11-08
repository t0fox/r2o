#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int exchange(const d2k_panel_config *config, const char *request,
                    char *body, size_t body_cap) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) { return -1; }
    size_t request_len = strlen(request);
    size_t sent = 0;
    while (sent < request_len) {
        ssize_t count = write(sockets[0], request + sent, request_len - sent);
        if (count <= 0) { close(sockets[0]); close(sockets[1]); return -1; }
        sent += (size_t)count;
    }
    shutdown(sockets[0], SHUT_WR);
    (void)d2k_panel_handle_fd(sockets[1], config);
    close(sockets[1]);

    char response[8192];
    size_t received = 0;
    while (received + 1 < sizeof response) {
        ssize_t count = read(sockets[0], response + received, sizeof response - received - 1);
        if (count == 0) { break; }
        if (count < 0) { close(sockets[0]); return -1; }
        received += (size_t)count;
    }
    close(sockets[0]);
    response[received] = '\0';

    int status = 0;
    if (sscanf(response, "HTTP/1.1 %d", &status) != 1) { return -1; }
    const char *separator = strstr(response, "\r\n\r\n");
    if (!separator) { return -1; }
    const char *body_start = separator + 4;
    size_t body_len = received - (size_t)(body_start - response);
    if (body_len + 1 > body_cap) { return -1; }
    memcpy(body, body_start, body_len);
    body[body_len] = '\0';
    return status;
}

static int show(const d2k_panel_config *config, const char *request) {
    char body[4096];
    int status = exchange(config, request, body, sizeof body);
    if (status < 0) { return -1; }
    size_t length = strlen(body);
    while (length && (body[length - 1] == '\n' || body[length - 1] == '\r')) {
        body[--length] = '\0';
    }
    printf("%d\n%s\n", status, body);
    return 0;
}

static const char stop_request[] =
    "POST /api/control/stop HTTP/1.1\r\n"
    "Host: localhost:8090\r\n"
    "Origin: http://localhost:8090\r\n"
    "Content-Length: 0\r\n\r\n";
static const char start_request[] =
    "POST /api/control/start HTTP/1.1\r\n"
    "Host: localhost:8090\r\n"
    "Origin: http://localhost:8090\r\n"
    "Content-Length: 0\r\n\r\n";

int main(void) {
    const char *service = getenv("R2O_PANEL_CONTROL_SERVICE");
    if (!service || !*service) { return 2; }
    d2k_panel_config config = {
        .service_path = service,
        .control_enabled = 1,
    };

    /* 202: команда запущена. */
    if (show(&config, stop_request) != 0) { return 3; }
    /* 409: предыдущая команда ещё выполняется. */
    if (show(&config, stop_request) != 0) { return 4; }
    /* 500: служба не найдена. */
    config.service_path = "";
    if (show(&config, stop_request) != 0) { return 5; }

    /* 404: неизвестное действие. */
    if (show(&config, "POST /api/control/bogus HTTP/1.1\r\n"
                      "Host: localhost:8090\r\n"
                      "Origin: http://localhost:8090\r\n"
                      "Content-Length: 0\r\n\r\n") != 0) { return 6; }

    /* 403: управление выключено. */
    config.control_enabled = 0;
    if (show(&config, stop_request) != 0) { return 7; }
    config.control_enabled = 1;

    /* 403: чужой источник. */
    if (show(&config, "POST /api/control/stop HTTP/1.1\r\n"
                      "Host: localhost:8090\r\n"
                      "Origin: http://evil.example\r\n"
                      "Content-Length: 0\r\n\r\n") != 0) { return 8; }

    /* 409: MODE=off запрещает запуск/перезапуск. */
    config.mode = "off";
    if (show(&config, start_request) != 0) { return 9; }
    config.mode = "apply";

    /* 409: telegram-enable без TG_MODE=local. */
    config.config_path = "/nonexistent/r2o-panel-test-config";
    if (show(&config, "POST /api/control/telegram-enable HTTP/1.1\r\n"
                      "Host: localhost:8090\r\n"
                      "Origin: http://localhost:8090\r\n"
                      "Content-Length: 0\r\n\r\n") != 0) { return 10; }
    config.config_path = "";

    /* 400: тело запрещено (Content-Length). */
    if (show(&config, "POST /api/control/stop HTTP/1.1\r\n"
                      "Host: localhost:8090\r\n"
                      "Origin: http://localhost:8090\r\n"
                      "Content-Length: 1\r\n\r\nx") != 0) { return 11; }

    /* 400: тело запрещено (Transfer-Encoding). */
    if (show(&config, "POST /api/control/stop HTTP/1.1\r\n"
                      "Host: localhost:8090\r\n"
                      "Origin: http://localhost:8090\r\n"
                      "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n") != 0) { return 12; }

    /* 405: не-POST на control. */
    if (show(&config, "GET /api/control/stop HTTP/1.1\r\n"
                      "Host: localhost:8090\r\n\r\n") != 0) { return 13; }
    return 0;
}
