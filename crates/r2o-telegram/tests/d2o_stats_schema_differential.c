/* TG19: C-оракул D2O stats-схемы.
 *
 * Включает production `stats_socket.c` и использует его
 * `append_active_sessions`/`stats_append` для сериализации synthetic stats.
 */
#define _POSIX_C_SOURCE 200809L
#include "stats_socket.c"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    tg_epoll_proxy_stats stats;
    memset(&stats, 0, sizeof stats);
    stats.monotonic_time_ms = 500000;
    stats.active_connections = 2;
    stats.process_started_at = 1700000000;
    stats.accepted_connections = 2;
    stats.max_connections = 64;
    stats.active_wss_connections = 1;
    stats.max_wss_connections = 64;
    stats.buffer_bytes_current = 1024;
    stats.buffer_bytes_peak = 4096;
    stats.buffer_bytes_limit = 1000000;
    stats.connections_started = 2;
    stats.bytes_from_clients = 1000;
    stats.bytes_from_upstreams = 2000;
    stats.wss_attempts = 2;
    stats.wss_failures = 1;
    stats.wss_responses = 4;
    stats.cf_wss_responses = 2;
    stats.last_success_dc = 2;
    stats.last_success_route = 3;
    stats.last_success_latency_ms = 250;
    stats.last_success_age_ms = 1000;
    stats.last_failure_dc = 4;
    stats.last_failure_route = 2;
    stats.last_failure_stage = 4;
    stats.last_failure_age_ms = 500;
    stats.client_response_latency_total = 4;
    stats.client_response_latency_samples = 4;
    stats.client_response_latency_last_us = 400;
    stats.client_response_latency_p50_us = 200;
    stats.client_response_latency_p95_us = 400;

    stats.route_cooldown_ms = 30000;
    stats.route_cooldowns_count = 1;
    stats.route_cooldowns[0].dc = 4;
    stats.route_cooldowns[0].is_media = 1;
    stats.route_cooldowns[0].transport = TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_WORKER;
    stats.route_cooldowns[0].remaining_ms = 15000;
    stats.route_cooldowns[0].failure_stage = 4;

    stats.active_sessions_count = 2;
    tg_active_route_session *first = &stats.active_sessions[0];
    first->id = 1;
    first->has_dc = 1;
    first->dc = 2;
    first->has_media = 1;
    first->is_media = 0;
    first->stage = TG_ROUTE_SESSION_STAGE_FIRST_WSS_BINARY_RESPONSE;
    first->direct_state = TG_ROUTE_SESSION_FIRST_BINARY_RESPONSE;
    first->direct_transport = TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS;
    first->selected_transport = TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS;
    first->telegram_response_seen = 1;
    first->bytes_from_clients = 100;
    first->bytes_from_upstreams = 200;
    first->event_count = 4;
    first->events[0].sequence = 1;
    first->events[0].timestamp_ms = 499100;
    first->events[0].branch = 0;
    first->events[0].transport = TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS;
    first->events[0].state = TG_ROUTE_SESSION_CONNECTING;
    first->events[1].sequence = 2;
    first->events[1].timestamp_ms = 499200;
    first->events[1].branch = 0;
    first->events[1].transport = TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS;
    first->events[1].state = TG_ROUTE_SESSION_CONNECTED;
    first->events[2].sequence = 3;
    first->events[2].timestamp_ms = 499300;
    first->events[2].branch = 0;
    first->events[2].transport = TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS;
    first->events[2].state = TG_ROUTE_SESSION_SELECTED;
    first->events[3].sequence = 4;
    first->events[3].timestamp_ms = 499750;
    first->events[3].branch = 0;
    first->events[3].transport = TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS;
    first->events[3].state = TG_ROUTE_SESSION_FIRST_BINARY_RESPONSE;

    tg_active_route_session *second = &stats.active_sessions[1];
    second->id = 2;
    second->stage = TG_ROUTE_SESSION_STAGE_ROUTING;
    second->fallback_state = TG_ROUTE_SESSION_CONNECTING;
    second->fallback_transport = TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_WORKER;
    second->bytes_from_clients = 900;
    second->bytes_from_upstreams = 1800;
    second->event_count = 1;
    second->events[0].sequence = 1;
    second->events[0].timestamp_ms = 499900;
    second->events[0].branch = 1;
    second->events[0].transport = TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_WORKER;
    second->events[0].state = TG_ROUTE_SESSION_CONNECTING;

    char response[131072];
    size_t used = 0;
    int length = snprintf(response, sizeof(response),
                          "{\"active_connections\":%zu,", stats.active_connections);
    if (length <= 0 || (size_t)length >= sizeof(response)) return 2;
    used = (size_t)length;
    if (append_active_sessions(response, sizeof(response), &used, &stats) != 0)
        return 3;
    if (stats_append(response, sizeof(response), &used,
            "\"max_connections\":%zu,\"active_wss_connections\":%zu"
            ",\"max_wss_connections\":%zu"
            ",\"buffer_bytes_current\":%zu"
            ",\"buffer_bytes_peak\":%zu"
            ",\"buffer_bytes_limit\":%zu"
            ",\"connections_started\":%" PRIu64
            ",\"bytes_from_clients\":%" PRIu64
            ",\"bytes_from_upstreams\":%" PRIu64
            ",\"wss_attempts\":%" PRIu64 ",\"wss_failures\":%" PRIu64
            ",\"wss_responses\":%" PRIu64
            ",\"cf_wss_responses\":%" PRIu64
            ",\"last_success_dc\":%u,\"last_success_route\":%u"
            ",\"last_success_latency_ms\":%" PRIu64
            ",\"last_success_age_ms\":%" PRIu64
            ",\"last_failure_dc\":%u,\"last_failure_route\":%u"
            ",\"last_failure_stage\":%u,\"last_failure_age_ms\":%" PRIu64
            ",\"client_response_latency_total\":%" PRIu64
            ",\"client_response_latency_samples\":%zu"
            ",\"client_response_latency_last_us\":%" PRIu64
            ",\"client_response_latency_p50_us\":%" PRIu64
            ",\"client_response_latency_p95_us\":%" PRIu64
            "}\n",
            stats.max_connections, stats.active_wss_connections,
            stats.max_wss_connections, stats.buffer_bytes_current,
            stats.buffer_bytes_peak, stats.buffer_bytes_limit,
            stats.connections_started, stats.bytes_from_clients,
            stats.bytes_from_upstreams, stats.wss_attempts,
            stats.wss_failures, stats.wss_responses,
            stats.cf_wss_responses, stats.last_success_dc,
            stats.last_success_route, stats.last_success_latency_ms,
            stats.last_success_age_ms,
            stats.last_failure_dc, stats.last_failure_route,
            stats.last_failure_stage, stats.last_failure_age_ms,
            stats.client_response_latency_total,
            stats.client_response_latency_samples,
            stats.client_response_latency_last_us,
            stats.client_response_latency_p50_us,
            stats.client_response_latency_p95_us) != 0)
        return 4;
    fwrite(response, 1, used, stdout);
    return 0;
}
