"use strict";

const assert = require("node:assert/strict");
const flow = require("../assets/telegram-flow.js");

const stats = {
  process_started_at: 1_800_000_000,
  listener_ready: true,
  active_connections: 1,
  active_sessions: [{
    id: 1,
    dc: 2,
    is_media: false,
    stage: "first_wss_binary_response",
    direct_state: "selected",
    direct_transport: "direct_wss",
    fallback_state: "idle",
    fallback_transport: null,
    selected_transport: "direct_wss",
    telegram_response_seen: true,
    events: [{ sequence: 1, branch: "direct", transport: "direct_wss", state: "first_binary_response" }],
  }],
  route_sessions_truncated: false,
  max_connections: 128,
  accepted_connections: 7,
  wss_established: 5,
  mtproto_success: 4,
  mtproto_failure: 1,
  last_mtproto_response_at: 1_800_000_001,
  dc_map: { generation: 1, fetched_at: 1, freshness_seconds: 5 },
  cf_domain_pool: { domains: [], fetched_at: 1, freshness_seconds: 5 },
  workers: {},
  sessions_by_dc_transport: { "dc2:direct-wss": 4 },
  failures: { tls: 1 },
  ttfb: {},
  rss_kib: 1024,
  rss_hwm_kib: 2048,
};

const view = flow.summarizeTelegramFlow(stats);
assert.equal(view.activeConnections, 1);
assert.equal(view.acceptedConnections, 7);
assert.equal(view.lanes[0].counts.selected, 1);
assert.equal(view.lanes[0].confirmed, 1);
assert.deepEqual(view.dcActivity[1], { active: 1, media: 0, confirmed: 1 });
assert.equal(flow.hasCurrentRouteFailure(stats), false,
  "исторические MTProto ошибки не объявляются текущим отказом маршрута");
assert.deepEqual(flow.collectConfirmedTrafficDeltas(new Map(), stats.active_sessions), [],
  "отсутствующие byte counters не рисуют вымышленный трафик");

const confirmedSession = {
  ...stats.active_sessions[0],
  bytes_from_clients: 120,
  bytes_from_upstreams: 80,
};
const previousTraffic = new Map();
assert.deepEqual(flow.collectConfirmedTrafficDeltas(previousTraffic, [confirmedSession]), [],
  "первый снимок задаёт начальные счётчики без анимации");
assert.deepEqual(flow.collectConfirmedTrafficDeltas(previousTraffic, [{
  ...confirmedSession,
  bytes_from_clients: 152,
  bytes_from_upstreams: 96,
}]), [
  { id: 1, laneIndex: 0, dc: 2, direction: "request", bytes: 32 },
  { id: 1, laneIndex: 0, dc: 2, direction: "response", bytes: 16 },
], "рисуются только новые байты подтверждённой сессии");
console.log("Telegram panel Rust stats compatibility: PASS");
