//! TG19: печатает D2O-совместимый stats snapshot.

use std::sync::Arc;
use std::time::Duration;

use r2o_telegram::memory_budget::MemoryBudget;
use r2o_telegram::stats::RuntimeStats;

fn main() {
    let stats = Arc::new(RuntimeStats::new());
    stats.set_started_at(1_700_000_000);
    stats.set_max_connections(64);
    stats.set_listener_ready(true);
    let budget = Arc::new(MemoryBudget::new(1_000_000));
    budget.reserve(4096);
    budget.release(3072);
    stats.set_memory_budget(budget);

    let first = stats.connection_started();
    let second = stats.connection_started();
    let _wss = stats.wss_connection();
    stats.record_wss_established();

    let first_telemetry = first.telemetry();
    first_telemetry.set_dc(2, false);
    first_telemetry
        .begin_attempt("direct", "direct_wss")
        .finish("connected");
    first_telemetry.select_transport("direct", "direct_wss");
    first_telemetry.mark_first_wss_binary();
    first_telemetry.record_client_bytes(100);
    first_telemetry.record_upstream_bytes(200);

    let second_telemetry = second.telemetry();
    let _second_attempt = second_telemetry.begin_attempt("fallback", "cloudflare_worker");
    second_telemetry.record_client_bytes(900);
    second_telemetry.record_upstream_bytes(1800);

    for (dc, transport, latency_ms, client_us) in [
        (2u32, "direct_wss", 100u64, 100u64),
        (2, "cloudflare_worker", 200, 200),
        (2, "direct_wss", 150, 300),
        (2, "cloudflare_proxy", 250, 400),
    ] {
        stats.record_mtproto_response_with_client_latency(
            dc,
            transport,
            Duration::from_millis(latency_ms),
            client_us,
        );
    }
    stats.record_route_failure(4, true, "cloudflare_worker", 4);

    let snapshot = stats.d2o_snapshot();
    println!("{}", serde_json::to_string(&snapshot).unwrap());
}
