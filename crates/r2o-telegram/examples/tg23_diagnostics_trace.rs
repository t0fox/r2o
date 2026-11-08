//! TG23: печатает schema/состояния diagnostics отчёта в стабильном виде.
//!
//! Используется differential-скриптом против z2kOW; live-сеть не требуется.

use std::net::IpAddr;

use r2o_telegram::diagnostics::{DcDiagnostic, DiagnosticReport, RouteDiagnostic};

fn route(
    transport: &'static str,
    domain: Option<&str>,
    ip: Option<&str>,
    state: &'static str,
    failed_stage: Option<&'static str>,
    http_status: Option<u16>,
) -> RouteDiagnostic {
    RouteDiagnostic {
        transport,
        domain: domain.map(str::to_string),
        selected_ip: ip.map(|text| text.parse::<IpAddr>().unwrap()),
        state,
        failed_stage,
        http_status,
        reason: (state != "healthy").then(|| format!("{state}: synthetic")),
        dns_ms: Some(1),
        tcp_ms: Some(2),
        tls_ms: Some(3),
        websocket_ms: Some(4),
        mtproto_ms: (state == "healthy").then_some(5),
    }
}

fn dc(dc: u32, state: &'static str, routes: Vec<RouteDiagnostic>) -> DcDiagnostic {
    DcDiagnostic { dc, state, routes }
}

fn print_report(name: &str, state: &'static str, data_centers: Vec<DcDiagnostic>) {
    let report = DiagnosticReport {
        checked_at: 1_800_000_000,
        state,
        data_centers,
    };
    println!(
        "report {name} healthy={} json={}",
        u8::from(report.has_healthy_route()),
        serde_json::to_string(&report).unwrap()
    );
}

fn main() {
    let healthy = (1..=5)
        .map(|dc_id| {
            dc(
                dc_id,
                "healthy",
                vec![route(
                    "direct-wss",
                    Some("kws1.web.telegram.org"),
                    Some("149.154.175.50"),
                    "healthy",
                    None,
                    None,
                )],
            )
        })
        .collect();
    print_report("healthy", "healthy", healthy);

    print_report(
        "partial",
        "partial",
        vec![
            dc(
                1,
                "healthy",
                vec![route(
                    "direct-wss",
                    Some("kws1.web.telegram.org"),
                    Some("149.154.175.50"),
                    "healthy",
                    None,
                    None,
                )],
            ),
            dc(
                2,
                "unavailable",
                vec![route(
                    "direct-wss",
                    Some("kws2.web.telegram.org"),
                    Some("149.154.167.51"),
                    "unavailable",
                    Some("dns"),
                    None,
                )],
            ),
        ],
    );

    print_report(
        "unverified",
        "unverified",
        vec![dc(
            1,
            "unverified",
            vec![route("cf-worker", None, None, "unverified", None, None)],
        )],
    );

    print_report(
        "blocked",
        "unavailable",
        vec![dc(
            4,
            "blocked",
            vec![
                route(
                    "cf-worker",
                    Some("worker.example"),
                    Some("149.154.167.91"),
                    "blocked",
                    Some("websocket"),
                    Some(403),
                ),
                route(
                    "cf-proxy",
                    Some("kws4.example.co.uk"),
                    None,
                    "unavailable",
                    Some("tcp"),
                    Some(503),
                ),
            ],
        )],
    );

    print_report("empty", "unavailable", Vec::new());
}
