// Расширенный диагностический JSON в стиле D2O требует большего лимита макроса.
#![recursion_limit = "256"]

pub mod ask;
pub mod catalog;
pub mod classify;
pub mod classify_json;
mod classify_measured;
pub mod compose_d2o;
pub mod diagnostics;
pub mod discovery;
pub mod domain;
pub mod ech;
pub mod fetch;
mod groups;
pub mod hello;
pub mod http_search;
pub mod https_probe;
pub mod live;
pub mod plan_text;
pub mod quic_replay;
pub mod r2o_fallback;
pub mod r2o_late_rx;
pub mod r2o_quic_deny;
pub mod r2o_quic_http3;
pub mod r2o_resource;
pub mod r2o_resource_limit;
pub mod r2o_rx_volume;
pub mod r2o_tls;
pub mod r2o_volume;
#[cfg(target_os = "linux")]
mod raw_probe;

/// C не-Linux `d2k_raw_pending_count` (`detect/raw.c:1333`): очередь
/// отложенных снятий RST на этой платформе не ведётся.
#[cfg(not(target_os = "linux"))]
pub(crate) fn rst_pending_count() -> usize {
    0
}
pub mod response;
pub mod trigger;
pub mod voice_discovery;
pub mod voice_measure;
pub mod voice_targets;
