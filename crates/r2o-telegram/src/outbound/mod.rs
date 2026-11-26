//! Прямой исходящий TCP connector с поддержкой SO_MARK на Linux.

mod connector;
mod network;

#[cfg(target_os = "linux")]
pub(crate) use network::NetworkEvents;

pub use connector::{OutboundConnector, OutboundError};

#[cfg(target_os = "linux")]
pub(crate) use connector::set_socket_mark;
