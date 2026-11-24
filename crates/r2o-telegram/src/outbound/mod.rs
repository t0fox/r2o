//! Прямой исходящий TCP connector с поддержкой SO_MARK на Linux.

mod connector;

pub use connector::{OutboundConnector, OutboundError};

#[cfg(target_os = "linux")]
pub(crate) use connector::set_socket_mark;
