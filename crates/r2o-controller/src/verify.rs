//! C `verify.c`: thread-local профиль проверки TCP timestamps.

use std::cell::Cell;

thread_local! {
    /// C `g_verify_tcp_timestamps`: -1 — не измерено, 0 — нет, 1 — есть.
    static VERIFY_TCP_TIMESTAMPS: Cell<i8> = const { Cell::new(-1) };
}

/// C `d2k_verify_tcp_timestamps_get`: текущее значение потока.
pub fn d2k_verify_tcp_timestamps_get() -> i8 {
    VERIFY_TCP_TIMESTAMPS.with(Cell::get)
}

/// C `d2k_verify_tcp_timestamps_set`: записать значение потока.
pub fn d2k_verify_tcp_timestamps_set(value: i8) {
    VERIFY_TCP_TIMESTAMPS.with(|cell| cell.set(value));
}

#[cfg(test)]
mod tests {
    use super::{d2k_verify_tcp_timestamps_get, d2k_verify_tcp_timestamps_set};

    #[test]
    fn tcp_timestamps_getter_reflects_thread_local_setter() {
        d2k_verify_tcp_timestamps_set(1);
        assert_eq!(d2k_verify_tcp_timestamps_get(), 1);
        d2k_verify_tcp_timestamps_set(0);
        assert_eq!(d2k_verify_tcp_timestamps_get(), 0);
        d2k_verify_tcp_timestamps_set(-1);
        assert_eq!(d2k_verify_tcp_timestamps_get(), -1);
    }
}
