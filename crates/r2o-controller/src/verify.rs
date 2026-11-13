//! C `verify.c`: thread-local профиль проверки TCP timestamps.

use std::cell::{Cell, RefCell};

thread_local! {
    /// C `g_verify_tcp_timestamps`: -1 — не измерено, 0 — нет, 1 — есть.
    static VERIFY_TCP_TIMESTAMPS: Cell<i8> = const { Cell::new(-1) };
    /// C `d2k_quic_form`: поточная форма клиента для QUIC-зонда.
    static VERIFY_QUIC_FORM: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    /// C `g_verify_budget`: бюджет зондов текущего потока.
    static VERIFY_BUDGET: Cell<u32> = const { Cell::new(0) };
}

/// C `d2k_verify_tcp_timestamps_get`: текущее значение потока.
pub fn d2k_verify_tcp_timestamps_get() -> i8 {
    VERIFY_TCP_TIMESTAMPS.with(Cell::get)
}

/// C `d2k_verify_tcp_timestamps_set`: записать значение потока.
pub fn d2k_verify_tcp_timestamps_set(value: i8) {
    // C `enabled in -1..1 ? enabled : -1`.
    let value = if (-1..=1).contains(&value) { value } else { -1 };
    VERIFY_TCP_TIMESTAMPS.with(|cell| cell.set(value));
}

/// C `d2k_verify_quic_form_set`: n>0 — копия формы, иначе сброс.
pub fn d2k_verify_quic_form_set(form: &[u8]) {
    VERIFY_QUIC_FORM.with(|cell| {
        let mut stored = cell.borrow_mut();
        stored.clear();
        if !form.is_empty() {
            stored.extend_from_slice(form);
        }
    });
}

/// Прочитать поточную QUIC-форму (для проверки C-семантики set/reset).
pub fn d2k_verify_quic_form_get() -> Vec<u8> {
    VERIFY_QUIC_FORM.with(|cell| cell.borrow().clone())
}

/// C `d2k_verify_budget_set`: установить бюджет зондов потока.
pub fn d2k_verify_budget_set(budget_packets: u32) {
    VERIFY_BUDGET.with(|cell| cell.set(budget_packets));
}

/// C `d2k_verify_budget_get`: бюджет зондов текущего потока.
pub fn d2k_verify_budget_get() -> u32 {
    VERIFY_BUDGET.with(Cell::get)
}

#[cfg(test)]
mod tests {
    use super::{
        d2k_verify_budget_get, d2k_verify_budget_set, d2k_verify_quic_form_get,
        d2k_verify_quic_form_set, d2k_verify_tcp_timestamps_get, d2k_verify_tcp_timestamps_set,
    };

    #[test]
    fn verify_budget_setter_reflects_thread_local_value() {
        d2k_verify_budget_set(0);
        assert_eq!(d2k_verify_budget_get(), 0);
        d2k_verify_budget_set(1280);
        assert_eq!(d2k_verify_budget_get(), 1280);
        d2k_verify_budget_set(u32::MAX);
        assert_eq!(d2k_verify_budget_get(), u32::MAX);
    }

    #[test]
    fn quic_form_setter_copies_or_resets_like_c() {
        d2k_verify_quic_form_set(b"form-bytes");
        assert_eq!(d2k_verify_quic_form_get(), b"form-bytes");
        d2k_verify_quic_form_set(&[]);
        assert!(d2k_verify_quic_form_get().is_empty());
    }

    #[test]
    fn tcp_timestamps_getter_reflects_thread_local_setter() {
        d2k_verify_tcp_timestamps_set(1);
        assert_eq!(d2k_verify_tcp_timestamps_get(), 1);
        d2k_verify_tcp_timestamps_set(0);
        assert_eq!(d2k_verify_tcp_timestamps_get(), 0);
        d2k_verify_tcp_timestamps_set(-1);
        assert_eq!(d2k_verify_tcp_timestamps_get(), -1);
        for invalid in [2, -2, 127, -128] {
            d2k_verify_tcp_timestamps_set(invalid);
            assert_eq!(d2k_verify_tcp_timestamps_get(), -1, "value {invalid}");
        }
    }
}
