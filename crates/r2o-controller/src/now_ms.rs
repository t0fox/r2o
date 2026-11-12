//! C `detect/classify.c:84-94`: монотонные миллисекунды и сдвиг часов.
//!
//! Ширина закреплена как 64 бита: на mipsel `long` 32-битный, поэтому
//! используется `i64`, как в C-typedef-проверке.

use std::sync::atomic::{AtomicI64, Ordering};

/// C `d2k_clock_offset_ms`: глобальный сдвиг для тестов и стенда.
static CLOCK_OFFSET_MS: AtomicI64 = AtomicI64::new(0);

/// Задать сдвиг монотонных часов (C-переменная `d2k_clock_offset_ms`).
pub fn set_clock_offset_ms(offset_ms: i64) {
    CLOCK_OFFSET_MS.store(offset_ms, Ordering::Relaxed);
}

/// Текущий сдвиг монотонных часов.
pub fn clock_offset_ms() -> i64 {
    CLOCK_OFFSET_MS.load(Ordering::Relaxed)
}

/// C `d2k_now_ms`: CLOCK_MONOTONIC в миллисекундах плюс сдвиг.
pub fn d2k_now_ms() -> i64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    let millis = if result == 0 {
        (ts.tv_sec as i64)
            .saturating_mul(1000)
            .saturating_add((ts.tv_nsec / 1_000_000) as i64)
    } else {
        0
    };
    millis.saturating_add(clock_offset_ms())
}

#[cfg(test)]
mod tests {
    use super::{clock_offset_ms, d2k_now_ms, set_clock_offset_ms};

    #[test]
    fn now_ms_survives_64bit_offset_like_c() {
        let saved = clock_offset_ms();
        set_clock_offset_ms(0);
        let base = d2k_now_ms();
        assert!(base > 0);

        // C-тест raw.c: сдвиг 50 суток — за пределом 32 бит.
        let offset = 50_i64 * 24 * 3600 * 1000;
        assert!(offset > u32::MAX as i64);
        set_clock_offset_ms(offset);
        assert!(d2k_now_ms() >= base.saturating_add(offset));

        // Граница знакового 32-битного long.
        set_clock_offset_ms(i64::from(i32::MAX) - 50);
        assert!(d2k_now_ms() > i64::from(i32::MAX));
        set_clock_offset_ms(saved);
    }
}
