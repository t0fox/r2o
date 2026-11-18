//! Общий источник случайности: C `d2k_t13_random` (`core/tls13core.c:21-27`)
//! и все места, которым нужны ровно `n` случайных байт.
//!
//! C открывает `/dev/urandom`, делает `fread(b, 1, n)` и требует `got == n`,
//! иначе возвращает -1. Здесь тот же контракт поверх `getrandom` — того же
//! OS-источника энтропии, что уже используется для DCID QUIC и id планов.

/// C `d2k_t13_random`: заполнить весь буфер или отказать. `n == 0` — успех
/// (C `fread(..., 0) == 0`).
pub fn fill_exact(bytes: &mut [u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    getrandom::getrandom(bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::fill_exact;

    #[test]
    fn fill_exact_matches_c_random_contract() {
        assert!(fill_exact(&mut []));

        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        assert!(fill_exact(&mut first));
        assert!(fill_exact(&mut second));
        assert_ne!(first, second, "два вызова дали одинаковые 256 бит");
        assert!(first.iter().any(|byte| *byte != 0));
    }
}
