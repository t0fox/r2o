//! C `d2k_session.suspects`: общий счётчик подозрений.

use std::sync::atomic::Ordering;

/// 64-битный счётчик, доступный и на 32-bit целях без `target_has_atomic="64"`
/// (armv5te/mipsel OpenWrt): на 64-bit — `AtomicU64`, иначе `Mutex<u64>`.
#[cfg(target_has_atomic = "64")]
pub type R2oAtomicU64 = std::sync::atomic::AtomicU64;

#[cfg(not(target_has_atomic = "64"))]
#[derive(Debug)]
pub struct R2oAtomicU64(std::sync::Mutex<u64>);

#[cfg(not(target_has_atomic = "64"))]
impl R2oAtomicU64 {
    pub const fn new(value: u64) -> Self {
        Self(std::sync::Mutex::new(value))
    }

    pub fn load(&self, _order: Ordering) -> u64 {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn store(&self, value: u64, _order: Ordering) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub fn fetch_add(&self, value: u64, _order: Ordering) -> u64 {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = *guard;
        *guard = previous.wrapping_add(value);
        previous
    }

    pub fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        _success: Ordering,
        _failure: Ordering,
    ) -> Result<u64, u64> {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *guard == current {
            *guard = new;
            Ok(current)
        } else {
            Err(*guard)
        }
    }
}

static SESSION_SUSPECTS: R2oAtomicU64 = R2oAtomicU64::new(0);

/// C `d2k_session_suspects`: число потоков, по которым впервые возникло
/// подозрение.
pub fn r2o_session_suspects() -> u64 {
    SESSION_SUSPECTS.load(Ordering::Relaxed)
}

/// Учесть первое подозрение потока (C `suspect_num`).
pub fn r2o_note_session_suspect() {
    SESSION_SUSPECTS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::{R2oAtomicU64, r2o_note_session_suspect, r2o_session_suspects};
    use std::sync::atomic::Ordering;

    #[test]
    fn portable_atomic_u64_preserves_load_store_add_cas() {
        let counter = R2oAtomicU64::new(0);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert_eq!(counter.fetch_add(5, Ordering::Relaxed), 0);
        assert_eq!(counter.load(Ordering::Relaxed), 5);
        counter.store(9, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), 9);
        assert_eq!(
            counter.compare_exchange(9, 11, Ordering::Relaxed, Ordering::Relaxed),
            Ok(9)
        );
        assert_eq!(
            counter.compare_exchange(9, 12, Ordering::Relaxed, Ordering::Relaxed),
            Err(11)
        );
        assert_eq!(counter.load(Ordering::Relaxed), 11);
        assert_eq!(counter.fetch_add(u64::MAX, Ordering::Relaxed), 11);
        assert_eq!(counter.load(Ordering::Relaxed), 10, "wrapping add");
    }

    #[test]
    fn session_suspects_increment_by_one_per_note() {
        let before = r2o_session_suspects();
        r2o_note_session_suspect();
        r2o_note_session_suspect();
        assert_eq!(r2o_session_suspects(), before + 2);
    }
}
