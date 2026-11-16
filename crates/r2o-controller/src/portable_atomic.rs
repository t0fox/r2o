//! 64-битные счётчики, переносимые на 32-bit musl targets.
//!
//! На целях с `target_has_atomic="64"` это обычные `AtomicU64`/`AtomicI64`.
//! На mipsel/armv5te (OpenWrt) 64-битных атомиков в std нет, поэтому
//! используется `Mutex` с теми же load/store/fetch/swap/CAS и wrapping-
//! семантикой. Ordering на Mutex-ветке не имеет аппаратного смысла, но
//! принимается и игнорируется, чтобы call-site не менялись.

#[cfg(not(target_has_atomic = "64"))]
use std::sync::atomic::Ordering;

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

    pub fn fetch_sub(&self, value: u64, _order: Ordering) -> u64 {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = *guard;
        *guard = previous.wrapping_sub(value);
        previous
    }

    pub fn swap(&self, value: u64, _order: Ordering) -> u64 {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::replace(&mut *guard, value)
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

    pub fn compare_exchange_weak(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.compare_exchange(current, new, success, failure)
    }
}

#[cfg(target_has_atomic = "64")]
pub type R2oAtomicI64 = std::sync::atomic::AtomicI64;

#[cfg(not(target_has_atomic = "64"))]
#[derive(Debug)]
pub struct R2oAtomicI64(std::sync::Mutex<i64>);

#[cfg(not(target_has_atomic = "64"))]
impl R2oAtomicI64 {
    pub const fn new(value: i64) -> Self {
        Self(std::sync::Mutex::new(value))
    }

    pub fn load(&self, _order: Ordering) -> i64 {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn store(&self, value: i64, _order: Ordering) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub fn fetch_add(&self, value: i64, _order: Ordering) -> i64 {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = *guard;
        *guard = previous.wrapping_add(value);
        previous
    }

    pub fn fetch_sub(&self, value: i64, _order: Ordering) -> i64 {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = *guard;
        *guard = previous.wrapping_sub(value);
        previous
    }

    pub fn swap(&self, value: i64, _order: Ordering) -> i64 {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::replace(&mut *guard, value)
    }

    pub fn compare_exchange(
        &self,
        current: i64,
        new: i64,
        _success: Ordering,
        _failure: Ordering,
    ) -> Result<i64, i64> {
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

    pub fn compare_exchange_weak(
        &self,
        current: i64,
        new: i64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<i64, i64> {
        self.compare_exchange(current, new, success, failure)
    }
}

#[cfg(test)]
mod tests {
    use super::{R2oAtomicI64, R2oAtomicU64};
    use std::sync::atomic::Ordering;

    #[test]
    fn portable_atomic_u64_preserves_load_store_add_sub_swap_cas_and_wrap() {
        let counter = R2oAtomicU64::new(0);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert_eq!(counter.fetch_add(5, Ordering::Relaxed), 0);
        assert_eq!(counter.load(Ordering::Relaxed), 5);
        assert_eq!(counter.fetch_sub(2, Ordering::Relaxed), 5);
        assert_eq!(counter.load(Ordering::Relaxed), 3);
        counter.store(9, Ordering::Relaxed);
        assert_eq!(counter.swap(10, Ordering::Relaxed), 9);
        assert_eq!(
            counter.compare_exchange(10, 11, Ordering::Relaxed, Ordering::Relaxed),
            Ok(10)
        );
        assert_eq!(
            counter.compare_exchange_weak(10, 12, Ordering::Relaxed, Ordering::Relaxed),
            Err(11)
        );
        assert_eq!(counter.load(Ordering::Relaxed), 11);
        assert_eq!(counter.fetch_add(u64::MAX, Ordering::Relaxed), 11);
        assert_eq!(counter.load(Ordering::Relaxed), 10, "wrapping add");
        assert_eq!(counter.fetch_sub(11, Ordering::Relaxed), 10);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX, "wrapping sub");
    }

    #[test]
    fn portable_atomic_i64_preserves_load_store_add_sub_swap_cas_and_wrap() {
        let counter = R2oAtomicI64::new(i64::MAX);
        assert_eq!(counter.fetch_add(1, Ordering::Relaxed), i64::MAX);
        assert_eq!(counter.load(Ordering::Relaxed), i64::MIN, "wrapping add");
        assert_eq!(counter.fetch_sub(1, Ordering::Relaxed), i64::MIN);
        assert_eq!(counter.load(Ordering::Relaxed), i64::MAX, "wrapping sub");
        counter.store(-7, Ordering::Relaxed);
        assert_eq!(counter.swap(3, Ordering::Relaxed), -7);
        assert_eq!(
            counter.compare_exchange(3, 4, Ordering::Relaxed, Ordering::Relaxed),
            Ok(3)
        );
        assert_eq!(
            counter.compare_exchange_weak(3, 5, Ordering::Relaxed, Ordering::Relaxed),
            Err(4)
        );
        assert_eq!(counter.load(Ordering::Relaxed), 4);
    }
}
