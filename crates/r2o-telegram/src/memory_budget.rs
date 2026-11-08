//! Динамический бюджет памяти Telegram-прокси (контракт D2O `memory_budget.c`).
//!
//! C ведёт `used`/`peak` и отказывает в резервировании, если рост превысил
//! остаток. R2O использует тот же жёсткий предел для буферов соединений:
//! отказ означает закрытие соединения, а не неограниченный рост.

use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct MemoryBudget {
    limit: usize,
    used: AtomicUsize,
    peak: AtomicUsize,
}

impl MemoryBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Acquire)
    }

    /// Зарезервировать `bytes`. Возвращает false, если бюджет исчерпан.
    pub fn reserve(&self, bytes: usize) -> bool {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            if used > self.limit || bytes > self.limit - used {
                return false;
            }
            match self.used.compare_exchange_weak(
                used,
                used + bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let mut peak = self.peak.load(Ordering::Acquire);
                    while used + bytes > peak {
                        match self.peak.compare_exchange_weak(
                            peak,
                            used + bytes,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => break,
                            Err(seen) => peak = seen,
                        }
                    }
                    return true;
                }
                Err(seen) => used = seen,
            }
        }
    }

    /// Освободить `bytes`; при перерасходе used насыщается нулём, как в C.
    pub fn release(&self, bytes: usize) {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used.saturating_sub(bytes);
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(seen) => used = seen,
            }
        }
    }
}

/// RAII-резервирование: освобождает бюджет при выходе из области видимости.
pub struct BudgetReservation {
    budget: std::sync::Arc<MemoryBudget>,
    bytes: usize,
}

impl BudgetReservation {
    pub fn acquire(budget: &std::sync::Arc<MemoryBudget>, bytes: usize) -> Option<Self> {
        budget.reserve(bytes).then(|| Self {
            budget: std::sync::Arc::clone(budget),
            bytes,
        })
    }
}

impl Drop for BudgetReservation {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryBudget;
    use std::sync::Arc;

    /// Векторы D2O `test_memory_budget.c`.
    #[test]
    fn reserve_release_and_peak_match_d2o() {
        let budget = MemoryBudget::new(64 * 1024);
        assert!(budget.reserve(48 * 1024));
        assert_eq!(budget.used(), 48 * 1024);
        assert_eq!(budget.peak(), budget.used());
        assert!(!budget.reserve(16 * 1024 + 1));
        assert_eq!(budget.used(), 48 * 1024);
        assert!(budget.reserve(16 * 1024));
        assert_eq!(budget.used(), budget.limit());
        assert_eq!(budget.peak(), budget.limit());

        budget.release(32 * 1024);
        assert_eq!(budget.used(), 32 * 1024);
        assert!(budget.reserve(32 * 1024));
        assert_eq!(budget.used(), budget.limit());
        budget.release(budget.limit());
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.peak(), budget.limit());
    }

    #[test]
    fn reservation_releases_on_drop() {
        let budget = Arc::new(MemoryBudget::new(1024));
        {
            let _guard = super::BudgetReservation::acquire(&budget, 512).unwrap();
            assert_eq!(budget.used(), 512);
        }
        assert_eq!(budget.used(), 0);
        assert!(super::BudgetReservation::acquire(&budget, 2048).is_none());
    }
}
