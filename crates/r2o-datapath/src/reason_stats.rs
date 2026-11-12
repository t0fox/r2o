//! C `count_reason` (`datapath/d2kd.c:165-186`): гистограмма причин пропуска.
//!
//! C сравнивает строки сперва по указателю, затем по содержимому; в Rust
//! строки сравниваются по содержимому — наблюдаемый результат тот же. После
//! 32 разных причин новые не заводятся (как `n_reasons < MAX_REASONS`).

use std::sync::Mutex;

const MAX_REASONS: usize = 32;

static REASONS: Mutex<Vec<(&'static str, u64)>> = Mutex::new(Vec::new());

/// Учесть причину пропуска. `None`/пустая строка игнорируются, как C `!r`.
pub fn record_reason(reason: &'static str) {
    if reason.is_empty() {
        return;
    }
    let mut reasons = REASONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(entry) = reasons.iter_mut().find(|(text, _)| *text == reason) {
        entry.1 = entry.1.saturating_add(1);
        return;
    }
    if reasons.len() < MAX_REASONS {
        reasons.push((reason, 1));
    }
}

/// Снимок гистограммы для сводки.
pub fn reason_snapshot() -> Vec<(&'static str, u64)> {
    REASONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Число учтённых пропусков (сумма счётчиков).
pub fn reason_total() -> u64 {
    REASONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .fold(0_u64, |total, (_, count)| total.saturating_add(*count))
}

#[cfg(test)]
pub fn reset_reasons() {
    REASONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}

#[cfg(test)]
mod tests {
    use super::{MAX_REASONS, reason_snapshot, reason_total, record_reason, reset_reasons};

    #[test]
    fn count_reason_merges_equal_text_and_caps_at_32() {
        reset_reasons();
        record_reason("");
        record_reason("пакет обрезан copy_range");
        record_reason("пакет обрезан copy_range");
        let snapshot = reason_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].1, 2);
        assert_eq!(reason_total(), 2);

        // 31 разная причина доводит гистограмму до предела 32.
        const EXTRA: [&str; 31] = [
            "r00", "r01", "r02", "r03", "r04", "r05", "r06", "r07", "r08", "r09", "r10", "r11",
            "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
            "r24", "r25", "r26", "r27", "r28", "r29", "r30",
        ];
        for reason in EXTRA {
            record_reason(reason);
        }
        assert_eq!(reason_snapshot().len(), MAX_REASONS);

        // Новая причина сверх предела не заводится и не считается.
        let before = reason_total();
        record_reason("overflow");
        assert_eq!(reason_snapshot().len(), MAX_REASONS);
        assert_eq!(reason_total(), before);

        // Существующая причина по-прежнему увеличивает счётчик.
        record_reason("r00");
        assert_eq!(reason_total(), before + 1);
        reset_reasons();
    }
}
