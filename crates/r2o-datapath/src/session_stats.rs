//! C `d2k_session.suspects`: общий счётчик подозрений.

use std::sync::atomic::{AtomicU64, Ordering};

static SESSION_SUSPECTS: AtomicU64 = AtomicU64::new(0);

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
    use super::{r2o_note_session_suspect, r2o_session_suspects};

    #[test]
    fn session_suspects_increment_by_one_per_note() {
        let before = r2o_session_suspects();
        r2o_note_session_suspect();
        r2o_note_session_suspect();
        assert_eq!(r2o_session_suspects(), before + 2);
    }
}
