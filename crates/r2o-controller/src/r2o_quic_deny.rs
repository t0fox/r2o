use std::net::SocketAddr;
use std::time::{Duration, Instant};

const R2O_QUIC_DENY_SLOTS: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oQuicDenyEntry {
    pub name: String,
    pub family: u8,
    pub server: SocketAddr,
    pub snapshot: Vec<u8>,
    pub streak: u8,
    pub until: Instant,
    pub active: bool,
    pub rechecking: bool,
    pub remove_pending: bool,
    remove_retry_at: Option<Instant>,
}

#[derive(Debug)]
pub struct R2oQuicDenyCache {
    entries: [Option<R2oQuicDenyEntry>; R2O_QUIC_DENY_SLOTS],
}

impl Default for R2oQuicDenyCache {
    fn default() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
        }
    }
}

impl R2oQuicDenyCache {
    pub fn r2o_next_delay(&self, name: &str, family: u8) -> Option<Duration> {
        let entry = self.r2o_find(name, family);
        if entry.is_none()
            && !self.entries.iter().any(Option::is_none)
            && !self.entries.iter().flatten().any(|entry| !entry.active)
        {
            return None;
        }
        Some(Self::r2o_delay(
            entry.map_or(1, |entry| entry.streak.saturating_add(1)),
        ))
    }

    pub fn r2o_record_cut(
        &mut self,
        name: &str,
        family: u8,
        server: SocketAddr,
        snapshot: &[u8],
        now: Instant,
    ) -> Option<Duration> {
        let slot = self.r2o_slot(name, family)?;
        let entry = self.entries[slot].get_or_insert_with(|| R2oQuicDenyEntry {
            name: name.into(),
            family,
            server,
            snapshot: Vec::new(),
            streak: 0,
            until: now,
            active: false,
            rechecking: false,
            remove_pending: false,
            remove_retry_at: None,
        });
        entry.server = server;
        entry.snapshot.clear();
        entry.snapshot.extend_from_slice(snapshot);
        entry.streak = entry.streak.saturating_add(1);
        let delay = Self::r2o_delay(entry.streak);
        entry.until = now + delay;
        entry.active = true;
        entry.rechecking = false;
        entry.remove_pending = false;
        entry.remove_retry_at = None;
        Some(delay)
    }

    pub fn r2o_due_rechecks(&self, now: Instant) -> Vec<R2oQuicDenyEntry> {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| {
                entry.active && !entry.rechecking && !entry.remove_pending && now >= entry.until
            })
            .cloned()
            .collect()
    }

    pub fn r2o_start_recheck(&mut self, name: &str, family: u8, now: Instant) -> bool {
        let Some(entry) = self.r2o_find_mut(name, family) else {
            return false;
        };
        if !entry.active || entry.rechecking || entry.remove_pending || now < entry.until {
            return false;
        }
        entry.rechecking = true;
        true
    }

    pub fn r2o_recheck_cut(&mut self, name: &str, family: u8, now: Instant) -> Option<Duration> {
        let entry = self.r2o_find_mut(name, family)?;
        if !entry.active || !entry.rechecking {
            return None;
        }
        entry.streak = entry.streak.saturating_add(1);
        let delay = Self::r2o_delay(entry.streak);
        entry.until = now + delay;
        entry.rechecking = false;
        Some(delay)
    }

    pub fn r2o_recheck_clear(&mut self, name: &str, family: u8) -> bool {
        let Some(entry) = self.r2o_find_mut(name, family) else {
            return false;
        };
        if !entry.active || !entry.rechecking {
            return false;
        }
        entry.rechecking = false;
        entry.remove_pending = true;
        entry.remove_retry_at = None;
        true
    }

    pub fn r2o_recheck_retry(&mut self, name: &str, family: u8) {
        if let Some(entry) = self.r2o_find_mut(name, family) {
            entry.rechecking = false;
        }
    }

    pub fn r2o_pending_removals(&self, now: Instant) -> Vec<(String, u8)> {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| {
                entry.active
                    && entry.remove_pending
                    && entry.remove_retry_at.is_none_or(|retry_at| now >= retry_at)
            })
            .map(|entry| (entry.name.clone(), entry.family))
            .collect()
    }

    pub fn r2o_finish_removal(&mut self, name: &str, family: u8, removed: bool, now: Instant) {
        let Some(entry) = self.r2o_find_mut(name, family) else {
            return;
        };
        if removed {
            entry.active = false;
            entry.remove_pending = false;
            entry.remove_retry_at = None;
        } else {
            entry.remove_retry_at = Some(now + Duration::from_secs(5));
        }
    }

    pub fn r2o_is_active(&self, name: &str, family: u8) -> bool {
        self.r2o_find(name, family)
            .is_some_and(|entry| entry.active)
    }

    fn r2o_find(&self, name: &str, family: u8) -> Option<&R2oQuicDenyEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.name == name && entry.family == family)
    }

    fn r2o_find_mut(&mut self, name: &str, family: u8) -> Option<&mut R2oQuicDenyEntry> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.name == name && entry.family == family)
    }

    fn r2o_slot(&mut self, name: &str, family: u8) -> Option<usize> {
        if let Some(index) = self.entries.iter().position(|entry| {
            entry
                .as_ref()
                .is_some_and(|entry| entry.name == name && entry.family == family)
        }) {
            return Some(index);
        }
        if let Some(index) = self.entries.iter().position(Option::is_none) {
            return Some(index);
        }
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                entry
                    .as_ref()
                    .filter(|entry| !entry.active)
                    .map(|entry| (index, entry.until))
            })
            .min_by_key(|(_, until)| *until)
            .map(|(index, _)| index)
    }

    fn r2o_delay(streak: u8) -> Duration {
        match streak {
            0 | 1 => Duration::from_secs(10 * 60),
            2 => Duration::from_secs(30 * 60),
            _ => Duration::from_secs(60 * 60),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::R2oQuicDenyCache;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    fn server(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), port)
    }

    #[test]
    fn задержка_запрета_растёт_по_ступеням_до_часа() {
        let now = Instant::now();
        let mut cache = R2oQuicDenyCache::default();
        assert_eq!(
            cache.r2o_next_delay("media.example", 4),
            Some(Duration::from_secs(600))
        );
        assert_eq!(
            cache.r2o_record_cut("media.example", 4, server(443), b"initial", now),
            Some(Duration::from_secs(600))
        );
        assert_eq!(
            cache.r2o_next_delay("media.example", 4),
            Some(Duration::from_secs(1800))
        );
        assert!(cache.r2o_start_recheck("media.example", 4, now + Duration::from_secs(600)));
        assert_eq!(
            cache.r2o_recheck_cut("media.example", 4, now + Duration::from_secs(600)),
            Some(Duration::from_secs(1800))
        );
        assert_eq!(
            cache.r2o_next_delay("media.example", 4),
            Some(Duration::from_secs(3600))
        );
    }

    #[test]
    fn чистая_перепроверка_снимает_запрет_только_после_подтверждения_удаления() {
        let now = Instant::now();
        let mut cache = R2oQuicDenyCache::default();
        cache.r2o_record_cut("media.example", 4, server(443), b"initial", now);
        assert!(cache.r2o_start_recheck("media.example", 4, now + Duration::from_secs(600)));
        assert!(cache.r2o_recheck_clear("media.example", 4));
        assert!(cache.r2o_is_active("media.example", 4));
        assert_eq!(
            cache.r2o_pending_removals(now),
            [("media.example".into(), 4)]
        );
        cache.r2o_finish_removal("media.example", 4, false, now);
        assert!(cache.r2o_is_active("media.example", 4));
        assert!(
            cache
                .r2o_pending_removals(now + Duration::from_secs(4))
                .is_empty()
        );
        cache.r2o_finish_removal("media.example", 4, true, now + Duration::from_secs(5));
        assert!(!cache.r2o_is_active("media.example", 4));
    }

    #[test]
    fn активная_перепроверка_не_ставится_в_очередь_повторно() {
        let now = Instant::now();
        let mut cache = R2oQuicDenyCache::default();
        cache.r2o_record_cut("media.example", 4, server(443), b"initial", now);
        let due = now + Duration::from_secs(600);
        assert_eq!(cache.r2o_due_rechecks(due).len(), 1);
        assert!(cache.r2o_start_recheck("media.example", 4, due));
        assert!(cache.r2o_due_rechecks(due).is_empty());
    }

    #[test]
    fn запрет_после_ошибки_отката_остаётся_на_перепроверку() {
        let now = Instant::now();
        let mut cache = R2oQuicDenyCache::default();
        assert_eq!(
            cache.r2o_record_cut("media.example", 4, server(443), b"initial", now),
            Some(Duration::from_secs(600))
        );
        assert_eq!(
            cache.r2o_due_rechecks(now + Duration::from_secs(600)).len(),
            1
        );
        assert!(cache.r2o_is_active("media.example", 4));
    }

    #[test]
    fn кольцо_не_вытесняет_действующие_запреты() {
        let now = Instant::now();
        let mut cache = R2oQuicDenyCache::default();
        for index in 0..16 {
            let name = format!("{index}.example");
            assert!(
                cache
                    .r2o_record_cut(&name, 4, server(443), b"initial", now)
                    .is_some()
            );
        }
        assert_eq!(cache.r2o_next_delay("overflow.example", 4), None);
        assert!(
            cache
                .r2o_record_cut("overflow.example", 4, server(443), b"initial", now)
                .is_none()
        );
    }
}
