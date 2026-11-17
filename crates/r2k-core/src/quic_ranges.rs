//! Принятые байты одного QUIC-потока: непересекающиеся слитые отрезки.
//!
//! Точный перенос `d2k_qw_ranges_*` (`core/quicwire.c`): ответ считается
//! целым только при FIN и непрерывном покрытии `[0, fin_off)`, а не по
//! наибольшему смещению.

/// C `D2K_QW_RANGES_MAX`: больше 64 отрезков не храним.
pub const R2K_QUIC_RANGES_MAX: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oQuicRanges {
    start: [u64; R2K_QUIC_RANGES_MAX],
    end: [u64; R2K_QUIC_RANGES_MAX],
    n: usize,
    fin: bool,
    fin_off: u64,
}

impl Default for R2oQuicRanges {
    fn default() -> Self {
        Self {
            start: [0; R2K_QUIC_RANGES_MAX],
            end: [0; R2K_QUIC_RANGES_MAX],
            n: 0,
            fin: false,
            fin_off: 0,
        }
    }
}

impl R2oQuicRanges {
    pub fn new() -> Self {
        Self::default()
    }

    /// C `d2k_qw_ranges_reset`.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// C `d2k_qw_ranges_add`: вставка со слиянием пересекающихся и касающихся
    /// отрезков; `fin` запоминается один раз; переполнение offset+len — отказ.
    pub fn add(&mut self, offset: u64, length: u64, fin: bool) {
        let Some(end) = offset.checked_add(length) else {
            return;
        };
        if fin && !self.fin {
            self.fin = true;
            self.fin_off = end;
        }
        if length == 0 {
            return;
        }
        let mut i = 0;
        while i < self.n && self.end[i] < offset {
            i += 1;
        }
        let mut j = i;
        let mut start = offset;
        let mut merged_end = end;
        while j < self.n && self.start[j] <= end {
            if self.start[j] < start {
                start = self.start[j];
            }
            if self.end[j] > merged_end {
                merged_end = self.end[j];
            }
            j += 1;
        }
        if j == i {
            if self.n == R2K_QUIC_RANGES_MAX {
                return;
            }
            self.start.copy_within(i..self.n, i + 1);
            self.end.copy_within(i..self.n, i + 1);
            self.n += 1;
        } else if j > i + 1 {
            let drop = j - i - 1;
            self.start.copy_within(j..self.n, i + 1);
            self.end.copy_within(j..self.n, i + 1);
            self.n -= drop;
        }
        self.start[i] = start;
        self.end[i] = merged_end;
    }

    /// C `d2k_qw_ranges_bytes`: сумма покрытых байт.
    pub fn bytes(&self) -> u64 {
        (0..self.n)
            .map(|index| self.end[index].saturating_sub(self.start[index]))
            .fold(0, u64::saturating_add)
    }

    /// C `d2k_qw_ranges_complete`: FIN, непустой `fin_off` и покрытие от нуля.
    pub fn complete(&self) -> bool {
        self.fin
            && self.fin_off != 0
            && self.n >= 1
            && self.start[0] == 0
            && self.end[0] >= self.fin_off
    }

    pub fn fin_seen(&self) -> bool {
        self.fin
    }

    pub fn fin_offset(&self) -> u64 {
        self.fin_off
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn range(&self, index: usize) -> Option<(u64, u64)> {
        (index < self.n).then(|| (self.start[index], self.end[index]))
    }
}
