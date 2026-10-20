/// Число записей, которое разрешено запросить для таблиц потоков r2o.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oFlowCapacity {
    slots: usize,
    limit: usize,
}

impl R2oFlowCapacity {
    pub const DEFAULT_REQUESTED: usize = 2048;

    /// Округлить запрошенную ёмкость до степени двойки, как в таблицах донора.
    pub fn from_requested(requested: usize) -> Option<Self> {
        if requested == 0 {
            return None;
        }
        let slots = requested.max(16).checked_next_power_of_two()?;
        Some(Self {
            slots,
            limit: slots - slots / 4,
        })
    }

    /// Число физических слотов после округления.
    pub const fn slots(self) -> usize {
        self.slots
    }

    /// Порог новых записей при заполнении таблицы на три четверти.
    pub const fn limit(self) -> usize {
        self.limit
    }
}

impl Default for R2oFlowCapacity {
    fn default() -> Self {
        Self::from_requested(Self::DEFAULT_REQUESTED).expect("ёмкость по умолчанию допустима")
    }
}

#[cfg(test)]
mod tests {
    use super::R2oFlowCapacity;

    #[test]
    fn r2o_ёмкость_повторяет_округление_таблицы_донора() {
        let cases = [(1, 16, 12), (16, 16, 12), (64, 64, 48), (65, 128, 96)];
        for (requested, slots, limit) in cases {
            let capacity = R2oFlowCapacity::from_requested(requested).unwrap();
            assert_eq!(capacity.slots(), slots);
            assert_eq!(capacity.limit(), limit);
        }
        assert!(R2oFlowCapacity::from_requested(0).is_none());
        assert!(R2oFlowCapacity::from_requested(usize::MAX).is_none());
    }
}
