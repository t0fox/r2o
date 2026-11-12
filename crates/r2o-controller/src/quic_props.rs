//! C `quicarms.c`/`quicprobe.c`: текстовый контракт QUIC-свойств.

pub const R2O_PROP_UNKNOWN: i8 = 0;
pub const R2O_PROP_NO: i8 = 1;
pub const R2O_PROP_YES: i8 = 2;

/// C `prop_word`: tri-state → слово для лога.
pub fn prop_word(value: i8) -> &'static str {
    match value {
        R2O_PROP_YES => "прошло",
        R2O_PROP_NO => "не прошло",
        _ => "ответа нет",
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct R2oQuicProps {
    pub residual_blocking: i8,
    pub residual_ignores_src_port: i8,
    pub junk_ahead: i8,
    pub fake_ahead: i8,
    pub split_crypto: i8,
    pub split_datagrams: i8,
    pub version2: i8,
    pub clear_fixed_bit: i8,
    pub low_source_port: i8,
}

impl R2oQuicProps {
    /// C `d2k_quic_props_findings`: донорские тексты только для YES-свойств.
    /// Возвращает число находок и строку, обрезанную до `cap - 1` байт.
    pub fn findings(&self, cap: usize) -> (usize, String) {
        if cap == 0 {
            return (0, String::new());
        }
        let texts: [(i8, &str); 6] = [
            (
                self.split_crypto,
                "приветствие, разложенное на два кадра CRYPTO, проходит — коробка их не пересобирает. Исполнимо (задача 40): план quicsplit — датапат перекладывает кадры CRYPTO в Initial клиента; ставится ответом вопроса стратегии с этапом данных.",
            ),
            (
                self.split_datagrams,
                "приветствие, разложенное на две датаграммы, проходит — коробка их не собирает. Движок так не умеет: второму пакету нужен свой номер, а следующий номер принадлежит клиенту — сервер отбросил бы его настоящий пакет как повтор.",
            ),
            (
                self.version2,
                "Initial второй версии проходит — коробка знает только первую. На живом пакете версию не переписать: она входит в связанные данные AEAD, и правка ломает рукопожатие самого пользователя. Движок так не умеет; это довод для клиента, не для движка.",
            ),
            (
                self.clear_fixed_bit,
                "с погашенным фиксированным битом Initial проходит. Сервер обязан такой пакет принять только если сам объявил grease_quic_bit, поэтому приём ненадёжен, а движок его не умеет.",
            ),
            (
                self.low_source_port,
                "с исходным портом ниже порта назначения Initial проходит — коробка так экономит на разборе. Десинком это не выражается и движок так не умеет: нужен SNAT исходного порта, отдельное правило фаервола.",
            ),
            (
                self.fake_ahead,
                "фальшивый Initial с разрешённым именем перед своим проходит — коробка считает поток разрешённым. Это исполнимо: ровно то же делает приманка движка.",
            ),
        ];
        let mut found = 0;
        let mut out = String::new();
        for (value, text) in texts {
            if value != R2O_PROP_YES {
                continue;
            }
            found += 1;
            if out.len() < cap - 1 {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(text);
            }
        }
        if out.len() >= cap {
            let mut end = cap - 1;
            while end > 0 && !out.is_char_boundary(end) {
                end -= 1;
            }
            out.truncate(end);
        }
        (found, out)
    }
}

#[cfg(test)]
mod tests {
    use super::{R2O_PROP_NO, R2O_PROP_YES, R2oQuicProps, prop_word};

    #[test]
    fn prop_word_matches_donor_tri_state() {
        assert_eq!(prop_word(2), "прошло");
        assert_eq!(prop_word(1), "не прошло");
        assert_eq!(prop_word(0), "ответа нет");
        assert_eq!(prop_word(-1), "ответа нет");
    }

    #[test]
    fn findings_include_only_yes_properties_and_truncate_to_cap() {
        let props = R2oQuicProps {
            split_crypto: R2O_PROP_YES,
            version2: R2O_PROP_NO,
            fake_ahead: R2O_PROP_YES,
            ..R2oQuicProps::default()
        };
        let (found, text) = props.findings(4096);
        assert_eq!(found, 2);
        assert!(text.contains("два кадра CRYPTO"));
        assert!(text.contains("фальшивый Initial"));
        assert!(!text.contains("второй версии"));

        let (found, text) = props.findings(32);
        assert_eq!(found, 2);
        assert!(text.len() < 32);
        assert!(std::str::from_utf8(text.as_bytes()).is_ok());
    }
}
