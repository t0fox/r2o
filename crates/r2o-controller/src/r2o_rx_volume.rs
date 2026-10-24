const R2O_RX_VOLUME_NAMES: &str = include_str!("../data/r2o_tcp1620_whitelist.txt");
const R2O_RX_VOLUME_SPLITS: [usize; 5] = [2, 1, 3, 4, 5];
const R2O_RX_VOLUME_SEGMENT: usize = 1400;

/// Число имён для проверки белого SNI.
pub fn r2o_rx_volume_name_count() -> usize {
    R2O_RX_VOLUME_NAMES.lines().count()
}

/// Имя сети в той же последовательности, которую использует C-планировщик.
pub fn r2o_rx_volume_name(index: usize) -> Option<&'static str> {
    R2O_RX_VOLUME_NAMES.lines().nth(index)
}

/// Число вариантов разреза для уже известного белого имени.
pub fn r2o_rx_volume_plan_count() -> usize {
    R2O_RX_VOLUME_SPLITS.len()
}

/// Построить один TCP-template план для приёма на объёмном RX-обрыве.
pub fn r2o_rx_volume_plan(variant: usize, name: &str, send_cap: usize) -> Result<String, String> {
    r2o_rx_volume_plan_for_client(variant, name, send_cap, true)
}

/// Построить RX-план с учётом timestamp option на захваченном клиентском потоке.
pub fn r2o_rx_volume_plan_for_client(
    variant: usize,
    name: &str,
    send_cap: usize,
    client_has_tcp_timestamps: bool,
) -> Result<String, String> {
    let split = *R2O_RX_VOLUME_SPLITS
        .get(variant)
        .ok_or_else(|| "вариант RX-плана вне диапазона".to_owned())?;
    let normalized = crate::domain::normalize(name)
        .map_err(|error| format!("имя приманки недопустимо: {error}"))?;
    if normalized != name {
        return Err("имя приманки должно быть в нормализованной форме".into());
    }
    let hello = crate::hello::r2o_rx_fake_client_hello(name)
        .map_err(|error| format!("не удалось собрать ClientHello приманки: {error}"))?;
    if send_cap != 0 && (hello.len() > send_cap || send_cap - hello.len() < 132) {
        return Err("ClientHello приманки не помещается в предел отправки".into());
    }

    let mut payload = String::with_capacity(hello.len() * 2);
    for byte in hello {
        use std::fmt::Write as _;
        write!(payload, "{byte:02x}").expect("запись в строку не завершается ошибкой");
    }
    let (minexec, poison) = if client_has_tcp_timestamps {
        (8, "tcpts")
    } else {
        (13, "autottl=1,2-12")
    };
    Ok(format!(
        "r2o-plan 1 {minexec}\nid 00000000000000000000000000000000\nproto tcp tls\nwire tcp-template-v1\ninput tls-sni\nsegment {R2O_RX_VOLUME_SEGMENT}\npayload 1 {payload}\npoison 1 {poison}\nfake payload=1 poison=1 repeats=8 gap_us=0 place=before tlsmod=rnd,dupsid\nsplit payload_start +{split}\norder forward\n"
    ))
}

/// Получить очередной план белого имени, затем варианты с запасным именем.
pub fn r2o_rx_volume_candidate(index: usize, send_cap: usize) -> Result<Option<String>, String> {
    let name_count = r2o_rx_volume_name_count();
    if let Some(name) = R2O_RX_VOLUME_NAMES.lines().nth(index) {
        return r2o_rx_volume_plan(0, name, send_cap).map(Some);
    }
    let variant = index.saturating_sub(name_count);
    if variant < R2O_RX_VOLUME_SPLITS.len() {
        return r2o_rx_volume_plan(variant, "hcaptcha.com", send_cap).map(Some);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use r2k_core::plan::{Plan, WIRE_TCP_TEMPLATE};

    use super::{
        R2O_RX_VOLUME_NAMES, r2o_rx_volume_candidate, r2o_rx_volume_name, r2o_rx_volume_name_count,
        r2o_rx_volume_plan, r2o_rx_volume_plan_for_client,
    };

    #[test]
    fn список_белых_имён_содержит_весь_донорский_набор() {
        assert_eq!(r2o_rx_volume_name_count(), 266);
        assert_eq!(R2O_RX_VOLUME_NAMES.lines().next(), Some("9gag.com"));
        assert_eq!(R2O_RX_VOLUME_NAMES.lines().last(), Some("zoho.com"));
        assert_eq!(r2o_rx_volume_name(0), Some("9gag.com"));
        assert_eq!(r2o_rx_volume_name(265), Some("zoho.com"));
        assert_eq!(r2o_rx_volume_name(266), None);
    }

    #[test]
    fn планы_собирают_все_пять_вариантов_и_проходят_проверку_исполнителя() {
        for (variant, split) in [2, 1, 3, 4, 5].into_iter().enumerate() {
            let text = r2o_rx_volume_plan(variant, "hcaptcha.com", 1492).unwrap();
            let bytes = crate::plan_text::compile_text(&text).unwrap();
            let plan = Plan::parse(&bytes).unwrap();
            assert_eq!(plan.wire_profile, WIRE_TCP_TEMPLATE);
            assert!(plan.input_tls);
            assert_eq!(plan.segment_size, 1400);
            assert_eq!(plan.payloads.len(), 1);
            assert_eq!(plan.poisons.len(), 1);
            assert_eq!(plan.fakes[0].repeats, 8);
            assert_eq!(plan.fakes[0].tls_mod, 3);
            assert_eq!(plan.splits[0].offset, i16::try_from(split).unwrap());
            r2o_datapath::engine::validate_runtime_plan(&plan).unwrap();
        }
    }

    #[test]
    fn клиенты_без_timestamp_получают_путь_autottl_со_всеми_пятью_разрезами() {
        for (variant, split) in [2, 1, 3, 4, 5].into_iter().enumerate() {
            let text = r2o_rx_volume_plan_for_client(variant, "hcaptcha.com", 1492, false).unwrap();
            assert!(text.starts_with("r2o-plan 1 13\n"));
            assert!(text.contains("poison 1 autottl=1,2-12\n"));
            assert!(text.contains("repeats=8 gap_us=0 place=before tlsmod=rnd,dupsid\n"));
            assert!(text.contains(&format!("split payload_start +{split}\norder forward\n")));
            let plan = Plan::parse(&crate::plan_text::compile_text(&text).unwrap()).unwrap();
            assert_eq!(plan.minexec, 13);
            assert_eq!(
                plan.poisons[0].autottl,
                Some(r2k_core::plan::AutoTtl {
                    delta: 1,
                    min: 2,
                    max: 12,
                })
            );
            assert_eq!(plan.poisons[0].flags, 0);
            r2o_datapath::engine::validate_runtime_plan(&plan).unwrap();
        }
    }

    #[test]
    fn очередь_перебирает_имена_и_затем_запасные_разрезы() {
        let count = r2o_rx_volume_name_count();
        for index in 0..count {
            let candidate = r2o_rx_volume_candidate(index, 1492).unwrap().unwrap();
            let bytes = crate::plan_text::compile_text(&candidate).unwrap();
            let plan = Plan::parse(&bytes).unwrap();
            r2o_datapath::engine::validate_runtime_plan(&plan).unwrap();
        }
        let first = r2o_rx_volume_candidate(0, 1492).unwrap().unwrap();
        let fallback = r2o_rx_volume_candidate(count, 1492).unwrap().unwrap();
        assert!(first.contains("payload 1 "));
        assert!(first.contains("split payload_start +2"));
        assert!(fallback.contains("split payload_start +2"));
        assert!(
            r2o_rx_volume_candidate(count + 4, 1492)
                .unwrap()
                .unwrap()
                .contains("split payload_start +5")
        );
        assert!(r2o_rx_volume_candidate(count + 5, 1492).unwrap().is_none());
    }

    #[test]
    fn генератор_отклоняет_имена_и_пределы_отправки_которые_не_подходят() {
        assert!(r2o_rx_volume_plan(0, "", 1492).is_err());
        assert!(r2o_rx_volume_plan(0, "hcaptcha.com", 100).is_err());
        assert!(r2o_rx_volume_plan(5, "hcaptcha.com", 1492).is_err());
    }

    #[test]
    fn планы_совпадают_с_эталоном_c_после_переименования_формата() {
        let cases = [
            (
                0,
                "hcaptcha.com",
                include_str!("../tests/fixtures/r2o-rx-volume-hcaptcha-split2-c.txt"),
            ),
            (
                4,
                "hcaptcha.com",
                include_str!("../tests/fixtures/r2o-rx-volume-hcaptcha-split5-c.txt"),
            ),
            (
                0,
                "video.edge.example.net",
                include_str!("../tests/fixtures/r2o-rx-volume-longname-c.txt"),
            ),
        ];
        for (variant, name, c_plan) in cases {
            let expected = c_plan.replacen("d2k-plan 1 8", "r2o-plan 1 8", 1);
            assert_eq!(r2o_rx_volume_plan(variant, name, 0).unwrap(), expected);
        }
    }
}
