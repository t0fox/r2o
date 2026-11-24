use super::*;

// Адаптация CheckIPv6, CheckIPRuleSupportsV6 и checkSupportsV6Filter из
// Tailscale util/linuxfw (Tailscale Inc & contributors, BSD-3-Clause).
pub(super) fn ipv6_enabled(proc: &Path) -> Result<()> {
    let disabled = fs::read_to_string(proc.join("sys/net/ipv6/conf/all/disable_ipv6"))?;
    if disabled.trim() != "0" {
        return Err(error("IPv6 отключён или sysctl не распознан"));
    }
    Ok(())
}

pub(super) fn ipv6_policy(proc: &Path) -> bool {
    // Отсутствие disable_policy допускается. Поддержку RPDB проверяем
    // чтением, которое не создаёт правила и не меняет маршрут.
    match optional(&proc.join("sys/net/ipv6/conf/all/disable_policy")) {
        Ok(Some(value)) if value.trim() == "0" => (),
        Ok(None) => (),
        _ => return false,
    }
    command("ip", &["-6", "rule", "show"], None).is_ok_and(|rules| !rules.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_disabled_missing_and_enabled_are_distinct() {
        let dir = std::env::temp_dir().join(format!("r2o-platform-ipv6-{}", std::process::id()));
        let file = dir.join("sys/net/ipv6/conf/all/disable_ipv6");
        assert!(ipv6_enabled(&dir).is_err());
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "1\n").unwrap();
        assert!(ipv6_enabled(&dir).is_err());
        fs::write(&file, "0\n").unwrap();
        assert!(ipv6_enabled(&dir).is_ok());
        fs::remove_dir_all(dir).unwrap();
    }
}
