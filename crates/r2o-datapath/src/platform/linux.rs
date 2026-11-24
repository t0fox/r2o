use super::*;

pub(super) fn accounting(sysctl: &Path, module: Option<&Path>, repair: bool) -> Result<()> {
    let (file, mut value, enabled) = match fs::read_to_string(sysctl) {
        Ok(value) => (sysctl, value, "1\n"),
        // Ядро Keenetic 4.9 публикует глобальный параметр вместо sysctl.
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let file = module.ok_or(err)?;
            (file, fs::read_to_string(file)?, "Y\n")
        }
        Err(err) => return Err(err),
    };
    if value.trim() != enabled.trim() && repair {
        fs::write(file, enabled)?;
        value = fs::read_to_string(file)?;
    }
    if value.trim() != enabled.trim() {
        return Err(error("не включён nf_conntrack_acct"));
    }
    Ok(())
}

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
    fn keenetic_accounting_falls_back_only_when_sysctl_is_missing() {
        let dir = env::temp_dir().join(format!("r2o-platform-accounting-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let sysctl = dir.join("nf_conntrack_acct");
        let module = dir.join("acct");
        fs::write(&module, "N\n").unwrap();
        assert!(accounting(&sysctl, Some(&module), false).is_err());
        assert!(accounting(&sysctl, None, true).is_err());
        assert_eq!(fs::read_to_string(&module).unwrap(), "N\n");
        accounting(&sysctl, Some(&module), true).unwrap();
        assert_eq!(fs::read_to_string(&module).unwrap(), "Y\n");
        accounting(&sysctl, Some(&module), false).unwrap();

        fs::write(&sysctl, "0\n").unwrap();
        assert!(accounting(&sysctl, Some(&module), false).is_err());
        accounting(&sysctl, Some(&module), true).unwrap();
        assert_eq!(fs::read_to_string(&sysctl).unwrap(), "1\n");
        fs::remove_dir_all(dir).unwrap();
    }

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
