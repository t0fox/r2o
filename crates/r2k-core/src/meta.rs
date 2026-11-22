//! Классификация наблюдений Meta. Суффиксы служат только для отбора кандидатов.

use std::path::{Path, PathBuf};

pub const PRODUCTS: &[&str] = &[
    "facebook",
    "instagram",
    "whatsapp",
    "messenger",
    "threads",
    "quest",
    "fbcdn",
];

pub fn protection_enabled(state: &Path) -> bool {
    state.join("meta-protection.enabled").is_file()
        && !state.join("meta-protection.disabled").exists()
}

pub fn product_marker(state: &Path, product: &str) -> Option<PathBuf> {
    PRODUCTS
        .contains(&product)
        .then(|| state.join(format!("meta-protection.{product}.disabled")))
}

pub fn disabled_products(state: &Path) -> Vec<&'static str> {
    PRODUCTS
        .iter()
        .copied()
        .filter(|name| product_marker(state, name).is_some_and(|path| path.exists()))
        .collect()
}

pub fn product(host: &str) -> Option<&'static str> {
    if host.len() > 253
        || !host.contains('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return None;
    }
    let under = |root| host == root || host.strip_suffix(root).is_some_and(|s| s.ends_with('.'));
    if under("messenger.com") || host == "edge-chat.facebook.com" {
        Some("messenger")
    } else if under("oculus.com")
        || under("oculuscdn.com")
        || under("oculusrift.com")
        || under("meta.com")
        || under("metaquest.com")
        || under("oculus.xx.fbcdn.net")
        || under("oculus.fallback.xx.fbcdn.net")
    {
        Some("quest")
    } else if under("threads.com") || under("threads.net") {
        Some("threads")
    } else if under("instagram.com") || under("cdninstagram.com") {
        Some("instagram")
    } else if under("whatsapp.com") || under("whatsapp.net") {
        Some("whatsapp")
    } else if under("facebook.com") || under("fb.com") || under("fbsbx.com") || under("fb.me") {
        Some("facebook")
    } else if under("fbcdn.net") || under("facebook.net") {
        Some("fbcdn")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_hostname_admission() {
        assert_eq!(product("edge-chat.facebook.com"), Some("messenger"));
        assert_eq!(product("oculus.xx.fbcdn.net"), Some("quest"));
        assert_eq!(product("new-cdn.whatsapp.net"), Some("whatsapp"));
        for host in [
            "whatsapp.net.example.org",
            "evilwhatsapp.net",
            "*.whatsapp.net",
            "bad;id.facebook.com",
        ] {
            assert_eq!(product(host), None, "{host}");
        }
    }
}
