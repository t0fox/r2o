//! C/Rust differential: Telegram-туннель и имя-приманка D2K.
//!
//! ```text
//! tg_telegram_domain_trace
//! ```

use r2o_controller::domain::{is_sched_decoy, is_telegram_tunnel_domain};

fn main() {
    for name in [
        "telegram.org",
        "TELEGRAM.ORG",
        "web.telegram.org",
        "a.b.Telegram.Org",
        ".telegram.org",
        "",
        "telegram.or",
        "nottelegram.org",
        "xtelegram.org",
        "telegram.org.evil",
        "telegram.org.",
        "telegramxorg",
        "disk.rzd.ru",
        "DISK.RZD.RU",
        "disk.rzd.ru.",
        "ddos-guard.net",
    ] {
        println!(
            "{name} tunnel={} decoy={}",
            u8::from(is_telegram_tunnel_domain(name)),
            u8::from(is_sched_decoy(name))
        );
    }
}
