use std::io::{BufRead, BufReader, Read};
use std::net::Ipv4Addr;
use std::path::Path;

pub const R2O_VOICE_MAX_TARGETS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oVoiceTarget {
    pub server_ip: Ipv4Addr,
    pub server_port: u16,
    pub client_ip: Ipv4Addr,
    pub client_port: u16,
    pub packets: i32,
    pub replied: bool,
}

pub fn r2o_parse_voice_targets(r2o_contents: &str) -> Vec<R2oVoiceTarget> {
    let mut r2o_targets = Vec::new();
    for r2o_line in r2o_contents.lines() {
        r2o_add_voice_target(r2o_line, &mut r2o_targets);
    }
    r2o_sort_voice_targets(&mut r2o_targets);
    r2o_targets
}

pub fn r2o_read_voice_targets(r2o_path: Option<&Path>) -> Vec<R2oVoiceTarget> {
    let r2o_path = r2o_path.unwrap_or_else(|| Path::new("/proc/net/nf_conntrack"));
    let Ok(r2o_file) = std::fs::File::open(r2o_path) else {
        return Vec::new();
    };

    let mut r2o_reader = BufReader::new(r2o_file);
    let mut r2o_targets = Vec::new();
    let mut r2o_line = Vec::with_capacity(2047);
    loop {
        r2o_line.clear();
        let r2o_bytes = match (&mut r2o_reader)
            .take(2047)
            .read_until(b'\n', &mut r2o_line)
        {
            Ok(r2o_bytes) => r2o_bytes,
            Err(_) => break,
        };
        if r2o_bytes == 0 {
            break;
        }
        r2o_add_voice_target(&String::from_utf8_lossy(&r2o_line), &mut r2o_targets);
    }
    r2o_sort_voice_targets(&mut r2o_targets);
    r2o_targets
}

pub fn r2o_format_voice_targets(r2o_targets: &[R2oVoiceTarget]) -> String {
    if r2o_targets.is_empty() {
        return "Живых разговоров не видно. Начните звонок и повторите.\n".into();
    }

    let mut r2o_output = String::from("Живые разговоры (по убыванию нагрузки):\n");
    for r2o_target in r2o_targets {
        let r2o_reply = if r2o_target.replied {
            ""
        } else {
            "  (ответов нет)"
        };
        r2o_output.push_str(&format!(
            "  {}:{}  <- {}:{}  пакетов {}{}\n",
            r2o_target.server_ip,
            r2o_target.server_port,
            r2o_target.client_ip,
            r2o_target.client_port,
            r2o_target.packets,
            r2o_reply
        ));
    }
    r2o_output
}

fn r2o_add_voice_target(r2o_line: &str, r2o_targets: &mut Vec<R2oVoiceTarget>) {
    if !r2o_line.contains("udp") {
        return;
    }

    let Some(r2o_server_ip) =
        r2o_field(r2o_line, "dst").and_then(|r2o_value| r2o_value.parse().ok())
    else {
        return;
    };
    if r2o_is_private(r2o_server_ip) {
        return;
    }
    let Some(r2o_server_port) = r2o_field(r2o_line, "dport")
        .and_then(|r2o_value| r2o_value.parse::<u16>().ok())
        .filter(|r2o_port| r2o_is_voice_port(*r2o_port))
    else {
        return;
    };
    let Some(r2o_client_ip) =
        r2o_field(r2o_line, "src").and_then(|r2o_value| r2o_value.parse().ok())
    else {
        return;
    };

    let r2o_client_port = r2o_field(r2o_line, "sport")
        .and_then(|r2o_value| r2o_value.parse::<u16>().ok())
        .unwrap_or(0);
    let r2o_packets = r2o_field(r2o_line, "packets")
        .and_then(|r2o_value| r2o_value.parse::<i32>().ok())
        .unwrap_or(0);
    let r2o_replied = !r2o_line.contains("[UNREPLIED]");

    if let Some(r2o_existing) = r2o_targets.iter_mut().find(|r2o_existing| {
        r2o_existing.server_ip == r2o_server_ip
            && r2o_existing.server_port == r2o_server_port
            && r2o_existing.client_ip == r2o_client_ip
            && r2o_existing.client_port == r2o_client_port
    }) {
        r2o_existing.packets = r2o_existing.packets.saturating_add(r2o_packets);
        r2o_existing.replied |= r2o_replied;
    } else if r2o_targets.len() < R2O_VOICE_MAX_TARGETS {
        r2o_targets.push(R2oVoiceTarget {
            server_ip: r2o_server_ip,
            server_port: r2o_server_port,
            client_ip: r2o_client_ip,
            client_port: r2o_client_port,
            packets: r2o_packets,
            replied: r2o_replied,
        });
    }
}

fn r2o_field<'a>(r2o_line: &'a str, r2o_name: &str) -> Option<&'a str> {
    let mut r2o_offset = 0;
    while let Some(r2o_relative) = r2o_line[r2o_offset..].find(r2o_name) {
        let r2o_start = r2o_offset + r2o_relative;
        let r2o_after_name = r2o_start + r2o_name.len();
        if (r2o_start == 0 || r2o_line.as_bytes()[r2o_start - 1] == b' ')
            && r2o_line.as_bytes().get(r2o_after_name) == Some(&b'=')
        {
            let r2o_value_start = r2o_after_name + 1;
            let r2o_value_end = r2o_line[r2o_value_start..]
                .find(char::is_whitespace)
                .map_or(r2o_line.len(), |r2o_end| r2o_value_start + r2o_end);
            return Some(&r2o_line[r2o_value_start..r2o_value_end]);
        }
        r2o_offset = r2o_after_name;
    }
    None
}

fn r2o_is_private(r2o_ip: Ipv4Addr) -> bool {
    let [r2o_first, r2o_second, _, _] = r2o_ip.octets();
    r2o_first == 127
        || r2o_first == 10
        || (r2o_first == 172 && r2o_second & 0xf0 == 16)
        || (r2o_first == 192 && r2o_second == 168)
        || (r2o_first == 169 && r2o_second == 254)
        || (r2o_first == 100 && r2o_second & 0xc0 == 64)
        || r2o_ip.is_unspecified()
}

fn r2o_is_voice_port(r2o_port: u16) -> bool {
    (50_000..=50_099).contains(&r2o_port)
        || r2o_port == 1400
        || (3478..=3481).contains(&r2o_port)
        || r2o_port == 5349
        || (19_294..=19_344).contains(&r2o_port)
}

fn r2o_sort_voice_targets(r2o_targets: &mut [R2oVoiceTarget]) {
    r2o_targets.sort_by(|r2o_left, r2o_right| r2o_right.packets.cmp(&r2o_left.packets));
}

#[cfg(test)]
mod tests {
    use super::{
        R2O_VOICE_MAX_TARGETS, R2oVoiceTarget, r2o_format_voice_targets, r2o_is_private,
        r2o_is_voice_port, r2o_parse_voice_targets, r2o_read_voice_targets,
    };
    use std::net::Ipv4Addr;

    #[test]
    fn отбирает_udp_голосовые_порты_и_публичные_адреса() {
        let r2o_targets = r2o_parse_voice_targets(
            "ipv4 2 udp 17 29 src=192.168.1.2 dst=35.217.0.67 sport=50001 dport=50000 packets=4\n\
             ipv4 2 udp 17 29 src=192.168.1.2 dst=35.217.0.68 sport=50001 dport=50099 packets=9\n\
             ipv4 2 udp 17 29 src=192.168.1.2 dst=35.217.0.69 sport=50001 dport=50100 packets=99\n\
             ipv4 2 tcp 6 29 src=192.168.1.2 dst=35.217.0.70 sport=50001 dport=50004 packets=99\n\
             ipv4 2 udp 17 29 src=192.168.1.2 dst=100.64.0.1 sport=50001 dport=50004 packets=99\n\
             ipv4 2 udp 17 29 src=192.168.1.2 dst=2001:db8::1 sport=50001 dport=50004 packets=99\n",
        );

        assert_eq!(r2o_targets.len(), 2);
        assert_eq!(r2o_targets[0].server_ip, Ipv4Addr::new(35, 217, 0, 68));
        assert_eq!(r2o_targets[0].server_port, 50_099);
        assert_eq!(r2o_targets[1].server_port, 50_000);
    }

    #[test]
    fn объединяет_только_одинаковые_потоки_и_сводит_ответы_по_или() {
        let r2o_targets = r2o_parse_voice_targets(
            "udp src=192.0.2.10 dst=35.217.0.67 sport=50001 dport=50004 packets=7 [UNREPLIED]\n\
             udp src=192.0.2.10 dst=35.217.0.67 sport=50001 dport=50004 packets=5\n\
             udp src=192.0.2.10 dst=35.217.0.67 sport=50002 dport=50004 packets=8 [UNREPLIED]\n",
        );

        assert_eq!(r2o_targets.len(), 2);
        assert_eq!(r2o_targets[0].client_port, 50_001);
        assert_eq!(r2o_targets[0].packets, 12);
        assert!(r2o_targets[0].replied);
        assert_eq!(r2o_targets[1].client_port, 50_002);
        assert!(!r2o_targets[1].replied);
    }

    #[test]
    fn ограничивает_список_восемью_потоками_и_сохраняет_порядок_равных() {
        let r2o_contents = (1..=10)
            .map(|r2o_index| {
                format!(
                    "udp src=192.0.2.{r2o_index} dst=35.217.0.{r2o_index} sport=50000 dport=50004 packets=10\n"
                )
            })
            .collect::<String>();
        let r2o_targets = r2o_parse_voice_targets(&r2o_contents);

        assert_eq!(r2o_targets.len(), R2O_VOICE_MAX_TARGETS);
        assert_eq!(r2o_targets[0].client_ip, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(r2o_targets[7].client_ip, Ipv4Addr::new(192, 0, 2, 8));
    }

    #[test]
    fn принимает_только_границы_голосовых_диапазонов_портов() {
        let r2o_allowed = [1400, 3478, 3481, 5349, 19_294, 19_344, 50_000, 50_099];
        let r2o_rejected = [
            1399, 1401, 3477, 3482, 5348, 5350, 19_293, 19_345, 49_999, 50_100,
        ];

        assert!(r2o_allowed.into_iter().all(r2o_is_voice_port));
        assert!(
            r2o_rejected
                .into_iter()
                .all(|r2o_port| !r2o_is_voice_port(r2o_port))
        );
    }

    #[test]
    fn исключает_частные_адреса_и_оставляет_соседние_публичные() {
        let r2o_private = [
            "0.0.0.0",
            "10.255.255.255",
            "127.0.0.1",
            "172.16.0.0",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
        ];
        let r2o_public = [
            "0.0.0.1",
            "8.8.8.8",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.1.1",
            "169.253.1.1",
            "100.63.255.255",
            "100.128.0.1",
        ];

        assert!(
            r2o_private
                .into_iter()
                .all(|r2o_ip| r2o_is_private(r2o_ip.parse().unwrap()))
        );
        assert!(
            r2o_public
                .into_iter()
                .all(|r2o_ip| !r2o_is_private(r2o_ip.parse().unwrap()))
        );
    }

    #[test]
    fn ограничивает_длину_строки_таблицы_двумя_тысячами_сорока_семью_байтами() {
        let r2o_path = std::env::temp_dir().join(format!(
            "r2o-voice-list-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let r2o_contents = format!(
            "udp {} src=192.0.2.10 dst=35.217.0.67 sport=50001 dport=50004 packets=9\n",
            "x".repeat(2100)
        );
        std::fs::write(&r2o_path, r2o_contents).unwrap();
        let r2o_targets = r2o_read_voice_targets(Some(&r2o_path));
        std::fs::remove_file(r2o_path).unwrap();

        assert!(r2o_targets.is_empty());
    }

    #[test]
    fn форматирует_ответ_и_пустой_список_по_русски() {
        let r2o_target = R2oVoiceTarget {
            server_ip: Ipv4Addr::new(35, 217, 0, 67),
            server_port: 50_004,
            client_ip: Ipv4Addr::new(192, 0, 2, 10),
            client_port: 54_321,
            packets: 812,
            replied: false,
        };

        assert_eq!(
            r2o_format_voice_targets(&[r2o_target]),
            "Живые разговоры (по убыванию нагрузки):\n  35.217.0.67:50004  <- 192.0.2.10:54321  пакетов 812  (ответов нет)\n"
        );
        assert_eq!(
            r2o_format_voice_targets(&[]),
            "Живых разговоров не видно. Начните звонок и повторите.\n"
        );
    }
}
