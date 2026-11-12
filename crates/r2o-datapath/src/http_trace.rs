//! C `datapath/http_trace.c`: текстовая строка HTTP-исполнения.
//!
//! Строка не печатает URL, cookies и заголовки — только имя хоста и
//! измеримые факты. Возвращаются байты без NUL, не длиннее `cap - 1`
//! (как `snprintf` в C).

use r2k_core::packet::PacketView;

/// C `d2k_result` в части, нужной трейсу.
pub struct HttpTraceResult<'a> {
    pub applied: bool,
    pub plan_id: [u8; 16],
    pub execution_id: u64,
    pub skipped: Option<&'a str>,
}

/// C `d2k_http_trace_outcome`: наблюдения после raw-отправок и вердикта.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HttpTraceOutcome {
    pub apply: bool,
    pub output_failed: bool,
    pub original_failed: bool,
    pub original_pending: bool,
    pub pending: bool,
    pub hook: u8,
    pub mark: u32,
    pub outdev: u32,
    pub verdict: u32,
    pub planned: usize,
    pub sent: usize,
    pub queued: usize,
}

/// C `d2k_http_trace`: пустой результат для не-HTTP-запроса.
pub fn http_trace(
    packet: &[u8],
    result: &HttpTraceResult<'_>,
    outcome: &HttpTraceOutcome,
    cap: usize,
) -> Vec<u8> {
    if cap == 0 {
        return Vec::new();
    }
    let Some(view) = PacketView::parse(packet) else {
        return Vec::new();
    };
    if view.protocol != 6 {
        return Vec::new();
    }
    let Some(tcp) = view.tcp_segment(packet) else {
        return Vec::new();
    };
    if tcp.destination_port != 80 {
        return Vec::new();
    }
    let segment_len = view.total_len.saturating_sub(view.l4_offset);
    if tcp.header_len < 20 || tcp.header_len >= segment_len {
        return Vec::new();
    }
    let Some(request) = packet.get(tcp.payload) else {
        return Vec::new();
    };
    let method_len = request
        .iter()
        .take_while(|byte| byte.is_ascii_uppercase())
        .count();
    if method_len == 0 || method_len == request.len() || request[method_len] != b' ' {
        return Vec::new();
    }

    let host = r2k_core::httpup::r2o_http_plan_request(request)
        .and_then(|parsed| request.get(parsed.host_range))
        .filter(|host| host.len() < 256)
        .map(|host| String::from_utf8_lossy(host).into_owned())
        .unwrap_or_else(|| "<unparsed>".to_string());

    let status = if !outcome.apply {
        "OBSERVE"
    } else if !result.applied {
        "SKIPPED"
    } else if outcome.output_failed || outcome.original_failed {
        "FAILED"
    } else if outcome.pending || outcome.original_pending {
        "PENDING"
    } else {
        "COMPLETE"
    };
    let plan = if result.applied {
        result
            .plan_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    } else {
        "-".to_string()
    };
    let original = if outcome.original_failed {
        "FAILED"
    } else if outcome.original_pending {
        "PENDING"
    } else if outcome.verdict != 0 {
        "ACCEPT"
    } else {
        "DROP"
    };
    let reason = result.skipped.unwrap_or("-");

    let line = format!(
        "d2kd: HTTP execution host={host} IPv{} [{}]:{} -> [{}]:80 seq={} hook={} mark=0x{:x} outdev={} status={status} prepared={} plan={plan} execution={} planned={} raw_sent={} queued={} original={original} output_failed={} reason={reason}",
        view.family,
        view.src,
        tcp.source_port,
        view.dst,
        tcp.sequence,
        outcome.hook,
        outcome.mark,
        outcome.outdev,
        u8::from(result.applied),
        result.execution_id,
        outcome.planned,
        outcome.sent,
        outcome.queued,
        u8::from(outcome.output_failed),
    );
    let mut bytes = line.into_bytes();
    bytes.truncate(cap - 1);
    bytes
}

#[cfg(test)]
mod tests {
    use super::{HttpTraceOutcome, HttpTraceResult, http_trace};

    const REQUEST: &[u8] =
        b"GET /private-path HTTP/1.1\r\nHost: example.com\r\nCookie: secret-cookie\r\n\r\n";

    fn tcp_packet(family: u8, destination_port: u16) -> Vec<u8> {
        let (ip_header, source, destination) = if family == 4 {
            (
                {
                    let mut header = vec![0_u8; 20];
                    header[0] = 0x45;
                    header[8] = 64;
                    header[9] = 6;
                    header[12..16].copy_from_slice(&[192, 0, 2, 1]);
                    header[16..20].copy_from_slice(&[198, 51, 100, 2]);
                    header
                },
                "192.0.2.1",
                "198.51.100.2",
            )
        } else {
            (
                {
                    let mut header = vec![0_u8; 40];
                    header[0] = 0x60;
                    header[6] = 6;
                    header[7] = 64;
                    header[8..24].copy_from_slice(&[
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]);
                    header[24..40].copy_from_slice(&[
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                    ]);
                    header
                },
                "2001:db8::1",
                "2001:db8::2",
            )
        };
        assert!(!source.is_empty() && !destination.is_empty());
        let mut tcp = vec![0_u8; 20];
        tcp[0..2].copy_from_slice(&53001_u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&1234_u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x18;
        let mut packet = ip_header;
        let header_len = packet.len();
        packet.extend_from_slice(&tcp);
        packet.extend_from_slice(REQUEST);
        let total = packet.len() as u16;
        if family == 4 {
            packet[2..4].copy_from_slice(&total.to_be_bytes());
        } else {
            packet[4..6].copy_from_slice(&(total as u16 - 40).to_be_bytes());
        }
        assert!(header_len > 0);
        packet
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn http_trace_matches_donor_statuses_and_hides_secrets() {
        let packet = tcp_packet(4, 80);
        let mut result = HttpTraceResult {
            applied: true,
            plan_id: {
                let mut id = [0; 16];
                id[0] = 0xab;
                id
            },
            execution_id: 42,
            skipped: None,
        };
        let mut outcome = HttpTraceOutcome {
            apply: true,
            hook: 4,
            planned: 1,
            pending: true,
            verdict: 1,
            ..HttpTraceOutcome::default()
        };
        let line = text(&http_trace(&packet, &result, &outcome, 1600));
        assert!(line.contains("status=PENDING"));
        assert!(line.contains("execution=42"));
        assert!(line.contains("plan=ab00"));
        assert!(line.contains("example.com"));
        assert!(!line.contains("secret-cookie"));
        assert!(!line.contains("private-path"));

        outcome.pending = false;
        outcome.sent = 1;
        let line = text(&http_trace(&packet, &result, &outcome, 1600));
        assert!(line.contains("status=COMPLETE"));
        assert!(line.contains("raw_sent=1"));
        assert!(line.contains("original=ACCEPT"));

        outcome.original_pending = true;
        let line = text(&http_trace(&packet, &result, &outcome, 1600));
        assert!(line.contains("status=PENDING"));
        assert!(line.contains("original=PENDING"));

        outcome.original_pending = false;
        outcome.original_failed = true;
        let line = text(&http_trace(&packet, &result, &outcome, 1600));
        assert!(line.contains("status=FAILED"));
        assert!(line.contains("original=FAILED"));

        outcome.original_failed = false;
        outcome.output_failed = true;
        let line = text(&http_trace(&packet, &result, &outcome, 1600));
        assert!(line.contains("status=FAILED"));

        outcome.output_failed = false;
        result.applied = false;
        result.skipped = Some("no HTTP plan");
        let line = text(&http_trace(&packet, &result, &outcome, 1600));
        assert!(line.contains("status=SKIPPED"));
        assert!(line.contains("reason=no HTTP plan"));

        outcome.apply = false;
        result.applied = true;
        let line = text(&http_trace(&packet, &result, &outcome, 1600));
        assert!(line.contains("status=OBSERVE"));
    }

    #[test]
    fn http_trace_rejects_other_ports_and_truncates_to_cap() {
        assert!(
            http_trace(
                &tcp_packet(4, 81),
                &HttpTraceResult {
                    applied: true,
                    plan_id: [0; 16],
                    execution_id: 1,
                    skipped: None,
                },
                &HttpTraceOutcome {
                    apply: true,
                    ..HttpTraceOutcome::default()
                },
                1600
            )
            .is_empty()
        );

        let packet = tcp_packet(6, 80);
        let result = HttpTraceResult {
            applied: true,
            plan_id: [0; 16],
            execution_id: 1,
            skipped: None,
        };
        let outcome = HttpTraceOutcome {
            apply: true,
            ..HttpTraceOutcome::default()
        };
        assert!(http_trace(&packet, &result, &outcome, 0).is_empty());
        let short = http_trace(&packet, &result, &outcome, 10);
        assert!(short.len() <= 9);
        let full = text(&http_trace(&packet, &result, &outcome, 1600));
        assert!(full.contains("IPv6"));
        assert!(full.contains("[2001:db8::1]:53001"));
    }
}
