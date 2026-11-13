use crate::{packet::PacketView, plan::Emission};

use crate::plan::{
    POISON_BADSUM, POISON_IPID_ZERO, POISON_MD5, POISON_TCPTS_BACK, POISON_TS_UP, WIRE_DETECT_TCP,
    WIRE_TCP_TEMPLATE,
};

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const TCP_TIMESTAMP_OPTION_LEN: usize = 12;

/// C `udp_next_fragment_id` (`core/udpruntime.c:22-30`): seed из random один
/// раз, затем `++id` с пропуском нулевого младшего 16-битного значения;
/// при отказе random — 0 (вызывающий отвергает план).
static UDP_FRAGMENT_ID: std::sync::Mutex<Option<u32>> = std::sync::Mutex::new(None);

fn next_udp_fragment_id() -> u32 {
    let mut state = UDP_FRAGMENT_ID
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.is_none() {
        let mut random = [0_u8; 4];
        if getrandom::getrandom(&mut random).is_err() {
            return 0;
        }
        *state = Some(u32::from_ne_bytes(random));
    }
    let mut id = state.unwrap_or(0).wrapping_add(1);
    if id as u16 == 0 {
        id = id.wrapping_add(1);
    }
    *state = Some(id);
    id
}

/// Собрать пакет TCP из исходного пакета соединения и действия плана.
///
/// Буфером `out` владеет вызывающий код и он же его переиспользует; при неверном
/// или слишком большом действии буфер остаётся нетронутым.
pub fn build_tcp_packet(input: &[u8], emission: &Emission, out: &mut [u8]) -> Option<usize> {
    let view = PacketView::parse(input)?;
    if view.protocol != 6
        || (emission.urgent
            && (emission.urgent_ptr == 0
                || usize::from(emission.urgent_ptr) > emission.bytes.len()))
        || (!emission.urgent && emission.urgent_ptr != 0)
        || emission.ipfrag != 0
        || !matches!(
            emission.wire_profile,
            0 | WIRE_DETECT_TCP | WIRE_TCP_TEMPLATE
        )
    {
        return None;
    }

    let tcp_view = view.tcp_segment(input)?;
    let measured = emission.wire_profile == WIRE_DETECT_TCP;
    let native = emission.wire_profile == WIRE_TCP_TEMPLATE;
    if emission.poison & POISON_MD5 != 0 && !measured {
        return None;
    }

    let tcp = input.get(view.l4_offset..view.total_len)?;
    if tcp.len() < TCP_HEADER_LEN {
        return None;
    }
    let original_options = input.get(tcp_view.options.clone())?;

    let mut options = [0; 40];
    let options_len = if native {
        options[..original_options.len()].copy_from_slice(original_options);
        let timestamp_at = shift_native_timestamp(
            &mut options[..original_options.len()],
            emission.poison & POISON_TCPTS_BACK != 0,
        )?;
        if emission.poison & POISON_TCPTS_BACK != 0 && timestamp_at.is_none() {
            return None;
        }
        if emission.poison & POISON_TS_UP != 0
            && let Some(offset) = timestamp_at
        {
            // D2O `wire.c` переносит весь 10-байтовый TS option в начало,
            // не меняя длину блока опций и data offset.
            options[..offset + 10].rotate_right(10);
        }
        original_options.len()
    } else if emission.poison & POISON_MD5 != 0 {
        20
    } else if emission.poison & POISON_TCPTS_BACK != 0 {
        TCP_TIMESTAMP_OPTION_LEN
    } else {
        0
    };

    let body_len = emission.prefix.len().checked_add(emission.bytes.len())?;
    if body_len > usize::from(u16::MAX) {
        return None;
    }
    let ip_header_len = if view.family == 6 {
        if emission.poison & POISON_IPID_ZERO != 0 {
            return None;
        }
        IPV6_HEADER_LEN
    } else {
        IPV4_HEADER_LEN
    };
    let tcp_header_len = TCP_HEADER_LEN.checked_add(options_len)?;
    let total_len = ip_header_len
        .checked_add(tcp_header_len)?
        .checked_add(body_len)?;
    if total_len > usize::from(u16::MAX) || out.len() < total_len {
        return None;
    }

    let measured_ip_id = if view.family == 4 && measured && emission.poison & POISON_IPID_ZERO == 0
    {
        let mut bytes = [0; 4];
        getrandom::getrandom(&mut bytes).ok()?;
        Some((u32::from_ne_bytes(bytes) % u32::from(u16::MAX)) as u16)
    } else {
        None
    };

    out[..total_len].fill(0);
    if view.family == 6 {
        let class = u32::from(view.traffic_class) << 20;
        let label = view.flow_label & 0x000f_ffff;
        out[..4].copy_from_slice(&(0x6000_0000 | class | label).to_be_bytes());
        write_u16(&mut out[4..6], (total_len - IPV6_HEADER_LEN) as u16);
        out[6] = 6;
        out[7] = if emission.ttl != 0 {
            emission.ttl
        } else if measured || view.hop_limit == 0 {
            64
        } else {
            view.hop_limit
        };
        out[8..24].copy_from_slice(&view.src.bytes());
        out[24..40].copy_from_slice(&view.dst.bytes());
    } else {
        out[0] = 0x45;
        write_u16(&mut out[2..4], total_len as u16);
        let ip_id = if emission.poison & POISON_IPID_ZERO != 0 {
            0
        } else if measured {
            measured_ip_id?
        } else if native {
            view.ip_id
        } else {
            view.ip_id.wrapping_add(1)
        };
        write_u16(&mut out[4..6], ip_id);
        write_u16(&mut out[6..8], if measured { 0 } else { 0x4000 });
        out[8] = if emission.ttl != 0 {
            emission.ttl
        } else if measured || view.hop_limit == 0 {
            64
        } else {
            view.hop_limit
        };
        out[9] = 6;
        let src = view.src.bytes();
        let dst = view.dst.bytes();
        out[12..16].copy_from_slice(&src[..4]);
        out[16..20].copy_from_slice(&dst[..4]);
        let checksum = checksum_value(sum16(&out[..IPV4_HEADER_LEN], 0));
        write_u16(&mut out[10..12], checksum);
    }

    let tcp_offset = ip_header_len;
    out[tcp_offset..tcp_offset + 4].copy_from_slice(&tcp[..4]);
    write_u32(
        &mut out[tcp_offset + 4..tcp_offset + 8],
        emission.seq.wrapping_add(emission.seq_shift as u32),
    );
    out[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&tcp[8..12]);
    out[tcp_offset + 12] = ((tcp_header_len / 4) as u8) << 4;
    out[tcp_offset + 13] = 0x18 | if emission.urgent { 0x20 } else { 0 };
    write_u16(
        &mut out[tcp_offset + 14..tcp_offset + 16],
        if measured {
            u16::MAX
        } else {
            u16::from_be_bytes([tcp[14], tcp[15]])
        },
    );
    if emission.urgent {
        write_u16(
            &mut out[tcp_offset + 18..tcp_offset + 20],
            emission.urgent_ptr,
        );
    }

    let option_offset = tcp_offset + TCP_HEADER_LEN;
    if native {
        out[option_offset..option_offset + options_len].copy_from_slice(&options[..options_len]);
    } else if emission.poison & POISON_MD5 != 0 {
        out[option_offset] = 19;
        out[option_offset + 1] = 18;
        out[option_offset + 18] = 1;
        out[option_offset + 19] = 1;
    } else if options_len != 0 {
        out[option_offset..option_offset + 4].copy_from_slice(&[1, 1, 8, 10]);
        write_u32(
            &mut out[option_offset + 4..option_offset + 8],
            if measured { 1 } else { 0 },
        );
    }

    let body_offset = tcp_offset + tcp_header_len;
    out[body_offset..body_offset + emission.prefix.len()].copy_from_slice(&emission.prefix);
    out[body_offset + emission.prefix.len()..total_len].copy_from_slice(&emission.bytes);

    let segment_len = tcp_header_len + body_len;
    let checksum = tcp_checksum(out, view.family, tcp_offset, segment_len)?;
    let checksum = if emission.poison & POISON_BADSUM == 0 {
        checksum
    } else if measured {
        match checksum ^ 0xbeef {
            0 => 0x1234,
            value => value,
        }
    } else {
        match !checksum {
            0 => u16::MAX,
            value => value,
        }
    };
    write_u16(&mut out[tcp_offset + 16..tcp_offset + 18], checksum);
    Some(total_len)
}

/// Собрать целый пакет UDP IPv4/IPv6 для отправки через raw-сокет.
/// Неподдерживаемые UDP-искажения и операции с пакетами отклоняются.
pub fn build_udp_packet(input: &[u8], emission: &Emission, out: &mut [u8]) -> Option<usize> {
    let view = PacketView::parse(input)?;
    if view.protocol != 17
        || view.total_len != input.len()
        || view.udp_payload_range(input).is_none()
        || emission.poison & (POISON_TCPTS_BACK | POISON_BADSUM) != 0
        || (view.family == 6 && emission.poison & POISON_IPID_ZERO != 0)
        || emission.seq_shift != 0
        || emission.wire_profile != 0
        || emission.ipfrag != 0
        || emission.urgent
        || emission.urgent_ptr != 0
        || !emission.prefix.is_empty()
    {
        return None;
    }

    let ip_header_len = if view.family == 4 {
        IPV4_HEADER_LEN
    } else {
        IPV6_HEADER_LEN
    };
    let udp_len = UDP_HEADER_LEN.checked_add(emission.bytes.len())?;
    let total_len = ip_header_len.checked_add(udp_len)?;
    if udp_len > usize::from(u16::MAX) || total_len > usize::from(u16::MAX) || out.len() < total_len
    {
        return None;
    }

    out[..total_len].fill(0);
    if view.family == 4 {
        out[0] = 0x45;
        out[1] = view.traffic_class;
        write_u16(&mut out[2..4], total_len as u16);
        let ip_id = if emission.poison & POISON_IPID_ZERO != 0 {
            0
        } else {
            view.ip_id.wrapping_add(1)
        };
        write_u16(&mut out[4..6], ip_id);
        write_u16(&mut out[6..8], 0x4000);
        out[8] = emission_ttl(emission, view.hop_limit);
        out[9] = 17;
        out[12..16].copy_from_slice(&view.src.bytes()[..4]);
        out[16..20].copy_from_slice(&view.dst.bytes()[..4]);
        let checksum = checksum_value(sum16(&out[..IPV4_HEADER_LEN], 0));
        write_u16(&mut out[10..12], checksum);
    } else {
        let class = u32::from(view.traffic_class) << 20;
        let label = view.flow_label & 0x000f_ffff;
        out[..4].copy_from_slice(&(0x6000_0000 | class | label).to_be_bytes());
        write_u16(&mut out[4..6], udp_len as u16);
        out[6] = 17;
        out[7] = emission_ttl(emission, view.hop_limit);
        out[8..24].copy_from_slice(&view.src.bytes());
        out[24..40].copy_from_slice(&view.dst.bytes());
    }

    let input_udp = input.get(view.l4_offset..view.l4_offset + UDP_HEADER_LEN)?;
    let udp_offset = ip_header_len;
    out[udp_offset..udp_offset + 4].copy_from_slice(&input_udp[..4]);
    write_u16(&mut out[udp_offset + 4..udp_offset + 6], udp_len as u16);
    out[udp_offset + UDP_HEADER_LEN..total_len].copy_from_slice(&emission.bytes);

    let pseudo = udp_pseudo_sum(&out[..], view.family, udp_len)?;
    let checksum = checksum_value(sum16(&out[udp_offset..total_len], pseudo));
    write_u16(
        &mut out[udp_offset + 6..udp_offset + 8],
        if checksum == 0 { u16::MAX } else { checksum },
    );
    Some(total_len)
}

/// Собрать набор UDP-фрагментов IPv4 или IPv6 по одной из четырёх форм QUIC.
pub fn build_udp_fragments(input: &[u8], emission: &Emission) -> Option<Vec<Vec<u8>>> {
    build_udp_fragments_with_capacity(input, emission, usize::MAX)
}

/// Собрать набор UDP-фрагментов, если он помещается в общий выходной буфер.
pub fn build_udp_fragments_with_capacity(
    input: &[u8],
    emission: &Emission,
    capacity: usize,
) -> Option<Vec<Vec<u8>>> {
    if !(1..=4).contains(&emission.ipfrag) {
        return None;
    }
    let view = PacketView::parse(input)?;
    let ip_header_len = if view.family == 4 {
        IPV4_HEADER_LEN
    } else {
        IPV6_HEADER_LEN
    };
    let mut whole_packet = vec![
        0;
        ip_header_len
            .checked_add(UDP_HEADER_LEN)?
            .checked_add(emission.bytes.len())?
    ];
    let mut whole_emission = emission.clone();
    whole_emission.ipfrag = 0;
    let whole_len = build_udp_packet(input, &whole_emission, &mut whole_packet)?;
    whole_packet.truncate(whole_len);
    let datagram = whole_packet.get(ip_header_len..whole_len)?;
    let cuts = udp_fragment_cuts(datagram.len(), emission.ipfrag)?;
    let reverse = emission.ipfrag > 1;
    let fragment_header_len: usize = if view.family == 4 { 20 } else { 48 };
    let needed = datagram
        .len()
        .checked_add(fragment_header_len.checked_mul(cuts.len())?)?;
    if needed > capacity {
        return None;
    }

    let id = next_udp_fragment_id();
    if id == 0 {
        return None;
    }
    let id4 = (id as u16).max(1);
    let id6 = id.max(1);
    let mut fragments = Vec::new();
    fragments.try_reserve_exact(cuts.len()).ok()?;
    for output_index in 0..cuts.len() {
        let logical_index = if reverse {
            cuts.len().checked_sub(output_index + 1)?
        } else {
            output_index
        };
        let (offset, length) = cuts[logical_index];
        let fragment_len = fragment_header_len.checked_add(length)?;
        if fragment_len > usize::from(u16::MAX) {
            return None;
        }
        let mut fragment = vec![0; fragment_len];
        if view.family == 4 {
            fragment[..20].copy_from_slice(&whole_packet[..20]);
            write_u16(&mut fragment[2..4], fragment_len as u16);
            write_u16(&mut fragment[4..6], id4);
            let more = logical_index + 1 < cuts.len();
            let flags_offset = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
            write_u16(&mut fragment[6..8], flags_offset);
            fragment[10..12].fill(0);
            let checksum = checksum_value(sum16(&fragment[..20], 0));
            write_u16(&mut fragment[10..12], checksum);
            fragment[20..].copy_from_slice(datagram.get(offset..offset + length)?);
        } else {
            fragment[..40].copy_from_slice(&whole_packet[..40]);
            let payload_len = UDP_HEADER_LEN.checked_add(length)?;
            write_u16(&mut fragment[4..6], payload_len as u16);
            fragment[6] = 44;
            fragment[40] = 17;
            let more = logical_index + 1 < cuts.len();
            let offset_and_more = (offset as u16) | if more { 1 } else { 0 };
            write_u16(&mut fragment[42..44], offset_and_more);
            write_u32(&mut fragment[44..48], id6);
            fragment[48..].copy_from_slice(datagram.get(offset..offset + length)?);
        }
        fragments.push(fragment);
    }
    Some(fragments)
}

fn udp_fragment_cuts(total: usize, shape: u8) -> Option<Vec<(usize, usize)>> {
    if total > 65_515 || !(1..=4).contains(&shape) {
        return None;
    }
    let first = if shape == 4 { 16 } else { 8 };
    if first >= total {
        return None;
    }
    if shape <= 2 {
        return Some(vec![(0, first), (first, total - first)]);
    }
    if total <= 24 {
        return None;
    }
    let mut second = if shape == 3 { 32 } else { 48 };
    second &= !7;
    if second <= first {
        second = first + 8;
    }
    if second >= total {
        second = (total - 8) & !7;
    }
    if second <= first {
        return None;
    }
    let overlap_first = (8usize).min(first - 8);
    let overlap_second = (8usize).min(second - 8);
    let offset_second = first - overlap_first;
    let mut offset_third = second - overlap_second;
    if offset_third <= offset_second {
        offset_third = offset_second + 8;
    }
    if offset_third >= total {
        offset_third = (total - 8) & !7;
    }
    if offset_third <= offset_second || offset_third >= total {
        return None;
    }
    Some(vec![
        (0, first),
        (offset_second, second - offset_second),
        (offset_third, total - offset_third),
    ])
}

fn emission_ttl(emission: &Emission, original: u8) -> u8 {
    if emission.ttl != 0 {
        emission.ttl
    } else if original != 0 {
        original
    } else {
        64
    }
}

/// Проверить контрольную сумму TCP целого пакета IPv4 или IPv6.
pub fn tcp_checksum_ok(packet: &[u8]) -> bool {
    let Some(view) = PacketView::parse(packet) else {
        return false;
    };
    if view.protocol != 6 || view.total_len > packet.len() {
        return false;
    }
    let Some(tcp_len) = view.total_len.checked_sub(view.l4_offset) else {
        return false;
    };
    if tcp_len < TCP_HEADER_LEN {
        return false;
    }
    let Some(tcp) = packet.get(view.l4_offset..view.total_len) else {
        return false;
    };
    let header_len = usize::from(tcp[12] >> 4) * 4;
    if !(TCP_HEADER_LEN..=tcp_len).contains(&header_len) {
        return false;
    }
    let Some(acc) = pseudo_sum(view.src.bytes(), view.dst.bytes(), view.family, tcp_len) else {
        return false;
    };
    checksum_value(sum16(tcp, acc)) == 0
}

fn shift_native_timestamp(options: &mut [u8], shift: bool) -> Option<Option<usize>> {
    let mut offset = 0;
    let mut found = None;
    while offset < options.len() {
        match options[offset] {
            0 => break,
            1 => offset += 1,
            kind => {
                let len = usize::from(*options.get(offset + 1)?);
                if len < 2 || len > options.len() - offset {
                    return None;
                }
                if kind == 8 {
                    if len != 10 || found.is_some() {
                        return None;
                    }
                    found = Some(offset);
                    if shift {
                        let timestamp =
                            u32::from_be_bytes(options[offset + 2..offset + 6].try_into().ok()?);
                        options[offset + 2..offset + 6]
                            .copy_from_slice(&timestamp.wrapping_sub(1000).to_be_bytes());
                    }
                }
                offset += len;
            }
        }
    }
    Some(found)
}

fn tcp_checksum(packet: &[u8], family: u8, offset: usize, len: usize) -> Option<u16> {
    let end = offset.checked_add(len)?;
    let tcp = packet.get(offset..end)?;
    let src: [u8; 16] = if family == 4 {
        let mut address = [0; 16];
        address[..4].copy_from_slice(packet.get(12..16)?);
        address
    } else {
        packet.get(8..24)?.try_into().ok()?
    };
    let dst: [u8; 16] = if family == 4 {
        let mut address = [0; 16];
        address[..4].copy_from_slice(packet.get(16..20)?);
        address
    } else {
        packet.get(24..40)?.try_into().ok()?
    };
    Some(checksum_value(sum16(
        tcp,
        pseudo_sum(src, dst, family, len)?,
    )))
}

fn pseudo_sum(src: [u8; 16], dst: [u8; 16], family: u8, tcp_len: usize) -> Option<u64> {
    let mut acc = 0;
    match family {
        4 => {
            acc = sum16(&src[..4], acc);
            acc = sum16(&dst[..4], acc);
            acc += 6 + u64::try_from(tcp_len).ok()?;
        }
        6 => {
            acc = sum16(&src, acc);
            acc = sum16(&dst, acc);
            acc += 6 + u64::try_from(tcp_len).ok()?;
        }
        _ => return None,
    }
    Some(acc)
}

/// C `pseudo_sum` (`datapath/wire_udp.c:57-65`): псевдозаголовок UDP —
/// адреса, ноль, proto 17, длина датаграммы; для IPv6 — 32 байта адресов.
fn udp_pseudo_sum(packet: &[u8], family: u8, udp_len: usize) -> Option<u64> {
    match family {
        4 => Some(
            sum16(packet.get(12..20)?, 0)
                .saturating_add(17)
                .saturating_add(udp_len as u64),
        ),
        6 => Some(
            sum16(packet.get(8..40)?, 0)
                .saturating_add(((udp_len as u32) >> 16) as u64)
                .saturating_add((udp_len as u32 & 0xffff) as u64)
                .saturating_add(17),
        ),
        _ => None,
    }
}

fn sum16(bytes: &[u8], mut acc: u64) -> u64 {
    for word in bytes.chunks(2) {
        acc += if word.len() == 2 {
            u64::from(u16::from_be_bytes([word[0], word[1]]))
        } else {
            u64::from(word[0]) << 8
        };
    }
    acc
}

fn checksum_value(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn write_u16(out: &mut [u8], value: u16) {
    out.copy_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut [u8], value: u32) {
    out.copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod udp_pseudo_sum_tests {
    use super::{sum16, udp_pseudo_sum};

    fn c_style_pseudo_header(source: &[u8], destination: &[u8], udp_len: usize) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(source);
        header.extend_from_slice(destination);
        header.push(0);
        header.push(17);
        header.extend_from_slice(&(udp_len as u16).to_be_bytes());
        header
    }

    #[test]
    fn udp_pseudo_sum_matches_c_pseudo_header() {
        let mut v4 = vec![0u8; 20];
        v4[12..16].copy_from_slice(&[192, 0, 2, 10]);
        v4[16..20].copy_from_slice(&[198, 51, 100, 20]);
        let header4 = c_style_pseudo_header(&v4[12..16], &v4[16..20], 1234);
        assert_eq!(udp_pseudo_sum(&v4, 4, 1234), Some(sum16(&header4, 0)));

        let source: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let destination: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut v6 = vec![0u8; 40];
        v6[8..24].copy_from_slice(&source.octets());
        v6[24..40].copy_from_slice(&destination.octets());
        let header6 = c_style_pseudo_header(&v6[8..24], &v6[24..40], 4321);
        assert_eq!(udp_pseudo_sum(&v6, 6, 4321), Some(sum16(&header6, 0)));
        assert_eq!(udp_pseudo_sum(&v4, 5, 10), None);
    }
}

#[cfg(test)]
mod udp_fragment_id_tests {
    #[test]
    fn udp_fragment_id_matches_c_counter() {
        let a = super::next_udp_fragment_id();
        assert_ne!(a, 0);
        assert_ne!(a as u16, 0);
        let b = super::next_udp_fragment_id();
        assert_ne!(b as u16, 0);
        assert!(b == a.wrapping_add(1) || b == a.wrapping_add(2));
    }
}
