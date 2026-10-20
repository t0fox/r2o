use crate::addr::Address;
use std::ops::Range;

/// Ограниченное представление только для чтения поддерживаемого пакета TCP/UDP IPv4 или IPv6.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketView {
    pub src: Address,
    pub dst: Address,
    pub total_len: usize,
    pub l4_offset: usize,
    pub family: u8,
    pub protocol: u8,
    pub hop_limit: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub fragment: u16,
    pub ip_id: u16,
}

/// Ограниченные поля TCP и диапазоны байтов пакета, разобранного через [`PacketView`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpSegmentView {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u8,
    pub window: u16,
    pub urgent_pointer: u16,
    pub header_len: usize,
    pub options: Range<usize>,
    pub payload: Range<usize>,
}

impl PacketView {
    /// Разбирать только такие пакеты, которые datapath может безопасно изменить.
    ///
    /// Для неподдерживаемых пакетов вернуть `None`, чтобы вызывающий код пропустил их.
    pub fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }

        let family = packet[0] >> 4;
        let mut view = Self {
            src: Address::from_v4([0; 4]),
            dst: Address::from_v4([0; 4]),
            total_len: 0,
            l4_offset: 0,
            family,
            protocol: 0,
            hop_limit: 0,
            traffic_class: 0,
            flow_label: 0,
            fragment: 0,
            ip_id: 0,
        };

        match family {
            4 => parse_ipv4(packet, &mut view)?,
            6 => parse_ipv6(packet, &mut view)?,
            _ => return None,
        }

        let minimum_transport_len = match view.protocol {
            6 => 20,
            17 => 8,
            _ => return None,
        };
        if view.total_len.checked_sub(view.l4_offset)? < minimum_transport_len {
            return None;
        }
        Some(view)
    }

    /// Вернуть ограниченный диапазон данных UDP, если объявленная длина совпадает с длиной IP-пакета.
    pub fn udp_payload_range(&self, packet: &[u8]) -> Option<Range<usize>> {
        if self.protocol != 17 || self.total_len > packet.len() {
            return None;
        }
        let udp_header_end = self.l4_offset.checked_add(8)?;
        if udp_header_end > self.total_len {
            return None;
        }
        let udp_len = usize::from(read_u16(packet, self.l4_offset + 4)?);
        if udp_len < 8 || udp_len != self.total_len.checked_sub(self.l4_offset)? {
            return None;
        }
        Some(udp_header_end..self.total_len)
    }

    /// Вернуть ограниченные поля TCP, если заголовок полностью присутствует.
    pub fn tcp_segment(&self, packet: &[u8]) -> Option<TcpSegmentView> {
        if self.protocol != 6 || self.total_len > packet.len() {
            return None;
        }
        let tcp = packet.get(self.l4_offset..self.total_len)?;
        if tcp.len() < 20 {
            return None;
        }
        let header_len = usize::from(tcp[12] >> 4) * 4;
        if !(20..=tcp.len()).contains(&header_len) {
            return None;
        }
        let options_start = self.l4_offset + 20;
        let header_end = self.l4_offset + header_len;
        Some(TcpSegmentView {
            source_port: read_u16(tcp, 0)?,
            destination_port: read_u16(tcp, 2)?,
            sequence: read_u32(tcp, 4)?,
            acknowledgment: read_u32(tcp, 8)?,
            flags: tcp[13],
            window: read_u16(tcp, 14)?,
            urgent_pointer: read_u16(tcp, 18)?,
            header_len,
            options: options_start..header_end,
            payload: header_end..self.total_len,
        })
    }
}

fn parse_ipv4(packet: &[u8], view: &mut PacketView) -> Option<()> {
    view.l4_offset = usize::from(packet[0] & 0x0f) * 4;
    view.total_len = usize::from(read_u16(packet, 2)?);
    if view.l4_offset < 20 || view.total_len < view.l4_offset || view.total_len > packet.len() {
        return None;
    }

    view.fragment = read_u16(packet, 6)?;
    if view.fragment & 0x1fff != 0 {
        return None;
    }
    view.ip_id = read_u16(packet, 4)?;
    view.protocol = packet[9];
    view.hop_limit = packet[8];
    view.traffic_class = packet[1];
    view.src = Address::from_v4(packet[12..16].try_into().ok()?);
    view.dst = Address::from_v4(packet[16..20].try_into().ok()?);
    Some(())
}

fn parse_ipv6(packet: &[u8], view: &mut PacketView) -> Option<()> {
    if packet.len() < 40 {
        return None;
    }
    let payload_len = usize::from(read_u16(packet, 4)?);
    if payload_len == 0 || payload_len > packet.len() - 40 {
        return None;
    }

    view.total_len = 40 + payload_len;
    view.l4_offset = 40;
    view.protocol = packet[6];
    view.hop_limit = packet[7];
    view.traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
    view.flow_label =
        (u32::from(packet[1] & 0x0f) << 16) | (u32::from(packet[2]) << 8) | u32::from(packet[3]);
    view.src = Address::from_v6(packet[8..24].try_into().ok()?);
    view.dst = Address::from_v6(packet[24..40].try_into().ok()?);

    let mut headers = 0;
    while matches!(view.protocol, 0 | 60) {
        headers += 1;
        if headers > 8 || view.total_len.checked_sub(view.l4_offset)? < 8 {
            return None;
        }
        let extension_len = (usize::from(*packet.get(view.l4_offset + 1)?) + 1) * 8;
        if extension_len > view.total_len - view.l4_offset {
            return None;
        }
        if !has_only_padding_options(packet, view.l4_offset, extension_len)? {
            return None;
        }
        view.protocol = *packet.get(view.l4_offset)?;
        view.l4_offset += extension_len;
    }
    Some(())
}

fn has_only_padding_options(packet: &[u8], offset: usize, extension_len: usize) -> Option<bool> {
    let end = offset.checked_add(extension_len)?;
    let mut option_offset = offset + 2;
    while option_offset < end {
        let option = *packet.get(option_offset)?;
        if option == 0 {
            option_offset += 1;
            continue;
        }
        if option != 1 || end - option_offset < 2 {
            return Some(false);
        }
        let padding_len = usize::from(*packet.get(option_offset + 1)?) + 2;
        if padding_len > end - option_offset {
            return Some(false);
        }
        option_offset += padding_len;
    }
    Some(true)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes(value.try_into().ok()?))
}
