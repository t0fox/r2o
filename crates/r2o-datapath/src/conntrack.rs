//! Запросы счётчиков потоков через Linux ctnetlink.

use crate::netlink::{MessageIter, NLMSG_ERROR};
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;

const NETLINK_NETFILTER: i32 = 12;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_NEW: u16 = 0;
const IPCTNL_MSG_CT_GET: u16 = 1;
const NLM_F_REQUEST: u16 = 1;
const NLA_HEADER_LEN: usize = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;
const NLA_F_NESTED: u16 = 0x8000;
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;
const CTA_PROTOINFO: u16 = 4;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_COUNTERS_PACKETS: u16 = 1;
const CTA_COUNTERS32_PACKETS: u16 = 3;
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;
const TCP_CONNTRACK_ESTABLISHED: u8 = 3;
const NLMSG_HEADER_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oConntrackTuple {
    pub family: u8,
    pub protocol: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oConntrackInfo {
    pub original_packets: u64,
    pub reply_packets: u64,
    pub tcp_state: Option<u8>,
}

impl R2oConntrackInfo {
    pub fn is_established(self) -> bool {
        self.tcp_state == Some(TCP_CONNTRACK_ESTABLISHED)
    }
}

pub fn encode_get(sequence: u32, tuple: &R2oConntrackTuple) -> Option<Vec<u8>> {
    if !matches!(tuple.family, 4 | 6) || !matches!(tuple.protocol, 6 | 17) {
        return None;
    }

    let address_len = if tuple.family == 4 { 4 } else { 16 };
    let mut ip = Vec::new();
    push_attribute(
        &mut ip,
        if tuple.family == 4 {
            CTA_IP_V4_SRC
        } else {
            CTA_IP_V6_SRC
        },
        &tuple.source[..address_len],
    );
    push_attribute(
        &mut ip,
        if tuple.family == 4 {
            CTA_IP_V4_DST
        } else {
            CTA_IP_V6_DST
        },
        &tuple.destination[..address_len],
    );

    let mut protocol = Vec::new();
    push_attribute(&mut protocol, CTA_PROTO_NUM, &[tuple.protocol]);
    push_attribute(
        &mut protocol,
        CTA_PROTO_SRC_PORT,
        &tuple.source_port.to_be_bytes(),
    );
    push_attribute(
        &mut protocol,
        CTA_PROTO_DST_PORT,
        &tuple.destination_port.to_be_bytes(),
    );

    let mut original_tuple = Vec::new();
    push_attribute(&mut original_tuple, CTA_TUPLE_IP | NLA_F_NESTED, &ip);
    push_attribute(
        &mut original_tuple,
        CTA_TUPLE_PROTO | NLA_F_NESTED,
        &protocol,
    );

    let mut message = vec![0; NLMSG_HEADER_LEN];
    message.extend_from_slice(&[if tuple.family == 4 { 2 } else { 10 }, 0, 0, 0]);
    push_attribute(&mut message, CTA_TUPLE_ORIG | NLA_F_NESTED, &original_tuple);
    let message_len = u32::try_from(message.len()).ok()?;
    message[..4].copy_from_slice(&message_len.to_ne_bytes());
    message[4..6]
        .copy_from_slice(&((NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET).to_ne_bytes());
    message[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    message[8..12].copy_from_slice(&sequence.to_ne_bytes());
    Some(message)
}

pub fn decode_info(bytes: &[u8], sequence: u32) -> Option<R2oConntrackInfo> {
    for message in MessageIter::new(bytes) {
        if message.sequence != sequence
            || message.kind != ((NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW)
            || message.body.len() < 4
        {
            continue;
        }
        let attributes = &message.body[4..];
        let original_packets = parse_counter(find_attribute(attributes, CTA_COUNTERS_ORIG).ok()??)?;
        let reply_packets = parse_counter(find_attribute(attributes, CTA_COUNTERS_REPLY).ok()??)?;
        let tcp_state = find_attribute(attributes, CTA_PROTOINFO)
            .ok()?
            .and_then(|protocol| find_attribute(protocol, CTA_PROTOINFO_TCP).ok()?)
            .and_then(|tcp| find_attribute(tcp, CTA_PROTOINFO_TCP_STATE).ok()?)
            .and_then(|state| state.first().copied());
        return Some(R2oConntrackInfo {
            original_packets,
            reply_packets,
            tcp_state,
        });
    }
    None
}

fn parse_counter(attributes: &[u8]) -> Option<u64> {
    if let Some(value) = find_attribute(attributes, CTA_COUNTERS_PACKETS).ok()? {
        if value.len() == 8 {
            return Some(u64::from_be_bytes(value.try_into().ok()?));
        }
    }
    find_attribute(attributes, CTA_COUNTERS32_PACKETS)
        .ok()?
        .and_then(|value| {
            if value.len() != 4 {
                return None;
            }
            let bytes: [u8; 4] = value.try_into().ok()?;
            Some(u64::from(u32::from_be_bytes(bytes)))
        })
}

fn find_attribute(attributes: &[u8], wanted: u16) -> Result<Option<&[u8]>, ()> {
    let mut offset = 0;
    while offset < attributes.len() {
        let header_end = offset.checked_add(NLA_HEADER_LEN).ok_or(())?;
        let header = attributes.get(offset..header_end).ok_or(())?;
        let length = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        if length < NLA_HEADER_LEN || length > attributes.len() - offset {
            return Err(());
        }
        let kind = u16::from_ne_bytes([header[2], header[3]]) & NLA_TYPE_MASK;
        if kind == wanted {
            return Ok(Some(&attributes[header_end..offset + length]));
        }
        let step = align4(length).ok_or(())?;
        if step > attributes.len() - offset {
            return Err(());
        }
        offset = offset.checked_add(step).ok_or(())?;
    }
    Ok(None)
}

fn align4(length: usize) -> Option<usize> {
    length.checked_add(3).map(|length| length & !3)
}

fn push_attribute(message: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = NLA_HEADER_LEN + value.len();
    message.extend_from_slice(&(length as u16).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(value);
    while message.len() % 4 != 0 {
        message.push(0);
    }
}

pub struct R2oConntrackClient {
    fd: RawFd,
    sequence: u32,
}

impl R2oConntrackClient {
    pub fn open() -> Option<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                NETLINK_NETFILTER,
            )
        };
        if fd < 0 {
            return None;
        }
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let bound = unsafe {
            libc::bind(
                fd,
                &address as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        } == 0;
        let mut client = Self { fd, sequence: 1 };
        if !bound || !client.probe() {
            return None;
        }
        Some(client)
    }

    pub fn query(&mut self, tuple: &R2oConntrackTuple) -> Option<R2oConntrackInfo> {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let sequence = self.sequence;
        let request = encode_get(sequence, tuple)?;
        self.send(&request).ok()?;
        self.receive_info(sequence)
    }

    fn probe(&mut self) -> bool {
        let tuple = R2oConntrackTuple {
            family: 4,
            protocol: 17,
            source: [0; 16],
            destination: [0; 16],
            source_port: 0,
            destination_port: 0,
        };
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let sequence = self.sequence;
        let Some(request) = encode_get(sequence, &tuple) else {
            return false;
        };
        if self.send(&request).is_err() {
            return false;
        }
        let mut poll = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 100) } <= 0 {
            return false;
        }
        let mut response = [0_u8; 4096];
        let read = unsafe {
            libc::recv(
                self.fd,
                response.as_mut_ptr() as *mut libc::c_void,
                response.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if read <= 0 {
            return false;
        }
        let response = &response[..read as usize];
        if decode_info(response, sequence).is_some() {
            return true;
        }
        MessageIter::new(response).any(|message| {
            message.sequence == sequence
                && message.kind == NLMSG_ERROR
                && message.body.len() >= 4
                && i32::from_ne_bytes(message.body[..4].try_into().expect("длина проверена"))
                    == -libc::ENOENT
        })
    }

    fn send(&self, request: &[u8]) -> io::Result<()> {
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                self.fd,
                request.as_ptr() as *const libc::c_void,
                request.len(),
                libc::MSG_DONTWAIT,
                &kernel as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != request.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "неполный запрос ctnetlink",
            ));
        }
        Ok(())
    }

    fn receive_info(&self, sequence: u32) -> Option<R2oConntrackInfo> {
        let mut response = [0_u8; 4096];
        for _ in 0..8 {
            let read = unsafe {
                libc::recv(
                    self.fd,
                    response.as_mut_ptr() as *mut libc::c_void,
                    response.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if read <= 0 {
                return None;
            }
            let response = &response[..read as usize];
            if MessageIter::new(response).any(|message| message.sequence == sequence) {
                return decode_info(response, sequence);
            }
        }
        None
    }
}

impl Drop for R2oConntrackClient {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

pub fn tuple_from_socket_addrs(
    client: SocketAddr,
    server: SocketAddr,
) -> Option<R2oConntrackTuple> {
    r2o_conntrack_tuple_from_socket_addrs(client, server, 6)
}

pub fn r2o_conntrack_tuple_from_socket_addrs(
    client: SocketAddr,
    server: SocketAddr,
    protocol: u8,
) -> Option<R2oConntrackTuple> {
    if !matches!(protocol, 6 | 17) {
        return None;
    }
    match (client, server) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            let mut source_bytes = [0; 16];
            source_bytes[..4].copy_from_slice(&source.ip().octets());
            let mut destination_bytes = [0; 16];
            destination_bytes[..4].copy_from_slice(&destination.ip().octets());
            Some(R2oConntrackTuple {
                family: 4,
                protocol,
                source: source_bytes,
                destination: destination_bytes,
                source_port: source.port(),
                destination_port: destination.port(),
            })
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => Some(R2oConntrackTuple {
            family: 6,
            protocol,
            source: source.ip().octets(),
            destination: destination.ip().octets(),
            source_port: source.port(),
            destination_port: destination.port(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CTA_COUNTERS_ORIG, CTA_COUNTERS_PACKETS, CTA_COUNTERS_REPLY, CTA_COUNTERS32_PACKETS,
        CTA_PROTO_DST_PORT, CTA_PROTO_SRC_PORT, CTA_TUPLE_IP, CTA_TUPLE_ORIG, CTA_TUPLE_PROTO,
        R2oConntrackInfo, R2oConntrackTuple, decode_info, encode_get, find_attribute,
        tuple_from_socket_addrs,
    };
    use crate::netlink::MessageIter;
    use std::net::SocketAddr;

    #[test]
    fn разбирает_счётчики_и_состояние_tcp_из_conntrack() {
        let message = ответ_conntrack(7, 22, 25, Some(3));
        assert_eq!(
            decode_info(&message, 7),
            Some(R2oConntrackInfo {
                original_packets: 22,
                reply_packets: 25,
                tcp_state: Some(3),
            })
        );
    }

    #[test]
    fn отклоняет_чужой_номер_и_усечённый_ответ() {
        let message = ответ_conntrack(7, 22, 25, Some(3));
        assert_eq!(decode_info(&message, 8), None);
        assert_eq!(decode_info(&message[..message.len() - 1], 7), None);
    }

    #[test]
    fn принимает_32_битные_счётчики_старого_ядра() {
        let message = ответ_conntrack32(7, 22, 25);
        assert_eq!(
            decode_info(&message, 7),
            Some(R2oConntrackInfo {
                original_packets: 22,
                reply_packets: 25,
                tcp_state: None,
            })
        );
    }

    #[test]
    fn строит_запрос_по_кортежу_ipv4() {
        let tuple = R2oConntrackTuple {
            family: 4,
            protocol: 6,
            source: [192, 0, 2, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            destination: [198, 51, 100, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            source_port: 50000,
            destination_port: 443,
        };
        let request = encode_get(9, &tuple).unwrap();
        let message = MessageIter::new(&request).next().unwrap();
        assert_eq!(message.kind, 0x0101);
        assert_eq!(message.flags, 1);
        assert_eq!(message.sequence, 9);
        assert_eq!(message.body[0], 2);
        let original = find_attribute(&message.body[4..], CTA_TUPLE_ORIG)
            .unwrap()
            .unwrap();
        let ip = find_attribute(original, CTA_TUPLE_IP).unwrap().unwrap();
        assert_eq!(find_attribute(ip, 1).unwrap().unwrap(), &[192, 0, 2, 10]);
        assert_eq!(find_attribute(ip, 2).unwrap().unwrap(), &[198, 51, 100, 20]);
        let protocol = find_attribute(original, CTA_TUPLE_PROTO).unwrap().unwrap();
        assert_eq!(
            find_attribute(protocol, CTA_PROTO_SRC_PORT)
                .unwrap()
                .unwrap(),
            &50000_u16.to_be_bytes()
        );
        assert_eq!(
            find_attribute(protocol, CTA_PROTO_DST_PORT)
                .unwrap()
                .unwrap(),
            &443_u16.to_be_bytes()
        );
        assert_eq!(CTA_COUNTERS32_PACKETS, 3);
    }

    #[test]
    fn собирает_сетевые_кортежи_одного_семейства() {
        let client: SocketAddr = "192.0.2.10:50000".parse().unwrap();
        let server: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let tuple = tuple_from_socket_addrs(client, server).unwrap();
        assert_eq!(tuple.family, 4);
        assert_eq!(&tuple.source[..4], &[192, 0, 2, 10]);
        assert_eq!(&tuple.destination[..4], &[198, 51, 100, 20]);
        assert_eq!(tuple.source_port, 50000);
        assert_eq!(tuple.destination_port, 443);
    }

    fn ответ_conntrack(
        sequence: u32,
        original: u64,
        reply: u64,
        tcp_state: Option<u8>,
    ) -> Vec<u8> {
        let mut body = vec![2, 0, 0, 0];
        let mut original_counter = Vec::new();
        атрибут(
            &mut original_counter,
            CTA_COUNTERS_PACKETS,
            &original.to_be_bytes(),
        );
        let mut reply_counter = Vec::new();
        атрибут(
            &mut reply_counter,
            CTA_COUNTERS_PACKETS,
            &reply.to_be_bytes(),
        );
        атрибут(&mut body, 9 | 0x8000, &original_counter);
        атрибут(&mut body, 10 | 0x8000, &reply_counter);
        if let Some(tcp_state) = tcp_state {
            let mut tcp = Vec::new();
            атрибут(&mut tcp, 1, &[tcp_state]);
            let mut protocol = Vec::new();
            атрибут(&mut protocol, 1 | 0x8000, &tcp);
            атрибут(&mut body, 4 | 0x8000, &protocol);
        }
        let mut message = vec![0; 16];
        message.extend_from_slice(&body);
        let message_len = message.len() as u32;
        message[..4].copy_from_slice(&message_len.to_ne_bytes());
        message[4..6].copy_from_slice(&0x0100_u16.to_ne_bytes());
        message[8..12].copy_from_slice(&sequence.to_ne_bytes());
        message
    }

    fn ответ_conntrack32(sequence: u32, original: u32, reply: u32) -> Vec<u8> {
        let mut body = vec![2, 0, 0, 0];
        let mut original_counter = Vec::new();
        атрибут(
            &mut original_counter,
            CTA_COUNTERS32_PACKETS,
            &original.to_be_bytes(),
        );
        let mut reply_counter = Vec::new();
        атрибут(
            &mut reply_counter,
            CTA_COUNTERS32_PACKETS,
            &reply.to_be_bytes(),
        );
        атрибут(&mut body, CTA_COUNTERS_ORIG | 0x8000, &original_counter);
        атрибут(&mut body, CTA_COUNTERS_REPLY | 0x8000, &reply_counter);
        let mut message = vec![0; 16];
        message.extend_from_slice(&body);
        let message_len = message.len() as u32;
        message[..4].copy_from_slice(&message_len.to_ne_bytes());
        message[4..6].copy_from_slice(&0x0100_u16.to_ne_bytes());
        message[8..12].copy_from_slice(&sequence.to_ne_bytes());
        message
    }

    fn атрибут(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
        let length = 4 + value.len();
        out.extend_from_slice(&(length as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
}
