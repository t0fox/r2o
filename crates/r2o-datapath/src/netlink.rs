//! Ограниченный побайтовый кодек сообщений Linux netlink и NFQUEUE.

use std::convert::TryInto;

pub const NETLINK_NETFILTER: i32 = 12;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NFNL_SUBSYS_QUEUE: u16 = 3;
pub const NFQNL_MSG_PACKET: u8 = 0;
pub const NFQNL_MSG_VERDICT: u8 = 1;
pub const NFQNL_MSG_CONFIG: u8 = 2;
pub const NFQA_PACKET_HDR: u16 = 1;
pub const NFQA_VERDICT_HDR: u16 = 2;
pub const NFQA_MARK: u16 = 3;
pub const NFQA_TIMESTAMP: u16 = 4;
pub const NFQA_IFINDEX_OUTDEV: u16 = 6;
pub const NFQA_PAYLOAD: u16 = 10;
pub const NFQA_CAP_LEN: u16 = 13;
pub const NFQA_SKB_INFO: u16 = 14;
pub const NFQA_CFG_CMD: u16 = 1;
pub const NFQA_CFG_PARAMS: u16 = 2;
pub const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
pub const NFQA_CFG_MASK: u16 = 4;
pub const NFQA_CFG_FLAGS: u16 = 5;
pub const NFQNL_CFG_CMD_BIND: u8 = 1;
pub const NFQNL_CFG_CMD_UNBIND: u8 = 2;
pub const NFQNL_COPY_PACKET: u8 = 2;
pub const NFQA_CFG_F_FAIL_OPEN: u32 = 1;
pub const NFQA_CFG_F_GSO: u32 = 1 << 2;
pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;

pub const R2O_NF_INET_PRE_ROUTING: u8 = 0;
pub const R2O_NF_INET_LOCAL_IN: u8 = 1;
pub const R2O_NF_INET_FORWARD: u8 = 2;
pub const R2O_NF_INET_LOCAL_OUT: u8 = 3;
pub const R2O_NF_INET_POST_ROUTING: u8 = 4;

const NLMSG_HEADER_LEN: usize = 16;
const NFGENMSG_LEN: usize = 4;
const NLA_HEADER_LEN: usize = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;
const NFQNL_V0: u8 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetlinkMessage<'a> {
    pub kind: u16,
    pub flags: u16,
    pub sequence: u32,
    pub pid: u32,
    pub body: &'a [u8],
}

/// Перебирать выровненные сообщения netlink. Некорректная длина завершает перебор.
pub struct MessageIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    stopped: bool,
}

impl<'a> MessageIter<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            stopped: false,
        }
    }
}

impl<'a> Iterator for MessageIter<'a> {
    type Item = NetlinkMessage<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stopped {
            return None;
        }
        let remaining = self.bytes.len().checked_sub(self.offset)?;
        if remaining < NLMSG_HEADER_LEN {
            self.stopped = true;
            return None;
        }
        let header = self
            .bytes
            .get(self.offset..self.offset + NLMSG_HEADER_LEN)?;
        let message_len = usize::try_from(u32::from_ne_bytes(header[..4].try_into().ok()?)).ok()?;
        if !(NLMSG_HEADER_LEN..=remaining).contains(&message_len) {
            self.stopped = true;
            return None;
        }
        let step = align4(message_len)?;
        let message = NetlinkMessage {
            kind: u16::from_ne_bytes(header[4..6].try_into().ok()?),
            flags: u16::from_ne_bytes(header[6..8].try_into().ok()?),
            sequence: u32::from_ne_bytes(header[8..12].try_into().ok()?),
            pid: u32::from_ne_bytes(header[12..16].try_into().ok()?),
            body: &self.bytes[self.offset + NLMSG_HEADER_LEN..self.offset + message_len],
        };
        self.offset = if step >= remaining {
            self.bytes.len()
        } else {
            self.offset + step
        };
        Some(message)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueuePacket<'a> {
    pub id: Option<u32>,
    pub hardware_protocol: Option<u16>,
    pub hook: Option<u8>,
    pub mark: Option<u32>,
    pub cap_len: Option<u32>,
    pub skb_info: Option<u32>,
    pub payload: Option<&'a [u8]>,
    pub output_device: Option<u32>,
    pub timestamp_ns: Option<u64>,
    pub truncated: bool,
}

impl<'a> QueuePacket<'a> {
    pub fn parse(message: &NetlinkMessage<'a>) -> Option<Self> {
        if message.body.len() < NFGENMSG_LEN {
            return None;
        }
        let mut packet = Self::default();
        let mut offset = align4(NFGENMSG_LEN)?;
        while offset.checked_add(NLA_HEADER_LEN)? <= message.body.len() {
            let header = &message.body[offset..offset + NLA_HEADER_LEN];
            let attr_len = usize::from(u16::from_ne_bytes(header[..2].try_into().ok()?));
            let attr_type = u16::from_ne_bytes(header[2..4].try_into().ok()?) & NLA_TYPE_MASK;
            if attr_len < NLA_HEADER_LEN || attr_len > message.body.len() - offset {
                break;
            }
            let value = &message.body[offset + NLA_HEADER_LEN..offset + attr_len];
            match attr_type {
                NFQA_PACKET_HDR if value.len() >= 7 => {
                    packet.id = Some(u32::from_be_bytes(value[..4].try_into().ok()?));
                    packet.hardware_protocol =
                        Some(u16::from_be_bytes(value[4..6].try_into().ok()?));
                    packet.hook = Some(value[6]);
                }
                NFQA_PAYLOAD => packet.payload = Some(value),
                NFQA_CAP_LEN if value.len() >= 4 => {
                    packet.cap_len = Some(u32::from_be_bytes(value[..4].try_into().ok()?));
                }
                NFQA_SKB_INFO if value.len() >= 4 => {
                    packet.skb_info = Some(u32::from_be_bytes(value[..4].try_into().ok()?));
                }
                NFQA_MARK if value.len() >= 4 => {
                    packet.mark = Some(u32::from_be_bytes(value[..4].try_into().ok()?));
                }
                NFQA_TIMESTAMP if value.len() >= 16 => {
                    let sec = u64::from_be_bytes(value[..8].try_into().ok()?);
                    let usec = u64::from_be_bytes(value[8..16].try_into().ok()?);
                    if sec != 0 && usec < 1_000_000 && sec < 18_000_000_000 {
                        packet.timestamp_ns =
                            Some(sec.checked_mul(1_000_000_000)?.checked_add(usec * 1_000)?);
                    }
                }
                NFQA_IFINDEX_OUTDEV if value.len() >= 4 => {
                    packet.output_device = Some(u32::from_be_bytes(value[..4].try_into().ok()?));
                }
                _ => {}
            }
            let step = align4(attr_len)?;
            if step > message.body.len() - offset {
                break;
            }
            offset += step;
        }
        packet.truncated = packet
            .cap_len
            .zip(packet.payload)
            .is_some_and(|(cap_len, payload)| cap_len as usize > payload.len());
        Some(packet)
    }
}

pub fn kernel_error(message: &NetlinkMessage<'_>) -> Option<i32> {
    (message.kind == NLMSG_ERROR && message.body.len() >= 4)
        .then(|| i32::from_ne_bytes(message.body[..4].try_into().expect("length checked")))
}

pub fn verdict(queue: u16, sequence: u32, packet_id: u32, action: u32) -> Vec<u8> {
    let mut message = header(
        queue,
        message_type(NFQNL_MSG_VERDICT),
        NLM_F_REQUEST,
        sequence,
    );
    let mut value = [0; 8];
    value[..4].copy_from_slice(&action.to_be_bytes());
    value[4..].copy_from_slice(&packet_id.to_be_bytes());
    push_attr(&mut message, NFQA_VERDICT_HDR, &value);
    finish(&mut message);
    message
}

pub fn verdict_payload(
    queue: u16,
    sequence: u32,
    packet_id: u32,
    action: u32,
    replacement: &[u8],
) -> Option<Vec<u8>> {
    if replacement.is_empty() || replacement.len() > u16::MAX as usize - NLA_HEADER_LEN {
        return None;
    }
    let mut message = verdict(queue, sequence, packet_id, action);
    push_attr(&mut message, NFQA_PAYLOAD, replacement);
    finish(&mut message);
    Some(message)
}

pub fn config_command(queue: u16, sequence: u32, command: u8, protocol_family: u16) -> Vec<u8> {
    let mut message = header(
        queue,
        message_type(NFQNL_MSG_CONFIG),
        NLM_F_REQUEST | NLM_F_ACK,
        sequence,
    );
    let mut value = [0; 4];
    value[0] = command;
    value[2..].copy_from_slice(&protocol_family.to_be_bytes());
    push_attr(&mut message, NFQA_CFG_CMD, &value);
    finish(&mut message);
    message
}

pub fn config_params(
    queue: u16,
    sequence: u32,
    copy_range: u32,
    max_len: u32,
    fail_open: bool,
) -> Vec<u8> {
    let mut message = header(
        queue,
        message_type(NFQNL_MSG_CONFIG),
        NLM_F_REQUEST | NLM_F_ACK,
        sequence,
    );
    let mut params = [0; 5];
    params[..4].copy_from_slice(&copy_range.to_be_bytes());
    params[4] = NFQNL_COPY_PACKET;
    push_attr(&mut message, NFQA_CFG_PARAMS, &params);
    push_attr(&mut message, NFQA_CFG_QUEUE_MAXLEN, &max_len.to_be_bytes());
    let flags = if fail_open { NFQA_CFG_F_FAIL_OPEN } else { 0 };
    push_attr(&mut message, NFQA_CFG_FLAGS, &flags.to_be_bytes());
    push_attr(
        &mut message,
        NFQA_CFG_MASK,
        &(NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO).to_be_bytes(),
    );
    finish(&mut message);
    message
}

fn header(queue: u16, kind: u16, flags: u16, sequence: u32) -> Vec<u8> {
    let mut message = vec![0; NLMSG_HEADER_LEN + NFGENMSG_LEN];
    message[4..6].copy_from_slice(&kind.to_ne_bytes());
    message[6..8].copy_from_slice(&flags.to_ne_bytes());
    message[8..12].copy_from_slice(&sequence.to_ne_bytes());
    message[16] = 0;
    message[17] = NFQNL_V0;
    message[18..20].copy_from_slice(&queue.to_be_bytes());
    message
}

fn push_attr(message: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    let attr_len = NLA_HEADER_LEN + value.len();
    message.extend_from_slice(&(attr_len as u16).to_ne_bytes());
    message.extend_from_slice(&attr_type.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(align4(message.len()).expect("message length fits usize"), 0);
}

fn finish(message: &mut [u8]) {
    let len = message.len() as u32;
    message[..4].copy_from_slice(&len.to_ne_bytes());
}

const fn message_type(operation: u8) -> u16 {
    (NFNL_SUBSYS_QUEUE << 8) | operation as u16
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn little_endian() -> bool {
        u16::from_ne_bytes([1, 0]) == 1
    }

    #[test]
    fn verdict_bytes_match_the_nfqueue_wire_contract() {
        let bytes = verdict(1, 7, 0x1122_3344, NF_ACCEPT);
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[18..20], &[0, 1]);
        assert_eq!(&bytes[24..28], &[0, 0, 0, 1]);
        assert_eq!(&bytes[28..32], &[0x11, 0x22, 0x33, 0x44]);
        if little_endian() {
            assert_eq!(
                bytes,
                [
                    0x20, 0, 0, 0, 1, 3, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 12, 0, 2, 0, 0,
                    0, 0, 1, 0x11, 0x22, 0x33, 0x44
                ]
            );
        }
    }

    #[test]
    fn replacement_verdict_carries_payload_and_zero_padding() {
        let bytes = verdict_payload(1, 7, 0x1122_3344, NF_ACCEPT, &[0x45, 1, 2, 3, 4]).unwrap();
        assert_eq!(bytes.len(), 44);
        assert_eq!(&bytes[32..36], &[9, 0, NFQA_PAYLOAD as u8, 0]);
        assert_eq!(&bytes[36..41], &[0x45, 1, 2, 3, 4]);
        assert_eq!(&bytes[41..44], &[0; 3]);
        assert!(verdict_payload(1, 7, 1, NF_ACCEPT, &[]).is_none());
    }

    #[test]
    fn configuration_matches_the_c_reference_fields() {
        let command = config_command(1, 3, NFQNL_CFG_CMD_BIND, 2);
        assert_eq!(command.len(), 28);
        assert_eq!(&command[18..20], &[0, 1]);
        assert_eq!(&command[20..24], &[8, 0, NFQA_CFG_CMD as u8, 0]);
        assert_eq!(&command[24..28], &[NFQNL_CFG_CMD_BIND, 0, 0, 2]);

        let params = config_params(1, 4, 0xffff, 1024, true);
        assert_eq!(params.len(), 56);
        assert_eq!(&params[20..24], &[9, 0, NFQA_CFG_PARAMS as u8, 0]);
        assert_eq!(&params[24..28], &[0, 0, 0xff, 0xff]);
        assert_eq!(params[28], NFQNL_COPY_PACKET);
        assert_eq!(&params[29..32], &[0; 3]);
        assert_eq!(&params[40..44], &[8, 0, NFQA_CFG_FLAGS as u8, 0]);
        assert_eq!(&params[44..48], &[0, 0, 0, NFQA_CFG_F_FAIL_OPEN as u8]);
        assert_eq!(&params[48..52], &[8, 0, NFQA_CFG_MASK as u8, 0]);
        assert_eq!(
            &params[52..56],
            &[0, 0, 0, (NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO) as u8]
        );
    }

    #[test]
    fn iterator_accepts_unpadded_last_message_and_stops_on_bad_lengths() {
        let message = verdict(1, 7, 42, NF_ACCEPT);
        let parsed = MessageIter::new(&message).next().unwrap();
        assert_eq!(
            parsed.kind,
            (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT as u16
        );
        assert_eq!(parsed.sequence, 7);
        assert!(MessageIter::new(&message[..15]).next().is_none());

        let mut malformed = message;
        malformed[..4].copy_from_slice(&15_u32.to_ne_bytes());
        assert!(MessageIter::new(&malformed).next().is_none());
    }

    #[test]
    fn parser_reads_packet_metadata_payload_and_missing_final_padding() {
        let mut body = vec![0, 0, 0, 1]; // nfgenmsg, queue=1
        let mut packet_header = [0; 7];
        packet_header[..4].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
        packet_header[4..6].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet_header[6] = 3;
        add_test_attr(&mut body, NFQA_PACKET_HDR, &packet_header, true);
        add_test_attr(&mut body, NFQA_MARK, &0x1234_u32.to_be_bytes(), true);
        add_test_attr(&mut body, NFQA_IFINDEX_OUTDEV, &7_u32.to_be_bytes(), true);
        let mut timestamp = [0; 16];
        timestamp[4..8].copy_from_slice(&1_700_000_000_u32.to_be_bytes());
        timestamp[12..16].copy_from_slice(&123_456_u32.to_be_bytes());
        add_test_attr(&mut body, NFQA_TIMESTAMP, &timestamp, true);
        add_test_attr(&mut body, NFQA_PAYLOAD, &[0xa5; 91], false);
        let message = NetlinkMessage {
            kind: (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET as u16,
            flags: 0,
            sequence: 0,
            pid: 0,
            body: &body,
        };
        let parsed = QueuePacket::parse(&message).unwrap();
        assert_eq!(parsed.id, Some(0xdead_beef));
        assert_eq!(parsed.hardware_protocol, Some(0x0800));
        assert_eq!(parsed.hook, Some(3));
        assert_eq!(parsed.mark, Some(0x1234));
        assert_eq!(parsed.output_device, Some(7));
        assert_eq!(parsed.timestamp_ns, Some(1_700_000_000_123_456_000));
        assert_eq!(parsed.payload, Some(&[0xa5; 91][..]));
    }

    #[test]
    fn parser_marks_copy_range_truncation_and_rejects_short_nfgenmsg() {
        let message = NetlinkMessage {
            kind: 0,
            flags: 0,
            sequence: 0,
            pid: 0,
            body: &[0, 0, 0, 0],
        };
        assert_eq!(QueuePacket::parse(&message), Some(QueuePacket::default()));

        let mut body = vec![0, 0, 0, 0];
        add_test_attr(&mut body, NFQA_CAP_LEN, &1400_u32.to_be_bytes(), true);
        add_test_attr(&mut body, NFQA_PAYLOAD, &[0; 64], true);
        let message = NetlinkMessage {
            body: &body,
            ..message
        };
        assert!(QueuePacket::parse(&message).unwrap().truncated);
        let message = NetlinkMessage {
            body: &[0; 3],
            ..message
        };
        assert_eq!(QueuePacket::parse(&message), None);
    }

    #[test]
    fn kernel_error_reads_native_signed_errno() {
        let body = (-22_i32).to_ne_bytes();
        let message = NetlinkMessage {
            kind: NLMSG_ERROR,
            flags: 0,
            sequence: 4,
            pid: 0,
            body: &body,
        };
        assert_eq!(kernel_error(&message), Some(-22));
    }

    fn add_test_attr(body: &mut Vec<u8>, kind: u16, value: &[u8], padded: bool) {
        body.extend_from_slice(&((NLA_HEADER_LEN + value.len()) as u16).to_ne_bytes());
        body.extend_from_slice(&kind.to_ne_bytes());
        body.extend_from_slice(value);
        if padded {
            body.resize(align4(body.len()).unwrap(), 0);
        }
    }
}
