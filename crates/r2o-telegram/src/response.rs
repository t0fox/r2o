//! Проверка первого ответа Telegram по тем же правилам, что и d2o.

use crate::crypto::{AesCtr256, HANDSHAKE_LEN, ProtoTag, direct_server_stream_cipher};
use cipher::StreamCipher;

const MAX_PACKET_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseObservation {
    Pending,
    Confirmed,
    Invalid,
}

pub(crate) struct ResponseObserver {
    cipher: AesCtr256,
    proto: ProtoTag,
    header: [u8; 4],
    header_len: usize,
    header_needed: usize,
    header_ack: bool,
    packet_len: usize,
    packet_seen: usize,
    prefix: [u8; 40],
    prefix_len: usize,
    packet_padded: bool,
}

impl ResponseObserver {
    pub(crate) fn new(init: &[u8; HANDSHAKE_LEN], proto: ProtoTag) -> Self {
        Self {
            cipher: direct_server_stream_cipher(init),
            proto,
            header: [0; 4],
            header_len: 0,
            header_needed: if proto == ProtoTag::Abridged { 0 } else { 4 },
            header_ack: false,
            packet_len: 0,
            packet_seen: 0,
            prefix: [0; 40],
            prefix_len: 0,
            packet_padded: false,
        }
    }

    pub(crate) fn observe(&mut self, encrypted: &[u8]) -> ResponseObservation {
        let mut response_seen = false;
        let mut decoded = [0u8; 16 * 1024];
        for chunk in encrypted.chunks(decoded.len()) {
            decoded[..chunk.len()].copy_from_slice(chunk);
            self.cipher.apply_keystream(&mut decoded[..chunk.len()]);
            match self.consume(&decoded[..chunk.len()]) {
                Ok(found) => response_seen |= found,
                Err(()) => return ResponseObservation::Invalid,
            }
        }
        if response_seen {
            ResponseObservation::Confirmed
        } else {
            ResponseObservation::Pending
        }
    }

    fn consume(&mut self, plaintext: &[u8]) -> Result<bool, ()> {
        let mut offset = 0;
        let mut response_seen = false;
        while offset < plaintext.len() {
            if self.packet_len == 0 {
                if self.header_needed == 0 {
                    let byte = plaintext[offset];
                    offset += 1;
                    self.header[0] = byte;
                    self.header_len = 1;
                    self.header_ack = false;
                    if self.proto == ProtoTag::Abridged && byte & 0x80 != 0 {
                        self.header_ack = true;
                        self.header_needed = 4;
                    } else {
                        self.header_needed = if self.proto == ProtoTag::Abridged && byte == 0x7f {
                            4
                        } else {
                            1
                        };
                    }
                }
                while self.header_len < self.header_needed && offset < plaintext.len() {
                    self.header[self.header_len] = plaintext[offset];
                    self.header_len += 1;
                    offset += 1;
                }
                if self.header_len < self.header_needed {
                    break;
                }
                if self.header_ack {
                    self.header_len = 0;
                    self.header_needed = 0;
                    self.header_ack = false;
                    continue;
                }

                self.packet_padded = false;
                if self.proto == ProtoTag::Abridged {
                    let words = if self.header_needed == 1 {
                        u32::from(self.header[0])
                    } else {
                        u32::from(self.header[1])
                            | (u32::from(self.header[2]) << 8)
                            | (u32::from(self.header[3]) << 16)
                    };
                    if words == 0 || words as usize > MAX_PACKET_BYTES / 4 {
                        return Err(());
                    }
                    self.packet_len = words as usize * 4;
                } else {
                    let raw_len = u32::from_le_bytes(self.header);
                    if self.proto == ProtoTag::Intermediate && raw_len & 0x8000_0000 != 0 {
                        self.header_len = 0;
                        self.header_needed = 4;
                        continue;
                    }
                    self.packet_padded = self.proto == ProtoTag::PaddedIntermediate;
                    self.packet_len = (raw_len & 0x7fff_ffff) as usize;
                    if !(8..=MAX_PACKET_BYTES).contains(&self.packet_len) {
                        return Err(());
                    }
                }
                self.packet_seen = 0;
                self.prefix_len = 0;
            }

            let remaining = self.packet_len - self.packet_seen;
            let amount = (plaintext.len() - offset).min(remaining);
            let prefix_space = self.prefix.len() - self.prefix_len;
            let prefix_copy = amount.min(prefix_space);
            if prefix_copy > 0 {
                self.prefix[self.prefix_len..self.prefix_len + prefix_copy]
                    .copy_from_slice(&plaintext[offset..offset + prefix_copy]);
                self.prefix_len += prefix_copy;
            }
            self.packet_seen += amount;
            offset += amount;

            if self.packet_seen == self.packet_len {
                match self.packet_valid() {
                    0 => return Err(()),
                    1 => response_seen = true,
                    2 => {}
                    _ => unreachable!("C response validator only returns 0, 1 or 2"),
                }
                self.packet_len = 0;
                self.packet_seen = 0;
                self.prefix_len = 0;
                self.header_len = 0;
                self.header_needed = if self.proto == ProtoTag::Abridged {
                    0
                } else {
                    4
                };
                self.header_ack = false;
            }
        }
        Ok(response_seen)
    }

    /// Mirrors d2o's response_packet_valid: 0 invalid, 1 response, 2 quick ACK.
    fn packet_valid(&self) -> u8 {
        if self.packet_padded
            && (8..=16).contains(&self.packet_len)
            && self.prefix_len >= 8
            && u32::from_le_bytes(self.prefix[..4].try_into().expect("four-byte prefix"))
                == u32::MAX
        {
            return 2;
        }
        if self.prefix_len < 20 {
            return 0;
        }
        if u64::from_le_bytes(self.prefix[..8].try_into().expect("eight-byte prefix")) == 0 {
            if self.prefix_len < 20 || self.packet_len < 24 {
                return 0;
            }
            let message_id = u64::from_le_bytes(self.prefix[8..16].try_into().expect("message id"));
            let message_len =
                u32::from_le_bytes(self.prefix[16..20].try_into().expect("message length"));
            if message_id == 0
                || message_id >> 63 != 0
                || message_id & 3 != 1
                || message_len < 4
                || message_len as usize > self.packet_len - 20
            {
                return 0;
            }
            let padding = self.packet_len - 20 - message_len as usize;
            if (self.packet_padded && padding <= 15) || (!self.packet_padded && padding == 0) {
                return 1;
            }
            return 0;
        }
        if self.prefix_len < 40 || self.packet_len < 40 {
            return 0;
        }
        let encrypted_len = self.packet_len - 24;
        if self.packet_padded || encrypted_len & 15 == 0 {
            1
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ResponseObservation, ResponseObserver};
    use crate::crypto::{HANDSHAKE_LEN, ProtoTag, direct_server_stream_cipher};
    use cipher::StreamCipher;

    const D2O_TEST_HANDSHAKE: [u8; HANDSHAKE_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x87, 0xae, 0xb3, 0xfe,
        0x05, 0x9b, 0x48, 0x07,
    ];

    fn encrypted(clear: &[u8]) -> ([u8; HANDSHAKE_LEN], Vec<u8>) {
        let init = D2O_TEST_HANDSHAKE;
        let mut bytes = clear.to_vec();
        direct_server_stream_cipher(&init).apply_keystream(&mut bytes);
        (init, bytes)
    }

    fn valid_intermediate_response() -> Vec<u8> {
        let mut frame = Vec::with_capacity(28);
        frame.extend_from_slice(&24u32.to_le_bytes());
        frame.extend_from_slice(&[0; 8]); // auth_key_id = 0
        frame.extend_from_slice(&1u64.to_le_bytes()); // server msg_id: low bits = 1
        frame.extend_from_slice(&4u32.to_le_bytes()); // message length
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        frame
    }

    fn d2o_wss_response_fixture(proto: ProtoTag) -> Vec<u8> {
        let mut clear = Vec::new();
        match proto {
            ProtoTag::Abridged => clear.extend_from_slice(&[0x80, 0, 0, 0]),
            ProtoTag::Intermediate => clear.extend_from_slice(&[0, 0, 0, 0x80]),
            ProtoTag::PaddedIntermediate => {
                clear.extend_from_slice(&[8, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4]);
            }
        }
        match proto {
            ProtoTag::Abridged => clear.push(10),
            ProtoTag::Intermediate => clear.extend_from_slice(&40u32.to_le_bytes()),
            ProtoTag::PaddedIntermediate => clear.extend_from_slice(&41u32.to_le_bytes()),
        }
        clear.extend(1..=8);
        clear.extend(0x20..=0x2f);
        clear.extend(0x40..=0x4f);
        if proto == ProtoTag::PaddedIntermediate {
            clear.push(0xa5);
        }
        clear
    }

    #[test]
    fn arbitrary_nonempty_binary_frame_does_not_confirm_response() {
        let (init, bytes) = encrypted(&[0, 0, 0, 0]);
        assert_eq!(bytes, [0x5c, 0xd3, 0x5e, 0x47]); // C tg_mtproto_direct_server_stream_cipher vector
        let mut observer = ResponseObserver::new(&init, ProtoTag::Intermediate);
        assert_eq!(observer.observe(&bytes), ResponseObservation::Invalid);
    }

    #[test]
    fn complete_valid_packet_confirms_across_websocket_frames() {
        let (init, bytes) = encrypted(&valid_intermediate_response());
        let mut observer = ResponseObserver::new(&init, ProtoTag::Intermediate);
        assert_eq!(observer.observe(&bytes[..2]), ResponseObservation::Pending);
        assert_eq!(
            observer.observe(&bytes[2..11]),
            ResponseObservation::Pending
        );
        assert_eq!(
            observer.observe(&bytes[11..]),
            ResponseObservation::Confirmed
        );
    }

    #[test]
    fn intermediate_transport_ack_does_not_confirm_response() {
        let mut clear = 0x8000_0000u32.to_le_bytes().to_vec();
        clear.extend_from_slice(&valid_intermediate_response());
        let (init, bytes) = encrypted(&clear);
        let mut observer = ResponseObserver::new(&init, ProtoTag::Intermediate);
        assert_eq!(observer.observe(&bytes[..4]), ResponseObservation::Pending);
        assert_eq!(
            observer.observe(&bytes[4..]),
            ResponseObservation::Confirmed
        );
    }

    #[test]
    fn abridged_transport_ack_does_not_confirm_response() {
        let (init, bytes) = encrypted(&d2o_wss_response_fixture(ProtoTag::Abridged));
        let mut observer = ResponseObserver::new(&init, ProtoTag::Abridged);
        assert_eq!(observer.observe(&bytes), ResponseObservation::Confirmed);
    }

    #[test]
    fn d2o_wss_response_fixtures_confirm_for_all_transport_tags() {
        for proto in [
            ProtoTag::Abridged,
            ProtoTag::Intermediate,
            ProtoTag::PaddedIntermediate,
        ] {
            let (init, bytes) = encrypted(&d2o_wss_response_fixture(proto));
            let mut observer = ResponseObserver::new(&init, proto);
            assert_eq!(
                observer.observe(&bytes),
                ResponseObservation::Confirmed,
                "transport fixture {proto:?}"
            );
        }
    }
}
