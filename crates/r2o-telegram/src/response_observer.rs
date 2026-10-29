//! Проверка первого ответа Telegram в прямом WSS-потоке.

use crate::crypto::{AesCtr256, ProtoTag, direct_server_stream_cipher};
use cipher::StreamCipher;

const MAX_PACKET: usize = 4 * 1024 * 1024;
const OBSERVER_CHUNK: usize = 16 * 1024;

pub(crate) struct MtprotoResponseObserver {
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

impl MtprotoResponseObserver {
    pub(crate) fn new(init: &[u8; crate::crypto::HANDSHAKE_LEN], proto: ProtoTag) -> Self {
        Self {
            cipher: direct_server_stream_cipher(init),
            proto,
            header: [0; 4],
            header_len: 0,
            header_needed: if matches!(proto, ProtoTag::Abridged) {
                0
            } else {
                4
            },
            header_ack: false,
            packet_len: 0,
            packet_seen: 0,
            prefix: [0; 40],
            prefix_len: 0,
            packet_padded: false,
        }
    }

    /// Возвращает true, когда поток содержит хотя бы один полный валидный ответ.
    /// Повреждённый поток отключает наблюдение, но не влияет на его передачу.
    pub(crate) fn observe(&mut self, payload: &[u8]) -> Result<bool, ()> {
        let mut offset = 0;
        let mut response_seen = false;
        while offset < payload.len() {
            if self.packet_len == 0 {
                if self.header_needed == 0 {
                    let byte = self.decrypt_byte(payload[offset]);
                    offset += 1;
                    self.header[0] = byte;
                    self.header_len = 1;
                    self.header_ack = false;
                    if matches!(self.proto, ProtoTag::Abridged) && byte & 0x80 != 0 {
                        self.header_ack = true;
                        self.header_needed = 4;
                    } else {
                        self.header_needed =
                            if matches!(self.proto, ProtoTag::Abridged) && byte == 0x7f {
                                4
                            } else {
                                1
                            };
                    }
                }
                while self.header_len < self.header_needed && offset < payload.len() {
                    self.header[self.header_len] = self.decrypt_byte(payload[offset]);
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
                let packet_len = match self.proto {
                    ProtoTag::Abridged => {
                        let words = if self.header_needed == 1 {
                            u32::from(self.header[0])
                        } else {
                            u32::from(self.header[1])
                                | (u32::from(self.header[2]) << 8)
                                | (u32::from(self.header[3]) << 16)
                        };
                        if words == 0 || words > (MAX_PACKET / 4) as u32 {
                            return Err(());
                        }
                        words as usize * 4
                    }
                    ProtoTag::Intermediate | ProtoTag::PaddedIntermediate => {
                        let raw_len = u32::from_le_bytes(self.header);
                        if matches!(self.proto, ProtoTag::Intermediate)
                            && raw_len & 0x8000_0000 != 0
                        {
                            self.header_len = 0;
                            self.header_needed = 4;
                            continue;
                        }
                        self.packet_padded = matches!(self.proto, ProtoTag::PaddedIntermediate);
                        let packet_len = (raw_len & 0x7fff_ffff) as usize;
                        if !(8..=MAX_PACKET).contains(&packet_len) {
                            return Err(());
                        }
                        packet_len
                    }
                };
                self.packet_len = packet_len;
                self.packet_seen = 0;
                self.prefix_len = 0;
            }

            let remaining = self.packet_len - self.packet_seen;
            let amount = (payload.len() - offset).min(OBSERVER_CHUNK).min(remaining);
            let mut decoded = [0_u8; OBSERVER_CHUNK];
            decoded[..amount].copy_from_slice(&payload[offset..offset + amount]);
            self.cipher.apply_keystream(&mut decoded[..amount]);
            let prefix_space = self.prefix.len() - self.prefix_len;
            let prefix_copy = amount.min(prefix_space);
            self.prefix[self.prefix_len..self.prefix_len + prefix_copy]
                .copy_from_slice(&decoded[..prefix_copy]);
            self.prefix_len += prefix_copy;
            self.packet_seen += amount;
            offset += amount;

            if self.packet_seen == self.packet_len {
                let packet_status = self.packet_valid();
                if packet_status <= 0 {
                    return Err(());
                }
                if packet_status == 1 {
                    response_seen = true;
                }
                self.packet_len = 0;
                self.packet_seen = 0;
                self.prefix_len = 0;
                self.header_len = 0;
                self.header_needed = if matches!(self.proto, ProtoTag::Abridged) {
                    0
                } else {
                    4
                };
                self.header_ack = false;
            }
        }
        Ok(response_seen)
    }

    fn decrypt_byte(&mut self, mut byte: u8) -> u8 {
        self.cipher.apply_keystream(std::slice::from_mut(&mut byte));
        byte
    }

    fn packet_valid(&self) -> i32 {
        if self.packet_padded
            && (8..=16).contains(&self.packet_len)
            && self.prefix_len >= 8
            && u32::from_le_bytes(self.prefix[..4].try_into().unwrap()) == u32::MAX
        {
            return 2;
        }
        if self.prefix_len < 20 {
            return 0;
        }
        if u64::from_le_bytes(self.prefix[..8].try_into().unwrap()) == 0 {
            if self.packet_len < 24 {
                return 0;
            }
            let message_id = u64::from_le_bytes(self.prefix[8..16].try_into().unwrap());
            let message_len = u32::from_le_bytes(self.prefix[16..20].try_into().unwrap());
            if message_id == 0
                || message_id >> 63 != 0
                || message_id & 3 != 1
                || message_len < 4
                || message_len as usize > self.packet_len - 20
            {
                return 0;
            }
            let padding = self.packet_len - 20 - message_len as usize;
            return if self.packet_padded {
                i32::from(padding <= 15)
            } else {
                i32::from(padding == 0)
            };
        }
        if self.prefix_len < 40 || self.packet_len < 40 {
            return 0;
        }
        let encrypted_len = self.packet_len - 24;
        i32::from(self.packet_padded || encrypted_len & 15 == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::MtprotoResponseObserver;
    use crate::crypto::{AesCtr256, HANDSHAKE_LEN, ProtoTag, make_cipher};
    use cipher::StreamCipher;

    const INIT: [u8; HANDSHAKE_LEN] = [
        0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 0x87, 0xae, 0xb3, 0xfe, 5, 0x9b, 0x48, 7,
    ];

    fn server_cipher(init: &[u8; HANDSHAKE_LEN]) -> AesCtr256 {
        let mut reversed = [0_u8; 48];
        for (to, from) in reversed.iter_mut().zip(init[8..56].iter().rev()) {
            *to = *from;
        }
        make_cipher(&reversed[..32], &reversed[32..])
    }

    fn parse_proto(value: &str) -> ProtoTag {
        match value {
            "1" => ProtoTag::Abridged,
            "2" => ProtoTag::Intermediate,
            "3" => ProtoTag::PaddedIntermediate,
            _ => panic!("unknown proto {value}"),
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        hex::decode(value).unwrap()
    }

    fn shared_vectors() -> String {
        include_str!("../tests/fixtures/d2o_mtproto_response_observer.tsv").to_string()
    }

    fn run_vector(line: &str) -> (String, String, String) {
        let mut fields = line.split('\t');
        let name = fields.next().unwrap().to_string();
        let proto = fields.next().unwrap().to_string();
        let chunks = fields.next().unwrap().to_string();
        let expected = fields.next().unwrap().to_string();
        assert!(fields.next().is_none());

        let mut encrypt = server_cipher(&INIT);
        let mut observer = MtprotoResponseObserver::new(&INIT, parse_proto(&proto));
        let mut statuses = Vec::new();
        for chunk in chunks.split(';') {
            let mut bytes = decode_hex(chunk);
            encrypt.apply_keystream(&mut bytes);
            let status = match observer.observe(&bytes) {
                Ok(true) => 1,
                Ok(false) => 0,
                Err(()) => -1,
            };
            statuses.push(status.to_string());
        }
        (name, statuses.join(","), expected)
    }

    #[test]
    fn observer_matches_d2o_mtproto_response_vectors() {
        let mut output = Vec::new();
        for line in shared_vectors().lines().filter(|line| !line.is_empty()) {
            let (name, actual, expected) = run_vector(line);
            assert_eq!(actual, expected, "vector {name}");
            output.push(format!("{name}\t{actual}"));
        }
        if let Ok(path) = std::env::var("R2O_TELEGRAM_RESPONSE_DIFF_OUTPUT") {
            std::fs::write(path, output.join("\n") + "\n").unwrap();
        }
    }
}
