//! Построение DNS A-запросов и ограниченная проверка ответов.

use std::net::Ipv4Addr;

const MAX_ANSWERS: usize = 32;
const MAX_ADDRESSES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DnsProvider {
    WebShift,
    AstraCat,
    Mafioznik,
}

impl DnsProvider {
    pub const fn name(self) -> &'static str {
        match self {
            Self::WebShift => "WebShift",
            Self::AstraCat => "AstraCat",
            Self::Mafioznik => "Mafioznik",
        }
    }

    pub const fn hostname(self) -> &'static str {
        match self {
            Self::WebShift => "dns.webshiftvpn.ru",
            Self::AstraCat => "dns.astracat.ru",
            Self::Mafioznik => "dns.mafioznik.xyz",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsResolver {
    pub provider: DnsProvider,
    pub address: Ipv4Addr,
}

pub const DNS_RESOLVERS: [DnsResolver; 9] = [
    DnsResolver {
        provider: DnsProvider::WebShift,
        address: Ipv4Addr::new(79, 174, 90, 44),
    },
    DnsResolver {
        provider: DnsProvider::WebShift,
        address: Ipv4Addr::new(31, 31, 207, 68),
    },
    DnsResolver {
        provider: DnsProvider::AstraCat,
        address: Ipv4Addr::new(176, 125, 254, 77),
    },
    DnsResolver {
        provider: DnsProvider::AstraCat,
        address: Ipv4Addr::new(108, 165, 164, 224),
    },
    DnsResolver {
        provider: DnsProvider::AstraCat,
        address: Ipv4Addr::new(108, 165, 164, 201),
    },
    DnsResolver {
        provider: DnsProvider::AstraCat,
        address: Ipv4Addr::new(135, 106, 217, 200),
    },
    DnsResolver {
        provider: DnsProvider::AstraCat,
        address: Ipv4Addr::new(87, 120, 165, 90),
    },
    DnsResolver {
        provider: DnsProvider::AstraCat,
        address: Ipv4Addr::new(185, 139, 69, 24),
    },
    DnsResolver {
        provider: DnsProvider::Mafioznik,
        address: Ipv4Addr::new(103, 27, 157, 38),
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsError {
    InvalidQuery,
    Mismatch,
    Malformed,
}

#[derive(Debug)]
enum RecordData {
    Address(Ipv4Addr),
    Cname(String),
}

#[derive(Debug)]
struct Record {
    owner: String,
    data: RecordData,
}

pub fn build_a_query(id: u16, name: &str) -> Result<Vec<u8>, DnsError> {
    if name.is_empty() || name.len() > 253 {
        return Err(DnsError::InvalidQuery);
    }
    let mut query = Vec::with_capacity(12 + name.len() + 6);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]);
    query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(DnsError::InvalidQuery);
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&[0, 1, 0, 1]);
    Ok(query)
}

pub fn parse_a_reply(message: &[u8], query: &[u8], qname: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
    if query.len() < 17 || message.len() < query.len() {
        return Err(DnsError::Malformed);
    }
    if message[..2] != query[..2]
        || message[2] & 0x80 == 0
        || message[2] & 0x78 != 0
        || message[2] & 0x02 != 0
        || message[3] & 0x0f != 0
        || read_u16(message, 4)? != 1
        || message[12..query.len()] != query[12..]
    {
        return Err(DnsError::Mismatch);
    }

    let answer_count = usize::from(read_u16(message, 6)?);
    if answer_count > MAX_ANSWERS {
        return Err(DnsError::Malformed);
    }
    let mut offset = query.len();
    let mut records = Vec::with_capacity(answer_count);
    for _ in 0..answer_count {
        let owner = read_name(message, &mut offset)?;
        let rr_header = message
            .get(offset..offset.checked_add(10).ok_or(DnsError::Malformed)?)
            .ok_or(DnsError::Malformed)?;
        let kind = u16::from_be_bytes([rr_header[0], rr_header[1]]);
        let class = u16::from_be_bytes([rr_header[2], rr_header[3]]);
        let data_len = usize::from(u16::from_be_bytes([rr_header[8], rr_header[9]]));
        offset += 10;
        let data_end = offset.checked_add(data_len).ok_or(DnsError::Malformed)?;
        let data = message.get(offset..data_end).ok_or(DnsError::Malformed)?;
        if class == 1 {
            match (kind, data_len) {
                (1, 4) => records.push(Record {
                    owner,
                    data: RecordData::Address(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                }),
                (5, _) => {
                    let mut name_offset = offset;
                    let target = read_name(message, &mut name_offset)?;
                    if name_offset != data_end {
                        return Err(DnsError::Malformed);
                    }
                    records.push(Record {
                        owner,
                        data: RecordData::Cname(target),
                    });
                }
                _ => {}
            }
        }
        offset = data_end;
    }

    let mut result = Vec::with_capacity(MAX_ADDRESSES);
    let mut current = qname.to_ascii_lowercase();
    for _ in 0..8 {
        for record in &records {
            if record.owner != current {
                continue;
            }
            if let RecordData::Address(address) = &record.data
                && !result.contains(address)
                && result.len() < MAX_ADDRESSES
            {
                result.push(*address);
            }
        }
        let cname = records.iter().find_map(|record| {
            if record.owner != current {
                return None;
            }
            match &record.data {
                RecordData::Cname(target) => Some(target.clone()),
                RecordData::Address(_) => None,
            }
        });
        let Some(target) = cname else {
            break;
        };
        if target == current {
            break;
        }
        current = target;
    }
    Ok(result)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DnsError> {
    let end = offset.checked_add(2).ok_or(DnsError::Malformed)?;
    let value = bytes.get(offset..end).ok_or(DnsError::Malformed)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_name(message: &[u8], offset: &mut usize) -> Result<String, DnsError> {
    let mut position = *offset;
    let mut jumped = false;
    let mut hops = 0;
    let mut labels = Vec::new();
    let mut wire_len = 0_usize;
    loop {
        let byte = *message.get(position).ok_or(DnsError::Malformed)?;
        if byte == 0 {
            if !jumped {
                *offset = position + 1;
            }
            break;
        }
        if byte & 0xc0 == 0xc0 {
            let second = *message.get(position + 1).ok_or(DnsError::Malformed)?;
            let target = (usize::from(byte & 0x3f) << 8) | usize::from(second);
            if target >= position || target >= message.len() || hops >= 16 {
                return Err(DnsError::Malformed);
            }
            if !jumped {
                *offset = position + 2;
                jumped = true;
            }
            position = target;
            hops += 1;
            continue;
        }
        if byte & 0xc0 != 0 || byte > 63 {
            return Err(DnsError::Malformed);
        }
        let label_len = usize::from(byte);
        let label_end = position
            .checked_add(1 + label_len)
            .ok_or(DnsError::Malformed)?;
        let label = message
            .get(position + 1..label_end)
            .ok_or(DnsError::Malformed)?;
        wire_len = wire_len
            .checked_add(label_len + 1)
            .ok_or(DnsError::Malformed)?;
        if wire_len > 255 {
            return Err(DnsError::Malformed);
        }
        let label = std::str::from_utf8(label).map_err(|_| DnsError::Malformed)?;
        labels.push(label.to_ascii_lowercase());
        position = label_end;
    }
    Ok(labels.join("."))
}
