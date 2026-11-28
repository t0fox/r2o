//! Wire identities for observations of opaque client traffic. Samples contain a
//! digest of one packet, never its application bytes.
use crate::control::{Frame, KEY_LEN, encode_frame, valid_flow_key};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub const EVENT_RAW_MEASURED: u16 = 0x0023;
pub const EVENT_RAW_RESULT: u16 = 0x0024;
pub const EVENT_RAW_UDP_REPEAT: u16 = 0x0025;
pub const COMMAND_RAW_TRIAL: u16 = 0x00b1;
pub const SHAPE_RAW_TCP: u8 = 16;
pub const SAMPLE_MIN: usize = 16;
pub const SAMPLE_MAX: usize = 1460;
pub const MAX_ACTIVE: usize = 4;
pub const LEASE: Duration = Duration::from_secs(12);
pub const REPEAT_MIN: Duration = Duration::from_millis(150);
pub const RETRY: Duration = Duration::from_secs(60);

pub fn enabled() -> bool {
    std::env::var_os("R2O_RAW_DISCOVERY").is_some_and(|value| value == "1")
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Profile {
    pub length: u16,
    pub tcp: u8,
    pub digest: [u8; 32],
}

impl Profile {
    pub const WIDTH: usize = 35;

    pub fn of(bytes: &[u8], tcp: u8) -> Option<Self> {
        if !(SAMPLE_MIN..=SAMPLE_MAX).contains(&bytes.len()) || tcp > 2 {
            return None;
        }
        Some(Self {
            length: bytes.len() as u16,
            tcp,
            digest: Sha256::digest(bytes).into(),
        })
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let [hi, lo, tcp, rest @ ..] = bytes else {
            return None;
        };
        let length = u16::from_be_bytes([*hi, *lo]);
        let digest: [u8; 32] = rest.try_into().ok()?;
        ((SAMPLE_MIN..=SAMPLE_MAX).contains(&usize::from(length)) && *tcp <= 2 && digest != [0; 32])
            .then_some(Self {
                length,
                tcp: *tcp,
                digest,
            })
    }

    pub fn encode(self) -> [u8; Self::WIDTH] {
        let mut out = [0; Self::WIDTH];
        out[..2].copy_from_slice(&self.length.to_be_bytes());
        out[2] = self.tcp;
        out[3..].copy_from_slice(&self.digest);
        out
    }

    pub fn tcp_split(self, id: [u8; 16]) -> crate::plan::Plan {
        crate::plan::Plan {
            schema: 1,
            minexec: 1,
            id,
            transport: 6,
            splits: vec![crate::plan::Split {
                anchor: 0,
                offset: (self.length / 2) as i16,
            }],
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sample {
    pub key: [u8; KEY_LEN],
    pub client_is_low: bool,
    pub epoch: [u8; 16],
    pub generation: u64,
    pub measurement: u64,
    pub seq: u32,
    pub profile: Profile,
}

impl Sample {
    const HEAD: usize = KEY_LEN + 1 + 16 + 8 + 8 + 4;
    pub const WIDTH: usize = Self::HEAD + Profile::WIDTH;

    pub fn encode(self) -> [u8; Self::WIDTH] {
        let mut out = [0; Self::WIDTH];
        out[..KEY_LEN].copy_from_slice(&self.key);
        let rest = &mut out[KEY_LEN..];
        rest[0] = u8::from(self.client_is_low);
        rest[1..17].copy_from_slice(&self.epoch);
        rest[17..25].copy_from_slice(&self.generation.to_be_bytes());
        rest[25..33].copy_from_slice(&self.measurement.to_be_bytes());
        rest[33..37].copy_from_slice(&self.seq.to_be_bytes());
        rest[37..].copy_from_slice(&self.profile.encode());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIDTH {
            return None;
        }
        let key = bytes[..KEY_LEN].try_into().ok()?;
        if !valid_flow_key(&key) {
            return None;
        }
        let rest = &bytes[KEY_LEN..];
        let client_is_low = match rest[0] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let epoch: [u8; 16] = rest[1..17].try_into().ok()?;
        let generation = u64::from_be_bytes(rest[17..25].try_into().ok()?);
        let measurement = u64::from_be_bytes(rest[25..33].try_into().ok()?);
        let seq = u32::from_be_bytes(rest[33..37].try_into().ok()?);
        let profile = Profile::decode(&bytes[Self::HEAD..])?;
        if epoch == [0; 16]
            || generation == 0
            || measurement == 0
            || (key[37] == 17 && (seq != 0 || profile.tcp != 0))
        {
            return None;
        }
        Some(Self {
            key,
            client_is_low,
            epoch,
            generation,
            measurement,
            seq,
            profile,
        })
    }

    pub fn server(self) -> SocketAddr {
        let (ip_start, port_start) = if self.client_is_low {
            (17, 35)
        } else {
            (1, 33)
        };
        let address: [u8; 16] = self.key[ip_start..ip_start + 16].try_into().unwrap();
        let ip = if self.key[0] == 4 {
            IpAddr::from(<[u8; 4]>::try_from(&address[..4]).unwrap())
        } else {
            IpAddr::from(address)
        };
        SocketAddr::new(
            ip,
            u16::from_be_bytes(self.key[port_start..port_start + 2].try_into().unwrap()),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Trial {
    pub sample: Sample,
    pub token: [u8; 16],
    pub plan: [u8; 16],
}

impl Trial {
    const WIDTH: usize = Sample::WIDTH + 32;

    fn encode(self) -> [u8; Self::WIDTH] {
        let mut out = [0; Self::WIDTH];
        out[..Sample::WIDTH].copy_from_slice(&self.sample.encode());
        out[Sample::WIDTH..Sample::WIDTH + 16].copy_from_slice(&self.token);
        out[Sample::WIDTH + 16..].copy_from_slice(&self.plan);
        out
    }

    pub fn frame(self) -> Result<Vec<u8>, &'static str> {
        encode_frame(COMMAND_RAW_TRIAL, &self.encode())
    }

    pub fn from_frame(frame: &Frame) -> Option<Self> {
        (frame.kind == COMMAND_RAW_TRIAL).then_some(())?;
        Self::decode(&frame.body)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIDTH {
            return None;
        }
        let sample = Sample::decode(&bytes[..Sample::WIDTH])?;
        let token = bytes[Sample::WIDTH..Sample::WIDTH + 16].try_into().ok()?;
        let plan = bytes[Sample::WIDTH + 16..].try_into().ok()?;
        (token != [0; 16] && plan != [0; 16]).then_some(Self {
            sample,
            token,
            plan,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ResultKind {
    Executed = 1,
    TransportAck = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    pub trial: Trial,
    pub execution: u64,
    pub kind: ResultKind,
}

impl Report {
    const WIDTH: usize = Trial::WIDTH + 9;

    pub fn encode(self) -> [u8; Self::WIDTH] {
        let mut out = [0; Self::WIDTH];
        out[..Trial::WIDTH].copy_from_slice(&self.trial.encode());
        out[Trial::WIDTH..Trial::WIDTH + 8].copy_from_slice(&self.execution.to_be_bytes());
        out[Trial::WIDTH + 8] = self.kind as u8;
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIDTH {
            return None;
        }
        let trial = Trial::decode(&bytes[..Trial::WIDTH])?;
        let execution = u64::from_be_bytes(bytes[Trial::WIDTH..Trial::WIDTH + 8].try_into().ok()?);
        let kind = match bytes[Trial::WIDTH + 8] {
            1 => ResultKind::Executed,
            2 if trial.sample.key[37] == 6 => ResultKind::TransportAck,
            _ => return None,
        };
        (execution != 0).then_some(Self {
            trial,
            execution,
            kind,
        })
    }
}
