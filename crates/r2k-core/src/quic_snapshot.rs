//! Упаковка и разбор точных QUIC Initial-датаграмм для повторного испытания.

use crate::quic::MAX_PACKET;

pub const R2K_QUIC_SNAPSHOT_MAX_DATAGRAMS: usize = 4;
pub const R2K_QUIC_SNAPSHOT_MAX_BYTES: usize = 6144;
const R2K_QUIC_SNAPSHOT_HEADER_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2kQuicSnapshot<'a> {
    datagrams: [&'a [u8]; R2K_QUIC_SNAPSHOT_MAX_DATAGRAMS],
    count: usize,
}

impl<'a> R2kQuicSnapshot<'a> {
    /// Вернуть датаграммы без копирования, ссылаясь на исходный снимок.
    pub fn datagrams(&self) -> &[&'a [u8]] {
        &self.datagrams[..self.count]
    }
}

/// Упаковать от одной до четырёх датаграмм в формат `QSN`.
pub fn r2k_quic_snapshot_pack(datagrams: &[&[u8]]) -> Option<Vec<u8>> {
    if datagrams.is_empty() || datagrams.len() > R2K_QUIC_SNAPSHOT_MAX_DATAGRAMS {
        return None;
    }
    let total = datagrams
        .iter()
        .try_fold(R2K_QUIC_SNAPSHOT_HEADER_BYTES, |total, datagram| {
            if datagram.is_empty() || datagram.len() > MAX_PACKET {
                return None;
            }
            total.checked_add(2)?.checked_add(datagram.len())
        })?;
    if total > R2K_QUIC_SNAPSHOT_MAX_BYTES {
        return None;
    }

    let mut packed = Vec::with_capacity(total);
    packed.extend_from_slice(b"QSN");
    packed.push(datagrams.len() as u8);
    for datagram in datagrams {
        packed.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
        packed.extend_from_slice(datagram);
    }
    Some(packed)
}

/// Разобрать снимок только при точной длине и допустимых границах записей.
pub fn r2k_quic_snapshot_parse(input: &[u8]) -> Option<R2kQuicSnapshot<'_>> {
    if input.len() < R2K_QUIC_SNAPSHOT_HEADER_BYTES
        || input.len() > R2K_QUIC_SNAPSHOT_MAX_BYTES
        || input.get(..3)? != b"QSN"
    {
        return None;
    }
    let count = usize::from(input[3]);
    if count == 0 || count > R2K_QUIC_SNAPSHOT_MAX_DATAGRAMS {
        return None;
    }

    let mut datagrams = [&input[..0]; R2K_QUIC_SNAPSHOT_MAX_DATAGRAMS];
    let mut offset = R2K_QUIC_SNAPSHOT_HEADER_BYTES;
    for datagram in &mut datagrams[..count] {
        let length_end = offset.checked_add(2)?;
        let length_bytes = input.get(offset..length_end)?;
        let length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
        if length == 0 || length > MAX_PACKET {
            return None;
        }
        let datagram_end = length_end.checked_add(length)?;
        *datagram = input.get(length_end..datagram_end)?;
        offset = datagram_end;
    }
    (offset == input.len()).then_some(R2kQuicSnapshot { datagrams, count })
}

/// Перезапечатать весь полёт под один новый DCID, не меняя границы пакетов.
pub fn r2k_quic_snapshot_reseal(input: &[u8]) -> Option<Vec<u8>> {
    let snapshot = r2k_quic_snapshot_parse(input)?;
    let datagrams = snapshot.datagrams();
    let (version, old_dcid) = crate::quic::r2k_quic_initial_flight_id(datagrams.first()?)?;
    if old_dcid.len() < 8 {
        return None;
    }

    let mut new_dcid = vec![0; old_dcid.len()];
    let mut unique = false;
    for _ in 0..4 {
        getrandom::getrandom(&mut new_dcid).ok()?;
        if new_dcid != old_dcid {
            unique = true;
            break;
        }
    }
    if !unique {
        return None;
    }

    let mut resealed = Vec::with_capacity(datagrams.len());
    for datagram in datagrams {
        let (datagram_version, datagram_dcid) = crate::quic::r2k_quic_initial_flight_id(datagram)?;
        if datagram_version != version || datagram_dcid != old_dcid {
            return None;
        }
        resealed.push(crate::quic::r2k_quic_initial_reseal_for_dcid(
            datagram, &new_dcid,
        )?);
    }

    let datagram_refs = resealed.iter().map(Vec::as_slice).collect::<Vec<_>>();
    r2k_quic_snapshot_pack(&datagram_refs)
}

/// Проверить, что ответ QUIC адресован SCID первого пакета снимка.
pub fn r2k_quic_snapshot_verify_bound_response(input: &[u8], response: &[u8]) -> bool {
    let Some(snapshot) = r2k_quic_snapshot_parse(input) else {
        return false;
    };
    let Some(client_initial) = snapshot.datagrams().first() else {
        return false;
    };
    crate::quic::r2k_quic_initial_verify_bound_response(client_initial, response)
}
