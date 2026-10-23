pub(crate) const R2O_VOLUME_MIN_BYTES: u64 = 12 * 1024;
const R2O_VOLUME_BYTE_SLACK: u64 = 4 * 1024;
const R2O_VOLUME_PACKET_SLACK: u32 = 3;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum R2oVolumeProbeStage {
    #[default]
    Transport,
    Handshake,
    Application,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum R2oVolumeRxEncoding {
    #[default]
    Identity,
    Gzip,
    Other,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum R2oVolumePacketBudget {
    #[default]
    NotMeasured,
    NotApplicable,
    Cut,
    Passed,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct R2oVolumeObservation {
    pub stage: R2oVolumeProbeStage,
    pub name_valid: bool,
    pub negotiated_tls: Option<u16>,
    pub replay_proof: bool,
    pub local_limit: bool,
    pub status: u16,
    pub body_complete: bool,
    pub body_encoding: R2oVolumeRxEncoding,
    pub body_framing_valid: bool,
    pub body_has_length: bool,
    pub body_chunked: bool,
    pub body_expected: u64,
    pub body_bytes: u64,
    pub rx_tls_wire_bytes: u64,
    pub rx_tls_record_missing: bool,
    pub data_packets: u32,
    pub packet_budget: R2oVolumePacketBudget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oVolumeRxDomain {
    HttpBody,
    TlsWire,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oVolumeRxEvidence {
    pub domain: R2oVolumeRxDomain,
    pub cut_kb: u32,
    pub expected_kb: u32,
    pub cut_packets: u32,
    pub compressed_complete: bool,
    pub reason: String,
}

/// Определяет подозрение на обрыв только по одному измерению.
pub fn r2o_volume_rx_partial(observation: &R2oVolumeObservation) -> bool {
    r2o_volume_rx_wire_partial(observation)
        || ((200..300).contains(&observation.status)
            && !observation.body_complete
            && observation.body_encoding == R2oVolumeRxEncoding::Identity
            && observation.body_framing_valid
            && observation.body_has_length != observation.body_chunked
            && observation.body_bytes >= R2O_VOLUME_MIN_BYTES
            && (!observation.body_has_length || observation.body_expected > observation.body_bytes))
}

/// Сравнивает два обрыва в одном измерительном домене и контексте.
pub fn r2o_volume_rx_pair_agrees(
    first: &R2oVolumeObservation,
    second: &R2oVolumeObservation,
) -> bool {
    if !r2o_volume_rx_partial(first) || !r2o_volume_rx_partial(second) {
        return false;
    }
    let first_is_wire = r2o_volume_rx_wire_partial(first);
    let second_is_wire = r2o_volume_rx_wire_partial(second);
    if first_is_wire != second_is_wire {
        return false;
    }
    if first_is_wire {
        first.negotiated_tls == second.negotiated_tls
    } else {
        first.body_has_length == second.body_has_length && first.body_chunked == second.body_chunked
    }
}

/// Запрашивает третий identity-замер только при противоречии двух первых.
pub fn r2o_volume_rx_needs_repeat(
    first: &R2oVolumeObservation,
    second: &R2oVolumeObservation,
) -> bool {
    r2o_volume_rx_partial(first)
        && !r2o_volume_rx_partial(second)
        && (200..300).contains(&second.status)
        && second.body_complete
        && second.body_framing_valid
        && second.body_bytes >= R2O_VOLUME_MIN_BYTES
}

/// Выдаёт вердикт только по паре identity-обрывов и отдельному gzip-контролю.
pub fn r2o_volume_rx_evidence(
    first: &R2oVolumeObservation,
    second: &R2oVolumeObservation,
    gzip: &R2oVolumeObservation,
) -> Option<R2oVolumeRxEvidence> {
    if r2o_volume_rx_wire_partial(first) || r2o_volume_rx_wire_partial(second) {
        return r2o_volume_rx_wire_evidence(first, second, gzip);
    }
    r2o_volume_rx_body_evidence(first, second, gzip)
}

fn r2o_volume_rx_wire_partial(observation: &R2oVolumeObservation) -> bool {
    observation.stage == R2oVolumeProbeStage::Handshake
        && observation.name_valid
        && observation.status == 0
        && !observation.replay_proof
        && !observation.local_limit
        && matches!(observation.negotiated_tls, Some(0x0303 | 0x0304))
        && observation.rx_tls_record_missing
        && observation.rx_tls_wire_bytes >= R2O_VOLUME_MIN_BYTES
}

fn r2o_volume_rx_wire_evidence(
    first: &R2oVolumeObservation,
    second: &R2oVolumeObservation,
    gzip: &R2oVolumeObservation,
) -> Option<R2oVolumeRxEvidence> {
    let tls = first.negotiated_tls?;
    if !r2o_volume_rx_wire_partial(first)
        || !r2o_volume_rx_wire_partial(second)
        || second.negotiated_tls != Some(tls)
        || gzip.negotiated_tls != Some(tls)
        || gzip.stage != R2oVolumeProbeStage::Application
        || !gzip.name_valid
        || gzip.local_limit
        || !(200..300).contains(&gzip.status)
        || !gzip.body_complete
        || !gzip.body_framing_valid
        || gzip.body_encoding != R2oVolumeRxEncoding::Gzip
        || gzip.body_bytes == 0
        || gzip.rx_tls_wire_bytes == 0
        || gzip.rx_tls_record_missing
        || gzip.rx_tls_wire_bytes >= first.rx_tls_wire_bytes
        || gzip.rx_tls_wire_bytes >= second.rx_tls_wire_bytes
    {
        return None;
    }
    let lower = first.rx_tls_wire_bytes.min(second.rx_tls_wire_bytes);
    let upper = first.rx_tls_wire_bytes.max(second.rx_tls_wire_bytes);
    if upper - lower > R2O_VOLUME_BYTE_SLACK {
        return None;
    }
    let cut_kb = r2o_volume_kilobytes(lower + (upper - lower) / 2);
    Some(R2oVolumeRxEvidence {
        domain: R2oVolumeRxDomain::TlsWire,
        cut_kb,
        expected_kb: 0,
        cut_packets: r2o_volume_min_known_packets(first.data_packets, second.data_packets),
        compressed_complete: true,
        reason: format!(
            "TLS RX дважды оборвался внутри записи около {cut_kb} КБ; меньший gzip завершился"
        ),
    })
}

fn r2o_volume_rx_body_evidence(
    first: &R2oVolumeObservation,
    second: &R2oVolumeObservation,
    gzip: &R2oVolumeObservation,
) -> Option<R2oVolumeRxEvidence> {
    if !(200..300).contains(&first.status)
        || !(200..300).contains(&second.status)
        || first.body_complete
        || second.body_complete
        || first.body_encoding != R2oVolumeRxEncoding::Identity
        || second.body_encoding != R2oVolumeRxEncoding::Identity
        || !first.body_framing_valid
        || !second.body_framing_valid
        || first.body_bytes < R2O_VOLUME_MIN_BYTES
        || second.body_bytes < R2O_VOLUME_MIN_BYTES
        || first.body_has_length != second.body_has_length
        || first.body_chunked != second.body_chunked
        || first.body_has_length == first.body_chunked
        || first.body_has_length && first.body_expected <= first.body_bytes
        || first.body_has_length && second.body_expected <= second.body_bytes
    {
        return None;
    }
    let delta = first.body_bytes.abs_diff(second.body_bytes);
    if delta > R2O_VOLUME_BYTE_SLACK
        || !(200..300).contains(&gzip.status)
        || !gzip.body_framing_valid
        || gzip.body_encoding != R2oVolumeRxEncoding::Gzip
        || gzip.body_bytes == 0
    {
        return None;
    }

    let packet_budget = if gzip.body_complete {
        false
    } else {
        if first.data_packets == 0 || second.data_packets == 0 || gzip.data_packets == 0 {
            return None;
        }
        let lowest = first
            .data_packets
            .min(second.data_packets)
            .min(gzip.data_packets);
        let highest = first
            .data_packets
            .max(second.data_packets)
            .max(gzip.data_packets);
        if highest - lowest > R2O_VOLUME_PACKET_SLACK {
            return None;
        }
        true
    };

    let midpoint = first.body_bytes.min(second.body_bytes) + delta / 2;
    let cut_kb = r2o_volume_kilobytes(midpoint);
    let expected_kb = if first.body_has_length && first.body_expected <= i32::MAX as u64 * 1024 {
        r2o_volume_kilobytes(first.body_expected)
    } else {
        0
    };
    let mut cut_packets = r2o_volume_min_known_packets(first.data_packets, second.data_packets);
    if packet_budget {
        cut_packets = cut_packets.min(gzip.data_packets);
    }
    let reason = if packet_budget {
        format!(
            "identity (около {cut_kb} КБ) и gzip оборвались на одном бюджете: ~{cut_packets} пакетов с данными на поток"
        )
    } else if expected_kb > 0 {
        format!(
            "identity-тело повторно оборвалось около {cut_kb}/{expected_kb} КБ; gzip завершился"
        )
    } else {
        format!("chunked identity-тело повторно оборвалось около {cut_kb} КБ; gzip завершился")
    };

    Some(R2oVolumeRxEvidence {
        domain: R2oVolumeRxDomain::HttpBody,
        cut_kb,
        expected_kb,
        cut_packets,
        compressed_complete: !packet_budget,
        reason,
    })
}

fn r2o_volume_min_known_packets(first: u32, second: u32) -> u32 {
    match (first, second) {
        (0, 0) => 0,
        (0, packets) | (packets, 0) => packets,
        (first, second) => first.min(second),
    }
}

fn r2o_volume_kilobytes(bytes: u64) -> u32 {
    (bytes / 1024).min(i32::MAX as u64) as u32
}
