use r2o_controller::r2o_volume::{
    R2oVolumeObservation, R2oVolumeProbeStage, R2oVolumeRxDomain, R2oVolumeRxEncoding,
    r2o_volume_rx_evidence, r2o_volume_rx_needs_repeat, r2o_volume_rx_pair_agrees,
    r2o_volume_rx_partial,
};

fn r2o_identity_cut(body_bytes: u64, data_packets: u32) -> R2oVolumeObservation {
    R2oVolumeObservation {
        stage: R2oVolumeProbeStage::Application,
        name_valid: true,
        negotiated_tls: Some(0x0304),
        status: 200,
        body_encoding: R2oVolumeRxEncoding::Identity,
        body_framing_valid: true,
        body_has_length: true,
        body_expected: 40 * 1024,
        body_bytes,
        rx_tls_wire_bytes: body_bytes + 1200,
        data_packets,
        ..Default::default()
    }
}

fn r2o_gzip_result(body_bytes: u64, data_packets: u32, complete: bool) -> R2oVolumeObservation {
    R2oVolumeObservation {
        stage: R2oVolumeProbeStage::Application,
        name_valid: true,
        negotiated_tls: Some(0x0304),
        status: 200,
        body_complete: complete,
        body_encoding: R2oVolumeRxEncoding::Gzip,
        body_framing_valid: true,
        body_has_length: true,
        body_expected: body_bytes,
        body_bytes,
        rx_tls_wire_bytes: body_bytes + 1200,
        data_packets,
        ..Default::default()
    }
}

#[test]
fn r2o_rx_вердикт_требует_двух_совпавших_обрывов_и_контроля_gzip() {
    let first = r2o_identity_cut(20 * 1024, 25);
    let second = r2o_identity_cut(21 * 1024, 26);
    let gzip = r2o_gzip_result(8 * 1024, 45, true);

    assert!(r2o_volume_rx_partial(&first));
    assert!(r2o_volume_rx_pair_agrees(&first, &second));
    let evidence = r2o_volume_rx_evidence(&first, &second, &gzip).unwrap();
    assert_eq!(evidence.domain, R2oVolumeRxDomain::HttpBody);
    assert_eq!(evidence.cut_kb, 20);
    assert_eq!(evidence.expected_kb, 40);
    assert!(evidence.compressed_complete);
}

#[test]
fn r2o_rx_не_смешивает_обрыв_и_завершённый_повтор() {
    let partial = r2o_identity_cut(16 * 1024, 25);
    let mut complete = partial;
    complete.body_complete = true;
    complete.body_bytes = 22 * 1024;
    assert!(!r2o_volume_rx_pair_agrees(&partial, &complete));
    assert!(r2o_volume_rx_needs_repeat(&partial, &complete));

    complete.body_bytes = 263;
    assert!(!r2o_volume_rx_needs_repeat(&partial, &complete));
}

#[test]
fn r2o_rx_непришедший_gzip_требует_того_же_пакетного_бюджета() {
    let first = r2o_identity_cut(20 * 1024, 25);
    let second = r2o_identity_cut(21 * 1024, 26);
    let gzip = r2o_gzip_result(24 * 1024, 28, false);
    let evidence = r2o_volume_rx_evidence(&first, &second, &gzip).unwrap();
    assert_eq!(evidence.cut_packets, 25);
    assert!(!evidence.compressed_complete);

    let different_budget = r2o_gzip_result(24 * 1024, 29, false);
    assert!(r2o_volume_rx_evidence(&first, &second, &different_budget).is_none());
    let unknown_budget = r2o_gzip_result(24 * 1024, 0, false);
    assert!(r2o_volume_rx_evidence(&first, &second, &unknown_budget).is_none());
}

#[test]
fn r2o_rx_отказывает_при_недостаточном_объёме_или_неверном_framing() {
    let mut first = r2o_identity_cut(11 * 1024, 25);
    let second = r2o_identity_cut(11 * 1024 + 100, 25);
    let gzip = r2o_gzip_result(4 * 1024, 30, true);
    assert!(!r2o_volume_rx_partial(&first));
    assert!(r2o_volume_rx_evidence(&first, &second, &gzip).is_none());

    first.body_bytes = 20 * 1024;
    let mut second = r2o_identity_cut(20 * 1024 + 100, 25);
    second.body_chunked = true;
    assert!(!r2o_volume_rx_pair_agrees(&first, &second));
    assert!(r2o_volume_rx_evidence(&first, &second, &gzip).is_none());

    second = r2o_identity_cut(20 * 1024 + 100, 25);
    second.body_expected = second.body_bytes;
    assert!(!r2o_volume_rx_partial(&second));
    assert!(r2o_volume_rx_evidence(&first, &second, &gzip).is_none());

    second = r2o_identity_cut(20 * 1024 + 100, 25);
    second.status = 403;
    assert!(!r2o_volume_rx_partial(&second));
}

#[test]
fn r2o_rx_сверяет_tls_wire_отдельно_от_http_тела() {
    let first = R2oVolumeObservation {
        stage: R2oVolumeProbeStage::Handshake,
        name_valid: true,
        negotiated_tls: Some(0x0304),
        rx_tls_wire_bytes: 14 * 1024,
        rx_tls_record_missing: true,
        ..Default::default()
    };
    let second = R2oVolumeObservation {
        rx_tls_wire_bytes: 14 * 1024 + 100,
        ..first
    };
    let gzip = R2oVolumeObservation {
        rx_tls_wire_bytes: 4500,
        ..r2o_gzip_result(3 * 1024, 30, true)
    };

    assert!(r2o_volume_rx_pair_agrees(&first, &second));
    let evidence = r2o_volume_rx_evidence(&first, &second, &gzip).unwrap();
    assert_eq!(evidence.domain, R2oVolumeRxDomain::TlsWire);
    assert!(evidence.compressed_complete);
    assert!(evidence.reason.contains("TLS"));
    assert!(!r2o_volume_rx_pair_agrees(
        &first,
        &r2o_identity_cut(14 * 1024, 25)
    ));

    let wrong_tls = R2oVolumeObservation {
        negotiated_tls: Some(0x0303),
        ..second
    };
    assert!(!r2o_volume_rx_pair_agrees(&first, &wrong_tls));
    assert!(r2o_volume_rx_evidence(&first, &wrong_tls, &gzip).is_none());

    let limited = R2oVolumeObservation {
        local_limit: true,
        ..first
    };
    assert!(!r2o_volume_rx_partial(&limited));
}
