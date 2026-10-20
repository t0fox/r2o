use r2k_core::quic_snapshot::{
    r2k_quic_snapshot_pack, r2k_quic_snapshot_parse, r2k_quic_snapshot_reseal,
};

#[test]
fn сохраняет_датаграммы_без_изменения_байтов() {
    let first = [0xc0, 0x00, 0x00, 0x01, 0xaa];
    let second = [0xc0, 0x00, 0x00, 0x02, 0xbb, 0xcc];
    let packed = r2k_quic_snapshot_pack(&[&first[..], &second[..]]).unwrap();

    assert_eq!(&packed[..4], b"QSN\x02");
    let parsed = r2k_quic_snapshot_parse(&packed).unwrap();
    assert_eq!(parsed.datagrams(), &[&first[..], &second[..]]);
    assert_eq!(
        parsed.datagrams()[0].as_ptr(),
        packed[6..].as_ptr(),
        "разбор должен ссылаться на исходный буфер снимка"
    );
}

#[test]
fn перезапечатывает_quic_initial_сохраняя_длину_и_sni() {
    let initials: [&[u8]; 2] = [
        &include_bytes!("fixtures/quic_v1_initial.bin")[..],
        &include_bytes!("fixtures/quic_v2_initial.bin")[..],
    ];

    for initial in initials {
        let packed = r2k_quic_snapshot_pack(&[initial, initial]).unwrap();
        let resealed = r2k_quic_snapshot_reseal(&packed).unwrap();
        let original = r2k_quic_snapshot_parse(&packed).unwrap();
        let replay = r2k_quic_snapshot_parse(&resealed).unwrap();
        assert_eq!(replay.datagrams().len(), 2);
        for (before, after) in original.datagrams().iter().zip(replay.datagrams()) {
            assert_eq!(before.len(), after.len());
            assert!(r2k_core::quic::is_authenticated_initial(after));
            assert_eq!(
                r2k_core::quic::initial_client_hello_sni(after).as_deref(),
                Some(b"example.com".as_slice())
            );
        }
        let (_, old_dcid) = r2k_core::quic::r2k_quic_initial_flight_id(initial).unwrap();
        let (version_a, new_dcid_a) =
            r2k_core::quic::r2k_quic_initial_flight_id(replay.datagrams()[0]).unwrap();
        let (version_b, new_dcid_b) =
            r2k_core::quic::r2k_quic_initial_flight_id(replay.datagrams()[1]).unwrap();
        assert_ne!(new_dcid_a, old_dcid);
        assert_eq!(version_a, version_b);
        assert_eq!(new_dcid_a, new_dcid_b);
    }
}

#[test]
fn отклоняет_неверную_структуру_снимка() {
    assert!(r2k_quic_snapshot_parse(b"QSN\x00").is_none());
    assert!(r2k_quic_snapshot_parse(b"QSN\x05").is_none());

    let packed = r2k_quic_snapshot_pack(&[&[1, 2, 3]]).unwrap();
    assert!(r2k_quic_snapshot_parse(&packed[..packed.len() - 1]).is_none());

    let mut with_tail = packed;
    with_tail.push(0);
    assert!(r2k_quic_snapshot_parse(&with_tail).is_none());
}

#[test]
fn ограничивает_число_и_размер_датаграмм() {
    let oversized = vec![0; 1501];

    assert!(r2k_quic_snapshot_pack(&[]).is_none());
    let empty: &[u8] = &[];
    assert!(r2k_quic_snapshot_pack(&[empty, &[1]]).is_none());
    assert!(r2k_quic_snapshot_pack(&[&oversized[..]]).is_none());
    assert!(r2k_quic_snapshot_pack(&[&[1][..], &[2], &[3], &[4], &[5]]).is_none());
}
