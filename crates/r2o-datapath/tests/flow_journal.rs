use r2k_core::control::{
    AppliedEvent, BindingContext, EVENT_R2O_QUIC_STALL, EVENT_R2O_QUIC_SUSPECT,
    EVENT_R2O_TCP_CLEAN_HANDSHAKE, EVENT_R2O_TCP_EARLY_RST, EVENT_R2O_TCP_FIN_RETRY,
    EVENT_R2O_TCP_REPEAT, EVENT_R2O_TCP_RST_AFTER_APP, EVENT_R2O_TCP_SILENT, EVENT_R2O_TCP_STALL,
    EVENT_R2O_VOICE_PROOF, EVENT_R2O_VOICE_RTP_PROOF, EVENT_R2O_VOICE_STUN_PROOF,
    EVENT_R2O_VOICE_SUSPECT, KEY_LEN, R2oQuicSuspectEvent, R2oTcpCleanHandshakeEvent,
    R2oTcpEarlyRstEvent, R2oTcpFinRetryEvent, R2oTcpRepeatEvent, R2oTcpRstAfterAppEvent,
    R2oTcpSilenceEvent, R2oTcpStallEvent, R2oVoiceProofEvent, R2oVoiceProofKind,
    R2oVoiceSuspectEvent,
};
use r2o_datapath::flow_journal::{
    R2oFlowJournal, R2oFlowJournalEntry, R2oFlowJournalKind, R2oFlowJournalSummary,
};
use r2o_datapath::r2o_quic::R2oUdpExchangeEvent;

fn запись(номер: u64) -> R2oFlowJournalEntry {
    R2oFlowJournalEntry {
        at_ns: номер,
        code: номер as u8,
        ..R2oFlowJournalEntry::default()
    }
}

#[test]
fn запись_журнала_сохраняет_все_поля_при_передаче_контроллеру() {
    let mut entry = запись(0x0102_0304_0506_0708);
    entry.execution_id = 0x1112_1314_1516_1718;
    entry.binding = Some(BindingContext {
        generation: 0x2122_2324_2526_2728,
        kind: 1,
        family: 6,
        shape: 3,
        temporary: true,
        epoch: [0x33; 16],
    });
    entry.key[0] = 6;
    entry.key[37] = 17;
    entry.kind = R2oFlowJournalKind::Exchange;
    entry.code = 0x44;
    entry.set_name(b"example.test");
    entry.num = 0x5152_5354;
    entry.ttl = 0x61;
    entry.reference_ttl = 0x62;
    entry.tos = 0x63;
    entry.server_hello = true;
    entry.planned = 2;
    entry.client_shape = 3;
    entry.client_is_low = Some(false);
    entry.elapsed_ms = 0x7172_7374;
    entry.ip_id = 0x8182;
    entry.mapped_ip = [0x91, 0x92, 0x93, 0x94];
    entry.mapped_port = 0xa1a2;
    entry.plan_id = [0xb3; 16];
    entry.trial_id = [0xc4; 16];

    let frame = entry.to_event_frame().unwrap();
    let restored = R2oFlowJournalEntry::from_event_frame(&frame).unwrap();

    assert_eq!(restored, entry);
}

#[test]
fn передача_журнала_отвергает_непредставленную_заметку() {
    let mut entry = запись(1);
    entry.note = Some("непередаваемая заметка");

    assert!(entry.to_event_frame().is_err());
}

#[test]
fn граница_снимка_сохраняет_счётчики_журнала() {
    let summary = R2oFlowJournalSummary {
        added: 0x0102_0304_0506_0708,
        dropped: 0x1112_1314_1516_1718,
        count: 0x2122_2324,
    };

    let frame = summary.to_event_frame();

    assert_eq!(
        R2oFlowJournalSummary::from_event_frame(&frame).unwrap(),
        summary
    );
}

#[test]
fn кольцо_хранит_новейшие_записи_и_выдаёт_их_по_порядку() {
    let mut журнал = R2oFlowJournal::with_capacity(2).unwrap();
    журнал.push(запись(1));
    журнал.push(запись(2));
    журнал.push(запись(3));

    assert_eq!(журнал.count(), 2);
    assert_eq!(журнал.added(), 3);
    assert_eq!(журнал.dropped(), 1);
    assert_eq!(журнал.get(0).unwrap().at_ns, 2);
    assert_eq!(журнал.get(1).unwrap().at_ns, 3);
    assert!(журнал.get(2).is_none());
}

#[test]
fn запись_tcp_обмена_передаёт_уровень_ответа_и_подтверждение_плана() {
    let событие = r2o_datapath::engine::R2oTcpExchangeEvent {
        key: {
            let mut key = [0; KEY_LEN];
            key[0] = 4;
            key[1..5].copy_from_slice(&[192, 0, 2, 10]);
            key[17..21].copy_from_slice(&[198, 51, 100, 20]);
            key[33..35].copy_from_slice(&41000_u16.to_be_bytes());
            key[35..37].copy_from_slice(&443_u16.to_be_bytes());
            key[37] = 6;
            key
        },
        code: 0x16,
        num: 1234,
        tos: 0x0c,
        server_hello: true,
        planned: 1,
    };
    let mut журнал = R2oFlowJournal::with_capacity(1).unwrap();

    журнал.record_tcp_exchange(456, &событие);

    let запись = журнал.get(0).unwrap();
    assert_eq!(запись.at_ns, 456);
    assert_eq!(запись.key, событие.key);
    assert_eq!(запись.kind, R2oFlowJournalKind::Exchange);
    assert_eq!(запись.code, 0x16);
    assert_eq!(запись.num, 1234);
    assert_eq!(запись.tos, 0x0c);
    assert!(запись.server_hello);
    assert_eq!(запись.planned, 1);
    assert_eq!(
        R2oFlowJournalEntry::from_event_frame(&запись.to_event_frame().unwrap()).unwrap(),
        *запись
    );
}

#[test]
fn запись_udp_обмена_сохраняет_первый_ответ_и_длину_пустой_датаграммы() {
    let mut ключ = [0; KEY_LEN];
    ключ[0] = 4;
    ключ[1..5].copy_from_slice(&[192, 0, 2, 10]);
    ключ[17..21].copy_from_slice(&[198, 51, 100, 20]);
    ключ[33..35].copy_from_slice(&53_123_u16.to_be_bytes());
    ключ[35..37].copy_from_slice(&443_u16.to_be_bytes());
    ключ[37] = 17;
    let событие = R2oUdpExchangeEvent {
        key: ключ,
        code: 0,
        num: 0,
    };
    let mut журнал = R2oFlowJournal::with_capacity(1).unwrap();

    журнал.record_udp_exchange(789, &событие);

    let запись = журнал.get(0).unwrap();
    assert_eq!(запись.at_ns, 789);
    assert_eq!(запись.key, ключ);
    assert_eq!(запись.kind, R2oFlowJournalKind::Exchange);
    assert_eq!(запись.code, 0);
    assert_eq!(запись.num, 0);
    assert_eq!(
        R2oFlowJournalEntry::from_event_frame(&запись.to_event_frame().unwrap()).unwrap(),
        *запись
    );
}

#[test]
fn нулевая_глубина_считает_события_без_хранения() {
    let mut журнал = R2oFlowJournal::with_capacity(0).unwrap();
    журнал.push(запись(1));
    журнал.push(запись(2));

    assert_eq!(журнал.count(), 0);
    assert_eq!(журнал.added(), 2);
    assert_eq!(журнал.dropped(), 0);
    assert!(журнал.get(0).is_none());
}

#[test]
fn имя_ограничено_63_байтами_и_очищено_для_вывода() {
    let mut entry = запись(1);
    let mut имя = vec![b'a'; 62];
    имя.extend_from_slice(&[0x1f, 0x7f, b'z']);
    entry.set_name(&имя);

    let mut журнал = R2oFlowJournal::with_capacity(1).unwrap();
    журнал.push(entry);
    let сохранено = журнал.get(0).unwrap();

    assert_eq!(сохранено.name_len, 63);
    assert!(сохранено.name[..62].iter().all(|byte| *byte == b'a'));
    assert_eq!(сохранено.name[62], b'.');
    assert_eq!(сохранено.name[63], 0);
}

#[test]
fn идентификаторы_плана_и_попытки_сохраняются_побайтно() {
    let mut entry = запись(1);
    entry.plan_id = [0xa5; 16];
    entry.trial_id = [0x5a; 16];
    let mut журнал = R2oFlowJournal::with_capacity(1).unwrap();
    журнал.push(entry);

    let сохранено = журнал.get(0).unwrap();
    assert_eq!(сохранено.plan_id, [0xa5; 16]);
    assert_eq!(сохранено.trial_id, [0x5a; 16]);
}

#[test]
fn запись_приветствия_сохраняет_ключ_имя_и_время() {
    let mut ключ = [0x42; KEY_LEN];
    ключ[0] = 4;
    ключ[5..17].fill(0);
    ключ[21..33].fill(0);
    ключ[37] = 6;
    let mut тело = ключ.to_vec();
    тело.extend_from_slice(&[4, b't', b'e', b's', b't']);
    let mut журнал = R2oFlowJournal::with_capacity(2).unwrap();

    assert!(журнал.record_hello_body(123, &тело));
    let запись = журнал.get(0).unwrap();
    assert_eq!(запись.at_ns, 123);
    assert_eq!(запись.key, ключ);
    assert_eq!(
        запись.kind,
        r2o_datapath::flow_journal::R2oFlowJournalKind::Hello
    );
    assert_eq!(запись.name_len, 4);
    assert_eq!(&запись.name[..4], b"test");
}

#[test]
fn повреждённое_приветствие_не_попадает_в_журнал() {
    let mut журнал = R2oFlowJournal::with_capacity(2).unwrap();
    let mut тело = [0; r2k_core::control::KEY_LEN + 2];
    тело[r2k_core::control::KEY_LEN] = 2;

    assert!(!журнал.record_hello_body(123, &тело));
    assert_eq!(журнал.count(), 0);
    assert_eq!(журнал.added(), 0);
}

#[test]
fn завершённое_исполнение_сохраняет_идентификаторы_и_снимок_привязки() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[37] = 6;
    let событие = AppliedEvent {
        key,
        plan_id: [0xa5; 16],
        trial_id: [0x5a; 16],
        execution_id: 77,
        binding: BindingContext {
            generation: 9,
            kind: 1,
            family: 4,
            shape: 2,
            temporary: true,
            epoch: [0x3c; 16],
        },
    };
    let mut журнал = R2oFlowJournal::with_capacity(2).unwrap();

    журнал.record_applied(123, &событие);

    let запись = журнал.get(0).unwrap();
    assert_eq!(запись.at_ns, 123);
    assert_eq!(запись.kind, R2oFlowJournalKind::PlanDone);
    assert_eq!(запись.key, key);
    assert_eq!(запись.plan_id, [0xa5; 16]);
    assert_eq!(запись.trial_id, [0x5a; 16]);
    assert_eq!(запись.execution_id, 77);
    assert_eq!(запись.binding, Some(событие.binding));
}

#[test]
fn подготовленный_план_остаётся_отдельным_от_успешного_исполнения() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[37] = 6;
    let событие = AppliedEvent {
        key,
        plan_id: [0x91; 16],
        trial_id: [0x72; 16],
        execution_id: 18,
        binding: BindingContext {
            generation: 3,
            kind: 1,
            family: 4,
            shape: 2,
            temporary: false,
            epoch: [0x31; 16],
        },
    };
    let mut журнал = R2oFlowJournal::with_capacity(2).unwrap();

    assert!(журнал.record_plan_prepared(100, &событие));
    assert!(журнал.record_applied(200, &событие));

    assert_eq!(журнал.get(0).unwrap().kind, R2oFlowJournalKind::PlanApplied);
    assert_eq!(журнал.get(0).unwrap().at_ns, 100);
    assert_eq!(журнал.get(1).unwrap().kind, R2oFlowJournalKind::PlanDone);
    assert_eq!(журнал.get(1).unwrap().at_ns, 200);
    assert_eq!(журнал.get(0).unwrap().plan_id, [0x91; 16]);
}

#[test]
fn отказ_и_повреждение_исполнения_сохраняют_исходный_контекст() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[37] = 6;
    let событие = AppliedEvent {
        key,
        plan_id: [0xa5; 16],
        trial_id: [0x5a; 16],
        execution_id: 77,
        binding: BindingContext {
            generation: 9,
            kind: 1,
            family: 4,
            shape: 2,
            temporary: false,
            epoch: [0x3c; 16],
        },
    };
    let mut журнал = R2oFlowJournal::with_capacity(4).unwrap();

    assert!(журнал.record_execution_failure(123, &событие, 1, false));
    assert!(журнал.record_execution_failure(456, &событие, 1, true));

    let не_отправлен = журнал.get(0).unwrap();
    assert_eq!(не_отправлен.kind, R2oFlowJournalKind::PlanUnsent);
    assert_eq!(не_отправлен.code, 1);
    assert_eq!(не_отправлен.key, key);
    assert_eq!(не_отправлен.plan_id, [0xa5; 16]);
    assert_eq!(не_отправлен.trial_id, [0x5a; 16]);
    assert_eq!(не_отправлен.execution_id, 77);
    assert_eq!(не_отправлен.binding, Some(событие.binding));

    let частично_отправлен = журнал.get(1).unwrap();
    assert_eq!(частично_отправлен.kind, R2oFlowJournalKind::PlanUnsent);
    assert_eq!(частично_отправлен.code, 1);
    assert_eq!(частично_отправлен.at_ns, 456);

    let повреждение = журнал.get(2).unwrap();
    assert_eq!(повреждение.kind, R2oFlowJournalKind::PlanDamaged);
    assert_eq!(повреждение.code, 4);
    assert_eq!(повреждение.key, key);
    assert_eq!(повреждение.plan_id, [0xa5; 16]);
    assert_eq!(повреждение.trial_id, [0x5a; 16]);
    assert_eq!(повреждение.execution_id, 77);
    assert_eq!(повреждение.binding, Some(событие.binding));
}

#[test]
fn отказ_исполнителя_сохраняет_код_плана_попытку_и_привязку() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[37] = 6;
    let binding = BindingContext {
        generation: 12,
        kind: 1,
        family: 4,
        shape: 1,
        temporary: true,
        epoch: [0x7a; 16],
    };
    let mut journal = R2oFlowJournal::with_capacity(2).unwrap();

    assert!(journal.record_plan_refused(
        321,
        key,
        r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_NOT_APPLIED,
        [0xa5; 16],
        [0x5a; 16],
        77,
        Some(binding),
    ));

    let refused = journal.get(0).unwrap();
    assert_eq!(refused.kind, R2oFlowJournalKind::PlanRefused);
    assert_eq!(refused.code, 5);
    assert_eq!(refused.key, key);
    assert_eq!(refused.plan_id, [0xa5; 16]);
    assert_eq!(refused.trial_id, [0x5a; 16]);
    assert_eq!(refused.execution_id, 77);
    assert_eq!(refused.binding, Some(binding));
    assert_eq!(
        R2oFlowJournalEntry::from_event_frame(&refused.to_event_frame().unwrap()).unwrap(),
        *refused
    );

    assert!(journal.record_plan_refused(
        322,
        key,
        r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_FLOW_UNFIT,
        [0xb6; 16],
        [0; 16],
        0,
        None,
    ));
    let refusal_without_binding = journal.get(1).unwrap();
    assert_eq!(refusal_without_binding.code, 6);
    assert_eq!(refusal_without_binding.plan_id, [0xb6; 16]);
    assert_eq!(refusal_without_binding.binding, None);
    assert!(
        R2oFlowJournalEntry::from_event_frame(&refusal_without_binding.to_event_frame().unwrap())
            .is_ok()
    );
}

#[test]
fn журнал_сохраняет_детали_подозрения_quic_и_отвергает_повреждённое_событие() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[37] = 17;
    let событие = R2oQuicSuspectEvent {
        key,
        client_is_low: true,
        planned: true,
    };
    let тело = событие.event_body().unwrap();
    let mut журнал = R2oFlowJournal::with_capacity(2).unwrap();

    assert!(журнал.record_control_event(456, EVENT_R2O_QUIC_SUSPECT, &тело));
    assert!(!журнал.record_control_event(789, EVENT_R2O_QUIC_SUSPECT, &тело[..KEY_LEN]));

    let запись = журнал.get(0).unwrap();
    assert_eq!(запись.at_ns, 456);
    assert_eq!(запись.kind, R2oFlowJournalKind::R2oQuicSuspect);
    assert_eq!(запись.key, key);
    assert_eq!(запись.client_is_low, Some(true));
    assert_eq!(запись.planned, 1);
    assert_eq!(журнал.added(), 1);
}

#[test]
fn журнал_проверяет_события_раннего_rst_и_чистого_tcp_рукопожатия() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[192, 0, 2, 10]);
    key[17..21].copy_from_slice(&[198, 51, 100, 80]);
    key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
    key[35..37].copy_from_slice(&443_u16.to_be_bytes());
    key[37] = 6;
    let early_rst = R2oTcpEarlyRstEvent {
        key,
        client_is_low: true,
        planned: false,
        ttl: 127,
        reference_ttl: 64,
        traffic_class: 0x88,
        ip_id: 54321,
    };
    let clean_handshake = R2oTcpCleanHandshakeEvent { key };
    let mut journal = R2oFlowJournal::with_capacity(2).unwrap();

    assert!(journal.record_control_event(
        100,
        EVENT_R2O_TCP_EARLY_RST,
        &early_rst.event_body().unwrap(),
    ));
    assert!(journal.record_control_event(
        101,
        EVENT_R2O_TCP_CLEAN_HANDSHAKE,
        &clean_handshake.event_body().unwrap(),
    ));
    assert!(!journal.record_control_event(
        102,
        EVENT_R2O_TCP_EARLY_RST,
        &early_rst.event_body().unwrap()[..KEY_LEN],
    ));
    assert_eq!(journal.added(), 0);
}

#[test]
fn журнал_различает_зависание_quic_после_ответа() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[37] = 17;
    let event = R2oQuicSuspectEvent {
        key,
        client_is_low: true,
        planned: false,
    };
    let body = event.event_body().unwrap();
    let mut journal = R2oFlowJournal::with_capacity(1).unwrap();

    assert!(journal.record_control_event(456, EVENT_R2O_QUIC_STALL, &body));
    let entry = journal.get(0).unwrap();
    assert_eq!(entry.kind, R2oFlowJournalKind::R2oQuicStall);
    assert_eq!(entry.client_is_low, Some(true));
}

#[test]
fn журнал_сохраняет_подтверждение_udp_обмена() {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[37] = 17;
    let событие = R2oVoiceProofEvent {
        key,
        trial_id: [0x73; 16],
        proof: R2oVoiceProofKind::DiscordDiscovery {
            mapped_ip: std::net::Ipv4Addr::new(203, 0, 113, 4),
            mapped_port: 3478,
        },
    };
    let тело = событие.event_body().unwrap();
    let mut журнал = R2oFlowJournal::with_capacity(3).unwrap();

    assert!(журнал.record_control_event(987, EVENT_R2O_VOICE_PROOF, &тело));

    let запись = журнал.get(0).unwrap();
    assert_eq!(запись.kind, R2oFlowJournalKind::R2oVoiceProof);
    assert_eq!(запись.at_ns, 987);
    assert_eq!(запись.trial_id, [0x73; 16]);
    assert_eq!(запись.mapped_ip, [203, 0, 113, 4]);
    assert_eq!(запись.mapped_port, 3478);

    let событие = R2oVoiceProofEvent {
        key,
        trial_id: [0x74; 16],
        proof: R2oVoiceProofKind::StunBinding,
    };
    assert!(журнал.record_control_event(
        988,
        EVENT_R2O_VOICE_STUN_PROOF,
        &событие.event_body().unwrap()
    ));
    let запись = журнал.get(1).unwrap();
    assert_eq!(запись.code, 2);
    assert_eq!(запись.trial_id, [0x74; 16]);
    assert_eq!(запись.mapped_ip, [0; 4]);
    assert_eq!(запись.mapped_port, 0);

    let событие = R2oVoiceProofEvent {
        key,
        trial_id: [0x75; 16],
        proof: R2oVoiceProofKind::RtpMedia {
            outbound_packets: 3,
            inbound_packets: 4,
        },
    };
    assert!(журнал.record_control_event(
        989,
        EVENT_R2O_VOICE_RTP_PROOF,
        &событие.event_body().unwrap()
    ));
    let запись = журнал.get(2).unwrap();
    assert_eq!(запись.code, 3);
    assert_eq!(запись.num, 0x0304);
    assert_eq!(запись.trial_id, [0x75; 16]);
}

#[test]
fn журнал_сохраняет_все_типы_подозрений_r2o() {
    let mut tcp_key = [0; KEY_LEN];
    tcp_key[0] = 4;
    tcp_key[37] = 6;
    let mut udp_key = tcp_key;
    udp_key[37] = 17;
    let cases = [
        (
            EVENT_R2O_VOICE_SUSPECT,
            R2oVoiceSuspectEvent {
                key: udp_key,
                client_is_low: false,
            }
            .event_body()
            .unwrap(),
            R2oFlowJournalKind::R2oVoiceSuspect,
            0,
            0,
            0,
            0,
        ),
        (
            EVENT_R2O_TCP_SILENT,
            R2oTcpSilenceEvent {
                key: tcp_key,
                client_is_low: true,
                planned: true,
                elapsed_ms: 1200,
            }
            .event_body()
            .unwrap(),
            R2oFlowJournalKind::R2oTcpSilent,
            1,
            1200,
            0,
            3,
        ),
        (
            EVENT_R2O_TCP_STALL,
            R2oTcpStallEvent {
                key: tcp_key,
                client_is_low: true,
                elapsed_ms: 3400,
                estimated_packets: 27,
                planned: true,
            }
            .event_body()
            .unwrap(),
            R2oFlowJournalKind::R2oTcpStall,
            1,
            3400,
            27,
            8,
        ),
        (
            EVENT_R2O_TCP_FIN_RETRY,
            R2oTcpFinRetryEvent {
                key: tcp_key,
                client_is_low: false,
                planned: false,
            }
            .event_body()
            .unwrap(),
            R2oFlowJournalKind::R2oTcpFinRetry,
            0,
            0,
            0,
            6,
        ),
        (
            EVENT_R2O_TCP_REPEAT,
            R2oTcpRepeatEvent {
                key: tcp_key,
                client_is_low: true,
                planned: true,
            }
            .event_body()
            .unwrap(),
            R2oFlowJournalKind::Suspect,
            1,
            0,
            0,
            2,
        ),
        (
            EVENT_R2O_TCP_RST_AFTER_APP,
            R2oTcpRstAfterAppEvent {
                key: tcp_key,
                client_is_low: true,
                planned: true,
            }
            .event_body()
            .unwrap(),
            R2oFlowJournalKind::R2oTcpRstAfterApp,
            1,
            0,
            0,
            5,
        ),
    ];
    let mut журнал = R2oFlowJournal::with_capacity(cases.len()).unwrap();

    for (index, (event_type, body, kind, planned, elapsed_ms, num, code)) in
        cases.iter().enumerate()
    {
        assert!(журнал.record_control_event(index as u64, *event_type, body));
        let entry = журнал.get(index).unwrap();
        assert_eq!(entry.kind, *kind);
        assert_eq!(entry.planned, *planned);
        assert_eq!(entry.elapsed_ms, *elapsed_ms);
        assert_eq!(entry.num, *num);
        assert_eq!(entry.code, *code);
        assert_eq!(entry.client_is_low, Some(body[KEY_LEN] == 1));
    }
}
