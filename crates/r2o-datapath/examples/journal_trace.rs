//! Печатает кольцо `flow_journal` в том же виде, что C `journal.c`.
//!
//! C-оракул — `scripts/fixtures/d2o_journal_trace.c`; differential сравнивает
//! retention, порядок, note-тексты и поля записей.

use r2k_core::control::{BindingContext, KEY_LEN};
use r2o_datapath::flow_journal::{R2oFlowJournal, R2oFlowJournalEntry, R2oFlowJournalKind};

const PLAN_ID: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const TRIAL_ID: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

fn key() -> [u8; KEY_LEN] {
    let mut key = [0; KEY_LEN];
    key[0] = 4;
    key[1..5].copy_from_slice(&[127, 0, 0, 1]);
    key[17..21].copy_from_slice(&[127, 0, 0, 2]);
    key[33..35].copy_from_slice(&0xbb01_u16.to_be_bytes());
    key[35..37].copy_from_slice(&0x01bb_u16.to_be_bytes());
    key[37] = 6;
    key
}

fn hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{byte:02x}");
    }
}

fn main() {
    let key = key();
    let mut retention = R2oFlowJournal::with_capacity(3).unwrap();
    for at_ns in [100, 200, 300, 400, 500] {
        retention.push(R2oFlowJournalEntry {
            at_ns,
            key,
            kind: R2oFlowJournalKind::Hello,
            ..R2oFlowJournalEntry::default()
        });
    }
    println!(
        "retention count={} added={} dropped={}",
        retention.count(),
        retention.added(),
        retention.dropped()
    );

    let mut journal = R2oFlowJournal::with_capacity(10).unwrap();
    let mut hello = R2oFlowJournalEntry {
        at_ns: 1000,
        key,
        kind: R2oFlowJournalKind::Hello,
        ..R2oFlowJournalEntry::default()
    };
    hello.set_name(b"exa\x01mple.com");
    journal.push(hello);
    journal.push(R2oFlowJournalEntry {
        at_ns: 2000,
        key,
        kind: R2oFlowJournalKind::PlanApplied,
        plan_id: PLAN_ID,
        trial_id: TRIAL_ID,
        ..R2oFlowJournalEntry::default()
    });
    journal.push(R2oFlowJournalEntry {
        at_ns: 3000,
        key,
        kind: R2oFlowJournalKind::PlanRefused,
        code: 5,
        note: Some("своя причина"),
        plan_id: PLAN_ID,
        trial_id: TRIAL_ID,
        ..R2oFlowJournalEntry::default()
    });
    journal.push(R2oFlowJournalEntry {
        at_ns: 4000,
        key,
        kind: R2oFlowJournalKind::Exchange,
        code: 22,
        num: 1234,
        tos: 0x88,
        server_hello: true,
        planned: 2,
        ..R2oFlowJournalEntry::default()
    });
    journal.push(R2oFlowJournalEntry {
        at_ns: 5000,
        key,
        kind: R2oFlowJournalKind::Shape,
        ..R2oFlowJournalEntry::default()
    });
    journal.push(R2oFlowJournalEntry {
        at_ns: 6000,
        key,
        kind: R2oFlowJournalKind::Suspect,
        code: 1,
        ttl: 63,
        reference_ttl: 64,
        tos: 0x88,
        ip_id: 0x4321,
        planned: 1,
        client_shape: 8,
        ..R2oFlowJournalEntry::default()
    });
    journal.push(R2oFlowJournalEntry {
        at_ns: 7000,
        key,
        kind: R2oFlowJournalKind::PlanDone,
        execution_id: 0x1122_3344_5566_7788,
        binding: Some(BindingContext {
            generation: 0x0102_0304_0506_0708,
            kind: 1,
            family: 4,
            shape: 1,
            temporary: false,
            epoch: [0x11; 16],
        }),
        plan_id: PLAN_ID,
        trial_id: TRIAL_ID,
        ..R2oFlowJournalEntry::default()
    });
    journal.push(R2oFlowJournalEntry {
        at_ns: 8000,
        key,
        kind: R2oFlowJournalKind::PlanUnsent,
        code: 3,
        plan_id: PLAN_ID,
        trial_id: TRIAL_ID,
        ..R2oFlowJournalEntry::default()
    });
    journal.push(R2oFlowJournalEntry {
        at_ns: 9000,
        key,
        kind: R2oFlowJournalKind::PlanDamaged,
        code: 4,
        plan_id: PLAN_ID,
        trial_id: TRIAL_ID,
        ..R2oFlowJournalEntry::default()
    });

    println!(
        "summary count={} added={} dropped={}",
        journal.count(),
        journal.added(),
        journal.dropped()
    );
    for entry in journal.iter() {
        let name = String::from_utf8_lossy(&entry.name[..usize::from(entry.name_len)]);
        print!(
            "entry at={} kind={} code={} name={} note={} plan=",
            entry.at_ns,
            entry.kind.c_name(),
            entry.code,
            name,
            entry.note.unwrap_or("")
        );
        hex(&entry.plan_id);
        print!(" trial=");
        hex(&entry.trial_id);
        let binding = entry.binding.unwrap_or_default();
        print!(
            " exec={} binding={}/{}/{}/{}/{}/",
            entry.execution_id,
            binding.generation,
            binding.kind,
            binding.family,
            binding.shape,
            u8::from(binding.temporary)
        );
        hex(&binding.epoch);
        println!();
    }
}
