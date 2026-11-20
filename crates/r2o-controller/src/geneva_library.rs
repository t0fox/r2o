//! Библиотека стратегий Geneva (P1, см. `docs/geneva-c-adoption.md`).
//!
//! Источник: geneva_c `src/library_data.h`, сгенерированный из Geneva
//! `library.py` (BSD-3-Clause, Copyright (c) 2020, University of Maryland
//! College Park). Строки стратегий перенесены без изменения; назначение —
//! корпус для парсера/каноникализатора и будущего импорта в R2OP.

/// Запись библиотеки Geneva.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenevaLibraryEntry {
    /// Текст стратегии в языке Geneva.
    pub strategy: &'static str,
    /// Доля успеха в процентах, как её измерила Geneva.
    pub rate: u8,
    /// `china`, `india`, `kazakhstan` или `lab`.
    pub country: &'static str,
    /// `http`, `dns`, `dns_tcp`, `kazakhstan_injected_https`, `echo`.
    pub test_type: &'static str,
    /// Человекочитаемое описание.
    pub description: &'static str,
    /// Стратегия выполняется на сервере, а не на клиенте.
    pub server_side: bool,
    /// Для `lab`: цензоры, которые она обходит (`"6 7 8"`).
    pub censors: Option<&'static str>,
}

/// Фильтр `library.c::library_match`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GenevaLibraryFilter<'a> {
    /// Точное совпадение страны; `None` — все, кроме `lab` (см. `with_lab`).
    pub country: Option<&'a str>,
    /// Точное совпадение типа проверки.
    pub test_type: Option<&'a str>,
    /// Цензор `lab`; префикс `censor` отбрасывается, как в C.
    pub censor: Option<&'a str>,
    /// 0 — любые, 1 — только клиентские, 2 — только серверные.
    pub side: u8,
    /// Минимальная доля успеха.
    pub min_rate: u8,
    /// При `country = None` включать записи `lab`.
    pub with_lab: bool,
}

impl GenevaLibraryFilter<'_> {
    /// Повторяет `library_match`: сначала страна/`lab`, затем тип проверки,
    /// цензор, сторона и минимальная доля успеха.
    pub fn matches(&self, entry: &GenevaLibraryEntry) -> bool {
        let lab = entry.country == "lab";
        if match self.country {
            Some(country) => entry.country != country,
            None => lab && !self.with_lab && self.censor.is_none(),
        } {
            return false;
        }
        if self.test_type.is_some_and(|test| entry.test_type != test) {
            return false;
        }
        if let Some(censor) = self.censor {
            let censor = censor.strip_prefix("censor").unwrap_or(censor);
            let matches = entry
                .censors
                .is_some_and(|list| list.split(' ').any(|word| word == censor));
            if !matches {
                return false;
            }
        }
        if (self.side == 1 && entry.server_side) || (self.side == 2 && !entry.server_side) {
            return false;
        }
        entry.rate >= self.min_rate
    }
}

impl GenevaLibraryEntry {
    /// Проходит ли запись через фильтр `library_match`.
    pub fn matches(&self, filter: &GenevaLibraryFilter<'_>) -> bool {
        filter.matches(self)
    }
}

/// Все 58 записей в исходном порядке.
pub static GENEVA_LIBRARY: &[GenevaLibraryEntry] = &[
    GenevaLibraryEntry {
        strategy: "\\/",
        rate: 3,
        country: "china",
        test_type: "http",
        description: "No strategy",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:replace:25776},),)-",
        rate: 98,
        country: "china",
        test_type: "http",
        description: "TCP Desync - Increment Dataofs - Corrupt Chksum",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{IP:ttl:replace:10},),)-",
        rate: 98,
        country: "china",
        test_type: "http",
        description: "TCP Desync - Increment Dataofs - Small TTL",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:flags:replace:FRAPUN},),)-",
        rate: 26,
        country: "china",
        test_type: "http",
        description: "TCP Desync - Increment Dataofs - Invalid Flags",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:ack:corrupt},),)-",
        rate: 94,
        country: "china",
        test_type: "http",
        description: "TCP Desync - Increment Dataofs - Corrupt ACK",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{TCP:options-wscale:corrupt}(tamper{TCP:dataofs:replace:8},),)-",
        rate: 98,
        country: "china",
        test_type: "http",
        description: "TCP Desync - Increment Dataofs - Corrupt WScale",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:chksum:corrupt},),)-",
        rate: 98,
        country: "china",
        test_type: "http",
        description: "TCP Desync - Invalid Payload - Corrupt Chksum",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{IP:ttl:replace:8}(duplicate(fragment{tcp:-1:False},),),),)-",
        rate: 98,
        country: "china",
        test_type: "http",
        description: "TCP Desync - Invalid Payload - Small TTL",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:ack:corrupt}(duplicate(fragment{tcp:-1:False},),),),)-",
        rate: 93,
        country: "china",
        test_type: "http",
        description: "TCP Desync - Invalid Payload - Corrupt ACK",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-",
        rate: 95,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST - Corrupt Chksum, High Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-",
        rate: 51,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST - Corrupt Chksum, Low Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:10},))-",
        rate: 87,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST - Small TTL, High Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:9},),)-",
        rate: 52,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST - Small TTL, Low Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-",
        rate: 86,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST - Invalid md5Header, High Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:RA},),)-",
        rate: 44,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST - Invalid md5Header, Low Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:replace:27925},))-",
        rate: 90,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST/ACK - Corrupt Chksum, High Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:replace:27925},),)-",
        rate: 66,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST/ACK - Corrupt Chksum, High Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},))-",
        rate: 94,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST/ACK - Small TTL, High Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},),)-",
        rate: 57,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST/ACK - Small TTL, Low Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-",
        rate: 94,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST/ACK - Invalid md5Header, High Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},),)-",
        rate: 48,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST/ACK - Invalid md5Header, Low Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{TCP:ack:corrupt},),)-",
        rate: 43,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST/ACK - Corrupt ACK, High Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:ack:corrupt},))-",
        rate: 31,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - with RST/ACK - Corrupt ACK, Low Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},))-",
        rate: 89,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - Invalid Flags - Corrupt Chksum, High Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},),)-",
        rate: 48,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - Invalid Flags - Corrupt Chksum, Low Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FREACN}(tamper{IP:ttl:replace:10},))-",
        rate: 96,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - Invalid Flags - Small TTL, High Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{IP:ttl:replace:10},),)-",
        rate: 56,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - Invalid Flags - Small TTL, Low Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUN}(tamper{TCP:options-md5header:corrupt},))-",
        rate: 94,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - Invalid Flags - Invalid md5Header, High Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:options-md5header:corrupt},),)-",
        rate: 55,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - Invalid Flags - Invalid md5Header, Low Percentage",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-tamper{TCP:load:replace:a5z2}(tamper{TCP:flags:replace:CN},)-",
        rate: 0,
        country: "china",
        test_type: "http",
        description: "TCB Teardown - Invalid Flags - Invalid Payload",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-fragment{tcp:8:False}-|[TCP:flags:A]-tamper{TCP:seq:replace:2258679050}-",
        rate: 92,
        country: "china",
        test_type: "http",
        description: "Segmentation - With ACK - Offsets, subvariant 1",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-fragment{tcp:8:False}-| [TCP:flags:A]-tamper{TCP:seq:replace:2258679050}(tamper{TCP:flags:replace:PA},)-",
        rate: 95,
        country: "china",
        test_type: "http",
        description: "Segmentation - With ACK - Offsets, subvariant 2",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-fragment{tcp:8:True}(,fragment{tcp:4:True})-",
        rate: 98,
        country: "china",
        test_type: "http",
        description: "Segmentation - Reassembly - Offsets, subvariant 1",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-fragment{tcp:4:True}(,fragment{tcp:19:True})-",
        rate: 96,
        country: "china",
        test_type: "http",
        description: "Segmentation - Reassembly - Offsets, subvariant 2",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:68},),)-| \\/",
        rate: 53,
        country: "china",
        test_type: "http",
        description: "Hybrid Strategy - HTTP - Fragment and set Fin flag",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:68},),)-| \\/",
        rate: 100,
        country: "china",
        test_type: "dns_tcp",
        description: "Hybrid Strategy - DNS Over TCP - Fragment and set Fin flag",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:SA]-duplicate(tamper{TCP:flags:replace:FREC}(duplicate,),tamper{TCP:flags:replace:FSEC})-| \\/",
        rate: 43,
        country: "china",
        test_type: "http",
        description: "Server-Side - Simultaneous Open",
        server_side: true,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "\\/ [UDP:sport:53:2]-drop-",
        rate: 96,
        country: "china",
        test_type: "dns",
        description: "DNS - Drop first two bad responses",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:options-altchksum:]-tamper{TCP:options-uto:corrupt}(duplicate,)-| \\/",
        rate: 100,
        country: "india",
        test_type: "http",
        description: "Invalid Options",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:options-mss:]-tamper{TCP:options-md5header:corrupt}-| \\/",
        rate: 100,
        country: "india",
        test_type: "http",
        description: "Invalid Options",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:9},)-| \\/",
        rate: 100,
        country: "india",
        test_type: "http",
        description: "Increasing dataofs",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{IP:len:replace:64},)-|",
        rate: 100,
        country: "india",
        test_type: "http",
        description: "IP length",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-fragment{tcp:-1:True}-|",
        rate: 100,
        country: "india",
        test_type: "http",
        description: "Segmentation",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:SA]-tamper{TCP:window:replace:98}-|",
        rate: 100,
        country: "india",
        test_type: "http",
        description: "Server side",
        server_side: true,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-fragment{tcp:-1:True}-|",
        rate: 100,
        country: "kazakhstan",
        test_type: "kazakhstan_injected_https",
        description: "Segmentation",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:PA]-duplicate(tamper{IP:len:replace:78},)-|",
        rate: 100,
        country: "kazakhstan",
        test_type: "kazakhstan_injected_https",
        description: "Segmentation Exploit - Small IP length",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:S]-duplicate(,tamper{TCP:load:corrupt})-|",
        rate: 100,
        country: "kazakhstan",
        test_type: "kazakhstan_injected_https",
        description: "Desync: load on second SYN",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:SA},)-|",
        rate: 100,
        country: "kazakhstan",
        test_type: "kazakhstan_injected_https",
        description: "TCB Turnaround",
        server_side: false,
        censors: None,
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-tamper{TCP:flags:replace:F}-| \\/",
        rate: 100,
        country: "lab",
        test_type: "echo",
        description: "Interrupts the 3-way handshake with a FIN. The server ignores the FIN, as the 3-way handshake has not been done yet, so there is no connection to teardown. Since the client's very next packet is a PSH-ACK, the ACK in this packet serves to complete the 3-way handshake, but the censor tears down it's TCB at the FIN.",
        server_side: false,
        censors: Some("6 7 8"),
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:seq:corrupt}(tamper{TCP:flags:replace:R},),)-| \\/",
        rate: 100,
        country: "lab",
        test_type: "echo",
        description: "Tears down a TCB right after a 3-way handshake by injecting a RST packet.",
        server_side: false,
        censors: Some("6 7"),
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \\/",
        rate: 100,
        country: "lab",
        test_type: "echo",
        description: "Creates a RST injection packet to tear down a TCB and corrupts the checksum, exploiting a censor that does not validate packet checksums.",
        server_side: false,
        censors: Some("6 7 8 8b"),
    },
    GenevaLibraryEntry {
        strategy: "\\/ [TCP:dataofs:5]-drop-|",
        rate: 100,
        country: "lab",
        test_type: "echo",
        description: "RST Packets (at least those constructed with scapy) have a data offset of 5. This beats a censor that only sends RSTs to the client by dropping the RST packets.",
        server_side: false,
        censors: Some("2"),
    },
    GenevaLibraryEntry {
        strategy: "\\/ [TCP:flags:R]-drop-|",
        rate: 100,
        country: "lab",
        test_type: "echo",
        description: "Beats a censor that only sends RSTs to the client by dropping the RST packets.",
        server_side: false,
        censors: Some("2"),
    },
    GenevaLibraryEntry {
        strategy: "\\/ [TCP:window:8192]-drop-|",
        rate: 100,
        country: "lab",
        test_type: "echo",
        description: "RST Packets (at least those constructed with scapy) have a default window size of 8192. This beats a censor that only sends RSTs to the client by dropping the RST packets.",
        server_side: false,
        censors: Some("2"),
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14239},),))-| \\/",
        rate: 100,
        country: "lab",
        test_type: "echo",
        description: "Triggers a RST packet and SYN packet to be sent immediately after the 3-way handshake finishes. The server ignores the RST, as the chksum is corrupted, and ignores the SYN, as a connection is already up. The censor sees the RST and enters the resynchronization state, and the immediate follow-up SYN packet causes the TCB to be deschronized from the real connection.",
        server_side: false,
        censors: Some("1 2 3 5 6 7 8 8b 9"),
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:15239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:seq:corrupt}(tamper{TCP:chksum:corrupt},),),))-| \\/",
        rate: 100,
        country: "lab",
        test_type: "echo",
        description: "Triggers a RST packet and SYN packet to be sent immediately after the 3-way handshake finishes. The server ignores the RST, as the chksum is corrupted, and ignores the SYN, as a connection is already up. The censor sees the RST and enters the resynchronization state, and the immediate follow-up SYN packet with a new seq causes the TCB to be deschronized from the real connection.",
        server_side: false,
        censors: Some("1 2 3 5 6 7 8 8b 9"),
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-tamper{TCP:dataofs:replace:0}-| \\/",
        rate: 100,
        country: "lab",
        test_type: "echo",
        description: "The dataofs field in the TCP header tells applications where the payload of the packet starts. By replacing the dataofs to 0 on a packet without a payload (ACK), it makes the TCP header look like data. Servers ignore this, but a censor that is trying to keep a TCB synchronized will be desynchronized from the connection when it gets a payload of an incorrect length.",
        server_side: false,
        censors: Some("1 2 3 5 9 10"),
    },
    GenevaLibraryEntry {
        strategy: "[TCP:flags:A]-duplicate(tamper{TCP:dataofs:replace:0},)-| \\/",
        rate: 100,
        country: "lab",
        test_type: "echo",
        description: "The dataofs field in the TCP header tells applications where the payload of the packet starts. By replacing the dataofs to 0 on a packet without a payload (ACK), it makes the TCP header look like data. Servers ignore this, but a censor that is trying to keep a TCB synchronized will be desynchronized from the connection when it gets a payload of an incorrect length. This strategy is functionally equivalent to the above strategy, but also preserves the original packet.",
        server_side: false,
        censors: Some("1 2 3 5 9 10"),
    },
];
