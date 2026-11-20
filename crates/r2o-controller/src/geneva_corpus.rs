//! Эталонные строки geneva_c для дифференциальных тестов парсера.
//!
//! Сгенерировано на ПК из geneva_c: 145 записей `tests/geneva_strategies.h`
//! и 58 записей `src/library_data.h` после `strategy_parse` + `strategy_print`.
//! Для невалидных корпусных записей `canonical` содержит текст ошибки C.

/// Одна запись корпуса Geneva.
pub struct GenevaCorpusEntry {
    pub text: &'static str,
    pub ok: bool,
    pub canonical: &'static str,
}

/// `tests/geneva_strategies.h`: 130 валидных и 15 негативных записей.
pub static CORPUS: &[GenevaCorpusEntry] = &[
    GenevaCorpusEntry {
        text: "\\/",
        ok: true,
        canonical: "\\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:replace:25776},),)-",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:replace:25776},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{IP:ttl:replace:10},),)-",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{IP:ttl:replace:10},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:flags:replace:FRAPUN},),)-",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:flags:replace:FRAPUN},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:ack:corrupt},),)-",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:ack:corrupt},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{TCP:options-wscale:corrupt}(tamper{TCP:dataofs:replace:8},),)-",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{TCP:options-wscale:corrupt}(tamper{TCP:dataofs:replace:8},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:chksum:corrupt},),)-",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:chksum:corrupt},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{IP:ttl:replace:8}(duplicate(fragment{tcp:-1:False},),),),)-",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{IP:ttl:replace:8}(duplicate(fragment{tcp:-1:False},),),),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:ack:corrupt}(duplicate(fragment{tcp:-1:False},),),),)-",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:ack:corrupt}(duplicate(fragment{tcp:-1:False},),),),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:10},))-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:10},))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:9},),)-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:9},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:RA},),)-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:RA},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:replace:27925},))-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:replace:27925},))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:replace:27925},),)-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:replace:27925},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},))-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},),)-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},),)-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{TCP:ack:corrupt},),)-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{TCP:ack:corrupt},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:ack:corrupt},))-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:ack:corrupt},))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},))-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},),)-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FREACN}(tamper{IP:ttl:replace:10},))-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FREACN}(tamper{IP:ttl:replace:10},))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{IP:ttl:replace:10},),)-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{IP:ttl:replace:10},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUN}(tamper{TCP:options-md5header:corrupt},))-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUN}(tamper{TCP:options-md5header:corrupt},))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:options-md5header:corrupt},),)-",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:options-md5header:corrupt},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-tamper{TCP:load:replace:a5z2}(tamper{TCP:flags:replace:CN},)-",
        ok: true,
        canonical: "[TCP:flags:A]-tamper{TCP:load:replace:a5z2}(tamper{TCP:flags:replace:CN},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-fragment{tcp:8:False}-|[TCP:flags:A]-tamper{TCP:seq:replace:2258679050}-",
        ok: true,
        canonical: "[TCP:flags:PA]-fragment{tcp:8:False}-| [TCP:flags:A]-tamper{TCP:seq:replace:2258679050}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-fragment{tcp:8:False}-| [TCP:flags:A]-tamper{TCP:seq:replace:2258679050}(tamper{TCP:flags:replace:PA},)-",
        ok: true,
        canonical: "[TCP:flags:PA]-fragment{tcp:8:False}-| [TCP:flags:A]-tamper{TCP:seq:replace:2258679050}(tamper{TCP:flags:replace:PA},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-fragment{tcp:8:True}(,fragment{tcp:4:True})-",
        ok: true,
        canonical: "[TCP:flags:PA]-fragment{tcp:8:True}(,fragment{tcp:4:True})-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-fragment{tcp:4:True}(,fragment{tcp:19:True})-",
        ok: true,
        canonical: "[TCP:flags:PA]-fragment{tcp:4:True}(,fragment{tcp:19:True})-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:68},),)-| \\/",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:68},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:SA]-duplicate(tamper{TCP:flags:replace:FREC}(duplicate,),tamper{TCP:flags:replace:FSEC})-| \\/",
        ok: true,
        canonical: "[TCP:flags:SA]-duplicate(tamper{TCP:flags:replace:FREC}(duplicate,),tamper{TCP:flags:replace:FSEC})-| \\/",
    },
    GenevaCorpusEntry {
        text: "\\/ [UDP:sport:53:2]-drop-",
        ok: true,
        canonical: "\\/ [UDP:sport:53:2]-drop-|",
    },
    GenevaCorpusEntry {
        text: "[TCP:options-altchksum:]-tamper{TCP:options-uto:corrupt}(duplicate,)-| \\/",
        ok: true,
        canonical: "[TCP:options-altchksum:]-tamper{TCP:options-uto:corrupt}(duplicate,)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:options-mss:]-tamper{TCP:options-md5header:corrupt}-| \\/",
        ok: true,
        canonical: "[TCP:options-mss:]-tamper{TCP:options-md5header:corrupt}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:9},)-| \\/",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:9},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{IP:len:replace:64},)-|",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{IP:len:replace:64},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-fragment{tcp:-1:True}-|",
        ok: true,
        canonical: "[TCP:flags:PA]-fragment{tcp:-1:True}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:SA]-tamper{TCP:window:replace:98}-|",
        ok: true,
        canonical: "[TCP:flags:SA]-tamper{TCP:window:replace:98}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate(tamper{IP:len:replace:78},)-|",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate(tamper{IP:len:replace:78},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:S]-duplicate(,tamper{TCP:load:corrupt})-|",
        ok: true,
        canonical: "[TCP:flags:S]-duplicate(,tamper{TCP:load:corrupt})-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:SA},)-|",
        ok: true,
        canonical: "[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:SA},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-tamper{TCP:flags:replace:F}-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-tamper{TCP:flags:replace:F}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:seq:corrupt}(tamper{TCP:flags:replace:R},),)-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:seq:corrupt}(tamper{TCP:flags:replace:R},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "\\/ [TCP:dataofs:5]-drop-|",
        ok: true,
        canonical: "\\/ [TCP:dataofs:5]-drop-|",
    },
    GenevaCorpusEntry {
        text: "\\/ [TCP:flags:R]-drop-|",
        ok: true,
        canonical: "\\/ [TCP:flags:R]-drop-|",
    },
    GenevaCorpusEntry {
        text: "\\/ [TCP:window:8192]-drop-|",
        ok: true,
        canonical: "\\/ [TCP:window:8192]-drop-|",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14239},),))-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14239},),))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:15239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:seq:corrupt}(tamper{TCP:chksum:corrupt},),),))-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:15239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:seq:corrupt}(tamper{TCP:chksum:corrupt},),),))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-tamper{TCP:dataofs:replace:0}-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-tamper{TCP:dataofs:replace:0}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:dataofs:replace:0},)-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:dataofs:replace:0},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[UDP:dport:53]-tamper{DNS:qd:compress}-|",
        ok: true,
        canonical: "[UDP:dport:53]-tamper{DNS:qd:compress}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:S]-sleep{1}-|",
        ok: true,
        canonical: "[TCP:flags:S]-sleep{1}-| \\/",
    },
    GenevaCorpusEntry {
        text: "\\/ [TCP:flags:SA]-sleep{1}-|",
        ok: false,
        canonical: "action sleep cannot be used in the inbound forest",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-trace{2:10}-|",
        ok: true,
        canonical: "[TCP:flags:PA]-trace{2:10}-| \\/",
    },
    GenevaCorpusEntry {
        text: "\\/ [TCP:flags:SA]-drop-|",
        ok: true,
        canonical: "\\/ [TCP:flags:SA]-drop-|",
    },
    GenevaCorpusEntry {
        text: "\\/ [UDP:dport:100]-drop-|",
        ok: true,
        canonical: "\\/ [UDP:dport:100]-drop-|",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-sleep{1}-|",
        ok: true,
        canonical: "[TCP:flags:PA]-sleep{1}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-drop-|",
        ok: true,
        canonical: "[TCP:flags:PA]-drop-| \\/",
    },
    GenevaCorpusEntry {
        text: "[UDP:dport:53]-sleep{1}-|",
        ok: true,
        canonical: "[UDP:dport:53]-sleep{1}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[UDP:dport:53]-drop-|",
        ok: true,
        canonical: "[UDP:dport:53]-drop-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-tamper{DNS:qd:compress}-|",
        ok: true,
        canonical: "[TCP:flags:PA]-tamper{DNS:qd:compress}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-drop-| [TCP:flags:FPA]-drop-|",
        ok: true,
        canonical: "[TCP:flags:PA]-drop-| [TCP:flags:FPA]-drop-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:SA]-drop-|",
        ok: true,
        canonical: "[TCP:flags:SA]-drop-| \\/",
    },
    GenevaCorpusEntry {
        text: "\\/ [UDP:dport:53]-drop-|",
        ok: true,
        canonical: "\\/ [UDP:dport:53]-drop-|",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-| \\/",
        ok: true,
        canonical: "[TCP:flags:PA]-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-drop-| \\/",
        ok: true,
        canonical: "[TCP:flags:PA]-drop-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:thisdontexist:1]-drop-|",
        ok: false,
        canonical: "unknown field \"thisdontexist\" for TCP in trigger",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-duplicate-|",
        ok: true,
        canonical: "[TCP:flags:PA]-duplicate-| \\/",
    },
    GenevaCorpusEntry {
        text: "[IP:proto:6:0]-tamper{IP:proto:replace:6}(fragment{ip:-1:True}(tamper{TCP:dataofs:replace:8}(duplicate,),tamper{IP:frag:replace:0}),)-| [IP:tos:0:0]-duplicate-| \\/",
        ok: true,
        canonical: "[IP:proto:6:0]-tamper{IP:proto:replace:6}(fragment{ip:-1:True}(tamper{TCP:dataofs:replace:8}(duplicate,),tamper{IP:frag:replace:0}),)-| [IP:tos:0:0]-duplicate-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:urgptr:0]-tamper{TCP:options-altchksumopt:corrupt}(fragment{tcp:-1:True}(tamper{IP:proto:corrupt},tamper{TCP:seq:replace:654077552}),)-| \\/",
        ok: true,
        canonical: "[TCP:urgptr:0]-tamper{TCP:options-altchksumopt:corrupt}(fragment{tcp:-1:True}(tamper{IP:proto:corrupt},tamper{TCP:seq:replace:654077552}),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:options-mss:]-tamper{TCP:load:replace:}(fragment{tcp:-1:True},)-| \\/",
        ok: true,
        canonical: "[TCP:options-mss:]-tamper{TCP:load:replace:}(fragment{tcp:-1:True},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:options-mss:]-tamper{IP:frag:replace:1353}(tamper{TCP:load:replace:}(fragment{tcp:-1:True},),)-| \\/",
        ok: true,
        canonical: "[TCP:options-mss:]-tamper{IP:frag:replace:1353}(tamper{TCP:load:replace:}(fragment{tcp:-1:True},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[IP:ihl:5]-duplicate-| [TCP:options-mss:]-tamper{IP:frag:replace:1353}(fragment{tcp:-1:True}(tamper{TCP:load:replace:}(fragment{tcp:-1:False},),tamper{DNSQR:qtype:replace:45416}),)-| \\/",
        ok: true,
        canonical: "[IP:ihl:5]-duplicate-| [TCP:options-mss:]-tamper{IP:frag:replace:1353}(fragment{tcp:-1:True}(tamper{TCP:load:replace:}(fragment{tcp:-1:False},),tamper{DNSQR:qtype:replace:45416}),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[DNSQR:qclass:25989]-duplicate(duplicate(tamper{DNSQR:qtype:replace:30882},),tamper{UDP:sport:replace:42042})-| [TCP:options-nop:]-tamper{TCP:options-nop:corrupt}(tamper{TCP:load:replace:mjkuskjzgy}(tamper{IP:frag:replace:410}(fragment{tcp:-1:True},),),)-| \\/",
        ok: true,
        canonical: "[DNSQR:qclass:25989]-duplicate(duplicate(tamper{DNSQR:qtype:replace:30882},),tamper{UDP:sport:replace:42042})-| [TCP:options-nop:]-tamper{TCP:options-nop:corrupt}(tamper{TCP:load:replace:mjkuskjzgy}(tamper{IP:frag:replace:410}(fragment{tcp:-1:True},),),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:load:TYPE%20A%0D%0A]-drop-| \\/",
        ok: true,
        canonical: "[TCP:load:TYPE%20A%0D%0A]-drop-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-| \\/",
    },
    GenevaCorpusEntry {
        text: "\\/ [TCP:flags:A]-|",
        ok: true,
        canonical: "\\/ [TCP:flags:A]-|",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(duplicate(duplicate(duplicate,),),)-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(duplicate(duplicate(duplicate,),),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[IP:version:4]-| \\/",
        ok: true,
        canonical: "[IP:version:4]-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:corrupt}(duplicate(duplicate,),),)-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:corrupt}(duplicate(duplicate,),),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-tamper{TCP:flags:replace:S}(duplicate,)-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-tamper{TCP:flags:replace:S}(duplicate,)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[IP:frag:0]-fragment{tcp:-1:False}(drop,tamper{TCP:options-altchksum:replace:})-| \\/",
        ok: true,
        canonical: "[IP:frag:0]-fragment{tcp:-1:False}(drop,tamper{TCP:options-altchksum:replace:})-| \\/",
    },
    GenevaCorpusEntry {
        text: "[IP:ihl:0]-fragment{tcp:-1:True}(duplicate,tamper{IP:load:replace:074})-| \\/",
        ok: true,
        canonical: "[IP:ihl:0]-fragment{tcp:-1:True}(duplicate,tamper{IP:load:replace:074})-| \\/",
    },
    GenevaCorpusEntry {
        text: "\\/ [TCP:flags:A]-drop-|",
        ok: true,
        canonical: "\\/ [TCP:flags:A]-drop-|",
    },
    GenevaCorpusEntry {
        text: "[]-asdfasdf",
        ok: false,
        canonical: "malformed trigger \"\" (expected proto:field:value[:gas])",
    },
    GenevaCorpusEntry {
        text: "[TCP:thing:1]-nooooooope",
        ok: false,
        canonical: "unknown field \"thing\" for TCP in trigger",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-sleep{0.5}-|",
        ok: true,
        canonical: "[TCP:flags:A]-sleep{0.5}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:R]-duplicate-| \\/",
        ok: true,
        canonical: "[TCP:flags:R]-duplicate-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:S]-drop-| \\/",
        ok: true,
        canonical: "[TCP:flags:S]-drop-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:R]-drop-| \\/",
        ok: true,
        canonical: "[TCP:flags:R]-drop-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:S]-duplicate-| \\/",
        ok: true,
        canonical: "[TCP:flags:S]-duplicate-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:R]-duplicate(drop,drop)-| \\/",
        ok: true,
        canonical: "[TCP:flags:R]-duplicate(drop,drop)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:S]-duplicate(drop,drop)-| \\/",
        ok: true,
        canonical: "[TCP:flags:S]-duplicate(drop,drop)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:R]-duplicate(drop, drop)-| \\/",
        ok: false,
        canonical: "strategy includes a space in \"[TCP:flags:R]-duplicate(drop, drop)-\"",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:15239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14539}(tamper{TCP:seq:corrupt},),),))-| \\/",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:15239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14539}(tamper{TCP:seq:corrupt},),),))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:load:]-tamper{TCP:load:replace:mhe76jm0bd}(fragment{ip:-1:True}(tamper{IP:load:corrupt},drop),)-| \\/",
        ok: true,
        canonical: "[TCP:load:]-tamper{TCP:load:replace:mhe76jm0bd}(fragment{ip:-1:True}(tamper{IP:load:corrupt},drop),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:options-eol:]-tamper{TCP:load:replace:o}(tamper{TCP:dataofs:replace:11},)-| \\/",
        ok: true,
        canonical: "[TCP:options-eol:]-tamper{TCP:load:replace:o}(tamper{TCP:dataofs:replace:11},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[IP:proto:6]-tamper{IP:proto:replace:125}(fragment{tcp:48:True:26}(tamper{TCP:options-md5header:replace:37f0e737da65224ea03d46c713ed6fd2},),)-| \\/",
        ok: true,
        canonical: "[IP:proto:6]-tamper{IP:proto:replace:125}(fragment{tcp:48:True:26}(tamper{TCP:options-md5header:replace:37f0e737da65224ea03d46c713ed6fd2},),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:PA]-trace{1:3}-| \\/",
        ok: true,
        canonical: "[TCP:flags:PA]-trace{1:3}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:reserved:0]-tamper{TCP:flags:replace:S}-|",
        ok: true,
        canonical: "[TCP:reserved:0]-tamper{TCP:flags:replace:S}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:RA]-tamper{TCP:flags:replace:S}-|",
        ok: true,
        canonical: "[TCP:flags:RA]-tamper{TCP:flags:replace:S}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[IP:ttl:64]-tamper{TCP:flags:replace:S}-|",
        ok: true,
        canonical: "[IP:ttl:64]-tamper{TCP:flags:replace:S}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:reserved:0]-tamper{TCP:chksum:corrupt}-|",
        ok: true,
        canonical: "[TCP:reserved:0]-tamper{TCP:chksum:corrupt}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:S}-|",
        ok: true,
        canonical: "[TCP:flags:0]-tamper{TCP:flags:replace:S}-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R},)-|",
        ok: true,
        canonical: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(duplicate,),)-|",
        ok: true,
        canonical: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(duplicate,),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(duplicate(drop,),),)-|",
        ok: true,
        canonical: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(duplicate(drop,),),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(duplicate(,drop),),)-|",
        ok: true,
        canonical: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(duplicate(,drop),),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:urgptr:15963]-duplicate(,drop)-|",
        ok: true,
        canonical: "[TCP:urgptr:15963]-duplicate(,drop)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:urgptr:15963]-drop-|",
        ok: true,
        canonical: "[TCP:urgptr:15963]-drop-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:urgptr:15963]-duplicate-|",
        ok: true,
        canonical: "[TCP:urgptr:15963]-duplicate-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-|",
        ok: true,
        canonical: "[TCP:flags:0]-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14239},),))-|",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14239},),))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R},),),)-|",
        ok: true,
        canonical: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R},),),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-duplicate-|",
        ok: true,
        canonical: "[TCP:flags:0]-duplicate-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},)-|",
        ok: true,
        canonical: "[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},tamper{TCP:flags:replace:R})-|",
        ok: true,
        canonical: "[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},tamper{TCP:flags:replace:R})-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},tamper{TCP:flags:replace:R}(tamper{TCP:flags:replace:A},))-|",
        ok: true,
        canonical: "[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},tamper{TCP:flags:replace:R}(tamper{TCP:flags:replace:A},))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},tamper{TCP:flags:replace:R})-| \\/",
        ok: true,
        canonical: "[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},tamper{TCP:flags:replace:R})-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:]-|",
        ok: false,
        canonical: "malformed trigger \"TCP:\" (expected proto:field:value[:gas])",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-foo-|",
        ok: false,
        canonical: "unknown action \"foo\"",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]--|",
        ok: true,
        canonical: "[TCP:flags:0]-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-duplicate(,,,)-|",
        ok: false,
        canonical: "unknown action \",,\"",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-duplicate()))-|",
        ok: false,
        canonical: "malformed action tree \"duplicate()))\"",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-duplicate(((()-|",
        ok: false,
        canonical: "malformed action tree \"duplicate(((()\"",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-duplicate(,))))-|",
        ok: false,
        canonical: "unknown action \")))\"",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-drop(duplicate,)-|",
        ok: false,
        canonical: "terminal action drop cannot have children",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-drop(duplicate,duplicate)-|",
        ok: false,
        canonical: "drop cannot have a right subtree",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(,duplicate)-|",
        ok: false,
        canonical: "tamper cannot have a right subtree",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(drop,duplicate)-|",
        ok: false,
        canonical: "tamper cannot have a right subtree",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:seq:corrupt},)-|",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:seq:corrupt},)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-|",
        ok: true,
        canonical: "[TCP:flags:A]-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S},))-|",
        ok: true,
        canonical: "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S},))-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(duplicate(,drop),)-|",
        ok: true,
        canonical: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(duplicate(,drop),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:R}(duplicate,)-|",
        ok: true,
        canonical: "[TCP:flags:0]-tamper{TCP:flags:replace:R}(duplicate,)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(duplicate,)-|",
        ok: true,
        canonical: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(duplicate,)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:R}(duplicate(,drop),)-|",
        ok: true,
        canonical: "[TCP:flags:0]-tamper{TCP:flags:replace:R}(duplicate(,drop),)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-drop-|",
        ok: true,
        canonical: "[TCP:flags:0]-drop-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(drop,)-|",
        ok: true,
        canonical: "[TCP:flags:0]-tamper{TCP:flags:replace:S}(drop,)-| \\/",
    },
    GenevaCorpusEntry {
        text: "[TCP:flags:0]-duplicate(drop,drop)-|",
        ok: true,
        canonical: "[TCP:flags:0]-duplicate(drop,drop)-| \\/",
    },
];

/// Каноническая форма 58 записей библиотеки в порядке `GENEVA_LIBRARY`.
pub static LIBRARY_CANONICAL: &[&str] = &[
    "\\/",
    "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:replace:25776},),)-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{IP:ttl:replace:10},),)-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:flags:replace:FRAPUN},),)-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:ack:corrupt},),)-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{TCP:options-wscale:corrupt}(tamper{TCP:dataofs:replace:8},),)-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:chksum:corrupt},),)-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{IP:ttl:replace:8}(duplicate(fragment{tcp:-1:False},),),),)-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:ack:corrupt}(duplicate(fragment{tcp:-1:False},),),),)-| \\/",
    "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \\/",
    "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:10},))-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:9},),)-| \\/",
    "[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:RA},),)-| \\/",
    "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:replace:27925},))-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:replace:27925},),)-| \\/",
    "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},))-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},),)-| \\/",
    "[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},),)-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{TCP:ack:corrupt},),)-| \\/",
    "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:ack:corrupt},))-| \\/",
    "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},))-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},),)-| \\/",
    "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FREACN}(tamper{IP:ttl:replace:10},))-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{IP:ttl:replace:10},),)-| \\/",
    "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUN}(tamper{TCP:options-md5header:corrupt},))-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:options-md5header:corrupt},),)-| \\/",
    "[TCP:flags:A]-tamper{TCP:load:replace:a5z2}(tamper{TCP:flags:replace:CN},)-| \\/",
    "[TCP:flags:PA]-fragment{tcp:8:False}-| [TCP:flags:A]-tamper{TCP:seq:replace:2258679050}-| \\/",
    "[TCP:flags:PA]-fragment{tcp:8:False}-| [TCP:flags:A]-tamper{TCP:seq:replace:2258679050}(tamper{TCP:flags:replace:PA},)-| \\/",
    "[TCP:flags:PA]-fragment{tcp:8:True}(,fragment{tcp:4:True})-| \\/",
    "[TCP:flags:PA]-fragment{tcp:4:True}(,fragment{tcp:19:True})-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:68},),)-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:68},),)-| \\/",
    "[TCP:flags:SA]-duplicate(tamper{TCP:flags:replace:FREC}(duplicate,),tamper{TCP:flags:replace:FSEC})-| \\/",
    "\\/ [UDP:sport:53:2]-drop-|",
    "[TCP:options-altchksum:]-tamper{TCP:options-uto:corrupt}(duplicate,)-| \\/",
    "[TCP:options-mss:]-tamper{TCP:options-md5header:corrupt}-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:9},)-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{IP:len:replace:64},)-| \\/",
    "[TCP:flags:PA]-fragment{tcp:-1:True}-| \\/",
    "[TCP:flags:SA]-tamper{TCP:window:replace:98}-| \\/",
    "[TCP:flags:PA]-fragment{tcp:-1:True}-| \\/",
    "[TCP:flags:PA]-duplicate(tamper{IP:len:replace:78},)-| \\/",
    "[TCP:flags:S]-duplicate(,tamper{TCP:load:corrupt})-| \\/",
    "[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:SA},)-| \\/",
    "[TCP:flags:A]-tamper{TCP:flags:replace:F}-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:seq:corrupt}(tamper{TCP:flags:replace:R},),)-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \\/",
    "\\/ [TCP:dataofs:5]-drop-|",
    "\\/ [TCP:flags:R]-drop-|",
    "\\/ [TCP:window:8192]-drop-|",
    "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14239},),))-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:15239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:seq:corrupt}(tamper{TCP:chksum:corrupt},),),))-| \\/",
    "[TCP:flags:A]-tamper{TCP:dataofs:replace:0}-| \\/",
    "[TCP:flags:A]-duplicate(tamper{TCP:dataofs:replace:0},)-| \\/",
];
