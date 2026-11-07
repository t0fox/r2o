# Аудит паритета datapath и detect: D2O (C) → R2O (Rust)

Дата аудита: 2026-11-07. Аудитор: субагент, только чтение исходников и существующих доказательств.
Ничего не собиралось и не запускалось; Git/Cargo/Rustc в PATH отсутствуют.

Источники:

- D2O: `E:\d2o\datapath\*.c` (production, кроме `test_*`, `planlab.c`, `ctlprobe.c`) и `E:\d2o\detect\*.c`.
- R2O: `crates/r2o-datapath/src`, `crates/r2k-core/src`, `crates/r2o-controller/src`, `crates/*/tests`, `scripts/*.sh`.
- Документы: `docs/functional-parity-matrix.md`, `docs/parity-function-inventory.md`.

## Краткое резюме

1. **Функционального паритета datapath/detect нет.** Существующий инвентарь модульный, матрица объединяет в одной строке контракты с разными гарантиями (NFQUEUE + парсер + цикл демона; `session.c` + `track.c`; `capture/tls/wire/addr`; `hold/udp_hold/udp_release`; `plan_parse/plan_apply/plans`; `raw/routemark`; `nat/ctq`; `http80/http_trace`; все 8 файлов detect). Ни одна строка не является доказательством пофункционального паритета.
2. **План несовместим по проводу.** C `d2k_plan_load` принимает `D2KP`, R2O `Plan::parse` принимает только `R2OP` (`crates/r2k-core/src/plan.rs:11`, `:159`). Внутренние TLV-записи совпадают численно, но C-план (файл или план от D2O-контроллера) R2O отвергнет с «не план r2o». Это не эквивалентность `plan_parse`, а другой контейнер.
3. **Управляющий протокол несовместим по версии и событиям.** C `D2K_CTL_PROTO_VERSION = 22`, R2O `PROTOCOL_VERSION = 48` (`crates/r2k-core/src/control.rs:7`). C `D2K_EV_CLIENT_TCP = 0x000D`, R2O `EVENT_R2O_VOICE_SUSPECT = 0x000D`; R2O добавил события `0x000e..0x001e`. Команды почти совпадают, но датапат и контроллер D2O/R2O взаимно несовместимы.
4. **Ёмкости таблиц планов расходятся.** C: одна таблица имён+адресов ёмкостью `--flows` (по умолчанию 2048) и отдельная таблица probe-записей той же ёмкости. R2O: `MAX_NAME_PLANS = 128`, `MAX_ADDR_PLANS = 128`, `MAX_ADDR_PROBES = 64`, `MAX_VOICE_ADDR_* = 128/64`, `MAX_SUFFIX_PLANS = 64`, `MAX_DOMAIN_BYPASSES = 256` (`crates/r2o-datapath/src/control.rs:25-34`). При 129-й цели R2O откажет там, где C ещё принимает (C ещё и вытесняет LRU, R2O отказывает).
5. **Кольцо управления больше.** C `D2K_CTL_OUT_RING = 65536`, R2O `MAX_CONTROL_OUTPUT = 128 * 1024`. Разное поведение при переполнении и разный счётчик dropped (C теряет кадр при нехватке места в 64 КиБ; R2O — в 128 КиБ).
6. **HTTP80-ёмкость больше.** C `D2K_HTTP80_FLOWS = 128`, R2O `HTTP_FLOW_CAPACITY = 1024` (`hold.rs:20`). C `D2K_HTTP80_NAMES = 256` совпадает с `MAX_HTTPS_NAMES = 256`; C `D2K_HTTP80_TARGET_MAX = 1024` совпадает с пределом target в hold.
7. **`tcp_ts_up` не реализован в R2O.** C `D2K_POISON_TS_UP (1u<<4)` (`d2k_plan.h:89`) и `wire.c:159` переставляют опцию TCP timestamp в начало заголовка. В R2O нет ни константы, ни поля `ts_up`, ни логики в `r2k-core/src/wire.rs`; C-тест `test_wire.c` проверяет это, R2O-тест отсутствует.
8. **Нет Rust-аналога `d2k_http_trace`.** C печатает строку `d2kd: HTTP execution host=... hook=... status=...` на каждое HTTP-исполнение (`datapath/http_trace.c:9`). В R2O такой текстовой трассы нет; есть только события/журнал.
9. **HTTP80-статистика и часть сводки отсутствуют.** C печатает `HTTP: запросов ..., вставок ..., потоков вытеснено ...; ...`, владение приветствием (`hold_owned/resent/fail`), NAT-статистику, routed flows, UDP marked, shape misses, plan count/capacity и причины пропуска (`d2kd.c:893-1028`). R2O `r2o_log_*` (`main.rs:612-763`) не печатает эти контракты; `test-datapath-stats-timer-differential.sh` сверяет только подмножество строк.
10. **CLI datapath неполон.** C `d2kd` поддерживает `--log FILE`, `--duration SEC`, `--health-file PATH`, `--udp-reverse-hook`; R2O `parse_options` (`main.rs:2630-2752`) их не знает или переименовал (`--r2o-udp-reverse-visible`, `--r2o-flow-capacity`), зато добавил `--family`, `--rcvbuf`, `--check`, `--controller-only`. C `--version`/`--offline-self-check` включает SHA256-самопроверку; R2O печатает только release/wire.
11. **IPv6 datapath — расширение R2O без C-oracle.** C `d2k_nfq_open` жёстко передаёт `AF_INET` (`nfq.c:204-222`). R2O принимает `AF_INET`/`AF_INET6` (`nfqueue.rs:115-186`). Все IPv6 NFQUEUE-тесты R2O не имеют C-эталона; это зафиксировано и в матрице.
12. **Scheduler R2O содержит контракты, которых нет в C.** C `sched.c` — только куча `(due_ns, seq)`, владение ID и отказы; отмены/резервирования flow в API нет. R2O `Scheduler.rs` добавляет `reserve`, `push_reserved`, `cancel`, `cancel_flow`, `cancel_direction`, `expire` по flow. Это расширение, а не перенос.
13. **Detect-паритет также частичный.** Есть сильные C/Rust-дифференциалы по дереву классификатора, response-направлению, raw-профилям и poison; но `cross_check_tls12` в C — честная заглушка, в R2O отсутствует; `--json` R2O не печатает C-поле `notes`; человеческий вывод R2O не совпадает с C; композиция свойств без control в R2O не создаёт кандидата «всё сразу», а C создаёт; `poison_has_fake` R2O не учитывает `autottl` (сегодня поле не выставляется, но контракт уже).
14. **Detect default SO_MARK расходится.** C `d2k_opts_defaults` ставит `D2K_BYPASS_MARK = 0x40000000`; R2O `BYPASS_MARK = 0x2d` (`response.rs:71`, `raw_probe.rs` `effective_mark`). Без явного `--mark` C и R2O шлют зонды с разными метками; это влияет на обход firewall и на измерение.
15. **NAT/conntrack gate R2O — расширение.** C datapath только проверяет наличие записи NAT/таблицы (`nat.c`, `ctq.c`) и полагается на ядро. R2O `r2o_conntrack_gate.rs` переписывает фрагменты и принимает решения о late-mark/queue; прямого C-аналога нет.
16. **Текущий подтверждённый процент не пересчитывается в этом аудите.** Ниже даны относительные веса и статусы без начисления баллов; существующие 19/89 datapath и 14/14 classifier/TLS нельзя подтвердить на функциональном уровне.

## Легенда статусов

- `equivalent (scoped)` — есть конкретный C/Rust дифференциал или байтовое сравнение, покрывающее заявленный узкий контракт; вне него эквивалентность не заявляется.
- `partial` — Rust-реализация есть, часть ветвей/состояний покрыта тестами, но нет полного дифференциала или есть расхождения.
- `implemented-unproven` — код есть, но ни один существующий тест/дифференциал не покрывает функцию (только компиляция/наличие).
- `missing` — Rust-аналога нет.
- `not-applicable` — C-контракт сам является заглушкой/не production-поведением, либо функция вне scope.

---

## Таблицы datapath по файлам

Правило группировки: строки с самостоятельным алгоритмом (`main`, `handle_udp`, `session_packet`, `d2k_plan_apply`, `d2k_raw_probe_poison_family`, `d2k_classify_run`, `sched_tcp` и т.п.) выделены отдельно; остальные строки объединяют однотипные helpers/accessors, причём все члены группы перечислены в первой колонке. Если для группы указан один статус, он относится к худшей из непроверенных ветвей группы, а не к каждой функции по отдельности.

### addr.c (3 функции)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `d2k_addr_parse` | `r2k-core/src/addr.rs:11 Address::parse` | `PacketView`, control-команды, plan-команды | IPv4/IPv6 `inet_pton`-семантика, отказ на `%zone`, пустой/невалидный текст | Нет прямого C/Rust дифференциала; `%scope` отвергается и там, и там | `r2k-core/tests/network.rs:6 address_literals_round_trip_without_scope_ids`, `:22 invalid_address_forms_are_rejected` | partial |
| `d2k_addr_text` | `r2k-core/src/addr.rs:19 Address::family`, `:31 bytes` + `Display`/`ToSocketAddrs` | журнал, события, control | IPv4/IPv6 текст, отказ при `cap==0`, `n>=cap` | Нет функции с точным контрактом «0 при нехватке буфера»; Rust использует `format!`, отдельного предела нет | те же network-тесты | partial |
| `d2k_addr_equal` | `r2k-core/src/addr.rs` (`PartialEq`), `:26 as_ip_addr` | поиск планов, route gate | Семейство+байты | Нет теста на «разные семейства с одинаковыми байтами» | network-тесты косвенно | partial |

### capture.c (6 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `same` (static, `d2k_key_equal`) | `TcpFlowKey`/`R2oUdpFlowKey` `Eq` (`capture.rs:23`, `r2o_udp_sessions.rs:37`) | ключи capture | канонический ключ потока | — | unit-тесты capture | partial |
| `d2k_capture_forget` | `CaptureTable::forget` (`capture.rs:650`) | `HoldTable` release, ready, reset | удаление всех слотов ключа | — | `capture.rs` unit | partial |
| `reject` (static) | `CaptureTable::reject_result` (`capture.rs:662`) | конфликт перекрытия | state=2, `rejected++`, отказ | — | `conflicting_overlap_poisoning_requires_a_new_generation_or_forget` (`capture.rs:949`) | partial |
| `d2k_capture_feed_ready` | `CaptureTable::feed_mode` (`capture.rs:514`), `feed` (`:446`), `feed_http` (`:480`) | `HoldTable::feed` (`hold.rs:298`) | TTL, generation, anchor, out-of-order, overlap, wrap, truncation, capacity, ready callback | Нет C/Rust дифференциала полного потока; C `rejected`/`full`/`expired` счётчики сверяются только unit-трассами | `capture.rs:989 capture_lifecycle_traces_match_d2o`, `:1099 capture_size_limit_traces_match_d2o`, `:1146`, `:1173`, `:1209`; D2O `test_capture.c` | partial |
| `tls_ready` (static) | `CaptureTable::tls_ready` (`capture.rs:673`) | TLS capture | record/handshake length, `total<9`, `high>total`, `hs+9!=total`, `n==total` | Нет отдельного differential только для `tls_ready` | `capture.rs` unit, `capture_shape.rs` | partial |
| `d2k_capture_feed` | `CaptureTable::feed` (`capture.rs:446`) | `HoldTable::feed` TLS | то же с `tls_ready` | — | см. выше | partial |

### http_trace.c (1 функция)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `d2k_http_trace` | — | — | — | **Функции нет.** C печатает `d2kd: HTTP execution host=%s IPv%u ... status=... prepared=... plan=... execution=... planned/raw_sent/queued/original/output_failed/reason` (`http_trace.c:39`). R2O не формирует эту строку ни в `main.rs`, ни в `flow_journal.rs`; события HTTP есть, текстовой трассы нет. | C `test_http_trace.c`; R2O аналога нет | missing |

### hold.c (12 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `r32`, `same` (static) | `HoldTable::parse_tcp` (`hold.rs:1245`), `TcpFlowKey` `Eq` | разбор удержанного TCP | big-endian seq/ack/flags, ключ | — | unit `hold.rs` | partial |
| `d2k_hold_parse` | `HoldTable::parse_tcp` (`hold.rs:1245`) | `feed` (`hold.rs:298`) | IPv4/IPv6, IHL, TCP header, fragment reject, total checks, canonical key, seq/ack/flags | C `v->dst_be`/`sport_be` поля для HTTP; Rust хранит `HttpRequestFlow` отдельно | `hold.rs` unit | partial |
| `d2k_hold_new` | `HoldTable::default` (`hold.rs:190`) | `main.rs:917` | создание | — | unit | partial |
| `d2k_hold_free` | `Drop`/`release_held_packets` (`hold.rs:1232`) | shutdown `main.rs:962` | освобождение | — | unit | partial |
| `release_slot` (static) | `release_held_packets` (`hold.rs:1232`), `remove_slot` (`:1225`) | flush/ready/reject | release каждого ID, capture forget, pending-- | — | unit | partial |
| `d2k_hold_flush` | `HoldTable::flush` (`hold.rs:884`) | `main.rs:1323`, `:1196`, shutdown | all/deadline/revision, `timed_out_pkts`, `plan_changed`, `dropped_all` | C `plan_changed` и `timed_out` одновременно; Rust отдельные тесты есть | `timeout_and_revision_change_fail_open_all_held_ids` (`hold.rs:2196`), `timeout_diagnostic_survives_deadline_and_revision_change_together` (`:2227`), C/Rust fixture `r2o-hold-timeout-revision-2026-11-03` | partial |
| `d2k_hold_next` | `HoldTable::timeout_ms` (`hold.rs:954`) | `main.rs:1168` | ближайший deadline | — | unit | partial |
| `d2k_hold_get_stats` | `HoldTable::r2o_hold_stats` (`hold.rs:200`) | `main.rs:697` | все поля C `d2k_hold_stats` | — | `r2o_log_hold_stats` + stats differential (subset) | partial |
| `d2k_hold_verdicts` | `release_accepting`/`send_verdicts` (`main.rs:3671`, `:3723`) | release batch | неудачные ID считаются, но C возвращает `failed`, Rust логирует | Нет прямого теста «частичный отказ вердикта» для TCP hold | `grouped_release_attempts_every_id_and_falls_back_per_packet` (`main.rs:6370`) | partial |
| `http_ready` (static) | `CaptureTable::http_ready` (`capture.rs:695`) | HTTP capture | полный заголовок, `n!=high`, `\r\n\r\n` reject | — | `hold.rs` HTTP unit | partial |
| `d2k_hold_feed` | `HoldTable::feed` (`hold.rs:298`), `feed_observing` (`:322`), `feed_controller_probe` (`:333`) | `main.rs:1645` | FIFO, limits, flags, ack match, sided, full, mismatch, head selection, stream-order originals, synthetic head, IPv6 total | C `s->kind==D2K_HOLD_HTTP` отдельная ветка; Rust `allow_http`/`observe_http`; нет C/Rust дифференциала полного HTTP hold | `hold.rs:1454`, `:2122`, `:2142`, `:2163`, `:2245`, `:2281`, `:2370`, `:2397` | partial |

### udp_hold.c (10 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `same_key`, `clear_slot` (static) | `R2oUdpFlowKey` `Eq`, `R2oUdpHoldTable` slots | hold UDP | ключ, очистка | — | unit | partial |
| `release_slot` (static) | `r2o_release_batch_with` (`r2o_udp_hold.rs:72`) | flush/overflow | release callback, count | — | unit | partial |
| `d2k_udp_hold_new` | `R2oUdpHoldTable::new` (`r2o_udp_hold.rs:147`) | `main.rs:943` | создание | — | unit | partial |
| `d2k_udp_hold_free` | `r2o_drain` (`r2o_udp_hold.rs:228`) | shutdown `main.rs:1012` | release всех слотов | — | unit | partial |
| `d2k_udp_hold_flush` | `r2o_flush` (`r2o_udp_hold.rs:212`) | `main.rs:1335` | deadline | — | unit | partial |
| `d2k_udp_hold_feed` | `r2o_feed` (`r2o_udp_hold.rs:154`) | `main.rs:1451` | вызов marked с mark=0 | — | `udp_hold.rs` tests | partial |
| `d2k_udp_hold_feed_marked` | `r2o_feed` (`r2o_udp_hold.rs:154`) | `main.rs:1451` | len limit, expiry-before-feed, slot reuse, packet cap overflow | Нет C/Rust дифференциала на «переполнение слота освобождает всю пачку» | `udp_hold.rs` tests | partial |
| `d2k_udp_hold_take` | `r2o_take` (`r2o_udp_hold.rs:198`) | `main.rs:1469` | забор по ключу | — | unit | partial |
| `d2k_udp_hold_next_ns` | `timeout_ms` (`r2o_udp_hold.rs:240`) | `main.rs:1169` | ближайший deadline | — | unit | partial |
| — (C не имеет `drain`) | `r2o_drain` (`r2o_udp_hold.rs:228`) | shutdown | — | R2O-дополнение | unit | not-applicable |

### udp_path.c (7 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `d2k_udp_path_release` | `r2o_release_udp_batch` (`main.rs:152`), `r2o_release_udp_batches` (`:199`) | flush/overflow | закрытие hold-транзакции, выпуск пачки | — | `r2o-udp-exchange-differential.sh`, `udp_hold.rs` | partial |
| `d2k_udp_path_pre` | `main.rs:1448-1496` | UDP hold start | flush expired, begin_hold, feed_marked, откат begin | — | `udp_hold.rs`, `udp_sessions.rs` | partial |
| `d2k_udp_path_post` | `main.rs:1533-1549`, `:2264-2480` | после `decide` | WAIT/READY/LOST/RECLAIMED, replay первой датаграммы, release остальных | Нет C/Rust дифференциала всех четырёх исходов | `udp_hold.rs`, `test-discord-scheduled-udp-differential.sh` | partial |
| `d2k_udp_path_read` | `main.rs:1216 udp_receive_seq` | каждый recv | номер пачки | — | unit | partial |
| `d2k_udp_path_expire` | `udp_holds.r2o_flush`, `r2o_age` (`main.rs:1219`) | каждый цикл | seq=NONE/next, flush по deadline | — | unit | partial |
| `d2k_udp_path_passed` | `r2o_udp_mark_plain_pass` (`main.rs:107`) | ACCEPT без плана | can_resend/follow, IPv4 len>=20, opening, neutral, follow mark | Нет C/Rust дифференциала «поздний хвост» | `r2o-udp-exchange-differential.sh` | partial |
| `d2k_udp_path_planned` | `r2o_udp_mark_planned` (`main.rs:130`) | DROP после плана | neutral emit, follow mark at deadline | — | `r2o-udp-session-table-check.sh` | partial |

### udp_release.c (34 функции)

| C-функция / группа | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `d2k_udp_release_new/free/enqueue/flush/next_ns` | `R2oUdpDeferredVerdicts::{new,enqueue,flush,timeout_ms}` (`r2o_udp_hold.rs:283-392`) | `main.rs:944`, `:2014`, `:2569` | кольцо отложенных вердиктов, capacity, deadline | C ring size 16/8; R2O `R2O_UDP_RELEASE_SLOTS=16`, `R2O_UDP_RELEASE_PACKETS=8`, `new()` без параметров | `udp_hold.rs` unit | partial |
| `next_due` (static) | `timeout_ms` (`r2o_udp_hold.rs:392`) | poll timeout | ближайший срок | — | unit | partial |
| `d2k_udp_replay_fates` | `r2o_release_udp_batches` (`main.rs:199`) | replay | fate batch | — | unit | partial |
| `plain_verdict`, `plain_resend` (static) | `r2o_udp_packet_is_neutral` (`main.rs:87`), `send_verdicts` | обычный UDP | neutral/accept | — | unit | partial |
| `d2k_udp_release_batch` | `r2o_release_udp_batch` (`main.rs:152`) | release batch | per-id verdict, head ordering | — | `test-discord-scheduled-udp-differential.sh` | partial |
| `release_batch`, `again` (static) | `r2o_release_udp_batch`/`release_many` (`main.rs:4165`) | batch release | повтор при busy | — | unit | partial |
| `follow_drop`, `d2k_udp_follow_age/live/busy/queue_full/refused`, `d2k_udp_send_busy` | `R2oUdpFollowTable::{r2o_age,is_empty,r2o_stats,r2o_note_busy,r2o_note_queue_full}` (`r2o_udp_hold.rs:480-623`), `r2o_udp_send_busy` (`:799`) | follow-таблица | возраст, busy/queue_full/refused, статистика | C `follow_live` отдельно; R2O `r2o_age` | `follow_stats_count_busy...` (`:831`), `:852` | partial |
| `d2k_udp_follow_new/free` | `R2oUdpFollowTable::new` (`:480`), `Drop` | `main.rs:946` | создание/освобождение | — | unit | partial |
| `follow_tuple`, `same_tuple`, `follow_put`, `follow_find` (static) | `R2oUdpFollowKey::from_packet` (`:428`), `r2o_mark` (`:508`), `r2o_match` (`:550`) | insert/find | канонический ключ, bucket | — | unit | partial |
| `d2k_udp_follow_mark` | `r2o_mark` (`r2o_udp_hold.rs:508`) | planned/passed | deadline, seq, queue full | — | `udp_hold.rs` unit | partial |
| `d2k_udp_follow_match` | `r2o_match` (`:550`) | late tail | tuple+seq window | — | unit | partial |
| `out_resend` (static) | `r2o_release_udp_batch`/`r2o_udp_handle_late_tail` (`main.rs:225`) | send tail | resend callback | — | unit | partial |
| `d2k_udp_out_owned_emit` | `r2o_cancel_delayed_udp_batch` (`main.rs:387`), owned id path | delayed tail | DROP/ACCEPT по факту send | — | unit | partial |
| `only` (static) | `r2o_udp_packet_is_neutral` | neutral filter | — | — | unit | partial |
| `out_verdict`, `d2k_udp_out_neutral`, `d2k_udp_out_batch`, `d2k_udp_out_late` | `r2o_udp_mark_plain_pass` (`main.rs:107`), `r2o_udp_handle_late_tail` (`:225`), `r2o_release_udp_batches` | обычный/поздний UDP | neutral/planned, batch, late window | C `out_late` 5 мс окно; R2O `r2o_udp_handle_late_tail` с `follow_receive_seq`; нет C/Rust дифференциала всех окон | `r2o-udp-exchange-differential.sh`, `test-discord-scheduled-udp-differential.sh` | partial |
| — | `R2oUdpDeferredResends` (`r2o_udp_hold.rs:658-799`) | retry resend | — | **R2O-расширение:** C `udp_release` не имеет отдельного retry-кольца resend; C `out_send_at_owned` + pending releases иначе | `deferred_resend_*` unit | not-applicable |

### sched.c (16 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `d2k_sched_new` | `ScheduledQueue::with_capacity` (`scheduler.rs:59`) | `main.rs:914` | capacity, overflow guard | — | unit | partial |
| `d2k_sched_grow_slot_size` | — | — | — | **Функции нет.** R2O `WirePacket`/`Vec` растёт динамически; C заранее увеличивает слоты при смене MTU (`cap_refresh`). Эквивалент по поведению не доказан. | — | missing |
| `d2k_sched_free` | `Drop` | shutdown | — | — | unit | partial |
| `earlier`, `sift_up`, `sift_down` (static) | `partition_point`/`entries` сортировка по `(due, order)` (`scheduler.rs:160-173`) | push/pop | стабильный порядок при равных сроках | C двоичная куча; R2O упорядоченный Vec; асимптотика другая, порядок проверен | `scheduled_packets_are_due_ordered_and_stable_for_equal_deadlines` (`tests/scheduler.rs:38`) | partial |
| `d2k_sched_push` | `push_reserved` (`scheduler.rs:136`) | `main.rs:3771`, `:3956` | due/order/bytes | C push без reservation; R2O требует ticket | unit | partial |
| `d2k_sched_push_serial` | `push_reserved` | `main.rs:3956` | execution key | — | unit | partial |
| `d2k_sched_push_owned` | `push_reserved` + owner id в `WirePacket`/pending | `main.rs:152` | owned id | C owner id хранится в entry; R2O в `PendingUdpRelease` | unit | partial |
| `push` (static) | `push_reserved` | — | len/capacity refusals | C `-2` (too long) vs R2O `Err(WirePacket)`; счётчик refusals C увеличивает на слишком длинную посылку, R2O — нет | unit | partial |
| `d2k_sched_pop_due` | `pop_due` (`scheduler.rs:204`) | `main.rs:2519` | due | — | unit | partial |
| `d2k_sched_pop_due_serial` | `pop_due` | — | execution | — | unit | partial |
| `d2k_sched_pop_due_ex` | `pop_due` + `FlowTicket` | `main.rs:2519` | owned/owner id, too-long discard | C при `len>outcap` выбрасывает голову и возвращает `-1` для owned; R2O `WirePacket` не имеет такого «слишком длинного» исхода — размер не ограничен буфером | `queue_capacity_refuses_a_whole_batch...` (`tests/scheduler.rs:92`) | partial |
| `d2k_sched_next_ns` | `timeout_ms` (`scheduler.rs:220`) | `main.rs:1167` | ближайший срок | — | unit | partial |
| `d2k_sched_count` | `len` (`scheduler.rs:240`) | stats | — | — | unit | partial |
| `d2k_sched_refusals` | `refusals` (`scheduler.rs:244`) | stats | — | — | `scheduled_queue_statistics_count_capacity_refusal` (`scheduler.rs:425`) | partial |
| — | `reserve`, `cancel`, `cancel_flow`, `cancel_direction`, `expire`, `has_pending` (`scheduler.rs:78-298`) | `main.rs:1543`, `:2526` | — | **R2O-расширение:** C `sched.c` не знает flow identity и отмены; эти контракты не из C | `an_expired_reservation...`, `rst_and_reused_syn...`, `a_fin_cancels...` | not-applicable |

### journal.c (14 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `d2k_journal_new` | `R2oFlowJournal::with_capacity` (`flow_journal.rs:489`) | `main.rs:898` | cap=0, allocation failure | — | unit | partial |
| `d2k_journal_free` | `Drop` | shutdown | — | — | unit | partial |
| `d2k_suspect_text` | `R2oFlowJournalKind::russian_name` (`flow_journal.rs:52`), `format_journal_details` (`main.rs:2860`) | journal print / events | тексты подозрений | C тексты `D2K_SUSPECT_*`; R2O имеет другой набор (R2O-события), полного соответствия строк нет | unit | partial |
| `d2k_refuse_text` | `format_journal_refusal_code` (`main.rs:2931`), `R2O_JOURNAL_REFUSE_*` | journal print | коды отказа | C 7 кодов; R2O набор шире/другие имена | unit | partial |
| `add_entry` (static) | `R2oFlowJournal::push` (`flow_journal.rs:502`) | все record_* | кольцо, dropped, added, name sanitize | — | unit | partial |
| `d2k_journal_add` | `record_hello_body`, `record_direction_event` (`:517`, `:887`) | hello/control | — | — | unit | partial |
| `d2k_journal_add_applied` | `record_applied` (`:571`) | APPLIED | plan/trial id | — | unit | partial |
| `d2k_journal_add_refused` | `record_plan_refused` (`:605`) | REFUSED | code/plan/trial | — | unit | partial |
| `d2k_journal_add_fate_bound` | `record_execution_failure` (`:643`) | UNSENT/DAMAGED | execution/binding | — | unit | partial |
| `d2k_journal_add_fate` | `record_execution_failure` с `binding=None` | — | — | — | unit | partial |
| `d2k_journal_count` | `count` (`:911`) | stats/pump | — | — | unit | partial |
| `d2k_journal_at` | `get` (`:915`), `iter` (`:935`) | print/pump | упорядочение «старое→новое» | — | unit | partial |
| `d2k_journal_dropped` | `dropped` (`:927`) | stats | — | — | unit | partial |
| `d2k_journal_added` | `added` (`:931`) | snapshot/pump | — | — | unit | partial |

### nat.c (5 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `parse_ip4` (static) | `proc_nat.rs:145 parse_ipv4`, `:134 parse_address` | разбор `/proc/net/nf_conntrack` | строгие 0..255, ровно 4 части, без хвоста | Rust дополнительно `Ipv6Addr::from_str`; C IPv6 через `inet_pton` | `d2o_nat_proc.rs:9 proc_nat_matches_d2o_c_on_shared_conntrack_vectors` | equivalent (scoped) |
| `field_after` (static) | `proc_nat.rs:122 field_after`, `:113 fields` | поиск полей | граница слова, `name=`, значение до пробела/`\n` | Rust режет строку на поля заранее; поведение на нескольких пробелах/табах проверено shared vectors | `d2o_nat_proc.rs` | equivalent (scoped) |
| `d2k_nat_outside` | `proc_nat::lookup` (`proc_nat.rs:20`) | `flow_tracked`/NAT-проверка плана | IPv4 обёртка | — | `d2o_nat_proc.rs` (проверяет `lookup`, не обёртку) | implemented-unproven |
| `parse_address` (static) | `proc_nat.rs:134 parse_address` | — | IPv4/IPv6 | — | shared vectors | equivalent (scoped) |
| `d2k_nat_outside_family` | `proc_nat::lookup` (`:20`) + `R2oProcNatLookup` (`:10`) | `main.rs` plan validation / `R2oConntrackGate` | table missing vs flow missing, best TTL, IPv4/IPv6, long lines | Rust `content_len > 1022` skip; C `fgets(1024)` + drain; shared vectors не покрывают все длины строк | `d2o_nat_proc.rs`, `scripts/r2o-nat-proc-differential.sh` | partial |

### icmpguard.c (7 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `d2k_icmpguard_init` | `R2oIcmpGuard::default` (`r2o_icmp_guard.rs:33`) | `main.rs:948` | нулевое состояние | — | unit | partial |
| `u16` (static) | `r2o_u16` (`:257`) | parse | big-endian | — | unit | partial |
| `parse_ip` (static) | `r2o_parse_icmp_quote` (`:204`), `r2o_icmp_quote_start` (`:175`) | note/check | IPv4/IPv6, non-first fragment, proto 6/17, min 8 bytes | — | `tests/r2o_icmp_guard.rs` | partial |
| `d2k_icmpguard_note` | `R2oIcmpGuard::r2o_note` (`:56`) | `main.rs` после raw emit | TTL<orig, ring, id, l4word, ip_len | C `now_ns?now:1`; Rust `max(1)` | unit, `test-icmp-guard-current-differential.sh` | partial |
| `d2k_icmpguard_check` | `R2oIcmpGuard::r2o_check` (`:90`) | `r2o_handle_at_hook` (`:127`) | TTL/ID/ports/word/len/keep window | C `q.ttl > s->ttl` reject; Rust same; нет C/Rust дифференциала всех полей | `test-icmp-guard-current-differential.sh`, `tests/r2o_icmp_guard.rs` | partial |
| `d2k_icmpguard_dropped` | `r2o_dropped` (`:149`) | summary | — | — | `r2o_periodic_icmp_summary_matches_d2o_fields` (`tests/...:254`) | partial |
| `d2k_icmpguard_noted` | `r2o_noted` (`:145`) | summary | — | — | там же | partial |

### nfq.c (12 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `say` (static) | `eprintln!`/`io::Error` | — | тексты ошибок | Тексты R2O другие; не контракт | — | not-applicable |
| `nl_write` (static) | `send_to_kernel` (`nfqueue.rs:416`) | все netlink send | EINTR retry, short write | — | unit | partial |
| `await_ack` (static) | `QueueSocket::await_ack`/`await_ack_with` (`:342`, `:366`) | `configure` | poll 1 с, 8 попыток, чужой seq, errno | C при `poll==0` сразу ошибка; Rust при `None` сразу ошибка; совпадает | `await_ack_stops_after_first_timeout` (`:480`) | partial |
| `send_and_ack` (static) | `configure` (`:336`) | open | send + await | — | unit | partial |
| `set_rcvbuf` (static) | `set_receive_buffer`/`_with` (`:13`, `:30`) | open | SO_RCVBUFFORCE→SO_RCVBUF, readback, effective<requested | C возвращает 1 при cap; Rust только логирует; семантика сообщения совпадает | `receive_buffer_*` (`:512-582`) | partial |
| `d2k_nfq_open` | `QueueSocket::open` (`:115`) | `main.rs:890` | socket/bind/family, rcvbuf, BIND, PARAMS, fail-open, GSO off, copy range | **C всегда AF_INET**; R2O принимает AF_INET/AF_INET6. C `copy_range` до 1600; R2O до 65535. C `D2K_NFQNL_CFG_CMD_BIND` с `AF_INET`; R2O `protocol_family` | `test-nfq-netns.sh`, `test-nfq-ipv6-forward-netns.sh`, unit `configuration_matches_the_c_reference_fields` (`netlink.rs:332`) | partial |
| `d2k_nfq_close` | `Drop for QueueSocket` (`:404`) | shutdown | UNBIND без ожидания, close | — | unit | partial |
| `d2k_nfq_fd` | `AsRawFd`/`receive_timeout_with_fd` | poll | — | — | unit | partial |
| `d2k_nfq_recv` | `receive_timeout_with_fd` (`:205`) | `main.rs:1179` | EAGAIN/EWOULDBLOCK/EINTR→нет пакета; ENOBUFS→lost++; прочее→Io | C возвращает 0 на EAGAIN; Rust `Ok(false)`. C не проверяет POLLERR; Rust превращает POLLERR без POLLIN в `Wait` и не считает потерю | `receive_error_policy_preserves_poll_and_empty_queue_cases` (`main.rs:4251`), `test-nfq-ipv4-recv-error-differential.sh`, `test-nfq-ipv6-recv-error-recovery.sh` | partial |
| `d2k_nfq_verdict` | `send_verdict` (`:310`) | `main.rs:3723` | verdict netlink, counters | — | `verdict_bytes_match_the_nfqueue_wire_contract` (`netlink.rs:304`) | partial |
| `d2k_nfq_verdict_payload` | `send_replacement` (`:317`) | HTTP 307 | ACCEPT с payload, счётчик accepted | **C буфер 64+2048=2112 байт**; R2O до 65531 байт. C отвергает замену примерно >2 КиБ (точный предел зависит от выравнивания), R2O принимает. Дифференциала нет. | `replacement_verdict_carries_payload_and_zero_padding` (`netlink.rs:322`) | partial |
| `d2k_nfq_lost` | `lost_packets` (`:271`) | stats | — | — | `record_lost_packet_counts_each_kernel_report` (`:492`) | partial |

### nl.c (19 функций)

| C-функция / группа | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `align4` (static) | `netlink.rs:291 align4` | парсер/сборка | — | — | unit | partial |
| `h16/h32/wh16/wh32` (static) | `u16/u32::from_ne_bytes`, `to_ne_bytes` | заголовки | host order | — | unit | partial |
| `n16/n32/wn16/wn32` (static) | `from_be_bytes`/`to_be_bytes` | атрибуты | network order | — | unit | partial |
| `d2k_nl_iter_init` | `MessageIter::new` (`:64`) | все | — | — | unit | partial |
| `d2k_nl_next` | `MessageIter::next` (`:76`) | все | mlen<hdr, mlen>left, last message без tail, стоп на мусоре | — | `iterator_accepts_unpadded_last_message_and_stops_on_bad_lengths` (`:355`) | partial |
| `d2k_nl_packet` | `QueuePacket::parse` (`:125`) | `main.rs:1345` | PACKET_HDR, PAYLOAD, CAP_LEN, SKB_INFO, MARK, TIMESTAMP, IFINDEX_OUTDEV, truncated | C `have_payload` отдельно; Rust `Option`. C timestamp sec/usec validation; Rust same. C `truncated=cap_len>payload_len`; Rust `cap_len>payload.len()` | `parser_reads_packet_metadata...` (`:371`), `parser_marks_copy_range_truncation...` (`:403`) | partial |
| `d2k_nl_errno` | `kernel_error` (`:183`) | `main.rs:?` | NLMSG_ERROR, signed errno | — | `kernel_error_reads_native_signed_errno` (`:429`) | partial |
| `hdr_init`, `put_attr` (static) | `header` (`:263`), `push_attr` (`:274`) | сборка | длина, очередь, zero padding | — | unit | partial |
| `d2k_nl_verdict` | `verdict` (`:188`) | verdict | 8-byte verdict hdr | — | byte test | partial |
| `d2k_nl_verdict_payload` | `verdict_payload` (`:203`) | replacement | len 0 / >65531 отказ | — | byte test | partial |
| `d2k_nl_cfg_cmd` | `config_command` (`:219`) | open/close | BIND/UNBIND, NLM_F_ACK | — | `configuration_matches_the_c_reference_fields` (`:332`) | partial |
| `d2k_nl_cfg_params` | `config_params` (`:234`) | open | copy_range, maxlen, flags/mask | — | `:332` | partial |

### ctl.c (14 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `say`, `set_nonblock` (static) | `io::Error`, `set_nonblocking` | — | — | — | unit | not-applicable/partial |
| `d2k_ctl_open` | `ControlServer::open` (`control.rs:1606`) | `main.rs:871` | путь, unlink, bind, listen(1), nonblock, 0600 | R2O дополнительно проверяет «путь занят не сокетом/обслуживается», ставит 0600 и удаляет только свой inode | `control_socket_is_private_to_its_owner` (`control.rs:2068`) | partial |
| `d2k_ctl_close` | `Drop` (`:1964`) | shutdown | close/unlink | R2O удаляет только свой inode | unit | partial |
| `d2k_ctl_listen_fd`, `d2k_ctl_peer_fd` | `listener`/`peer`, `poll` | `main.rs:1263` | — | — | unit | partial |
| `d2k_ctl_set_disconnect_hook` | `ControlServer` disconnect path (`:1953`), `NamePlans::clear_probes` (`main.rs:1291`) | `main.rs` | hook заменён прямой очисткой | C hook вызывается при drop_peer; R2O очищает probes в `main` при `!is_connected()` | unit | partial |
| `d2k_ctl_accept` | `accept_peer` (`:1831`) | poll | второй peer отвергается, nonblock, reset ring/in | R2O отправляет greeting сразу в `accept_peer`; C требует явного `greet` из main | `control_server_accepts_reconnect_pending_after_previous_peer_closes` (`:2086`) | partial |
| `drop_peer` (static) | `disconnect` (`:1953`) | close/error | close, reset in/out, hook | — | unit | partial |
| `d2k_ctl_flush` | `flush` (`:1919`) | event/ACK | частичная запись, EAGAIN, EINTR, drop peer | C ring 64 КиБ; R2O VecDeque 128 КиБ | unit | partial |
| `d2k_ctl_event` | `send_event`/`try_send_event`/`enqueue` (`:1698`, `:1710`, `:1907`) | события | кадр целиком, dropped++, sent++ | C `dropped` при `len>FRAME_MAX-2` или нет места; R2O при >128 КиБ или нет peer. **Разный порог.** | `control_server_counts_each_event_without_connected_peer_as_dropped_like_d2o` (`:2133`), `try_send_event...` (`:2193`) | partial |
| `d2k_ctl_poll` | `poll` (`:1669`), `read_peer` (`:1853`), `take_complete_frames` (`:1881`) | `main.rs:1264` | EINTR/EAGAIN, неверная длина→disconnect, частичный кадр, полный буфер→disconnect, 256 команд за poll | C лимита 256 нет; C `done` считает кадры. R2O `MAX_COMMANDS_PER_POLL=256` — расширение/ограничение | `control_server_accepts_reconnect...`; `control_cli` tests | partial |
| `d2k_ctl_dropped` | `dropped_events` (`:1746`) | stats | — | — | unit | partial |
| `d2k_ctl_sent` | — | — | — | **Счётчика sent в R2O нет.** C `D2K_EV_STATS` отправляет dropped+sent раз в секунду (`d2kd.c:2339-2350`); R2O не отправляет `EVENT_STATS` с sent (в `main.rs` нет `EVENT_STATS` отправки). | — | missing/partial |

### ctlsrv.c (12 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `put_key` (static) | `control::KEY_LEN` + `flow_journal_key_for_packet` (`control.rs:1516`) / `encode_*` | события | 38-байтный ключ | — | control unit | partial |
| `d2k_plan_fits` | `NamePlans::r2o_plan_valid` (`control.rs:158`), `validate_runtime_plan` (`engine.rs:2011`) | установка плана | send_maxlen, IPID_ZERO, max emit | C `limits==0`→OK; Rust `validate_runtime_plan` для TCP отвергает IPID_ZERO всегда; C только при `D2K_RAW_CANT_IPID`. Разные предусловия | control unit, `validate_runtime_plan` tests | partial |
| `ack`, `ack_trial` (static) | `ControlServer::send_ack` (`control.rs:1684`), `Ack` (`r2k-core/control.rs`) | каждая команда | key+4, trial ID, binding для SET_NAME_BOUND | C `type>=SET_SUFFIX && <=DEL_BYPASS` плюс probe/bound; R2O `send_ack` кодирует по `Ack`; полный дифференциал ACK-байтов не заявлен | `permanent_http_set_ack...` (`control.rs:3158`), `control_cli` | partial |
| `d2k_ctlsrv_greet` | `control::encode_greeting` (`r2k-core/control.rs:874`), `accept_peer`/`r2o_set_send_maxlen` | accept/limit change | protocol version, send_maxlen, release ID | **Версия 22 vs 48**; layout совпадает | `control_server_announces_updated_send_limit...` (`:2239`) | partial |
| `d2k_ctlsrv_peer_closed` | `main.rs:1285-1293` (`clear_probes`, rearm suspicions) | disconnect | очистка probe | — | `control_server_accepts_reconnect...` | partial |
| `canonical_address` (static), `addr_shape_valid` (static) | `valid_addr_shape` (`control.rs:1458`), `addr_plan_matches_shape` (`:1465`), `set_addr` (`:753`) | SET_ADDR | family 4/6, zero tail, shape whitelist | — | control unit | partial |
| `read_probe_flow` (static) | `encode/decode` addr probe (`r2k-core/control.rs:1186`, `:1209`), `set_addr_probe` (`control.rs:1097`) | SET_ADDR_PROBE | family, IP, ports, transport | — | control unit | partial |
| `d2k_ctlsrv_command` | `NamePlans::handle` (`control.rs:163`) | `main.rs:1277` | все команды, bad args/plan/no room, trial ACK, ARM_SHAPE, SET_HTTPS, stall budgets | R2O добавляет `--controller-only`/`COMMAND_STATS`; **R2O не поддерживает C `D2K_CMD_SET_STALL_BUDGETS`?** проверено наличие `COMMAND_SET_TCP_STALL_BUDGETS` и decode; C `D2K_CMD_STATS`? R2O `COMMAND_STATS` есть, но обработчик — stats? | `control_cli.rs`, `test-panel-control-response-differential.sh` | partial |
| `d2k_ctlsrv_pump` | `send_journal_snapshot`/`send_journal_updates` (`main.rs:2585`, `:2604`), `R2oFlowJournalEntry::to_event_frame` | события | HELLO/SUSPECT/APPLIED/REFUSED/DAMAGED/UNSENT/SHAPE/EXCHANGE, key/plan/trial/execution/binding | **R2O event IDs и тела отличаются** (`EVENT_CLIENT_SHAPE 0x17` вместо C `0x0d`; R2O voice/quic/tcp events 0x0e..0x1e). C отдельно шлёт `D2K_EV_CLIENT_TCP` (0x0d) с TCP options, затем `D2K_EV_SHAPE`; R2O шлёт один `EVENT_CLIENT_SHAPE` (0x17) с `tcp_has_timestamp` и байтами hello, отдельного CLIENT_TCP нет. C `D2K_EV_SUSPECT` 10-байтовое тело; R2O `send_tcp_silent_event`/`send_quic_suspect_event` имеют другой формат. | `r2o-control-events-differential.sh`, `r2o-control-dropped-differential.sh`, `control_cli.rs` | partial |
| `d2k_ctlsrv_http80_event` | `send_http_portal_event` (`main.rs:2996`), `send_http_response_event` (`:3008`) | HTTP80 | key, response/answered, host, execution/plan/trial, request_ms, path, binding, status/body_bytes/request_no | Нет C/Rust дифференциала тела события HTTP80; `http_trace` отсутствует | HTTP hold tests (косвенно) | implemented-unproven |

### raw.c datapath (17 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `if_mtu`, `pick_maxlen`, `route_mtu` (static) | `r2o_interface_mtu` (`raw.rs:301`), `r2o_pick_maxlen` (`:270`), `r2o_route_mtu` (`:484`), `r2o_select_egress_mtu` (`:329`) | open/adopt | MTU по iface/маршруту, min MTU, tunnel exclusion | R2O добавляет route cache и `r2o_tls_route_probe`; C `d2k_raw_route_maxlen` без кеша? | `raw_egress_mtu.rs`, `r2o-route-gate-differential.sh` | partial |
| `say` (static) | `eprintln!` | — | — | — | — | not-applicable |
| `d2k_raw_open` | `RawSocket::open` (`raw.rs:48`) | `main.rs:814` | socket, mark, iface, MTU, limits | C `d2k_raw_limits` возвращает capability mask; R2O `validate_runtime_plan` жёстко проверяет IPID_ZERO | `raw.rs` tests | partial |
| `d2k_raw_close` | `Drop` | shutdown | — | — | unit | partial |
| `d2k_raw_limits` | — | — | — | **Отдельной функции нет.** Единственный C-флаг `D2K_RAW_CANT_IPID` в R2O заменён проверкой в `validate_runtime_plan`; расширяемость limits потеряна | — | partial/missing |
| `d2k_raw_maxlen` | `maxlen` (`raw.rs:96`) | stats/plan_fits | — | — | unit | partial |
| `d2k_raw_adopt_egress` | `r2o_adopt_egress` (`raw.rs:106`) | `main.rs:855` | выбрать min MTU, имена, 0/1/-1 | C печатает имена; R2O возвращает maxlen | `test-raw-egress-mtu-netns.sh` | partial |
| `blend` (static) | `r2o_lower` (`raw.rs:400`) | MTU blend | — | — | unit | partial |
| `d2k_raw_route_maxlen`, `_family` | `r2o_effective_route_maxlen` (`raw.rs:351`), `r2o_route_mtu` (`:484`) | per-packet cap | IPv4/IPv6, route lookup, cache | C `d2k_raw_route_maxlen_family` спрашивает маршрут; R2O кеширует | `raw_egress_mtu.rs` | partial |
| `d2k_raw_prepare` | `validate_runtime_plan`/`RawSocket::send_packet_inner` (`:155`) | отправка | проверка формы, length | C `prepare` отдельно от send; R2O `send_packet` собирает/проверяет | `raw_sender_accepts_only_well_formed...` (`:875`) | partial |
| `d2k_raw_send` | `send_packet`/`send_packet_inner` (`:147`, `:155`) | `main.rs:3771`, `transmit_many` | sendto, EINTR, EAGAIN/ENOBUFS, counters | C считает `busy` на EAGAIN/ENOBUFS; R2O `record_send_outcome` | `raw_send_stats_count_success_and_busy_errors_like_d2o` (`:232`), `raw_send_stats_ignore_input_rejections...` (`:253`), `r2o-raw-emission-cancel-differential.sh`, `test-raw6-send-differential.sh` | partial |
| `d2k_raw_sent`, `d2k_raw_errors`, `d2k_raw_busy` | `send_stats` (`:100`) | stats | — | — | unit | partial |

### routemark.c (23 функции)

| C-функция / группа | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `rd16h/rd32h/wr16h/wr32h` (static) | `r2o_u16/u32` в `r2o_route.rs` | сборка/разбор | — | — | unit | partial |
| `d2k_routemark_init` | `R2oRouteGate::default`, `R2oRouteMonitor::default` | `main.rs:831`, `:845` | — | — | unit | partial |
| `d2k_routemark_request` | `r2o_route_rule_request` (`r2o_route.rs:679`) | refresh | RTM_GETRULE dump | — | `route-gate` unit | partial |
| `nl_error` (static) | `r2o_kernel_error` (`:863`) | parse | — | — | unit | partial |
| `d2k_routemark_parse` | `r2o_route_parse_rules` (`:711`) | refresh | FWMARK/FWMASK, invert, DONE/ERROR, truncated tail | — | `r2o-route-gate-differential.sh` | partial |
| `d2k_routemark_lookup_request` | `r2o_route_lookup_request` (`:691`) | refresh | IPv4/IPv6 doc prefix | — | unit | partial |
| `add_oif`, `route_oifs` (static) | `r2o_route_add_ifindex` (`:950`), `r2o_route_parse_multipath` (`:913`), `r2o_route_attributes` (`:876`) | refresh | OIF, multipath, dedup | — | unit | partial |
| `d2k_routemark_lookup_parse` | `r2o_route_parse_lookup` (`:774`) | refresh | unicast, no-device=2, no-route=3, malformed | — | unit | partial |
| `d2k_routemark_watch_relevant` | `r2o_route_watch_relevant` (`:806`) | `main.rs:1221` | NEW/DEL rule, default route | — | unit | partial |
| `d2k_routemark_clear_oifs`, `set_oifs` | `r2o_set_default_ifindices` (`:131`), `r2o_egress_ifindices` (`:152`) | refresh | семейство, OIF max, changed | — | unit | partial |
| `d2k_routemark_set`, `merge` | `R2oRouteMonitor::r2o_refresh` (`:372`), `r2o_set_rules` (`:119`) | refresh | слияние v4/v6, failed family сохраняет прежнее, truncated | — | `r2o-route-gate-differential.sh` | partial |
| `d2k_routemark_set_policy`, `policy_match` | `R2oRouteGate::r2o_set_policy` (`:170`), `R2oRoutePolicy::r2o_matches` (`:93`) | `--only-mark` | mark/mask/none | — | `test-router-route-gate-config.sh` | partial |
| `d2k_routemark_routed` | `r2o_mark_is_routed` (`:175`) | route gate | mark routed | — | `r2o-route-gate-differential.sh` | partial |
| `d2k_routemark_client` | `r2o_route_mark` (`:201`) | gate | policy + routed | — | unit | partial |
| `d2k_routemark_gate` | `r2o_mark_is_routed`/`r2o_route_mark` + `R2oRoutedFlows::r2o_skip_packet` (`:596`) | `main.rs:1401` | mark, outdev, probe mark, own mark | R2O `R2oRoutedFlows` дополнительно ведёт таблицу routed flows | `r2o-route-gate-differential.sh`, `test-datapath-stats-timer-differential.sh` | partial |
| `d2k_routemark_describe` | — | — | — | **Текстового описания маршрутов/меток в R2O нет**; R2O печатает только ошибки refresh | — | missing |

### routemark_nl.c (8 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `parse_rules` (static) | `r2o_route_parse_rules` (`r2o_route.rs:711`) | refresh | — | — | unit | partial |
| `support` (static) | `r2o_route_messages` (`:824`) | dump | — | — | unit | partial |
| `dump_rules` (static) | `r2o_dump_rules` (`:398`) | refresh | EAFNOSUPPORT/EOPNOTSUPP→пусто | R2O обработка ошибок в `r2o_refresh`; нет exact теста | unit | partial |
| `lookup_route` (static) | `r2o_lookup_default` (`:425`), `r2o_receive_request` (`:448`) | refresh | ENETUNREACH/EHOSTUNREACH/ENETDOWN→3 | — | unit | partial |
| `all` (static) | `r2o_refresh` (`:372`) | `main.rs:1236` | dump v4/v6 + lookup v4/v6 | — | `r2o-route-gate-differential.sh` | partial |
| `d2k_routemark_load` | `R2oRouteMonitor::r2o_refresh` (`:372`) | `main.rs:852` | merge rules + oifs + status | — | `r2o-route-gate-differential.sh` | partial |
| `d2k_routemark_watch_open` | `r2o_open_watch` (`:283`) | `main.rs:847` | NETLINK_ROUTE, nonblock, subscribe | — | unit | partial |
| `d2k_routemark_watch_drain` | `r2o_drain_watch` (`:334`) | `main.rs:1221` | читает и сообщает relevant | — | unit | partial |

### ctq.c (20 функций)

| C-функция / группа | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `align4`, `wr16h`, `wr32h`, `rd16h`, `rd64be`, `rd32be` (static) | `conntrack.rs:250 align4`, `u16/u32/u64` | сборка/разбор | host/be | — | unit | partial |
| `put`, `open_nest`, `close_nest` (static) | `push_attribute` (`conntrack.rs:254`), `encode_get` (`:74`) | запрос | nested attrs | — | unit | partial |
| `d2k_ct_get_req` | `R2oConntrackInfo::encode_get` (`:74`), `tuple_from_packet` (`:420`) | `main.rs:919` | IPv4/IPv6 TCP/UDP tuple, seq | — | `d2o_conntrack.rs:7 ct_get_bytes_match_d2o_for_ipv4_and_ipv6`, `r2o-conntrack-ctget-differential.sh` | equivalent (scoped) |
| `counter`, `tcp_state` (static) | `parse_counter` (`:211`), `decode_entry` (`:137`) | ответ | 64/32-bit counters, TCP state | — | `d2o_conntrack.rs:63` | partial |
| `d2k_ct_info_parse` | `decode_info` (`:133`), `decode_entry` (`:137`) | query | seq, NLMSG_ERROR, CTA_COUNTERS_*, no counters=2, TCP state | — | `d2o_conntrack.rs` | partial |
| `d2k_ct_counters_parse` | `decode_info` (`:133`) | query | — | — | unit | partial |
| `d2k_ct_query_info_fd` | `R2oConntrackClient::query` (`:297`) | `main.rs` stall detectors | nonblocking send/recv, 8 rounds, seq filter | — | `test-conntrack-retry-current-differential.sh` | partial |
| `d2k_ct_query_fd` | `query` (`:297`) | — | — | — | unit | partial |
| `reply_errno` (static) | `kernel_error`/`decode` | probe | errno sign | — | unit | partial |
| `d2k_ct_probe_fd` | `R2oConntrackClient::probe` (`:309`) | `ct_probe` | ENOENT/0→available, 8 polls | — | `test-conntrack-retry-current-differential.sh` | partial |
| `d2k_ct_open` (Linux) | `R2oConntrackClient::open` (`:270`) | `main.rs:919`, refresh | NETLINK_NETFILTER, nonblock, bind | — | unit | partial |
| `d2k_ct_open` (non-Linux) | — | — | R2O target Linux | — | — | not-applicable |

### wire.c (9 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `wr16/wr32/rd16` (static) | `write_u16/write_u32` (`wire.rs:545`, `:549`) | сборка | - | - | unit | partial |
| `auto_ttl` (static) | `emission_ttl` (`wire.rs:418`) | TTL | ttl/auto/ref | C `auto_ttl` может считать от `ref_ttl`; R2O `Emission.ttl` уже вычислен в engine | `autottl_uses_the_observed_reverse_tcp_ttl...` (`engine.rs:2120`) | partial |
| `sum16`, `fold`, `pseudo_sum` (static) | `sum16` (`wire.rs:527`), `checksum_value` (`:538`), `pseudo_sum` (`:509`) | checksum | IPv4/IPv6 pseudo | — | wire unit | partial |
| `d2k_wire_build` | `build_tcp_packet` (`wire.rs:18`) | `engine.rs` emissions | family, urgent, ipfrag reject, wire profiles, MD5, TCPTS_BACK, native template, ts_up, IP ID, checksum, OOB | **`ts_up` (D2K_POISON_TS_UP) отсутствует в R2O**; C переставляет опцию timestamp в начало и сдвигает значение. C `D2K_POISON_IPID_ZERO` для IPv6 reject; Rust также. C `wire_profile` 0/1/2; Rust same. | `tests/wire.rs` (clean/badsum/md5/urgent/ipv6/template/timestamp back), `r2o-raw-emission-cancel-differential.sh` для измеренного split | partial |
| `d2k_wire_tcp_checksum_ok` | `tcp_checksum_ok` (`wire.rs:429`) | проверка входящих/исходящих | IPv4/IPv6, bounds, header len | — | wire unit | partial |

### wire_udp.c (5 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `wr16`, `sum16`, `fold`, `pseudo_sum` (static) | `wire.rs` те же | UDP checksum | — | — | wire unit | partial |
| `d2k_wire_build_udp` | `build_udp_packet` (`wire.rs:206`), `build_udp_fragments` (`:287`), `build_udp_fragments_with_capacity` (`:292`) | `engine.rs` QUIC/voice/udplen | IPv4/IPv6, payload, checksum, fragment cuts/order/overlap, capacity | C `d2k_udpfrag_build_ex`/`d2k_udpfrag6_build_ex` в `core/ipfrag.c`; R2O `build_udp_fragments`; дифференциал `test-ipfrag-differential.sh` покрывает shapes 1-4 и 16 capacity cases | `test-ipfrag-differential.sh`, `tests/ipfrag.rs`, `r2o-raw-split-support-differential.sh` | partial |

### tls.c (7 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `rd16`, `skip_u8_vec`, `skip_u16_vec` (static) | `tls.rs:129 read_u16`, `:141 skip_u8_vector`, `:158 skip_u16_vector` | разбор ClientHello | bounds, truncated | — | `tls.rs` unit | partial |
| `has_ech_offer` | `tls.rs:230 has_ech_offer` | capture/hello | ECH extension structural checks | — | `recognizes_only_structurally_consistent_ech_offer` (`tls.rs:467`) | partial |
| `has_tls13` | `tls.rs:175 has_tls13` | shape | supported_versions vs key_share | — | `complete_supported_versions_overrides_key_share_heuristic` (`tls.rs:439`), `partial_key_share...` (`:412`) | partial |
| `find_sni` | `tls.rs:274 find_sni` | trigger/capture | SNI extension bounds, multiple names | — | `rejects_inconsistent_sni...` (`:446`), `rejects_sni_extension_without_its_list_length` (`:456`) | partial |
| `d2k_tls_parse` | `tls.rs:32 parse` | capture/engine | record type/version, ClientHello, SNI range, ECH/TLS13 flags, record_end | Нет C/Rust дифференциала полного `d2k_tls_parse`; C `test_tls.c` | `tests/capture_shape.rs`, `tls.rs` unit | partial |

### http80.c (30 функций)

| C-функция / группа | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `d2k_http80_new`, `free`, `get_stats` | `HoldTable::default` (`hold.rs:190`), `r2o_hold_stats` (`:200`); **get_stats нет** | `main.rs:917` | создание/освобождение | **Нет счётчиков requests/injections/evicted/untracked/unparsed/later**; C печатает их в stats. C `D2K_HTTP80_FLOWS=128`, R2O `HTTP_FLOW_CAPACITY=1024` (`hold.rs:20`). | hold unit | partial |
| `name_norm` (static) | `canonical_name` (`control.rs:1976`) / HTTP host normalization | SET_HTTPS/план | lowercase/trailing dot/port | C `name_norm` для HTTP host; R2O `httpup` нормализация host | `test-classifier-white-decoy-differential.sh` (косвенно) | partial |
| `d2k_http80_set_https`, `d2k_http80_https` | `NamePlans::set_https` (`control.rs:903`), `has_verified_https` (`:461`) | SET_HTTPS, redirect gate | TTL, exact host | R2O хранит `https_names` с TTL; C `d2k_http80` хранит свою таблицу; TTL/лимит могут расходиться | `set_https_command_accepts_an_exact_name_with_a_bounded_ttl` (`control.rs:2763`) | partial |
| `wr16`, `wr32`, `sum16`, `fold`, `build`, `rd32`, `stale`, `find`, `make` (static) | `http_replace.rs:79 build_segment`, `:147 pseudo_sum`, `:154 sum16`, `:165 checksum`, `:178 server_packet`; hold HTTP flow table | замена 307/RST | TCP checksum, SYN/seq/ack, stale/find | R2O строит 307 и RST в `build_http_redirect_packets`; C `make` кеширует; не доказано совпадение всех полей | `http_replace.rs:219 builds_checksum_valid_307...`; `r2o-tcp-rst-cut-differential.sh` (косвенно) | partial |
| `d2k_http80_executed` | `HoldTable::note_http_execution` (`hold.rs:209`) | после успешного плана | execution id | — | `hold.rs` unit | partial |
| `request_result`, `d2k_http80_delivered` | `mark_http_response_answered` (`hold.rs:239`), `reject_http_response` (`:220`), `observe_http_response` (`:1084`) | вердикт/ответ | delivered/rejected/cut | — | hold unit (косвенно) | implemented-unproven |
| `seq_after`, `delivered`, `cut_pending`, `cut_result` (static) | `finish_http_response` (`hold.rs:1265`), `sweep_http_responses` (`:255`) | ответ/обрыв | close-delimited, fixed length, quiet | C `cut_pending/cut_result`; R2O событие code 2 и `sweep_http_responses` | `incomplete_fixed_length_response...` (`hold.rs:2078`), `server_fin_completes...` (`:1943`) | partial |
| `d2k_http80_sweep` | `HoldTable::sweep_http_responses` (`:255`) | `main.rs:1337` | истечение | — | unit | partial |
| `request_prefix`, `request_feed` (static) | `r2k-core/httpup.rs R2oHttpRequestSequence`, `hold.rs:1000 remember_http_request` | HTTP keep-alive | префикс запроса, границы, keep-alive | C `http80` и `session.c` ведут счётчики `http_later/unaligned/open_end`; R2O `R2oHttpKeepAliveStats` | `r2o-tcp-payload-stats-differential.sh`, `engine.rs:4745` tests | partial |
| `d2k_http80_packet` | `HoldTable::feed`/`observe_http_response` + `main.rs` `http80_step`-эквивалент | `main.rs:1637-1858` | request parsing, replacement eligibility, HTTPS gate, 307/RST | **Нет прямой функции `d2k_http80_packet`.** Логика размазана между hold и main; C `test_http80.c`/`test_http_hello.c` аналога полного differential нет. | hold unit, `test-datapath-controller-probe-capture-differential.sh` | implemented-unproven |
| `d2k_http80_swap` | `build_http_redirect_packets` (`http_replace.rs:8`) + `main.rs:1966-2000` | замена | payload ACCEPT, RST, откат при ошибке | C `d2k_http80_swap` принимает `d2k_http80_io` callbacks; R2O напрямую `send_replacement` + `raw.send_packet`; порядок и fail-open проверены частично | `http_replace.rs` unit, `r2o-tcp-rst-cut-differential.sh` | implemented-unproven |
| `lc` (static), `d2k_http_request`, `d2k_http_hello` | `r2k-core/httpup.rs`, `http_response.rs`, `r2k-core/tls.rs` | парсеры HTTP | request line/headers/host, hello/SNI | C `d2k_http_request` и `d2k_http_hello` используются `http_trace` и hold; Rust `httpup`/`http_response` имеют свои пределы (header 64 KiB, chunk line 128) | `scripts/test-http-chunk-framing-differential.sh`, `tests/http_response.rs`, `tests/httpup.rs` | partial |

### plan_parse.c (17 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `rd16`, `rd32`, `fail` (static) | `plan.rs:861 read_u16`, `:871 read_u32`, `PlanError` | парсер | bounds/error text | — | plan unit | partial |
| `scan` (static) | `Plan::scan` (`plan.rs:656`), `next_record` (`:815`), `require_len` (`:837`) | parse | все REC_*, minexec, длины, дубликаты, refs | C и R2O record IDs совпадают; **контейнер `D2KP` vs `R2OP`**; C `D2K_SCHEMA_MAX=1`, R2O same; C `D2K_EXEC_VERSION=13`, R2O `EXEC_VERSION=13` | `tests/plan.rs`, `plan.rs` unit | partial |
| `check_refs` (static) | `Plan::check_references` (`plan.rs:468`) | parse | payload/poison refs, oob, autottl | — | plan unit | partial |
| `d2k_find_payload` | `Plan::payloads.iter().find` (inline), `plan_text` | apply | id lookup | Нет отдельной публичной функции | plan unit | partial |
| `d2k_find_poison` | `Plan::poisons.iter().find` (inline), `apply.rs` | apply | id lookup | Нет отдельной публичной функции | plan unit | partial |
| `d2k_plan_load` | `Plan::parse` (`plan.rs:159`) | `main.rs:3635 load_plan` | magic/schema/minexec/flags/declared/records/refs | **`D2KP` отвергается**: R2O принимает только `R2OP`. C-план несовместим; обратное тоже (R2O-контроллер шлёт R2OP). | `tests/plan.rs`, `save_plan_file` tests, `raw_probe` compile tests | partial |
| `d2k_plan_free` | `Drop` | — | — | — | unit | partial |
| `d2k_plan_poison_used` | `Plan::poison_used` (`plan.rs:296`) | install/validate | OR flags | R2O не знает `D2K_POISON_TS_UP (1<<4)`; `poison_used` вернёт бит, но `wire.rs` его не исполняет | unit | partial |
| `d2k_plan_flow_needs` | — | — | — | **Функции нет.** C вычисляет потребности потока (например, SNI/HTTP) для планировщика; R2O использует `plan.transport/proto/input_*` в `engine.rs`/`control.rs`; отдельного контракта нет. | — | partial/missing |
| `d2k_plan_quic_deny` | `Plan::quic_deny` (`plan.rs:302`) | `main.rs:1608` | qdeny | — | qdeny tests | partial |
| `d2k_plan_guards` | `plan.guards` field + `validate_runtime_plan` | `engine.rs` | GUARD_RST_ALIEN | — | `rst_alien_guard_*` tests | partial |
| `d2k_plan_transport` | `plan.transport` | control/engine | — | — | unit | partial |
| `d2k_plan_proto` | `plan.proto` | control/engine | — | — | unit | partial |
| `d2k_plan_stream_input` | `Plan::stream_input` (`plan.rs:306`) | engine | input_tls/input_len | — | unit | partial |
| `d2k_plan_id` | `plan.id` | events/journal | — | — | unit | partial |

### plan_apply.c (15 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `anchor_offset` | `apply.rs:862 anchor_offset` | split/oob | anchor types, SNI/payload/middle/record end | — | apply unit | partial |
| `cmp_size` (static) | `apply.rs` sorting helper | split ordering | — | — | unit | partial |
| `split_points` | `apply.rs:908 split_points` | split | cuts, dedup, bounds | — | apply unit | partial |
| `tls_ch_layout` | `apply.rs:970 tls_client_hello_layout` | fake_tls_bytes | record/handshake layout | — | apply unit | partial |
| `random_bytes` | `apply.rs:1019 secure_random` | fake TLS mod | `/dev/urandom`/fallback | C `random_bytes`; R2O `secure_random` может иметь другой fallback | apply unit | partial |
| `wr16`, `wr24` | `write_u16`, `write_u24` (`apply.rs:1036`, `:1041`) | fake build | — | — | unit | partial |
| `fake_tls_bytes` | `apply.rs:531 fake_tls_bytes` | fake | rnd/dupsid/sni mods | — | apply unit | partial |
| `emit_fake` | `apply.rs:486 emit_fake`, `append_fake_repeats` (`:463`) | apply | repeats/gap/place/order | — | apply unit | partial |
| `emit_vec_free` | `Drop`/`Actions` | — | — | — | unit | partial |
| `emit_overhead` | `apply.rs:737 emit_overhead` | install/fits | — | — | unit | partial |
| `d2k_plan_max_emit` | `Plan::max_emit` (`apply.rs:418`) | control/plan_fits | — | — | apply unit | partial |
| `d2k_plan_apply` | `Plan::apply` (`apply.rs:155`) | `engine.rs:1691 decide_packet_with_segment_cap`, `raw_probe` | payload/input_tls/input_len/http/qdeny/splits/fakes/seqovl/order/guard/pace/delay/segment/wire/oob/ipfrag/udplen/qsplit/autottl | **`ts_up` не реализован**; C `D2K_POISON_TS_UP` даёт другую посылку. C `D2K_REFUSE_*` причины; R2O `ApplyError` коды/строки. C `d2k_actions_cancel`; R2O `Cancellation`. | `tests/apply.rs`, `r2o-raw-emission-cancel-differential.sh`, `r2o-raw-profile-differential.sh`, `test-classifier-raw-production-differential.sh` | partial |
| `d2k_actions_cancel` | `Actions::cancel` (`apply.rs:104`) | cancel | — | — | apply unit | partial |
| `d2k_actions_free` | `Drop` | — | — | — | unit | partial |

### plans.c (75 функций)

Все ссылки вида `:NNN` в колонке Rust-аналога этой таблицы относятся к `crates/r2o-datapath/src/control.rs`, если не указан другой файл.

| C-функция / группа | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `bind_context` (static) | `NamePlans` generation/binding (`control.rs:1424 next_generation`, `:561 binding_for_plan`) | установка/ACK | generation, trial id, shape, temporary | C `binding_owner` указатель; R2O нет owner-указателя, есть поколение | control unit | partial |
| `d2k_plantab_new`, `free` | `NamePlans::default` (`control.rs:126`), `Drop` | `main.rs:888` | capacity, epoch | **C capacity = `--flows` (2048); R2O 128 name + 128 addr.** C одна таблица; R2O отдельные map | `name_plan_table_is_bounded_and_delete_releases_a_slot` (`:2274`) | partial |
| `name_eq` (static) | `NamePlanKey` `Eq` | поиск | case? C `name_same` в session; `name_eq` в plans | — | unit | partial |
| `shape_transport` (static) | `shape_family_slot`/shape checks (`control.rs:1601`) | поиск | shape→transport | — | unit | partial |
| `area_name_valid`, `suffix_member`, `area_exact`, `area_set`, `area_del`, `area_match`, `area_bypassed` | `set_suffix` (`:783`), `delete_domain_area` (`:869`), `domain_suffix_member` (`:1435`), `set_domain_bypass` (`:836`), `name_is_bypassed` (`:1389`) | DEL/SUFFIX/BYPASS | длина/форма/транспорт/семейство, exact/suffix | C arrays `suffixes[64]`, `bypasses[256]`; R2O HashMaps 64/256 | control unit | partial |
| `d2k_plantab_set_suffix_family`, `del_suffix_family` | `set_suffix`, `delete_domain_area` | команды | — | — | control unit | partial |
| `d2k_plantab_set_bypass_family`, `del_bypass_family` | `set_domain_bypass`, `delete_domain_area` | команды | — | — | control unit | partial |
| `d2k_plantab_revision` | `revision` (`:457`) | hold revision | — | — | unit | partial |
| `d2k_plantab_has_ech_target` | — | — | — | **Функции нет.** C отдельно проверяет наличие ECH-цели; R2O использует `SHAPE_ECH_TCP`/`has_tls_candidate`; отдельного контракта нет | — | partial/missing |
| `d2k_plantab_stream_candidate*`, `_family`, `_target` | `has_tls_candidate` (`:483`), `has_http_candidate` (`:495`), `has_quic_candidate` (`:501`), `select*` | capture/plan | stream input/shape family/target | R2O не имеет точных функций; логика в `select_with_quic_host*` и `has_*_candidate`; прямое соответствие не доказано | control unit (косвенно) | implemented-unproven |
| `find_name_skip`, `find_name`, `find_name_shape_port`, `find_name_port` (static) | `NamePlans::find` (`:1327`), `select` (`:313`), `select_with_quic_host` (`:318`) | пакетный путь | name+shape+port+family | R2O ключ HashMap, C линейный поиск с LRU; порядок/вытеснение различаются | control unit | partial |
| `d2k_plantab_http_candidate`, `find_http` | `has_http_candidate`, `select` HTTP | HTTP | — | — | control unit | partial |
| `find_addr_shape`, `find_addr` (static) | `find_addr` (`:1338`), `find_addr_fallback` (`:1354`), `addr_plan_key` (`:1442`) | пакетный путь | address+shape/family | R2O `AddrPlanKey` (address+shape); C отдельно shape/family | control unit | partial |
| `modern_shape_for_ech` | shape conversion (`SHAPE_ECH_TCP`) | HTTP/ECH | — | — | control unit | partial |
| `scan_name`, `scan_addr`, `used`, `take_free_or_evict` (static) | `HashMap` insert + `MAX_*` refusal; вытеснение LRU отсутствует | установка | capacity/eviction | **C вытесняет LRU (`last_used_ns`); R2O при достижении лимита отказывает** (`control.rs:742`, `:979`). Это поведенческое расхождение, не только ёмкость. | `name_plan_table_is_bounded...` | partial |
| `d2k_plantab_set_name_shaped`, `_probe`, `probe_transport`, `set_name_family`, `set_name`, `set_name_trial` | `set_name` (`:703`), `set_name_probe` (`:940`), `set_name_bound` (`:273`), `valid_tcp_shape` (`:1558`), `valid_tcp_probe_shape` (`:1565`) | команды | shape/family/probe port/trial id | C `set_name_shaped` отдельно; R2O `set_name` проверяет shape | control unit | partial |
| `d2k_plantab_set_addr`, `_family`, `_shaped`, `_probe` | `set_addr` (`:753`), `set_addr_probe` (`:1097`) | команды | address/shape/family/lease | C `set_addr_shaped`; R2O `set_addr` + `valid_addr_shape` | control unit | partial |
| `drop` (static), `d2k_plantab_del_*` (name/addr/suffix/bypass/probe/bound) | `delete_name` (`:1226`), `delete_name_bound` (`:1253`), `delete_addr` (`:1313`), `delete_name_probe` (`:1199`), `delete_addr_probe` (`:1155`), `delete_voice_addr_probe` (`:1181`), `delete_domain_area` (`:869`) | команды | stale no-op, exact binding | R2O `delete_name` может не иметь всех C условий; control tests | `conditional_http_delete...` (`:3193`) | partial |
| `trial_id_valid`, `port`, `probe_flow_equal`, `probe_drop`, `clear_probes`, `find_probe`, `find_addr_probe`, `find_voice_probe`, `probe_count` | `valid_udp_addr_probe_flow` (`:1255`), `addr_probe_binding_at_hook` (`:675`), `voice_address_binding` (`:635`), `clear_probes` (`:471`) | probe | flow equality, expiry, wildcard port | **`d2k_plantab_probe_count` отсутствует**; R2O нет публичного счётчика probe | control unit | partial |
| `shape_fits`, `shape_is_udp`, `d2k_plantab_shape_misses` | `valid_*_shape`, `has_*_candidate`; **shape_misses нет** | поиск/shape | shape compatibility | **Счётчика `shape_misses` нет**; stats R2O не печатает эту строку | control unit | partial |
| `d2k_plantab_find`, `find_sport`, `find_family`, `find_target` | `select`, `select_with_quic_host`, `find`, `find_addr` | пакетный путь | target selection | — | control unit | partial |
| `d2k_plantab_count`, `capacity`, `binding`, `trial` | `plans.len`/`MAX_NAME_PLANS`, `binding_for_plan`, `next_generation` | stats/ACK | — | **plan count/capacity в stats R2O не печатаются** | control unit | partial |

### session.c (107 функций)

Группировка: в одной строке перечислены все функции группы; тривиальные helpers перечислены явно. Rust-аналоги распределены между `engine.rs`, `hold.rs`, `control.rs`, `r2o_udp_sessions.rs`, `r2o_quic.rs`, `r2o_voice.rs`.

| C-функция / группа (все члены) | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| Lifecycle: `initial_dcid`, `init_ring_add`, `init_ring_drop`, `init_ring_pack`, `slot_of`, `shape_slot`, `next_fragment_id`, `d2k_session_new`, `d2k_session_free`, `d2k_session_set_plan`, `name_same`, `rd16`, `rd32` | `TcpSessions::try_with_capacity` (`engine.rs:395`), `R2oQuicSessions::try_with_capacity` (`r2o_quic.rs:154`), `R2oUdpSessions::new` (`r2o_udp_sessions.rs:121`), `R2oVoiceSessions::try_with_capacity` (`r2o_voice.rs:480`), `NamePlans::default` (`control.rs:126`); QUIC init ring в `r2o_quic.rs:192 capture_hello_at_hook_at` | `main.rs:888-942` | раздельные таблицы, capacity, init ring, fragment id | **C: две таблицы (TCP+UDP) ёмкости `--flows`; R2O: TCP + UDP + QUIC + voice, каждая ёмкости `--r2o-flow-capacity`.** Суммарная ёмкость UDP-подобных потоков в R2O втрое выше; отказы считаются раздельно. C init ring 32 записи; R2O `MAX_INITIAL_RING = 32` (`r2o_quic.rs:17`). Нет C/Rust дифференциала высоких кардинальностей QUIC/voice. | `engine.rs:2788 tcp_table_capacity_differential_matches_d2o`, `test-datapath-high-cardinality-differential.sh`, `test-datapath-tcp-capacity-differential.sh` | partial |
| Отказы/подозрения: `refuse_coded`, `refuse`, `suspect_num`, `suspect`, `on_flow_expire` | `R2oFlowJournal::record_plan_refused` (`flow_journal.rs:605`), `send_refused_event` (`main.rs:3597`), `TcpSessions::expire_with_silent` callback (`engine.rs:698`), `send_tcp_silent_event` (`main.rs:3098`) | отказы/истечение | коды, journal, silent event | C `d2k_suspect_text` и `D2K_REFUSE_*`; R2O коды уже/шире; тексты не совпадают | `r2o-control-events-differential.sh`, `test-tcp-silence-current-differential.sh` | partial |
| TCP options: `tcp_options_timestamp_profile`, `tcp_options_have_timestamp` | `TcpHello::tcp_timestamp_option_present` (`capture.rs:183`), `TcpSessions::r2o_client_offers_tcp_timestamps_for_packet` (`engine.rs:472`), `raw_probe.rs:2222 timestamp_options` | shape/raw | TCP timestamp presence, profile | — | `engine.rs:2205 tcp_template_timestamp_requirement...`, `raw_probe.rs:2348 raw_syn_profile...` | partial |
| `plan_handed_off` (static) | `TcpSessions::r2o_begin_execution` (`engine.rs:588`), `r2o_mark_plan_done` (`:576`), `AppliedEvent`/`BindingContext` | decide/APPLIED | execution generation, key, plan id | — | engine unit, `r2o-ack-applied-persist-differential.sh` | partial |
| `table_of`, `plan_fits_transport` (static) | `TcpSessions`/`R2oUdpSessions` выбор, `Plan::transport` | пакетный путь | proto 6/17, transport 0/6/17 | — | engine unit | partial |
| `flow_tracked` (static) | `R2oConntrackGate::guard_decision` (`r2o_conntrack_gate.rs:115`), `R2oConntrackClient::query` (`conntrack.rs:297`), `flow_capacity.rs` | `main.rs:1680 guard_decision` | first packet skip, SYN-ACK proof, 3 NAT retries, table-missing vs miss, `R2oConntrackGate` | **C читает `/proc/net/nf_conntrack` (`nat.c`); R2O использует ctnetlink + gate.** C не переписывает фрагменты, R2O `fragment_decision`/`rewrite_fragment_group` — расширение. C `g_nat_retried`; R2O нет статистики NAT retries | `r2o-conntrack-ctget-differential.sh`, `test-conntrack-retry-current-differential.sh`, `test-nfq-ipv4-recv-error-differential.sh` (SNAT) | partial |
| `d2k_session_nat_stats` | — | — | — | **Функции/счётчиков нет.** C печатает `поток ведётся conntrack: да/нет/таблицы нет/спасла перепроверка`; R2O эту строку не печатает | — | missing |
| UDP-разбор и направление: `handle_udp` (целиком, 793 строки) | `main.rs:1419-2520` (UDP hold, `udp_admitted`, `r2o_udp_decide_once`), `R2oUdpSessions::observe_packet*` (`r2o_udp_sessions.rs:148-224`), `R2oQuicSessions::capture_hello*` (`r2o_quic.rs:180-278`), `R2oVoiceSessions::observe_packet` (`r2o_voice.rs:499`) | UDP/QUIC/STUN/voice | hook→port direction, server side accounting, `rev_seen`, `fwd_pkts`, damaged, qdeny, hello window, Discord/STUN detection, plan selection, raw execution | Нет C/Rust дифференциала полного `handle_udp`; отдельные тесты покрывают QUIC/STUN/voice. C `is_discord_ip_discovery*`/`is_stun_*` реализованы в Rust (`r2k-core/stun.rs`, `r2o_udp_sessions`, `r2o_voice`) — сверить точные сигнатуры. C `voice_proof_told`/`stun_proof_told` → R2O events. | `test-discord-udp-observer-reconnect-differential.sh`, `r2o-quic-stun-watch-differential.sh`, `udp_sessions.rs`, `engine.rs` qdeny/qsplit tests | partial |
| `note_tcp_hello` (static) | `TcpSessions::track_packet_mode` (`engine.rs:911`), `r2o_tcp_hello_flows`/`r2o_tcp_hellos_with_sni` (`:539`, `:543`), `TcpHello::event_body` (`capture.rs:76`) | TCP hello | hello/sni counting, shape | — | `r2o_tcp_counts_sni_hello_once...` (`engine.rs:2565`), `:2580`; `test-datapath-stats-timer-differential.sh` | partial |
| `routed_flow` (static) | `R2oRoutedFlows::r2o_skip_packet` (`r2o_route.rs:596`), `R2oRouteGate::r2o_route_mark` (`:201`) | `main.rs:1401` | route mark/outdev gate, routed flow table | **R2O-расширение**: C `session.c` только считает `routed_flows`; R2O ведёт таблицу и skip-логику. C route gate в `routemark.c`. | `r2o-route-gate-differential.sh` | partial |
| `session_packet` (static, 975 строк) | `engine.rs:1684 decide`, `:1691 decide_packet_with_segment_cap`, `:1440 decide_with_session_mode`, `:1849 decide_tcp`, `:1806 decide_voice` | `main.rs:3202 decide_with_tcp_session*`, `:1660` | TCP prologue, capture, TLS parse, plan selection, HTTP, execution, raw emissions, verdict, counters | **Нет C/Rust дифференциала полного `session_packet`.** Есть дифференциалы отдельных решений (`test-ipfrag`, `test-tcp-silence`, `r2o-tcp-*`). C `D2K_RESULT_MAX`/OUT_BUF; R2O `WIRE_BATCH_MAX=26`. C `out->first_payload=0xFF`; R2O `OriginalFate`. | `test-tcp-silence-current-differential.sh`, `test-tcp-rst-*`, `r2o-tcp-payload-stats-differential.sh`, `engine.rs` unit | partial |
| API: `d2k_session_packet`, `_mtu`, `_probe`, `_probe_mtu` | `decide_with_session`, `decide_with_session_mtu`, `decide_with_session_probe`, `decide_with_session_probe_mtu` (`engine.rs:1403-1440`), `main.rs:3202-3300` | `main.rs:1743-1767` | normal/probe, MTU cap | C probe variants; R2O `controller_probe` flag | engine unit | partial |
| API: `d2k_session_observe_tcp`, `plan_revision`, `stream_anchor`, `set_hook`, `set_route_mark`, `route_mark`, `routed_flows`, `set_udp_reverse_hook`, `set_ct_query` | `TcpSessions`/`NamePlans`/`R2oRouteGate`; `hold.rs:965 remember_syn`; `main.rs:1379`, `:1401` | main | hook, mark, revision, anchor, ct query | C `set_ct_query`; R2O conntrack client напрямую, нет hook-функции | engine unit | partial |
| UDP hold: `d2k_session_udp_hold_begin`, `udp_opening`, `udp_hold_end`, `udp_hold_replay`, `note_unassembled`, `hold_candidate` | `R2oUdpSessions::{r2o_begin_hold,r2o_udp_opening,r2o_mark_hold_replay_first}` (`r2o_udp_sessions.rs:361-427`), `HoldTable::feed` options (`hold.rs:298`), `r2o_report_incomplete_captures` (`main.rs:541`) | `main.rs:1448-1500`, `:1650` | hold transaction, opening, replay, incomplete diagnostics | C `hold_candidate` checks plan/transport/family/hello window; R2O `allow_tls/allow_http` + `feed_observing`; нет прямого differential `hold_candidate` | `udp_hold.rs`, `timeout_reports_unassembled_tls_record...` (`hold.rs:2245`) | partial |
| Shape: `want_shape`, `want_shape_family`, `shape`, `shape_family`, `shape_tcp_options_family` | `ControlServer::arm_client_shape` (`control.rs:1751`), `observe_client_shape` (`:1809`), `TcpSessions::r2o_note_captured_client_shape` (`engine.rs:481`), cached shape в `ControlServer` | ARM_SHAPE/событие | one-shot arm, cache per family, TCP options | C хранит shape в session; R2O в ControlServer; C `D2K_EV_CLIENT_TCP 0x0d`, R2O `EVENT_CLIENT_SHAPE 0x17` | `tcp_timestamp_option_is_carried...` (`control.rs:2632`), `arm_client_shape` tests | partial |
| Plans: `d2k_session_plans`, `plan_count`, `plan_capacity` | `NamePlans`/`MAX_*`; **plan_count/capacity нет** | stats/control | — | **Нет публичного count/capacity**; stats R2O не печатает | control unit | partial |
| Silence/FIN: `silence_deadline`, `tcp_silence_observe`, `fin_retry_window`, `fin_window_over`, `sweep_one`, `sweep_udp_one` | `TcpSessions::{expire_with_silent,sweep_silent,fin_retry_candidates,mark_fin_retry}` (`engine.rs:693-788`), `R2oUdpSessions::expire` (`:456`), `R2oVoiceSessions::sweep` (`r2o_voice.rs:581`), `R2oQuicSessions::sweep` (`r2o_quic.rs:478`), `send_pending_tcp_fin_retry` (`main.rs:3140`) | `main.rs:1073-1161`, `:1307` | silent detection, RTT, FIN retry, UDP sweep | Нет C/Rust дифференциала FIN retry и UDP sweep в полном объёме; `test-tcp-silence-current-differential.sh` покрывает TCP silence | `test-tcp-silence-current-differential.sh`, engine unit `tcp_fin_*`/`fin_retry` tests | partial |
| CT/stall: `quic_watch`, `flow_tuple`, `ct_flow`, `tcp_watch`, `tcp_in_band`, `tcp_band_top`, `ct_tcp_flow`, `set_stall_budgets`, `stall_budgets` | `R2oQuicSessions::r2o_quic_stall_candidates/update_r2o_quic_stall` (`r2o_quic.rs:503-574`), `TcpSessions::tcp_stall_candidates/update_tcp_stall` (`engine.rs:788-896`), `COMMAND_SET_TCP_STALL_BUDGETS` (`r2k-core/control.rs:52`, handler `main.rs:67-77`, `engine.rs:451`) | `main.rs:1094-1138` | conntrack counters, stall budgets, band | C `tcp_band_top`/`tcp_in_band`; R2O бюджеты в engine; нет C/Rust дифференциала stall budgets | `test-datapath-stats-timer-differential.sh` (частично), engine unit | partial |
| Sweep/expire: `d2k_session_sweep`, `d2k_session_expire` | `TcpSessions::expire_with_silent` (`engine.rs:698`), `expire` (`:693`), `R2oUdpSessions::expire` (`:456`), `R2oQuicSessions::expire` (`:609`), `R2oVoiceSessions::expire` (`:626`) | `main.rs:1073` | idle expiry, silent first | C одна пара таблиц; R2O четыре | `tcp_session_table_expires_idle_flows...` (`engine.rs:5032`) | partial |
| Metrics: `d2k_session_flows`, `send_pending`, `sent`, `exec_failed`, `guards`, `client_shape`, `damaged`, `unsent`, `applied`, `done`, `damaged_count`, `sent_lost`, `refusals`, `capacity`, `flows_tcp/udp`, `capacity_tcp/udp`, `refusals_tcp/udp`, `hellos`, `with_sni`, `suspects`, `rst_dropped`, `exchanges`, `reply_hidden`, `tcp_hello_flows`, `payload_stats`, `journal` | `TcpSessions::{len,r2o_tcp_flow_capacity,r2o_tcp_flow_refusals,r2o_flow_metrics,r2o_http_keepalive_stats,r2o_tcp_payload_stats,r2o_tcp_hello_flows,r2o_tcp_hellos_with_sni,r2o_reply_hidden,r2o_tcp_rst_dropped}` (`engine.rs:430-552`), `R2oUdpSessions::stats` (`r2o_udp_sessions.rs:465`), `R2oFlowJournal` | `main.rs:665-763` | почти все счётчики | **Нет `exchanges`, `suspects` (episode counters), `nat_stats`, `shape_misses`, plan count/capacity.** C `d2k_session_suspects`/`exchanges` — агрегаты; R2O отдаёт события, не агрегаты. | stats differential (subset) | partial |

### d2kd.c (45 функций)

Все ссылки вида `:NNN` в колонке Rust-аналога этой таблицы относятся к `crates/r2o-datapath/src/main.rs`, если не указан другой файл.

| C-функция / группа | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `on_signal` | `install_signal_handlers` (`main.rs:3622`), `STOP` | shutdown | SIGINT/SIGTERM, SIGPIPE | C `stop_flag`; R2O AtomicBool | unit/process | partial |
| `self_cost`, `now_ns` | `r2o_process_cost_from_proc` (`:566`), `r2o_process_cost` (`:602`), `Instant` | stats | `/proc/self/stat`, `statm`, CPU ms, RSS | C `sysconf(_SC_CLK_TCK)`; R2O использует `_SC_CLK_TCK`/`_SC_PAGESIZE` (`main.rs:606-608`); stats differential проверяет формат | `process_cost_matches_d2o_proc_state_cursor_and_rss` (`:4270`), `process_stats_line_matches...` (`:4279`) | partial |
| `emit` (static helper) | `transmit_many` (`:3771`), `flush_scheduled` (`:3956`) | отправка | — | C `emit` helper; R2O распределён | raw differentials | partial |
| `count_reason` | — | — | — | **Причины пропуска не агрегируются.** C печатает `пропуск «%s»: N` по 32 причинам; R2O `res.skipped` есть, но сводки причин нет. | — | missing |
| `icmp_step` | `R2oIcmpGuard::r2o_handle_at_hook` (`r2o_icmp_guard.rs:127`), `main.rs:1358` | пакетный путь | ICMP only, hook gating, verdict, counters, first-drop log | C `st.icmp_seen`; R2O `seen`; C DROP/ACCEPT counters in main; R2O `send_verdicts` | `test-icmp-guard-current-differential.sh` | partial |
| `log_send_fail` | `r2o_log_raw_stats`? / `log_send_fail` отсутствует | — | — | **Нет эквивалента**: C первые 16 строк busy + счётчик; R2O `eprintln!` на каждую ошибку в `transmit_many`, без лимита 16 | — | partial/missing |
| `before` (static helper) | — | — | — | Тривиальный helper; в R2O нет отдельной функции | — | not-applicable |
| `routes_routed` | `R2oRouteGate::r2o_mark_is_routed` (`r2o_route.rs:175`) | `main.rs:1401` | callback | — | route gate diff | partial |
| `describe_oifs` | — | — | — | **Текстового описания OIF нет.** R2O печатает maxlen, но не список интерфейсов | — | missing |
| `cap_refresh` | `main.rs:855-862`, `:1239-1251` | старт/refresh | adopt egress, обновить send_maxlen, greeting | C `d2k_sched_grow_slot_size`; R2O динамический Vec, нет grow | `test-datapath-default-mode-differential.sh` | partial |
| `send_original_verdict`, `send_delayed_verdict` | `send_verdicts` (`:3723`), `release_accepting` (`:3671`), `release_many` (`:4165`) | вердикты | counters, ошибки | C `st.verdict_fail`; R2O считает в `send_verdicts`? | `test-datapath-stats-timer-differential.sh` (subset) | partial |
| `delayed_verdict_done` | `r2o_complete_delayed_udp_batch` (`:363`), `r2o_cancel_delayed_udp_batch` (`:387`), `r2o_finish_tcp_execution` (`:410`) | отложенные | DONE/fail | — | unit | partial |
| `hold_owns` | `HoldTable::feed`/`feed_observing` `own_packets` (`hold.rs:76`), `main.rs:1643` | hold | TCP not port 80 | — | `owned_tls_*` tests (`hold.rs:2142`) | partial |
| `resend_original`, `resend_originals` | `r2o_resend_owned_originals` (`main.rs:3654`), `r2o_flush_owned_hold_releases` (`:3666`) | возврат оригиналов | raw send, counters, fail lines | C `st.hold_resent/fail`; R2O счётчиков нет | `owned_tls_timeout_replays...` (`hold.rs:2142`) | partial |
| `release_original` | `release_accepting` + `r2o_flush_owned_hold_releases` | flush | UDP hold end, note_unassembled, observe_tcp, verdict/resend | — | hold tests | partial |
| `ct_query`, `ct_probe` | `R2oConntrackClient::query/probe` (`conntrack.rs:297`, `:309`), `main.rs:919`, `:1094` | stall detectors | probe at startup/refresh, query on sweep | C `ctl_ct.up` sticky; R2O `conntrack` Option, reopens on route refresh | `test-conntrack-retry-current-differential.sh` | partial |
| `out_verdict` | `send_verdicts`/`release_accepting` | verdict | — | — | unit | partial |
| `out_fail`, `out_send_now`, `out_send_at`, `out_send_at_owned` | `transmit_many` (`:3771`), `flush_scheduled` (`:3956`), `ScheduledQueue::push_reserved` | raw emit | ENOTSOCK/ENOSPC/errno, deferred | C `out_send_at` uses `d2k_sched_push_serial`; R2O `WirePacket` + ticket. C `out_send_at_owned` owner id; R2O `pending_udp_releases`. | raw/scheduler diffs | partial |
| `out_marked` | `r2o_udp_mark_plain_pass`? / `udp_follow` stats; **функции логирования нет** | — | — | **Нет строки «поток UDP ... с меткой клиента»**; R2O только счётчик `r2o_log_udp_follow_stats` (refused/busy/queue_full), без `udp_marked_kept` | — | partial/missing |
| `out_defer` | `R2oUdpDeferredVerdicts::r2o_enqueue` (`r2o_udp_hold.rs:291`), `main.rs:225` | UDP deferred verdict | — | — | unit | partial |
| `out_resend_failed` | `r2o_udp_follow.r2o_mark_failed` (`r2o_udp_hold.rs:582`), `main.rs:2550` | follow failure | — | C печатает адрес/порты/семейство/длину для первых `D2K_UDP_REFUSED_LOG`; R2O только счётчик | — | partial |
| `http80_log`, `http80_io_payload`, `http80_io_accept`, `http80_io_rst`, `http80_cut`, `http80_step` | `http_replace.rs`, `main.rs:1966-2000`, `send_http_response_event`/`send_http_portal_event` | HTTP80 | замена/307/RST/событие/CUT | **Нет `http80_log`** и полного `http80_step`; логика в main/hold. C `test_http80.c`/`test_http_trace.c` прямого Rust-дифференциала не имеют. | hold/http_replace unit | partial |
| `usage`, `arg_u32`, `port_of` | `print_help` (`:2808`), `parse_value`/`parse_mark` (`:2767`, `:2785`), `u16` | CLI | — | `port_of` тривиален | — | partial |
| `print_stats` | `r2o_log_process_stats`, `r2o_log_queue_stats`, `r2o_log_flow_table_stats`, `r2o_log_scheduler_stats`, `r2o_log_session_stats`, `r2o_log_capture_stats`, `r2o_log_payload_stats`, `r2o_log_hold_stats`, `r2o_log_raw_stats`, `r2o_log_udp_follow_stats` (`main.rs:626-763`) | stats | значительная часть | **Отсутствуют:** HTTP80 stats, hold ownership (owned/resent/fail), NAT stats, routed flow count, UDP marked count, shape misses, plan count/capacity, reasons, exchange/suspect counters, `D2K_EV_STATS` with dropped+sent. Формат/префиксы отличаются (`r2o-datapath:` vs `d2kd:`). | `test-datapath-stats-timer-differential.sh` сверяет подмножество | partial |
| `proto_name`, `jrn_kind`, `print_journal` | `format_journal_key` (`:2840`), `format_journal_details` (`:2860`), `format_journal_refusal_code` (`:2931`) | shutdown print | журнал | R2O печатает `нс` и другой формат; C `мс` и `proto_name`; полного differential нет | — | partial |
| `refuse_of_errno` | `refuse` code mapping в `transmit_many`/`flush_scheduled` | send failure | EMSGSIZE→TOO_LONG, остальное SEND | R2O коды `R2O_JOURNAL_REFUSE_*`, mapping может отличаться | unit | partial |
| `offline_self_check` | — | — | — | **Нет SHA256 self-check.** C `--offline-self-check` проверяет `SHA256("abc")` и wire version; R2O `--version` только печатает. | — | missing |
| `main` | `run` (`:765`) | daemon | CLI, queue, raw, control, loop, stats, shutdown | **Флаги:** нет `--log`, `--duration`, `--health-file`; `--udp-reverse-hook`→`--r2o-udp-reverse-visible`; `--flows`→`--r2o-flow-capacity`; нет `--plan` default? R2O default `/etc/r2o/plans/current.r2op`. Добавлены `--family`,`--rcvbuf`,`--check`,`--controller-only`. C apply требует mark; R2O `needs_raw_socket`. C `--duration` exit; R2O только SIG. | `test-datapath-default-mode-differential.sh`, `test-nfq-netns.sh`, `test-datapath-stats-timer-differential.sh` | partial |

## Таблицы detect по файлам

### trigger.c (9 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `d2k_trigger_tls` | `Trigger::tls` (`classify.rs:87`), `Trigger::tls13` (`:96`), `hello::legacy_client_hello`/`modern_client_hello` (`hello.rs:284`, `:289`), `classify_target_trigger` (`main.rs:1358`) | CLI/дерево | SNI, legacy/modern, `tls:<sni>`, `ServerHello`, SNI offset/len | C profile builder `d2k_hello_from_profile`; Rust profile files. Нет дифференциала всех профилей/длин SNI, только white-decoy/composite. | `test-classifier-white-decoy-differential.sh`, `hello.rs` tests | partial |
| `hexval` (static) | `trigger.rs:4 parse_raw_hex` | CLI `--raw` | hex nibble | — | `trigger.rs` tests | partial |
| `d2k_trigger_raw_hex` | `Trigger::raw_hex` (`classify.rs:77`), `parse_raw_hex` (`trigger.rs:4`) | CLI `--raw`, `--control-raw` | separators, odd/invalid/short/oversize, `raw:NB`, Accept::Any | R2O limit 16384; C `D2K_TRIGGER_MAX = D2K_ARM_TRIGGER_MAX = 16384` (`d2k_arm.h`). Текст oversize отличается. | `trigger.rs:45`, `:54`; `test-classifier-raw-production-differential.sh` | partial |
| `d2k_trigger_control` | `classify_control_trigger` (`main.rs:1327`), `hello::legacy_client_hello` | CLI/дерево | `probe-d2k.invalid-control.example`, Accept::TlsRecord | C `probe-%s.invalid-control.example` (tag `d2k`); R2O default SNI `probe-d2k.invalid-control.example` (`main.rs:1345`) — совпадает | `main.rs:1327` tests, shared fixtures | partial |
| `d2k_opts_decoy` | `ClassifyOptions::decoy`? (`classify.rs`), `select_bridge_decoy` (`raw_probe.rs:602`) | tree | decoy vs control | R2O `decoy` в bridge выбирает client clone/control | `raw_probe` unit | partial |
| `d2k_trigger_host_ts_override`, `host_offers_ts` (static), `d2k_trigger_offers_ts` | `HOST_TCP_TIMESTAMPS`/`raw_offer_timestamps` (`raw_probe.rs:673`) | raw profile | `/proc/sys/net/ipv4/tcp_timestamps`, override для тестов | C static cache + override setter; R2O `OnceLock`, нет публичного override (тесты используют `client_tcp_has_timestamps`) | `raw_probe.rs:2461 white_hello_ts...`, `test-classifier-white-decoy-differential.sh` | partial |
| `d2k_trigger_allows_poison` | `raw_profile_allows` (`raw_probe.rs:731`) | sweep | `!p->tcp_ts || offers_ts` | — | raw profile tests | partial |

### response.c (7 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `resp_timeout` (static) | `response_timeout` (`response.rs:108`) | handshake | `<3000` иначе 3000 | — | response tests | partial |
| `d2k_resp_scan12` | `scan12` (`response.rs:1167`) | handshake | TLS records, fragmentation, ServerHelloDone, fatal alert, incomplete | C возвращает 1 при alert (done=0); Rust `FatalAlert`; C не возвращает `ServerHello` отдельно; Rust `Scan12::ServerHello` используется в `scan_server_hello` | `test-d2o-shared-fixtures.sh` (13 vectors), `response.rs:1261` response unit | equivalent (scoped) |
| `d2k_resp_handshake12` | `handshake` (`response.rs:969`), `resolve_address` (`:127`), `probe_socket` (`:233`) | `probe_response` | legacy hello, DNS family, SO_MARK, TCP_NODELAY, timeouts, connect, send, poll/recv, `RESPONSE_CAP`, alert/SHD | C `getaddrinfo` per attempt; Rust `resolve_address` per attempt. C treats poll EINTR as failure; Rust `poll <=0` failure. C `RESPONSE_CAP=65536`; Rust same. Нет дифференциала DNS-ротации/всех errno. | shared fixtures, `d2o_verify_differential.rs`, `test-classifier-full-tree-control-differential.sh` | partial |
| `count_handshakes` (static) | `count_handshakes` (`:1067`) | probe | sequential repeats, unmeasured, DNS failure counts failed | — | response tests | partial |
| `d2k_neutral_sni` | `neutral_sni` (`:1091`) | probe | `/dev/urandom`, fallback xorshift, `z<10hex>.example.com` | C fallback uses `clock_gettime/getpid/counter`; Rust `SystemTime/process id/counter`; формат совпадает | response unit | partial |
| `d2k_resp_decide` | `decide` (`:1223`) | probe | unmeasured>0, control=0, target=repeats, target=0, flaky; причины | Текст причины R2O совпадает по смыслу; байтовое сравнение reason не заявлено, эквивалентность ограничена `(verdict,target,control)`. | shared 13 vectors | equivalent (scoped) |
| `d2k_probe_response` | `probe_response` (`:1126`) | classifier `run` | target/control repeats, neutral SNI, probes | C `probes += 2*repeats` в classify; Rust `probes` считает фактические попытки; `ClassifyResult` добавляет. | shared fixtures, full-tree follow-up | partial |

### poison.c (12 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `d2k_poison_supports_family` | `poison_supports_family` (`classify.rs:389`) | sweep | IPv4 любой, IPv6 без ip_id_zero | — | unit | partial |
| `d2k_poison_has_fake` | `poison_has_fake` (`classify.rs:382`) | strategy/sweep | syn_data/oob/fake_between исключены; badsum/md5/ttl/autottl/seq_shift/tcp_ts | **R2O не учитывает `autottl`**. Сегодня C `p->autottl` нигде не выставляется, поэтому поведение совпадает, но контракт уже. | unit | partial |
| `add`, `already_listed` (static) | `add_poison` (`classify.rs:215`), `same_hypothesis` (`:200`) | init | — | — | unit | partial |
| `d2k_poison_same` | `Poison::same_hypothesis` (`classify.rs:200`) | dedup | name cleared, repeats<=1→1 | Rust `Poison` содержит `split_pos`, C тоже; поля совпадают? | unit | partial |
| `init_poisons` (static), `d2k_poisons` | `build_poisons` (`classify.rs:223`), `poisons` (`:377`) | sweep | 85 гипотез, порядок, TTL/seqovl/gap/repeats, dedup badsum | Списки совпадают по коду; нужен точный тест эквивалентности 85 имён/полей. `test-classifier-candidate-filter-differential.sh` проверяет фильтры, не полный список. | `classify.rs` unit?; `test-classifier-candidate-filter-differential.sh` | partial |
| `d2k_note_props_hit` | `note_props_hit` (`classify.rs:173`) | sweep | badsum/ttl/disorder/seqovl/decoy_hello | C `else if`; Rust same | unit | partial |
| `d2k_note_props_miss` | `note_props_miss` (`classify.rs:189`) | sweep | disorder, seqovl без decoy | — | unit | partial |
| `d2k_strategy_for_poison` | `strategy_for_poison` (`classify.rs:394`) | hit | все ветви: syndata/oob/fakedsplit/fake+overlap/seqovl/disorder/etc. | Rust `poison_has_fake` без autottl; `strategy_for_poison` при неизвестной комбинации возвращает `None`, C всегда пишет строку (может пустую) | `test-classifier-raw-production-differential.sh` проверяет стратегии для badsum/seqovl-1/property/compose | partial |
| `d2k_strategy_for` | — | — | — | **Функции нет.** C `--lua-desync=multisplit:payload=unknown:dir=out:pos=%d` для найденной границы; R2O генерирует `plan_text`/R2OP, не эту строку | — | missing |
| `d2k_arm_from_poison` | `make_poison_hit`/`executable_poison_hit` (`raw_probe.rs:1101`, `:1122`), `classify::plan_text_for_poison`, `plan_text::compile_text` | hit | arm→plan, unplannable reasons | R2O компилирует R2OP и валидирует runtime; C создаёт `d2k_arm` и позже план. `syndata`/`oob`/seq_shift branching сверить. | `test-classifier-raw-production-differential.sh`, `test-classifier-full-tree-control-differential.sh` | partial |

### props.c (7 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `prop_probes` (static) | `property_probes` (`raw_probe.rs:840`) | sweep | 12 вопросов, порядок, labels, poisons | C `PROP_QUESTIONS=12`; Rust Vec capacity 12. Списки совпадают; `white-hello-ts` fields (tcp_ts, decoy, repeats=8, split_pos=2) совпадают. | `raw_probe.rs:2461 white_hello_ts...`, `test-classifier-white-decoy-differential.sh` | partial |
| `apply_set` (static) | `apply_property` (`raw_probe.rs:1005`) | run | все Property, только pass для CHECKSUM/PARSES/etc. | C/Rust `TriState` mapping | unit | partial |
| `d2k_run_properties` | `raw_probe::run_properties`? (`classify.rs:683/693 sweep_poisons` + `raw_probe`); публичная функция в `raw_probe` | sweep | 12 вопросов, majority, skip, ts/white/seqovl-sni preconditions, local error | **R2O majority/compose в raw_probe; полного C/Rust дифференциала 12 вопросов нет.** `test-classifier-raw-production-differential.sh` проверяет property case (ServerHello на первом property) и compose case. | `test-classifier-raw-production-differential.sh`, `r2o-raw-profile-differential.sh` | partial |
| `d2k_run_properties_family` | `raw_probe::...` + `classify.rs:683 sweep_poisons_with_progress` | sweep | family v4/v6 | C IPv6 `poison_supports_family`; R2O same | unit | partial |
| `tri_no`, `tri_yes` (static) | `TriState` matches | compose | — | — | unit | partial |
| `d2k_compose_from_props` | `compose_from_props` (`raw_probe.rs:1047`) | sweep | duplicates (2×20, 7), overlap, disorder, all-at-once, control len | **Расхождение:** C при `n==0` всегда создаёт «СОБРАНО: всё сразу» (`props.c:477-486`), даже если `ctl==NULL`; Rust `compose_from_props` добавляет all-at-once только `if control.is_some()` (`raw_probe.rs:1094`). При отсутствии control R2O не даст кандидата. В обычном detect control есть. | `test-classifier-raw-production-differential.sh` (compose case с control) | partial |

### classify.c (36 функций)

| C-функция / группа (все члены) | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| Names/clock: `d2k_verdict_name`, `d2k_resp_name`, `d2k_now_ms`, `d2k_sleep_ms` | `Verdict::as_str` (`classify.rs`), response enum mapping, `Instant`, `thread::sleep` | CLI/tree | — | C `d2k_clock_offset_ms` глобальный; R2O нет | unit | partial |
| `d2k_trigger_accepts` | `trigger_accepts` (`classify.rs:543`) | probes | ServerHello, TLS record, any (empty=false) | — | shared fixtures | equivalent (scoped) |
| `d2k_trigger_sni` | `Trigger.name`/`sni` helpers (`classify.rs:87-105`), `classify_target_trigger` | classify | `tls:` prefix | — | unit | partial |
| `d2k_detect_stopped` | `ClassifyOptions.cancel` (`AtomicBool`), `is_cancelled` (`raw_probe.rs:641`) | tree | task stop/all | C sticky global; R2O `AtomicBool` per options + global shutdown | unit | partial |
| `d2k_opts_defaults` | `ClassifyOptions::default` (`classify.rs:860`) | CLI/tree | repeats=3, timeout=6s, write_gap=60, long_gap=700, mark: C 0x40000000 / R2O 0x2d | **Расхождение:** C `D2K_BYPASS_MARK = 0x40000000`, R2O `BYPASS_MARK = 0x2d` (`response.rs:71`, `raw_probe.rs:637`). R2O CLI `mark: None` → 0x2d. Без явного `--mark` зонды C и R2O идут с разными метками. | `test-classifier-so-mark-production-differential.sh` (loopback, явная метка) | partial |
| `d2k_opts_acceptable`, `d2k_opts_skipped` | `poison_selected` (`classify.rs:885`), `ClassifyOptions.only_poison/skip_poisons` | sweep | only/skip, accept callback | C `accept` callback = `plannable_hit`; R2O `make_poison_hit`/unplannable | unit | partial |
| `d2k_trace_add` | `add_observation` (`raw_probe.rs:631`) | tree | trace limit | C `D2K_TRACE_MAX`; R2O `Vec` без жёсткого? | unit | partial |
| `obs_done` (static) | progress callback in `run_with_backend_progress` (`classify.rs:1298`) | tree | — | — | CLI progress differential | partial |
| `d2k_note`, `note_gap_loss` | — | — | — | **`notes` отсутствуют.** C накапливает до `D2K_NOTES_MAX` и печатает/JSON; R2O `ClassifyResult` поля `notes` нет; `note_gap_loss` (оценка потерь на gap) отсутствует. | — | missing |
| `d2k_split_offsets` | `split_offsets` (`classify.rs` ~?); `raw_probe::probe_tcp_split` | split | cuts, sort, dedup, cap 8 | — | `test-classifier-full-tree-control-differential.sh` | partial |
| `dial_marked_mode`, `dial_marked`, `d2k_dial_deadline_err` | `dial_probe_target` (`response.rs:643`), `ProbeError::DialTimeout/Transport`, `is_dial_timeout` (`classify.rs:575`) | tree | SO_MARK, TCP_NODELAY, nonblock connect, timeout, require_mark | R2O `dial_probe_target` для raw split; socket probes use `response::probe_trigger`; соответствие ветвей не полное | `r2o-tcp-exchange-differential.sh`, `r2o-socket-split-deadline-differential.sh` | partial |
| `once_probe` (static) | `probe_trigger` (`response.rs:695`), `raw_probe::probe_tcp_split` (`:1140`), `raw_probe_once` (`:1174`) | measure | raw split gate, resolve, send, gap, cancel, poll, recv, accept | C returns numeric peer on raw connect timeout; Rust `ProbeError::RawConnectTimeout { peer }`; retry logic in `measure`/classify. Нет дифференциала всех ветвей. | raw production differential, socket split deadline | partial |
| `unacked_bytes`, `d2k_probe_data_ack` | `unacked_bytes` (`response.rs:872`), `probe_neutral_ack` (`:817`) | tree | TIOCOUTQ/SO_NWRITE, poll 20ms, cancel | R2O returns `ProbeError::Unsupported` on other platforms; C returns -2 | `test-tcp-silence-current-differential.sh`? neutral-ack coverage | partial |
| `measure`, `d2k_tally` | `measure`/`measure_baseline` (`classify.rs:1076`, `:1904`), `run_with_backend_progress` | tree | repeats, seeded whole, until_pass, raw connect timeout recovery | C `seed_whole` optimization; R2O `seed_whole`; C `transport:raw-connect` trace; R2O tests cover. | `raw_connect_timeout_runs_control_then_retries_once...` (`classify.rs:2490`) | partial |
| Poison helpers: `bind_decoy`, `answered_by_props`, `fam_ix`, `self_ix`, `selftest_cached_age`, `selftest_store`, `d2k_raw_note_rc`, `raw_selftest`, `raw_doubted`, `raw_recheck` | `select_bridge_decoy` (`raw_probe.rs:602`), `note_raw_probe` (`:701`), `raw_selftest_age` (`:685`), `store_raw_selftest` (`:735`), `should_recheck` (`:669`), `raw_recheck` (`:746`), `raw_selftest` (`raw_probe.rs` ~?); `sweep_poisons_with_progress` | sweep | cache per family/ts, 2 errors/0 success recheck, props restore | C `d2k_raw_note_rc` counters; R2O `RawSelftestState`. Нет полного differential self-test cache/recheck. | `r2o-raw-profile-differential.sh`, `raw_selftest_recheck_requires...` (`raw_probe.rs:2513`) | partial |
| `sweep_poisons` | `sweep_poisons_with_progress` (`classify.rs:693`, `TcpProbeBackend`), `raw_probe` | tree | self-test, properties, compose, poison list, only/skip, family, decoy, answered_by_props, raw_doubted | C `raw_rst_fail_count` branch; R2O `RstGuard` counters. C `props0` restore; R2O maybe. Нет полного дифференциала 85 гипотез. | `test-classifier-raw-production-differential.sh` (93 probes), `test-classifier-full-tree-control-differential.sh` | partial |
| `cross_check_tls12` (static) | — | — | — | **В C это заглушка** (`classify.c:1079-1092`: «НЕ ПЕРЕНОСЕНО», `covers_tls12=UNSET`, note). В R2O функции/поля нет. Контракт не реализован ни там, ни там. | — | not-applicable (C stub) / missing (R2O field) |
| `d2k_classify_run` | `ClassifyResult::run_with_backend_progress` (`classify.rs:1298`), `run` (`:1929`) | CLI/Discovery | target parse, localhost guard, trigger len, baseline, double timeout retry, clear+response, split, control, neutral-ack, sweep, address/opaque/flaky/whole-prefix boundary, response | C has `cross_check_tls12` stub; R2O no. C `covers_tls12`; R2O no. C `d2k_opts.cancel` vs R2O AtomicBool. C `--progress` via `on_obs`; R2O callback. | `test-classifier-full-tree-control-differential.sh`, `test-classifier-clear-confirm-differential.sh`, `test-d2o-shared-fixtures.sh`, `test-classifier-raw-production-differential.sh` | partial |
| `d2k_send_nosig` | `libc::send(... MSG_NOSIGNAL)` in `probe_trigger`/`raw_probe` | probes | SIGPIPE | — | unit | partial |

### bridge.c (17 записей, 15 функций + макрос `SEEDED`)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `d2k_detect_stop_all`, `stop_asked` (static) | `R2O_CONTROLLER_STOP`/`r2o_controller_request_stop` (`main.rs:80`), `ClassifyOptions.cancel` | Discovery worker | sticky stop + task stop | R2O per-task AtomicBool + global | unit | partial |
| `plannable_hit` (static) | `make_poison_hit`/`executable_poison_hit` (`raw_probe.rs:1101`, `:1122`), `r2o_discovery_search_owned` (`main.rs:5530`) | bridge | plannable filter, unplannable first/others | C records first/why/others; R2O `UnplannablePoison` list; формат причины другой | `test-classifier-raw-production-differential.sh`, `r2o-measured-split-differential.sh` | partial |
| `map_verdict` | `Verdict` conversion in `r2o_discovery_search_owned`/`bridge_search_owned` (`main.rs:5530`, `:5560`) | bridge | clear/prefix/whole/opaque/address/response/unreachable/flaky | R2O `Verdict` enum | unit | partial |
| `bridge_input` (static) | `r2o_discovery_search_owned` (`:5530`), `r2o_discovery_bridge_search_owned` (`:5560`), `r2o_target_confirmed_probe_path` (`:2588`) | worker | trigger clone, TCP options, SNI extraction, control/decoy/white, repeats/gap/timeout/mark/cancel, address format | C `control_vouched=0` for scheduler-supplied control; R2O `control_vouched` option. C `trigger.snapped`/clone decoy; R2O `select_bridge_decoy`. | `r2o-scheduler-differential.sh`, `test-classifier-white-decoy-differential.sh` | partial |
| `progress_seen` (static) | progress closure in `run_with_backend_progress`, Discovery `update_probe_progress` (`main.rs:9604`) | worker | seeded whole, probe pass/fail | — | `r2o-scheduler-*`, `--progress` differential | partial |
| `trace_questions` (static) | `qtrace`/property labels in `raw_probe.rs`/Discovery diagnostic | worker | property labels, utf-8 truncation, sent/answered/outcome | R2O `qtrace`/`Property` labels в `r2o-controller`; label truncation | `test-classifier-raw-production-differential.sh` | partial |
| `retry_base_timeout` (static) | `is_dial_timeout_text` (`classify.rs:1244`), `measure_baseline` | worker | one fresh baseline on dial timeout | — | `raw_connect_timeout...` tests | partial |
| `sched_tcp` (static) | `r2o_discovery_bridge_search_owned` (`main.rs:5560`), `r2o_discovery_search_owned` (`:5530`) | scheduler hook | full tree, seed, white, stop, verdict, arm | C `owns_search` logic; R2O `r2o_discovery_bridge_search_owned`/split gate. Нет прямого C/Rust bridge differential. | `r2o-scheduler-differential.sh`, `r2o-known-plans-differential.sh` (косвенно) | implemented-unproven |
| `d2k_detect_sched_tcp`, `_white`, `_seeded`, `_seeded_white` | `r2o_discovery_search_owned`/`bridge_search_owned` + white/seed options | scheduler | variants | C four entrypoints; R2O options. | scheduler/Discovery differentials | partial |
| `SEEDED` (макрос, не функция) | — | — | — | Ложное срабатывание извлечения; не функция | — | not-applicable |
| `base_seen`, `base_stop` (static) | `run_base_with_backend_progress` (`classify.rs:1842`), baseline callback | base question | stop after whole | — | `r2o-scheduler-dead-address-differential.sh` | partial |
| `d2k_detect_sched_tcp_ack` | `probe_neutral_ack` (`response.rs:817`), `r2o_discovery` base/ack caller | scheduler | repeats, 0/1/-1, probes | C `d2k_probe_data_ack`; R2O | `r2o-scheduler-dead-address-differential.sh` | partial |
| `d2k_detect_sched_tcp_base` | `run_base_with_backend_progress` (`classify.rs:1842`), `measure_baseline` (`:1904`) | scheduler | whole only, no raw, seed validity, unreachable/clear/flaky | C returns `D2K_V_*`; R2O `Verdict` | `test-classifier-full-tree-control-differential.sh` | partial |

### raw.c detect (62 записи; production-функции сгруппированы)

| C-функция / группа (все члены) | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| RST rule parse: `parse_long_exact`, `d2k_parse_rst_rule`, `d2k_parse_stale_rst_rule`, `pid_alive`, `d2k_rst_rule_stale`, `d2k_raw_alive_hook` | `RstRule::install` (`raw_probe.rs:1501`), `RstGuard` (`:1613`), `rst_delete_once` (`:1638`), `sweep_stale_iptables` (`:1749`) | raw probes | nft/iptables rule, port/pid, stale detection | C `d2k_raw_alive_hook` pluggable; R2O `pid_alive`? (нет отдельной функции; проверка в `install`) | `raw_probe.rs:2723 nft_rst_rule...`, `:2757`, `:2770` | partial |
| RST lifecycle: `raw_rule_system`, `d2k_raw_rst_fail_count`, `rst_nft`, `sweep_stale_rst_rules`, `rst_rule_cmd_form`, `rst_rule_cmd`, `rc_exit1`, `rst_delete_once`, `rst_abandon`, `register_atexit`, `rst_remember`, `retry_pending_releases`, `rst_release_locked`, `d2k_raw_flush_pending`, `d2k_raw_pending_count`, `raw_atexit`, `rst_key_of`, `suppress_kernel_rst`, `release_kernel_rst` | `RstRule::{install,nft_args,iptables_args}` (`:1501-1613`), `RstGuard::{from_install_result,drop,rst_delete_once_locked,rst_release,retry_pending_rst_releases,register_rst_cleanup,sweep_stale_iptables}` (`:1619-1849`), `r2o_rst_uses_nft` (`:1496`) | raw probe connect/drop | nft table `r2o_rst`, timeout 300s, exact tuple, pending retries, sweep stale, atexit | **C table `d2k_rst`; R2O `r2o_rst`.** C `RST_PENDING_MAX=64`, 5 attempts; R2O `RST_PENDING_MAX=64` (`raw_probe.rs:28`). C iptables fallback; R2O `r2o_rst_uses_nft` + iptables args. | `raw_probe.rs:2723`, `:2757`, `:2770`; `test-firewall-nft-down-rst-lifetime-differential.sh`, `test-router-tg-firewall.sh` | partial |
| Seed/ports: `seed_init`, `seed_once`, `next_source_port`, `d2k_raw_dial_count` | `random_u32` (`:1419`), `next_source_port` (`:1441`), `RawConn` | raw probe | source port random, dial counter | R2O random source port; C `seed_once` global | unit | partial |
| Build/send primitives: `local_addr_for`, `rd16`, `rd32`, `wr16`, `wr32`, `checksum`, `tcp_checksum`, `build_ipv4_tcp`, `tcp_checksum_family`, `build_ip_tcp`, `raw_sendto`, `d2k_raw_set_segment_max`, `raw_send`, `raw_send_syn` | `local_address_for` (`:1463`), `internet_checksum` (`:1308`), `tcp_checksum` (`:1328`), `tcp_checksum_valid` (`:1324`), `build_control_packet` (`:1350`), `RawConn::send_ip_packet` (`:2002`) | raw | IPv4/IPv6 packet, options, checksum, mark, segment max, SYN | C `build_ip_tcp` handles both families; R2O `build_control_packet` IPv4/IPv6. C `raw_send_syn` separate; R2O `RawConn::connect`. Нет дифференциала всех профилей SYN. | `raw_probe.rs:2870 builds_an_ipv4_syn...`, `:2896 builds_an_ipv6_syn...`, `:2348 raw_syn_profile_matches...`, `r2o-raw-profile-differential.sh` | partial |
| Connection: `raw_recv`, `raw_read_payload`, `raw_close`, `raw_handshake`, `raw_dial` | `RawConn::{receive_segment,read_payload}` (`:2041`, `:2156`), `RawConn::connect` (`:1841`), `Drop` | raw probe | SYN/SYN-ACK, seq/ack, flags, payload, timestamp, timeout, cancel, retries | C `raw_dial` filters source port; R2O. Нет C/Rust дифференциала всех таймаутов/повторов. | `raw_probe.rs` unit, `r2o-raw-connect-fallback-differential.sh` | partial |
| Probe: `d2k_raw_probe_handshake_as`, `raw_send_plan`, `d2k_raw_probe_poison_family`, `d2k_raw_supported`, `d2k_raw_probe_handshake`, `_family`, `_poison`, non-Linux stubs | `raw_probe::{probe_tcp_split,raw_probe_once,raw_supported}` (`:1140`, `:1174`, `:63`), `emit_plan_packets` (`:1267`), `RawSelftestState` (`raw_probe.rs:40`) | classifier | plan apply, raw emits, cancel, timeouts, poison | **R2O не имеет `d2k_raw_probe_handshake_as`/`_handshake_family` как публичных функций**; handshake реализован внутри `RawConn::connect`. C non-Linux stubs; R2O target Linux. | `test-classifier-raw-production-differential.sh`, `test-raw6-send-differential.sh`, `test-raw6-live` (D2O), `r2o-raw-emission-cancel-differential.sh` | partial |

### main.c (8 функций)

| C-функция | Rust-аналог | Вызывающий путь R2O | Покрыто | Не покрыто / расхождения | Тесты / доказательства | Статус |
|---|---|---|---|---|---|---|
| `usage` (static) | `print_help` (`main.rs:1431`) | CLI | флаги | Тексты/набор флагов отличаются (`--save-plan`, `--arm`, `--probe-response` R2O-only) | unit | partial |
| `print_json_str`, `print_tri`, `print_json` | `classify_json::result_json_value` (`classify_json.rs:18`), serde_json | `--json` | target/verdict/reason/repeats/probes/duration/trigger_len/boundary/split_pos/reassembles/strategy/props/composed/raw_usable/trace/response/path | **`notes` отсутствует.** C `covers_tls12` (всегда UNSET); R2O нет. C `props` порядок полей; serde_json порядок вставки сохранён. C `strategy` и `path`; R2O есть. | `test-classifier-full-tree-control-differential.sh` (`--json` compare), `test-classifier-raw-production-differential.sh` | partial |
| `print_progress` (static) | progress closure (`main.rs:959`) | `--progress` | формат `[%4ld с] %-28s прошло=... не прошло=... err` | R2O печатает `[{:4} с] {:<28} прошло={} не прошло={}` **без `err`**; C печатает ошибку. Нет полного differential всех сообщений. | `test-classifier-full-tree-control-differential.sh` (`--progress`), `test-classifier-raw-production-differential.sh` | partial |
| `tri_word`, `print_human` | human print in `main.rs:1026-1078` | stdout | вердикт/причина/зонды/время/стратегия/ответ/трасса | **Формат и состав не совпадают:** C `Цель:`, `Триггер:`, `Вердикт:`, `Зондов:`, `Граница:`, `Пересборка:`, `Стратегия:` с пояснением, `Оговорка:`, `Свойства коробки:`, `Трасса:`; R2O `цель:`, `вердикт:`, `причина:`, `зонды:`, `время:`, `стратегия:`. C `notes` нет. | human output differential отсутствует | implemented-unproven |
| `main` | controller CLI (`main.rs:914-1078`), classify options parser (`:1128`) | CLI | exit codes: 2 usage, 1 trigger errors, 0 run | C always 0 after run; R2O returns `Err` for some cases; `--hello both` rejected обоими. R2O добавляет `--save-plan`, `--arm`, `--probe-response`. C `--control-sni`/`--control-raw` semantics; R2O `classify_control_trigger`. | CLI tests `classify.rs`/`main.rs`, differentials | partial |

## Функции без Rust-аналога

Ниже перечислены только те C-функции/контракты, для которых не найдено Rust-реализации с тем же назначением. Для части из них есть «похожая» логика в другом месте — это указано.

### Datapath

| C-функция | Файл | Что потеряно |
|---|---|---|
| `d2k_http_trace` | `datapath/http_trace.c:9` | Текстовая трасса HTTP-исполнения (`HTTP execution host=... status=...`) для поля/панели. R2O шлёт события, но не эту строку. |
| `d2k_sched_grow_slot_size` | `datapath/sched.c:73` | Предварительное расширение слота при смене MTU. R2O использует `Vec`, поэтому функция не нужна, но поведение «очередь уже вмещает новый предел до объявления контроллеру» не проверено. |
| `d2k_raw_limits` | `datapath/raw.c:271` | Маска возможностей raw-сокета (`D2K_RAW_CANT_IPID`). R2O заменил одной проверкой `validate_runtime_plan`; расширяемость потеряна. |
| `d2k_session_nat_stats` | `datapath/session.c:650` | Счётчики NAT: `ok/miss/none/retried`. R2O не печатает и не агрегирует их. |
| `d2k_session_plan_count`, `d2k_session_plan_capacity` | `session.c:2996`, `:3000` | Публичные count/capacity таблицы планов для сводки. R2O не имеет функций и не печатает строку. |
| `d2k_session_exchanges`, `d2k_session_suspects` | `session.c:3605`, `:3597` | Агрегаты числа обменов/подозрений. R2O отдаёт события, но не эти счётчики. |
| `d2k_plantab_shape_misses` | `plans.c:1058` | Счётчик «запись нашлась, но не подошла по форме». R2O не считает и не печатает. |
| `d2k_plantab_probe_count` | `plans.c:1020` | Публичный счётчик probe-записей. R2O не имеет. |
| `d2k_plantab_has_ech_target` | `plans.c:288` | Отдельная проверка наличия ECH-цели. R2O использует `SHAPE_ECH_TCP`/`has_tls_candidate`; отдельного контракта нет. |
| `d2k_plantab_stream_candidate`, `_family`, `_target` | `plans.c:316-352` | Точные функции выбора stream-кандидата. R2O заменил `has_tls/http/quic_candidate` и `select*`; поведение при нескольких кандидатах не доказано. |
| `d2k_routemark_describe` | `routemark.c:327` | Текстовое описание правил/OIF. R2O печатает только ошибки refresh. |
| `d2k_ctl_sent` | `ctl.c:316` | Счётчик отправленных кадров. R2O не имеет и не отправляет `D2K_EV_STATS` с `dropped+sent`. |
| `d2k_http80_get_stats` | `http80.c:75` | Счётчики requests/injections/evicted/untracked/unparsed/later. R2O не имеет. |
| `d2k_http80_request_result`, `d2k_http80_delivered`, `_executed`, `_sweep` как отдельные API | `http80.c:238-327` | R2O размазал по `hold.rs`/`main.rs`; отдельные публичные контракты не сохранены, полного differential нет. |
| `d2k_http_request`, `d2k_http_hello` (как отдельные публичные API) | `http80.c:551`, `:634` | R2O использует `r2k-core/httpup.rs`/`http_response.rs`/`tls.rs`; функции с теми же именами/контрактами нет, байтовое совпадение всех ветвей не доказано. |
| `d2k_suspect_text`, `d2k_refuse_text` (точные тексты) | `journal.c:41`, `:55` | R2O имеет свои русские строки; посимвольного соответствия нет. |
| `refuse_of_errno` (точная градация) | `d2kd.c:1114` | R2O mapping может отличаться; отдельного теста нет. |
| `count_reason` | `d2kd.c:165` | Агрегация причин пропуска в сводке. R2O не имеет. |
| `describe_oifs` | `d2kd.c:282` | Текстовое описание выходных интерфейсов. R2O не имеет. |
| `log_send_fail` (лимит 16 строк busy) | `d2kd.c:253` | R2O печатает каждую ошибку, без лимита. |
| `print_stats` в полном объёме | `d2kd.c:878` | Множество строк/счётчиков, см. таблицу d2kd.c. |
| `print_journal` (формат) | `d2kd.c:1070` | R2O печатает другой формат (`нс`, другой ключ/детали). |
| `offline_self_check` | `d2kd.c:1118` | SHA256-самопроверка и wire-константа. R2O `--version` не проверяет. |

### Detect

| C-функция | Файл | Что потеряно |
|---|---|---|
| `d2k_note`, `note_gap_loss` | `detect/classify.c:217`, `:238` | `notes[]` и оценка потерь на gap. R2O `ClassifyResult` не имеет `notes`; JSON/человеческий вывод не печатает оговорки. |
| `d2k_strategy_for` | `detect/poison.c:401` | Строка `--lua-desync=multisplit:payload=unknown...` для найденной границы. R2O генерирует план, не эту строку. |
| `cross_check_tls12` (C — заглушка) | `detect/classify.c:1084` | В C явно не перенесено; в R2O поля `covers_tls12` нет. Это не «потеря переноса», а незакрытый контракт в обеих реализациях. |
| `d2k_trigger_host_ts_override` | `detect/trigger.c:156` | Публичный setter для тестов/стенда. R2O использует `client_tcp_has_timestamps`/`HOST_TCP_TIMESTAMPS`, отдельного setter нет. |
| `d2k_resp_name` | `detect/classify.c:74` | Функция текстового имени response-вердикта. R2O формирует строки вручную в `main.rs`/`classify_json.rs`. |
| `d2k_raw_probe_handshake_as`, `d2k_raw_probe_handshake_family` (публичные) | `detect/raw.c:1187`, `:1364` | R2O реализует handshake внутри `RawConn::connect`; публичных функций с этими контрактами нет. |
| `d2k_parse_rst_rule`, `d2k_parse_stale_rst_rule`, `d2k_rst_rule_stale` (публичные) | `detect/raw.c:79-137` | R2O имеет внутренние `RstRule`/`RstGuard`, но не эти публичные парсеры; C `test_raw.c` проверяет их напрямую. |
| `d2k_raw_flush_pending`, `d2k_raw_pending_count` (публичные) | `detect/raw.c:481`, `:488` | R2O имеет `RstGuard::retry_pending_rst_releases`, но не публичные flush/count с теми же именами. |
| `d2k_raw_set_segment_max` (публичная) | `detect/raw.c:814` | R2O устанавливает размер сегмента через параметры `RawConn`/trigger, публичного setter нет. |

## Rust-код без C-аналога

| Rust-контракт | Файл:строка | Почему это не C-перенос |
|---|---|---|
| Формат плана `R2OP` и компилятор `plan_text` | `r2k-core/src/plan.rs:11`, `r2o-controller/src/plan_text.rs:64`, `classify_measured.rs:14`, `ask.rs:424` | C использует `D2KP`; R2OP — новый контейнер/формат, несовместимый с D2O. |
| Управляющий протокол v48 и новые события | `r2k-core/src/control.rs:7`, `EVENT_R2O_*` (`:14-37`) | C v22; Event ID `0x000d` занят другим смыслом; события 0x0e..0x1e отсутствуют в C. |
| Journal snapshot/update frames | `r2o-datapath/src/flow_journal.rs:150`, `main.rs:2585`, `:2604` | C journal — in-memory ring; ctlsrv кодирует события ad hoc. Формат `EVENT_R2O_JOURNAL_ENTRY/END` — новый. |
| Второй control-сокет для snapshot | `main.rs:882-887`, `r2k-core/control.rs r2k_snapshot_socket_path` | C d2kd открывает один `--control`; второго сокета нет. |
| `ScheduledQueue::{reserve,push_reserved,cancel,cancel_flow,cancel_direction,expire,has_pending}` | `scheduler.rs:78-298` | C `sched.c` не знает flow identity, отмены и резервирования. |
| `R2oConntrackGate::{guard_decision,fragment_decision,rewrite_fragment_group}` | `r2o_conntrack_gate.rs:115-330` | C полагается на ядро/NAT и только читает `/proc`; перезапись фрагментов — R2O-расширение. |
| `R2oVoiceTrialProofs`, события `VOICE_PROOF/RTP_PROOF/STUN_PROOF` | `r2o_voice.rs:181-480`, `r2k-core/control.rs EVENT_R2O_VOICE_*` | C voice-логика в `session.c` даёт exchange-событие, но не отдельные proof-события с RTP/STUN. |
| `R2oRoutedFlows` (таблица routed flow + skip) | `r2o_route.rs:586-679` | C `session.c` считает `routed_flows`, но не ведёт таблицу и не делает skip на её основе. |
| `R2oUdpDeferredResends` | `r2o_udp_hold.rs:658-799` | C `udp_release` не имеет отдельного retry-кольца resend. |
| `R2oUdpHoldTable::r2o_drain` | `r2o_udp_hold.rs:228` | C `udp_hold` не имеет drain; освобождение через free/flush. |
| CLI `--controller-only`, `--family`, `--rcvbuf`, `--check`, `--r2o-flow-capacity`, `--r2o-udp-reverse-visible` | `main.rs:2630-2752` | C d2kd не имеет этих флагов; часть — переименования C-флагов, часть — новое поведение. |
| `r2o-datapath` обработка `--check` и default plan path | `main.rs:2631`, `:2724` | C `--plan` опционален, default нет; R2O всегда читает `/etc/r2o/plans/current.r2op`. |
| `full_detect_semantics`, `confirm_clear` (library default) | `r2o-controller/src/classify.rs:819`, `:870` | C detect `d2k_classify_run` не делает +2 подтверждающих probe для CLEAR; это семантика core/verdict. CLI выставляет `full_detect_semantics=true`, `confirm_clear=false`, но библиотечный default другой. |
| `HttpsProbeState`, `probe_https_name/state`, `https_certificate_name_matches` | `r2o-controller/src/response.rs:73-622` | C-аналог — `core/httpsprobe.c`, не `detect/*.c`; в detect C этого нет. |
| `make_poison_hit`/`executable_poison_hit` (компиляция R2OP из hit) | `raw_probe.rs:1101-1138` | C `d2k_arm_from_poison` создаёт `d2k_arm`, план строит планировщик; R2O компилирует и валидирует R2OP на месте. |
| `classify_json.rs` serializer | `r2o-controller/src/classify_json.rs:18` | C `print_json` в `detect/main.c`; R2O использует serde_json и другой набор полей (`notes` нет). |
| `--save-plan`, `--arm`, `--probe-response` CLI | `r2o-controller/src/main.rs:914-1115` | C detect CLI их не имеет. |

## Пробелы доказательств

1. **Нет C/Rust дифференциала полного `d2k_session_packet`/`handle_udp`.** Есть дифференциалы отдельных решений (TCP silence, RST, payload stats, QUIC/STUN/voice), но не полного дерева с планами, hold, HTTP и NAT одновременно.
2. **Нет C/Rust дифференциала `d2k_plan_load`.** Более того, он невозможен без конвертера `D2KP↔R2OP`: R2O отвергает C-план. Все «plan parse» тесты R2O проверяют R2OP, не D2KP.
3. **Нет C/Rust дифференциала control-протокола.** Версии 22/48 и разные event ID исключают прямую совместимость. `r2o-control-events-differential.sh` сравнивает R2O-события с R2O-ожиданиями, а не с D2O v22.
4. **ENOBUFS/потеря пакетов NFQUEUE не проверена живым дифференциалом.** Есть unit `record_lost_packet`, EIO/EAGAIN сценарии и IPv4 EIO differential; `ENOBUFS` (LostPackets) в production-процессе не сравнивался с C.
5. **Замена вердикта >~2 КиБ.** C `d2k_nfq_verdict_payload` ограничен буфером 2112; R2O допускает до 65531. Нет теста, который бы показал расхождение/отказ.
6. **IPv6 datapath без C-oracle.** C `nfq.c` AF_INET-only. Все IPv6 NFQUEUE/route/conntrack/ICMP тесты R2O — расширение; сравнивать не с чем.
7. **Планы и таблицы при высокой кардинальности.** C 2048 целей + LRU-вытеснение; R2O 128/128/64 + отказ. Нет дифференциала «129-я цель», «вытеснение LRU», «probe 65+».
8. **Scheduler cancel/reservation.** Нет C-аналога; тесты R2O не являются доказательством переноса.
9. **HTTP80.** Нет полного C/Rust дифференциала `d2k_http80_packet`/`swap`/`executed/delivered/sweep`; `http_trace` отсутствует; HTTP80 stats отсутствуют. `test-http-chunk-framing-differential.sh` покрывает только парсер HTTP-ответа, не HTTP80-поток.
10. **`tcp_ts_up`.** C `test_wire.c` проверяет перестановку TCP timestamp; R2O-теста и реализации нет.
11. **NAT/conntrack.** `r2o-conntrack-ctget-differential.sh` и IPv4 SNAT differential есть; IPv6 CT_GET reply и IPv6 NAT — только R2O/локальные, без C NFQUEUE-oracle. `R2oConntrackGate` перезапись фрагментов не сравнивалась с C (у C её нет).
12. **Route mark.** `r2o-route-gate-differential.sh` покрывает mark/outdev; `r2o_routemark_describe` и точные тексты/логи не сравниваются.
13. **ICMP guard.** `test-icmp-guard-current-differential.sh` покрывает summary и 6 сценариев; live IPv6 NFQUEUE и полный набор полей цитаты не проверены.
14. **Detect default SO_MARK расходится.** C `D2K_BYPASS_MARK = 0x40000000`, R2O `BYPASS_MARK = 0x2d`. Без явного `--mark` C/R2O шлют зонды с разными метками; `test-classifier-so-mark-production-differential.sh` передаёт метку явно и этого не ловит.
15. **HTTP80 capacity.** C `D2K_HTTP80_FLOWS = 128`, R2O `HTTP_FLOW_CAPACITY = 1024`; нет дифференциала 129/1025 потоков.
16. **Detect `notes`/`cross_check_tls12`.** C `D2K_NOTES_MAX=8`; R2O поля `notes` нет. C `cross_check_tls12` — заглушка, R2O поля `covers_tls12` нет.
17. **Stats/CLI.** `test-datapath-stats-timer-differential.sh` сверяет подмножество строк; нет дифференциала `--log`, `--duration`, `--health-file`, `--version`/self-check, полного `print_stats`/`print_journal`.
18. **Detect `d2k_classify_run`.** Есть сильные дифференциалы (`test-classifier-full-tree-control`, `test-classifier-clear-confirm`, `test-d2o-shared-fixtures`, `test-classifier-raw-production`), но не все ветви: `cross_check_tls12` (C stub), `notes`, `gap_loss`, нейтральный ACK на всех платформах, DNS-ротация, все 85 poison, все 12 property-вопросов.
19. **Detect raw.** `r2o-raw-profile-differential.sh`, `test-classifier-raw-production-differential.sh`, `test-raw6-send-differential.sh` покрывают профили, self-test cache/recheck, badsum/seqovl-1, property/compose, IPv6 send. Не покрыты: все ошибки nft/iptables, stale RST cleanup на живом ядре, `syndata`/`oob`/`seq-out-of-window` на всех семействах, IPv6 raw RST.
20. **Detect bridge.** Нет прямого C/Rust дифференциала `bridge.c`; scheduler/discovery-тесты проверяют R2O-поведение, но не `sched_tcp`/`bridge_input` из C.
21. **Detect CLI.** `--json` сравнивается в отдельных кейсах; `notes` отсутствует; человеческий stdout и `--progress` с `err` не совпадают; exit codes не покрыты полным differential.
22. **Исторические доказательства.** Часть логов в матрице относится к другим ревизиям (`304ba893`, `a378e23`, `a63d964`) и не перезапускалась на текущем `E:\d2o`/`E:\r2o`. Это указано в матрице, но при чтении строки легко принять за текущую эквивалентность.
23. **Компиляция не является доказательством.** Наличие `cargo test` в истории и успешная сборка не доказывают ветви, перечисленные выше.

## Предлагаемое разбиение контрактов матрицы

Ниже — предлагаемое разбиение без начисления баллов. Веса относительные; их нужно нормировать внутри существующих групп матрицы (Datapath 19, Classifier/TLS 14), не увеличивая итог. «Текущий доказанный статус» — по этому аудиту.

### Datapath: 25 контрактов (вместо одной/нескольких сборных строк)

| ID | Контракт | C-источник | Вес | Текущий статус | Что должно быть доказано |
|---|---|---|---:|---|---|
| D1 | NFQUEUE: socket/bind/family/rcvbuf/BIND/PARAMS/GSO/fail-open/close | `nfq.c`, `nl.c` | 2 | partial | C/Rust байты конфигурации на одном ядре; AF_INET6 отдельно как расширение без C-oracle; ошибки bind/EINVAL/ack timeout |
| D2 | NFQUEUE recv: EAGAIN/EINTR/ENOBUFS/lost/truncation/POLLERR | `nfq.c`, `nl.c` | 2 | partial | живой ENOBUFS-дифференциал; POLLERR/HUP; kernel loss counter; truncation copy_range |
| D3 | Verdict: accept/drop/replacement, limits, errors | `nfq.c`, `nl.c` | 1 | partial | замена >~2 КиБ; short write; errno; счётчики accepted/dropped |
| D4 | Daemon: poll deadlines, recv batching, control/route/stats/sweep/expire ordering | `d2kd.c` | 2 | partial | C/Rust трасса одного прогона с одинаковыми сроками; shutdown/drain |
| D5 | Daemon CLI/stats/journal/version/health | `d2kd.c` | 1 | partial | `--log`, `--duration`, `--health-file`, `--version`/self-check, полный stats/journal |
| D6 | TCP hold: parse/FIFO/limits/flags/ack/head/ordered originals/synthetic/IPv6 | `hold.c` | 2 | partial | C/Rust дифференциал всех ветвей `d2k_hold_feed`; HTTP hold |
| D7 | TCP hold: timeout/revision/all-flush/diagnostics/ownership | `hold.c`, `d2kd.c` | 2 | partial | уже есть timeout/revision unit + EIO held TCP; нужны HTTP/ownership счётчики |
| D8 | UDP hold: slots/expiry/overflow/release callback | `udp_hold.c` | 2 | partial | C/Rust дифференциал overflow/expiry; порядок release |
| D9 | UDP deferred verdicts/release ring/follow/resend | `udp_release.c`, `udp_path.c` | 3 | partial | все четыре исхода path; ring full; follow window; late tail |
| D10 | TCP flow table: key/capacity/refusal/expiry/reuse | `track.c`, `session.c` | 2 | partial | уже есть capacity differential; добавить C/Rust expiry/reuse и reverse lookup |
| D11 | UDP/QUIC/STUN/voice session tables: direction/hello/proofs/expiry | `session.c` | 3 | partial | C/Rust дифференциал `handle_udp`; отдельные ёмкости vs C `uflows`; voice proofs |
| D12 | Capture/TLS: slots/TTL/generation/overlap/ready/TLS parse | `capture.c`, `tls.c` | 1 | partial | C test_capture трассы уже совпадают unit; нужен C/Rust process differential |
| D13 | Wire: TCP/UDP build, checksum, profiles, urgent, ts_up, IPv6 | `wire.c`, `wire_udp.c` | 1 | partial | **ts_up отсутствует**; полный C/Rust байтовый differential профилей 0/1/2 |
| D14 | Plan parse/validate: D2KP/R2OP, schema/minexec/records/refs | `plan_parse.c` | 2 | partial | **конвертер/совместимость D2KP↔R2OP**; C-план не принимается |
| D15 | Plan apply: splits/fakes/seqovl/order/guard/pace/delay/segment/oob/ipfrag/udplen/qsplit | `plan_apply.c` | 3 | partial | C/Rust дифференциал всех 85 poison-планов; ts_up |
| D16 | Plan table: name/addr/suffix/bypass/probe, LRU, capacity, binding | `plans.c` | 3 | partial | **ёмкость 2048 vs 128**, LRU vs отказ; C/Rust команды/события |
| D17 | Control framing: accept/reconnect/flush/ring/drop/frames | `ctl.c` | 2 | partial | 64 КиБ vs 128 КиБ; drop counts; invalid frame; partial writes |
| D18 | Control protocol: commands/ACK/events/journal pump | `ctlsrv.c` | 3 | partial | **v22 vs v48**, event ID collision, bodies; D2O/R2O interop |
| D19 | Raw send: open/mark/MTU/route/send/error counters | `raw.c` | 2 | partial | C/Rust MTU per route; busy/EAGAIN; partial send; IPv6 |
| D20 | Route mark: rules dump/lookup/watch/gate/OIF | `routemark.c`, `routemark_nl.c` | 2 | partial | уже есть route gate diff; describe/logs; all kernel errno |
| D21 | Conntrack/NAT: ctnetlink, proc NAT, probe, gate/retry | `ctq.c`, `nat.c`, `d2kd.c` | 2 | partial | CT_GET/NAT proc уже scoped; IPv6 live; fragment rewrite (R2O-only) |
| D22 | ICMP guard: note/check/ring/summary | `icmpguard.c` | 1 | partial | уже есть current differential; live IPv6; все поля цитаты |
| D23 | HTTP80: parse/HTTPS gate/307/RST/delivered/executed/sweep/stats | `http80.c` | 3 | partial | нет полного differential; `http_trace` и stats missing; flows 128 vs 1024 |
| D24 | Scheduler: heap/order/refusals/owned IDs | `sched.c` | 2 | partial | уже есть ordering/refusals; cancellation/reservation — R2O-only |
| D25 | Journal: ring/retention/dropped/added/entry fidelity | `journal.c` | 1 | partial | нужен C/Rust differential формата/retention; тексты не совпадают |

Сумма весов = 50. Если сохранять существующие 19 баллов Datapath, предлагаемые веса умножаются на 19/50; это не начисление, а нормировка.

### Detect: 8 контрактов (вместо одной строки на все detect-файлы)

| ID | Контракт | C-источник | Вес | Текущий статус | Что должно быть доказано |
|---|---|---|---:|---|---|
| T1 | Trigger: TLS modern/legacy, raw hex, control, decoy, host TS, allows poison | `trigger.c` | 1 | partial | полный C/Rust differential профилей/длин SNI/hex-лимитов; `host_ts_override` |
| T2 | Bridge: input, verdict map, progress, questions, seed/base/ack | `bridge.c` | 2 | partial | прямой C/Rust bridge differential; stop/cancel; owns_search |
| T3 | Tree: address/localhost, baseline, double timeout, split, control, neutral-ack, response, boundary, verdicts | `classify.c` | 4 | partial | уже есть full-tree/clear/shared; нужны notes/gap/cross-check |
| T4 | Properties: 12 questions, majority, ts/white preconditions, compose | `props.c` | 2 | partial | C/Rust 12-вопросный differential; compose без control |
| T5 | Poisons: 85 list, family, has_fake, strategy, arm/plan | `poison.c` | 2 | partial | точный список/поля/стратегии; `strategy_for`; autottl |
| T6 | Raw: profiles, self-test cache/recheck, RST suppression, build/send/recv, IPv6 | `raw.c` | 4 | partial | все профили/ошибки nft/iptables; stale cleanup; syndata/oob/seq-out; IPv6 |
| T7 | Response: scan12, handshake12, neutral SNI, decide, probe | `response.c` | 3 | partial | shared 13 vectors + full-tree follow-up уже есть; DNS rotation/errno/live IPv6 |
| T8 | CLI/output: flags, exit codes, stdout, progress, JSON | `main.c` | 2 | partial | human output, notes, progress err, exit codes, `--json` full, default mark 0x40000000 vs 0x2d |

Сумма весов = 20. Если сохранять существующие 14 баллов Classifier/TLS, веса нормируются на 14/20 (detect — часть группы; не добавлять новые баллы).

### Где текущая матрица объединяет разные контракты

- «Пакетный путь NFQUEUE/verdict/loop» объединяет D1–D5 (nfq, nl, d2kd, control/sweep). Один успешный EIO-тест не доказывает парсер/лимиты/CLI.
- «session/track/flow capacity» объединяет D10–D11 (два C-файла, 107+18 функций) и разные таблицы.
- «capture/tls/wire/addr» объединяет D12–D13 и addr; у них разные гарантии (TTL/overlap vs checksum vs parse).
- «hold/udp_hold/udp_release» объединяет D6–D9; у TCP и UDP разное владение ID и разные таймауты.
- «udp_path/session UDP/QUIC/voice» объединяет D9–D11; C `uflows` одна таблица, R2O — три.
- «plan_parse/plan_apply/plans» объединяет D14–D16; разный формат (D2KP/R2OP), разная ёмкость, разный LRU.
- «raw/routemark/routemark_nl» объединяет D19–D20; send path и policy gate независимы.
- «nat/ctq/ct_probe» объединяет D21; C только читает, R2O переписывает фрагменты.
- «http80/http_trace/ctlsrv events» объединяет D23 и D18; HTTP-поток, текстовая трасса и протокол событий — три контракта.
- «detect: bridge/classify/poison/props/raw/response/trigger/main» — одна строка на 8 файлов, 172+ функции; предлагается T1–T8.
- Дублирование: scheduler встречается в «Scheduler cooldown», «Discord scheduled UDP», «Discord voice trial clock»; response — в «TLS 1.2 response probe» и «Connect/read timeout classifier»; `d2k_classify_run` — в «Classifier baseline», «transport errors», «timeout»; `d2k_probe_response` — в response-строке и в строке «TCP measurement and core TLS/HTTP verifier» (там на самом деле `core/verify.c`, не detect/response.c). Эти строки нужно не дублировать, а разложить по ветвям T3/T7.

## Итоговая оценка

- Datapath: **ни один контракт не доказан как equivalent в полном объёме.** Есть scoped-эквивалентности: `d2k_proc_nat` (shared vectors), `d2k_ct_get_req` (byte differential), `d2k_resp_scan12`/`d2k_resp_decide` (detect, 13 vectors), отдельные wire/ipfrag/raw-профили.
- Detect: scoped-эквивалентности есть для response scan/decide и trigger_accepts; дерево, свойства, poison, raw, bridge и CLI остаются partial.
- Главные блокеры для 100%: несовместимый план (`D2KP`/`R2OP`), несовместимый control-протокол (v22/v48), отсутствие `tcp_ts_up`, ёмкости/LRU планов, отсутствие `http_trace`/HTTP80 stats, IPv6 без C-oracle, CLI/health/self-check, detect `notes`/`cross_check_tls12`/human output.

**Никакого фиктивного прогресса:** перечисленные выше «partial» нельзя закрывать по наличию функции или успешной компиляции; нужен конкретный C/Rust differential или воспроизводимый тест на каждую ветвь.


