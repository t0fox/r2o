# Пофункциональный аудит паритета datapath-core: D2O (C) → R2O (Rust)

Дата аудита: 2026-11-11. Метод: чтение тел C-функций по срезу и сопоставление с
реализацией R2O по коду; тесты в этой сессии **не запускались** (в окружении нет
`cargo`/`git`), поэтому статусы отражают наличие реализации и наличие теста в
дереве, а не факт его успешного прогона.

## Baseline

- D2O (oracle): `E:\d2o-a378w`, SHA `a378e230947ebfd011439e1cac0f1e994d883aae`.
- R2O: `E:\r2o`, ветка `main`, HEAD `d7b5a87971f689760ea3d061e246b54a7ae02f76`
  (на момент аудита; рабочее дерево не изменялось).
- Срез: `E:\r2o-tooling\audit\slice-datapath-core.csv` — **400 функций**
  (`file,name,line,end_line,lines,static,signature,sha256,rust_candidates`).
- Проверено строк таблицы: **400** (по одной на каждую функцию среза, без
  повторов; сумма по файлам совпадает с распределением среза).
- Исходники D2O не менялись; код R2O не менялся.

## Статусы

- **E** — эквивалент подтверждён тестом/дифференциалом, покрывающим контракт
  функции, либо прямой структурной эквивалентностью без ветвей (RAII,
  `derive`, поле-аксессор, каноническая арифметика).
- **P** — Rust-реализация есть, но не все ветви/краевые случаи доказаны
  (нет прямого теста, другая структура данных, иной контракт ошибок).
- **N** — реализации нет (или есть только неэквивалентный суррогат).
- **?** — не установлено.

Ограничения: дифференциальные shell-скрипты (`scripts/test-datapath-*`,
`scripts/r2o-*-differential.sh`) в этой сессии не выполнялись; их наличие
указано как возможное доказательство, а не как подтверждённый результат.
C-хелперы без собственного состояния наследуют статус владельца с пометкой
`(static)`.

## Сводка

- Всего функций: **400**.
- **E: 120 (30,00 %)**; **P: 270 (67,50 %)**; **N: 10 (2,50 %)**; **?: 0**.
- Полностью отсутствуют: `count_reason` (гистограмма причин пропуска в сводке),
  `d2k_session_nat_stats` (счётчики NAT), `offline_self_check`
  (`--offline-self-check`), `d2k_http_trace` (текстовый HTTP-трейс), а также
  агрегатные счётчики `d2k_session_applied`, `d2k_session_done`,
  `d2k_session_damaged_count`, `d2k_session_sent_lost`, `d2k_session_suspects`,
  `d2k_session_exchanges` — события этих видов есть, но сводных чисел R2O не
  ведёт.
- Неподтверждённые ветви (P) сосредоточены в `session.c` (97), `d2kd.c` (41),
  `http80.c` (22), `udp_release.c` (20): в основном это склейка/loop-код,
  у которого проверены ключевые ветви, но не весь набор краевых условий C.

| Файл | E | P | N |
|---|---:|---:|---:|
| d2kd.c | 1 | 41 | 2 |
| session.c | 3 | 97 | 7 |
| track.c | 3 | 15 | 0 |
| capture.c | 6 | 0 | 0 |
| hold.c | 5 | 7 | 0 |
| udp_hold.c | 3 | 7 | 0 |
| udp_path.c | 0 | 7 | 0 |
| udp_release.c | 14 | 20 | 0 |
| nfq.c | 6 | 6 | 0 |
| nl.c | 19 | 0 | 0 |
| icmpguard.c | 4 | 3 | 0 |
| http80.c | 8 | 22 | 0 |
| http_trace.c | 0 | 0 | 1 |
| journal.c | 6 | 8 | 0 |
| nat.c | 1 | 4 | 0 |
| ctq.c | 11 | 9 | 0 |
| sched.c | 7 | 9 | 0 |
| wire.c | 8 | 1 | 0 |
| wire_udp.c | 3 | 2 | 0 |
| addr.c | 2 | 1 | 0 |
| tls.c | 7 | 0 | 0 |
| include/*.h | 3 | 11 | 0 |

Ключевые расхождения, не позволяющие поднять статус (подробно в строках):
`wire_udp` отвергает `POISON_IPID_ZERO`, разрешённый C для IPv4, и берёт TOS из
пакета; `d2k_session_shape_tcp_options_family` не передаёт опции целиком;
`nfq_recv` в C глотает `EINTR`, в R2O он возвращается вызывающему; CLI R2O не
поддерживает `--log`, `--duration`, `--health-file`, `--sched-slots`; в
`session.c` отсутствуют счётчики NAT (`d2k_session_nat_stats`), а гистограмма
причин пропуска (`count_reason`) не печатается.

### Проверка ключевых расхождений по исходникам

- `wire_udp`: подтверждено. C `datapath/wire_udp.c:75` запрещает
  `POISON_IPID_ZERO` только для IPv6, а для IPv4 пишет нулевой ID
  (`wire_udp.c:136`); R2O `r2k-core/src/wire.rs:213 build_udp_packet` отвергает
  **любой** `emission.poison != 0`. Для UDP-планов с IPID_ZERO это реальный
  отказ, статус P.
- `nfq_recv`: подтверждено на уровне API, но не поведения цикла. C
  `nfq.c:263` возвращает 0 на `EINTR`; R2O `nfqueue.rs:353-361` возвращает
  `ReceiveError::Wait`, который `main.rs` обрабатывает как «пакета нет» без
  flush. Наблюдаемое поведение цикла совпадает; P относится к внутреннему
  контракту возврата, а не к потере пакета.
- `--log/--duration/--health-file/--sched-slots`: это CLI-контракт D2O. R2O
  использует `--log-file`/сервисные аргументы; для точного паритета CLI нужен
  маппинг/алиасы, статус P.
- `d2k_session_nat_stats`, `count_reason`, агрегатные счётчики
  `applied/done/damaged/sent_lost/suspects/exchanges`: N, но это
  диагностические/сводные величины, а не packet-path обход. События и
  per-flow счётчики в R2O есть; отсутствуют именно сводные числа.
- `d2k_http_trace`: N как отдельный формат лога; R2O пишет HTTP-события через
  журнал/`http_replace.rs`, но не повторяет строку `d2kd: HTTP execution ...`.
  Влияние — только диагностика.

## d2kd.c (44 функции)

Процесс-служба: CLI, NFQUEUE-цикл, raw/sched, hold, HTTP80, ICMP-guard, метрики.
R2O-владелец: `crates/r2o-datapath/src/main.rs` (`run`, `parse_options`,
`r2o_log_*`), `raw.rs`, `scheduler.rs`, `hold.rs`, `r2o_route.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `on_signal` (static) | 62 | 1 | SIGINT/SIGTERM → `stop_flag` | `main.rs:3762 install_signal_handlers`, `main.rs:55 STOP` | P | обработчик ставит только atomic-флаг; отдельного теста на сигнал нет |
| `self_cost` (static) | 68–110 | 43 | CPU/RSS из `/proc/self/stat` и `statm` | `main.rs:569 r2o_process_cost_from_proc`, `:605 r2o_process_cost` | P | `test-datapath-process-stats-differential.sh`; unit-тест разбора отсутствует |
| `now_ns` (static) | 112–116 | 5 | `CLOCK_MONOTONIC` в нс | `std::time::Instant` (монотонные часы) | P | контракт «целые нс» заменён на `Duration`; отдельного теста нет |
| `tls_route_segment_cap` (static) | 123–151 | 29 | MTU маршрута минус IP+32 только для TLS ClientHello | `raw.rs:130 tls_route_segment_cap`, `:119 packet_route_maxlen` | P | есть unit-тесты raw.rs на route cap; C-семантика «только для 0x16/0x03» воспроизведена |
| `count_reason` (static) | 165–186 | 22 | гистограмма причин пропуска (до 32) | нет прямого аналога; причины уходят в `RefusedEvent`/журнал | N | в R2O нет таблицы причин в сводке; счётчики причин не печатаются |
| `icmp_step` (static) | 220–248 | 29 | ICMP time-exceeded: DROP только на свою фальшивку, иначе ACCEPT | `r2o_icmp_guard.rs:127 r2o_handle_at_hook`, вызов в `main.rs` | P | `scripts/test-icmp-guard-current-differential.sh`; unit-тестов в модуле нет |
| `log_send_fail` (static) | 253–261 | 9 | лог отказа raw с лимитом 16 строк для busy | `main.rs:186`/`:192` eprintln без лимита строк | P | лимит 16 строк не воспроизведён; счётчик busy есть в `RawSendStats` |
| `routes_routed` (static) | 278–280 | 3 | предикат «метка выбирает политику» | `r2o_route.rs:175 r2o_mark_is_routed` | P | unit-тесты `r2o_route.rs:982+`; семантика маски совпадает |
| `describe_oifs` (static) | 282–294 | 13 | имена выходных интерфейсов для лога | `r2o_route.rs:152 r2o_egress_ifindices`, строки `r2o_refresh` | P | формат лога иной; список oif читается |
| `routes_refresh` (static) | 302–370 | 69 | разбор ip rule/маршрутов, лог смен, quiet 600 с | `r2o_route.rs:372 r2o_refresh` (по netlink-watch, без периодического цикла) | P | `r2o-route-gate-differential.sh`; quiet-окно 600 с и лог смен состояния не воспроизведены |
| `cap_refresh` (static) | 372–415 | 44 | adopt egress MTU → grow sched → greet control | `raw.rs:106 r2o_adopt_egress`, `scheduler.rs:260 grow_slot_size`, `main.rs` greet | P | ветви «adopted=0/ошибка grow» покрыты кодом, прямого differential нет |
| `send_original_verdict` (static) | 417–427 | 11 | вердикт NFQUEUE + счётчики accepted/dropped | `nfqueue.rs:310 send_verdict`; `main.rs:4335 release_with` | P | byte-level тесты netlink; счётчики QueueStats |
| `send_delayed_verdict` (static) | 429–431 | 3 | обёртка того же вердикта | `main.rs:319 r2o_release_delayed_udp_batch_with` | P | — |
| `delayed_verdict_done` (static) | 433–446 | 14 | complete → `session_sent`, иначе `exec_failed` | `main.rs:411 r2o_finish_tcp_execution`, `:319` | P | ветви token=0/complete/sent!=0 реализованы, прямого теста нет |
| `hold_owns` (static) | 484–489 | 6 | TLS-hold владеет ID (не порт 80) | `hold.rs:298 feed` + `main.rs:2148 batch_owned_originals` | P | D6 `test-datapath-hold-differential.sh` |
| `resend_original` (static) | 493–508 | 16 | вернуть снятый оригинал raw-посылкой | `main.rs:3794 r2o_resend_owned_originals` | P | считает успех/отказ; тест `hold.rs:2167` покрывает владение, не сокет |
| `resend_originals` (static) | 510–516 | 7 | цикл по `orig[]` | `main.rs:3794` | P | — |
| `release_original` (static) | 518–542 | 25 | таймаут: закрыть UDP-hold, note_unassembled, observe, resend/ACCEPT | `hold.rs:888 flush`, `main.rs:433 r2o_release_damaged_tcp_hold` | P | порядок side effects воспроизведён в main; D6 |
| `ct_query` (static) | 561–571 | 11 | ctnetlink GET по кортежу + лог «нет acct» | `conntrack.rs:297 query`, `:309 probe` | P | codec-тесты conntrack.rs; реальный GET не тестируется |
| `ct_probe` (static) | 578–595 | 18 | одноразовая проба ctnetlink, вкл/выкл детекторы | `conntrack.rs:309 probe` (в `open`) | P | `r2o-conntrack-ctget-differential.sh`; лог-строки иные |
| `out_verdict` (static) | 597–599 | 3 | обёртка вердикта | `main.rs:4335 release_with` | P | — |
| `out_fail` (static) | 603–607 | 5 | учесть отказ переиздания, сохранить errno | `main.rs:272` eprintln + `follow.r2o_note_busy` | P | errno-классификация есть (`r2o_udp_send_busy`) |
| `out_marked` (static) | 615–635 | 21 | лог «метка клиента → хвосты ядром» | `main.rs:88 r2o_udp_packet_is_neutral`, `r2o_route` gate | P | счётчик `udp_marked_kept` не выводится отдельно |
| `out_defer` (static) | 640–647 | 8 | вердикт позже, за отложенной головой | `r2o_udp_hold.rs:291 R2oUdpDeferredVerdicts::r2o_enqueue` | P | `hold` D6; unit-теста именно на очередь вердиктов нет |
| `out_resend_failed` (static) | 651–671 | 21 | одна строка на поток при отказе хвоста | `main.rs:287` лог позднего хвоста | P | лимит `D2K_UDP_REFUSED_LOG` и адресная строка не воспроизведены |
| `out_send_now` (static) | 673–684 | 12 | raw send немедленно | `raw.rs:147 send_packet` | P | raw.rs unit-тесты исходящего пакета |
| `out_send_at` (static) | 686–696 | 11 | отложить без владения ID | `scheduler.rs:209 push_raw` | P | `test-datapath-scheduler-differential.sh` |
| `out_send_at_owned` (static) | 699–709 | 11 | отложить с владением NFQUEUE ID | `scheduler.rs:214 push_owned`, `:275 pop_due_ex` | P | unit `scheduler.rs:564` + D21 |
| `http80_log` (static) | 717–728 | 12 | строка «вставка провайдера 30x» | `main.rs:3136 send_http_portal_event` (событие, не текст) | P | текст/формат C-лога не воспроизведён |
| `http80_io_payload` (static) | 733–743 | 11 | вердикт ACCEPT с заменой | `nfqueue.rs:317 send_replacement` | P | netlink-тесты замены; D17 |
| `http80_io_accept` (static) | 745–755 | 11 | вердикт ACCEPT | `nfqueue.rs:310 send_verdict` | E | `netlink.rs:304 verdict_bytes...` + `:321 replacement...` |
| `http80_io_rst` (static) | 757–768 | 12 | raw RST серверу после 307 | `raw.rs:147 send_packet` | P | D17 проверяет сборку RST, не отправку |
| `http80_cut` (static) | 776–784 | 9 | событие обрыва ответа контроллеру | `hold.rs:255 sweep_http_responses`, `main.rs:3148` | P | `hold.rs:2082 incomplete_fixed_length...` |
| `http80_step` (static) | 786–829 | 44 | диспетчер HTTP80: DROP/REPLACE/swap/лог | `main.rs:2006 build_http_redirect_packets`, `:2093 send_replacement`, `hold.rs` | P | D17 paired differential; ветви «raw нет» и «swap rejected» покрыты кодом |
| `usage` (static) | 834–861 | 28 | текст помощи CLI | `main.rs:2952 print_help` | P | набор опций отличается (см. `main`) |
| `arg_u32` (static) | 863–871 | 9 | строгий разбор u32 | `main.rs:2911 parse_value` | P | общий `FromStr`; граничные тесты не выделены |
| `port_of` (static) | 873–876 | 4 | big-endian u16 | `packet.rs`/`read_u16` (приватный) | P | тривиально; отдельного теста нет |
| `print_stats` (static) | 878–1030 | 153 | периодическая сводка (потоки/счётчики/причины) | `main.rs:629–773 r2o_log_*` | P | состав строк иной; блока причин нет; `test-datapath-stats-timer-differential.sh` |
| `proto_name` (static) | 1039–1045 | 7 | имя протокола 6/17 | inline в `main.rs` | P | — |
| `jrn_kind` (static) | 1050–1066 | 17 | код журнала → текст | `flow_journal.rs:85 c_name`, `:100 russian_name` | P | `flow_journal.rs:1027 journal_note_texts_match_d2o` |
| `print_journal` (static) | 1070–1104 | 35 | печать журнала по записям | `main.rs:3006 format_journal_details` | P | формат отличается; D22 сверяет записи, не печать |
| `refuse_of_errno` (static) | 1114–1116 | 3 | errno → код REFUSE | `flow_journal.rs:16-23` константы + `main.rs` | P | маппинг SEND/TOO_LONG разнесён по вызывающим |
| `offline_self_check` (static) | 1118–1123 | 6 | `--offline-self-check` SHA-проверка | нет | N | опция отсутствует в `parse_options` |
| `main` | 1125–2415 | 1291 | CLI, сокеты, NFQUEUE-цикл, sweep, hold/release, stats | `main.rs:884 run` (и `parse_options` `:2754`) | P | цикл и большинство ветвей есть; нет `--log`/`--duration`/`--health-file`/`--sched-slots`, добавлены `--family`/`--check`/`--controller-only`/`--control-wire`/`--rcvbuf` |

## session.c (107 функций)

Склейка датапата: таблицы TCP/UDP, разбор TLS/QUIC/STUN/voice, выбор плана,
сборка посылок, hold, детекторы молчания, учёт исполнения. R2O-владельцы:
`engine.rs` (TCP-сессия и решение), `main.rs` (UDP-путь и цикл),
`r2o_udp_sessions.rs`, `r2o_quic.rs`, `r2o_voice.rs`, `hold.rs`, `r2o_route.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `initial_dcid` (static) | 202–211 | 10 | DCID открытого Initial-заголовка | `r2o_quic.rs:217 r2k_quic_initial_flight_id` | P | разбор QUIC покрыт `r2k-core` тестами quic; отдельного DCID-теста нет |
| `init_ring_add` (static) | 215–236 | 22 | кольцо Initial-датаграмм полёта, дедуп по байтам | `r2o_quic.rs:229-243` (`MAX_INITIAL_RING=32`) | P | unit-тесты `r2o_quic.rs` (28 функций) |
| `init_ring_drop` (static) | 239–247 | 9 | забыть датаграммы потока | `r2o_quic.rs:263 initial_ring.retain` | P | — |
| `init_ring_pack` (static) | 253–283 | 31 | собрать полёт по DCID в порядке провода | `r2o_quic.rs:245-260`, `r2k-core/src/quic_snapshot.rs` pack | P | `r2o-quic-hello-differential.sh`; порядок/дедуп совпадают |
| `slot_of` (static) | 288 | 1 | слот снимка: UDP=1, иначе TCP=0 | `r2o_udp_sessions.rs:427 mark_hello_seen` (снимок в сессии потока) | P | глобальных слотов нет — иная структура |
| `shape_slot` (static) | 289–291 | 3 | индекс слота транспорт×семейство | `r2o_quic.rs`/`r2o_udp_sessions.rs` (ключ включает family) | P | — |
| `next_fragment_id` (static) | 293–304 | 12 | случайный nonzero IP-ID фрагментов | `wire.rs:334-337 getrandom` | P | `ipfrag.rs` тесты; random-источник иной |
| `d2k_session_new` | 306–344 | 39 | создать таблицы flows/uflows/plans/journal | `main.rs:884 run` (TcpSessions/R2oUdpSessions/HoldTable/NamePlans) | P | инициализация разнесена по `run`; тестов на OOM-ветви нет |
| `d2k_session_free` | 346–356 | 11 | освободить всё | `Drop` (Rust RAII) | E | освобождение гарантировано типами |
| `d2k_session_set_plan` | 358–365 | 8 | заменить запасной план, revision++ | `control.rs` NamePlans revision; `main.rs` plan swap | P | revision считается иначе (план+таблица) |
| `name_same` (static) | 369–382 | 14 | сравнение имени без регистра | `httpup.rs:468 same_host` | P | ASCII-понижение; тест `httpup` косвенный |
| `rd16` (static) | 384–386 | 3 | big-endian u16 | `packet.rs:231 read_u16` | P | — |
| `refuse_coded` (static) | 402–413 | 12 | отказ плана в журнал; зонд молчит только при code=0 | `flow_journal.rs:684 record_plan_refused`, `main.rs:3737 send_refused_event` | P | D22 сверяет записи; условие «зонд+code 0» реализовано |
| `refuse` (static) | 415–418 | 4 | `refuse_coded(...,NONE,NULL)` | там же | P | — |
| `tcp_options_timestamp_profile` (static) | 422–433 | 12 | профиль опций: UNKNOWN/NO_TS/TS | `packet.rs:39 tcp_options_timestamp_profile` | E | unit-тесты packet/tcp на опции |
| `tcp_options_have_timestamp` (static) | 435–437 | 3 | есть ли TS-опция | `packet.rs:39` + сравнение | P | — |
| `plan_handed_off` (static) | 446–473 | 28 | applied, execution_id, счёт посылок, binding | `engine.rs:588 r2o_begin_execution`, `main.rs` execution bookkeeping | P | `sends_left` заменён на tickets/execution; семантика та же |
| `table_of` (static) | 477–479 | 3 | выбрать таблицу по proto | `TcpSessions`/`R2oUdpSessions` (разные типы) | P | — |
| `suspect_num` (static) | 486–503 | 18 | подозрение один раз на поток + planned/shape | `engine.rs` tcp_*_events, `r2o_quic.rs:478 sweep`, `flow_journal` | P | дедуп на поток есть; единой функции нет |
| `suspect` (static) | 505–508 | 4 | `suspect_num(...,0)` | там же | P | — |
| `on_flow_expire` (static) | 521–530 | 10 | при истечении: forget capture, silence_observe | `engine.rs:693 expire_with_silent` | P | callback заменён замыканием retain |
| `rd32` (static) | 532–535 | 4 | big-endian u32 | `packet.rs:236 read_u32` | P | — |
| `is_discord_ip_discovery` (static) | 544–550 | 7 | строгая сигнатура 74 байта, нули 8..71 | `stun.rs:82 is_discord_ip_discovery_request` | P | end-to-end в `r2o_voice` тестах; unit в stun.rs нет |
| `is_discord_ip_discovery_response` (static) | 552–564 | 13 | ответ 0x0002, тот же SSRC, адрес/порт | `stun.rs:89 is_discord_ip_discovery_response` | P | `r2o_voice.rs` proof-тесты |
| `is_stun_binding` (static) | 569–578 | 10 | RFC 5389: cookie, длина, тип | `stun.rs:116 is_binding` | P | тестов в stun.rs нет; voice-тесты косвенные |
| `is_stun_request` (static) | 580–582 | 3 | Binding Request 0x0001 | `stun.rs:71 is_binding_request` | P | — |
| `is_stun_response_for` (static) | 584–588 | 5 | Binding Success + txid | `stun.rs:76 is_binding_response_for` | P | — |
| `d2k_session_nat_stats` | 650–656 | 7 | глобальные счётчики NAT ok/miss/none/retry | нет аналога (proc_nat не считает) | N | счётчики NAT в R2O не собираются |
| `plan_fits_transport` (static) | 672–676 | 5 | план объявлен для этого proto (0=любой) | `Plan.transport` проверка в `engine.rs`/`main.rs` | P | — |
| `flow_tracked` (static) | 678–777 | 100 | подтверждение conntrack: 1-й пакет/SYN-ACK/3 попытки/procfs | `proc_nat.rs:20 lookup`, `engine.rs` conntrack gate | P | `r2o-nat-proc-differential.sh`; три попытки и «нет таблицы» воспроизведены |
| `handle_udp` (static) | 779–1569 | 791 | весь UDP-путь: направление, voice/QUIC, hold, NAT, план, сборка, ipfrag | `main.rs:1600-2600` (UDP), `r2o_udp_sessions.rs`, `r2o_quic.rs`, `r2o_voice.rs` | P | `r2o-udp-exchange-differential.sh`, `test-controller-udpplan-differential.sh`, voice/quic differentials; ветви ipfrag/NAT-fragment проверены частично |
| `note_tcp_hello` (static) | 1573–1580 | 8 | запомнить ACK приветствия, счётчик hello-потоков | `engine.rs` `hello_ack`/`hello_ack_valid` | P | — |
| `routed_flow` (static) | 1593–1626 | 34 | клиент с меткой политики → без плана; новый SYN снимает флаг | `r2o_route.rs:580 R2oRoutedFlows::r2o_skip_packet`, `:666 r2o_is_new_syn` | P | `r2o-route-gate-differential.sh` |
| `session_packet` (static) | 1628–2601 | 974 | TCP-путь: заголовки, направление, capture, TLS/HTTP, план, сборка | `engine.rs:1441 decide_with_session_mode` + `:1849 decide_tcp` | P | `test-datapath-default-mode-differential.sh`, tcp differentials; полный набор ветвей C не доказан |
| `d2k_session_packet` | 2603–2606 | 4 | публичный вход (observe/probe=0) | `engine.rs:1403 decide_with_session` | P | — |
| `d2k_session_packet_mtu` | 2608–2613 | 6 | вход с `tcp_segment_cap` | `engine.rs:1421 decide_with_session_mtu` | P | `test-tcp-shape-context-differential.sh` |
| `d2k_session_packet_probe` | 2615–2619 | 5 | вход зонда контроллера | `engine.rs:1412 decide_with_session_probe` | P | `test-datapath-controller-probe-capture-differential.sh` |
| `d2k_session_packet_probe_mtu` | 2621–2626 | 6 | зонд + cap | `engine.rs:1430 decide_with_session_probe_mtu` | P | — |
| `d2k_session_observe_tcp` | 2628–2631 | 4 | только наблюдение, без вердикта | `main.rs` observe-mode `decide_with_session` | P | — |
| `d2k_session_plan_revision` | 2633–2635 | 3 | план + таблица ревизий | `control.rs` NamePlans revision | P | — |
| `d2k_session_stream_anchor` | 2637–2645 | 9 | якорь HTTP-потока или SYN+1 | `hold.rs:969 remember_syn` (capture_anchor) | P | D6 |
| `d2k_session_set_hook` | 2647–2649 | 3 | hook текущего пакета | `main.rs` `queue_hook` (параметр на пакет) | P | — |
| `d2k_session_set_route_mark` | 2651–2653 | 3 | метка текущего пакета | `main.rs` `options.probe_mark`/route gate | P | — |
| `d2k_session_route_mark` | 2655–2657 | 3 | чтение метки | `main.rs` route gate | P | — |
| `d2k_session_routed_flows` | 2659–2661 | 3 | счётчик routed-потоков | `r2o_route.rs:580 R2oRoutedFlows` + лог | P | — |
| `d2k_session_set_udp_reverse_hook` | 2663–2665 | 3 | «обратное UDP видно» | `main.rs` `reverse_queue_visible` | P | — |
| `d2k_session_set_ct_query` | 2667–2669 | 3 | включить ctnetlink-запросы | `conntrack.rs:264 R2oConntrackClient` (Option) | P | — |
| `d2k_session_udp_hold_begin` | 2671–2711 | 41 | начало UDP-hold: только клиентский Initial, окно, не routed | `r2o_udp_sessions.rs:410 r2o_begin_hold`, `main.rs` hold gate | P | `r2o-udp-session-table-check.sh` |
| `d2k_session_udp_opening` | 2713–2736 | 24 | «первый клиентский пакет потока» | `r2o_udp_sessions.rs:361 r2o_udp_opening`, `:347 is_first_client_packet` | P | unit-тесты r2o_udp_sessions |
| `d2k_session_udp_hold_end` | 2738–2742 | 5 | закрыть транзакцию hold | `r2o_udp_sessions.rs` hold state + `main.rs` release | P | — |
| `d2k_session_udp_hold_replay` | 2744–2751 | 8 | hold → replay первой датаграммы | `r2o_udp_sessions.rs:337 r2o_mark_hold_replay_first` | P | unit `:640` |
| `d2k_session_note_unassembled` | 2753–2784 | 32 | «составное приветствие не собралось» один раз + HTTP-ветка | `hold.rs:235 r2o_take_incomplete_diagnostics`, `main.rs:544` | P | `hold.rs:2249 timeout_reports_unassembled_tls_record...` |
| `d2k_session_hold_candidate` | 2794–2924 | 131 | право начать TCP-hold: SYN, окно 16 КБ, форма, HTTP-кандидат | `hold.rs:298 feed` + `HoldOptions.allow_tls`, `:356 feed_observing_mode` | P | D6; HTTP80-кандидат разнесён между hold/control |
| `d2k_session_want_shape` | 2926–2929 | 4 | запрос снимка формы (family=4) | API «взведи ожидание» нет; снимок уходит событием HELLO (`main.rs:3093 send_hello_event`, `control.rs HelloEvent`) | P | механизм иной: R2O отдаёт снимок сразу, без отложенного запроса |
| `d2k_session_want_shape_family` | 2931–2960 | 30 | отдать last_hello или взвести ожидание по transport/family | там же; per-flow capture вместо сессионного слота | P | повторный запрос после утери потока снимок не вернёт |
| `d2k_session_shape` | 2962–2964 | 3 | снимок формы TCP | `capture.rs:170 tcp_hello_from_packet`, `r2o_quic.rs:180 capture_hello` | P | снимок берётся из capture/события, не из сессионного буфера |
| `d2k_session_shape_family` | 2966–2980 | 15 | снимок формы по family | `capture.rs:170`, `r2o_quic.rs:180` (family в ключе потока) | P | — |
| `d2k_session_shape_tcp_options_family` | 2982–2990 | 9 | опции TCP к снимку | `control.rs HelloEvent.tcp_has_timestamp` (только флаг) | P | сырые байты опций не передаются |
| `d2k_session_plans` | 2992–2994 | 3 | таблица планов | `control.rs` NamePlans | P | — |
| `d2k_session_plan_count` | 2996–2998 | 3 | число планов | `control.rs` NamePlans len | P | — |
| `d2k_session_plan_capacity` | 3000–3002 | 3 | ёмкость планов | `control.rs` MAX_* лимиты | P | — |
| `silence_deadline` (static) | 3018–3028 | 11 | срок молчания: 8×RTT, [1,5] с, без RTT 2 с | `engine.rs` `tcp_silence_event`/`fin_retry_window` | P | `r2o-tcp-silence` differential; формула воспроизведена |
| `tcp_silence_observe` (static) | 3034–3049 | 16 | SILENT: TTL-видимость, нет payload, повтор | `engine.rs:1330-1369` silence events | P | `test-tcp-silence-current-differential.sh` |
| `fin_retry_window` (static) | 3063–3067 | 5 | окно повтора FIN = 3×max(3RTT,1с) | `engine.rs` `fin_retry_window` | P | — |
| `fin_window_over` (static) | 3069–3073 | 5 | истекло окно pending FIN | `engine.rs:700` fin expiry | P | — |
| `sweep_one` (static) | 3084–3087 | 4 | обход TCP-потоков | `engine.rs:693 expire_with_silent` | P | — |
| `sweep_udp_one` (static) | 3112–3142 | 31 | SILENT по UDP: rev_seen/повтор PTO/срок | `r2o_quic.rs:478 sweep`, `main.rs` quic sweep | P | `r2o-quic-stun-watch-differential.sh` |
| `quic_watch` (static) | 3164–3169 | 6 | кандидат QUIC-stall | `r2o_quic.rs:503 r2o_quic_stall_candidates` | P | — |
| `flow_tuple` (static) | 3174–3187 | 14 | прямой кортеж для ctnetlink | `conntrack.rs:420 tuple_from_packet`, `:413 from_socket_addrs` | P | — |
| `ct_flow` (static) | 3197–3221 | 25 | QUIC stall по счётчикам conntrack | `r2o_quic.rs:527 update_r2o_quic_stall` | P | `r2o-quic-stun-watch-differential.sh`, `test-conntrack-retry-current-differential.sh` |
| `tcp_watch` (static) | 3257–3261 | 5 | кандидат TCP-stall | `engine.rs` stall watch (`stall_watch_off`) | P | — |
| `tcp_in_band` (static) | 3263–3269 | 7 | оценка в полосе бюджета ±3 | `engine.rs` `TCP_STALL_PACKET_SLACK` | P | — |
| `tcp_band_top` (static) | 3271–3277 | 7 | верх полосы бюджетов | `engine.rs` budgets | P | — |
| `ct_tcp_flow` (static) | 3279–3328 | 50 | TCP stall: ESTABLISHED, 3 пакета, RTO, полоса | `engine.rs` conntrack stall detection | P | `test-tcp-stall*`/`r2o-tcp-silence`; полный differential не подтверждён |
| `d2k_session_set_stall_budgets` | 3330–3343 | 14 | до 8 ненулевых бюджетов, пусто → полевой | `engine.rs:451 set_tcp_stall_budgets` | E | `engine.rs` unit на отказ нулевого/превышения |
| `d2k_session_stall_budgets` | 3345–3351 | 7 | чтение бюджетов | `engine.rs` поле `tcp_stall_budgets` | P | — |
| `d2k_session_sweep` | 3353–3370 | 18 | обход TCP+UDP и ct-детекторов | `main.rs` periodic sweep, `engine.rs`/`r2o_quic.rs` | P | — |
| `d2k_session_expire` | 3372–3395 | 24 | remove_if(FIN) + expire TCP с callback + UDP | `engine.rs:698 expire_with_silent`, `r2o_udp_sessions.rs:456 expire` | P | — |
| `d2k_session_flows` | 3397–3399 | 3 | сумма потоков TCP+UDP | `main.rs:668 r2o_log_flow_table_stats` | P | — |
| `d2k_session_send_pending` | 3401–3405 | 5 | есть ли незавершённые посылки | `scheduler.rs:342 has_pending` | P | — |
| `d2k_session_sent` | 3407–3428 | 22 | учёт отправки, PLAN_DONE, sent_lost | `main.rs:411 r2o_finish_tcp_execution` | P | — |
| `d2k_session_exec_failed` | 3449–3501 | 53 | общий исход отказа, damaged, UDP replan | `main.rs:468 r2o_fail_pending_applied`, `:446` | P | `test-raw-emission-cancel-differential.sh` |
| `d2k_session_guards` | 3503–3507 | 5 | guards потока | `engine.rs` `session.guards` | P | — |
| `d2k_session_client_shape` | 3509–3513 | 5 | форма клиента потока | `engine.rs` `client_shape` | P | — |
| `d2k_session_damaged` | 3515–3523 | 9 | пометить поток damaged | `engine.rs:672 r2o_mark_damaged_for_execution` | P | — |
| `d2k_session_unsent` | 3525–3539 | 15 | PLAN_UNSENT + обнулить sends | `main.rs` refused/damaged journal | P | D22 |
| `d2k_session_applied` | 3541–3543 | 3 | счётчик applied | агрегата нет; APPLIED — только события/журнал | N | счётчик не ведётся |
| `d2k_session_done` | 3545–3547 | 3 | счётчик done | агрегата нет; PLAN_DONE — событие журнала | N | счётчик не ведётся |
| `d2k_session_damaged_count` | 3549–3551 | 3 | число damaged-потоков | флаг `damaged` на потоке есть, агрегата нет | N | счётчик не ведётся |
| `d2k_session_sent_lost` | 3553–3555 | 3 | «некому приписать отправку» | нет | N | счётчик не ведётся |
| `d2k_session_refusals` | 3557–3559 | 3 | отказы таблиц TCP+UDP | `main.rs:668` | P | — |
| `d2k_session_capacity` | 3561–3563 | 3 | ёмкость TCP+UDP | `main.rs:668` | P | — |
| `d2k_session_flows_tcp` | 3565–3567 | 3 | число TCP-потоков | `engine.rs:429 len` | P | — |
| `d2k_session_flows_udp` | 3569–3571 | 3 | число UDP-потоков | `r2o_udp_sessions.rs:465 stats` | P | — |
| `d2k_session_capacity_tcp` | 3573–3575 | 3 | ёмкость TCP | `engine.rs:434 r2o_tcp_flow_capacity` | P | — |
| `d2k_session_capacity_udp` | 3577–3579 | 3 | ёмкость UDP | `r2o_udp_sessions.rs:465` | P | — |
| `d2k_session_refusals_tcp` | 3581–3583 | 3 | отказы TCP | `engine.rs:438 r2o_tcp_flow_refusals` | P | — |
| `d2k_session_refusals_udp` | 3585–3587 | 3 | отказы UDP | `r2o_udp_sessions.rs:465` | P | — |
| `d2k_session_hellos` | 3589–3591 | 3 | число приветствий | `r2o_udp_sessions.rs:447`, `engine.rs` hello counters | P | — |
| `d2k_session_with_sni` | 3593–3595 | 3 | приветствий с SNI | `r2o_udp_sessions.rs:451` | P | — |
| `d2k_session_suspects` | 3597–3599 | 3 | число подозрений | агрегата нет; подозрения уходят событиями SUSPECT | N | счётчик не ведётся |
| `d2k_session_rst_dropped` | 3601–3603 | 3 | снятых чужих RST | `engine.rs` `r2o_tcp_rst_dropped` | P | — |
| `d2k_session_exchanges` | 3605–3607 | 3 | число обменов | агрегата нет; EXCHANGE — событие журнала | N | счётчик не ведётся; `r2o-udp-exchange-differential.sh` сверяет события |
| `d2k_session_reply_hidden` | 3609–3611 | 3 | «ответ не видели» | `engine.rs` `r2o_reply_hidden` | P | `r2o-tcp-reply-hidden-differential.sh` |
| `d2k_session_tcp_hello_flows` | 3613–3615 | 3 | TCP-потоков с приветствием | `engine.rs` `r2o_tcp_hello_flows` | P | — |
| `d2k_session_payload_stats` | 3617–3638 | 22 | разбор нагрузки: причины, HTTP, capture | `engine.rs` `R2oTcpPayloadStats` | P | `r2o-tcp-payload-stats-differential.sh` |
| `d2k_session_journal` | 3640–3642 | 3 | доступ к журналу | `flow_journal.rs:543 R2oFlowJournal` | P | D22 |

## track.c (18 функций)

Таблица потоков: открытая адресация, FNV-1a, удаление сдвигом, порог 3/4.
R2O заменил структуру на `HashMap`, сохранив ключ, ёмкость и порог отказов.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_key_make` | 18–51 | 34 | канонический ключ IPv4 (addr+port, порядок low/high) | `engine.rs:67 TcpFlowKey::from_endpoints`, `r2o_udp_sessions.rs:35 R2oUdpFlowKey::new` | P | порядок по (family,addr,port) вместо 6 байт; тесты capture/udp_sessions |
| `d2k_key_make_addr` | 55–74 | 20 | канонический ключ IPv4/IPv6 | `engine.rs:48 TcpFlowKey::from_packet`, `r2o_udp_sessions.rs:82 flow_key_from_packet` | P | IPv6-порядок по 16 байтам затем порту — совпадает |
| `round_pow2` (static) | 84–90 | 7 | округление ёмкости до степени 2 (мин. 16) | `flow_capacity.rs:12 from_requested` | E | `flow_capacity.rs:45` тест `r2o_ёмкость_повторяет_округление...` |
| `key_eq` (static) | 92–104 | 13 | побайтовое сравнение ключа | `#[derive(Eq, Hash)]` (`engine.rs:42`, `capture.rs:14`) | E | используется во всех тестах ключей |
| `key_hash` (static) | 108–115 | 8 | FNV-1a по sizeof(key) | `HashMap` SipHash (по умолчанию) | P | хеш-функция иная; коллизии не влияют на семантику |
| `d2k_track_new` | 117–133 | 17 | таблица + state, округление | `engine.rs:395 try_with_capacity`, `flow_capacity.rs:12` | P | — |
| `d2k_track_free` | 135–142 | 8 | освобождение | `Drop` | E | RAII |
| `d2k_track_find` | 144–160 | 17 | поиск без создания | `engine.rs` `self.flows.get` (напр. `:1578`) | P | — |
| `remove_at` (static) | 165–191 | 27 | удаление сдвигом назад (без надгробий) | `HashMap::remove` (внутренняя стратегия) | P | структура иная, инвариант «нет надгробий» не применим |
| `d2k_track_get` | 193–229 | 37 | get-or-create, last_ns, порог 3/4 | `engine.rs:911 track_packet_mode`, `:941` лимит | P | `engine.rs:2847` тест отказов на лимите |
| `d2k_track_new_connection` | 231–257 | 27 | сброс полей при новом SYN, сохранение учёта посылок | `engine.rs:938` ветка new_connection (новый `TcpSession`, metrics сохраняются) | P | `execution` переносится иначе — через tickets |
| `d2k_track_remove` | 259–267 | 9 | удалить поток | `engine.rs` `flows.remove` | P | — |
| `d2k_track_walk` | 269–278 | 10 | обход всех живых | `flows.iter()` / `retain` (`engine.rs:698`) | P | — |
| `d2k_track_expire` | 280–308 | 29 | истечение по idle с callback до удаления | `engine.rs:698 expire_with_silent` | P | callback вызывается до retain-удаления |
| `d2k_track_remove_if` | 310–325 | 16 | удаление по предикату (FIN-окно) | `engine.rs:700` fin_expired в retain | P | — |
| `d2k_track_count` | 327–329 | 3 | число записей | `engine.rs:429 len` | P | — |
| `d2k_track_capacity` | 331–333 | 3 | ёмкость (степень 2) | `engine.rs:434 r2o_tcp_flow_capacity` | P | — |
| `d2k_track_refusals` | 335–337 | 3 | отказы вставки | `engine.rs:438 r2o_tcp_flow_refusals` | P | `test-datapath-tcp-capacity-differential.sh` |

## capture.c (6 функций)

Сборка ClientHello/HTTP-заголовка по seq: TTL, generation, anchor, перекрытия,
конфликт → poison. R2O: `crates/r2o-datapath/src/capture.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `same` (static) | 4–6 | 3 | сравнение ключей | `TcpFlowKey` `Eq` (`capture.rs:14`) | E | используется во всех capture-тестах |
| `d2k_capture_forget` | 8–14 | 7 | сбросить слоты ключа | `capture.rs:650 forget` | E | `capture.rs:949` (требует forget/new generation) |
| `reject` (static) | 16–20 | 5 | state=2, rejected++ | `capture.rs:662 reject_result` | E | `capture.rs:949` conflicting overlap |
| `d2k_capture_feed_ready` | 22–107 | 86 | сборка по seq: TTL, generation, anchor, overlap, wrap, ready-callback | `capture.rs:514 feed_mode`, `:446 feed` | E | `capture.rs:989/1099 capture_*_traces_match_d2o`, `scripts/test-datapath-capture-lifecycle-differential.sh` (скрипт пинится на другой SHA D2O — ограничение) |
| `tls_ready` (static) | 109–118 | 10 | критерий целой TLS-записи (1 запись, длины) | `capture.rs:673 tls_ready` | E | `capture.rs:1209 rejects_invalid_single_record_client_hellos...` |
| `d2k_capture_feed` | 119–124 | 6 | feed с TLS-критерием | `capture.rs:446 feed` | E | те же трассы |

## hold.c (12 функций)

Удержание TCP-сегментов до сборки приветствия/HTTP-заголовка: слоты, дедлайн,
ревизия плана, порядок оригиналов, ready-batch. R2O: `hold.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `r32` (static) | 17 | 1 | big-endian u32 | `packet.rs:236 read_u32` | P | — |
| `same` (static) | 18–20 | 3 | сравнение ключей | `TcpFlowKey` Eq | E | — |
| `d2k_hold_parse` | 21–40 | 20 | разбор TCP-заголовка и полей hold | `hold.rs:1249 parse_tcp` | P | D6 |
| `d2k_hold_new` | 41 | 1 | создание | `HoldTable::default` (`hold.rs:194`) | E | RAII |
| `d2k_hold_free` | 42 | 1 | освобождение | `Drop` | E | RAII |
| `release_slot` (static) | 43–51 | 9 | вернуть ID, forget capture, pending-- | `hold.rs:1236 release_held_packets`, `:1229 remove_slot` | P | — |
| `d2k_hold_flush` | 52–72 | 21 | таймаут/смена ревизии/всё: release + статистика | `hold.rs:888 flush` | E | `hold.rs:2200 timeout_and_revision_change_fail_open...`, D6 |
| `d2k_hold_next` | 73–80 | 8 | ближайший дедлайн | `hold.rs:958 timeout_ms` | P | — |
| `d2k_hold_get_stats` | 81–84 | 4 | снимок статистики | `hold.rs:200 r2o_hold_stats` | P | — |
| `d2k_hold_verdicts` | 85–92 | 8 | выдать вердикт пачке ID | `main.rs:4335 release_with`, `:4308 release_many` | P | — |
| `http_ready` (static) | 93–100 | 8 | готовность HTTP-заголовка (или конфликт) | `hold.rs:695 http_ready`, `:1343 incomplete_http_head` | P | `hold.rs:2374 timeout_reports_unassembled_http_headers` |
| `d2k_hold_feed` | 101–236 | 136 | приём сегмента: слот, side, лимиты, capture, порядок, синтетическая голова | `hold.rs:356 feed_observing_mode`, `:1348 synthetic_packet` | E | `hold.rs:1458/2126/2167` (split head, out-of-order, order), D6 |

## udp_hold.c (10 функций)

Ограниченное владение NFQUEUE ID для сборки QUIC ClientHello: слоты, дедлайн,
пачки, переполнение. R2O: `r2o_udp_hold.rs` (`R2oUdpHoldTable`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `same_key` (static) | 14–16 | 3 | сравнение ключа | `R2oUdpFlowKey` Eq (`r2o_udp_sessions.rs:37`) | E | — |
| `clear_slot` (static) | 18–20 | 3 | обнулить слот | `Option::take`/`None` | E | — |
| `release_slot` (static) | 22–29 | 8 | release-callback + clear | `r2o_udp_hold.rs:212 r2o_flush`, `:228 r2o_drain` | P | release выполняется вызывающим, не слотом |
| `d2k_udp_hold_new` | 31 | 1 | создание | `R2oUdpHoldTable::new` (`:147`) | E | — |
| `d2k_udp_hold_free` | 33–39 | 7 | слить все слоты | `r2o_drain` (`:228`) | P | — |
| `d2k_udp_hold_flush` | 41–52 | 12 | истёкшие слоты → release | `r2o_flush` (`:212`) | P | — |
| `d2k_udp_hold_feed` | 54–58 | 5 | feed с mark=0 | `r2o_feed` (`:154`, mark=0) | P | — |
| `d2k_udp_hold_feed_marked` | 60–96 | 37 | приём: лимит 1600, слот по ключу, переполнение 8 | `:154 r2o_feed` (`R2O_UDP_HOLD_PACKETS=8`, max 1600) | P | отличается: overflow возвращает batch, C освобождает слот |
| `d2k_udp_hold_take` | 98–113 | 16 | забрать пачку целиком | `:198 r2o_take` | P | — |
| `d2k_udp_hold_next_ns` | 115–123 | 9 | ближайший дедлайн | `:240 timeout_ms` | P | — |

## udp_path.c (7 функций)

Транзакция UDP-hold вокруг решения сессии и выпуск/повтор пачек.
R2O: `main.rs` (`r2o_release_udp_batch*`, `r2o_udp_handle_late_tail`),
`r2o_udp_sessions.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_udp_path_release` | 6–13 | 8 | закрыть hold и выпустить пачку ACCEPT | `main.rs:153 r2o_release_udp_batch`, `:200 batches` | P | — |
| `d2k_udp_path_pre` | 15–33 | 19 | flush истёкших, hold_begin, feed; откат при отказе | `main.rs:1590-1630` hold/feed/overflow | P | `r2o-udp-session-table-check.sh` |
| `d2k_udp_path_post` | 35–60 | 26 | HELD/REPLAY/LOST/RECLAIMED по результату сессии | `main.rs:1600-2200` (ready/replay/late) | P | — |
| `d2k_udp_path_read` | 62–67 | 6 | новый receive-seq | `main.rs` `udp_receive_seq` | P | — |
| `d2k_udp_path_expire` | 69–74 | 6 | flush по таймеру с seq | `main.rs:1330` flush + release | P | — |
| `d2k_udp_path_passed` | 76–88 | 13 | пассивный проход: neutral + follow_mark | `main.rs:108 r2o_udp_mark_plain_pass` | P | — |
| `d2k_udp_path_planned` | 90–97 | 8 | плановая посылка: neutral + follow_mark(at) | `main.rs:131 r2o_udp_mark_planned` | P | — |

## udp_release.c (34 функции)

Очередь отложенных вердиктов, судьбы повторной отправки пачки, окно follow
(5 мс), нейтральность метки, out_batch/out_late. R2O: `r2o_udp_hold.rs`
(`R2oUdpDeferredVerdicts`, `R2oUdpFollowTable`, `R2oUdpDeferredResends`,
`r2o_release_batch_with`), `main.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_udp_release_new` | 29–51 | 23 | очередь slots×batch, защита от переполнения | `r2o_udp_hold.rs:283 R2oUdpDeferredVerdicts::new` (фикс. 16×8) | P | параметры стали константами |
| `d2k_udp_release_free` | 53–59 | 7 | освобождение | `Drop` | E | RAII |
| `d2k_udp_release_enqueue` | 61–81 | 21 | положить пачку ID+вердиктов с due/seq/token | `:291 r2o_enqueue` (due+order, flow_key) | P | token/seq заменены order |
| `next_due` (static) | 83–94 | 12 | минимальный (due,seq) | `:355` min_by_key(due,order) | P | порядок реализован; отдельного теста на равенство due нет |
| `d2k_udp_release_flush` | 96–122 | 27 | выдать созревшие, done(complete,sent) | `:345 r2o_flush` | P | callback done отсутствует; ошибки собираются в first_error |
| `d2k_udp_release_next_ns` | 124–133 | 10 | ближайший due | `:392 timeout_ms` | P | — |
| `d2k_udp_replay_fates` | 135–154 | 20 | судьбы: owned head DROP, tails resend/ACCEPT | `:72 r2o_release_batch_with` (инлайн) | P | `owned`-ветка head_already_released |
| `plain_verdict` (static) | 174–177 | 4 | адаптер verdict | замыкание `send_verdict` | E | — |
| `plain_resend` (static) | 178–182 | 5 | адаптер resend без ID | замыкание `resend` | E | — |
| `d2k_udp_release_batch` | 184–192 | 9 | обёртка release_batch | `:72 r2o_release_batch_with` | P | — |
| `release_batch` (static) | 194–247 | 54 | ядро: may/defer/owned/resend/verdict/fallback | `:72 r2o_release_batch_with` | P | нет `may[]`/defer/owned; часть в main |
| `follow_stale` (static) | 272–275 | 4 | устаревание окна по времени и seq | `:550 r2o_match` (stale), `:602 r2o_age` | P | формула совпадает |
| `follow_drop` (static) | 277–280 | 4 | снять запись, live-- | `:565`/`:611` | E | — |
| `d2k_udp_follow_age` | 282–287 | 6 | обход устаревших | `:602 r2o_age` | P | — |
| `d2k_udp_follow_live` | 289 | 1 | live | `:490 r2o_stats` | E | `:830 follow_stats_*` |
| `d2k_udp_follow_busy` | 290 | 1 | busy | `:490` | E | `:830` |
| `d2k_udp_follow_queue_full` | 291 | 1 | queue_full | `:490` | E | `:830` |
| `d2k_udp_follow_refused` | 292 | 1 | refused | `:490` | E | `:830` |
| `d2k_udp_send_busy` | 294–296 | 3 | EAGAIN/EWOULDBLOCK/ENOBUFS | `:799 r2o_udp_send_busy` | E | `:852` busy vs permanent |
| `d2k_udp_follow_new` | 298 | 1 | создание | `:480 new` | E | — |
| `d2k_udp_follow_free` | 300 | 1 | освобождение | `Drop` | E | — |
| `follow_tuple` (static) | 302–319 | 18 | кортеж UDP, отказ фрагментам/мультикасту | `:428 R2oUdpFollowKey::from_packet` | P | — |
| `same_tuple` (static) | 321–324 | 4 | сравнение кортежа | `Eq` | E | — |
| `d2k_udp_follow_mark` | 329–332 | 4 | поставить окно | `:508 r2o_mark` | P | — |
| `follow_put` (static) | 334–355 | 22 | выбрать слот/вытеснить, until/at/seq | `:508 r2o_mark` | P | вытеснение по min(until) |
| `follow_find` (static) | 357–370 | 14 | найти окно, попутно истекая | `:550 r2o_match` | P | — |
| `d2k_udp_follow_match` | 372–378 | 7 | match + at_ns | `:550 r2o_match` → `R2oUdpFollowMatch` | E | `main.rs:4922` unit, D6 |
| `out_resend` (static) | 388–415 | 28 | resend с учётом at/owned/ENOSPC/busy | `main.rs:226 r2o_udp_handle_late_tail`, `:250` deferred | P | — |
| `d2k_udp_out_owned_emit` | 417–421 | 5 | вердикт владеемой посылки | `main.rs:4335 release_with` | P | — |
| `refused_flow` (static) | 425–430 | 6 | счётчик + первый лог на поток | `main.rs:285 follow.r2o_mark_failed` | P | — |
| `out_verdict` (static) | 432–435 | 4 | адаптер вердикта | `queue.send_verdict` | E | — |
| `d2k_udp_out_neutral` | 437–440 | 4 | mark 0/нейтральный/не routed | `main.rs:88 r2o_udp_packet_is_neutral` | P | семантика совпадает |
| `d2k_udp_out_batch` | 442–473 | 32 | выпуск пачки: may, marked, follow, failed | `main.rs:153 r2o_release_udp_batch` | P | — |
| `d2k_udp_out_late` | 475–509 | 35 | поздний хвост: follow, defer, resend | `main.rs:226 r2o_udp_handle_late_tail` | P | — |

## nfq.c (12 функций)

NFQUEUE: netlink bind/params с ACK, SO_RCVBUF(FORCE), recv ENOBUFS, вердикты.
R2O: `nfqueue.rs`, `netlink.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `say` (static) | 33–41 | 9 | форматирование ошибки в буфер | `io::Error`/`format!` | P | иной механизм, контракт тот же |
| `nl_write` (static) | 43–57 | 15 | sendto с EINTR-retry | `nfqueue.rs:416 send_to_kernel` | E | `netlink` тесты + код |
| `await_ack` (static) | 61–109 | 49 | poll 8×1 с, разбор NLMSG_ERROR | `nfqueue.rs:342 await_ack`, `:366 await_ack_with` | E | `nfqueue.rs:480 await_ack_stops_after_first_timeout` |
| `send_and_ack` (static) | 111–122 | 12 | запись + ACK | `nfqueue.rs:336 configure` | P | — |
| `set_rcvbuf` (static) | 127–145 | 19 | RCVBUFFORCE → RCVBUF, вернуть effective | `nfqueue.rs:13 set_receive_buffer_with` | E | `:512`/`:535`/`:563` три теста |
| `d2k_nfq_open` | 147–230 | 84 | socket/bind/BIND/PARAMS(fail_open,GSO off) | `nfqueue.rs:115 open` | P | параметры и ACK совпадают; AF_INET6 добавлен |
| `d2k_nfq_close` | 232–248 | 17 | UNBIND без ACK + close | `nfqueue.rs:404 Drop` | P | — |
| `d2k_nfq_fd` | 250–252 | 3 | fd | `nfqueue.rs` `AsRawFd` | P | — |
| `d2k_nfq_recv` | 254–274 | 21 | recv; EAGAIN/EINTR→0, ENOBUFS→-2 lost | `nfqueue.rs:190 receive`, `:195 receive_timeout` | P | EINTR→`ReceiveError::Wait`, а не 0 |
| `d2k_nfq_verdict` | 276–292 | 17 | вердикт | `nfqueue.rs:310 send_verdict` | E | `netlink.rs:304 verdict_bytes...` |
| `d2k_nfq_verdict_payload` | 294–311 | 18 | вердикт с заменой | `nfqueue.rs:317 send_replacement` | E | `netlink.rs:321 replacement_verdict...` |
| `d2k_nfq_lost` | 313–315 | 3 | счётчик потерь | `nfqueue.rs:271 lost_packets` | E | `nfqueue.rs:492 record_lost_packet...` |

## nl.c (19 функций)

Netlink/NFQUEUE кодек: итератор сообщений, атрибуты пакета, сборка вердиктов и
конфигурации. R2O: `netlink.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `align4` (static) | 10–12 | 3 | выравнивание | `netlink.rs:291 align4` | E | используется в тестах кодекa |
| `h16` (static) | 16 | 1 | host u16 | `from_ne_bytes` (`netlink.rs:95`) | E | тесты конфигурации |
| `h32` (static) | 17 | 1 | host u32 | `from_ne_bytes` (`:88`) | E | `:355` iterator test |
| `wh16` (static) | 18 | 1 | запись host u16 | `to_ne_bytes` (`:266`) | E | — |
| `wh32` (static) | 19 | 1 | запись host u32 | `to_ne_bytes` (`:284`) | E | — |
| `n16` (static) | 22–24 | 3 | сетевой u16 | `from_be_bytes` (`:143`) | E | `:371` parser test |
| `n32` (static) | 25–28 | 4 | сетевой u32 | `from_be_bytes` (`:141`) | E | `:371` |
| `wn16` (static) | 29–31 | 3 | запись сетевого u16 | `to_be_bytes` (`:228`) | E | `:332` |
| `wn32` (static) | 32–35 | 4 | запись сетевого u32 | `to_be_bytes` (`:196`) | E | `:304` |
| `d2k_nl_iter_init` | 37–43 | 7 | инициализация итератора | `MessageIter::new` (`:64`) | E | `:355` |
| `d2k_nl_next` | 45–77 | 33 | следующее сообщение, битые длины → стоп | `MessageIter::next` (`:76`) | E | `:355` (unpadded/bad length) |
| `d2k_nl_packet` | 79–161 | 83 | атрибуты NFQA: hdr/payload/cap/ts/mark/oif | `netlink.rs:125 QueuePacket::parse` | E | `:371`, `:403` |
| `d2k_nl_errno` | 163–176 | 14 | знаковый errno из NLMSG_ERROR | `netlink.rs:183 kernel_error` | E | `:429 kernel_error_reads...` |
| `hdr_init` (static) | 181–197 | 17 | nlmsghdr+nfgenmsg | `netlink.rs:263 header` | E | `:332` |
| `put_attr` (static) | 200–216 | 17 | атрибут + zero padding | `netlink.rs:274 push_attr` | E | `:321` |
| `d2k_nl_verdict` | 218–234 | 17 | VERDICT | `netlink.rs:188 verdict` | E | `:304` |
| `d2k_nl_verdict_payload` | 236–252 | 17 | VERDICT+PAYLOAD | `netlink.rs:203 verdict_payload` | E | `:321` |
| `d2k_nl_cfg_cmd` | 254–273 | 20 | CONFIG BIND/UNBIND, ACK | `netlink.rs:219 config_command` | E | `:332` |
| `d2k_nl_cfg_params` | 275–309 | 35 | PARAMS/MAXLEN/FLAGS/MASK | `netlink.rs:234 config_params` | E | `:332` |

## icmpguard.c (7 функций)

Отсечение ICMP time-exceeded на свои фальшивки с пониженным TTL.
R2O: `r2o_icmp_guard.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_icmpguard_init` | 6–8 | 3 | обнулить кольцо 256 | `Default for R2oIcmpGuard` (`:32`) | E | — |
| `u16` (static) | 10 | 1 | big-endian u16 | `r2o_icmp_guard.rs:257 r2o_u16` | E | — |
| `parse_ip` (static) | 21–47 | 27 | IP-заголовок цитаты, отказ не-первому фрагменту | `:204 r2o_parse_icmp_quote` | P | — |
| `d2k_icmpguard_note` | 49–69 | 21 | запомнить фальшивку: TTL ниже исходного, кортеж, l4word, ip_id | `:56 r2o_note` | P | `test-icmp-guard-current-differential.sh` |
| `d2k_icmpguard_check` | 71–110 | 40 | ICMPv4 type 11/0, v6 type 3/0; сверка 7 полей, TTL ≤ | `:90 r2o_check`, `:175 r2o_icmp_quote_start` | P | те же; unit-тестов в модуле нет |
| `d2k_icmpguard_dropped` | 112 | 1 | счётчик снятых | `:149 r2o_dropped` | E | — |
| `d2k_icmpguard_noted` | 113 | 1 | счётчик запомненных | `:145 r2o_noted` | E | — |

## http80.c (30 функций)

Провайдерская вставка в HTTP/80: таблица потоков, RTT по SYN/SYN-ACK, потоковый
разбор запроса/ответа, портал, 307+HTTPS name, RST. R2O: `hold.rs` (HTTP
observation), `control.rs` (https names), `http_replace.rs` (пакеты),
`r2k-core/httpup.rs`, `http_response.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_http80_new` | 67–69 | 3 | создать таблицу 128 потоков/256 имён | `control.rs` NamePlans + `hold.rs` HoldTable | P | объект разнесён на два |
| `d2k_http80_free` | 71–73 | 3 | освободить | `Drop` | E | RAII |
| `d2k_http80_get_stats` | 75–79 | 5 | снимок статистики | `hold.rs:200 r2o_hold_stats`, `control.rs` | P | состав счётчиков иной |
| `name_norm` (static) | 83–95 | 13 | нормализация имени: нижний регистр, LDH, без точки | `r2o-datapath/src/control.rs:2233 canonical_name` | P | R2O строже: требует ≥2 метки и хотя бы одну нецифровую (C принимает односложное имя) |
| `d2k_http80_set_https` | 97–118 | 22 | добавить/снять имя с TTL, вытеснение записи с наименьшим expires | `r2o-datapath/src/control.rs:1055 set_https`, `:1077` лимит 256 и `min_by_key(expires)` | P | `control.rs:3157` тест set_https; семантика вытеснения совпадает |
| `d2k_http80_https` | 120–129 | 10 | имя подтверждено и не истекло | `r2o-datapath/src/control.rs:590 has_verified_https` | P | `control.rs:3157` |
| `wr16` (static) | 133 | 1 | big-endian u16 | `wire.rs:552 write_u16` | E | `wire` тесты |
| `wr32` (static) | 134–136 | 3 | big-endian u32 | `wire.rs:556 write_u32` | E | — |
| `sum16` (static) | 138–142 | 5 | RFC1071 | `wire.rs:534 sum16` | E | `wire.rs` golden |
| `fold` (static) | 144–147 | 4 | свёртка | `wire.rs:545 checksum_value` | E | — |
| `build` (static) | 156–188 | 33 | IP+TCP без опций, 307/RST, суммы | `http_replace.rs:79 build_segment` | E | `http_replace.rs:219` v4/v6 + валидные суммы |
| `rd32` (static) | 190–192 | 3 | big-endian u32 | `packet.rs:236 read_u32` | P | — |
| `stale` (static) | 196–198 | 3 | простой > IDLE | `hold.rs` `seen`/таймауты HTTP-потока | P | — |
| `find` (static) | 200–215 | 16 | найти поток по 5-tuple | `hold.rs:1225 slot_index`/`:210` | P | — |
| `make` (static) | 217–236 | 20 | создать/вытеснить самый давний | `hold.rs` HttpRequestFlow создание | P | — |
| `d2k_http80_executed` | 238–254 | 17 | привязать execution к потоку запроса | `hold.rs:209 note_http_execution` | P | — |
| `request_result` (static) | 256–265 | 10 | заполнить результат запроса | `hold.rs:1269 finish_http_response` | P | — |
| `d2k_http80_delivered` | 267–276 | 10 | отказ доставки замены → invalid/DONE | `hold.rs:220 reject_http_response` | P | — |
| `seq_after` (static) | 281 | 1 | сравнение seq с переносом | `hold.rs:1318 seq_after` | E | — |
| `delivered` (static) | 285–287 | 3 | дальний из reply_next/acked | `hold.rs:276` вычисление delivered | P | — |
| `cut_pending` (static) | 289–293 | 5 | условия обрыва тела | `hold.rs:260-286` sweep | P | — |
| `cut_result` (static) | 295–303 | 9 | CUT: body_bytes=max, rtt, DONE | `hold.rs:287-293` (response=4) | P | `hold.rs:2082` |
| `d2k_http80_sweep` | 305–323 | 19 | тишина 3×RTT (мин. 2 с) → CUT | `hold.rs:255 sweep_http_responses` | P | `hold.rs:2082`; D17 |
| `request_prefix` (static) | 327–341 | 15 | GET/HEAD + target + Host из префикса | `httpup.rs:180 r2o_http_plan_request` | P | — |
| `request_feed` (static) | 342–347 | 6 | потоковый разбор запроса и граница | `httpup.rs:116 observe_detailed` | P | `hold.rs:2401 split_http_request...` |
| `d2k_http80_packet` | 349–525 | 177 | вся стейт-машина HTTP/80 (SYN/OPEN/IDLE/REQUEST/INJECTED/SWAP) | `hold.rs:1088 observe_http_response` + `:356 feed_observing_mode` | P | D17 paired differential покрывает портал/307/поздний/дубль; полный набор состояний C не доказан |
| `d2k_http80_swap` | 527–545 | 19 | вердикт с заменой + RST, иначе ACCEPT | `main.rs:2093 send_replacement`, `:2114 mark_http_response_answered` | P | D17 проверяет исход, сокет-путь — нет |
| `lc` (static) | 549 | 1 | ASCII lower | `u8::to_ascii_lowercase` | E | — |
| `d2k_http_request` | 551–632 | 82 | строгий разбор запроса: метод, origin-form, Host:80, LDH, не IPv4 | `httpup.rs:180 r2o_http_plan_request`, `:220 parse_request` | P | тесты httpup; полный набор отказов C не сверен |
| `d2k_http_hello` | 634–640 | 7 | host_off/host_len из запроса | `httpup.rs:175 request_host_range` | P | — |

## http_trace.c (1 функция)

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_http_trace` | 9–50 | 42 | строка `d2kd: HTTP execution host=... hook=... status=...` по пакету и исходу | нет: grep `HTTP execution` по R2O пуст | N | текстовый трейс HTTP-исполнения отсутствует; события портала/ответа есть, но это другой контракт |

## journal.c (14 функций)

Кольцо журнала наблюдений: kinds, коды suspect/refuse, очистка имени, plan/trial/
execution/binding, added/dropped. R2O: `flow_journal.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_journal_new` | 16–31 | 16 | кольцо cap (0 — выключен) | `flow_journal.rs:552 with_capacity` | P | cap=0 в R2O — ошибка, а не «выключен» |
| `d2k_journal_free` | 33–39 | 7 | освобождение | `Drop` | E | RAII |
| `d2k_suspect_text` | 41–53 | 13 | тексты SUSPECT_* (8 кодов + default) | `flow_journal.rs:28 r2o_suspect_text` | E | `:1027 journal_note_texts_match_d2o` |
| `d2k_refuse_text` | 55–68 | 14 | тексты REFUSE_* (7 кодов + default) | `:45 r2o_refuse_text` | E | `:1027` |
| `add_entry` (static) | 76–130 | 55 | общая запись: added/dropped, note по умолчанию, чистка имени | `:565 push` (note default `:530`), `:184 set_name` | P | очистка имени реализована, счётчики added/dropped есть |
| `d2k_journal_add` | 132–137 | 6 | добавить наблюдение | `:565 push` | P | — |
| `d2k_journal_add_applied` | 139–149 | 11 | APPLIED + plan/trial | `:650 record_applied` | P | D22 |
| `d2k_journal_add_refused` | 151–158 | 8 | REFUSED + code/plan/trial | `:684 record_plan_refused` | P | D22 |
| `d2k_journal_add_fate_bound` | 160–176 | 17 | DONE/UNSENT/DAMAGED + execution/binding | `:722 record_execution_failure`, `:667 record_plan_prepared` | P | три вида разнесены по вызывающим |
| `d2k_journal_add_fate` | 178–182 | 5 | fate без execution | те же без execution | P | — |
| `d2k_journal_count` | 184–186 | 3 | число записей | `:990 count` | E | — |
| `d2k_journal_at` | 188–196 | 9 | запись от старой к новой | `:994 get`, `:1014 iter` | P | кольцо заменено VecDeque с вытеснением |
| `d2k_journal_dropped` | 198–200 | 3 | вытеснено | `:1006 dropped` | E | — |
| `d2k_journal_added` | 202–204 | 3 | добавлено всего | `:1010 added` | E | — |

## nat.c (5 функций)

Внешний адрес/порт из `/proc/net/nf_conntrack`: разбор строк, «лучшая запись» по
TTL, отличие «нет таблицы» от «нет записи». R2O: `proc_nat.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `parse_ip4` (static) | 20–41 | 22 | строгий разбор IPv4 без inet_pton | `proc_nat.rs:145 parse_ipv4` | P | `r2o-nat-proc-differential.sh`; unit-теста на отказы (переполнение/хвост) нет |
| `field_after` (static) | 46–63 | 18 | поле `name=` на границе слова | `proc_nat.rs:122 field_after`, `:113 fields` | P | R2O парсит токены `key=value` целиком — строже C |
| `d2k_nat_outside` | 67–73 | 7 | IPv4-обёртка | `:20 lookup` с tuple family=4 | P | — |
| `parse_address` (static) | 75–82 | 8 | IPv4/IPv6 литерал | `:134 parse_address` | P | — |
| `d2k_nat_outside_family` | 84–194 | 111 | проход файла, прямой/обратный кортеж, best TTL, коды -1/0/1 | `:20 lookup` → `R2oProcNatLookup` | E | `:220 отличает_отсутствие_таблицы...` + `r2o-nat-proc-differential.sh` |

## ctq.c (20 функций)

ctnetlink: сборка GET, разбор счётчиков/состояния TCP, неблокирующий запрос,
проба подсистемы, открытие сокета. R2O: `conntrack.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `align4` (static) | 16 | 1 | выравнивание | `conntrack.rs:250 align4` | E | — |
| `wr16h` (static) | 18 | 1 | host u16 | `to_ne_bytes` (`:256`) | E | `:543` encode test |
| `wr32h` (static) | 19 | 1 | host u32 | `to_ne_bytes` (`:125`) | E | `:543` |
| `rd16h` (static) | 20 | 1 | host u16 | `from_ne_bytes` (`:233`) | E | `:543` |
| `rd64be` (static) | 21–25 | 5 | сетевой u64 | `u64::from_be_bytes` (`:214`) | E | `:487` тест счётчиков |
| `rd32be` (static) | 26–28 | 3 | сетевой u32 | `u32::from_be_bytes` (`:224`) | E | `:529` 32-битные счётчики |
| `put` (static) | 31–40 | 10 | атрибут с padding | `push_attribute` (`:254`) | E | `:543` |
| `open_nest` (static) | 43–47 | 5 | вложенный атрибут | `push_attribute(kind с NLA_F_NESTED)` (`:114`) | P | — |
| `close_nest` (static) | 48–50 | 3 | длина вложенного | length prefix в `push_attribute` | P | — |
| `d2k_ct_get_req` | 52–81 | 30 | GET orig-tuple (family/proto/ports) | `conntrack.rs:74 encode_get` | E | `:543 строит_запрос_по_кортежу_ipv4` |
| `counter` (static) | 84–96 | 13 | packets из вложенного counters (64/32) | `:211 parse_counter` | E | `:487`, `:529` |
| `tcp_state` (static) | 99–120 | 22 | состояние TCP (+1 enum) | `:156-160` из PROTOINFO | E | `:487` (state=3) |
| `d2k_ct_info_parse` | 122–156 | 35 | разбор ответа: коды -1/0/1/2 | `:137 decode_entry`, `:133 decode_info` | P | коды заменены `Option`; «нет счётчиков» → `info=None` |
| `d2k_ct_counters_parse` | 158–167 | 10 | только счётчики | `decode_info(...).map(...)` | P | — |
| `d2k_ct_query_info_fd` | 169–186 | 18 | send GET + до 8 recv без ожидания | `:301 query_entry`, `:384 receive_entry` | P | — |
| `d2k_ct_query_fd` | 188–197 | 10 | обёртка счётчиков | `:297 query` | P | — |
| `reply_errno` (static) | 201–212 | 12 | errno из NLMSG_ERROR по seq | `kernel_error` + фильтр seq (`:350`) | P | — |
| `d2k_ct_probe_fd` | 214–238 | 25 | проба ENOENT/запись → подсистема есть | `:309 probe` (100 мс poll) | P | `r2o-conntrack-ctget-differential.sh` |
| `d2k_ct_open` (linux) | 243–253 | 11 | netlink socket + nonblock + bind | `:270 open` (SOCK_NONBLOCK) | P | — |
| `d2k_ct_open` (не linux) | 255 | 1 | заглушка -1 | `#[cfg(target_os="linux")]` | E | платформенная ветка |

## sched.c (16 функций)

Двоичная куча отложенной отправки по (due, seq), владение NFQUEUE ID,
выбрасывание слишком длинной головы. R2O: `scheduler.rs` (отсортированный Vec +
flow-брони).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_sched_new` | 43–71 | 29 | ёмкость/slot_size, freelist | `scheduler.rs:89 with_limits` | E | `:563` тест ёмкости |
| `d2k_sched_grow_slot_size` | 73–88 | 16 | увеличить слот, перенести данные | `:260 grow_slot_size` | P | копирование не нужно (Vec) |
| `d2k_sched_free` | 90–98 | 9 | освобождение | `Drop` | E | RAII |
| `earlier` (static) | 102–107 | 6 | (due,seq) порядок | сравнение `(due, order)` (`:195`) | E | `:526` порядок |
| `sift_up` (static) | 109–120 | 12 | подъём кучи | вставка в отсортированный Vec (`:196`) | P | структура иная, порядок тот же |
| `sift_down` (static) | 122–139 | 18 | спуск кучи | `remove(0)` (`:285`) | P | — |
| `d2k_sched_push` | 141–144 | 4 | push без execution | `:209 push_raw` | E | `:526` |
| `d2k_sched_push_serial` | 149–152 | 4 | push с execution/ключом | `:167 push_reserved` | P | execution → ticket |
| `d2k_sched_push_owned` | 154–157 | 4 | push с владением ID | `:214 push_owned` | P | путь owned не покрыт unit-тестом |
| `push` (static) | 159–190 | 32 | проверки len/cap, seq++, sift | `:223 push_owner` | P | — |
| `d2k_sched_pop_due` | 192–196 | 5 | pop без execution | `:329 pop_due` | P | — |
| `d2k_sched_pop_due_serial` | 198–202 | 5 | pop с execution | `:275 pop_due_ex` | P | — |
| `d2k_sched_pop_due_ex` | 204–267 | 64 | pop; слишком длинная голова выбрасывается, owned отдаёт ID | `:275 pop_due_ex` (`ScheduledPop`) | P | `:526`/`:563` + D21; ветка `OversizedOwned` не тестирована |
| `d2k_sched_next_ns` | 269–271 | 3 | ближайший due | `:298 next_due` | E | — |
| `d2k_sched_count` | 273–275 | 3 | число в очереди | `:373 len` | E | — |
| `d2k_sched_refusals` | 277–279 | 3 | отказы | `:377 refusals` | E | `:563` |

## wire.c (9 функций)

Единственное место расчёта контрольных сумм TCP: TTL по измеренному пути,
опции, MD5, seq_shift, badsum, IPv4/IPv6. R2O: `r2k-core/src/wire.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `wr16` (static) | 23–26 | 4 | big-endian u16 | `wire.rs:552 write_u16` | E | golden-тесты wire.rs |
| `wr32` (static) | 28–33 | 6 | big-endian u32 | `:556 write_u32` | E | — |
| `rd16` (static) | 35–37 | 3 | big-endian u16 | `u16::from_be_bytes` в `:436` | P | — |
| `auto_ttl` (static) | 54–70 | 17 | TTL по rev_ttl: origin 64/128/255, delta, min/max, clamp | `plan/apply.rs:764 poison_ttl` | E | `engine.rs:2120 autottl_uses_the_observed_reverse_tcp_ttl...` |
| `sum16` (static) | 73–82 | 10 | RFC1071 | `wire.rs:534 sum16` | E | wire golden |
| `fold` (static) | 84–89 | 6 | свёртка | `:545 checksum_value` | E | — |
| `pseudo_sum` (static) | 99–107 | 9 | псевдозаголовок TCP | `:516 pseudo_sum` | E | — |
| `d2k_wire_build` | 109–277 | 169 | сборка TCP-пакета: профили, MD5, TS, ts_up, seq_shift, poison, суммы | `wire.rs:18 build_tcp_packet` | E | `wire.rs` 12 тестов (golden, template, ts_up, badsum, measured, MD5, v6, capacity) + `test-wire-ts-up-plan-differential.sh` |
| `d2k_wire_tcp_checksum_ok` | 279–306 | 28 | проверка суммы IPv4/IPv6 | `wire.rs:436 tcp_checksum_ok` | E | `wire.rs` тесты + используется в http_replace |

## wire_udp.c (5 функций)

Сборка UDP-датаграммы IPv4/IPv6; отказ неприменимым искажениям, обязательная
сумма (0→0xffff). R2O: `wire.rs::build_udp_packet`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `wr16` (static) | 22–25 | 4 | big-endian u16 | `wire.rs:552 write_u16` | E | — |
| `sum16` (static) | 31–40 | 10 | RFC1071 | `:534 sum16` | E | — |
| `fold` (static) | 42–47 | 6 | свёртка | `:545 checksum_value` | E | — |
| `pseudo_sum` (static) | 57–65 | 9 | псевдозаголовок UDP | `build_udp_packet` внутри (`:271-285`) | P | вынесенной функции нет |
| `d2k_wire_build_udp` | 67–207 | 141 | сборка UDP, запрет pre/seq_shift/TS/BADSUM, сумма всегда | `wire.rs:213 build_udp_packet` | P | `crates/r2o-datapath/tests/raw.rs:181` собирает пакет; divergence: R2O отвергает **любой** poison, включая IPID_ZERO, который C для IPv4 допускает, и заполняет TOS из пакета |

## addr.c (3 функции)

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_addr_parse` | 5–18 | 14 | IPv4/IPv6 литерал, отказ `%zone` | `r2k-core/src/addr.rs:11 Address::parse` | E | `r2k-core/tests/network.rs:6`, `:22` (включая `fe80::1%eth0`) |
| `d2k_addr_text` | 20–30 | 11 | текст адреса, 0 при cap==0/нехватке | `addr.rs:49 Display` | P | контракт «не влезло → 0» не нужен: `format!` не усекает |
| `d2k_addr_equal` | 32–36 | 5 | равенство family+bytes | `addr.rs:5 PartialEq` | E | `network.rs:16` |

## tls.c (7 функций)

Разбор TLS ClientHello/ServerHello: границы claimed/avail, SNI, TLS1.3,
ECH, середина приветствия. R2O: `r2k-core/src/tls.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `rd16` (static) | 30–32 | 3 | big-endian u16 | `tls.rs:129 read_u16` | E | `tls.rs` тесты |
| `skip_u8_vec` (static) | 36–46 | 11 | пропуск вектора с u8-длиной | `:141 skip_u8_vector` | E | `:367` |
| `skip_u16_vec` (static) | 48–58 | 11 | пропуск вектора с u16-длиной | `:158 skip_u16_vector` | E | `:367` |
| `has_ech_offer` (static) | 72–87 | 16 | структурно целый ECH (0xfe0d) | `:230 has_ech_offer` | E | `:466 recognizes_only_structurally_consistent_ech_offer` |
| `has_tls13` (static) | 105–129 | 25 | supported_versions 0x0304, key_share на обрыве | `:175 has_tls13` | E | `:411`, `:438` |
| `find_sni` (static) | 131–177 | 47 | server_name/host_name, отказ пустому/битому | `:274 find_sni` | E | `:445`, `:455` |
| `d2k_tls_parse` | 179–361 | 183 | весь разбор, ServerHello ≥38, hello_middle, record_end | `tls.rs:32 parse` | E | `:367`-`:525` + сверка с `tls_parser` `:394` + fuzz-префиксы `:503` |

## include/*.h (14 inline-функций)

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_ctl_binding_write` (inline) | 86–90 | 5 | запись binding (generation/kind/family/shape/temporary/epoch) | `r2k-core/src/control.rs:333 AppliedEvent::event_body`, `BindingContext` `:305` | P | формат совпадает; отдельных unit на раскладку нет |
| `d2k_ctl_binding_read` (inline) | 91–99 | 9 | чтение/валидация binding | `control.rs` decode applied/refused, `valid_binding` | P | — |
| `d2k_http_request_stream_init` (inline) | 19–21 | 3 | инициализация потокового парсера запроса | `httpup.rs:63 R2oHttpRequestSequence::new` | P | — |
| `d2k_http_request_stream_line` (inline) | 22–30 | 9 | завершение строки, лимиты | `httpup.rs:220 parse_request`, `:382 find_crlf` | P | — |
| `d2k_http_request_stream_feed` (inline) | 31–86 | 56 | потоковый разбор заголовка, end/past_end/invalid | `httpup.rs:116 observe_detailed`, `:73 candidate` | P | `hold.rs:2401 split_http_request...` косвенно |
| `d2k_hr_decimal` (inline) | 21–29 | 9 | десятичное число с ограничением | `http_response.rs:360 parse_decimal` | P | тестов в http_response.rs нет |
| `d2k_hr_token` (inline) | 31–34 | 4 | допустимый token-байт | `httpup.rs:346 is_http_token` (заголовки — `:273 invalid_header_byte`) | P | — |
| `d2k_hr_field` (inline) | 35–42 | 8 | валидация поля заголовка | `http_response.rs:281 parse_headers` | P | — |
| `d2k_hr_extensions` (inline) | 43–70 | 28 | Transfer-Encoding/chunked/расширения | `:281 parse_headers`, `:372 parse_chunk_size` | P | `test-http-chunk-framing-differential.sh` |
| `d2k_hr_headers` (inline) | 72–105 | 34 | разбор блока заголовков ответа | `:281 parse_headers` | P | — |
| `d2k_http_response_feed` (inline) | 107–160 | 54 | потоковый разбор ответа (status/CL/chunk/fin) | `http_response.rs:55 feed` | P | `hold.rs:1719/1947/2082` косвенно |
| `d2k_packet_u16` (inline) | 20–22 | 3 | big-endian u16 | `packet.rs:231 read_u16` | E | `packet.rs` тесты |
| `d2k_packet_parse` (inline) | 24–70 | 47 | разбор IPv4/IPv6, опции, ext-заголовки, L4 | `packet.rs:69 PacketView::parse` | E | `r2k-core/tests/network.rs:36+` |
| `d2k_key_equal` (inline) | 76–83 | 8 | равенство ключа | `#[derive(PartialEq)]` (`engine.rs:41`, `capture.rs:13`) | E | — |

