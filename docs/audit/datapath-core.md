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
| session.c | 3 | 96 | 8 |
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

## datapath/d2kd.c (44 функции)

Процесс-служба: CLI, NFQUEUE-цикл, raw/sched, hold, HTTP80, ICMP-guard, метрики.
R2O-владелец: `crates/r2o-datapath/src/main.rs` (`run`, `parse_options`,
`r2o_log_*`), `raw.rs`, `scheduler.rs`, `hold.rs`, `r2o_route.rs`.

**Прочитано построчно: 44/44 функции, 2415 строк C (1–2415).**

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
| `out_verdict` (static) | 432–435 | 4 | адаптер вердикта | `queue.send_verdict` | **E** | Тонкий адаптер. |
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
| `usage` (static) | 834–861 | 28 | текст помощи CLI | `main.rs:2952-2984 print_help` | **P** | **Точный состав C (`d2kd.c:834-861`):** `--queue` (обязательно), `--plan`, `--mode observe\|apply`, `--mark M`, `--probe-mark M`, `--only-mark M[/K]\|none`, `--udp-reverse-hook`, `--iface NAME`, `--flows N` (2048, отдельно TCP и UDP), `--queue-len N` (1024), `--copy-range N` (1600), `--sched-slots N` (128), `--journal N` (256), `--control PATH`, `--idle SEC` (120), `--log FILE`, `--stats SEC` (10), `--duration SEC`, `--no-fail-open`. В справке нет `--health-file` и `--version`, хотя парсер их знает. **R2O (`print_help`):** есть `--plan`, `--controller-only`, `--r2o-udp-reverse-visible\|--udp-reverse-hook`, `--queue`, `--idle`, `--r2o-flow-capacity\|--flows`, `--stats`, `--family`, `--mode`, `--mark`, `--iface`, `--probe-mark`, `--only-mark`, `--copy-range` (64..65535), `--queue-len`, `--journal`, `--rcvbuf`, `--control`, `--control-wire v22\|v48`, `--control-release-id`, `--no-fail-open`, `--check`, `--version`, `--help`. **Подтверждённые пробелы:** нет `--log`, `--health-file`, `--duration`, `--sched-slots`; добавлены `--family`, `--controller-only`, `--control-wire`, `--control-release-id`, `--rcvbuf`, `--check`, `--both` (не в help), `--r2o-flow-capacity`, `--r2o-udp-reverse-visible`. Текст и умолчания (`copy-range` 65535 против 1600) отличаются. |
| `arg_u32` (static) | 863–871 | 9 | строгий разбор u32 через `strtoul(v,&end,0)`: база 0 (десятичное/0x hex/ведущий 0 — восьмеричное), `*end==0`, `n<=0xffffffff` | `main.rs:2911-2923 parse_value`; `:2929-2937 parse_mark`; `:2939-2950 parse_only_mark` | **P** | **Подтверждённые расхождения синтаксиса:** C `strtoul(...,0)` принимает `0x10`, `010` (восьмеричное 8), ведущие пробелы и знак `+`/`-`; пустая строка даёт `end==v`, `*end=='\\0'`, `n=0` — **принимается как 0**. Rust `parse_value::<u32>` — строгий `FromStr`: только десятичное, без пробелов/знака/пустой строки; `parse_mark` дополнительно принимает только `0x`/`0X` hex, но не восьмеричное и не пробелы. Для `--mark/--probe-mark/--only-mark` C и Rust понимают hex, но расходятся на пустой строке, `010`, `+1`, ` 1`. Граничные тесты в Rust не выделены. |
| `port_of` (static) | 873–876 | 4 | big-endian u16: `b[0]<<8 \| b[1]` | `r2k-core/src/packet.rs:138-139` (`read_u16` TCP), `main.rs:2989-2990` (`u16::from_be_bytes` в журнале) | **E*** | **Точное совпадение:** C читает сетевой порядок как `(b[0]<<8)\|b[1]` (`d2kd.c:873-876`); Rust `read_u16`/`from_be_bytes` дают то же значение. Используется в `print_journal` (`1092-1093`) и разборе UDP-заголовка (`1776-1777,1804-1805`), в Rust — в `format_journal_key` и `PacketView::tcp_segment`/UDP-разборе. |
| `print_stats` (static) | 878–1030 | 153 | периодическая сводка: процесс, HTTP80, hold, владение приветствием, пакеты, ICMP, план applied/done/emitted/deferred/damaged/stale/sent_lost, TCP/UDP-потоки, приветствия/обмены/подозрения, reply hidden, sched, обрезано/без нагрузки/без заголовка, payload, keep-alive, снимки, lost/verdict/send/recv, NAT, routed, udp_marked, raw, follow, shape misses, plan count, причины | `main.rs:629-773` (`r2o_log_process_stats`, `r2o_log_queue_stats`, `r2o_log_flow_table_stats`, `r2o_log_scheduler_stats`, `r2o_log_session_stats`, `r2o_log_payload_stats`, `r2o_log_capture_stats`, `r2o_log_hold_stats`, `r2o_log_raw_stats`, `r2o_log_udp_follow_stats`), `r2o_icmp_guard.rs:153-161` | **P** | **Совпадает дословно/по полям:** процессор/RSS (`r2o_process_stats_line` — та же формула `cpu_ms/10/сек` и остаток), hold (`started/ready/released/timed_out/timed_out_packets/plan_changed/dropped_all/joined/mismatched/sided/full/pending`), пакеты/байты/принято/снято, ICMP, TCP/UDP-потоки и отказы, reply hidden, sched count/refusals, truncated/no_payload/no_header, payload (reverse/after_hello/late/not_hello/first_byte/sni_next_seg/HTTP keep-alive), снимки, lost, raw sent/errors/busy, UDP follow refused/busy/queue_full/route notifications. **Подтверждённые пробелы:** (1) нет HTTP80-строки (`requests/injections/evicted/untracked/unparsed/later`); (2) нет `hold_owned/hold_resent/hold_resend_fail`; (3) нет `applied/done/emitted/deferred/immediate/late/damaged/stale_deferred/sent_lost` — в R2O этих агрегатов нет; (4) нет `verdict_fail/recv_err` отдельными числами; (5) нет NAT `ok/miss/none/retry`; (6) нет `routed_flows` и `udp_marked_kept`; (7) `shape_misses` и `plan_count/capacity` в `NamePlans` есть (`control.rs:178-195`), но в сводку не выводятся; (8) нет гистограммы причин (`count_reason` — N). ICMP выводится отдельно только при `seen/noted != 0`. `test-datapath-stats-timer-differential.sh` покрывает таймер, не состав. |
| `proto_name` (static) | 1039–1045 | 7 | `6→tcp`, `17→udp`, иначе `?` | нет прямого аналога; `format_journal_key` (`main.rs:2986-3000`) печатает адреса/порты без имени протокола | **P** | C использует `proto_name` только в `print_journal` (`d2kd.c:1091`); Rust `format_journal_key` не выводит `tcp/udp/?`, а сразу пару адресов. Функция тривиальна, но текстовое представление журнала различается (см. `print_journal`). |
| `jrn_kind` (static) | 1050–1066 | 17 | коды журнала → тексты: HELLO_SNI «приветствие», HELLO_NONAME «приветствие без имени», PLAN_APPLIED «план применён», PLAN_REFUSED «план не применён», SUSPECT «подозрение», EXCHANGE «обмен пошёл», SHAPE «снята форма приветствия», PLAN_DONE `""`, PLAN_UNSENT «посылка не ушла», PLAN_DAMAGED «поток испорчен», default «запись неизвестного вида» | `flow_journal.rs:85-98 c_name`, `:100-123 russian_name` | **P** | **Совпадают:** `PLAN_APPLIED`, `PLAN_REFUSED`, `SUSPECT`, `EXCHANGE`, `SHAPE`, `PLAN_DONE` (пустая строка), `PLAN_UNSENT`, `PLAN_DAMAGED` — те же русские тексты (`flow_journal.rs:85-98`). **Подтверждённые расхождения:** (1) у C есть отдельный `D2K_JRN_HELLO_NONAME` → «приветствие без имени»; в Rust один `R2oFlowJournalKind::Hello` → «приветствие», имя с `name_len==0` печатается пустым, и вид не отличает отсутствие имени; (2) C default → «запись неизвестного вида», Rust `c_name` для R2O-only видов уходит в `russian_name` (например, «наблюдение», «подозрение голосового UDP-потока»), то есть неизвестного вида не бывает. `journal_note_texts_match_d2o` (`flow_journal.rs:1027`) проверяет тексты suspect/refuse, не `jrn_kind`. |
| `print_journal` (static) | 1070–1104 | 35 | один раз в конце: пусто → «журнал пуст»; шапка «--- журнал: N записей, затёрто D ---»; строка `%6llu мс  proto low:port - high:port  kind name: note` | `main.rs:1140-1173` (перебор `flow_journal.iter()` в ветке STOP), `:2986-3000 format_journal_key`, `:3006-3075 format_journal_details` | **P** | **Совпадает:** печать один раз при завершении, порядок от старых к новым, имя только при `name_len != 0`, пояснение только при непустом виде. **Подтверждённые отличия формата:** (1) C печатает время в **мс** от старта, Rust — `[{} нс]`; (2) C печатает `proto` (`tcp/udp/?`), Rust `format_journal_key` — сразу `client:port → server:port`, без протокола и в направлении клиент→сервер, а не канонической паре low-high через дефис; (3) C при пустом журнале печатает «журнал пуст», Rust не печатает ничего; (4) C печатает шапку с числом записей и `dropped`, Rust шапки нет; (5) C печатает `note` записи, Rust — `format_journal_details` по виду (план/попытка/исполнение, причина отказа, TTL и т.п.). D22 сверяет записи журнала, не текстовую печать. |
| `refuse_of_errno` (static) | 1114–1116 | 3 | `EMSGSIZE → D2K_REFUSE_TOO_LONG`, иначе `D2K_REFUSE_SEND` | `main.rs:3904-3950` (`r2o_first_oversized_emit` → `R2O_JOURNAL_REFUSE_TOO_LONG`), `:4024-4041` (raw send error → `R2O_JOURNAL_REFUSE_SEND`), `:3974-3987` (queue full → `REFUSE_QUEUE`) | **P** | **Подтверждённое отличие:** C классифицирует **фактический** `errno` от `send`/`sendto`: `EMSGSIZE` → «посылка длиннее способа отправки», всё остальное → «ядро отвергло посылку». Rust проверяет предел маршрута **до** отправки (`r2o_first_oversized_emit` → `TOO_LONG`), а любую ошибку `raw.send_packet` относит к `REFUSE_SEND` (`main.rs:4040`, `4148`, `4188`). Если `sendto` вернёт `EMSGSIZE` при неизвестном/устаревшем кэше MTU, C запишет `TOO_LONG`, Rust — `SEND`; `raw.rs:208-216` при этом лишь понижает кэш и повторяет, а окончательный код остаётся `SEND`. Отдельного differential на коды нет. |
| `offline_self_check` (static) | 1118–1123 | 6 | `--offline-self-check`: `D2K_CTL_PROTO_VERSION == D2K_RUNTIME_WIRE` и SHA-256("abc") равна эталону; иначе -1 | нет | **N** | C вызывает проверку через `d2k_runtime_offline(argc, argv, "d2kd", offline_self_check)` до разбора опций (`d2kd.c:1127-1128`); Rust `parse_options` такой опции не знает (`main.rs:2784-2873`), `--offline-self-check` завершится «неизвестный параметр». Ни SHA-256("abc"), ни сверки `PROTOCOL_VERSION` с `D2K_RUNTIME_WIRE` в датапате нет. |
| `main` | 1125–2415 | 1291 | CLI, план, raw, NFQUEUE, control, session, HTTP80, hold/release, route/cap, цикл, sweep, stats, shutdown | `main.rs:884-2707 run`, `:2754-2897 parse_options`, `:3775-3788 load_plan`, `:3081-3091 needs_raw_socket` | **P** | **Перенесено:** `--version` (свой бренд), NFQUEUE, raw (при `needs_raw_socket`), `--only-mark`/route-gate, rtnetlink-watch + опрос, adopt egress MTU, control + snapshot-сокет, name-plans, hold/UDP-hold/deferred verdicts/resends/follow, ICMP-guard, session/HTTP/voice/QUIC, sched, TCP-hold/release, delayed UDP, stats, signals, shutdown. **Подтверждённые отличия:** (1) нет `--health-file` — C пишет heartbeat `d2k_runtime_heartbeat(health_path,…)` **каждый проход цикла** (`d2kd.c:1477`), Rust health-файла не пишет; (2) нет `--log` — C делает `freopen(log_path,"a",stdout/stderr)` + `setvbuf(_IOLBF)` (`1236-1245`), Rust всегда stderr; (3) нет `--duration` — C выходит по `t-start >= duration_s` (`1483-1485`), Rust не имеет; (4) нет `--sched-slots` — C `d2k_sched_new(slots=128, raw_maxlen)` (`1347`), Rust `ScheduledQueue::default()` = 128 слотов, `slot_size=65536` (`scheduler.rs:9,84-85,440-444`), опция отсутствует; (5) `--copy-range`: C 64..`MAX_PKT=1600` (`1211-1214`), Rust 64..65535 (`2876-2878`); (6) C в apply **всегда** требует `--plan` или `--control` (`1215-1221`) и **всегда** `--mark != 0` (`1222-1230`); Rust `load_plan` в apply без `--plan` читает `/etc/r2o/plans/current.r2op` (`3775-3787`), а `needs_raw_socket` требует mark только для TCP/voice/спец-QUIC/control (`3081-3091`) — UDP-план без control может пойти с mark=0; (7) C читает план не более 64 КиБ (`1258-1265`), Rust `std::fs::read` без явного предела (`3783`); (8) C ставит `SO_TIMESTAMP` на NFQUEUE (`1313-1319`), в Rust `SO_TIMESTAMP` не найден; (9) C создаёт `d2k_session_new(flows, journal)` и `http80`, затем `ct_probe(sess,1)` (`1333-1341`); Rust ведёт отдельные таблицы и `R2oConntrackClient::open` + проверку `/proc/net/nf_conntrack` (`1043-1055`); (10) C зовёт `ct_probe(sess,0)` при каждом обновлении маршрутов (`1556`), Rust только переоткрывает conntrack, если его не было (`1376-1383`); (11) C опрашивает control-listen/peer в том же `poll` (`1523-1536,1561-1571`), Rust обрабатывает control после приёма очереди, из-за чего команда может ждать до 200 мс; (12) C раз в секунду шлёт `EVENT_STATS` с `dropped/sent` (`2329-2352`), Rust `EVENT_STATS` не отправляет (grep по датапату — только whitelist/tests); (13) C при завершении дренирует sched с `UINT64_MAX`, owned→`ECANCELED`, named pending→`exec_failed(QUEUE)`, считает `stale_deferred` (`2369-2388`); Rust в ветке STOP снимает pending-карты и hold, но `flush_scheduled` не вызывает (`1083-1174`), поэтому записи sched без записи в pending-картах могут не быть разобраны; (14) C печатает итоговый `print_stats` + `print_journal` (`2389-2391`), Rust — набор `r2o_log_*` и перебор журнала (`1140-1173`); (15) Rust добавил `--family`, `--controller-only`, `--control-wire`, `--control-release-id`, `--rcvbuf`, `--check`, `--both`, `--r2o-flow-capacity`, `--r2o-udp-reverse-visible`, которых у C нет. Проверки `probe-mark != mark` совпадают (`1231-1234` ↔ `2884-2886`). |

### Углублённая сверка d2kd.c (44 функции)

- **Сигналы/время/стоимость:** `on_signal` (62) ставит
  `volatile sig_atomic_t`; Rust — `install_signal_handlers` + `STOP`
  (`main.rs:55,3762`), P. `now_ns` (112–116) — `CLOCK_MONOTONIC` в нс,
  Rust `Instant`, P. `self_cost` (68–110) читает `/proc/self/stat` и
  `statm`; Rust `r2o_process_cost_from_proc`/`r2o_process_cost`
  (`main.rs:569,605`), P, differential `test-datapath-process-stats`.
- **MTU/маршруты:** `tls_route_segment_cap` (123–151) — MTU минус
  IP+32 только для TLS ClientHello (`0x16`, major 3); Rust
  `raw.rs:130`/`:119`, P. `routes_routed` (278–280) — метка выбирает
  политику; Rust `r2o_mark_is_routed` (`r2o_route.rs:175`), P.
  `describe_oifs` (282–294) — имена egress; Rust
  `r2o_egress_ifindices`, P. `routes_refresh` (302–370) — разбор
  `ip rule`/маршрутов, лог смен, quiet 600 с; Rust `r2o_refresh`
  (`r2o_route.rs:372`) по netlink-watch, quiet-окно не
  воспроизведено, P. `cap_refresh` (372–415) — adopt MTU → grow
  sched → greet; Rust `r2o_adopt_egress`/`grow_slot_size`/greet, P.
- **Подсчёт причин:** `count_reason` (165–186) — гистограмма до 32
  причин, печатается в сводке (1026–1028); в R2O аналога нет,
  причины уходят событиями/журналом. **N.**
- **ICMP:** `icmp_step` (220–248) — DROP только на свою фальшивку,
  иначе ACCEPT; Rust `r2o_icmp_guard.rs:127 r2o_handle_at_hook`,
  P + differential `test-icmp-guard-current-differential.sh`.
- **Логи отказов:** `log_send_fail` (253–261) — лимит 16 строк для
  busy; Rust `main.rs:186/192` eprintln без лимита, P.
  `out_resend_failed` (651–671) — одна строка на поток, лимит
  `D2K_UDP_REFUSED_LOG`; Rust `main.rs:287` без лимита/адресной
  строки, P.
- **Вердикты/отложенные:** `send_original_verdict` (417–427),
  `send_delayed_verdict` (429–431), `delayed_verdict_done` (433–446)
  — вердикт, счётчики accepted/dropped, complete→session_sent,
  иначе exec_failed; Rust `nfqueue.rs:310`, `main.rs:411/319`,
  P. `out_verdict`/`out_fail`/`out_marked`/`out_defer` (597–647) —
  вердикт, errno, метка клиента, отложенный вердикт; Rust
  `main.rs:4335`, `r2o_udp_hold.rs:291`, P.
- **Hold/release:** `hold_owns` (484–489) — TLS-hold владеет ID, не
  порт 80; Rust `hold.rs:298`/`batch_owned_originals`, P + D6.
  `resend_original`/`resend_originals` (493–516) — raw-возврат
  оригинала; Rust `r2o_resend_owned_originals`, P.
  `release_original` (518–542) — таймаут, закрытие UDP-hold,
  `note_unassembled`, observe, resend/ACCEPT; Rust `hold.rs:888`,
  `r2o_release_damaged_tcp_hold`, P + D6.
- **Conntrack:** `ct_query`/`ct_probe` (561–595) — ctnetlink GET и
  одноразовая проба; Rust `conntrack.rs:297/309`, P;
  `r2o-conntrack-ctget-differential.sh`.
- **Отправка:** `out_send_now` (673–684) — raw send; Rust
  `raw.rs:147`, P. `out_send_at`/`out_send_at_owned` (686–709) —
  отложенная отправка без/с владением ID; Rust
  `scheduler.rs:209/214`, P + D21. `refuse_of_errno` (1114–1116) —
  EMSGSIZE→TOO_LONG, иначе SEND; Rust проверяет предел до отправки,
  а ошибку `sendto` относит к SEND (`main.rs:3904-3950,4040`), P.
- **HTTP80:** `http80_log` (717–728) — текст «вставка провайдера»;
  Rust событие `send_http_portal_event`, P. `http80_io_payload`/
  `http80_io_accept`/`http80_io_rst` (733–768) — ACCEPT с заменой,
  ACCEPT, raw RST; Rust `nfqueue.rs:317/310`, `raw.rs:147`, E/P.
  `http80_cut` (776–784) — событие обрыва; Rust
  `hold.rs:255`/`main.rs:3148`, P. `http80_step` (786–829) —
  DROP/REPLACE/swap; Rust `main.rs:2006/2093` + `hold.rs`, P + D17.
- **CLI/вывод:** `usage` (834–861) — R2O не имеет
  `--log/--health-file/--duration/--sched-slots`, добавляет
  `--family/--check/--controller-only/--control-wire/--rcvbuf/
  --both` и др. `arg_u32` (863–871) — `strtoul(...,0)` принимает
  hex/восьмеричное/пробелы/пустую строку; Rust `parse_value`
  десятичный, `parse_mark` — десятичный/0x, P.
  `port_of` (873–876) — BE u16, Rust `read_u16`/`from_be_bytes`, E*.
  `print_stats` (878–1030) — R2O не печатает HTTP80, hold ownership,
  план applied/done/damaged/stale/sent_lost, NAT, routed, udp_marked,
  shape_misses, plan count, гистограмму причин; остальные группы
  совпадают. `proto_name` (1039–1045) — tcp/udp/?; Rust не печатает
  протокол. `jrn_kind` (1050–1066) — нет отдельного
  «приветствие без имени» и default «запись неизвестного вида».
  `print_journal` (1070–1104) — Rust печатает нс, `client→server`,
  без протокола/шапки/`note`.
- **Самопроверка:** `offline_self_check` (1118–1123) — SHA-256("abc")
  и версия провода; Rust-опции `--offline-self-check` нет. **N.**
- **`main` (1125–2415):** CLI, план, raw, NFQUEUE, control, session,
  http80, sched, signals, цикл. Нет `--log`/`--health-file`/
  `--duration`/`--sched-slots`; health-файл не пишется, остановки по
  времени нет, лог не переоткрывается; `SO_TIMESTAMP` на NFQUEUE не
  ставится. `EVENT_STATS` раз в секунду не отправляется; shutdown не
  дренирует sched так, как C. Остальные ветви (NFQUEUE, raw, control,
  hold/release, HTTP, ICMP, stats, route/cap) перенесены — P.

**Итог:** 44 функции; N — `count_reason`, `offline_self_check`
(диагностика/CLI), остальные P/E с подтверждёнными пробелами
CLI-логирования, health-файла, duration, состава сводки,
`EVENT_STATS` и shutdown-дренажа sched.

## datapath/session.c (107 функций)

Склейка датапата: таблицы TCP/UDP, разбор TLS/QUIC/STUN/voice, выбор плана,
сборка посылок, hold, детекторы молчания, учёт исполнения. R2O-владельцы:
`engine.rs` (TCP-сессия и решение), `main.rs` (UDP-путь и цикл),
`r2o_udp_sessions.rs`, `r2o_quic.rs`, `r2o_voice.rs`, `hold.rs`, `r2o_route.rs`.

**Прочитано построчно: 107/107 функций, 3642 строки C (1–3642).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `initial_dcid` (static) | 202–211 | 10 | DCID открытого Initial: `d2k_qw_hdr_parse`, long header, тип Initial, `dcid_len <= D2K_QW_CID_MAX` | `r2k-core/src/quic.rs:410-417 r2k_quic_initial_flight_id` | **P** | **Совпадает:** Rust `r2k_quic_initial_flight_id` разбирает Initial и возвращает `(version, dcid)`. **Подтверждённое отличие:** C извлекает DCID из структурно корректного Initial без проверки аутентификации (`d2k_qw_hdr_parse` + тип), Rust требует `is_authenticated_initial(input)` (`quic.rs:411`). Для настоящего Initial результат тот же; для подделки/мусора C может записать DCID, Rust — нет. Отдельного differential нет. |
| `init_ring_add` (static) | 215–236 | 22 | кольцо 32: дедуп по key+len+байтам, запись key/DCID/len/dg | `r2o_quic.rs:229-243` (`MAX_INITIAL_RING=32`) | **P** | **Совпадает:** дедуп по `key + bytes`, кольцо 32, вытеснение старого, запись DCID/version/байт. **Отличия:** (1) C хранит `dcid` без версии, Rust — `version + dcid`; (2) Rust при уже отправленном приветствии (`hello_reported`) удаляет записи потока и не добавляет датаграмму (`r2o_quic.rs:223-227`), C добавляет до `qsnap_done`; (3) C проверяет `len <= D2K_QW_MAX_DGRAM`, Rust — разбор Initial. Unit-тесты `:1041-1056`. |
| `init_ring_drop` (static) | 239–247 | 9 | забыть датаграммы потока (обнулить записи) | `r2o_quic.rs:225,263` (`retain`) | **E*** | C обнуляет `len/dcid_len/key` у совпавших записей, Rust удаляет их `retain`; для последующего `pack` оба варианта эквивалентны (нулевые записи пропускаются). |
| `init_ring_pack` (static) | 253–283 | 31 | собрать полёт по key+DCID от самой старой записи, до `D2K_QSNAP_MAX_DGRAMS`, `d2k_qsnap_pack` | `r2o_quic.rs:245-260` | **P** | **Подтверждённое отличие порядка отбора:** C идёт по кольцу от `init_ring_next - init_ring_n` (старые→новые) и берёт **первые** `MAX_DGRAMS`; Rust фильтрует `key+version+dcid`, затем `matching.len().saturating_sub(MAX_INITIAL_DATAGRAMS)` берёт **последние** N (`r2o_quic.rs:249-255`). При числе датаграмм больше предела наборы различаются. C дополнительно требует совпадения DCID, Rust — DCID и version. |
| `slot_of` (static) | 288 | 1 | слот снимка: UDP=1, иначе TCP=0 | `r2o_udp_sessions.rs`/`r2o_quic.rs` (снимок в потоке) | **P** | C держит четыре глобальных слота `last_hello[4]`; Rust хранит снимок в `QuicHello`/`ClientShapeEvent` и ключе потока, без глобального индекса. Поведение «TCP и UDP не делят снимок» сохраняется, структура иная. |
| `shape_slot` (static) | 289–291 | 3 | индекс слота: `slot_of + (family==6 ? 2 : 0)` | ключ потока включает family (`r2o_quic.rs`/`r2o_udp_sessions.rs`) | **P** | C вычисляет глобальный индекс 0..3; Rust не имеет массива слотов, family входит в ключ `FlowKey`/`R2oUdpFlowKey`. Эквивалентно по различимости TCP/UDP и 4/6, не по API. |
| `next_fragment_id` (static) | 293–304 | 12 | seed из `/dev/urandom` на сессию, затем `++`, пропуск нуля | `r2k-core/src/wire.rs:334-337` | **P** | **Подтверждённое отличие:** C сеет **один** `fragment_id` на сессию из `/dev/urandom` и инкрементирует его, пропуская нулевое 16-битное значение (`session.c:293-304`). Rust `wire.rs:334-337` берёт `getrandom` **на каждую сборку** фрагментов, `max(1)`; сессионного счётчика нет. Оба дают ненулевой ID, но последовательность и момент отказа (`urandom` недоступен → C 0, Rust `None`) различаются. |
| `d2k_session_new` | 306–344 | 39 | `calloc`, hook=UNKNOWN, бюджет 25, `flows`/`uflows` по capacity, `plans` по capacity таблицы, journal | `main.rs:884 run` (`TcpSessions`, `R2oUdpSessions`, `NamePlans`, `R2oFlowJournal`) | **P** | **Совпадает:** отдельные таблицы TCP/UDP с одинаковой ёмкостью, журнал, бюджет по умолчанию 25 (`engine.rs:451-460`). **Отличия:** C хранит `hook`, `route_mark`, `fragment_id`, `rev_seen`, `shape_*` в сессии; Rust передаёт hook/route_mark на пакет, а снимки/visible-флаги живут в `QuicSessions`/`TcpSessions`/`R2oUdpSessions`. C `plans` ёмкость выводит из `d2k_track_capacity(flows)`, Rust `NamePlans` — из `--r2o-flow-capacity`. OOM-ветка C (`plans==NULL`) в Rust — `Result` при создании таблиц. |
| `d2k_session_free` | 346–356 | 11 | освободить plans/journal/uflows/flows/plan/session | `Drop` (Rust RAII) | **E** | C вручную освобождает пять владений; Rust `TcpSessions`/`R2oUdpSessions`/`NamePlans`/`R2oFlowJournal`/`Plan` освобождаются `Drop`. Для непустой сессии эквивалентно; OOM-ветка C (`plans==NULL`) в Rust — `Result` при создании. |
| `d2k_session_set_plan` | 358–365 | 8 | освободить прежний запасной план, сохранить новый, `plan_revision++` | `main.rs` `plan`/`NamePlans` revision | **P** | C владеет `d2k_plan*` и освобождает старый; Rust хранит `Plan` значением/в `Arc`-подобной структуре, ревизия `NamePlans` растёт на каждое изменение таблицы/плана. Смысл «смена плана видна hold/sched» сохранён, но счётчик C складывает ревизию запасного плана и таблицы (`d2k_session_plan_revision`), Rust — одна. |
| `name_same` (static) | 369–382 | 14 | равная длина, ASCII A-Z→a-z, без нормализации точки | `r2k-core/src/httpup.rs:468-472 same_host` | **P** | **Подтверждённое расхождение:** C сравнивает ровно `alen==blen` и байты без учёта регистра, **не снимая** хвостовую точку и не требуя непустого имени (`session.c:369-382`). Rust `same_host` снимает по одной хвостовой `.` с обеих сторон и требует `!left.is_empty()` (`httpup.rs:469-471`). Для `example.com.` и `example.com` C вернёт 0, Rust 1; для пустого имени C может вернуть 1 при обоих пустых, Rust — 0. Используется в `last_hello`/`shape`; для SNI с точкой поведение различается. |
| `rd16` (static) | 384–386 | 3 | big-endian u16 | `r2k-core/src/packet.rs:231 read_u16` | **E*** | C `(p[0]<<8)\|p[1]`; Rust `read_u16` с `get`-проверкой границ. Используется в TCP/UDP-разборе; `tests/network.rs` покрывает. |
| `refuse_coded` (static) | 402–413 | 12 | отказ плана в журнал; зонд молчит только при `code==NONE`; trial/plan id | `flow_journal.rs:684-720 record_plan_refused`, `main.rs:3737-3760 send_refused_event` | **P** | **Подтверждённое отличие:** C находит поток по ключу и при `controller_probe && code==D2K_REFUSE_NONE` **не пишет** запись (`session.c:404-406`); Rust `record_plan_refused` не знает о probe и принимает только `NOT_APPLIED/FLOW_UNFIT`, а `send_refused_event` всегда пишет журнал и отправляет событие. Для `code==NONE` C пишет запись (кроме probe), Rust `record_plan_refused` её отвергает; отказ NONE идёт только событием. D22 покрывает основные коды, не это условие. |
| `refuse` (static) | 415–418 | 4 | `refuse_coded(..., NONE, NULL)` | `main.rs:3737 send_refused_event` (событие), `flow_journal.rs:684 record_plan_refused` | **P*** | C-обёртка передаёт `code=NONE`, без плана/trial. Rust отправляет `EVENT_REFUSED` и пишет журнал только для `NOT_APPLIED/FLOW_UNFIT`; отказ `NONE` в журнал не попадает (см. `refuse_coded`). |
| `tcp_options_timestamp_profile` (static) | 422–433 | 12 | профиль TCP-опций: UNKNOWN/NO_TS/TS; EOL, NOP, длина 2..n, TS len=10 | `r2k-core/src/packet.rs:39-64` | **E** | **Точное совпадение:** C `kind==0` → break, `kind==1` → off++, длина `<2`/`>n-off` → UNKNOWN, `kind==8 && len==10` → TS, иначе NO_TS (`session.c:422-433`); Rust `tcp_options_timestamp_profile` те же ветви (`packet.rs:39-64`). Unit-тесты packet/tcp. |
| `tcp_options_have_timestamp` (static) | 435–437 | 3 | профиль == TS | `packet.rs:39` + сравнение с `TCP_PROFILE_TS` | **E*** | C-обёртка `tcp_options_timestamp_profile(o,n)==D2K_TCP_PROFILE_TS`; Rust сравнивает результат с `TCP_PROFILE_TS`. Используется в `D2K_FLOW_NEED_TCPTS`; тесты опций косвенные. |
| `plan_handed_off` (static) | 446–473 | 28 | applied/key/plan/trial/binding; `orig_taken`; `sends_left=n_out+1`; execution id | `engine.rs:588-603 r2o_begin_execution`, `main.rs:411 R2oTcpExecution`, `PendingApplied` | **P** | **Совпадает:** Rust фиксирует `execution_id`, ключ, план/trial/binding, `payload_on_wire/original_spent/original_taken`, а завершение ждёт опустошения `ScheduledQueue` по ticket. **Подтверждённые отличия:** C ведёт **числовые** `sends_left = n_out+1`, `sends_done`, `sends_failed`, `udp_replan` на потоке и `sent_lost`; Rust использует булевы `TransmissionOutcome.r2o_sends_done`/`payload_on_wire` и `PendingApplied`, числовых счётчиков и `sent_lost` нет. C `orig_taken = verdict==DROP`; Rust `fate == OriginalFate::Drop`. |
| `table_of` (static) | 477–479 | 3 | `proto==17 → uflows`, иначе `flows` | `TcpSessions`/`R2oUdpSessions` (разные типы) | **P** | C выбирает таблицу по `k->proto`; Rust держит TCP и UDP в разных структурах и выбирает по типу пакета/потока. Для ключа `proto 17` эквивалентно, API иной. |
| `suspect_num` (static) | 486–503 | 18 | не чаще раза на поток: `controller_probe`/`suspected` → выход; `suspects++`, journal SUSPECT с planned/client_shape | `engine.rs` tcp_*_events, `r2o_quic.rs:478`, `flow_journal.rs` | **P** | **Совпадает:** C и Rust не повторяют подозрение на потоке (`fl->suspected`/`flow.suspected`, `silence_reported` и т.п.), пишут событие/журнал с `planned` и формой клиента. **Отличия:** C ведёт агрегат `s->suspects++`; в Rust отдельного агрегата нет (счётчики событий/журнала). C единая функция для TCP/UDP, Rust — отдельные `tcp_*_event`, `r2o_quic`/`r2o_voice`; набор полей журнала (`tos/server_hello/ttl/ref_ttl/ipid`) распределён по событиям. |
| `suspect` (static) | 505–508 | 4 | `suspect_num(...,0)` | `engine.rs` tcp_*_events, `r2o_quic.rs:478` | **P*** | C-обёртка без `num`; Rust события не имеют числового `num` (кроме stall), поэтому передача `0` эквивалентна. |
| `on_flow_expire` (static) | 521–530 | 10 | при истечении: `capture_forget` + повторный `track_find` + `tcp_silence_observe` | `engine.rs:698-760 expire_with_silent` | **P** | **Совпадает:** Rust `expire_with_silent` вызывает `tcp_silence_event`/замыкание до удаления и забывает capture. **Отличие:** C повторно ищет живой `d2k_flow`, чтобы выставить `silence_told` до `track_expire`; Rust хранит `silence_reported` в `TcpSession` и удаляет запись после события. Callback заменён замыканием; порядок эквивалентен. |
| `rd32` (static) | 532–535 | 4 | big-endian u32 | `r2k-core/src/packet.rs:236 read_u32` | **E*** | C `p[0]<<24\|p[1]<<16\|p[2]<<8\|p[3]`; Rust `read_u32` с проверкой границ. Используется в seq/ack; `tests/network.rs`. |
| `is_discord_ip_discovery` (static) | 544–550 | 7 | ровно 74 байта, `[0,1,0,70]`, нули 8..71 | `r2k-core/src/stun.rs:82-86` | **E** | **Точное совпадение:** C `n==74 && d[0..4]=={0,1,0,70}` и все `d[8..72]==0` (`session.c:544-550`); Rust `is_discord_ip_discovery_request` те же проверки (`stun.rs:82-86`). |
| `is_discord_ip_discovery_response` (static) | 552–564 | 13 | 74 байта, `[0,2,0,70]`, тот же SSRC, адрес только `0-9.:`, порт != 0 | `r2k-core/src/stun.rs:89-107` | **P** | **Подтверждённое отличие строгости:** C принимает любую непустую последовательность цифр/`.`/`:` в 8..71 и требует ненулевой порт (`session.c:552-564`); Rust требует первый NUL в 8..72, непустой префикс и успешный `Ipv4Addr::parse` (`stun.rs:97-106`), поэтому IPv6-подобный `::` и мусорные `:` C принимает, Rust — нет. Порт проверяется одинаково. Voice-proof тесты частичные. |
| `is_stun_binding` (static) | 569–578 | 10 | n>=20, top bits 0, length%4, 20+len<=n, magic cookie, type | `r2k-core/src/stun.rs:116-131` | **E** | **Точное совпадение:** C и Rust проверяют те же поля/границы (`session.c:569-578`, `stun.rs:116-131`). |
| `is_stun_request` (static) | 580–582 | 3 | Binding Request 0x0001 | `stun.rs:71-73 is_binding_request` | **E*** | C-обёртка `is_stun_binding(...,0x0001)`; Rust `is_binding_request` → `is_binding(...,BINDING_REQUEST)`. |
| `is_stun_response_for` (static) | 584–588 | 5 | Binding Success 0x0101 + txid | `stun.rs:76-78` | **E** | C `is_stun_binding(...,0x0101) && memcmp(d+8,txid,12)==0`; Rust `is_binding(packet, BINDING_RESPONSE) && packet[8..20]==txid` (`stun.rs:76-78`). |
| `d2k_session_nat_stats` | 650–656 | 7 | глобальные NAT ok/miss/none/retry | нет аналога | **N** | C ведёт `g_nat_ok/miss/none/retried` в `flow_tracked` и отдаёт их в `print_stats`. Rust `R2oConntrackGate` кеширует подтверждение, но счётчиков NAT не ведёт; строки `поток ведётся conntrack` в сводке нет. |
| `plan_fits_transport` (static) | 672–676 | 5 | `!p → 1`; transport 0 или совпал с proto | выбор плана в `engine.rs`/`main.rs` (`plan.transport`) | **P** | C явно пропускает план с `transport==0` и отвергает чужой (`session.c:672-676`). Rust `name_plans`/`decide_with_session` проверяет транспорт при выборе/применении; отдельной функции нет. Для планов R2O с явным transport эквивалентно; «дедушкино» 0 обрабатывается иначе (по контексту плана). |
| `flow_tracked` (static) | 678–777 | 100 | conntrack: первый пакет — не читать; SYN-ACK — доказано; до 3 попыток procfs; nat_state 0/1/3, g_nat_* | `r2o_conntrack_gate.rs:55-93 confirm`, `:115-175 guard_decision`, `proc_nat.rs:20 lookup` | **P** | **Совпадает:** первый пакет не читает таблицу; TCP SYN-ACK считается доказательством; три попытки `lookup`; «таблицы нет» — отдельное состояние; первый пакет при промахе пропускается. **Подтверждённые отличия:** (1) C ведёт глобальные `g_nat_ok/miss/none/retried` и `nat_state` на потоке; Rust кеширует `Tracked/NoConntrackTable` в `R2oConntrackGate`, счётчиков NAT нет (N `d2k_session_nat_stats`); (2) C вызывает `flow_tracked` **до** применения плана и при `-1` отказывает целиком; Rust `guard_decision` вызывается после решения и для UDP-фрагментов дополнительно переписывает адреса; (3) C `first_packet` для TCP всегда 0, Rust передаёт `first_udp_packet` только в UDP-ветке, TCP — `false`; (4) C при `rc>0` ставит `nat_state=3` навсегда, Rust кеширует `NoConntrackTable` с idle 120 с. |
| `handle_udp` (static) | 779–1569 | 791 | весь UDP-путь: направление по hook/flow/443, серверные счётчики/voice/STUN, окно 8, hold, QUIC-сборка/снимок/ECH, addr/voice/name/fallback планы, `plan_fits_transport`, запрет разреза, conntrack/NAT фрагментов, сборка до 16 посылок, APPLIED | `main.rs:1543-2604` (UDP-путь), `r2o_udp_sessions.rs`, `r2o_quic.rs`, `r2o_voice.rs`, `r2o_conntrack_gate.rs` | **P** | **Совпадает по крупным ветвям:** направление из OUT/POST vs IN/PRE с fallback на известное направление и порт 443; серверная сторона учитывается, voice/STUN-доказательства и UDP EXCHANGE; окно 8; `saw_hello`/`saw_initial`; запрет повторного плана; `quic_deny`; выбор addr/voice/name/fallback; `plan_fits_transport`; запрет нескольких payload-посылок; conntrack/NAT; лимит 16; APPLIED. **Подтверждённые отличия:** (1) C хранит `saw_initial` и `rev_after_hello` в `d2k_flow`; Rust `r2o_udp_sessions` имеет `hello_seen`, но отдельного состояния «Initial без имени» не найдено — молчание по такому потоку может не наблюдаться; (2) C добавляет датаграмму в `init_ring` всегда до `qsnap_done`; Rust — только до первого отправленного приветствия (`hello_reported`), после чего кольцо чистится; (3) C снимок `last_hello/last_name` глобальный на слот, Rust `QuicHello { key, host, snapshot }`; (4) C `find_addr_probe`/`find_voice_probe`/`find_target`/`s->plan` и `refuse` при отсутствии; Rust `select_with_quic_host_at_hook` + fallback `plan`, `qdeny`; (5) C `payload_emits > 1` отвергает план для UDP, Rust проверка в `engine`/`wire` иная; (6) C при `acts.fate==HOLD` отказывает, Rust `Transmit`/fate; (7) C `out->quic_name/quic_shape_miss` для лога, Rust — события. Полного C/Rust differential на все ветви нет; `r2o-udp-exchange-differential.sh`, voice/quic differentials частичные. |
| `note_tcp_hello` (static) | 1573–1580 | 8 | `!controller_probe` → `tcp_hello_flows++`; `hello_ack=rd32(tcp+8)`, `hello_ack_valid=ack` | `engine.rs:1044-1049`, `r2o_tcp_hello_flows` | **P** | **Совпадает:** инкремент только для не-зонда; Rust `hello_ack: Option<u32>` заменяет пару `hello_ack/hello_ack_valid`; счётчик `r2o_tcp_hello_flows`. Тесты `engine.rs:2548/2565/2608`; C/Rust differential нет. |
| `routed_flow` (static) | 1593–1626 | 34 | TCP/UDP не фрагмент: route_mark → `track_get`, `routed=1`, `routed_flows++`, first/mark; без метки — найти routed, новый SYN снимает флаг | `r2o_route.rs:596-665 R2oRoutedFlows::r2o_skip_packet`, `:666-678 r2o_is_new_syn` | **P** | **Совпадает:** метка → поток помечается routed и идёт ядром; ответ без метки наследует флаг; новый SYN без метки снимает routed. Rust `r2o_skip_packet` дополнительно вставляет reverse-ключ и чистит по idle/ёмкости; C счётчик `s->routed_flows`, Rust — `R2oRoutedFlows` + лог. `r2o-route-gate-differential.sh`. |
| `session_packet` (static) | 1628–2601 | 974 | TCP-путь: IP/TCP-заголовки, направление SYN/SYN-ACK/первый, capture, rev-профиль/TLS-ответ, reply_hidden, EXCHANGE, alien-RST, FIN, HTTP keep-alive, TLS-форма (ECH/truncated), план, conntrack, сборка, APPLIED | `engine.rs:1403-1439 decide_with_session*`, `:1849 decide_tcp`, `capture.rs`, `httpup.rs`, `hold.rs` | **P** | **Совпадает по крупным ветвям:** разбор заголовков, направление по SYN/SYN-ACK с fallback, счётчики forward/reverse, профиль TTL/TOS первого ответа, `rev_server_hello`/`rev_types`/`rev_payload_after_hello`, reply_hidden, EXCHANGE, alien-RST guard с `RST_CUT`/`RST_AFTER_APP`, FIN-ожидание, HTTP-разбор/keep-alive, TLS-форма MODERN/LEGACY/ECH, выбор плана по имени/адресу/HTTP, отказ при отсутствии/чужом транспорте, `D2K_FLOW_NEED_TCPTS`, сборка и APPLIED. **Подтверждённые отличия:** (1) C при `tls.is_tls13 && !ech && exts_truncated` и наличии ECH-цели оставляет форму ANY (`session.c:2325-2334`); Rust `r2o_client_shape_from_legacy` сводит к MODERN/LEGACY/ECH без проверки ECH-таблицы (`main.rs:9356-9393`) — план может не найтись/примениться иначе; (2) C хранит `rev_first_type/rev_types/rev_server_hello` и отдаёт в журнал; Rust события `R2oTcpExchangeEvent`; (3) C `pending_fin` и окно FIN; Rust `pending_fin`/`fin_retry_window`; (4) C `http_skip` тексты и keep-alive `http_next`; Rust `httpup`/`hold`; (5) C `plan_done` запрещает повтор кроме HTTP; Rust `NamePlans`/session; (6) C `d2k_plan_apply` и `d2k_wire_build`; Rust engine `transmit_many`; (7) C `sends_left` числовой, Rust `ScheduledQueue`/PendingApplied. Полного differential на все ветви нет. |
| `d2k_session_packet` | 2603–2606 | 4 | публичный вход: `observe_only=0, probe=0, mtu=0` | `engine.rs:1403-1410 decide_with_session` | **E*** | Обёртка C и Rust передают те же флаги (`observe=false`, `controller_probe=false`, без MTU); вся логика в `session_packet`/`decide_with_session`. |
| `d2k_session_packet_mtu` | 2608–2613 | 6 | вход с `tcp_segment_cap` | `engine.rs:1421-1429 decide_with_session_mtu` | **E*** | C передаёт `tcp_segment_cap` в `session_packet`; Rust `decide_with_session_mtu` — в `transmit_many`/wire. `test-tcp-shape-context-differential.sh`. |
| `d2k_session_packet_probe` | 2615–2619 | 5 | вход зонда (`probe=1`) | `engine.rs:1412-1419 decide_with_session_probe` | **E*** | C `controller_probe=1`; Rust `decide_with_session_probe`. Проба исключается из пользовательских счётчиков; `test-datapath-controller-probe-capture-differential.sh`. |
| `d2k_session_packet_probe_mtu` | 2621–2626 | 6 | зонд + `tcp_segment_cap` | `engine.rs:1431-1439 decide_with_session_probe_mtu` | **E*** | Комбинация флагов совпадает; отдельного differential нет. |
| `d2k_session_observe_tcp` | 2628–2631 | 4 | только наблюдение, без вердикта (`observe_only=1`) | `main.rs` observe-mode `decide_with_session` | **P** | C вызывает `session_packet(..., observe_only=1, probe=0, mtu=0)` и игнорирует результат. Rust в observe-режиме вызывает `decide_with_session` с `observe_plan` и не отправляет; `observe_only` как отдельный флаг отсутствует. Наблюдаемые счётчики/события совпадают, но ветки capture/hold могут различаться. |
| `d2k_session_plan_revision` | 2633–2635 | 3 | `plan_revision + d2k_plantab_revision(plans)` | `control.rs` `NamePlans.revision` | **P** | **Подтверждённое отличие:** C складывает ревизию запасного плана и таблицы (`session.c:2634`). Rust ведёт **один** счётчик `NamePlans.revision`, растущий на любые изменения; отдельной ревизии запасного `Plan` нет. Для обнаружения изменений эквивалентно, для точного числа — нет. |
| `d2k_session_stream_anchor` | 2637–2645 | 9 | hold_parse → поток с `saw_syn`; `http_flow && http_conn ? http_next : syn_seq+1` | `hold.rs:969 remember_syn`, `main.rs` capture anchor | **P** | **Совпадает по смыслу:** Rust хранит anchor по SYN в hold-слоте и использует `syn_seq+1`; HTTP keep-alive anchor ведётся `httpup`/`http_next`. **Отличия:** C функция единая, возвращает `http_next` при `http_flow && http_conn`, Rust — отдельные `capture_anchor`/`note_http_execution`; проверка `saw_syn` и приоритет HTTP не вынесены в один API. D6. |
| `d2k_session_set_hook` | 2647–2649 | 3 | hook текущего пакета (`D2K_HOOK_UNKNOWN` по умолчанию) | `main.rs` `queue_hook` (параметр на пакет) | **P** | C хранит hook в сессии и сбрасывает/ставит на каждый пакет; Rust передаёт `queue_hook` параметром в `r2o_udp_hold_candidate`/`r2o_udp_packet_direction`/engine. Семантика «текущий пакет» та же, состояние не хранится. |
| `d2k_session_set_route_mark` | 2651–2653 | 3 | метка маршрутизации текущего пакета | `main.rs` route gate/`options.probe_mark` | **P** | C хранит `route_mark` в сессии; Rust вычисляет `route_gate` на пакет и передаёт в `r2o_packet_route_skip`/UDP hold. Для `route_mark==0` и ненулевой метки эквивалентно. |
| `d2k_session_route_mark` | 2655–2657 | 3 | чтение метки текущего пакета | `main.rs` route gate | **P** | C getter поля; Rust не хранит метку в сессии, а использует локальную `route_gate`/`umark`. Эквивалент для текущего пакета отсутствует как API. |
| `d2k_session_routed_flows` | 2659–2661 | 3 | счётчик routed-потоков | `r2o_route.rs:580 R2oRoutedFlows` | **P** | C `s->routed_flows++`; Rust `R2oRoutedFlows` хранит map потоков, отдельного счётчика/геттера не найдено. В сводке C печатает число, Rust — нет. |
| `d2k_session_set_udp_reverse_hook` | 2663–2665 | 3 | «обратное UDP видно» | `main.rs` `reverse_queue_visible` | **P** | C хранит флаг в сессии и использует в `sweep_udp_one`; Rust `options.reverse_queue_visible` + `ControlServer::is_connected`, передаётся в `sweep`. Смысл тот же, поле/условие иное. |
| `d2k_session_set_ct_query` | 2667–2669 | 3 | включить ctnetlink-запросы | `conntrack.rs:264 R2oConntrackClient` (`Option`) | **P** | C инъектирует `ct_query`/`ctx`; Rust `conntrack: Option<R2oConntrackClient>` создаётся в `run`, `None` при недоступности. Эквивалентно по включению/выключению, API иной. |
| `d2k_session_udp_hold_begin` | 2671–2711 | 41 | route_mark=0, UDP не фрагмент, hook client/server, 443 fallback, QUIC Initial, поток не plan_done/damaged/saw_hello/routed, fwd_pkts<8 | `r2o_udp_hold.rs:19-47 r2o_udp_hold_candidate`, `r2o_udp_sessions.rs:410-424 r2o_begin_hold` | **P** | **Совпадает:** только клиентский Initial (OUT/POST или порт 443 fallback), не фрагмент, окно 8, запрет после плана/приветствия. **Подтверждённые отличия:** C проверяет `route_mark==0`, `fl->damaged`, `fl->routed` в этой функции; Rust `r2o_udp_hold_candidate` их не проверяет (route gate выполняется раньше, `damaged` — в `r2o_begin_hold` отсутствует), а `r2o_begin_hold` добавляет `hold_attempts`/`client_packets` и `r2o_mark_hello_seen`. C `saw_initial` не входит в запрет, Rust `hello_seen` входит. |
| `d2k_session_udp_opening` | 2713–2736 | 24 | первый клиентский пакет: `fwd_pkts==1`, hook OUT/POST→клиент, IN/PRE→сервер, иначе flow, иначе 443 | `r2o_udp_sessions.rs:361-371 r2o_udp_opening` | **P** | **Совпадает:** проверка «ровно один клиентский пакет» и направление. **Отличие:** Rust `r2o_udp_opening` вызывает `r2o_udp_packet_direction(packet, key, None, known)` — **без текущего hook**, поэтому для первого пакета неизвестного потока остаётся только сохранённое направление/порт 443; C использует hook. При известном направлении результат совпадает. |
| `d2k_session_udp_hold_end` | 2738–2742 | 5 | закрыть транзакцию hold (`udp_hold_active=0`) | `r2o_udp_sessions.rs` hold state + `main.rs` release | **P** | C снимает флаг на потоке после сборки/отказа. Rust `r2o_begin_hold`/`hold_attempts` и `r2o_mark_hello_seen`; отдельного `hold_end` нет — состояние снимается release/hello. Эквивалент по смыслу, не по API. |
| `d2k_session_udp_hold_replay` | 2744–2751 | 8 | `udp_hold_active=0`, `udp_hold_replay_first=1` | `r2o_udp_sessions.rs:337-343 r2o_mark_hold_replay_first` | **P** | C после сборки снимает active и помечает первую датаграмму к повтору. Rust `r2o_mark_hold_replay_first` ставит `hold_replay_first=true`; `hold_active` как отдельное поле отсутствует, повтор выбирается `r2o_udp_opening`/`replay_first`. Unit `:640`. |
| `d2k_session_note_unassembled` | 2753–2784 | 32 | «составное приветствие не собралось» один раз на поток + HTTP-ветка (порт 80, нет hello, начало запроса), лог declared/payload | `hold.rs:235 r2o_take_incomplete_diagnostics`, `main.rs:544` | **P** | **Совпадает:** диагностика один раз на поток, HTTP-ветка снимает `http_checked/http_conn` и пишет отказ. **Отличия:** C печатает `d2kd: составное приветствие отпущено без сборки: объявлено N байт…`; Rust `r2o_take_incomplete_diagnostics` формирует события/строки иначе, точный текст/числа не сверены. `hold.rs:2249` покрывает TLS-таймаут. |
| `d2k_session_hold_candidate` | 2794–2924 | 131 | право начать TCP-hold: route_mark=0, hold_parse, payload, флаги ACK/PSH, saw_syn, dir_known, init_low, не damaged/routed; HTTP-кандидат; окно 16 КБ; голова 0x16; SNI/ECH/stream-план | `hold.rs:298 feed`, `:356 feed_observing_mode`, `HoldOptions.allow_tls/allow_http` | **P** | **Совпадает по крупным условиям:** только поток с наблюдённым SYN и известным направлением; не damaged/routed; окно 16 КБ; голова должна начинаться с 0x16; полная запись не удерживается; HTTP-кандидат только при порте 80 и правдоподобном начале; `stream_attempted`/`http_checked`; ECH-цель удерживается для хвоста. **Подтверждённые отличия:** (1) C проверяет `(v.flags & ~0x18)` и обязательный ACK (`session.c:2796-2797`); Rust `hold.rs` использует `TcpSegmentView` и `HoldOptions`, набор флагов иной; (2) C `d2k_plantab_http_candidate`/`stream_candidate_target` и `d2k_plan_stream_input(s->plan)`; Rust `NamePlans`/`hold` выбирает кандидатов иначе; (3) C `at_head` требует первый байт 22 и неполную запись, Rust — capture/TLS-условия; (4) C при SNI+truncated+ECH-цель возвращает 1 до проверки `is_tls13`; Rust ECH-ожидание в `hold` иное. D6 покрывает базовые сценарии. |
| `d2k_session_want_shape` | 2926–2929 | 4 | запрос снимка формы TCP (family=4) | `main.rs:20162 r2o_capture_client_shape`, `control.rs:1988` | **P** | C-обёртка `want_shape_family(...,4)`; Rust `arm_client_shape`/`r2o_capture_client_shape` принимает family. Механизм иной: R2O отдаёт снимок событием `CLIENT_SHAPE`, без отложенного `shape_armed` на 4 слота. |
| `d2k_session_want_shape_family` | 2931–2960 | 30 | валидация family 4/6, transport 6/17, имени; если `last_hello` есть и имя совпало (len=0 — любой) — копировать hello+**все TCP-опции**, снять armed; иначе armed=1, сохранить имя | `main.rs:20162-20192 r2o_capture_client_shape`, `control.rs:1988 ClientShapeEvent`, `arm_client_shape` | **P** | **Совпадает:** немедленная выдача последнего снимка при совпадении имени, иначе взведение ожидания; ограничение длины имени 256. **Подтверждённые отличия:** (1) C копирует `shape_opts` (полный набор TCP-опций, 40 байт); Rust `ClientShapeEvent` несёт только `tcp_has_timestamp: Option<bool>` — полного набора нет (`d2k_session_shape_tcp_options_family` — N); (2) C `shape_armed`/`shape_name` на 4 слота; Rust `last_client_shapes`/`arm_client_shape`; (3) C при `len=0` принимает любой last_hello; Rust arm по имени/семейству. |
| `d2k_session_shape` | 2962–2964 | 3 | снимок формы TCP (family=4) | `capture.rs:170 tcp_hello_from_packet`, `r2o_quic.rs:180 capture_hello` | **P** | C-обёртка `shape_family(...,4)`; Rust снимок берётся из capture/`ClientShapeEvent`, не из сессионного буфера `shape[4]`. Для TCP/4 результат тот же при наличии снимка. |
| `d2k_session_shape_family` | 2966–2980 | 15 | вернуть `shape[k]`/длину по transport/family | `capture.rs:170`, `r2o_quic.rs:180`, `control.rs ClientShapeEvent` | **P** | **Совпадает:** C отдаёт сохранённый снимок, если `shape_len!=0`; Rust — ClientHello из `ClientShapeEvent`/кэша. **Отличие:** C снимок в сессии на 4 слота; Rust — по потоку/событию, полный набор TCP-опций не хранится. |
| `d2k_session_shape_tcp_options_family` | 2982–2990 | 9 | вернуть полный набор TCP-опций слота формы (до 40 байт) | `control.rs ClientShapeEvent.tcp_has_timestamp` (только bool) | **N** | **Подтверждённый пробел:** C хранит `shape_opts[4][40]`/`shape_opts_len` и отдаёт произвольные TCP-опции клиента (MD5, порядок TS, NOP и т.п.). Rust `ClientShapeEvent`/`HelloEvent` передаёт только `Option<bool>` «есть TS»; v22 `CLIENT_TCP` уходит с пустыми/шаблонными опциями. Контроллер не может воспроизвести клиента с нестандартными опциями; для TS-клиента форма сводится к `NO_TS`. |
| `d2k_session_plans` | 2992–2994 | 3 | таблица планов | `control.rs NamePlans` | **P** | C возвращает `d2k_plantab*`; Rust `NamePlans` — отдельная структура в `run`. Эквивалент по доступу, тип/владение иные. |
| `d2k_session_plan_count` | 2996–2998 | 3 | число планов | `control.rs:178 r2o_plan_count` | **E*** | C `d2k_plantab_count`; Rust `NamePlans::r2o_plan_count()`. Оба считают активные записи таблицы; тесты `control.rs:2643-2688`. |
| `d2k_session_plan_capacity` | 3000–3002 | 3 | ёмкость планов | `control.rs:182 r2o_plan_capacity` | **E*** | C `d2k_plantab_capacity`; Rust `NamePlans::r2o_plan_capacity()`. Ёмкость выводится из `--r2o-flow-capacity`; тест `control.rs:2670-2671`. |
| `silence_deadline` (static) | 3018–3028 | 11 | RTT неизвестен → 2 с; иначе `8*RTT`, clamp 1..5 с | `engine.rs:239-242` | **E** | **Точное совпадение:** C `2*NS_PER_S` при `!rtt_ns`; иначе `8*rtt`, минимум 1 с, максимум 5 с (`session.c:3018-3028`). Rust `rtt.map_or(2s, |rtt| rtt*8 clamp 1..5)` (`engine.rs:239-242`). |
| `tcp_silence_observe` (static) | 3034–3049 | 16 | SILENT: не probe, есть hello, не told/suspected, `rev_pkts>0`, нет payload после hello, нет reverse RST; ждать deadline или повтор hello | `engine.rs:223-252 tcp_silence_event` | **P** | **Совпадает:** те же условия (probe/silence_reported/reverse_seen/response_payload/saw_reverse_rst), deadline или `hello_repeats>0`; событие `R2oTcpSilenceEvent` с planned/elapsed. **Отличие:** C `F->hello_repeats > 0` и отдельный `suspected`; Rust `session.repeat_reported`/`silence_reported` — флаги отправки события, не обязательно факта повтора; семантика близка, но не тождественна. `test-tcp-silence-current-differential.sh`. |
| `fin_retry_window` (static) | 3063–3067 | 5 | окно повтора FIN: `3×max(3×RTT, 1с)` = `max(9×RTT, 3с)` | `engine.rs:1389 fin_retry_window` | **E** | Формула совпадает: Rust `rtt*9`, минимум 3 с; `None` (RTT неизвестен) → 3 с, что соответствует C `rtt_ns=0`. Тест `engine.rs:3823` (истечение ограниченного окна FIN) и `:3568` (повтор FIN). |
| `fin_window_over` (static) | 3069–3073 | 5 | `pending_fin && now>=pending_fin_ns && now-pending_fin_ns >= fin_retry_window(f)` | `engine.rs:708-710 fin expiry` | **E** | Rust проверяет `pending_fin_at.is_some_and(|started| elapsed >= fin_retry_window(rtt))`; порядок и сравнение `>=` совпадают. Тест `engine.rs:3823`. |
| `sweep_one` (static) | 3084–3087 | 4 | обход TCP-потоков, `told += tcp_silence_observe` | `engine.rs:693 expire_with_silent`, `:1330-1372` sweep | **P** | C проходит `d2k_track_walk(flows, sweep_one)` и считает подозрения. Rust `tcp_sessions.sweep_silent`/`tcp_silence_events`; счётчик `told` не возвращается, события забираются отдельно. Эквивалент по наблюдению, API иной. |
| `sweep_udp_one` (static) | 3112–3142 | 31 | UDP SILENT: saw_hello/saw_initial, не silence_told/suspected/quic_deny; ответ после последнего повтора; rev_seen или udp_reverse_hook; fwd_after_hello>0; deadline | `r2o_quic.rs:478 sweep`, `main.rs` quic sweep | **P** | **Совпадает:** критерий «клиент повторял после приветствия, ответа после последнего повтора не было, обратное направление видно (или hook), прошёл deadline». **Отличия:** C использует `rev_seen[slot]` и `udp_reverse_hook`; Rust `reverse_queue_visible`/`ControlServer::is_connected` и `R2oQuicSessions::sweep`; поля `saw_initial`/`last_rev_after_hello` в Rust распределены между `hello_seen`/`last_reverse`, отдельного `saw_initial` нет. `r2o-quic-stun-watch-differential.sh`. |
| `quic_watch` (static) | 3164–3169 | 6 | кандидат QUIC-stall: proto 17, hello/initial, был ответ, не suspected/probe/quic_deny/voice/STUN | `r2o_quic.rs:503 r2o_quic_stall_candidates` | **P** | **Совпадает:** proto 17, было приветствие и ответ, не подозревался, не зонд, не quic_deny, не voice/STUN. **Отличие:** C отдельно проверяет `voice_ssrc_valid`/`stun_txid_valid`; Rust `quic_stall_excluded`/`last_reverse`/`suspected`. Voice/STUN-потоки Rust исключает в `r2o_voice`, не в этом предикате. |
| `flow_tuple` (static) | 3174–3187 | 14 | прямой кортеж клиент→сервер по `init_low` | `conntrack.rs:413-430 tuple_from_packet/from_socket_addrs` | **P** | C строит кортеж из канонического ключа и `init_low`; Rust `tuple_from_packet` берёт адреса/порты из пакета, `from_socket_addrs` — из сокета. Для потока с известным `init_low` эквивалентно; C не требует пакета. |
| `ct_flow` (static) | 3197–3221 | 25 | QUIC stall по conntrack: reply изменился → запомнить; reply<=rev_pkts, orig delta<3 → нет; PTO=max(3*quic_rtt,1с); suspect QUIC_STALL | `r2o_quic.rs:527-571 update_r2o_quic_stall` | **E*** | **Точное совпадение условий:** `reply_packets` изменился → mark; `reply <= reverse_packets` или `orig - mark.orig < 3` → нет; `pto = 3*first_response_rtt`, минимум 1 с; время от mark ≥ pto → событие. C `quic_rtt_ns` измеряется hello→first reverse, Rust `first_response_rtt`; для штатного потока эквивалентно. `r2o-quic-stun-watch-differential.sh`. |
| `tcp_watch` (static) | 3257–3261 | 5 | TCP-stall: proto 6, saw_hello, had_sni, rev_payload_after_hello>0, не suspected/probe/pending_fin/tcp_watch_off/routed | `engine.rs:788-815 tcp_stall_candidates` | **P** | **Подтверждённое расхождение набора:** C требует `pending_fin==0` и `routed==0`; Rust `tcp_stall_candidates` их не проверяет, но добавляет `reverse_rst==0`, `guards==0`, `!stall_reported` и `direction_known`. C `tcp_watch_off` выставляется при выходе за полосу; Rust `stall_watch_off`/`stall_reported`. Таблица только TCP. |
| `tcp_in_band` (static) | 3263–3269 | 7 | `est+3 >= b && est <= b+3` для любого бюджета | `engine.rs:880-883` | **E** | **Точное совпадение:** C `est + D2K_TCP_STALL_SLACK >= b && est <= b + SLACK` (`session.c:3263-3269`); Rust `saturating_add(3) >= budget && estimate <= budget+3` (`engine.rs:880-883`), `TCP_STALL_PACKET_SLACK=3`. Тесты `engine.rs:2341/2381/2405`. |
| `tcp_band_top` (static) | 3271–3277 | 7 | максимум бюджетов + 3; пустой список → 3 | `engine.rs:850-855` | **P** | **Подтверждённое отличие пустого списка:** C при `n_stall_budget==0` даёт `0+3=3` (`session.c:3271-3277`); Rust `max().unwrap_or(25)+3=28`. На практике `set_stall_budgets` заменяет пустой список на `[25]`, но граничный случай различается и отдельного теста нет. Для непустого списка — совпадение. |
| `ct_tcp_flow` (static) | 3279–3328 | 50 | TCP stall: ESTABLISHED, unseen = reply-rev_pkts_conn, est = fwd+rev+unseen, band top, reply change → mark, orig delta>=3, RTO=max(3*rtt,2с), band, suspect с est | `engine.rs` conntrack stall detection | **P** | **Совпадает:** ESTABLISHED-only, `unseen`, `est`, верхняя полоса, обновление mark при смене reply, `orig` delta ≥3, RTO `3*rtt` минимум 2 с, `tcp_in_band`, событие с `num=est`. **Отличия:** C `tcp_watch_off=1` при не-ESTABLISHED/выше полосы; Rust `stall_watch_off`/`stall_reported`; C `suspect_num` с деталями server_hello, Rust `R2oTcpStallEvent` с полями. Полного differential нет. |
| `d2k_session_set_stall_budgets` | 3330–3343 | 14 | до 8 ненулевых бюджетов, пусто → полевой 25 | `engine.rs:451-460 set_tcp_stall_budgets` | **E** | Точное совпадение: `>8` или любой `0` → отказ; пустой список → `[25]`; иначе копия. Тесты `engine.rs:2431-2434` (нулевой/9/пусто/25). |
| `d2k_session_stall_budgets` | 3345–3351 | 7 | чтение бюджетов до cap, вернуть полное число | `engine.rs:371/850` поле `tcp_stall_budgets` | **P** | C getter копирует до `cap` и возвращает `n_stall_budget`; Rust поле используется напрямую в `tcp_in_band`/`tcp_band_top`, отдельного getter с cap нет. Эквивалент для чтения. |
| `d2k_session_sweep` | 3353–3370 | 18 | TCP sweep + UDP sweep; при `ct_query` — обход uflows/flows через `ct_flow`/`ct_tcp_flow`, вернуть число подозрений | `main.rs:1197-1263` periodic sweep, `engine.rs`, `r2o_quic.rs`, `conntrack.rs` | **P** | **Совпадает:** раз в секунду TCP/UDP sweep, затем conntrack-запросы для наблюдаемых потоков, сумма `told`. **Отличия:** C `d2k_track_walk` по двум таблицам и единый `told`; Rust отдельные `tcp_sessions.sweep_silent`, `quic_sessions`/`voice_sessions/udp_sessions` и `conntrack.query`; порядок uflows→flows не гарантирован. Полного differential нет. |
| `d2k_session_expire` | 3372–3395 | 24 | удалить FIN-окно, expire TCP с callback, expire UDP без callback | `engine.rs:698-760 expire_with_silent`, `r2o_udp_sessions.rs:456 expire` | **P** | **Совпадает:** TCP expiry вызывает `tcp_silence_observe`/capture-forget до удаления; UDP удаляется без callback; FIN-записи снимаются по своему окну. **Отличия:** C `d2k_track_remove_if(fin_window_over)` и `d2k_track_expire`; Rust `expire_with_silent` + `R2oUdpSessions::expire`; порядок/тайминги и счётчик `freed` не сверены. |
| `d2k_session_flows` | 3397–3399 | 3 | сумма TCP+UDP потоков | `main.rs:668-679 r2o_log_flow_table_stats` | **P** | C `track_count(flows)+track_count(uflows)`; Rust `tcp_sessions.len()+udp_stats.flows`. Сумма та же; UDP-счётчик Rust исключает `controller_probe` (`r2o_udp_sessions.rs:465-471`), C — нет. |
| `d2k_session_send_pending` | 3401–3405 | 5 | `fl && execution_id==execution && sends_left && !sends_failed` | `engine.rs:614 r2o_send_pending` | **P** | Rust проверяет `execution_id != 0`, совпадение поколения, `r2o_execution_pending` и `!damaged`. `sends_left` заменён ожиданием `ScheduledQueue`, `sends_failed` — удалением `PendingApplied`; для проверяемых состояний эквивалентно. Тесты `engine.rs:4600`, `:4639` (истина → ложь после завершения/чужого поколения). Числового `sends_left` нет. |
| `d2k_session_sent` | 3407–3428 | 22 | `sends_left--`, `sends_done++`; при нуле и без failed → `done++` + PLAN_DONE; иначе `sent_lost++` | `engine.rs:627-653 r2o_mark_plan_done_for_execution`, `r2o_send_pending` | **P** | **Совпадает:** DONE ставится только при совпадении key/execution и отсутствии damaged; устаревшее/чужое завершение игнорируется. **Подтверждённые отличия:** C ведёт числовые `sends_left/sends_done` и `sent_lost++`; Rust `r2o_execution_pending`/`plan_done` булевы, числовых счётчиков и `sent_lost` нет — устаревшее завершение просто не ставит DONE. C `sends_left` уменьшается на каждый raw-send+вердикт; Rust ждёт опустошения `ScheduledQueue` по ticket. |
| `d2k_session_exec_failed` | 3449–3501 | 53 | общий отказ: UNSENT один раз; UDP original-lost → udp_replan; damaged → damaged_flows++, guards=0, PLAN_DAMAGED один раз; возврат «оригинал цел» | `main.rs:411-446 r2o_finish_tcp_execution/r2o_release_damaged_tcp_hold`, `engine.rs:672-690 r2o_mark_damaged_for_execution`, `r2o_udp_sessions.rs:383-406` | **P** | **Совпадает:** при damaged Rust ставит `damaged=true`, `r2o_execution_pending=false`, `guards=0` и пишет `PlanUnsent` + `PlanDamaged` (две записи, как C); UDP-lost сбрасывает `plan_applied`; чистый выход при `payload_on_wire=false`/оригинал не взят. **Подтверждённые отличия:** (1) C `damaged_flows++` — агрегата в Rust нет (N `d2k_session_damaged_count`); (2) C `sends_failed/sends_left/orig_taken/sends_done` числовые, Rust `r2o_sends_done` bool; (3) C возвращает 0/1 «оригинал цел», Rust `r2o_finish_tcp_execution`/`TransmissionOutcome` решают по `payload_on_wire/original_spent/original_taken`; (4) C UDP `udp_replan` — флаг потока, Rust `r2o_note_execution_failure` сбрасывает `plan_applied` только при `!payload_on_wire`. |
| `d2k_session_guards` | 3503–3507 | 5 | guards потока | `engine.rs` `session.guards` | **P** | C getter по ключу; Rust поле `TcpSession.guards` доступно внутри engine, отдельного публичного getter нет. `r2o_mark_damaged_for_execution` обнуляет, как C. |
| `d2k_session_client_shape` | 3509–3513 | 5 | форма клиента потока | `engine.rs` `session.client_shape` | **P** | C getter; Rust `TcpSession.client_shape` заполняется из ClientHello. Полный набор TCP-опций не хранится (N `shape_tcp_options_family`). |
| `d2k_session_damaged` | 3515–3523 | 9 | пометить damaged при совпадении execution | `engine.rs:672-690 r2o_mark_damaged_for_execution` | **P** | C ставит только `damaged=1`; Rust дополнительно `r2o_execution_pending=false`, `guards=0`. Для флага эквивалентно; guards сбрасываются раньше, чем C в `exec_failed`. |
| `d2k_session_unsent` | 3525–3539 | 15 | PLAN_UNSENT + `sends_left=0`/`sends_failed=1` | `main.rs:468 r2o_fail_pending_applied`, `r2o_datapath::flow_journal::record_execution_failure` | **P** | C пишет PLAN_UNSENT и обнуляет счётчики; Rust `sends_left/sends_failed` не имеет, UNSENT — часть `record_execution_failure` (PlanUnsent). Повторный UNSENT невозможен, потому что `r2o_fail_pending_applied` удаляет `PendingApplied`; это функциональный эквивалент `sends_failed=1`. D22. |
| `d2k_session_applied` | 3541–3543 | 3 | счётчик applied | агрегата нет | **N** | C `s->applied++` в `plan_handed_off`; Rust APPLIED — событие/журнал, агрегата в `TcpSessions`/`R2oUdpSessions` нет. Сводка R2O это число не печатает. |
| `d2k_session_done` | 3545–3547 | 3 | счётчик done | агрегата нет | **N** | C `s->done++` при завершении всех посылок; Rust `r2o_mark_plan_done_for_execution` ставит флаг/событие, счётчика нет. |
| `d2k_session_damaged_count` | 3549–3551 | 3 | число damaged-потоков | флага достаточно, агрегата нет | **N** | C `damaged_flows++` один раз на поток в `exec_failed`; Rust выставляет `session.damaged`, но агрегата не ведёт. |
| `d2k_session_sent_lost` | 3553–3555 | 3 | «некому приписать отправку» | нет | **N** | C `sent_lost++` при отсутствии потока/чужом поколении/нулевом `sends_left`; Rust такие завершения просто игнорирует, счётчика нет. |
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
| `d2k_session_suspects` | 3597–3599 | 3 | число подозрений | агрегата нет | **N** | C `s->suspects++` в `suspect_num`; Rust подозрения уходят событиями `EVENT_R2O_*`/журналом, общего счётчика нет. |
| `d2k_session_rst_dropped` | 3601–3603 | 3 | снятых чужих RST | `engine.rs` `r2o_tcp_rst_dropped` | P | — |
| `d2k_session_exchanges` | 3605–3607 | 3 | число обменов | агрегата нет; EXCHANGE — событие журнала | **N** | C `s->exchanges++` при первом ответе/прикладных данных; Rust `R2oTcpExchangeEvent`/UDP exchange events, агрегата нет. `r2o-udp-exchange-differential.sh` сверяет события. |
| `d2k_session_reply_hidden` | 3609–3611 | 3 | «ответ не видели» | `engine.rs` `r2o_reply_hidden` | P | `r2o-tcp-reply-hidden-differential.sh` |
| `d2k_session_tcp_hello_flows` | 3613–3615 | 3 | TCP-потоков с приветствием | `engine.rs` `r2o_tcp_hello_flows` | P | — |
| `d2k_session_payload_stats` | 3617–3638 | 22 | снимок: reverse/after_hello/late/not_hello/first_byte/sni_next_seg/capture + http_later/unaligned/open_end | `engine.rs R2oTcpPayloadStats` | **P** | **Совпадает по полям:** reverse/after_hello/late/not_hello/first_byte/sni_next_seg/capture_* и HTTP keep-alive счётчики; Rust `r2o_tcp_payload_stats` (`main.rs:719-733`). **Отличия:** C `capture.rejected/expired/full` берутся из `d2k_capture`, Rust `capture_stats`; C `last_nonhello_first` — первый байт последнего не-ClientHello, Rust `last_first_byte`; `test-datapath-stats-timer-differential.sh` и payload-тесты частичные. |
| `d2k_session_journal` | 3640–3642 | 3 | доступ к журналу | `flow_journal.rs:543 R2oFlowJournal` | P | D22 |

## datapath/track.c (18 функций)

Таблица потоков: открытая адресация, FNV-1a, удаление сдвигом, порог 3/4.
R2O заменил структуру на `HashMap`, сохранив ключ, ёмкость и порог отказов.

**Прочитано построчно: 18/18 функций, 337 строк C (1–337).** Сверено с `flow_capacity.rs:12-21` (`from_requested`: `max(16).next_power_of_two`, `limit=slots-slots/4`) и `engine.rs:41-88` (`TcpFlowKey`), `:393-440` (`try_with_capacity`, len/capacity/refusals), `:698-732` (`expire_with_silent`), `:911-970` (`track_packet_mode`, лимит/новый SYN), `:1111` (`last_seen`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_key_make` | 18–51 | 34 | IPv4-ключ: сравнить 6 байт `addr + port`, выбрать low/high, занулить весь `d2k_key`, записать ip/port/proto | `engine.rs:67 TcpFlowKey::from_endpoints`, `r2o_udp_sessions.rs:35 R2oUdpFlowKey::new` | **P** | C сравнивает `src_ip4 + sport_be` с `dst_ip4 + dport_be` и при равенстве делает источник low (`<=`). Rust сравнивает `(family, 16-байтный Address, port)`; для одной family порядок эквивалентен: хвостовые нули IPv4 не влияют, пока адреса равны, а затем решает порт. Представление ключа разное (типизированный ключ против 16-байтной структуры). Тесты capture/udp_sessions; C/Rust differential нет. |
| `d2k_key_make_addr` | 55–74 | 20 | IPv4 делегирует `d2k_key_make`; IPv6 — 16 байт адреса, затем порт; family=6 | `engine.rs:48 TcpFlowKey::from_packet`, `r2o_udp_sessions.rs:82 flow_key_from_packet` | **P** | Порядок IPv6 совпадает (16 байт, затем порт, `<=` → low). C проверяет `src->family == dst->family` и отвергает иные family; Rust получает family из `Address` (4/6). Отдельного теста на равные адреса и порты нет. |
| `round_pow2` (static) | 84–90 | 7 | ёмкость → степень 2, минимум 16 | `flow_capacity.rs:12 from_requested` | **E** | Точное совпадение `max(16).next_power_of_two()`; тест `flow_capacity.rs:45` (`1→16`, `64→64`, `65→128`, лимит `slots-slots/4`). |
| `key_eq` (static) | 92–104 | 13 | `memcmp` всего `d2k_key`; padding занулён `memset` | `#[derive(Eq, Hash)]` (`engine.rs:42`, `capture.rs:14`) | **E** | C сравнивает 16 байт, включая занулённые хвосты; Rust сравнивает все поля типизированного ключа, padding отсутствует. Семантика равенства совпадает; используется во всех тестах ключей. |
| `key_hash` (static) | 108–115 | 8 | FNV-1a по всем байтам ключа | `HashMap` SipHash (по умолчанию) | **P** | Хеш-функция намеренно иная; на семантику поиска не влияет, но порядок коллизий/пробирования и устойчивость к HashDoS отличаются. C/Rust differential хеша нет. |
| `d2k_track_new` | 117–133 | 17 | `calloc` таблицы, `round_pow2`, отдельные `slots/state`; при сбое — `free` | `engine.rs:395 try_with_capacity`, `flow_capacity.rs:12` | **P** | C выделяет два массива и при частичном сбое освобождает; Rust делает `HashMap::try_reserve(slots)` и резервирует очереди событий, возвращая `TryReserveError`. Ёмкость/лимит совпадают, профиль памяти и OOM-поведение — нет. OOM-теста нет. |
| `d2k_track_free` | 135–142 | 8 | освободить slots/state/table | `Drop` | **E** | RAII; отдельного теста не требуется. |
| `d2k_track_find` | 144–160 | 17 | линейное пробирование, остановка на свободной ячейке | `engine.rs` `self.flows.get` (напр. `:1578`) | **P** | C ищет по FNV-хешу и обрывает цепочку на `SLOT_FREE`; Rust — `HashMap::get`. Результат поиска по ключу тот же, внутренний порядок и пробирование иные. |
| `remove_at` (static) | 165–191 | 27 | удаление сдвигом назад, без надгробий; пересчёт `home` | `HashMap::remove` | **P** | C поддерживает инвариант линейного пробирования сдвигом кластера; Rust удаляет через `HashMap`, где надгробия/сдвиг — внутренняя деталь. Функционально удаление по ключу эквивалентно; пошагового differential нет. |
| `d2k_track_get` | 193–229 | 37 | get-or-create, `last_ns=now`, отказ при `used+1 > cap-cap/4`, зануление новой записи | `engine.rs:911 track_packet_mode`, `:941` лимит, `:1111 last_seen` | **P** | C обновляет `last_ns` на каждом пакете и отказывает при `used+1 > limit`; Rust обновляет `last_seen` (`:1111`) и отказывает при `len >= limit` — эквивалентно. C зануляет весь flow; Rust создаёт `TcpSession::new`. **Отличие:** при новом SYN Rust сохраняет только `metrics`, а C — ещё и учёт посылок/execution (см. `d2k_track_new_connection`). Тест `engine.rs:2847` (лимит). |
| `d2k_track_new_connection` | 231–257 | 27 | сброс полей при новом SYN; сохраняются key/in_use/first/last/init_low/dir_known/счётчики пакетов и байт, **sends_left/sends_failed/execution_id/binding/plan_id/trial_id** | `engine.rs:938-961` ветка `new_connection`: новый `TcpSession`, копируется только `metrics` | **P** | **Подтверждённое расхождение:** C сохраняет `sends_left/sends_failed/execution_id/binding/plan_id/trial_id` через границу нового SYN, чтобы позднее завершение старой посылки не приняли за новую. Rust создаёт `TcpSession::new` с `execution_id=0`, `r2o_execution_pending=false`; `PendingApplied`/tickets живут отдельно, поэтому поздний completion старого поколения отбрасывается (`r2o_send_pending` вернёт false), а не учитывается. Нужен тест «новый SYN при незавершённой посылке». |
| `d2k_track_remove` | 259–267 | 9 | найти и удалить сдвигом | `engine.rs` `flows.remove` | **P** | C: `find` + `remove_at`; Rust: `HashMap::remove`. Функционально эквивалентно; отдельного теста на удаление середины кластера нет (в C это важно, в Rust — нет). |
| `d2k_track_walk` | 269–278 | 10 | обход всех занятых слотов в порядке таблицы | `flows.iter()` / `retain` (`engine.rs:698`) | **P** | C обходит слоты по возрастанию индекса; Rust — в неопределённом порядке `HashMap`. Если потребитель зависит от порядка (логи/диагностика), результат может отличаться; функциональные счётчики не зависят. |
| `d2k_track_expire` | 280–308 | 29 | истечение по idle: `now>=last && now-last>=idle`, callback **до** удаления, повторная проверка слота после сдвига | `engine.rs:698-732 expire_with_silent` | **P** | C: явное `now>=last` (защита от убывания часов), callback `on_expire` до `remove_at`, повторная проверка слота. Rust: `idle_expired = now.saturating_duration_since(last_seen) >= idle`; **дополнительно** `fin_expired` по `pending_fin_at` (`:708-711`), `on_silent` до `retain`-удаления (`:713-719`), `capture.forget` при удалении (`:723-728`), одним `retain` (`:706-731`). Итоговый набор idle-удалённых и событий совпадает; FIN-истечение в C вынесено в `d2k_track_remove_if`; порядок обхода иной. Тесты `engine.rs:3356`, `:3448`. |
| `d2k_track_remove_if` | 310–325 | 16 | удаление по предикату (FIN-окно), повторная проверка слота | `engine.rs:700 fin_expired в retain` | **P** | C: `while (used && gone()) remove_at`; Rust: `retain` с `fin_expired`. Набор удаляемых совпадает; C перепроверяет слот после сдвига, Rust — нет необходимости. Отдельного теста на несколько подряд идущих FIN нет. |
| `d2k_track_count` | 327–329 | 3 | число занятых записей | `engine.rs:429 len` | **E** | Прямой getter `flows.len()`; используется в тестах и статистике. |
| `d2k_track_capacity` | 331–333 | 3 | физическая ёмкость (степень 2) | `engine.rs:434 r2o_tcp_flow_capacity` | **E** | Прямой getter `flow_capacity.slots()`; тест `flow_capacity.rs:45` проверяет округление. |
| `d2k_track_refusals` | 335–337 | 3 | счётчик отказов вставки | `engine.rs:438 r2o_tcp_flow_refusals` | **P** | Прямой getter; инкремент в `track_packet_mode` при `len >= limit`. Есть `test-datapath-tcp-capacity-differential.sh`, но в этом проходе он не перезапускался; статус P. |

## datapath/capture.c (6 функций)

Сборка ClientHello/HTTP-заголовка по seq: TTL, generation, anchor, перекрытия,
конфликт → poison. R2O: `crates/r2o-datapath/src/capture.rs`.

**Прочитано построчно: 6/6 функций, 124 строки C (1–124).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `same` (static) | 4–6 | 3 | сравнение ключей | `TcpFlowKey` `Eq` (`capture.rs:14`) | E | используется во всех capture-тестах |
| `d2k_capture_forget` | 8–14 | 7 | сбросить слоты ключа | `capture.rs:650 forget` | E | `capture.rs:949` (требует forget/new generation) |
| `reject` (static) | 16–20 | 5 | state=2, rejected++ | `capture.rs:662 reject_result` | E | `capture.rs:949` conflicting overlap |
| `d2k_capture_feed_ready` | 22–107 | 86 | сборка по seq: TTL, generation, anchor, overlap, wrap, ready-callback | `capture.rs:514 feed_mode`, `:446 feed`, `:480 feed_http` | **P** | TLS-путь совпадает построчно: TTL (`now<started`/`now-started>=TTL` ↔ `checked_duration_since`), generation, проверка anchor (`(int32_t)offset >= 0`, `< CAPTURE_BYTES`, `len <= CAPTURE_BYTES-offset`), `delta`, overlap-conflict, `high`, `contiguous`, `reject/full/completed`. **Отличия:** (1) Rust требует совпадения `mode` и освобождает слот при смене TLS↔HTTP, C режима не знает; (2) C при отсутствии anchor требует `bytes[0]==22` для **любого** ready-callback, Rust — только для TLS, HTTP без anchor принимает; (3) Rust `http_ready` использует `request_host_range`, C `d2k_http_request`: Rust требует полностью закрытые заголовки (`find_crlf`), C может вернуть 1 при завершённой строке Host без пустой строки; Rust отвергает `#` и target ≥2048, C — нет; Rust отвергает полный 4096-байтный буфер без `\r\n\r\n`, C оставляет слот до TTL; (4) статистика Rust гейтится `visible`, C считает всегда (R2O-расширение для controller probe). Trace-тесты `capture.rs:989/1099` есть, но `test-datapath-capture-lifecycle-differential.sh` пинится на другой SHA. |
| `tls_ready` (static) | 109–118 | 10 | критерий целой TLS-записи (1 запись, длины) | `capture.rs:673 tls_ready` | **E** | Точное совпадение: `n>=2 && b[1]!=3`, `n>=6 && b[5]!=1`, `total=5+u16`, `9..=4096`, `high>total`, `hs+9==total`, `n==total`; тест `capture.rs:1209`. |
| `d2k_capture_feed` | 119–124 | 6 | feed с TLS-критерием `tls_ready` | `capture.rs:446 feed` | **E** | Тонкая TLS-обёртка: C `feed_ready(..., tls_ready)`, Rust `feed(..., CaptureMode::Tls, visible=true)`. Для пользовательского TLS-трафика `feed_ready` эквивалентен; общий HTTP-путь — P (см. выше). |

### datapath/capture.c: построчная сверка

- **`same` (4–6) ↔ `TcpFlowKey: Eq`:** C `d2k_key_equal`, Rust
  `capture.rs:14`. E; используется всеми capture-тестами.
- **`d2k_capture_forget` (8–14) ↔ `capture.rs:650`:** оба проходят все
  слоты и освобождают совпавший ключ, независимо от state. E;
  `capture.rs:949` (новый generation/forget).
- **`reject` (16–20) ↔ `capture.rs:662`:** C `state=2`, `rejected++`;
  Rust `SlotState::Rejected` + `reject_result` с гейтом `visible`.
  Для пользовательского трафика эквивалентно. E.
- **`d2k_capture_feed_ready` (22–107) ↔ `feed_mode`:** TLS-путь
  совпадает: TTL (`now<started` / `now-started>=TTL` ↔
  `checked_duration_since`), generation, anchor
  (`(int32_t)offset >= 0`, `< CAPTURE_BYTES`,
  `len <= CAPTURE_BYTES-offset`), `delta`, overlap-conflict, `high`,
  `contiguous`, `tls_ready`, счётчики. Отличия — mode/visibility,
  HTTP-callback и полный буфер; подробно в строке таблицы. P.
- **`tls_ready` (109–118) ↔ `capture.rs:673`:** точное совпадение всех
  проверок; E, `capture.rs:1209`.
- **`d2k_capture_feed` (119–124) ↔ `capture.rs:446`:** TLS-обёртка;
  E для TLS, HTTP-путь наследует P `feed_ready`.

## datapath/hold.c (12 функций)

Удержание TCP-сегментов до сборки приветствия/HTTP-заголовка: слоты, дедлайн,
ревизия плана, порядок оригиналов, ready-batch. R2O: `hold.rs`.

**Прочитано построчно: 12/12 функций, 236 строк C (1–236).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `r32` (static) | 17 | 1 | big-endian u32 | `packet.rs:236 read_u32` | **P** | Формула совпадает; Rust `read_u32` дополнительно проверяет границы через `get`. `parse_tcp` получает `sequence/acknowledgment` уже из `TcpSegmentView`; отдельного теста `r32` нет. |
| `same` (static) | 18–20 | 3 | сравнение ключей | `TcpFlowKey` Eq | **E** | C `d2k_key_equal`, Rust derived `Eq`; используется всеми hold-тестами. |
| `d2k_hold_parse` | 21–40 | 20 | разбор TCP-заголовка и полей hold: ihl/header/total/payload/src_low/seq/ack/flags/dst/dst_be/sport_be | `hold.rs:1249 parse_tcp` | **P** | Используемые поля эквивалентны: `ihl=view.l4_offset`, `header=tcp.payload.start`, `total=view.total_len`, `payload=tcp.payload.len`, `src_low = source==key.low`, `seq/ack/flags` из `TcpSegmentView`. Rust не материализует `dst_be`/`sport_be`; в `hold.c` они только записываются и не читаются. C отвергает fragment `&0x3fff`, Rust — то же; D6. |
| `d2k_hold_new` | 41 | 1 | `calloc` таблицы | `HoldTable::default` (`hold.rs:194`) | **E** | RAII; C при OOM возвращает NULL, Rust `Default` может аварийно завершиться — отличие только в OOM-ветви. |
| `d2k_hold_free` | 42 | 1 | `free` | `Drop` | **E** | RAII; C-контракт «flush ALL first» в Rust обеспечивается владельцем/Drop. |
| `release_slot` (static) | 43–51 | 9 | вернуть каждый ID с байтами, `stats.released++`, `capture_forget`, `pending-=count` | `hold.rs:1229 remove_slot`, `:1236 release_held_packets` | **P** | C вызывает callback на каждый пакет; Rust возвращает `Vec<u32>` ID, а owned-пакеты кладёт в `owned_releases`. `pending`/`released` считаются так же; `capture.forget` в Rust вызывает вызывающий (в части веток — после `remove_slot`). P — разный контракт владения. |
| `d2k_hold_flush` | 52–72 | 21 | `all`/deadline/смена ревизии: release + `dropped_all`/`plan_changed`/`timed_out`/`timed_out_pkts` | `hold.rs:888 flush` | **E** | Условия и счётчики совпадают; Rust дополнительно складывает `R2oIncompleteCaptureDiagnostic` для истёкших TLS/HTTP, если поток не controller_probe. Тесты `hold.rs:2200`, `:2231`, `:2249`. |
| `d2k_hold_next` | 73–80 | 8 | абсолютный минимальный deadline (ns), 0 если слотов нет | `hold.rs:958 timeout_ms` | **P** | C отдаёт абсолютное время в наносекундах; Rust — относительные миллисекунды до ближайшего deadline с ограничением `max_ms`, `0` при `deadline<=now` или `max_ms<=0`. Для poll-таймаута эквивалентно, отдельного absolute-getter нет. |
| `d2k_hold_get_stats` | 81–84 | 4 | снимок `d2k_hold_stats` | `hold.rs:200 r2o_hold_stats` | **P** | Поля совпадают: `started, ready, released, full, timed_out, timed_out_pkts/timed_out_packets, plan_changed, dropped_all, joined, mismatched, sided, pending`. Rust возвращает `R2oHoldStats` по значению; отдельного теста снимка нет. |
| `d2k_hold_verdicts` | 85–92 | 8 | выдать вердикт всем ID, считать ошибки, продолжить после отказа | `main.rs:4308 release_many`, `:4319 release_many_with` | **P** | C проходит все ID и возвращает число ошибок; Rust `release_many_with` тоже продолжает после ошибки, но возвращает первую `io::Error`. Семантика «попробовать все» совпадает, форма результата иная. |
| `http_ready` (static) | 93–100 | 8 | готовность HTTP-заголовка; полный заголовок без Host → -1 | `hold.rs:695 http_ready`, `:1343 incomplete_http_head` | **P** | C `d2k_http_request` vs Rust `request_host_range`: Rust требует полностью закрытые заголовки (`find_crlf`), C может вернуть 1 при завершённой строке Host без пустой строки; Rust отвергает `#` и target ≥2048, C — нет; см. также `capture.c`. Тест `hold.rs:2374`. |
| `d2k_hold_feed` | 101–236 | 136 | приём сегмента: flush, слот/сторона, лимиты 8×1600, capture, выбор головы, порядок оригиналов, синтетическая голова | `hold.rs:356 feed_observing_mode`, `:1348 synthetic_packet` | **P** | **Совпадает:** константы `HOLD_SLOTS=16`, `HOLD_PACKETS=8`, `HOLD_PACKET_BYTES=1600`, `HOLD_WAIT=100 мс`; флаги `~0x18`/ACK, `ack`, лимит пакетов, capture TLS/HTTP, поиск головы по sequence, stable-сортировка оригиналов по `seq-hello_seq`, synthetic head и пересчёт IP total. **Отличия:** C получает готовый `allow_start` и `anchor/have_anchor` от сессии; Rust сам ведёт `syns`/`http_requests`, проверяет `attempted/saw_hello`, различает `observe_tls/observe_http/own_packets` и поддерживает `OwnedReady`/HTTP-response. Ветви старта/якоря/наблюдения/owned не покрыты одним C/Rust differential; тесты `hold.rs:1458/2126/2167` подтверждают split/out-of-order/order. P. |

### datapath/hold.c: построчная сверка

- **`r32` (17) ↔ `packet.rs:236`:** BE u32; Rust bounds-checked.
  P — отдельного теста helper'а нет, но `parse_tcp` получает поля из
  проверенного `TcpSegmentView`.
- **`same` (18–20) ↔ `TcpFlowKey: Eq`:** E.
- **`d2k_hold_parse` (21–40) ↔ `hold.rs:1249 parse_tcp`:** C
  материализует `ihl/header/total/payload/src_low/seq/ack/flags/dst/
  dst_be/sport_be`; Rust отдаёт `PacketView`/`TcpSegmentView`/ключ/
  endpoints. Используемые поля эквивалентны; `dst_be`/`sport_be` в
  `hold.c` только записываются и не читаются. P, D6.
- **`d2k_hold_new/free` (41–42) ↔ `HoldTable::default`/`Drop`:** E;
  отличие только в OOM-ветви `calloc`.
- **`release_slot` (43–51) ↔ `remove_slot`/`release_held_packets`:**
  C отдаёт каждый ID с байтами через callback; Rust возвращает ID, а
  owned-пакеты складывает в `owned_releases`. `pending/released`
  считаются одинаково. P — разный контракт владения.
- **`d2k_hold_flush` (52–72) ↔ `hold.rs:888`:** условия
  `all/deadline/revision` и счётчики совпадают; Rust добавляет
  incomplete-диагностику для истёкших TLS/HTTP. E, тесты `:2200`,
  `:2231`, `:2249`.
- **`d2k_hold_next` (73–80) ↔ `timeout_ms`:** C — абсолютный ns,
  Rust — относительные ms с cap и `0` при истёкшем deadline. P.
- **`d2k_hold_get_stats` (81–84) ↔ `r2o_hold_stats`:** поля
  `started/ready/released/full/timed_out/timed_out_pkts/plan_changed/
  dropped_all/joined/mismatched/sided/pending` совпадают. P — нет
  отдельного теста снимка.
- **`d2k_hold_verdicts` (85–92) ↔ `release_many_with`:** оба проходят
  все ID и продолжают после ошибки; C возвращает число ошибок, Rust —
  первую `io::Error`. P.
- **`http_ready` (93–100) ↔ `hold.rs:695`:** C `d2k_http_request` vs
  Rust `request_host_range`; различия в полноте заголовков, `#`,
  target ≥2048. P; тест `hold.rs:2374`.
- **`d2k_hold_feed` (101–236) ↔ `feed_observing_mode`:** константы
  `16/8/1600/100 мс`, флаги `~0x18`/ACK, `ack`, capture TLS/HTTP,
  поиск головы по sequence, stable-порядок оригиналов и synthetic head
  совпадают. C получает `allow_start`/anchor от сессии, Rust сам ведёт
  `syns`/`http_requests`, различает `observe_*`/`own_packets` и умеет
  `OwnedReady`/HTTP-response. Ветви старта/якоря/наблюдения/owned не
  покрыты одним C/Rust differential; split/out-of-order/order
  подтверждены `hold.rs:1458/2126/2167`. P.

## datapath/udp_hold.c (10 функций)

Ограниченное владение NFQUEUE ID для сборки QUIC ClientHello: слоты, дедлайн,
пачки, переполнение. R2O: `r2o_udp_hold.rs` (`R2oUdpHoldTable`).

**Прочитано построчно: 10/10 функций, 123 строки C (1–123).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `same_key` (static) | 14–16 | 3 | сравнение ключа | `R2oUdpFlowKey` Eq (`r2o_udp_sessions.rs:37`) | **E** | C `d2k_key_equal`; Rust типизированный `Eq` по адресам/портам/proto. Используется поиском слота в `r2o_feed`/`r2o_take`. |
| `clear_slot` (static) | 18–20 | 3 | обнулить слот без release | `Option::take`/`None` | **E** | C `memset(s,0)`, Rust `slots[i].take()`; освобождение ID в обоих случаях делает вызывающий (C — `release_slot`, Rust — `r2o_take`/`r2o_drain`). |
| `release_slot` (static) | 22–29 | 8 | `release(ctx,&batch)`, clear, вернуть count | `r2o_udp_hold.rs:212 r2o_flush`, `:228 r2o_drain`, `:198 r2o_take` | **P** | C вызывает release-callback и сам чистит слот; Rust возвращает `R2oUdpHoldBatch` вызывающему, который обязан отпустить ID. Семантика «release → clear» та же, владение и форма результата разные. |
| `d2k_udp_hold_new` | 31 | 1 | `calloc` таблицы | `R2oUdpHoldTable::new` (`:147`) | **E** | C `calloc` (NULL при OOM), Rust `[None; 16]`; OOM-ветвь отличается, обычный путь эквивалентен. |
| `d2k_udp_hold_free` | 33–39 | 7 | слить все занятые слоты, затем `free` | `r2o_drain` (`:228`) | **P** | C при free вызывает release-callback для каждого used-слота; Rust `r2o_drain` возвращает пачки, а `Drop` не отпускает NFQUEUE ID сам — это обязанность вызывающего. |
| `d2k_udp_hold_flush` | 41–52 | 12 | `used && now>=deadline` → release, сумма count | `r2o_flush` (`:212`) | **P** | Условие deadline совпадает; C отпускает ID внутри и возвращает число, Rust возвращает `Vec<R2oUdpHoldBatch>` без вердиктов. Вызывающий `main.rs:1459/1570` отпускает пачки отдельно. |
| `d2k_udp_hold_feed` | 54–58 | 5 | feed с `mark=0` | `r2o_feed` (`:154`, mark=0) | **P** | Тонкая обёртка; Rust передаёт mark явно, C — 0. |
| `d2k_udp_hold_feed_marked` | 60–96 | 37 | валидация len 1..1600, flush истёкших, слот по ключу/свободный, переполнение 8, запись id/len/mark/packet | `:154 r2o_feed` (`R2O_UDP_HOLD_PACKETS=8`, max 1600) | **P** | **Отличия:** C сначала вызывает `d2k_udp_hold_flush`, Rust `r2o_feed` сам не flush-ит — это делает `main.rs:1570` перед feed; C при переполнении освобождает слот через callback и возвращает 0, Rust снимает слот и возвращает `Overflow(batch)`, который вызывающий обязан отпустить. Валидация len>1600 и ключа эквивалентна; пустой пакет Rust отвергает через `flow_key_from_packet`. Тестов `R2oUdpHoldTable` в файле нет (тесты `:830+` относятся к follow/deferred). |
| `d2k_udp_hold_take` | 98–113 | 16 | забрать пачку по ключу, очистить слот; `now_ns` не используется | `:198 r2o_take` | **P** | C копирует `d2k_udp_hold_batch` и чистит слот; Rust возвращает `Option<R2oUdpHoldBatch>`, слот забирает через `Option::take`. Истёкшие слоты оба не трогают — C требует предварительного flush, Rust вызывает `r2o_flush` отдельно. |
| `d2k_udp_hold_next_ns` | 115–123 | 9 | абсолютный минимальный deadline (ns), 0 если пусто | `:240 timeout_ms` | **P** | C отдаёт абсолютные ns; Rust — относительные ms с `max_ms` и `0` при `deadline<=now`/`max_ms<=0`. Для poll эквивалентно, отдельного absolute-getter нет. |

### datapath/udp_hold.c: построчная сверка

- **Константы:** C `SLOTS=16`, `PACKETS=8`, `PACKET=1600`,
  `WAIT=100 мс`; Rust `R2O_UDP_HOLD_SLOTS=16`,
  `R2O_UDP_HOLD_PACKETS=8`, `R2O_UDP_HOLD_PACKET_MAX=1600`,
  `R2O_UDP_HOLD_WAIT=100 мс`. Совпадают.
- **`same_key`/`clear_slot`/`d2k_udp_hold_new`:** E. C
  `d2k_key_equal`/`memset`/`calloc`; Rust `Eq`/`Option::take`/
  `[None; 16]`. Отличие только OOM-ветвь `calloc`.
- **`release_slot`/`d2k_udp_hold_free`/`d2k_udp_hold_flush`:** P.
  C отпускает NFQUEUE ID через callback внутри слота; Rust возвращает
  `R2oUdpHoldBatch`/`Vec<...>` и оставляет release вызывающему. Условие
  `now>=deadline` и счётчики совпадают.
- **`d2k_udp_hold_feed_marked`:** P. C сначала flush-ит истёкшие, затем
  ищет слот/свободную ячейку; Rust `r2o_feed` flush не делает — это
  отдельный `r2o_flush` в `main.rs:1570`. При переполнении 8 пакетов C
  освобождает слот и возвращает 0, Rust снимает слот и возвращает
  `Overflow(batch)`; вызывающий обязан отпустить пачку. Валидация
  `len<=1600` и ключа эквивалентна; пустой пакет Rust отвергает через
  `flow_key_from_packet`.
- **`d2k_udp_hold_take`:** P. C копирует batch и чистит слот; Rust
  возвращает `Option<R2oUdpHoldBatch>` через `Option::take`. Истёкшие
  слоты оба не трогают.
- **`d2k_udp_hold_next_ns`:** P. C — абсолютные ns; Rust `timeout_ms` —
  относительные ms с `max_ms` и `0` при истёкшем deadline.
- **Тесты:** прямых unit-тестов `R2oUdpHoldTable` в
  `r2o_udp_hold.rs` нет; тесты `:830+` относятся к follow/deferred.
  Поведение hold-таблицы проверяется косвенно через `main.rs`
  (`r2o-udp-session-table-check.sh` и UDP differentials).

## datapath/udp_path.c (7 функций)

Транзакция UDP-hold вокруг решения сессии и выпуск/повтор пачек.
R2O: `main.rs` (`r2o_release_udp_batch*`, `r2o_udp_handle_late_tail`),
`r2o_udp_sessions.rs`.

**Прочитано построчно: 7/7 функций, 97 строк C (1–97).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_udp_path_release` | 6–13 | 8 | закрыть session-hold и выпустить пачку `NF_ACCEPT` | `main.rs:153 r2o_release_udp_batch`, `:200 r2o_release_udp_batches` | **P** | C вызывает `d2k_session_udp_hold_end(&b->key)` и `d2k_udp_out_batch(..., NF_ACCEPT, 0, now, now, seq)`. Rust `r2o_release_udp_batch` отпускает голову/хвосты через `r2o_release_batch_with`, помечает follow и логирует ошибки, но **прямого `hold_end` нет**: `r2o_udp_sessions` не хранит `udp_hold_active`, а `r2o_begin_hold` ограничивает попытки через `hold_attempts/hello_seen/plan_applied`. P — разный жизненный цикл hold. |
| `d2k_udp_path_pre` | 15–33 | 19 | flush истёкших, `session_udp_hold_begin`, `hold_feed_marked`; при отказе feed — `hold_end` | `main.rs:1560-1635` flush/release + begin_hold + feed | **P** | C: flush с release-callback → `hold_begin` → `feed_marked`; при отказе feed вызывает `hold_end`. Rust: `r2o_flush(now)` + `r2o_release_udp_batches`, затем `r2o_begin_hold` и `r2o_feed`; `Held` без собранного ClientHello делает `continue` без отката, `Overflow` отпускает пачку, `Refused` ничего; `hold_end` отсутствует. Логика близка, но ветви rollback/held-без-hello различаются. |
| `d2k_udp_path_post` | 35–60 | 26 | `udp_hold_wait` → HELD/NORMAL; `udp_hold_ready` → take/replay → REPLAY, иначе LOST; `fed` → take/release → RECLAIMED | `main.rs:1600-2210` (late tail/replay/release) | **P** | C возвращает один из четырёх кодов и явно вызывает `hold_replay`/`hold_end`. Rust разносит это по веткам `PacketDecision`, `r2o_udp_handle_late_tail`, `r2o_mark_hold_replay_first` и `r2o_release_udp_batch`; отдельной функции с теми же четырьмя исходами нет. P — нужен differential на HELD/REPLAY/LOST/RECLAIMED. |
| `d2k_udp_path_read` | 62–67 | 6 | `rseq++`, `seq=rseq`, `now_ns` | `main.rs:1340` `udp_receive_seq` | **P** | C инкрементирует `rseq` без защиты от нуля; Rust `wrapping_add(1).max(1)` — при переполнении C даёт `seq=0`, Rust `1`. На практике 64-битный счётчик не переполняется; отличие зафиксировано. |
| `d2k_udp_path_expire` | 69–74 | 6 | `seq = read_follows ? rseq+1 : NONE`, flush по таймеру | `main.rs:1330-1345` flush + release + `follow.age` | **P** | C `D2K_UDP_SEQ_NONE` для отсутствия чтения; Rust `follow_receive_seq = received ? udp_receive_seq : 0`, затем `r2o_flush`/`r2o_release_udp_batches`/`r2o_age`. Семантика 0/NONE совпадает, но `max(1)` и порядок flush/release/age разнесены. |
| `d2k_udp_path_passed` | 76–88 | 13 | пассивный проход: IPv4, len≥20, `udp_opening`, neutral, follow_mark(0,seq) | `main.rs:108 r2o_udp_mark_plain_pass` | **P** | Rust дополнительно требует `view.protocol==17` и `fragment & 0x3fff == 0` через `PacketView`, C проверяет только `len>=20` и версию IPv4; C `d2k_udp_out_neutral` и Rust `r2o_udp_packet_is_neutral` учитывают route/probe mark. `follow_mark(...,0,seq)` ↔ `follow.r2o_mark(packet, now, None, receive_seq)`. P. |
| `d2k_udp_path_planned` | 90–97 | 8 | плановая посылка: те же проверки + follow_mark(at_ns,seq) | `main.rs:131 r2o_udp_mark_planned` | **P** | То же отличие proto/fragment; `at_ns` ↔ `Option<Instant> at`, `seq` ↔ `receive_seq`. Отдельного differential на planned-путь с `at` нет. |

### datapath/udp_path.c: построчная сверка

- **`d2k_udp_path_release` (6–13) ↔ `r2o_release_udp_batch`
  (`main.rs:153`):** C закрывает session-hold (`udp_hold_active=0`) и
  отдаёт всю пачку `NF_ACCEPT` через `d2k_udp_out_batch`. Rust
  отпускает голову/хвосты через `r2o_release_batch_with`, помечает
  follow и пишет ошибки; **прямого `hold_end` нет** — состояние hold
  в `r2o_udp_sessions` выражено через `hold_attempts/hello_seen/
  plan_applied`. P.
- **`d2k_udp_path_pre` (15–33) ↔ `main.rs:1560-1635`:** оба делают
  flush истёкших, `begin_hold`, `feed`. C при отказе feed вызывает
  `hold_end`; Rust `Held` без ClientHello делает `continue` без
  отката, `Overflow` отпускает пачку, `Refused` ничего. P.
- **`d2k_udp_path_post` (35–60) ↔ `main.rs:1600-2210`:** C возвращает
  `HELD/REPLAY/LOST/RECLAIMED` одной функцией; Rust разносит исходы по
  `PacketDecision`, `r2o_udp_handle_late_tail`,
  `r2o_mark_hold_replay_first` и `r2o_release_udp_batch`. P.
- **`d2k_udp_path_read` (62–67) ↔ `udp_receive_seq`:** C `rseq++` без
  защиты от 0; Rust `wrapping_add(1).max(1)`. При переполнении
  `u64` C даёт 0, Rust — 1; практически недостижимо. P.
- **`d2k_udp_path_expire` (69–74) ↔ `main.rs:1330-1345`:** C
  `seq = read_follows ? rseq+1 : NONE`, затем flush; Rust
  `follow_receive_seq = received ? udp_receive_seq : 0`, затем
  `r2o_flush` → release → `r2o_age`. Семантика 0/NONE совпадает,
  порядок и `max(1)` отличаются. P.
- **`d2k_udp_path_passed` (76–88) ↔ `r2o_udp_mark_plain_pass`:** Rust
  дополнительно проверяет `protocol==17` и `fragment & 0x3fff == 0`
  через `PacketView`; C — только `len>=20` и IPv4. Neutral учитывает
  route/probe mark в обоих. `follow_mark(...,0,seq)` ↔
  `follow.r2o_mark(..., None, receive_seq)`. P.
- **`d2k_udp_path_planned` (90–97) ↔ `r2o_udp_mark_planned`:** те же
  отличия proto/fragment; `at_ns` ↔ `Option<Instant>`, `seq` ↔
  `receive_seq`. P.

## datapath/udp_release.c (34 функции)

Очередь отложенных вердиктов, судьбы повторной отправки пачки, окно follow
(5 мс), нейтральность метки, out_batch/out_late. R2O: `r2o_udp_hold.rs`
(`R2oUdpDeferredVerdicts`, `R2oUdpFollowTable`, `R2oUdpDeferredResends`,
`r2o_release_batch_with`), `main.rs`.

**Прочитано построчно: 34/34 функции, 509 строк C (1–509).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_udp_release_new` | 29–51 | 23 | очередь `slots×batch_size`, проверка `slots*batch_size`/нулей, три `calloc`, раскладка указателей | `r2o_udp_hold.rs:283 R2oUdpDeferredVerdicts::new` (16×8) | **P** | **Совпадает:** ёмкость очереди и проверка нулей. **Отличие:** C принимает `slots`/`batch_size` параметрами и считает `slots*batch_size` с защитой от переполнения; Rust фиксирован на 16 слотах по 8 ID. OOM-ветка C отдельная, Rust `Vec::with_capacity` может паниковать. |
| `d2k_udp_release_free` | 53–59 | 7 | освободить verdicts/ids/slot/queue | `Drop` | **E** | RAII; C освобождает три массива, Rust — владеющие `Vec`/`Box`. |
| `d2k_udp_release_enqueue` | 61–81 | 21 | проверить аргументы и `count<=batch`, найти свободный слот, скопировать ids/verdicts, `due/seq=next_seq++/key/token/count` | `r2o_udp_hold.rs:291 r2o_enqueue` | **P** | **Совпадает:** поиск свободного слота, копирование ID/вердиктов, отказ при полной очереди. **Отличия:** C хранит `seq` и `token` (номер поколения/исполнения), Rust — `order` и `flow_key`; C `next_seq++` без защиты от переполнения, Rust wrapping; C возвращает -1/0, Rust `bool`/`Option`. |
| `next_due` (static) | 83–94 | 12 | минимальный `(due_ns, seq)` среди `due<=now` | `r2o_udp_hold.rs:355` (`min_by_key(due,order)`) | **P** | **Совпадает:** выбирается созревший слот с минимальным `(due,seq)`. Rust использует `(due,order)` и `min_by_key`; при равных due порядок стабилен. Отдельного теста на равные due нет. |
| `d2k_udp_release_flush` | 96–122 | 27 | выдать все созревшие: `send` каждый ID, `complete=0` при ошибке, `done(key,token,complete,sent)`, освободить слот | `r2o_udp_hold.rs:345 r2o_flush` | **P** | **Совпадает:** цикл по созревшим, отправка каждого ID, освобождение слота. **Отличия:** C вызывает `done(ctx,key,token,complete,sent)` и считает `sent`; Rust собирает `first_error`, возвращает число пачек, callback `done`/`token` отсутствуют. C продолжает после ошибки `send`, Rust тоже; форма результата иная. |
| `d2k_udp_release_next_ns` | 124–133 | 10 | абсолютный минимальный due (ns), 0 если пусто | `r2o_udp_hold.rs:392 timeout_ms` | **P** | C отдаёт абсолютные ns; Rust — относительные ms с `max_ms` и `0` при `deadline<=now`. Для poll эквивалентно, отдельного absolute-getter нет. |
| `d2k_udp_replay_fates` | 135–154 | 20 | судьбы пачки: owned head → DROP; хвост при `can_resend` → DROP+resend; иначе ACCEPT; вернуть число повторных | `r2o_udp_hold.rs:72 r2o_release_batch_with` (инлайн) | **P** | **Совпадает:** owned голова не повторяется (DROP), хвосты при возможности уходят raw (DROP+resend), иначе ACCEPT. **Отличия:** C отдельная функция с массивами `verdicts[]/resend[]`; Rust вычисляет `can_send_raw` в цикле и учитывает `head_succeeded`, `neutral`, `resend_busy/failed`; `owned` форсирует `can_resend` в C, Rust `head_succeeded`. |
| `plain_verdict` (static) | 174–177 | 4 | адаптер `verdict(ctx,id,v)` | замыкание `send_verdict` | **E** | Тонкий адаптер без логики; C и Rust вызывают один и тот же вердикт. |
| `plain_resend` (static) | 178–182 | 5 | адаптер `resend(ctx,pkt,len)` без ID | замыкание `resend` | **E** | C игнорирует `id` и возвращает 0/-1; Rust замыкание возвращает `io::Result`. Семантика та же. |
| `d2k_udp_release_batch` | 184–192 | 9 | обёртка `release_batch` с plain-адаптерами | `r2o_udp_hold.rs:72 r2o_release_batch_with` | **P** | C-обёртка передаёт `verdict/resend` через `plain_ctx`; Rust вызывает `r2o_release_batch_with` напрямую. Логика в `release_batch`/`r2o_release_batch_with`; P наследуется. |
| `release_batch` (static) | 194–247 | 54 | ядро: `replay_fates`, fallback при `vfail&&!owned`, `may[]`→ACCEPT+defer, resend 1/0/-1, verdict, счётчики | `r2o_udp_hold.rs:72 r2o_release_batch_with` | **P** | **Подтверждённые отличия:** (1) C имеет `may[]` (ненейтральная метка) и при `defer` откладывает ACCEPT; Rust `r2o_release_batch_with` не имеет `may[]`/defer и сразу отдаёт ACCEPT ненейтральному хвосту; (2) C `owned` форсирует `can_resend` и при `vfail&&!owned` откатывает raw-хвост в ACCEPT; Rust учитывает `head_succeeded`/`resend_busy`/`resend_failed`; (3) C `resend` возвращает 1 — ID забирает очередь, 0 — отправлено, -1 — откат; Rust `r2o_release_batch_with` различает `resend_failed`/`resend_busy` и `on_permanent_failure`; (4) C считает `fell_back` включая ненейтральные, Rust `resend_failed` — только ошибки raw. |
| `follow_stale` (static) | 272–275 | 4 | устаревание: `now>=until` и не та же пачка `seq`, затем `e.seq==0` или `seq!=0 && e.seq<seq` | `r2o_udp_hold.rs:550 r2o_match` (stale) | **E*** | **Точное совпадение формулы:** C (`udp_release.c:272-275`) и Rust `r2o_match`/`r2o_age` используют те же условия: запись живёт до `until`, совпадающая текущая пачка (`seq`) её не старит, запись без seq старится только при seq=0, иначе — при меньшем seq. Отдельного differential нет. |
| `follow_drop` (static) | 277–280 | 4 | `used=0`, `live--` | `r2o_udp_hold.rs:565/611` | **E** | C уменьшает `live` только если был used; Rust `retain`/`Option` и `saturating_sub`. Эквивалентно. |
| `d2k_udp_follow_age` | 282–287 | 6 | обход слотов, снять stale | `r2o_udp_hold.rs:602 r2o_age` | **P** | C останавливает обход при `live==0`; Rust проходит все слоты и удаляет stale. Набор удалённых тот же; порядок/стоимость иные. |
| `d2k_udp_follow_live` | 289 | 1 | число живых записей | `r2o_udp_hold.rs:490 r2o_stats` | **E** | Прямой getter; тест `:830 follow_stats_*`. |
| `d2k_udp_follow_busy` | 290 | 1 | счётчик busy | `:490 r2o_stats` | **E** | Прямой getter; `:830`. |
| `d2k_udp_follow_queue_full` | 291 | 1 | счётчик queue_full | `:490 r2o_stats` | **E** | Прямой getter; `:830`. |
| `d2k_udp_follow_refused` | 292 | 1 | счётчик refused | `:490 r2o_stats` | **E** | Прямой getter; `:830`. |
| `d2k_udp_send_busy` | 294–296 | 3 | EAGAIN/EWOULDBLOCK/ENOBUFS | `main.rs:799 r2o_udp_send_busy` | **E** | **Точное совпадение:** C `err == EAGAIN || EWOULDBLOCK || ENOBUFS`; Rust `r2o_udp_send_busy` те же errno. Тест `:852`. |
| `d2k_udp_follow_new` | 298 | 1 | `calloc` таблицы | `:480 new` | **E** | C `calloc`/NULL при OOM; Rust `Default`/`new`. Обычный путь эквивалентен. |
| `d2k_udp_follow_free` | 300 | 1 | `free` | `Drop` | **E** | RAII. |
| `follow_tuple` (static) | 302–319 | 18 | UDP-кортеж; отказ IPv4 MF, broadcast/multicast, иным proto | `:428 R2oUdpFollowKey::from_packet` | **P** | **Совпадает:** proto 17, отказ IPv4-фрагмента (MF), v4 `dst[0]>=224`, v6 `dst[0]==0xff`. **Отличие:** C проверяет `d2k_packet_parse` (принимает первый фрагмент), Rust `PacketView::parse` + `fragment & 0x3fff == 0`, то есть отвергает и смещённые фрагменты; для первого фрагмента с MF оба отказывают. |
| `same_tuple` (static) | 321–324 | 4 | family/src/dst/ports | `#[derive(Eq)]` | **E** | C `memcmp` 16+16+4 и family; Rust типизированный `Eq`. |
| `d2k_udp_follow_mark` | 329–332 | 4 | поставить окно, 0/-1 | `:508 r2o_mark` | **P** | C `follow_put` возвращает запись/NULL → 0/-1; Rust `r2o_mark` возвращает `bool`/`Result`. Семантика та же. |
| `follow_put` (static) | 334–355 | 22 | `until=max(now,at)+5мс`, `at_ns=at>now?at:0`, поиск same-tuple или свободного/самого раннего, live++ | `:508 r2o_mark` | **P** | **Совпадает:** окно 5 мс, `at` только если в будущем, same-tuple переиспользуется, вытеснение по `until`, `live++` для новой. **Отличия:** C хранит `seq/at_ns/noted/failed`; Rust `R2oUdpFollowEntry` — `deferred_at/failed/noted?`; C выбирает свободный слот раньше самого раннего, Rust — по `min_by_key`. |
| `follow_find` (static) | 357–370 | 14 | найти окно, попутно снять stale, вернуть `at_ns` | `:550 r2o_match` | **P** | **Совпадает:** stale удаляется на ходу; запись считается действующей при `e.seq==seq` или `now<until`; сравнение кортежа. **Отличие:** C возвращает `at_ns` через `d2k_udp_follow_match`, Rust — `Option<R2oUdpFollowMatch { at, failed }>`. |
| `d2k_udp_follow_match` | 372–378 | 7 | match + `at_ns` | `:550 r2o_match` → `R2oUdpFollowMatch` | **E*** | **Совпадает:** при найденном окне возвращает `at_ns`; Rust `r2o_match` возвращает `Option` с `at`/`failed`. Unit `main.rs:4922`, D6. |
| `out_resend` (static) | 388–415 | 28 | raw по `send_at_owned`/`send_at`/`send_now`; ENOSPC→queue_full, busy→busy, иначе первый failed; 1/0/-1 | `main.rs:226 r2o_udp_handle_late_tail`, `:250` deferred | **P** | **Совпадает:** при `at>now` и наличии `send_at_owned` ID забирает очередь (`taken=1`), иначе `send_at`/`send_now`; ENOSPC и busy считаются отдельно; первый постоянный отказ запоминается. **Отличия:** C возвращает 1/0/-1, Rust `io::Result`/`bool`; C `at>now && !send_at` → -1, Rust `None` → `NotConnected`; C `errno` сохраняется, Rust `io::Error`. |
| `d2k_udp_out_owned_emit` | 417–421 | 5 | вердикт владеемой посылки: busy→busy++; err→ACCEPT, иначе DROP | `main.rs:4335 release_with` | **P** | **Совпадает:** ошибка → ACCEPT (копия идёт ядром), успех → DROP (копия снята); busy учитывается. **Отличие:** C возвращает -1/0, Rust `release_with` возвращает `Result`; отдельного имени нет. |
| `refused_flow` (static) | 425–430 | 6 | `++follow->refused` на **каждый** отказ; лог первых `D2K_UDP_REFUSED_LOG` | `main.rs:285 follow.r2o_mark_failed` | **P** | **Подтверждённое отличие счётчика:** C увеличивает `refused` **на каждый** отказ и логирует первые 64; Rust `r2o_mark_failed` ставит `failed` один раз на поток и возвращает `bool`, поэтому повторные отказы того же потока не увеличивают `refused`. Число в сводке может отличаться. |
| `out_verdict` (static) | 432–435 | 4 | адаптер вердикта | `queue.send_verdict` | **E** | Тонкий адаптер. |
| `d2k_udp_out_neutral` | 437–440 | 4 | mark 0/neutral_mark → 1; иначе routed и не routed-политика | `main.rs:88 r2o_udp_packet_is_neutral` | **P** | **Совпадает:** mark 0 и neutral_mark нейтральны; иначе neutral только если метка не выбирает политику (`routed`). **Отличие:** C принимает `ipver`/`routes`; Rust проверяет `r2o_mark_is_routed`/policy, набор аргументов иной. |
| `d2k_udp_out_batch` | 442–473 | 32 | выпуск пачки: `may[]`, `marked_tail`, `release_batch`, `refused_flow`, `follow_put` головы с at/seq | `main.rs:153 r2o_release_udp_batch` | **P** | **Совпадает:** нейтральность каждой датаграммы, raw-хвосты, отметка marked при первом ненейтральном хвосте, follow-запись головы, счётчик отказа. **Отличия:** C `release_batch` с `may[]`/defer; Rust `r2o_release_batch_with` без `may[]`/defer, `mark_failed` один раз; C `at`/`seq` для follow, Rust `R2oUdpFollowTable` и `deferred_at`. |
| `d2k_udp_out_late` | 475–509 | 35 | поздний хвост: follow-match, failed→0, marked/defer→ACCEPT, resend, verdict | `main.rs:226 r2o_udp_handle_late_tail` | **P** | **Совпадает:** без follow/failed — обычный путь; ненейтральная метка помечается и при отложенной голове уходит ACCEPT через `defer`; иначе raw-resend, при ошибке ACCEPT/отметка failed. **Отличия:** C `defer_verdict` с `at_ns`; Rust `r2o_deferred_verdicts`/`r2o_deferred_resends`; C `e->failed` на потоке, Rust `follow.r2o_mark_failed`; возврат 0/1 и `verdict_failed`. |

### datapath/udp_release.c: построчная сверка

- **Очередь `d2k_udp_release_new/enqueue/next_due/flush/next_ns`
  (29–133) ↔ `R2oUdpDeferredVerdicts` (`r2o_udp_hold.rs:283`):** C
  принимает `slots×batch_size`, проверяет переполнение `slots*batch`,
  хранит `key/token/seq`, `next_seq++`; Rust фиксирован на 16×8,
  `flow_key` выводит из пакета, `order++`, token отсутствует. `next_due`
  C — минимум `(due,seq)` среди `due<=now`; Rust `r2o_flush` —
  `min_by_key((due,order))`, формула совпадает, отдельного теста на
  равные `due` нет. `flush`: C считает `complete/sent` и вызывает
  `done(ctx,key,token,complete,sent)`; Rust отправляет все ID, копит
  `first_error`, возвращает число пачек — callback и `token` отсутствуют.
  `next_ns` C — абсолютные ns; Rust `timeout_ms` — относительные ms.
  P.
- **`d2k_udp_replay_fates`/`d2k_udp_release_batch`/`release_batch`
  (135–247) ↔ `r2o_release_batch_with` (`:72`):** C строит массивы
  `verdicts[]/resend[]`: owned head → DROP, хвосты → DROP+resend при
  `can_resend`, иначе ACCEPT; `may[]` запрещает raw для ненейтральной
  метки, `defer` откладывает вердикт за отложенной головой, `owned`
  форсирует `can_resend`. Rust: `head_succeeded`, затем для каждого
  хвоста `can_send_raw = head_succeeded && can_resend && neutral`;
  при ошибке raw — ACCEPT, `resend_failed/resend_busy`,
  `on_permanent_failure`; при ошибке DROP-вердикта — повтор с ACCEPT.
  **Отличия:** Rust не имеет `may[]`, `defer`-callback и `owned`-
  параметра; `resend_failed` считает только ошибки raw, а C
  `fell_back` — ещё и ненейтральные метки; ненейтральный хвост C может
  отложить через `defer`, Rust в `release_batch_with` сразу отдаёт
  ACCEPT. P.
- **`follow_stale/follow_drop/follow_age/live/busy/queue_full/refused`
  (272–296) ↔ `R2oUdpFollowTable` (`:420`):** формула stale совпадает:
  `now>=until && !same_seq && (seq==0 || (seq!=0 && entry.seq<seq))`.
  C останавливает обход при `live==0`, Rust проходит все слоты; live--
  и saturating_sub эквивалентны. Счётчики busy/queue_full/refused —
  E; `refused_flow` (425–430) считает **каждый** отказ
  (`++follow->refused`) и логирует первые 64, Rust `r2o_mark_failed`
  считает **один раз на поток** (`if !failed`), поэтому семантика
  счётчика разная. P.
- **`follow_tuple/same_tuple/follow_mark/follow_put/follow_find/
  follow_match` (302–378) ↔ `R2oUdpFollowKey`/`r2o_mark`/`r2o_match`:**
  C `d2k_packet_parse` + proto 17, отвергает IPv4 MF, v4
  `dst[0]>=224`, v6 `dst[0]==0xff`; Rust `from_packet` требует
  `fragment & 0x3fff == 0` (эквивалентно MF+offset) и те же multicast.
  `until = max(at,now)+5 мс`, `at_ns = at>now ? at : 0` ↔
  `deferred_at = at>now`, `anchor = deferred_at.unwrap_or(now)`.
  Rust не хранит `noted`; `follow_find` C возвращает `at_ns`, Rust
  `r2o_match` — `Option<{at,failed}>`. P.
- **`out_resend/out_owned_emit/refused_flow/out_verdict/
  out_neutral/out_batch/out_late` (388–509):** C `out_resend` умеет
  `send_at_owned` (deferred queue забирает ID, `taken=1`), `send_at`,
  `send_now`, `ENOSPC`→`queue_full`, busy→`busy`, иначе первый
  `failed_pkt`; `out_batch` считает `may[]`, `marked_tail`,
  `defer_verdict`, `follow_put` с `at`, `noted/failed`; `out_late`
  отдельно обрабатывает follow-match, marked, `defer_verdict` и
  `out_resend`. Rust разносит это между `r2o_release_batch_with`
  (immediate raw), `r2o_udp_handle_late_tail` (deferred_resends/
  deferred_verdicts), `r2o_udp_packet_is_neutral` и
  `r2o_mark_failed`; **нет** `send_at_owned/taken` в release-пути,
  нет `noted`, `marked`-callback и `defer` в `release_batch_with`.
  P — нужен differential на late-tail/ENOSPC/owned.

## datapath/nfq.c (12 функций)

NFQUEUE: netlink bind/params с ACK, SO_RCVBUF(FORCE), recv ENOBUFS, вердикты.
R2O: `nfqueue.rs`, `netlink.rs`.

**Прочитано построчно: 12/12 функций, 315 строк C (1–315).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `say` (static) | 33–41 | 9 | `vsnprintf` ошибки в буфер `err/cap` | `io::Error`/`format!` | **P** | C пишет текст в переданный буфер; Rust возвращает `io::Error`/`Display`, вызывающий логирует. Контракт «не падать, отдать причину» тот же, тексты не сверяются. |
| `nl_write` (static) | 43–57 | 15 | `sendto` с EINTR-retry; короткая запись → -1 | `nfqueue.rs:416 send_to_kernel` | **E** | Оба повторяют `sendto` на EINTR и отвергают короткую запись (C -1, Rust `WriteZero`). |
| `await_ack` (static) | 61–109 | 49 | poll 1000 мс × 8, EINTR-retry, разбор `NLMSG_ERROR`, сверка seq | `nfqueue.rs:342 await_ack`, `:366 await_ack_with` | **E** | C `poll(...,1000)` ×8, `recv`, `d2k_nl_iter`, `m.seq`, `d2k_nl_errno`; Rust `ACK_TIMEOUT_MS=1000`, `ACK_ATTEMPTS=8`, `MessageIter`, `message.sequence`, `kernel_error`. Тест `nfqueue.rs:480`. |
| `send_and_ack` (static) | 111–122 | 12 | len==0 → ошибка; `nl_write`; `await_ack(seq)` | `nfqueue.rs:336 configure` | **P** | C принимает seq параметром; Rust извлекает seq из netlink-заголовка (`message[8..12]`), затем `send_to_kernel` + `await_ack`. Эквивалентно; отдельного теста `configure` нет. |
| `set_rcvbuf` (static) | 127–145 | 19 | `SO_RCVBUFFORCE` → `SO_RCVBUF`, `getsockopt`; 0/1/-1 | `nfqueue.rs:13 set_receive_buffer_with` | **E** | C возвращает 0 при `effective>=requested`, 1 при cap, -1 при ошибке; Rust возвращает effective, `open` сравнивает и логирует. Тесты `:512`, `:535`, `:563`. |
| `d2k_nfq_open` | 147–230 | 84 | socket/bind/BIND+ACK/PARAMS(fail_open,GSO off), rcvbuf | `nfqueue.rs:115 open` | **P** | C: `AF_NETLINK/SOCK_RAW`, bind pid0, `BIND AF_INET`, `PARAMS` с `fail_open` и маской GSO. Rust: `SOCK_CLOEXEC`, `bind`, `config_command(BIND, protocol_family)`, `config_params(fail_open)`, rcvbuf; **добавлены family 2/10 и валидация copy_range≥64/max_len≠0**, C фиксирован на AF_INET. GSO-маска в Rust задаётся в `netlink::config_params` (проверить построчно). P. |
| `d2k_nfq_close` | 232–248 | 17 | UNBIND без ACK, close, free | `nfqueue.rs:404 Drop` | **P** | Оба посылают UNBIND без ожидания ACK; C делает `close/free`, Rust `OwnedFd` + Drop. Эквивалентно, отдельного close-API нет. |
| `d2k_nfq_fd` | 250–252 | 3 | fd или -1 | `nfqueue.rs` `AsRawFd` | **P** | C отдаёт `-1` для NULL; Rust `AsRawFd` всегда валиден (OwnedFd). Для непустого объекта эквивалентно. |
| `d2k_nfq_recv` | 254–274 | 21 | recv; EAGAIN/EWOULDBLOCK/EINTR→0, ENOBUFS→lost++, -2, иначе -1 | `nfqueue.rs:190 receive`, `:195 receive_timeout` | **P** | **Расхождение:** C `recv` при EINTR/EAGAIN/EWOULDBLOCK возвращает 0 (wait); Rust `receive_timeout_with_fd` маппит ENOBUFS в `LostPackets`, а прочие ошибки `recv` — в `ReceiveError::Io`; `ReceiveError::Wait` используется для ошибок `poll`, не для EINTR/EAGAIN `recv`. Вызывающий `main.rs` может по-разному трактовать wait/io. ENOBUFS-счётчик совпадает. |
| `d2k_nfq_verdict` | 276–292 | 17 | вердикт без payload | `nfqueue.rs:310 send_verdict` | **E** | C `d2k_nl_verdict` + `nl_write`; Rust `verdict` + `send_to_kernel`, плюс `record_verdict`. Тесты `netlink.rs:304`. |
| `d2k_nfq_verdict_payload` | 294–311 | 18 | вердикт с заменой до 2048 байт | `nfqueue.rs:317 send_replacement` | **E** | C `d2k_nl_verdict_payload` + `nl_write`; Rust `verdict_payload(NF_ACCEPT)` + `send_to_kernel`; лимит буфера 64+2048. Тесты `netlink.rs:321`. |
| `d2k_nfq_lost` | 313–315 | 3 | счётчик потерянных пакетов | `nfqueue.rs:271 lost_packets` | **E** | C `q->lost`, Rust `Cell<u64>` с saturating_add; тест `:492`. |

### datapath/nfq.c: построчная сверка

- **`say` (33–41) ↔ `io::Error`:** C `vsnprintf` в `err/cap`;
  Rust возвращает ошибку, вызывающий логирует. P — текст не сверяется.
- **`nl_write` (43–57) ↔ `send_to_kernel` (`nfqueue.rs:416`):**
  EINTR-retry и отказ короткой записи совпадают. E.
- **`await_ack` (61–109) ↔ `await_ack_with` (`:366`):** C
  `poll(1000)` ×8, `recv`, `d2k_nl_iter`, `seq`, `d2k_nl_errno`;
  Rust `ACK_TIMEOUT_MS=1000`, `ACK_ATTEMPTS=8`, `MessageIter`,
  `sequence`, `kernel_error`. E, тест `:480`.
- **`send_and_ack`/`set_rcvbuf`:** C `send_and_ack` + `await_ack`;
  Rust `configure` извлекает seq из заголовка. C `set_rcvbuf` даёт
  0/1/-1, Rust `set_receive_buffer_with` — effective, `open`
  сравнивает и логирует. P/E.
- **`d2k_nfq_open` (147–230) ↔ `QueueSocket::open` (`:115`):** C
  фиксирован на `AF_INET`, Rust принимает family 2/10 и валидирует
  `copy_range>=64`, `max_len!=0`; оба делают bind pid0, BIND+ACK,
  PARAMS с `fail_open`; GSO выключается через `netlink::config_params`.
  P — набор family/валидаций шире.
- **`close`/`fd`:** C UNBIND без ACK + `close/free`, `fd` или -1;
  Rust `Drop` + `OwnedFd`/`AsRawFd`. P — API иной, поведение то же.
- **`d2k_nfq_recv` (254–274) ↔ `receive_timeout_with_fd`:** C
  EAGAIN/EWOULDBLOCK/EINTR → 0 (wait), ENOBUFS → `lost++`, -2;
  Rust ENOBUFS → `LostPackets`, а EINTR/EAGAIN `recv` → `Io`, не
  `Wait`. `Wait` используется для ошибок `poll`. P — вызывающий может
  по-разному трактовать wait/io; ENOBUFS-счётчик совпадает.
- **`verdict`/`verdict_payload`/`lost`:** C `d2k_nl_verdict*` +
  `nl_write`, `q->lost`; Rust `verdict*` + `send_to_kernel` +
  `record_verdict`, `Cell<u64>`. E, тесты `netlink.rs:304/321`,
  `nfqueue.rs:492`.

## datapath/nl.c (19 функций)

Netlink/NFQUEUE кодек: итератор сообщений, атрибуты пакета, сборка вердиктов и
конфигурации. R2O: `netlink.rs`.

**Прочитано построчно: 19/19 функций, 309 строк C (1–309).**

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
| `d2k_nl_packet` | 79–161 | 83 | атрибуты NFQA: hdr/payload/cap/ts/mark/oif | `netlink.rs:125 QueuePacket::parse` | **P** | Все поля совпадают: `PACKET_HDR` (id/hw_protocol/hook при vlen≥7), `PAYLOAD`, `CAP_LEN`, `SKB_INFO`, `MARK`, `TIMESTAMP` (sec/usec, границы), `IFINDEX_OUTDEV`. **Расхождение `truncated`:** C `out->truncated = cap_len > payload_len` даже при отсутствии `PAYLOAD` (`payload_len=0`), Rust `cap_len.zip(payload).is_some_and(cap>len)` — без `PAYLOAD` даёт `false`. Тесты `:371`, `:403` этот случай не покрывают. |
| `d2k_nl_errno` | 163–176 | 14 | знаковый errno из NLMSG_ERROR | `netlink.rs:183 kernel_error` | E | `:429 kernel_error_reads...` |
| `hdr_init` (static) | 181–197 | 17 | nlmsghdr+nfgenmsg | `netlink.rs:263 header` | E | `:332` |
| `put_attr` (static) | 200–216 | 17 | атрибут + zero padding | `netlink.rs:274 push_attr` | E | `:321` |
| `d2k_nl_verdict` | 218–234 | 17 | VERDICT | `netlink.rs:188 verdict` | E | `:304` |
| `d2k_nl_verdict_payload` | 236–252 | 17 | VERDICT+PAYLOAD | `netlink.rs:203 verdict_payload` | E | `:321` |
| `d2k_nl_cfg_cmd` | 254–273 | 20 | CONFIG BIND/UNBIND, ACK | `netlink.rs:219 config_command` | E | `:332` |
| `d2k_nl_cfg_params` | 275–309 | 35 | PARAMS/MAXLEN/FLAGS/MASK | `netlink.rs:234 config_params` | E | `:332` |

### datapath/nl.c: построчная сверка

- **`align4/h16/h32/wh16/wh32/n16/n32/wn16/wn32` (10–35) ↔
  `netlink.rs`:** C `align4` без проверки переполнения, Rust
  `checked_add(3)`; для длин netlink-сообщений разница недостижима.
  Host-endian поля — `memcpy` ↔ `from_ne_bytes/to_ne_bytes`, сетевые —
  `n16/n32/wn16/wn32` ↔ `from_be_bytes/to_be_bytes`. E.
- **`d2k_nl_iter_init`/`d2k_nl_next` (37–77) ↔ `MessageIter`
  (`:64`):** C проверяет `left<hdr`, `mlen<16 || mlen>left`, берёт
  type/flags/seq/pid/body, `step=align4(mlen)`, при `step>=left`
  гасит итератор; Rust те же проверки, `step>=remaining` →
  `bytes.len()`. Непакованный последний сообщение и битая длина
  покрыты `:355`. E.
- **`d2k_nl_packet` (79–161) ↔ `QueuePacket::parse` (`:125`):** все
  атрибуты и границы совпадают, включая timestamp-границы
  `sec!=0/17e9`, `usec<1e6`, `skb_info`, `outdev`, `mark`, `cap_len`.
  **Отличие:** `truncated = cap_len > payload_len` в C считается и при
  отсутствующем `PAYLOAD` (`payload_len=0`), Rust использует
  `cap_len.zip(payload)` и без payload даёт `false`. P.
- **`d2k_nl_errno` (163–176) ↔ `kernel_error` (`:183`):** C требует
  `NLMSG_ERROR` и body≥4, читает host-endian signed i32; Rust то же.
  E, `:429`.
- **`hdr_init/put_attr/verdict/verdict_payload/cfg_cmd/cfg_params`
  (181–309) ↔ `header/push_attr/verdict/verdict_payload/
  config_command/config_params`:** заголовок 16+4, `nfgen_family=0`,
  version 0, queue BE; `put_attr` выравнивает и зануляет padding;
  verdict-attr 8 байт (action/id BE); payload ≤ `u16::MAX-4`; CFG
  BIND/UNBIND с ACK, params copy_range+copy_mode, MAXLEN, FLAGS, MASK
  (FAIL_OPEN|GSO). E, тесты `:304/321/332`.

## datapath/icmpguard.c (7 функций)

Отсечение ICMP time-exceeded на свои фальшивки с пониженным TTL.
R2O: `r2o_icmp_guard.rs`.

**Прочитано построчно: 7/7 функций, 113 строк C (1–113).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_icmpguard_init` | 6–8 | 3 | обнулить кольцо 256 | `Default for R2oIcmpGuard` (`:32`) | **E** | C `memset`, Rust `[Slot::default(); 256]` + счётчики 0. |
| `u16` (static) | 10 | 1 | big-endian u16 | `r2o_icmp_guard.rs:257 r2o_u16` | **E** | C `(p[0]<<8)|p[1]`; Rust `from_be_bytes` с проверкой границ через `get`. |
| `parse_ip` (static) | 21–47 | 27 | IP-заголовок цитаты: IPv4/IPv6, proto 6/17, отказ non-first fragment, `n>=hl+8` | `:204 r2o_parse_icmp_quote` | **P** | Построчно совпадает: family по версии; IPv4 `n>=20`, `hl=(p[0]&15)*4>=20`, `fragment & 0x1fff == 0`; IPv6 `n>=40`, `ip_id=0`; proto 6/17; `transport=get(hl..hl+8)`. Rust checked-арифметика (`checked_add`) вместо C `n<hl+8`. Unit-тестов в модуле нет; differential `test-icmp-guard-current-differential.sh` есть. |
| `d2k_icmpguard_note` | 49–69 | 21 | запомнить фальшивку: `ttl<orig_ttl`, ring 256, `at=now?now:1`, family/proto/ttl, src/dst, ports, l4word, ip_len, ip_id | `:56 r2o_note` | **P** | C для UDP копирует в `l4word` 2 байта (остаток занулён `memset`), Rust всегда копирует `transport[4..8]` (4 байта); `check` для UDP сравнивает только 2, поэтому на результат не влияет. `have_id = family==4 && ip_id!=0`, `at=max(now,1)`, ring 256 — совпадают. Differential `test-icmp-guard-current-differential.sh`. |
| `d2k_icmpguard_check` | 71–110 | 40 | ICMPv4 type 11/0, v6 type 3/0; `fragment & 0x3fff`, цитата family, 7 полей, `q.ttl<=s.ttl`, dropped++ | `:90 r2o_check`, `:175 r2o_icmp_quote_start` | **P** | C и Rust совпадают: IPv4 len/ihl/proto 1/`0x3fff`/type 11 code 0; IPv6 len 48/proto 58/type 3 code 0; `quote_start=hl+8/48`; `parse_ip` цитаты; family match; слоты 256, `at!=0`, `now>=at`, `now-at<=5с`, family/proto, src/dst (4/16), sport/dport, l4word (TCP 4/UDP 2), ip_len, `have_id/ip_id`, `q.ttl<=slot.ttl`; иначе dropped++. Отличие только в представлении (`memcmp` ↔ срезы). Unit-тестов в модуле нет; differential есть. |
| `d2k_icmpguard_dropped` | 112 | 1 | счётчик снятых | `:149 r2o_dropped` | **E** | Прямой getter; `u64` saturating/wrapping-add. |
| `d2k_icmpguard_noted` | 113 | 1 | счётчик запомненных | `:145 r2o_noted` | **E** | Прямой getter; `u64` saturating/wrapping-add. |

### datapath/icmpguard.c: построчная сверка

- **`d2k_icmpguard_init`/`u16`/`dropped`/`noted` (6–10, 112–113):**
  C `memset`, BE-u16, getters; Rust `Default`, `from_be_bytes`,
  `u64`-счётчики. E.
- **`parse_ip` (21–47) ↔ `r2o_parse_icmp_quote` (`:204`):** family
  по версии; IPv4 `n>=20`, `hl=(p[0]&15)*4>=20`,
  `fragment & 0x1fff == 0`; IPv6 `n>=40`, `ip_id=0`; proto 6/17;
  `transport = get(hl..hl+8)`. Rust заменяет C-арифметику на
  `checked_add`, результат тот же. P — unit-тестов в модуле нет,
  есть `test-icmp-guard-current-differential.sh`.
- **`d2k_icmpguard_note` (49–69) ↔ `r2o_note` (`:56`):** TTL ниже
  исходного, ring 256, `at=max(now,1)`, family/proto/ttl, src/dst,
  ports, `ip_len`, `have_id/ip_id` совпадают. **Отличие:** C для UDP
  копирует в `l4word` только 2 байта, Rust — 4; `check` для UDP
  сравнивает 2, поэтому результат тот же. P.
- **`d2k_icmpguard_check` (71–110) ↔ `r2o_check` (`:90`):** ICMPv4
  type 11/0, IPv6 type 3/0, `fragment & 0x3fff`, `quote_start`,
  family-match, 7 полей, `q.ttl<=slot.ttl`, `dropped++` — совпадают.
  Rust сравнивает срезы вместо `memcmp`. P — unit-тестов нет,
  differential есть.
- **R2O-расширения:** `r2o_handle_at_hook` (hook LOCAL_IN/FORWARD),
  `r2o_seen`, `r2o_stats_line` не имеют отдельных C-функций в
  `icmpguard.c`; в C их роль выполняет вызывающий код.

## datapath/http80.c (30 функций)

Провайдерская вставка в HTTP/80: таблица потоков, RTT по SYN/SYN-ACK, потоковый
разбор запроса/ответа, портал, 307+HTTPS name, RST. R2O: `hold.rs` (HTTP
observation), `control.rs` (https names), `http_replace.rs` (пакеты),
`r2k-core/httpup.rs`, `http_response.rs`.

**Прочитано построчно: 30/30 функций, 640 строк C (1–640).**

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
| `rd32` (static) | 532–535 | 4 | big-endian u32 | `r2k-core/src/packet.rs:236 read_u32` | **E*** | C `p[0]<<24\|p[1]<<16\|p[2]<<8\|p[3]`; Rust `read_u32` с проверкой границ. Используется в seq/ack; `tests/network.rs`. |
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

### datapath/http80.c: построчная сверка

- **`d2k_http80_new/free/get_stats` (67–79) ↔ `HoldTable` +
  `NamePlans`:** C один `calloc` на 128 flow + 256 имён; Rust
  `HoldTable`/`NamePlans` раздельно, HTTP-потоков до 1024 без
  вытеснения (см. header, п. 8). `free` — RAII; `get_stats` —
  композиция `r2o_hold_stats` + control stats, состав иной. P.
- **`name_norm` (83–95) ↔ `control.rs:2233 canonical_name`:** C
  снимает одну хвостовую точку, принимает LDH/точки, **односложные и
  числовые** имена; Rust требует ≥2 метки и хотя бы одну нецифровую.
  Подтверждённое расхождение для `SET_HTTPS`/`SET_SUFFIX`/`SET_BYPASS`.
- **`d2k_http80_set_https/https` (97–129) ↔ `control.rs:1055/590`:**
  C: add/remove по `expires==0`, 256 имён, вытеснение `min(expires)`;
  Rust `set_https`/`has_verified_https` с теми же лимитами, но
  канонизация имени строже (см. выше). P.
- **`wr16/wr32/sum16/fold/rd32` (133–147, 190–192) ↔
  `wire.rs:552/556/534/545`, `packet.rs:236`:** точные BE-записи,
  RFC1071 и свёртка; E.
- **`build` (156–188) ↔ `http_replace.rs:79 build_segment`:** C
  собирает IPv4/IPv6 IP+TCP без опций, TOS/TTL/flow label/ip_id,
  307/RST, пересчитывает суммы; Rust то же, тесты `:219`
  (v4/v6+суммы). E.
- **`stale/find/make` (196–236):** C линейный поиск 128 flow по
  family/портам/адресам, stale по `IDLE`, вытеснение самого старого
  с `evicted++`; Rust `hold.rs:1225 slot_index`/HTTP `Vec`, stale и
  вытеснение выражены иначе, лимит 1024. P.
- **`d2k_http80_executed` (238–254) ↔ `hold.rs:209
  note_http_execution`:** C требует `state==ST_REQUEST` и
  `request_seq==seq`, затем пишет execution/binding/plan/trial; Rust
  ищет flow по key+request_sequence и `!response_reported`, пишет
  `applied`. P — эквивалентно для нормального запроса, но проверка
  состояния/seq иная.
- **`request_result` (256–265) ↔ `finish_http_response`
  (`hold.rs:1269`):** C заполняет family/client/server/ports/
  execution/binding/request_ms/request_no/status/body_bytes/plan/
  trial/request_path/host; Rust формирует `HttpResponseEvent` с
  теми же полями, `request_path` только для GET без `?/#/\`. P.
- **`d2k_http80_delivered` (267–276) ↔ `reject_http_response`
  (`hold.rs:220`):** C при отказе доставки ставит `reply.invalid=1`,
  `complete=0`, `state=ST_DONE`, `response=2`; Rust сбрасывает
  `ready_for_next`, не меняя response/state. P — разный контракт
  отказа.
- **`seq_after` (281) ↔ `hold.rs:1318`:** точное `wrapping_sub`/i32.
  E.
- **`delivered/cut_pending/cut_result/sweep` (285–323) ↔
  `hold.rs:255-293`:** C `delivered=max(acked,reply_next)`,
  `cut_pending` требует `ST_REQUEST/body_end_known/!cut_told/
  header_done/!complete/!invalid/body_end>delivered`,
  `cut_result` считает `body_bytes=max(got,r->body_bytes)`, rtt,
  `DONE`; `sweep` — `quiet=3*rtt`, минимум 2 с. Rust
  `sweep_http_responses` `finish_http_response(flow,4,...)` +
  `reject_http_response`; тест `hold.rs:2082`. P — формулы совпадают,
  представление состояния и `response=4`/CUT иное.
- **`request_prefix/request_feed` (327–347) ↔ `httpup.rs:180/116`:**
  C `d2k_http_request` + GET/HEAD, target без `<=0x20/0x7f/#`,
  `host_len<256`, stream parser `header_done && !invalid &&
  !past_end && next==end`; Rust `r2o_http_plan_request`/
  `observe_detailed` с другими границами (target<2048, `#`
  отвергается, полные заголовки). P.
- **`d2k_http80_packet` (349–525) ↔ `hold.rs:1088
  observe_http_response` + `:356 feed_observing_mode`:** C
  state-machine `FREE/SYN/OPEN/IDLE/REQUEST/INJECTED/SWAP/ANSWERED/
  DONE`, RTT по SYN/SYN-ACK (в т.ч. kernel timestamps), портал по
  Location+`dt<rtt/2`, body_end/cut, RST/ACK, замена; Rust
  `HttpRequestFlow`/`SynAnchor`, portal/late/response tracking.
  D17 paired differential покрывает портал/307/поздний/дубль, полный
  набор C-состояний (INJECTED/SWAP/ANSWERED, overlap/gap, kernel
  timestamps) не доказан. P.
- **`d2k_http80_swap` (527–545) ↔ `main.rs:2093/2114`:** C
  `verdict_payload(out)` + `send_rst`, при ошибке `ANSWERED`,
  `swap_failed++`, `verdict_accept`; Rust `send_replacement` +
  `mark_http_response_answered`, RST отдельно. P — сокет-путь не
  покрыт paired differential.
- **`lc` (549) ↔ `u8::to_ascii_lowercase`:** E.
- **`d2k_http_request` (551–632) ↔ `httpup.rs:180/220`:** C method
  1..20 uppercase, origin-form, ровно `HTTP/1.0|1.1`, ровно один
  `Host` с портом 80, LDH, последняя метка не all-digits, затем
  stream parser для `end_known`; Rust `parse_plan_request` добавляет
  `#`/target<2048, требует полные заголовки, иначе обрабатывает
  Host/CL/TE. P — полный набор отказов C не сверен.

## datapath/http_trace.c (1 функция)

**Прочитано построчно: 1/1 функция, 50 строк C (1–50).** Сверено: в `crates/` нет строки `HTTP execution`, функции `d2k_http_trace` или `http_trace`; R2O использует `HttpPortalEvent`/`HttpResponseEvent` и журнал `flow_journal`, поэтому текстовый формат не портирован.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_http_trace` | 9–50 | 42 | строка `d2kd: HTTP execution host=... IPv4/6 [src]:cport -> [dst]:80 seq=... hook/mark/outdev/status/prepared/plan/execution/planned/raw_sent/queued/original/output_failed/reason` | нет: grep `HTTP execution` по R2O пуст | **N** | C: TCP/80, method заглавными + пробел, `d2k_http_request` иначе `host=<unparsed>`, `inet_ntop`, plan hex или `-`, status `OBSERVE/SKIPPED/FAILED/PENDING/COMPLETE`, seq/hook/mark/outdev, execution, planned/sent/queued, original `ACCEPT/DROP`, output_failed, reason; возвращает длину с усечением до `cap-1`. В R2O есть события портала/ответа и журнал, но **нет** этой текстовой строки; N подтверждён. |

## datapath/journal.c (14 функций)

Кольцо журнала наблюдений: kinds, коды suspect/refuse, очистка имени, plan/trial/
execution/binding, added/dropped. R2O: `flow_journal.rs`.

**Прочитано построчно: 14/14 функций, 204 строки C (1–204).** Сверено с `flow_journal.rs:16-56` (константы/тексты), `:184-195` (`set_name`), `:530-581` (`default_journal_note`, `with_capacity`, `push`), `:650-757` (`record_applied/plan_prepared/plan_refused/execution_failure`), `:990-1020` (`count/get/dropped/added`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_journal_new` | 16–31 | 16 | кольцо cap (0 — журнал ничего не хранит, но считает added) | `flow_journal.rs:552-564` `with_capacity`, `:565-582` `push` | **P** | Поведение совпадает: `with_capacity(0)` возвращает `Ok`, `push` инкрементирует `added` и выходит при `capacity == 0`. Прежнее утверждение «cap=0 — ошибка» неверно. Отдельного теста cap=0 нет. |
| `d2k_journal_free` | 33–39 | 7 | освобождение | `Drop` | E | RAII |
| `d2k_suspect_text` | 41–53 | 13 | тексты SUSPECT_* (8 кодов + default) | `flow_journal.rs:28 r2o_suspect_text` | E | `:1027 journal_note_texts_match_d2o` |
| `d2k_refuse_text` | 55–68 | 14 | тексты REFUSE_* (7 кодов + default) | `:45 r2o_refuse_text` | E | `:1027` |
| `add_entry` (static) | 76–130 | 55 | общая запись: added/dropped, note по умолчанию, чистка имени | `flow_journal.rs:565-582` `push`, `:530-543` `default_journal_note`, `:184-196` `set_name` | **P** | Санитизация совпадает: байты 0x20..0x7e как есть, остальные → `.`, предел 63 (`journal.c:111-123`). Заметки: SUSPECT→`suspect_text`, UNSENT/DAMAGED→`refuse_text`, DONE→«план доисполнен» — совпадает с C. Отдельного теста на непечатаемое имя нет. |
| `d2k_journal_add` | 132–137 | 6 | добавить наблюдение | `:565 push` | P | — |
| `d2k_journal_add_applied` | 139–149 | 11 | `PLAN_APPLIED` + plan_id/trial_id | `flow_journal.rs:667-683 record_plan_prepared` | **P** | C пишет kind `D2K_JRN_PLAN_APPLIED`; Rust `record_plan_prepared` — `PlanApplied`. `record_applied` (`:650`) — это `PlanDone` и соответствует C `d2k_journal_add_fate_bound(...PLAN_DONE...)`, а не этой функции. Отдельного теста prepared нет. |
| `d2k_journal_add_refused` | 151–158 | 8 | REFUSED + code/plan/trial | `flow_journal.rs:684-720` `record_plan_refused` | **P** | **Расхождение:** Rust принимает только `NOT_APPLIED|FLOW_UNFIT` и валидный ключ/привязку; C `refuse_coded` вызывается с `NOT_APPLIED/FLOW_UNFIT` (`session.c:1364,2445,2481`) и с `NONE` через `refuse()` (`:417`). Отказ `NONE` R2O отправляет событием, но в журнал не пишет. D22 покрывает основные коды. |
| `d2k_journal_add_fate_bound` | 160–176 | 17 | один fate-kind за вызов: DONE/UNSENT/DAMAGED + plan/trial/execution/binding | `flow_journal.rs:722-757` `record_execution_failure`, `:650` `record_applied` | **P** | C `add_fate_bound` пишет **один** kind за вызов. Rust `record_execution_failure` за один вызов пишет `PlanUnsent` и при `damaged` **дополнительно** `PlanDamaged`. **Но** C `d2k_session_exec_failed` делает два отдельных вызова: `d2k_session_unsent` (`session.c:3533`, `PLAN_UNSENT`) и `PLAN_DAMAGED` (`session.c:3493`), поэтому итоговый журнал повреждённого потока содержит те же две записи. Отличается гранулярность API, не итог. `record_applied` (`PlanDone`) соответствует C `PLAN_DONE`; `record_plan_prepared` — `PLAN_APPLIED`. |
| `d2k_journal_add_fate` | 178–182 | 5 | fate без execution | те же без execution | P | — |
| `d2k_journal_count` | 184–186 | 3 | число записей | `:990 count` | E | — |
| `d2k_journal_at` | 188–196 | 9 | запись от старой к новой | `flow_journal.rs:994-1004 get`, `:1014-1020 iter` | **P** | Порядок совпадает: C отдаёт от `head` при заполненном кольце, Rust `VecDeque`-подобное кольцо с `head/length`; `get(i)` и `iter()` идут от старой к новой. Отдельного теста порядка нет. |
| `d2k_journal_dropped` | 198–200 | 3 | вытеснено | `:1006 dropped` | E | — |
| `d2k_journal_added` | 202–204 | 3 | добавлено всего | `:1010 added` | E | — |

## datapath/nat.c (5 функций)

Внешний адрес/порт из `/proc/net/nf_conntrack`: разбор строк, «лучшая запись» по
TTL, отличие «нет таблицы» от «нет записи». R2O: `proc_nat.rs`.

**Прочитано построчно: 5/5 функций, 195 строк C (1–195).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `parse_ip4` (static) | 20–41 | 22 | строгий IPv4: 4 десятичных октета 0..255, ровно точки и NUL | `proc_nat.rs:145 parse_ipv4` | **P** | C принимает ведущие нули (`001`→1), отвергает пустой октет, `>255`, лишние символы/точки. Rust `split('.')`, все ASCII-цифры, `checked_mul/checked_add`, `<=255`, ровно 4 части — эквивалентно. Unit-теста на отказы нет; differential есть. |
| `field_after` (static) | 46–63 | 18 | найти `name=` на границе слова, вернуть значение до пробела/`\n`, сдвинуть `next` | `proc_nat.rs:122 field_after`, `:113 fields` | **P** | C `strstr` + проверка `p==s\|\|p[-1]==' '` + `p[nl]=='='`, режет копию строки. Rust сначала токенизирует строку по ASCII-пробелам в `(key,value)`, затем ищет **точное** имя. Для нормальной строки эквивалентно; Rust строже к `src=` внутри значения другого поля. |
| `d2k_nat_outside` | 67–73 | 7 | IPv4-обёртка: family=4, src/dst как 4 байта | `:20 lookup` с tuple family=4 | **P** | C передаёт указатели на `uint32_t` и family 4; Rust `R2oConntrackTuple.family=4`, адреса 16-байтные с нулевым хвостом. Эквивалентно. |
| `parse_address` (static) | 75–82 | 8 | IPv4 через `parse_ip4`, IPv6 через `inet_pton`, out[16] занулён | `:134 parse_address` | **P** | C `memset(out,0,16)`, v6 `inet_pton(AF_INET6)`, v4 `parse_ip4` + 4 байта. Rust `Ipv6Addr::from_str` / `parse_ipv4`, 16-байтный массив. Оба не принимают `%zone`; unit-теста нет. |
| `d2k_nat_outside_family` | 84–194 | 111 | fopen; 1 — нет таблицы, -1 — нет записи, 0 — найдено; строки >1022 пропуск; direct/reverse tuple; best TTL (3-е число) | `:20 lookup` → `R2oProcNatLookup` | **E** | C `fopen` fail → 1, Rust `TableMissing`; пустая/без записи → -1/Missing; найдено → 0/Found. Совпадают: `fgets(1024)` + drain длинной строки ↔ `read_until` + `content_len>1022`; `strstr(tcp/udp)`; direct `src/dst/sport/dport`; reverse `dst/dport`; `third_number`; `ttl<=best` skip; memcmp адресов/портов. Тест `:220 отличает_отсутствие_таблицы...` + `r2o-nat-proc-differential.sh`; в этом проходе не перезапускались. |

### datapath/nat.c: построчная сверка

- **`parse_ip4` (20–41) ↔ `proc_nat.rs:145`:** C 4 октета 0..255,
  ровно точки/NUL, ведущие нули допустимы; Rust `split('.')` +
  `checked_mul/add` + `<=255` + ровно 4 части. Эквивалентно; P —
  unit-теста на отказы нет, differential есть.
- **`field_after` (46–63) ↔ `field_after/fields`:** C `strstr` +
  граница слова + `=` + резка значения до пробела/`\n`; Rust сначала
  токенизирует `key=value`, затем ищет точное имя. Для нормальной
  строки эквивалентно, Rust строже к вложенным `src=`. P.
- **`d2k_nat_outside` (67–73):** IPv4-обёртка family=4; Rust tuple
  family=4. P.
- **`parse_address` (75–82) ↔ `:134`:** C v6 `inet_pton`, v4
  `parse_ip4`; Rust `Ipv6Addr::from_str`/`parse_ipv4`. Оба без `%zone`.
  P — unit-теста нет.
- **`d2k_nat_outside_family` (84–194) ↔ `lookup`:** коды
  `1/-1/0` ↔ `TableMissing/Missing/Found`; `fgets(1024)` + drain
  длинной строки ↔ `read_until` + `content_len>1022`; `strstr(tcp/udp)`;
  direct/reverse кортеж; третье число как TTL; `ttl<=best` skip;
  memcmp адресов/портов. E; тест `:220` + `r2o-nat-proc-differential.sh`
  (не перезапускались).

## datapath/ctq.c (20 функций)

ctnetlink: сборка GET, разбор счётчиков/состояния TCP, неблокирующий запрос,
проба подсистемы, открытие сокета. R2O: `conntrack.rs`.

**Прочитано построчно: 20/20 функций, 256 строк C (1–256).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `align4` (static) | 16 | 1 | выравнивание | `conntrack.rs:250 align4` | E | — |
| `wr16h` (static) | 18 | 1 | host u16 | `to_ne_bytes` (`:256`) | E | `:543` encode test |
| `wr32h` (static) | 19 | 1 | host u32 | `to_ne_bytes` (`:125`) | E | `:543` |
| `rd16h` (static) | 20 | 1 | host u16 | `from_ne_bytes` (`:233`) | E | `:543` |
| `rd64be` (static) | 21–25 | 5 | сетевой u64 | `u64::from_be_bytes` (`:214`) | E | `:487` тест счётчиков |
| `rd32be` (static) | 26–28 | 3 | сетевой u32 | `u32::from_be_bytes` (`:224`) | E | `:529` 32-битные счётчики |
| `put` (static) | 31–40 | 10 | атрибут с padding | `push_attribute` (`:254`) | E | `:543` |
| `open_nest` (static) | 43–47 | 5 | вложенный атрибут: пишет `type \| NLA_F_NESTED`, длина позже | `push_attribute(kind с NLA_F_NESTED)` (`:114`) | **P** | C сначала пишет только заголовок, `close_nest` проставляет длину; Rust собирает вложенное значение в `Vec` и `push_attribute` сразу пишет длину+padding. Wire-формат совпадает, порядок сборки разный. |
| `close_nest` (static) | 48–50 | 3 | проставить длину вложенного атрибута | length prefix в `push_attribute` | **P** | C `end-start` без padding; Rust `push_attribute` добавляет padding. Для кратности 4 результат тот же; отдельного теста нет. |
| `d2k_ct_get_req` | 52–81 | 30 | GET orig-tuple (family/proto/ports) | `conntrack.rs:74 encode_get` | E | `:543 строит_запрос_по_кортежу_ipv4` |
| `counter` (static) | 84–96 | 13 | packets из вложенного counters (64/32) | `:211 parse_counter` | E | `:487`, `:529` |
| `tcp_state` (static) | 99–120 | 22 | состояние TCP (+1 enum) | `:156-160` из PROTOINFO | E | `:487` (state=3) |
| `d2k_ct_info_parse` | 122–156 | 35 | разбор ответа: -1 нет seq, 0 счётчики+state, 1 NLMSG_ERROR, 2 нет счётчиков; оба counters обязательны | `:137 decode_entry`, `:133 decode_info` | **P** | C различает четыре кода и требует **оба** `CTA_COUNTERS_ORIG/REPLY`; при отсутствии одного возвращает 2. Rust `decode_entry` возвращает `None` для нет seq/не CT_NEW, `Some(Entry{info:None})` при нехватке counters, NLMSG_ERROR не разбирает (это делает `probe`). `tcp_state`: C `+1` в helper и `-1` в info, Rust хранит enum как `Option<u8>`; итог совпадает. P — другой канал ошибок/«нет счётчиков». |
| `d2k_ct_counters_parse` | 158–167 | 10 | обёртка: только orig/reply packets, код пробрасывается | `decode_info(...).map(...)` | **P** | C сохраняет код `info_parse`; Rust `decode_info` — `Option`, разделения 1/2 нет. |
| `d2k_ct_query_info_fd` | 169–186 | 18 | send GET `MSG_DONTWAIT`, до 8 recv `MSG_DONTWAIT`, вернуть -1/0/1/2 | `:301 query_entry`, `:384 receive_entry` | **P** | C цикл 8 `recv`, `d2k_ct_info_parse` с seq; Rust `query_entry` send + `receive_entry` 8 циклов, возвращает `Option<Entry>`. Количество попыток/неблокирующий режим совпадают, коды/`Option` — нет. |
| `d2k_ct_query_fd` | 188–197 | 10 | обёртка `query_info_fd` для счётчиков | `:297 query` | **P** | C возвращает код, Rust `query` — `Option<Info>`; эквивалентно только для успеха. |
| `reply_errno` (static) | 201–212 | 12 | по seq: положительный errno, 0 — не ошибка, -1 — нет ответа | `kernel_error` + фильтр seq (`:350`) | **P** | C различает «нет ответа на seq» и «ответ не ошибка»; Rust `probe` проверяет только `NLMSG_ERROR == -ENOENT`, общего `reply_errno` нет. |
| `d2k_ct_probe_fd` | 214–238 | 25 | zero-tuple GET, poll `wait_ms` до 8 раз, ENOENT(2) или запись(0) → подсистема есть | `:309 probe` (100 мс poll) | **P** | C принимает `wait_ms` и делает до 8 poll/recv; Rust `probe` фиксирован на 100 мс и **одном** recv, затем `decode_entry` или `NLMSG_ERROR == -ENOENT`. Параметр ожидания и повторные ответы не портированы. Дифференциал `r2o-conntrack-ctget-differential.sh`. |
| `d2k_ct_open` (linux) | 243–253 | 11 | `SOCK_RAW \| SOCK_CLOEXEC`, fcntl O_NONBLOCK, bind; fd возвращается без проверки подсистемы | `:270 open` (`SOCK_NONBLOCK`) | **P** | C открывает сокет и не пробует conntrack; Rust `open` после bind вызывает `probe()` и возвращает `None`, если подсистема недоступна. Вызывающий C может отдельно вызвать `d2k_ct_probe_fd`; поведение API разное. |
| `d2k_ct_open` (не linux) | 255 | 1 | заглушка -1 | `#[cfg(target_os="linux")]` | E | платформенная ветка |

### datapath/ctq.c: построчная сверка

- **`align4/wr16h/wr32h/rd16h/rd64be/rd32be/put` (16–40):** C
  host-endian `memcpy`, BE-чтение, атрибут с padding; Rust
  `to_ne/from_ne`, `from_be`, `push_attribute`. E; тесты `:543`,
  `:487`, `:529`.
- **`open_nest/close_nest` (43–50):** C пишет заголовок, длину
  проставляет `close_nest`; Rust собирает вложенное значение и
  `push_attribute` сразу пишет длину+padding. Wire-формат тот же,
  порядок сборки разный. P.
- **`d2k_ct_get_req` (52–81) ↔ `encode_get` (`:74`):** C:
  nlmsghdr+4, family 2/10, nested `TUPLE_ORIG`→`TUPLE_IP`/`TUPLE_PROTO`,
  V4/V6 src/dst, proto/ports BE, type `CT_GET`, seq; Rust то же через
  `Vec`+`push_attribute`. E; `:543`.
- **`counter`/`tcp_state` (84–120):** C nested counters 64/32 и
  `PROTOINFO_TCP_STATE` с `+1` (0 — нет); Rust `parse_counter`/
  `find_attribute` + `Option<u8>`; в `info_parse` C снова `-1`, итог
  совпадает. E; `:487`, `:529`.
- **`d2k_ct_info_parse` (122–156) ↔ `decode_entry`:** C коды
  `-1/0/1/2`, требует оба counters; Rust `None`/`Some(Entry)` с
  `info:None` при нехватке, NLMSG_ERROR обрабатывает `probe`.
  **Разный канал ошибок и семантика «нет счётчиков».** P.
- **`counters_parse/query_info_fd/query_fd` (158–197):** C
  пробрасывает коды `info_parse`; Rust `decode_info`/`query` —
  `Option`, успех эквивалентен, коды 1/2 не различаются. P.
- **`reply_errno` (201–212):** C по seq различает положительный
  errno, 0 и -1; Rust общего helper'а нет, `probe` проверяет только
  `-ENOENT`. P.
- **`d2k_ct_probe_fd` (214–238) ↔ `probe` (`:309`):** C принимает
  `wait_ms`, делает до 8 poll/recv, успех при `ENOENT` или записи;
  Rust фиксирует 100 мс и один recv, затем `decode_entry` или
  `NLMSG_ERROR == -ENOENT`. P.
- **`d2k_ct_open` (243–253) ↔ `R2oConntrackClient::open` (`:270`):**
  C `SOCK_RAW|SOCK_CLOEXEC` + fcntl O_NONBLOCK + bind, fd отдаётся
  без проверки подсистемы; Rust `SOCK_NONBLOCK` + bind + обязательный
  `probe()`, иначе `None`. P; не-Linux C-заглушка — E.

## datapath/sched.c (16 функций)

Двоичная куча отложенной отправки по (due, seq), владение NFQUEUE ID,
выбрасывание слишком длинной головы. R2O: `scheduler.rs` (отсортированный Vec +
flow-брони).

**Прочитано построчно: 16/16 функций, 279 строк C (1–279).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_sched_new` | 43–71 | 29 | ёмкость/slot_size, `slots*slot_size` overflow, mem/heap/freelist | `scheduler.rs:89 with_limits` | **E** | C `calloc` трёх массивов и freelist, отказ при 0/overflow; Rust `with_limits` проверяет 0, `Vec`/`HashMap` растут лениво, `capacity`/`refusals` тест `:563`. Ёмкость/отказы совпадают; профиль памяти/OOM иной. |
| `d2k_sched_grow_slot_size` | 73–88 | 16 | новый `cap*slot_size`, копировать живые записи, free старый | `:260 grow_slot_size` | **P** | C физически копирует `e->len` каждого heap-entry в новый массив; Rust меняет только `slot_size`, потому что `WirePacket` владеет байтами. Коды 0/1/-1 и overflow-проверка совпадают. |
| `d2k_sched_free` | 90–98 | 9 | free mem/heap/freelist/table | `Drop` | **E** | RAII. |
| `earlier` (static) | 102–107 | 6 | порядок `(due_ns, seq)`, seq устойчив при равных сроках | `(due, order)` (`:195`) | **E** | C `due` затем `seq`; Rust `partition_point((due,order))`, тест `:526`. |
| `sift_up` (static) | 109–120 | 12 | подъём двоичной кучи | вставка в отсортированный Vec (`:196`) | **P** | C куча с parent/swap; Rust `partition_point`+`Vec::insert`. Итоговый порядок `(due,order)` тот же, структура и стоимость иные. |
| `sift_down` (static) | 122–139 | 18 | спуск кучи после изъятия головы | `remove(0)` (`:285`) | **P** | C меняет голову с последним и sift_down; Rust `Vec::remove(0)` сдвигает. Порядок тот же. |
| `d2k_sched_push` | 141–144 | 4 | push без execution: serial(...,0) | `:209 push_raw` | **E** | Тонкая обёртка; тест `:526`. |
| `d2k_sched_push_serial` | 149–152 | 4 | push с execution и ключом | `:167 push_reserved` | **P** | C хранит `execution`/`key` в entry; Rust `FlowTicket`+`Reservation` (batch/remaining), ключ потока в `flows`. Семантика брони иная, `push_reserved` проверяет ticket. |
| `d2k_sched_push_owned` | 154–157 | 4 | push с владением NFQUEUE ID | `:214 push_owned` | **P** | C `owned=1`, `owner_id`; Rust `ScheduledOwner::Owned(id)`. Путь owned не покрыт unit-тестом. |
| `push` (static) | 159–190 | 32 | `data/len` проверки, `len>slot_size`→refusals++ -2, full→refusals++ -1, freelist, seq++, sift | `:223 push_owner` | **P** | C: пустой пакет → -2 без счётчика; слишком длинный → refusals++ -2; full → refusals++ -1; `next_seq++`, freelist. Rust: empty → Err без счётчика; len>slot_size/full → refusals++ Err; sorted insert, `next_order++`. Коды C (-2/-1) заменены `Err`, порядок/отказы совпадают; `reserved_packets`/`flows` — расширение Rust. |
| `d2k_sched_pop_due` | 192–196 | 5 | pop без execution: serial(...,NULL) | `:329 pop_due` | **P** | C обёртка; Rust `pop_due` возвращает `(WirePacket,FlowTicket)` и `expire(now)`. |
| `d2k_sched_pop_due_serial` | 198–202 | 5 | pop с execution: pop_due_ex | `:275 pop_due_ex` | **P** | C обёртка; Rust `pop_due_ex` с `ScheduledPop`. |
| `d2k_sched_pop_due_ex` | 204–267 | 64 | пусто/не созрело→0; слишком длинная голова: refusals++, owned→ID, freelist, sift; иначе copy out/len/key/execution/owned/ID→1 | `:275 pop_due_ex` (`ScheduledPop`) | **P** | C коды 0/1/-1, `out==NULL`→0; Rust `Empty/Dropped/OversizedOwned/Emitted`, `outcap`; **C owned-oversized возвращает -1 и owner_id, Rust `OversizedOwned{owner_id}`**; C `expire` нет (вызывающий), Rust `expire(now)` чистит flows. Ветка `OversizedOwned` не тестирована; D21. |
| `d2k_sched_next_ns` | 269–271 | 3 | due головы или 0 | `:298 next_due` | **E** | C absolute ns/0, Rust `Option<Instant>`. Для вызывающего эквивалентно. |
| `d2k_sched_count` | 273–275 | 3 | n | `:373 len` | **E** | Прямой getter. |
| `d2k_sched_refusals` | 277–279 | 3 | refusals | `:377 refusals` | **E** | Тест `:563`. |

### datapath/sched.c: построчная сверка

- **`d2k_sched_new/grow_slot_size/free` (43–98) ↔
  `with_limits/grow_slot_size/Drop`:** C выделяет `mem/heap/freelist`
  и при grow копирует живые записи в новый `cap*slot_size`; Rust
  `Vec`/`HashMap` растут лениво, grow меняет только `slot_size`
  (байты принадлежат `WirePacket`). Коды 0/1/-1 и overflow-проверки
  совпадают; профиль памяти иной. E/P.
- **`earlier` (102–107) ↔ `(due,order)`:** C сортирует по
  `(due_ns, seq)`, Rust — `(due, order)` через `partition_point`.
  E.
- **`sift_up/sift_down` (109–139):** C двоичная куча с parent/swap;
  Rust вставка в отсортированный `Vec` и `remove(0)`. Итоговый
  порядок тот же, структура и стоимость иные. P.
- **`d2k_sched_push`/`push_serial`/`push_owned`/`push` (141–190):**
  C хранит `key/execution/owned/owner_id` в entry, freelist и
  `next_seq`; проверки: пустой пакет -2 без счётчика, длинный
  refusals++ -2, full refusals++ -1; Rust `push_owner` — empty Err
  без счётчика, len/full refusals++ Err, `ScheduledOwner`
  (`Flow/Owned/Raw`), `Reservation`/`reserved_packets`, `next_order`.
  Коды C заменены `Err`, отказы совпадают; брони/flow — расширение.
  P.
- **`d2k_sched_pop_due/pop_due_serial/pop_due_ex` (192–267) ↔
  `pop_due/pop_due_ex`:** C: пусто/не созрело → 0; длинная голова —
  refusals++, owned → `owned=1/owner_id`, freelist+sift, return -1
  для owned и 0 для обычной; иначе copy out/len/key/execution/
  owned/ID, return 1. Rust: `Empty/Dropped/OversizedOwned/Emitted`,
  `expire(now)` чистит flows. **`OversizedOwned` не тестирован**;
  код возврата C -1/0/1 заменён enum. P.
- **`next_ns/count/refusals` (269–279):** C absolute ns/0, n,
  refusals; Rust `Option<Instant>`, `len`, `refusals`. E.
- **R2O-расширения:** `reserve`/`push_reserved`/`observe`/`cancel`/
  `expire`/`has_pending`/`timeout_ms` не имеют отдельных C-функций в
  `sched.c`; в C брони и очистка потоков живут в вызывающем коде.

## datapath/wire.c (9 функций)

Единственное место расчёта контрольных сумм TCP: TTL по измеренному пути,
опции, MD5, seq_shift, badsum, IPv4/IPv6. R2O: `r2k-core/src/wire.rs`.

**Прочитано построчно: 9/9 функций, 306 строк C (1–306).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `wr16` (static) | 23–26 | 4 | big-endian u16 | `wire.rs:552 write_u16` | E | golden-тесты wire.rs |
| `wr32` (static) | 28–33 | 6 | big-endian u32 | `:556 write_u32` | E | — |
| `rd16` (static) | 384–386 | 3 | big-endian u16 | `r2k-core/src/packet.rs:231 read_u16` | **E*** | C `(p[0]<<8)\|p[1]`; Rust `read_u16` с `get`-проверкой границ. Используется в TCP/UDP-разборе; `tests/network.rs` покрывает. |
| `auto_ttl` (static) | 54–70 | 17 | TTL по rev_ttl: origin 64/128/255, delta, min/max, clamp 1..255; 0 если нельзя | `plan/apply.rs:764 poison_ttl` | **E** | Формула совпадает: первый `origin` из 64/128/255 ≥ rev_ttl, `hops=origin-rev_ttl`, `+delta`, `max`, `min`, `clamp(1,255)`. C при rev_ttl=0/нет origin возвращает 0, Rust `poison_ttl` — `poison.ttl`, далее `emission_ttl` даёт original/64; итог тот же. Тест `engine.rs:2120`. |
| `sum16` (static) | 73–82 | 10 | RFC1071 | `wire.rs:534 sum16` | **E** | Пословное сложение BE с нечётным хвостом; golden wire. |
| `fold` (static) | 84–89 | 6 | свёртка и инверсия | `:545 checksum_value` | **E** | Точное совпадение. |
| `pseudo_sum` (static) | 99–107 | 9 | IPv4 псевдозаголовок TCP | `:516 pseudo_sum` | **E** | C строит 12-байтный ph, Rust складывает src/dst+6+len; для IPv4 эквивалентно. |
| `d2k_wire_build` | 109–277 | 169 | сборка TCP: профили 0/DETECT/TEMPLATE, MD5, TS/TS-up, seq_shift, poison, суммы | `wire.rs:18 build_tcp_packet` | **P** | **Совпадает:** family 4/6, urgent, ipfrag/profile, MD5 только measured, native options ≤40/кратность 4, TS 8/10 уникальна, TS-back `-1000`, TS-up перенос 10 байт, IPv4 ID 0/random/native+1, measured DF=0/window=65535, IPv6 IPID_ZERO reject, MD5-байты 19/18/1/1, TS NOP/NOP/8/10, badsum measured `^0xbeef`/0x1234 vs legacy `~`/0xffff. **Отличия:** C берёт src/dst/ports/ack/window/ttl/ip_id/traffic_class/flow_label/options из `d2k_conn`, Rust — из входного `PacketView`/`TcpSegmentView`; C `measured` IP-ID — `random()%65535`, Rust — `getrandom()%u16::MAX` (разный источник); C допускает `family=0` как IPv4, Rust требует 4/6. 12 golden/дифференциалов покрывают шаблон/TS-up/badsum/measured/MD5/v6/capacity, но не равенство RNG и не conn-vs-input. |
| `d2k_wire_tcp_checksum_ok` | 279–306 | 28 | IPv4: версия/proto/ihl/total; IPv6: len≥60/proto 6/base-only; сверка суммы | `wire.rs:436 tcp_checksum_ok` | **P** | Для базовых IPv4/IPv6-пакетов формула та же (`pseudo_sum`+`sum16`+`fold==0`). C IPv6 смотрит только основной заголовок (`pkt[6]==6`, len≥60), Rust `PacketView` допускает цепочку padding-extension headers; C `total<ihl`/ihl<20 — аналогично. Различается набор принимаемых ext-header пакетов; тесты wire/http_replace покрывают базовые. |

### datapath/wire.c: построчная сверка

- **`wr16/wr32/rd16` (23–37):** C BE-запись/чтение; Rust
  `write_u16/write_u32`/`from_be_bytes`. E/P.
- **`sum16/fold/pseudo_sum` (73–107):** C RFC1071, свёртка с
  инверсией, 12-байтный IPv4 ph; Rust `sum16`/`checksum_value`/
  `pseudo_sum`. Для IPv4 эквивалентно; golden wire. E.
- **`auto_ttl` (54–70) ↔ `poison_ttl` (`apply.rs:764`):** formula
  `origin∈{64,128,255}≥rev_ttl`, `hops=origin-rev_ttl`, `+delta`,
  `max`, `min`, `clamp(1,255)` совпадает. C 0 при
  `rev_ttl=0`/нет origin; Rust `poison.ttl`, затем `emission_ttl`
  original/64 — итог тот же. E, `engine.rs:2120`.
- **`d2k_wire_build` (109–277) ↔ `build_tcp_packet` (`wire.rs:18`):**
  совпадают профили 0/DETECT/TEMPLATE, urgent, ipfrag, MD5-only-
  measured, native options ≤40/кратность 4, TS 8/10 уникальна,
  TS-back `-1000`, TS-up перенос 10 байт, IPv4 ID (0/random/native+1),
  measured DF=0/window=65535, IPv6 IPID_ZERO reject, MD5 19/18/1/1,
  TS NOP/NOP/8/10, badsum measured/legacy, суммы. **Отличия:**
  C берёт адреса/порты/ack/window/TTL/ip_id/TOS/flow/options из
  `d2k_conn`, Rust — из входного пакета; C measured IP-ID —
  `random()%65535`, Rust — `getrandom()%u16::MAX`; C допускает
  `family=0` как IPv4, Rust требует 4/6. P.
- **`d2k_wire_tcp_checksum_ok` (279–306) ↔ `tcp_checksum_ok`
  (`:436`):** для базовых IPv4/IPv6 формула та же; C IPv6 смотрит
  только основной заголовок, Rust `PacketView` допускает
  padding-extension headers. Набор принимаемых ext-header пакетов
  различается. P.
- **Доказательства:** 12 golden/дифференциалов `wire.rs`
  (template, ts_up, badsum, measured, MD5, v6, capacity,
  `test-wire-ts-up-plan-differential.sh`); они не покрывают RNG
  и conn-vs-input.

## datapath/wire_udp.c (5 функций)

Сборка UDP-датаграммы IPv4/IPv6; отказ неприменимым искажениям, обязательная
сумма (0→0xffff). R2O: `wire.rs::build_udp_packet`.

**Прочитано построчно: 5/5 функций, 207 строк C (1–207).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `wr16` (static) | 22–25 | 4 | big-endian u16 | `wire.rs:552 write_u16` | E | — |
| `sum16` (static) | 31–40 | 10 | RFC1071 | `:534 sum16` | E | — |
| `fold` (static) | 42–47 | 6 | свёртка | `:545 checksum_value` | E | — |
| `pseudo_sum` (static) | 57–65 | 9 | IPv4 UDP ph: src/dst, 0, proto 17, udp_len; 12 байт | `build_udp_packet` внутри (`:265-285`) | **P** | C отдельная функция только для IPv4 (IPv6 считает `sum16(out+8,32,len+17)`); Rust `pseudo_sum` для TCP и inline-сумма для UDP: IPv4 `sum16(out[12..20]) + 17 + udp_len`, IPv6 адреса+длина. Для IPv4 эквивалентно, отдельного символа нет. |
| `d2k_wire_build_udp` | 67–207 | 141 | сборка UDP: family 0/4/6, IPv6 IPID_ZERO reject, запрет pre/seq_shift/TCPTS_BACK/BADSUM, TOS=0, IP-ID, TTL, сумма всегда | `wire.rs:213-305 build_udp_packet` | **P** | **Подтверждённые расхождения:** (1) C для IPv4 допускает `POISON_IPID_ZERO` и пишет ID=0 (`:136-137`), для IPv6 отвергает (`:75`); R2O отвергает **любой** `emission.poison != 0` (`:222-231`), включая IPv4 IPID_ZERO, MD5 и TS_UP. (2) C ставит TOS=0 (`:130`), R2O копирует `view.traffic_class` (`:244`). (3) C отвергает только `TCPTS_BACK|BADSUM` (`:106-109`), а `urgent/urgent_ptr` и prefix не проверяет; R2O дополнительно требует `urgent==false`, `urgent_ptr==0`, `prefix.is_empty()`, `wire_profile==0`, `ipfrag==0`. (4) TTL: C `e->ttl ?: c->ttl ?: 64` (`:148`), R2O `emission_ttl(emission, view.hop_limit)` (`:425-433`) — эквивалентно, если `c->ttl` снят из пакета. (5) C допускает `family=0` как IPv4 и берёт адреса/порты/ip_id/TOS/flow из `d2k_conn`; Rust требует `PacketView` family 4/6, `proto17`, `total_len==input.len()`, `udp_payload_range`, и берёт поля из input. Сумма всегда, `0→0xffff`, длины и IPv6-запрет IPID_ZERO совпадают. `tests/raw.rs:181` собирает пакет, но divergence не покрывает. |

## Углублённая сверка: journal/nl/icmpguard/wire_udp

- **`journal.c` (14):** `d2k_journal_new` подтверждает, что C `cap=0` — это
  «ничего не хранить, но считать added»; Rust `with_capacity(0)` +
  `push` (`flow_journal.rs:552-582`) ведёт себя так же. `add_entry`:
  санитизация имени 0x20..0x7e, иначе `.`, предел 63 (`journal.c:111-123`)
  совпадает с `set_name` (`flow_journal.rs:184-196`); заметки по
  умолчанию (`:530-543`) повторяют C. **Расхождения:** (1)
  `record_plan_refused` принимает только `NOT_APPLIED|FLOW_UNFIT`
  (`:684-706`), тогда как C `refuse()` пишет и `NONE` (`session.c:417`);
  (2) `record_execution_failure` за один вызов пишет `PlanUnsent` **и**
  при `damaged` `PlanDamaged` (`:722-757`); C `d2k_journal_add_fate_bound`
  пишет один kind за вызов, но `d2k_session_exec_failed` делает два
  вызова — `d2k_session_unsent` (`PLAN_UNSENT`, `session.c:3533`) и
  `PLAN_DAMAGED` (`session.c:3493`), поэтому итоговый журнал
  повреждённого потока совпадает, а гранулярность API — нет; (3) числовые kind'ы R2O
  (`PlanApplied=2`, `PlanDone=7`) не равны C (`PLAN_APPLIED=3`,
  `PLAN_DONE=8`), но `EVENT_R2O_JOURNAL_ENTRY` в D2O отсутствует
  (grep по `datapath/`, `core/` пуст), а v22-транслятор журнал не
  пересылает (`control.rs:1783-1794`) — это R2O-локальный формат;
  (4) `c_name` для `PlanDone` пуст (`flow_journal.rs:93`), поэтому
  строка лога датапата для DONE печатает пустой вид (`main.rs:1168`).
- **`nl.c` (19):** `MessageIter`/`QueuePacket::parse`/`verdict`/
  `verdict_payload`/`config_command`/`config_params` сверены с
  `netlink.rs`; тесты `:304` (verdict), `:321` (payload), `:332`
  (config/attrs), `:355` (iterator), `:371` (packet attrs), `:403`
  (payload range), `:429` (kernel error). Атрибуты `NFQA_HDR/PAYLOAD/
  CAP_LEN/TS/MARK/OIF`, выравнивание и big-endian/host-endian
  разложены так же; расхождений не найдено. E оставлены.
- **`icmpguard.c` (7):** `parse_ip` (IPv4: n≥20, hl≥20, маска
  `0x1fff` — не первый фрагмент; IPv6: n≥40; proto 6/17; n≥hl+8),
  `d2k_icmpguard_note` (TTL ниже исходного, кольцо 256, `now?1`,
  `have_id` для IPv4 при ip_id≠0) и `d2k_icmpguard_check` (IPv4:
  proto 1, маска `0x3fff`, type 11/code 0; IPv6: len≥48, next=58,
  type 3/code 0; сравнение family/proto/src/dst/sport/dport/l4word/
  ip_len/optional ip_id/`q.ttl≤s->ttl`) построчно совпадают с
  `r2o_icmp_guard.rs:44-140`. Rust добавляет счётчик `seen` и
  `stats_line` — расширение, не пробел. Дифференциал
  `test-icmp-guard-current-differential.sh` есть, не перезапускался;
  статусы P сохранены.
- **`wire_udp.c` (5):** подтверждены четыре различия сборки:
  IPv4 `POISON_IPID_ZERO` (C разрешает, R2O отвергает любой poison),
  TOS (C 0, R2O из пакета), набор отвергаемых poison-битов (C только
  `TCPTS_BACK|BADSUM`, R2O все) и TTL (C `c->ttl`, R2O
  `view.hop_limit`; эквивалентно при снятом TTL). Сумма всегда,
  `0→0xffff`, длины и IPv6-запрет IPID_ZERO совпадают.
  Дополнительно Rust отвергает `urgent/urgent_ptr` и `prefix`, требует
  `PacketView` `proto17/total_len==len/udp_payload_range` и берёт
  TOS/адреса/порты/ip_id из input; C берёт их из `d2k_conn` и
  допускает `family=0`.

## datapath/addr.c (3 функции)

**Прочитано построчно: 3/3 функции, 36 строк C (1–36).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_addr_parse` | 5–18 | 14 | IPv4/IPv6 литерал, отказ `%zone`, family 4/6 | `r2k-core/src/addr.rs:11 Address::parse` | **E** | C отвергает NULL и любой `%`, `inet_pton(AF_INET)` затем `AF_INET6`, family 4/6. Rust `IpAddr::parse` отвергает host/zone, те же семейства; `network.rs:6`, `:22` (включая `fe80::1%eth0`). Форматы ввода совпадают. |
| `d2k_addr_text` | 20–30 | 11 | `inet_ntop`, отказ при неизвестной family; `n>=cap`→0, иначе копия+`\0`, вернуть n | `addr.rs:49 Display` | **P** | C пишет в буфер `out/cap`, проверяет `n>=cap` и возвращает длину; Rust `Display`/`format!` не имеет буфера и не усекает, вызывающий сам выделяет строку. Текст IPv4/IPv6 совпадает, контракт «не влезло → 0» не портирован. |
| `d2k_addr_equal` | 32–36 | 5 | family совпадает, `memcmp` 4/16; неизвестная family → 0 | `addr.rs:5 PartialEq` | **E** | C сравнивает family+bytes, family 0/иная → 0; Rust derived `Eq` на `IpAddr` (V4/V6 — разные варианты). `network.rs:16`. |

### datapath/addr.c: построчная сверка

- **`d2k_addr_parse` (5–18) ↔ `Address::parse` (`addr.rs:11`):** C
  отвергает NULL и любой `%`, затем `inet_pton(AF_INET)` /
  `AF_INET6`; Rust `IpAddr::parse` отвергает host/zone и даёт V4/V6.
  E; `network.rs:6/22`.
- **`d2k_addr_text` (20–30) ↔ `Display` (`:49`):** C `inet_ntop` в
  `out/cap`, `n>=cap`→0, возвращает n; Rust `Display`/`format!` не
  имеет буфера/усечения. Текст IPv4/IPv6 совпадает, контракт
  «не влезло → 0» не портирован. P.
- **`d2k_addr_equal` (32–36) ↔ `PartialEq`:** C family+`memcmp` 4/16,
  неизвестная family→0; Rust derived `Eq` на `IpAddr` (V4/V6 разные
  варианты). E; `network.rs:16`.

## datapath/tls.c (7 функций)

Разбор TLS ClientHello/ServerHello: границы claimed/avail, SNI, TLS1.3,
ECH, середина приветствия. R2O: `r2k-core/src/tls.rs`.

**Прочитано построчно: 7/7 функций, 361 строка C (1–361).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `rd16` (static) | 384–386 | 3 | big-endian u16 | `r2k-core/src/packet.rs:231 read_u16` | **E*** | C `(p[0]<<8)\|p[1]`; Rust `read_u16` с `get`-проверкой границ. Используется в TCP/UDP-разборе; `tests/network.rs` покрывает. |
| `skip_u8_vec` (static) | 36–46 | 11 | пропуск вектора с u8-длиной | `:141 skip_u8_vector` | **E** | C `off+1>len`/`off+1+n>len`; Rust `get`+`checked_add`, затем `next>end`. Эквивалентно; `:367`. |
| `skip_u16_vec` (static) | 48–58 | 11 | пропуск вектора с u16-длиной | `:158 skip_u16_vector` | **E** | C `rd16`+те же две проверки; Rust `read_u16`+checked. `:367`. |
| `has_ech_offer` (static) | 72–87 | 16 | структурно целый ECH 0xfe0d: type, n≥10, b[off]==0, enc≤n-10, payload>0 и ==n-10-enc | `:230 has_ech_offer` | **E** | C и Rust проверяют те же поля/границы; Rust checked-арифметика. Тест `:466`. |
| `has_tls13` (static) | 105–129 | 25 | supported_versions содержит 0x0304; если блок оборван — key_share | `:175 has_tls13` | **E** | C: `key_share` ставится до проверки длины, supported_versions с list_len и чётными версиями, иначе `truncated && key_share`; Rust тот же порядок и эвристика. `:411`, `:438`. |
| `find_sni` (static) | 131–177 | 47 | server_name→host_name; пустое/битое имя — отказ | `:274 find_sni` | **E** | C возвращает -1 при выходе extension/list/name за границы и при nlen==0; Rust `Option`/None с теми же проверками. `:445`, `:455`. |
| `d2k_tls_parse` | 179–361 | 183 | запись TLS, claimed/avail, ServerHello≥38, ClientHello, hello_middle, extensions, ECH/TLS1.3/SNI | `tls.rs:32 parse` | **E** | Построчно совпадает: `len<3`/`b[1]!=3`, `record_type`, `record_end` при полной записи, `record_type!=0x16`, `end=min(claimed,avail)`, ServerHello `sh_len>=38 && off+4+sh_len<=claimed`, ClientHello `hs_end<=claimed`, `hello_middle=off+hs_len/2` только при полном hello, 34 байта version/random, skip session/ciphers/compression, exts_len/claimed, `exts_truncated` при exts_end>hs_end, затем has_tls13/ECH/find_sni. Тесты `:367`-`:525`, `tls_parser` `:394`, fuzz-префиксы `:503`. |

### datapath/tls.c: построчная сверка

- **`rd16` (30–32) ↔ `tls.rs:129`:** BE u16; Rust с bounds-check.
  E.
- **`skip_u8_vec/skip_u16_vec` (36–58) ↔ `skip_u8_vector/
  skip_u16_vector`:** C две проверки `off+len`/`off+prefix+len`; Rust
  `get`+`checked_add`+`next>end`. Эквивалентно; `:367`. E.
- **`has_ech_offer` (72–87) ↔ `:230`:** type 0xfe0d, `n>=10`,
  `b[off]==0`, `enc<=n-10`, `payload>0 && payload==n-10-enc`;
  те же границы, Rust checked. `:466`. E.
- **`has_tls13` (105–129) ↔ `:175`:** `key_share` фиксируется до
  проверки длины; supported_versions с `list_len` и чётными версиями
  0x0304; иначе `truncated && key_share`. Порядок и эвристика
  совпадают; `:411`, `:438`. E.
- **`find_sni` (131–177) ↔ `:274`:** обход extensions, SNI list,
  host_name; выход за extension/list/name или `nlen==0` → отказ.
  C -1, Rust None. `:445`, `:455`. E.
- **`d2k_tls_parse` (179–361) ↔ `parse` (`:32`):** совпадают
  `len<3`/`b[1]!=3`, `record_type`, `record_end` только при полной
  записи, `record_type!=0x16`, `end=min(claimed,avail)`,
  ServerHello `sh_len>=38 && off+4+sh_len<=claimed`,
  ClientHello `hs_end<=claimed`, `hello_middle` только при полном
  hello, 34 байта version/random, skip session/ciphers/compression,
  `exts_len`/`claimed`, `exts_truncated` при `exts_end>hs_end`,
  затем has_tls13/ECH/find_sni. Тесты `:367`-`:525`, независимый
  `tls_parser` `:394`, fuzz-префиксы `:503`. E.

## datapath/include/d2k_ctl.h (2 inline-функции)

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_ctl_binding_write` (inline) | 86–90 | 5 | запись binding: BE u64 generation, kind/family/shape/temporary, 16-байтная epoch | `r2k-core/src/control.rs:330-347 AppliedEvent::event_body`, `:305 BindingContext`, `:2016/2051 encode_ack_with_binding` | **P** | Раскладка построчно совпадает (BE u64 + 4 байта + epoch). Roundtrip-тесты APPLIED/REFUSED/ACK (`:2528-2607`, `:2770+`, `:2168-2337`) проверяют кодирование/декодирование, но **C/Rust byte-differential отсутствует**; отдельного теста на все три места записи нет. |
| `d2k_ctl_binding_read` (inline) | 91–99 | 9 | чтение/валидация binding: n=28, kind≤4, family 0/4/6, shape≤MAX, temporary≤1 | `control.rs:2373 decode_applied`, `:2445 decode_refused`, `:3104 valid_binding` | **P** | Валидации совпадают: `kind<=4`, `family in {0,4,6}`, `shape<=SHAPE_ECH_TS`, temporary только 0/1. Тесты: REFUSED roundtrip/truncated (`:2528-2607`), APPLIED; ветки `kind=5`, `family=1`, `shape>MAX` отдельным тестом не покрыты. |

## datapath/include/d2k_http_request_stream.h (3 inline-функции)

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_http_request_stream_init` (inline) | 19–21 | 3 | обнулить состояние, `start=next=seq`, `first=1` | `httpup.rs:64 R2oHttpRequestSequence::new` | **P** | Rust хранит только `first/next/checked/disabled`, без `start/head_len/end/length`; это другой уровень (трекер границ, не байтовый парсер). |
| `d2k_http_request_stream_line` (inline) | 22–30 | 9 | завершение строки: ровно один Host, конец ≤0x7fffffff, CL с цифрами | `httpup.rs:231 parse_plan_request`, `:219 parse_request`, `:382 find_crlf` | **P** | C завершает строку инкрементально и валидирует `hosts==1`, `length`, 10 цифр CL; Rust разбирает весь буфер и проверяет Host через `Option`, а `header_len/end_offset` вычисляет в конце. Промежуточного состояния строки нет. |
| `d2k_http_request_stream_feed` (inline) | 31–86 | 56 | потоковый разбор заголовка: CRLF, token, Host, CL, TE/Upgrade, end/past_end/invalid | `httpup.rs:116 observe_detailed`, `:73 candidate`, `:263-316 boundary_known` | **P** | **Расхождения:** C отвергает TE/Upgrade (`invalid`), Rust только `end_offset=None`; C отвергает управляющие байты и неверные имена полей, Rust помечает лишь `boundary_known=false` и продолжает; C ограничивает CL 10 цифрами, Rust — `usize`; C не валидирует DNS-значение Host, Rust требует `valid_dns_host`, снимает `:80` и точку. C игнорирует полностью старые байты, Rust — `candidate_state`; обе стороны считают `end<=0x7fffffff`. Отдельного C/Rust differential для потока нет. |

## datapath/include/d2k_http_response.h (6 inline-функций)

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_hr_decimal` (inline) | 21–29 | 9 | десятичное число с проверкой переполнения | `http_response.rs:360 parse_decimal` | **E** | Совпадает: пусто/нецифра → ошибка, `checked_mul/checked_add`; тест `rejects_malformed...` с `18446744073709551616` (`tests/http_response.rs:229`). |
| `d2k_hr_token` (inline) | 31–34 | 4 | допустимый token-байт RFC 7230 | `httpup.rs:346 is_http_token` | **E** | Набор символов совпадает; используется в `parse_plan_request` для имени заголовка запроса. В ответном парсере Rust этот предикат не применяется (см. `d2k_hr_field`). |
| `d2k_hr_field` (inline) | 35–42 | 8 | валидация поля: непустое имя, token, допустимые байты значения | `http_response.rs:281 parse_headers` | **P** | **Неполно:** Rust ищет `:` и разбирает известные поля, но не отвергает строку без `:`, не проверяет token-символы имени и управляющие байты значения; C делает всё это через `d2k_hr_field`. |
| `d2k_hr_extensions` (inline) | 43–70 | 28 | разбор chunk-extensions: `;token[=token/quoted]`, OWS, контрольные байты | `http_response.rs:372 parse_chunk_size` | **P** | **Неполно:** Rust отбрасывает всё после первого `;` и не валидирует extensions; C проверяет token, кавычки, escape и управляющие байты. Поэтому `1;\x01`, незакрытая кавычка и `1 ;x` дают разный исход. |
| `d2k_hr_headers` (inline) | 72–105 | 34 | разбор status-line и заголовков, CL/TE, interim, 101/204/304 | `http_response.rs:281 parse_headers`, `:321 parse_status_line` | **P** | **Расхождения:** C `head[8192]`, Rust 64 КиБ; C принимает status-line ровно 12 байт, Rust требует 13-й символ; C валидирует каждое поле и отвергает дубли Content-Length, Rust пропускает строки без `:` и разрешает одинаковые CL; C отвергает управляющие байты в заголовках, Rust после status-line их не проверяет. Логика interim/101/204/304/CL+TE совпадает. |
| `d2k_http_response_feed` (inline) | 107–160 | 54 | потоковый разбор ответа: header/fixed/chunk/trailer/close/fin | `http_response.rs:55 feed` | **P** | **Расхождения:** C при байтах после `complete` ставит `invalid`, Rust молча `break`; C `line[512]`, Rust 128; C валидирует trailer как поле и отвергает NUL, Rust принимает ведущий NUL как пустой trailer; C проверяет chunk-extensions, Rust игнорирует; C `head[8192]`, Rust 64 КиБ. Общая state-machine и `fin`-логика совпадают. |

## datapath/include/d2k_packet.h (2 inline-функции)

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_packet_u16` (inline) | 20–22 | 3 | big-endian u16 | `packet.rs:231 read_u16` | E | Построчно совпадает; используется в `parse_ipv4/parse_ipv6` с bounds-check. |
| `d2k_packet_parse` (inline) | 24–70 | 47 | разбор IPv4/IPv6, fragment, extension headers, только Pad1/PadN, L4 minimum | `packet.rs:69 PacketView::parse`, `:152 parse_ipv4`, `:172 parse_ipv6`, `:203 has_only_padding_options` | E | IPv4: IHL/ total / fragment offset / ID / proto / TTL / TOS / адреса совпадают. IPv6: payload≠0, total=40+payload, TC/flow label, до 8 extension headers, Pad1/PadN; иные опции отвергаются. Тесты `r2k-core/tests/network.rs:36+`. |

## datapath/include/d2k_track.h (1 inline-функция)

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_key_equal` (inline) | 76–83 | 8 | равенство ключа: proto/ports/family/адреса; family 0 и 4 эквивалентны | `#[derive(Eq, PartialEq)]` (`capture.rs:13 TcpFlowKey`, `engine.rs:41`, `r2o_udp_hold.rs`, `session`) | **E** | Для ключей, созданных R2O, поля сравниваются все; family 4/6 представлена `Address`, legacy family 0 не используется. C-ветка `family==0` и `family==4` с `low_ip` эквивалентна Rust-ключу IPv4. Отдельного differential нет. |

### datapath/include/*.h (14 inline-функций)

- **`d2k_ctl_binding_write` (86–90) ↔ `control.rs:330-347`:** C пишет
  BE u64 generation, `kind/family/shape/temporary`, 16-байтную epoch.
  Rust `AppliedEvent::event_body` и `encode_ack_with_binding` пишут те же
  28 байт в том же порядке. Roundtrip-тесты APPLIED/REFUSED/ACK есть,
  но C/Rust byte-differential отсутствует; P.
- **`d2k_ctl_binding_read` (91–99) ↔ `control.rs:2373/2445/3104`:**
  C проверяет `n==28`, `kind<=4`, `family in {0,4,6}`,
  `shape<=D2K_TCP_SHAPE_MAX`, `temporary<=1`. Rust проверяет точные
  длины событий, temporary только 0/1, `valid_binding` — те же
  kind/family/shape. Ветки `kind=5`, `family=1`, `shape>MAX` не имеют
  отдельного теста; P.
- **`d2k_http_request_stream_init/line/feed` (19–86) ↔
  `httpup.rs:64/116/231`:** это **не** построчный порт. C — байтовый
  инкрементальный парсер с состояниями `cr/line/value/field/name`,
  счётчиком Host, CL до 10 цифр, `past_end` и `invalid`. Rust
  `R2oHttpRequestSequence` отслеживает только границы запросов, а
  `parse_plan_request` разбирает уже собранный буфер. Отсюда:
  TE/Upgrade C считает `invalid`, Rust — `end_offset=None`; управляющие
  байты и неверные имена C отвергает, Rust только снимает
  `boundary_known`; C не валидирует DNS-значение Host, Rust требует
  `valid_dns_host` и снимает `:80`/точку. P.
- **`d2k_hr_decimal` (21–29) ↔ `http_response.rs:360`:** эквивалентно,
  включая переполнение; E.
- **`d2k_hr_token` (31–34) ↔ `httpup.rs:346`:** набор token-байт
  совпадает; в ответном парсере предикат не используется; E для
  предиката, но не для ответной валидации.
- **`d2k_hr_field` (35–42) ↔ `http_response.rs:281`:** C требует
  непустое token-имя, `:` и допустимые байты значения; Rust ищет `:`,
  но строку без `:` пропускает, token-символы имени и управляющие
  байты значения не проверяет. P (частично).
- **`d2k_hr_extensions` (43–70) ↔ `http_response.rs:372`:** C
  валидирует `;token[=token/quoted]`, OWS, escape и control-байты;
  Rust отбрасывает всё после первого `;`. `1;\x01`, незакрытая
  кавычка и `1 ;x` дают разный исход. P (частично).
- **`d2k_hr_headers` (72–105) ↔ `parse_headers/parse_status_line`:**
  логика interim/101/204/304, CL+TE, TE=chunked совпадает. Отличия:
  C `head[8192]` против 64 КиБ; C принимает status-line ровно 12
  байт, Rust требует 13-й; C отвергает дубли Content-Length всегда,
  Rust разрешает одинаковые; C валидирует все поля, Rust — нет.
- **`d2k_http_response_feed` (107–160) ↔ `http_response.rs:55`:**
  общая state-machine header/fixed/chunk/trailer/close/fin совпадает.
  Отличия: C при байтах после `complete` ставит `invalid`, Rust
  молча `break`; C `line[512]` против 128; C валидирует trailer и
  отвергает NUL, Rust принимает ведущий NUL; C проверяет extensions,
  Rust игнорирует. P.
- **`d2k_packet_u16/parse` (20–70) ↔ `packet.rs:231/69`:** построчно
  совпадает, включая IPv4 IHL/fragment/ID/TOS, IPv6 payload≠0,
  TC/flow-label, до 8 extension headers и только Pad1/PadN. E,
  `r2k-core/tests/network.rs:36+`.
- **`d2k_key_equal` (76–83) ↔ derived `Eq`:** C сравнивает
  proto/ports/family/адреса, family 0 и 4 эквивалентны; Rust-ключи
  (`TcpFlowKey`, UDP/session) сравнивают все поля, family 4/6
  представлена `Address`. Для созданных R2O ключей эквивалентно; E.
- **Версионный дрейф:** `scripts/test-http-chunk-framing-differential.sh`
  привязан к donor `a63d9641f4e00aa35fa1e5ccbda47bb5f310c0fe`, которого
  нет в этом окружении. Ожидания Rust-теста `matches_d2o_http_header_...`
  (64 КиБ/128, пропуск строк без `:`, bytes-after-complete) соответствуют
  другой ревизии C, а не oracle `a378e230`. Поэтому E по
  `http_response` против a378 не ставится; differential не перезапускался.

## Углублённая сверка: nat/ctq/sched/addr/tls/include

- **`nat.c` (5):** `parse_ip4` — P (strict IPv4 без inet_pton,
  `r2o-nat-proc-differential.sh`; unit на переполнение/хвост нет);
  `field_after` — P (R2O парсит `key=value` токенами строже C);
  `d2k_nat_outside`/`parse_address` — P* (обёртки);
  `d2k_nat_outside_family` — E: проход файла, прямой/обратный кортеж,
  best TTL, коды -1/0/1; differential + unit
  `отличает_отсутствие_таблицы_от_отсутствия_записи`.
- **`ctq.c` (20):** E — `align4`, `wr16h/wr32h/rd16h/rd64be/rd32be`,
  `put`, `d2k_ct_get_req`, `counter`, `tcp_state`: encode test
  `conntrack.rs:543`, counters `:487`, 32-bit `:529`. **P:**
  `open_nest/close_nest` (length-prefix вместо отдельных функций),
  `d2k_ct_info_parse` (C-коды -1/0/1/2 заменены `Option`/`info=None`),
  `d2k_ct_counters_parse`, `d2k_ct_query_info_fd` (C: send + до 8 recv
  без ожидания; Rust: `query_entry`/`receive_entry` с poll),
  `d2k_ct_query_fd`, `reply_errno`, `d2k_ct_probe_fd`
  (`r2o-conntrack-ctget-differential.sh`), `d2k_ct_open` (netlink
  SOCK_NONBLOCK/bind). Не-Linux `d2k_ct_open` — E-заглушка.
- **`sched.c` (16):** E — `d2k_sched_new` (ёмкость/freelist,
  `scheduler.rs:89`), `free` (RAII), `earlier` (due,seq),
  `d2k_sched_push`, `pop_due`, `next_ns`, `count`, `refusals`
  (тесты `:526/:563`). **P:** `grow_slot_size` (Vec не копирует),
  `sift_up/down` (отсортированный Vec), `push_serial` (execution →
  ticket), `push_owned`, `pop_due_serial/ex` (ветка `OversizedOwned`
  не тестирована; D21 покрывает базовый oversized).
- **`addr.c` (3):** `d2k_addr_parse` — E (`addr.rs:11`, тесты
  `network.rs:6/22`, включая `%zone`); `d2k_addr_text` — P (C
  возвращает 0 при нехватке cap, Rust `Display` не усекает);
  `d2k_addr_equal` — E (`PartialEq`, `network.rs:16`).
- **`tls.c` (7):** все E — `rd16`, `skip_u8/u16_vec`, `has_ech_offer`,
  `has_tls13`, `find_sni`, `d2k_tls_parse`: `tls.rs` тесты
  (`:367-:525`), сверка с `tls_parser` (`:394`), fuzz-префиксы (`:503`).
- **`include/*.h` (14):** E — `d2k_packet_u16/parse` (`packet.rs`,
  `tests/network.rs:36+`), `d2k_key_equal` (`PartialEq`). **P:**
  `d2k_ctl_binding_write/read` (формат совпадает, отдельного unit на
  раскладку нет), `d2k_http_request_stream_init/line/feed`
  (`httpup.rs`, `hold.rs:2401` косвенно), `d2k_hr_decimal/token/field/
  extensions/headers` (`http_response.rs:281/360/372`;
  `test-http-chunk-framing-differential.sh`),
  `d2k_http_response_feed` (`http_response.rs:55`, `hold.rs` косвенно).
- **Вывод:** 65 функций; E — nat main, ctq кодирование/счётчики,
  sched базовые, addr parse/equal, весь tls, packet/key; P — CT-разбор/
  query, sched owned/oversized, addr text, inline HTTP/binding.
  Новых N нет.

## Углублённая сверка session.c: форма и учёт исполнения

- **Слоты формы:** C хранит `last_hello/last_name/last_opts` и
  `shape/shape_name/shape_opts` на `(transport,family)` (`session.c:140-143,
  2931-2990`); `want_shape` отдаёт сохранённое при совпадении имени и
  взводит ожидание иначе. Rust — `ClientShapeEvent`/`last_client_shapes`
  (`control.rs:1765-1774`) и `r2o_capture_client_shape`; **полный
  `shape_opts` не передаётся**, только `tcp_has_timestamp`
  (`r2o_session_shape_tcp_options_family` — N).
- **Stall-бюджеты:** `d2k_session_set_stall_budgets` точно совпадает с
  `TcpSessions::set_tcp_stall_budgets` (`engine.rs:451-460`): ≤8,
  любой 0 — отказ, пусто → `[25]`; тесты `engine.rs:2431-2434` — E.
- **`d2k_session_sent`:** C ведёт `sends_left/sends_done/sent_lost/done`
  и пишет PLAN_DONE при `sends_left==0`. Rust завершает попытку одним
  `plan_done=true`/`r2o_execution_pending=false`
  (`engine.rs:627-653`); `sends_left/sends_done/sent_lost` не найдены.
- **`d2k_session_exec_failed`:** C различает UDP original-lost
  (`udp_replan`) и damaged (`damaged_flows++`, `guards=0`,
  PLAN_DAMAGED один раз). Rust `r2o_finish_tcp_execution`
  (`main.rs:411-430`) + `r2o_mark_damaged_for_execution`
  (`engine.rs:672-690`, `guards=0`) + `record_execution_failure`;
  `udp_replan`/`damaged_flows` не найдены; для damaged Rust пишет
  PlanUnsent **и** PlanDamaged, C — одну запись.
- **`guards`/`client_shape`/`damaged`/`unsent`:** поля/методы есть;
  `damaged` в Rust дополнительно сбрасывает pending/guards;
  `sends_left/sends_failed` не портированы, UNSENT — часть
  `record_execution_failure`.
- **Счётчики `applied/done/damaged/sent_lost/suspects/exchanges`:** в
  R2O остаются событиями/журналом, сводных геттеров нет — N (см.
  N-раздел). `payload_stats` — `r2o_tcp_payload_stats`
  (`engine.rs:534-542`), P; журнал — `R2oFlowJournal`, P.

## Углублённая сверка session.c: packet-обёртки, conntrack, routed

- **Packet-обёртки (2603–2626):** C четыре входа вызывают
  `session_packet` с `observe_only=0`, `probe` и `tcp_segment_cap`;
  Rust `decide_with_session`/`_probe`/`_mtu`/`_probe_mtu`
  (`engine.rs:1403-1439`) → `decide_with_session_mode`. Семантика
  совпадает, вся логика в нижнем слое; P.
- **`plan_handed_off` (446–473):** C ставит applied/key/plan/trial,
  `orig_taken = verdict==DROP`, `sends_left=n_out+1`,
  `sends_failed=sends_done=udp_replan=0`, execution_id (пропуск 0),
  binding. Rust `r2o_begin_execution` (`engine.rs:588-603`) ставит
  `execution_id`/`r2o_execution_pending` и отказывает damaged;
  `payload_on_wire/original_spent/original_taken` — в `PendingApplied`.
  **`sends_left/sends_failed/sends_done/udp_replan` не найдены.**
- **`suspect_num` (486–503):** C один раз на поток, `suspects++`,
  journal SUSPECT с `planned`/`client_shape`. Rust — события
  `EVENT_R2O_TCP_*` и `flow_journal`; сводного `suspects++` нет (N).
- **`on_flow_expire` (521–530):** C `capture_forget` +
  `tcp_silence_observe`; Rust `expire_with_silent` (`engine.rs:698`)
  вызывает замыкание перед удалением. P.
- **`flow_tracked` (678–777):** C: первый пакет — не читать;
  SYN-ACK — запись доказана; иначе до 3 попыток `nat_family_hook`;
  `nat_state` 0/1/3, `g_nat_ok/miss/none/retry`. Rust `proc_nat`
  lookup + conntrack gate; три попытки/«нет таблицы» есть
  (`r2o-nat-proc-differential.sh`), **`g_nat_*` счётчики не
  ведутся** (N).
- **`routed_flow` (1593–1626):** C по `route_mark` ставит
  `fl->routed`, `routed_flows++`, `routed_first/mark`; без метки
  проверяет флаг, новый SYN его снимает. Rust
  `R2oRoutedFlows::r2o_skip_packet` (`r2o_route.rs:596`) вставляет
  key+reverse, новый SYN удаляет оба, чистит по idle/ёмкости. P;
  `r2o-route-gate-differential.sh`.
- **`d2k_session_sweep`/`expire`/`flows` (3353–3399):** C обходит
  TCP/UDP, при `ct_query` — `ct_flow`/`ct_tcp_flow`;
  `expire` — FIN-window + TCP-callback + UDP без callback;
  `flows` — сумма. Rust — периодический sweep, `expire_with_silent`
  + UDP expire, `tcp.len()+udp.flows`. P.

## Углублённая сверка: 11 N-функций

**Прочитано построчно: 11/11 N-функций; тела прочитаны по указанным строкам, отсутствие/частичность аналогов в R2O подтверждены поиском по `crates/`.**

- **`count_reason` (static, 165–186):** гистограмма причин отказа по
  указателю/строке, до 32 записей, печатается в итоговой сводке `d2kd`.
  R2O причины передаёт в `RefusedEvent`/журнал, но агрегированной таблицы
  и печати нет. N — диагностика, packet-path не меняет.
- **`offline_self_check` (static, 1118–1123):** `--offline-self-check`
  проверяет `D2K_CTL_PROTO_VERSION == D2K_RUNTIME_WIRE` и SHA-256("abc")
  по эталону. R2O SHA-256 покрыт `test-core-crypto-differential.sh`; своя
  offline-самопроверка есть у панели (`r2o-panel/tests/cli.rs:135`), но у
  `r2o-datapath` (преемник `d2kd`) этой CLI-опции нет. N — CLI/self-check.
- **`d2k_session_nat_stats` (650–656):** глобальные `nat_ok/miss/none/
  retried`; R2O `proc_nat` эти счётчики не ведёт. N — диагностика NAT.
- **`d2k_session_applied` (3541–3543):** агрегат `s->applied`; R2O
  APPLIED отдаёт событием/журналом, сводного числа нет. N — диагностика.
- **`d2k_session_done` (3545–3547):** агрегат `s->done`; аналог —
  событие `PLAN_DONE`, сводного счётчика нет. N — диагностика.
- **`d2k_session_damaged_count` (3549–3551):** `s->damaged_flows`; в R2O
  есть флаг `damaged` на потоке, но не агрегат. N — диагностика.
- **`d2k_session_sent_lost` (3553–3555):** «некому приписать отправку»;
  в R2O счётчика нет. N — диагностика.
- **`d2k_session_suspects` (3597–3599):** агрегат `s->suspects`;
  в R2O SUSPECT — событие, сводного числа нет. N — диагностика.
- **`d2k_session_exchanges` (3605–3607):** агрегат `s->exchanges`;
  в R2O EXCHANGE — событие журнала, сводного числа нет. N — диагностика.
- **`d2k_http_trace` (9–50):** строка `d2kd: HTTP execution host=...
  hook=... mark=... outdev=... status=... prepared=... plan=...
  execution=... planned/raw_sent/queued/original/output_failed/reason`.
  R2O пишет события портала/ответа и flow journal, но не этот текстовый
  трейс; `grep "HTTP execution"` по R2O пуст. N — диагностика.
- **`d2k_session_shape_tcp_options_family` (2982–2990):** C хранит
  `shape_opts[4][40]`/`shape_opts_len[4]` и отдаёт полный набор TCP-опций
  снимка. R2O `ClientShapeEvent` (`r2k-core/control.rs:421-433`) несёт
  полный ClientHello и только булев `tcp_has_timestamp`; v22
  `CLIENT_TCP` уходит с пустыми TCP options. Произвольные опции
  (MD5/порядок TS и др.) не передаются, D2O-контроллер получает `NO_TS`
  для TS-клиента. N — отсутствует сам API полного набора опций.

**Итог:** 11 N: 10 диагностических/CLI-величин и один реальный
packet-path-пробел (`shape_tcp_options_family`). Счётчики событий в R2O
есть на уровне событий/журнала, но не в виде сводных C-геттеров.

## Углублённая сверка: session/track/hold/capture/wire

- **`session.c` (70+ функций):** `session_packet` (974 строки) и
  `handle_udp` (791 строка) — TCP/UDP-путь: заголовки, направление,
  capture, TLS/HTTP, план, сборка, ipfrag, NAT-fragment, voice/QUIC.
  R2O — `engine.rs:1440 decide_with_session_mode`, `:1849 decide_tcp`,
  `r2o_udp_sessions.rs`, `r2o_quic.rs`, `r2o_voice.rs`. Основные ветви
  покрыты `test-datapath-default-mode-differential.sh`,
  `r2o-udp-exchange-differential.sh`, `test-controller-udpplan-differential.sh`,
  voice/quic differentials; полный набор ветвей C не доказан — P.
  **Подтверждённый пробел TCP-опций:** C хранит
  `shape_opts[4][40]`/`shape_opts_len[4]` (`session.c:142-143,2258-2259,2947-2949`)
  и отдаёт их `d2k_session_shape_tcp_options_family` (2982–2990). R2O
  `ClientShapeEvent` (`r2k-core/control.rs:421-433`) несёт полный
  `client_hello` и только булев `tcp_has_timestamp`; полного набора
  TCP-опций нет. `ARM_SHAPE`/повтор формы не может воспроизвести
  произвольные опции клиента (MD5/TS-порядок и др.), только факт TS.
  Это **N**, а не P: отсутствует сам API полного набора опций; базовый
  TLS-путь работает, но точная форма TCP-опций не передаётся.
- **`track.c`:** `d2k_key_make*`, `round_pow2`, `key_eq/key_hash`,
  `d2k_track_new/find/get/new_connection/remove/walk/expire/remove_if/
  count/capacity/refusals` сверены с `engine.rs` HashMap +
  `flow_capacity.rs` (`try_with_capacity`, лимит 3/4 слота, округление
  capacity). `d2k_track_new_connection` сбрасывает поля, сохраняя учёт
  посылок; R2O создаёт новый `TcpSession`, а execution-идентификаторы
  переносит через tickets. P, полного C/Rust differential таблицы нет.
- **`hold.c`:** `d2k_hold_parse/new/free/flush/next/get_stats/verdicts/
  feed` сверены с `hold.rs` (`HOLD_SLOTS=16`, `HOLD_PACKETS=8`,
  `HOLD_PACKET_BYTES=1600`, `HOLD_WAIT=100ms`, `FeedResult`,
  `r2o_hold_stats`). `d2k_hold_verdicts` — цикл `send(ctx,id,verdict)`;
  R2O `send_verdicts` делает то же. D6 `test-datapath-hold-differential.sh`
  и unit `hold.rs` покрывают lifecycle; P на редкие состояния/таймауты.
- **`capture.c`:** `d2k_capture_forget/reject/feed_ready/feed` сверены с
  `capture.rs` (`SlotState::{Free,Collecting,Rejected,Delivered}`,
  `CAPTURE_WINDOW`, `try_*`), тесты capture lifecycle; P.
- **`wire.c`:** `d2k_wire_build` (TCP: профили, MD5, TS, ts_up,
  seq_shift, poison, суммы) — E: `wire.rs:18 build_tcp_packet`, 12 тестов
  + `test-wire-ts-up-plan-differential.sh`. `d2k_wire_build_udp` — P:
  R2O `wire.rs:213 build_udp_packet` отвергает **любой** poison, включая
  `POISON_IPID_ZERO`, который C для IPv4 допускает (`wire_udp.c:75,136`),
  и берёт TOS из пакета; `raw.rs:181` собирает пакет, но этот divergence
  не покрыт.
- **Вывод:** session/hold/capture/track — P с конкретными пробелами
  (TCP options, полная таблица, редкие таймауты); wire TCP — E, wire UDP —
  P из-за IPID_ZERO/TOS.

## Углублённая сверка: nfq/udp_hold/udp_path/udp_release/http80

- **`nfq.c`:** `say`, `nl_write`, `await_ack`, `send_and_ack`, `set_rcvbuf`,
  `d2k_nfq_open/close/fd`, `d2k_nfq_recv`, `d2k_nfq_verdict(_payload)`,
  `d2k_nfq_lost` сверены с `nfqueue.rs`/`netlink.rs`. Bind/params/ACK,
  `SO_RCVBUF(FORCE)`, очередь и счётчик `lost` покрыты netlink/NFQUEUE
  тестами. **Расхождение ENOBUFS:** C `d2k_nfq_recv` при `ENOBUFS`
  возвращает `-2`, `d2kd.c:1590` делает `d2k_hold_flush(..., all=1)` для
  TCP и только `d2k_udp_path_expire(..., read_follows=0)` для UDP; R2O
  `ReceiveError::LostPackets` (`main.rs:1312-1335`) вызывает
  `holding.flush(..., all=true)` **и** `udp_holds.r2o_drain()` +
  `udp_deferred_verdicts/resends.r2o_drain_accept()`, то есть сбрасывает
  все UDP-удержания, а не только истёкшие. P, конкретный behavioural gap.
  EINTR: C возвращает 0, R2O `ReceiveError::Wait`; `receive_error_requires_flush`
  для `Wait` = false, поэтому наблюдаемое поведение цикла совпадает.
- **`udp_hold.c`:** `same_key`, `clear_slot`, `release_slot`, `new/free/
  flush/feed/feed_marked/take/next_ns` сверены с `r2o_udp_hold.rs`:
  `SLOTS=16`, `PACKETS=8`, `PACKET_MAX=1600`, `WAIT=100ms` совпадают;
  release/follow slots 16/8 и 256. P на редкие переполнения/метки.
- **`udp_path.c`:** `d2k_udp_path_pre/post/read/expire/passed/planned`
  перенесены в UDP-цикл `main.rs`/`r2o_udp_sessions`; проверка 5-мс follow
  и «номер чтения» реализована. P, полного C/Rust differential нет.
- **`udp_release.c`:** `d2k_udp_release_new/free/enqueue/flush/next_ns`,
  `d2k_udp_replay_fates`, `release_batch`, `follow_*`, `d2k_udp_send_busy`,
  `d2k_udp_out_*` сверены с `main.rs`/`r2o_udp_hold.rs`. `send_busy`
  (EAGAIN/EWOULDBLOCK/ENOBUFS) — E (`r2o_udp_send_busy`); остальное P.
  ENOBUFS-дренаж см. выше.
- **`http80.c`:** `d2k_http80_new/free/get_stats/set_https/https`,
  `executed/delivered/sweep/packet/swap`, `d2k_http_request/hello`.
  **Ёмкость/вытеснение:** C `D2K_HTTP80_FLOWS=128`, `NAMES=256`; `make`
  вытесняет самый старый поток (`http80.c:217-236`). R2O
  `HTTP_FLOW_CAPACITY=1024` (`hold.rs:20`) и при заполнении **не
  вытесняет**, а отказывает новому потоку (`hold.rs:1080-1084`). Это
  реальное расхождение: R2O дольше держит старые HTTP-потоки и иначе
  ведёт себя при переполнении. `set_https` C 256 имён с вытеснением
  `min(expires)`; R2O `control.rs:1055-1088` — те же 256 и
  `min_by_key(expires)`, совпадает.
  Состояния `ST_FREE/…/ST_SWAP` и D17-дифференциал покрывают портал/307/
  поздний ответ/дубль; полный набор C-состояний не доказан — P.
  `http80_log` — событие вместо текста, `http_trace` — N (см. выше).
- **Вывод:** nfq/udp/http80 — P с двумя конкретными расхождениями:
  ENOBUFS-дренаж всех UDP-удержаний и HTTP80 1024-без-вытеснения против
  128-с-вытеснением. Остальное — архитектурная замена/неполные
  differentials.

