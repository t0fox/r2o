# Глубокий аудит datapath-core: N-ряды и ключевые P

Дата: 2026-11-11. Это отдельный отчёт; `docs/audit/datapath-core.md` не изменялся.

## Baseline и метод

- D2O (oracle): `E:\d2o-a378w`, SHA `a378e230947ebfd011439e1cac0f1e994d883aae`.
- R2O: `E:\r2o`. HEAD на момент завершения аудита:
  `6bef8f77b0be9fbca2b79a73a69ba730a3c0a2b7` (во время аудита HEAD
  двигался; параллельные коммиты меняли только `docs/audit/*`, исходники
  `crates/**` не менялись). Отчёт `datapath-core.md` писался на HEAD
  `d7b5a879…`; номера строк Rust ниже сверены с `6bef8f77…`.
- Срез: `E:\r2o-tooling\audit\slice-datapath-core.csv`, 400 функций.
- База для «текущего статуса»: `docs/audit/datapath-core.md` (E 120, P 270,
  N 10).
- Метод: прочитаны тела C-функций по исходникам, найдена Rust-реализация по
  коду, сверены ветви, коды ошибок, побочные эффекты и состояние. Для
  проверяемых контрактов запущены целевые тесты и дифференциалы (список ниже).
  Никакие исходники и существующие отчёты не изменялись; новый файл —
  только этот отчёт. Временные harness-файлы лежат вне репозитория:
  `E:\r2o-tooling\tmp\wire-udp-audit\`.

### Ограничения

- Не запускался `scripts/test-nfq-ipv4-recv-error-differential.sh`: нужен
  root и сетевые namespace; в WSL пользователь `uid=1000`, sudo без пароля
  недоступен. D2O `d2kd` при этом собран из pinned SHA, R2O binary в
  `r2o-tooling/linux-target/release` есть, но предусловие root не выполнено.
- HTTP/80 differential — только 6 сценариев (`cases=6`), не весь набор
  состояний C `d2k_http80_packet`.
- Wire-UDP harness — только IPv4; IPv6-псевдозаголовок и IPv6-сумма
  проверены чтением кода, не differential-ом.
- Проверки выполнены в WSL Ubuntu 26.04, cargo 1.98.0; OpenWrt/musl и
  реальный роутер не задействованы.
- «E» в таблице означает либо подтверждённый дифференциал/тест, либо прямую
  структурную эквивалентность без ветвей. «Тест есть, не перезапускался» —
  явно указано в строке.

## Реально выполненные проверки

| Команда/действие | Результат |
|---|---|
| `cargo test --locked --offline -p r2o-datapath --lib` | 263 passed, 0 failed, 3 ignored |
| `cargo test --locked --offline -p r2o-datapath --bin r2o-datapath` | 52 passed, 0 failed |
| `cargo test --locked --offline -p r2k-core --test wire` | 12 passed |
| `cargo test --locked --offline -p r2k-core --lib translates_r2o_tcp_stall_and_exchange_to_v22` | 1 passed; тест **закрепляет пустые TCP options** в v22 `CLIENT_TCP` |
| `cargo test --locked --offline -p r2o-datapath --lib http` | 20 passed, 1 ignored (`d17_http80_trace`) |
| `cargo test --locked --offline -p r2o-datapath --lib arm_shape` | 1 passed (только TCP-половина) |
| `cargo test --locked --offline -p r2o-datapath --lib incomplete_fixed_length_response_is_reported_after_quiet_period` | 1 passed |
| `cargo test --locked --offline -p r2o-datapath --lib server_fin_completes_close_delimited_response_and_client_fin_reports_cut` | 1 passed |
| `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/test-datapath-http80-differential.sh` | `cases=6`, PASS (C/Rust HTTP/80 replacement) |
| C/Rust wire-UDP harness (C `wire_udp.o` pinned SHA против `r2k_core::wire::build_udp_packet`) | 4 сценария poison; результаты ниже |
| `make -C /mnt/e/d2o-a378w/datapath d2kd` | собрался (для будущего nfq-differential; сам differential не запускался) |
| `r2o-datapath --help` и `--version` (prebuilt `r2o-tooling/linux-target/release`) | подтверждено отсутствие `--log/--duration/--health-file/--sched-slots/--self-check`; `--version` = `release=dev wire=48` |

Wire-UDP harness, IPv4, TOS 0x28 у исходного пакета, TTL 8, payload `xyz`:

```text
poison=0x00            C: 4500001f1235400008117472c0a80143c6336408c73801bb000b584378797a
                       R: 4528001f123540000811744ac0a80143c6336408c73801bb000b584378797a
poison=0x04_ipid_zero  C: 4500001f00004000081186a7c0a80143c6336408c73801bb000b584378797a
                       R: len=0
poison=0x10_ts_up      C: 4500001f1235400008117472c0a80143c6336408c73801bb000b584378797a
                       R: len=0
poison=0x01_badsum     C: len=0
                       R: len=0
```

Отсюда: при `poison=0` и TOS=0 пакеты байт-в-байт совпадают; расхождения —
TOS (C пишет 0, R2O копирует DSCP/ECN), IPID_ZERO для IPv4 (C собирает, R2O
отвергает) и TS_UP/MD5 (C игнорирует, R2O отвергает).

## Таблица проверки

**Прочитано построчно: все перечисленные в таблице функции (тела и ветви); полный реестр 400 функций — в `datapath-core.md`, где отмечены все строки.**

`C-строки` — по срезу. `Rust` — файл:строка/символ. «Текущий» — статус в
`datapath-core.md`, «проверенный» — результат этой сессии.

| C-функция | C-строки | текущий статус | проверенный статус | Rust (file:line/символ) | доказательство или конкретный пробел |
|---|---|---|---|---|---|
| `wr16` (wire_udp, static) | 22–25 | E | E | `crates/r2k-core/src/wire.rs:552 write_u16` | каноническая big-endian запись; участвует в golden/harness, сумма совпала |
| `sum16` (wire_udp, static) | 31–40 | E | E | `wire.rs:534 sum16` | RFC1071, нечётный хвост; UDP-сумма harness `0x5843` совпала |
| `fold` (wire_udp, static) | 42–47 | E | E | `wire.rs:545 checksum_value` | та же свёртка; harness |
| `pseudo_sum` (wire_udp, static) | 57–65 | P | P | `wire.rs:271-284` (inline в `build_udp_packet`) | IPv4-псевдозаголовок подтверждён harness; IPv6 только по коду, отдельного теста нет |
| `d2k_wire_build_udp` | 67–207 | P | P | `wire.rs:213 build_udp_packet` | Три расхождения: (1) C разрешает `POISON_IPID_ZERO` для IPv4 (`wire_udp.c:75,136`), R2O отвергает любой `poison != 0` (`wire.rs:218`); harness: C len=31 id=0, R2O len=0. (2) C пишет TOS IPv4 = 0 (`:130`), R2O копирует DSCP/ECN (`wire.rs:244`); harness `…7472…` против `…744a…`. (3) C игнорирует `MD5`/`TS_UP`/`urgent`, R2O отвергает (`wire.rs:218,222-223`); harness TS_UP: C len=31, R2O len=0. Совпадают: checksum всегда и 0→0xffff, ID+1, TTL, seq_shift/pre/wire_profile/ipfrag-отказы. IPv6: C берёт `traffic_class`/`flow_label` из `d2k_conn`, R2O — из пакета; при штатном шаблоне совпадает, отдельного IPv6-harness нет. `validate_runtime_plan` при этом допускает UDP-план с IPID_ZERO (`engine.rs:2081-2085`) — отказ возникает уже на сборке |
| `d2k_nfq_recv` | 254–274 | P | P | `crates/r2o-datapath/src/nfqueue.rs:190 receive`, `:195 receive_timeout_with_fd`, `:263 ENOBUFS`; `main.rs:57 receive_error_requires_flush` | `EAGAIN/EWOULDBLOCK/EINTR`: C возвращает 0, R2O — `Wait/Io`, но `main` фильтрует Interrupted/WouldBlock и не делает flush; наблюдаемое «пакета нет» совпадает. `ENOBUFS`: оба считают lost, но C только сбрасывает hold и двигает UDP-path (`d2kd.c:1589-1593`), R2O дополнительно дренирует **все** UDP-hold и deferred verdicts/resends (`main.rs:1320-1336`) — досрочный выпуск и смена порядка на редком пути. `receive_error_policy_preserves_poll_and_empty_queue_cases` passed (проверяет политику R2O, не C-паритет) |
| `main` (ветка recv/ENOBUFS) | 1580–1593 | P | P | те же | C на `-1/-2`: `hold_flush` + `udp_path_read` + `udp_path_expire`; R2O на ошибке дополнительно `udp_holds.r2o_drain()` и ACCEPT всех deferred verdicts. R2O логирует каждый ENOBUFS, C — только счётчик. Целевой ENOBUFS-дифференциал не запускался |
| `main` (d2kd) | 1125–2415 | P | P | `main.rs:884 run`, `:2754 parse_options`, `:2952 print_help` | Нет CLI-опций `--log`, `--duration`, `--health-file`, `--sched-slots` (C: 1155, 1158, 1181, 1185); нет `freopen` stdout+stderr (`d2kd.c:1236-1245`), таймера duration (`:1483-1485`), heartbeat (`:1477`), настройки ёмкости sched (`:1347`). Shutdown по SIGINT/SIGTERM (`main.rs:1083-1174`) функционально повторяет финальный flush/stats/journal C. Добавлены чужие опции `--family/--check/--controller-only/--control-wire/--rcvbuf`; `--version` печатает `wire=48`, C — `wire=22` |
| `count_reason` (static) | 165–186 | N | N | нет; `engine.rs:1658 PacketDecision` без поля причины | C хранит до 32 строк «причина → счётчик» и печатает их в `print_stats` (`d2kd.c:1026-1028`), вызов на каждом `res.skipped` (`:1895-1897`). В R2O у `PacketDecision` нет строки причины для Accept-веток (только `Refused{plan_id}`/`FlowUnfit`), гистограммы и вызова нет |
| `print_stats` (static) | 878–1030 | P | P | `main.rs:629-766` | R2O печатает process/queue/raw/flow/sched/hold/capture/payload/icmp/reply-hidden. **Нет**: applied/done/damaged/sent_lost (C 933-939), NAT (1003-1008), exchanges/suspects (956-961), plan count/capacity (1024-1025), shape misses (1022-1023), verdict/send/recv errors (995-997), HTTP80 stats (893-906), routed flows (1009-1010), `udp_marked_kept` (1011-1012), reason histogram (1026-1028). `r2o_shape_misses()` и `r2o_plan_count()` в R2O есть, но не печатаются |
| `offline_self_check` (static) | 1118–1123 | N | N | нет; `main.rs:893-898` только `--version` | C-обёртка `runtime/d2k_runtime.h:26-33` даёт `--release-id` и `--self-check`; проверка = валидный release id + SHA-256("abc") (сравнение `D2K_CTL_PROTO_VERSION == D2K_RUNTIME_WIRE` тавтологично, это один и тот же макрос). R2O не имеет ни флагов, ни KAT, ни проверки release id. В отчёте флаг назван `--offline-self-check`; в C такого флага нет |
| `http80_log` (static) | 717–728 | P | P | `main.rs:3136 send_http_portal_event` | C печатает «HTTP … вставка провайдера — 30x на … через … мкс после запроса при RTT …; исход»; R2O отправляет только событие `EVENT_HTTP_PORTAL`, текстовой строки нет |
| `log_send_fail` (static) | 253–261 | P | P | `main.rs:186-196` (агрегаты) | C печатает первые 16 busy-строк (`what`+`err`), затем только счётчик; отдельная адресная строка — `out_resend_failed` (`d2kd.c:651-671`, первые `D2K_UDP_REFUSED_LOG` потоков). R2O печатает только агрегат `resend_failed/verdict_failures`, без per-flow строки и лимита 16 |
| `out_marked` (static) | 615–635 | P | P | `main.rs:108-129 r2o_udp_mark_plain_pass` | C считает `udp_marked_kept`, логирует первые 16 потоков (sport/dport/mark/outdev) и печатает счётчик (`d2kd.c:1011-1012`). R2O при ненейтральной метке просто возвращает `false`: ни счётчика, ни лога, ни строки в сводке |
| `d2k_session_nat_stats` | 650–656 | N | N | `r2o_conntrack_gate.rs:55-93 confirm` (только `Confirmation`) | C ведёт глобальные `g_nat_ok/miss/none/retried` (инкременты 700, 741, 747, 752, 761) и печатает их (`d2kd.c:1003-1008`). R2O различает `Tracked/Missing/NoConntrackTable/FirstPacket/TcpSynAck`, но счётчиков не ведёт |
| `d2k_session_applied` | 3541–3543 | N | N | нет; `main.rs:3715 send_applied_event` | C `s->applied++` на выдаче плана (1554 UDP, 2589 TCP), до отправки. R2O на handoff пишет только `record_plan_prepared` (`main.rs:2081-2084`), а `EVENT_APPLIED` шлёт после `execution_succeeded` (`main.rs:2626-2639`). Это не только отсутствие счётчика, но и другая семантика «применён» |
| `d2k_session_done` | 3545–3547 | N | N | `engine.rs:627 r2o_mark_plan_done_for_execution` (bool) | C `s->done++`, когда `sends_left == 0` (3423); учитываются и UDP-исполнения (тесты `test_quic_session`). R2O ведёт только TCP-флаг `plan_done`, UDP-учёта нет, агрегата нет |
| `d2k_session_damaged_count` | 3549–3551 | N | N | `engine.rs:672 r2o_mark_damaged_for_execution` (bool) | C `s->damaged_flows++` один раз на поток (3477), включая UDP с `payload_on_wire`. R2O имеет только TCP-флаг `damaged`; `r2o_udp_sessions.rs:383-407 r2o_note_execution_failure` не помечает UDP damaged, только сбрасывает `plan_applied`. Агрегата нет |
| `d2k_session_sent_lost` | 3553–3555 | N | N | нет | C `s->sent_lost++` при чужом/просроченном completion (3417). R2O `r2o_mark_plan_done_for_execution` молча возвращает `false` при несовпадении (`engine.rs:639-648`), `r2o_finish_tcp_execution` игнорирует результат (`main.rs:411-431`); счётчика нет |
| `d2k_session_suspects` | 3597–3599 | N | N | события `r2o_quic.rs`, `r2o_voice.rs`, TCP early-RST; агрегата нет | C `s->suspects++` один раз на поток (493), печать в сводке (956-961). R2O хранит `suspected` на потоке (`r2o_quic.rs:105`, `r2o_voice.rs:77`, `engine.rs:152 rst_cut_reported`), но общего числа не ведёт |
| `d2k_session_exchanges` | 3605–3607 | N | N | `engine.rs:377 tcp_exchange_events`, `r2o_udp_sessions.rs:112 udp_exchange_events` | C `s->exchanges++` (911, 921, 932, 1869), печать 956-961. R2O события обмена/STUN/voice есть, счётчика нет; `take_*_exchange_events` только опустошает очередь |
| `d2k_session_sent` | 3407–3428 | P | P | `main.rs:411 r2o_finish_tcp_execution`, `engine.rs:627` | TCP-путь покрывает DONE, но C считает `sends_left/done` и для UDP (`d2kd.c:2194`, `test_quic_session.c`), а в R2O UDP-исполнение учитывается только флагом `plan_applied`/`udp_replan`; stale completion не даёт `sent_lost` |
| `d2k_session_exec_failed` | 3449–3501 | P | P | `main.rs:468 r2o_fail_pending_applied`, `:446 r2o_execution_is_damaged`, `r2o_udp_sessions.rs:383` | TCP-ветви (payload_on_wire, orig_spent/taken, guards=0, журнал DAMAGED) совпадают. Для UDP C при `payload_on_wire` помечает поток damaged (3476-3498); R2O `r2o_execution_is_damaged` тоже вернёт true, но у UDP-сессии нет `damaged`, есть только `udp_replan` |
| `d2k_session_routed_flows` | 2659–2661 | P | P | `r2o_route.rs:580 R2oRoutedFlows` | C `s->routed_flows++` (1609) и печать (1009-1010). R2O хранит `HashMap` обеих сторон потока (`r2o_route.rs:581`), но публичного счётчика нет (`len()/2` не выставлен), в сводке не печатается |
| `d2k_session_shape_tcp_options_family` | 2982–2990 | P | **N** | `r2k-core/src/control.rs:407 HelloEvent`, `:417 tcp_has_timestamp`; `engine.rs:952-955`; `control.rs:1202 translate_event_to_v22` | C отдаёт сырые 0..40 байт TCP-опций сегмента, на котором собрался ClientHello (`session.c:2258-2259`; `ctlsrv.c:362-368,647-652`). R2O хранит только `bool` из SYN (`engine.rs:952-955`), а v22 `CLIENT_TCP` отправляет пустые `options` (`control.rs:1212-1219`), что закреплено тестом `translates_r2o_tcp_stall_and_exchange_to_v22`. D2O controller (`core/sched.c:10432`, `client_tcp_profile` 2303-2317) для `len=0` даёт `NO_TS` (при совпадении ключа; иначе `UNKNOWN`) — в любом случае не `TS`, то есть TS-клиент классифицируется неверно. Это другой контракт, а не недоказанная ветвь |
| `d2k_session_want_shape_family` | 2931–2960 | P | P | `r2o-datapath/src/control.rs:1988 arm_client_shape`, `:2053 observe_client_shape` | TCP-половина работает (`arm_shape_serves_cached_client_hello_of_older_target` passed), но `arm_client_shape` отвергает `transport != 6` (`control.rs:2002-2014`), хотя декодер принимает 17 (`r2k-core/control.rs:925`); C поддерживает 17 и family 4/6 (`session.c:2931-2960`; `ctlsrv.c:339-345`). QUIC-снимок по запросу не отдаётся |
| `d2k_session_shape_family` | 2966–2980 | P | P | `control.rs:2053-2082` (кэш TCP), `HelloEvent.quic_snapshot` (`r2k-core/control.rs:415`) | C хранит снимок по (transport, family) и отдаёт его после утери потока. R2O кэширует только TCP `ClientShape` (кэш 512, `control.rs:1769`), QUIC Initial уходит в `EVENT_HELLO`, но в ARM-кэш не попадает |
| `d2k_session_shape` | 2962–2964 | P | P | `control.rs:1988` | C возвращает `shape[]` — снимок, снятый по запросу или из-за ECH; R2O отдаёт любой закэшированный TCP ClientHello по host/family. Для family 4 после ARM эквивалентно, но контракт «только запрошенный/ECH» шире |
| `d2k_http_trace` | 9–50 | N | N | нет; `main.rs:3136/3148` только события | C формирует строку `d2kd: HTTP execution host=… status=… prepared=… plan=… execution=… planned=… raw_sent=… queued=… original=… output_failed=… reason=…` и вызывает её на каждом HTTP-пакете (`d2kd.c:2229-2231`). В R2O строки `HTTP execution` нет; есть только `EVENT_HTTP_PORTAL`/`EVENT_HTTP_RESPONSE` |
| `d2k_http80_new` | 67–69 | P | P | `hold.rs:182 HoldTable` + `control.rs NamePlans` | C — один объект на 128 flow и 256 имён (`d2k_http80.h:40-41`). R2O — `HoldTable` + `NamePlans`; `HTTP_FLOW_CAPACITY = 1024` (`hold.rs:20`), имён 256. Ёмкости и владение разнесены |
| `d2k_http80_get_stats` | 75–79 | P | P | `hold.rs:83 R2oHoldStats`; `engine.rs R2oHttpKeepAliveStats` | C отдаёт 9 полей: requests/injections/answered/swap_failed/dropped/evicted/untracked/unparsed/later. R2O имеет только `later/unaligned/open_end` и статистику hold; requests, injections, answered, swap_failed, evicted, untracked, unparsed отсутствуют; строки HTTP80 в сводке нет (есть только keep-alive `later/unaligned/open_end`) |
| `name_norm` (static) | 83–95 | P | P | `control.rs:2233 canonical_name` | C принимает односложное имя, имя из цифр и точку в конце. R2O требует ≥2 метки и хотя бы одну нецифровую (`control.rs:2233-2259`), поэтому `set_https("localhost")`/`"123"` C примет, R2O — нет |
| `d2k_http80_set_https` | 97–118 | P | P | `control.rs:1055 set_https`, `:1077-1085` вытеснение | C вытесняет запись с минимальным `expires`; R2O делает то же и держит лимит 256 (`MAX_HTTPS_NAMES`); тест `set_https` в `control.rs` есть |
| `d2k_http80_https` | 120–129 | P | P | `control.rs:590 has_verified_https` | C: имя найдено и `now < expires`; R2O: подтверждённое имя и не истекло; тест есть |
| `find` (static) | 200–215 | P | P | `hold.rs:1097` поиск по key | C — фиксированные слоты и stale 60 с (`d2k_http80.h:50`), проверяется лениво в `find`/`make`. R2O — Vec и `retain` по `SYN_TRACK_TTL` 120 с в начале каждого `feed` (`hold.rs:375-376`), то есть окно простоя вдвое шире |
| `make` (static) | 217–236 | P | P | `hold.rs:1076-1085` | C при полной таблице вытесняет самый давний и считает `evicted`. R2O при 1024 занятых **отбрасывает новый** поток (`hold.rs:1080-1084`), `evicted` не считает |
| `d2k_http80_packet` | 349–525 | P | P | `hold.rs:1088 observe_http_response`, `:356 feed_observing_mode`, `main.rs:2006 build_http_redirect_packets` | D17 differential: `cases=6`, PASS (PASS/REPLACE/DROP, portal, post-server/post-client). Полный набор состояний C (untracked/unparsed/later/evicted/idle/keep-alive, SWAP/ANSWERED) не покрыт |
| `d2k_http80_swap` | 527–545 | P | P | `main.rs:2093 send_replacement`, `:2114 mark_http_response_answered` | D17 проверяет решение swap и пост-состояния; реальный NFQUEUE verdict с заменой и raw-RST через сокет дифференциалом не покрыт |
| `d2k_http80_sweep` | 305–323 | P | P | `hold.rs:255 sweep_http_responses` | Формула `max(3×RTT, 2 с)` совпадает (`hold.rs:283`); тесты `incomplete_fixed_length_response_is_reported_after_quiet_period` и `server_fin_completes_close_delimited_response_and_client_fin_reports_cut` passed |
| `d2k_http80_executed` | 238–254 | P | P | `hold.rs:209 note_http_execution` | C привязывает execution/binding к потоку запроса; R2O копирует `AppliedEvent` в flow. Покрыто косвенно D17 и HTTP-тестами |
| `d2k_http80_delivered` | 267–276 | P | P | `hold.rs:220 reject_http_response`, `:239 mark_http_response_answered` | C при неудачной доставке помечает invalid/DONE; R2O reject/mark. Покрыто HTTP-тестами |
| `cut_pending`/`cut_result` (static) | 289–303 | P | P | `hold.rs:260-293` | Условия обрыва и CUT (`response=4`, `body_bytes=max`) совпадают; тест `incomplete_fixed_length...` passed |
| `http80_cut` (d2kd, static) | 776–784 | P | P | `main.rs:3148 send_http_response_event` | C печатает «HTTP обрыв ответа host/path/body/request/RTT» и шлёт событие; R2O шлёт только событие, текстовой строки нет |

## Все N-ряды: отдельная сверка

**Прочитано построчно: 10/10 N-функций отчёта + 1 новый N (`shape_tcp_options_family`); тела и инкременты проверены по строкам.**

Список отчёта (10) подтверждён полностью; ни один N не «закрыт» событиями
или per-flow флагами.

1. `count_reason` — C `d2kd.c:165-186`, вызов `:1895-1897`, печать
   `:1026-1028`. R2O: `PacketDecision` (`engine.rs:1658-1673`) не содержит
   причины Accept-решения, таблицы причин нет. N.
2. `d2k_session_nat_stats` — C `session.c:650-656`, инкременты
   `700/741/747/752/761`, печать `d2kd.c:1003-1008`. R2O: только
   `Confirmation` в `r2o_conntrack_gate.rs:55-93`, счётчиков нет. N.
3. `offline_self_check` — C `d2kd.c:1118-1123` + `runtime/d2k_runtime.h:26-33`.
   R2O: только `--version` (`main.rs:893-898`); `--release-id`/`--self-check`
   и SHA-256 KAT отсутствуют. N. (Флаг в C называется `--self-check`, не
   `--offline-self-check`.)
4. `d2k_http_trace` — C `http_trace.c:9-50`, вызов `d2kd.c:2229-2231`.
   R2O: строки `HTTP execution` нет; только события портала/ответа
   (`main.rs:3136/3148`). N.
5. `d2k_session_applied` — C `session.c:3541-3543`, инкременты `1554/2589`.
   R2O: агрегата нет; `EVENT_APPLIED` шлётся после успеха, не на handoff. N.
6. `d2k_session_done` — C `session.c:3545-3547`, инкремент `3423`.
   R2O: только TCP-флаг `plan_done` (`engine.rs:627`), UDP-учёта и агрегата
   нет. N.
7. `d2k_session_damaged_count` — C `session.c:3549-3551`, инкремент `3477`.
   R2O: TCP-флаг `damaged` (`engine.rs:672`), UDP damaged нет, агрегата нет. N.
8. `d2k_session_sent_lost` — C `session.c:3553-3555`, инкремент `3417`.
   R2O: stale completion молча возвращает `false` (`engine.rs:639-648`),
   счётчика нет. N.
9. `d2k_session_suspects` — C `session.c:3597-3599`, инкремент `493`.
   R2O: только per-flow `suspected` и события, общего числа нет. N.
10. `d2k_session_exchanges` — C `session.c:3605-3607`, инкременты
    `911/921/932/1869`. R2O: очереди событий (`engine.rs:377`,
    `r2o_udp_sessions.rs:112`), счётчика нет. N.

Дополнительно статус **P → N** изменён для
`d2k_session_shape_tcp_options_family` (сырые TCP-опции не передаются; v22
`CLIENT_TCP` уходит с пустым набором, что меняет профиль TCP у D2O
контроллера). Итог: 11 N в проверенных строках, из них 10 — из отчёта, 1 —
новый.

## Ключевые P-расхождения (сверх «нет счётчика»)

**Прочитано построчно: ключевые P из таблицы; тела и ветви проверены по фактическим строкам, C/Rust-расхождения подтверждены.**

1. **wire_udp**: R2O отвергает `POISON_IPID_ZERO` для IPv4, который C
   разрешает; копирует DSCP/ECN вместо C-нуля; отвергает `MD5`/`TS_UP` и
   `urgent`, которые C молча игнорирует. Есть байтовый harness. При этом
   `validate_runtime_plan` допускает UDP-план с IPID_ZERO — план принимается,
   но ни одна посылка не собирается.
2. **nfq ENOBUFS**: R2O дренирует все UDP-hold и deferred verdicts, C — только
   истёкшие слоты и hold. Это меняет владение ID и порядок «голова → хвост»
   на редком пути; при потере пакетов ядра возможны досрочные ACCEPT.
3. **CLI**: отсутствуют `--log`, `--duration`, `--health-file`,
   `--sched-slots`; нет D2KH1-heartbeat в датапате; `--self-check` нет.
   `--sched-slots` подменён фиксированными 128 (`scheduler.rs:9,442`).
   C-умолчания: `--sched-slots 128`, `--duration 0` (бесконечно),
   `--health-file /tmp/d2k/d2kd.health`, `--log` не задан; R2O умеет только
   фиксированные 128 и не умеет остальные три.
4. **print_stats**: отсутствуют 10 групп строк (applied/done, NAT,
   exchanges/suspects, plan count/capacity, shape misses, verdict/send/recv
   errors, HTTP80 stats, routed flows, marked flows, reasons). Часть значений
   в R2O уже есть (`r2o_shape_misses`, `r2o_plan_count`), но не выводится.
5. **shape**: `ARM_SHAPE` для QUIC/UDP отвергается, хотя декодер и C его
   поддерживают; QUIC-снимок не кэшируется для позднего запроса.
6. **TCP options**: вместо сырых байт опций ClientHello передаётся bool из
   SYN; v22 `CLIENT_TCP` пуст, D2O-контроллер получает `NO_TS` для
   TS-клиента.
7. **HTTP80**: 1024 flow вместо 128, нет вытеснения (новый поток
   отбрасывается), нет 60-секундного idle, нет счётчиков
   requests/injections/answered/swap_failed/evicted/untracked/unparsed, нет
   текстовой строки `http80_log`.
8. **UDP-учёт исполнения**: `d2k_session_sent`/`exec_failed`/`done` для UDP
   в C есть, в R2O — только `plan_applied`/`udp_replan`; damaged/sent_lost
   для UDP не ведутся.
9. **routed flows**: таблица есть, но счётчик не выставлен и не печатается.
10. **out_marked / log_send_fail**: нет первых 16 адресных строк и счётчиков
    `udp_marked_kept`/busy-лимита; только агрегаты.

### HTTP80 и HTTP-trace: модель состояния и формат лога

C `d2k_http80_packet` — фиксированная таблица 128 потоков и явная
стейт-машина `ST_FREE/SYN/OPEN/IDLE/REQUEST/INJECTED/SWAP/ANSWERED/DONE`
(`http80.c:17-27`); `find`/`make` лениво чистят 60-секундный idle и вытесняют
самый давний поток с `evicted++` (`:196-236`). R2O вместо состояний хранит
запись `HttpRequestFlow` с полями `request_sequence/request_end/response/
applied/answered/ready_for_next` (`hold.rs:121-145`), таблица 1024 записи
(`hold.rs:20`), чистка `retain` по 120 с в начале `feed` (`hold.rs:375-376`),
при переполнении новый поток **отбрасывается** без вытеснения
(`hold.rs:1080-1084`). Поэтому C-ветки `IDLE` (следующий keep-alive запрос),
`INJECTED/SWAP/ANSWERED` и `evicted` в R2O выражены иначе; D17 покрывает
только 6 базовых сценариев.

Формат лога C — три разные строки: `d2kd: HTTP execution host=… status=…
prepared=… plan=… execution=… raw_sent=… queued=…` на каждый HTTP-пакет
(`http_trace.c:39-49`), `d2kd: HTTP … вставка провайдера — 30x на …` на
вставку (`d2kd.c:717-728`) и `d2kd: HTTP обрыв ответа host=… path=…` на CUT
(`d2kd.c:776-784`). В R2O ни одной из этих строк нет: только события
`EVENT_HTTP_PORTAL`/`EVENT_HTTP_RESPONSE` (`main.rs:3136-3156`) и
keep-alive-счётчики. Это соответствует N для `d2k_http_trace` и P для
`http80_log`/`http80_cut`.

## Предлагаемые исправления

Приоритет 0 — packet-path/совместимость:

1. `build_udp_packet` (`wire.rs:213`): разрешить `POISON_IPID_ZERO` для IPv4
   (писать ID 0), игнорировать `MD5`/`TS_UP`/`urgent` для UDP, как C; для
   IPv4 писать TOS 0. Добавить unit/differential на 4 случая harness
   (0/IPID_ZERO/TS_UP/BADSUM) + TOS 0x28; проверить `build_udp_fragments`.
2. `receive_timeout_with_fd`/`main.rs:1320-1336`: на ENOBUFS не дренировать
   все UDP-hold/deferred verdicts; повторить C-порядок (`hold.flush`,
   `udp_path_read`, `udp_path_expire`). Добавить ENOBUFS-дифференциал с
   удержанным UDP-слотом и отложенным вердиктом; проверить, что слот
   выпускается по due, а не сразу.
3. `d2k_session_shape_tcp_options_family`: хранить сырые 0..40 байт опций
   сегмента ClientHello (а не bool из SYN), передавать их в
   `EVENT_CLIENT_SHAPE`/`HelloEvent` и в v22 `CLIENT_TCP`; добавить
   differential с C для TS/NO_TS/пустых/битых опций. Проверить
   `core/sched.c:2303` на стороне D2O.
4. `ARM_SHAPE`: поддержать transport 17 и family 4/6, кэшировать QUIC
   Initial по (transport, family, name); отдавать снимок немедленно, если
   он есть. Тест: TCP/QUIC, family 4/6, повторный запрос после утери потока.

Приоритет 1 — наблюдаемость/сводка:

5. Добавить агрегаты `applied`, `done`, `damaged_flows`, `sent_lost`,
   `suspects`, `exchanges` в TCP- и UDP-сессии; инкрементировать в тех же
   точках, что C; печатать в `r2o_log_*`. Для applied сохранить C-семантику
   «на handoff», а не «после успешной отправки» (или явно разделить
   `APPLIED` и `SENT`).
6. `count_reason`: ввести причину пропуска (id/строку) в решение и таблицу
   до 32 записей; печатать в сводке; тест на 33 причины и дедупликацию.
7. `d2k_session_nat_stats`: добавить ok/miss/none/retried в
   `R2oConntrackGate`, инкрементировать на `Tracked`/`Missing`/
   `NoConntrackTable`/retry; печатать строку «поток ведётся conntrack».
8. `print_stats`: добавить отсутствующие строки (см. п. 4 выше), в том числе
   `r2o_shape_misses`, `r2o_plan_count`, routed flows, `udp_marked_kept`,
   verdict/send/recv errors, HTTP80 stats.
9. `d2k_session_routed_flows`: выставить счётчик (учитывать обе стороны
   HashMap как один поток) и печатать.

Приоритет 2 — CLI/диагностика:

10. `--log FILE` (append stdout+stderr, line-buffered), `--duration SEC`
    (дедлайн в цикле с обычным shutdown), `--health-file PATH` (D2KH1 раз в
    секунду), `--sched-slots N` (ёмкость `ScheduledQueue`), `--release-id`,
    `--self-check` (SHA-256("abc") + release id). Добавить CLI-тесты и
    duration/stats differential.
11. `d2k_http_trace` и `http80_log`: реализовать точные строки C или явно
    задокументировать отказ; добавить фикстуры из `test_http_trace.c` и
    `test_http80.c`.
12. HTTP80: привести ёмкость/вытеснение/idle к C (128 flow, 60 с, evict
    oldest) или обосновать 1024; добавить счётчики get_stats; тест на
    переполнение и `evicted`.

## Counts

- Проверено строк таблицы: **43** (не весь срез 400; выбраны все 10 N,
  ключевые P по wire_udp, nfq, session-счётчикам, shape, http80, http_trace,
  CLI).
- Статусы до: **E 3 / P 30 / N 10**.
- Статусы после: **E 3 / P 29 / N 11**.
- Изменено статусов: **1** — `d2k_session_shape_tcp_options_family` P→N.
- Подтверждено N из отчёта: **10/10**.
- Новых N: **1** (сырые TCP options).
- P-областей с новыми конкретными пробелами: **12** (wire_udp, nfq recv,
  recv-ветка main, CLI main, print_stats, out_marked, log_send_fail,
  want_shape, shape_family, http80 get_stats, http80 new/make,
  routed_flows). Отдельно уточнены UDP-учёт `sent/exec_failed` и
  HTTP80-логи/ёмкость без изменения статуса.
- Запущено: **8 cargo-прогонов** (lib/bin/wire/translate/http/arm_shape/
  incomplete/server_fin), **1 shell-дифференциал** (http80, `cases=6`),
  **1 C/Rust harness** (wire-udp, 4 poison-случая) и **1 проверка CLI**
  (`--help/--version`). Не запускался nfq-EIO differential (root/netns).
- Исходники D2O/R2O и существующие отчёты не изменялись.
