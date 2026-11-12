# Аудит паритета: datapath — планы и управляющий слой (D2O → R2O)

Дата аудита: 2026-11-11. Работа только с исходниками: код не менялся, роутер не затрагивался.

## Baseline

- D2O (oracle): `E:\d2o-a378w`, SHA `a378e230947ebfd011439e1cac0f1e994d883aae`.
- R2O: `E:\r2o`, HEAD `9272eafa7992e88dff99cd25056e93157008a3d5` (ветка `main`).
- Срез: `E:\r2o-tooling\audit\slice-datapath-plan.csv` — **183 функции** из 9 файлов:
  `datapath/plans.c` (75), `datapath/routemark.c` (23), `datapath/plan_parse.c` (17),
  `datapath/raw.c` (17), `datapath/plan_apply.c` (15), `datapath/ctl.c` (14),
  `datapath/ctlsrv.c` (12), `datapath/routemark_nl.c` (8), `datapath/include/d2k_plans.h` (2).
- Метод: прочитано тело каждой функции по `line..end_line` из среза; для каждой найдена
  конкретная Rust-функция (не совпадение имени), проверены ветви, состояния, коды ошибок и
  побочные эффекты. Тесты цитируются только те, которые реально есть в дереве; номера строк —
  по указанному HEAD.

## Статусы

- **E** — эквивалент подтверждён тестом/дифференциальной сверкой с D2O-фикстурами.
- **P** — реализация есть, но не все ветви/отличия доказаны; отличие или пробел названы в
  последней колонке.
- **N** — реализации нет.
- **?** — не установлено.

Static-хелперы наследуют статус владельца (владелец указан в колонке «назначение»).
«Размер» — число строк тела по срезу.

## Сводка

| Статус | Кол-во |
|---|---:|
| E | 105 |
| P | 72 |
| N | 5 |
| ? | 1 |
| **Всего** | **183** |

По файлам:

| Файл | Функций | E | P | N | ? |
|---|---:|---:|---:|---:|---:|
| datapath/plans.c | 75 | 34 | 39 | 1 | 1 |
| datapath/routemark.c | 23 | 19 | 3 | 1 | 0 |
| datapath/plan_parse.c | 17 | 14 | 3 | 0 | 0 |
| datapath/raw.c | 17 | 8 | 9 | 0 | 0 |
| datapath/plan_apply.c | 15 | 14 | 1 | 0 | 0 |
| datapath/ctl.c | 14 | 8 | 3 | 3 | 0 |
| datapath/ctlsrv.c | 12 | 6 | 6 | 0 | 0 |
| datapath/routemark_nl.c | 8 | 2 | 6 | 0 | 0 |
| datapath/include/d2k_plans.h | 2 | 0 | 2 | 0 | 0 |

---

## datapath/ctl.c (14 функций)

Транспорт управляющего сокета: открытие, один пир, кольцо исходящих кадров, разбор кадров.
R2O-аналог — `crates/r2o-datapath/src/control.rs` (`ControlServer`), плюс цикл в
`crates/r2o-datapath/src/main.rs` (вызывает `poll()` напрямую, без epoll-регистрации fd).

**Прочитано построчно: 14/14 функций, 316 строк C (1–316).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| say | 66-74 | 9 | static: форматирование текста ошибки (владелец — `d2k_ctl_open`) | `control.rs:1798` `ControlServer::open` — текст через `io::Error::new`/`format!` | P | Отдельного форматтера нет; тексты ошибок другие, поведение (причина названа) сохранено. |
| set_nonblock | 76-79 | 4 | static: `O_NONBLOCK` на fd | `control.rs:1852` `listener.set_nonblocking(true)`, `:2088` `peer.set_nonblocking(true)` | E | `control_server_accepts_reconnect_pending_after_previous_peer_closes` (control.rs:2343): без nonblocking цикл `accept_peer` завис бы. |
| d2k_ctl_open | 81-127 | 47 | создать AF_UNIX listener, снять старый файл, listen(1) | `control.rs:1798` `open`, `:1807` `open_with_profile` | P | `control_socket_is_private_to_its_owner` (control.rs:2325). Отличия: R2O не удаляет чужой не-сокет и занятый живой сокет, ставит права 0600, backlog по умолчанию. |
| d2k_ctl_close | 129-141 | 13 | закрыть оба fd и снять свой файл сокета | `control.rs:2220` `impl Drop for ControlServer` | E | `control_socket_is_private_to_its_owner` проверяет удаление пути и права. |
| d2k_ctl_listen_fd | 143-143 | 1 | вернуть listen fd для внешнего цикла | — | N | Цикл `main.rs:1388` вызывает `control.poll()` напрямую; дескриптор наружу не отдаётся. |
| d2k_ctl_peer_fd | 144-144 | 1 | вернуть fd пира | — | N | То же: пир инкапсулирован в `ControlServer`. |
| d2k_ctl_set_disconnect_hook | 146-150 | 5 | повесить hook на разрыв | `main.rs:1409-1415` — цикл сам вызывает `name_plans.clear_probes()` при `!is_connected()` | P | Hook в объекте отсутствует; эквивалент распределён по циклу. Тест `clearing_disconnected_http_probes_keeps_the_permanent_plan` (control.rs:3703) проверяет очистку. |
| d2k_ctl_accept | 152-177 | 26 | принять одного пира, второго отвергнуть | `control.rs:2084` `accept_peer` | E | `control_server_accepts_reconnect_...` (control.rs:2343) — второй лишний пир закрывается, переподключение принимается. |
| drop_peer | 179-188 | 10 | закрыть пир, очистить буферы, позвать hook | `control.rs:2210` `disconnect` | E | Тот же тест: после `drop(previous)` `is_connected()` ложно, затем принимается новый пир. |
| d2k_ctl_flush | 190-215 | 26 | дослать кольцо, EAGAIN — на следующий раз | `control.rs:2176` `flush` | E | `control_server_sends_a_tls_hello_event_to_connected_controller` (control.rs:2460) читает кадр после `send_event`. |
| d2k_ctl_event | 217-255 | 39 | положить кадр целиком или потерять и посчитать | `control.rs:1913` `send_event`, `:2164` `enqueue` | **P** | **Подтверждённое отличие размера:** C `D2K_CTL_OUT_RING=65536` (`ctl.c:21`), R2O `MAX_CONTROL_OUTPUT=128*1024` (`control.rs:28`). Оба кладут кадр целиком, при нехватке — `dropped++`/`dropped_events`; C дополнительно `sent++`, в R2O счётчика `sent` нет. `len>FRAME_MAX-2` → drop. Тесты `control.rs:2434`, `:2552-2583`. |
| d2k_ctl_poll | 257-313 | 57 | прочитать, разобрать кадры, рвать на невозможной длине | `control.rs:1883` `poll`, `:2110` `read_peer`, `:2138` `take_complete_frames` | **P** | C делает один `read` до EAGAIN и разбирает всё, что пришло; R2O `read_peer` читает блоками 8192 в цикле до EAGAIN, но не более `MAX_COMMANDS_PER_POLL=256` кадров (`control.rs:29,2114,2141`). Проверка длины `2..=FRAME_MAX`, разрыв на неверной длине/переполнении входа (`FRAME_MAX+4`) и удаление обработанного префикса совпадают. Reconnect-тест читает `EVENT_PROTOCOL`; границы `FRAME_MAX` — `take_complete_frames`. |
| d2k_ctl_dropped | 315-315 | 1 | счётчик потерянных кадров | `control.rs:1983` `dropped_events` | E | `control_server_counts_each_event_without_connected_peer...` (control.rs:2434) сверяет счётчик. |
| d2k_ctl_sent | 316-316 | 1 | счётчик поставленных в кольцо кадров | — | N | Счётчика `sent` в R2O нет; есть только `dropped_events`. |

Итог по файлу: E 6, P 5, N 3. Пробелы: нет доступа к fd (listen/peer), нет счётчика
отправленных кадров, hook разрыва реализован в цикле, а не в объекте; outbox R2O
128 КиБ против C 64 КиБ; `poll` разбирает до 256 кадров за вызов.

**Построчная сверка a378:** все 14 функций прочитаны. Кольцо `D2K_CTL_OUT_RING`
(C 65536), кадр `HDR=6` (`plen` включает 2 байта типа, `plen>=2`), `D2K_CTL_FRAME_MAX`,
потеря кадра при нехватке места и `dropped++`, EAGAIN-дозапись, один пир,
`drop_peer` при ошибке чтения — совпадают с `control.rs` (`send_event`/`enqueue`/
`take_complete_frames`/`disconnect`) по семантике; R2O `MAX_CONTROL_OUTPUT=128*1024`
и `MAX_COMMANDS_PER_POLL=256` расширяют пределы. Отличия: R2O не отдаёт listen/peer fd,
не считает `sent`, hook разрыва вызывает цикл `main.rs`, а не объект; `open`
не удаляет чужой не-сокет и ставит 0600/backlog по умолчанию.

---

## datapath/ctlsrv.c (12 функций)

Смысл команд и событий управляющего протокола. R2O: `NamePlans::handle` +
`ControlServer` (`crates/r2o-datapath/src/control.rs`), кодеки — `crates/r2k-core/src/control.rs`,
журнал событий — `flow_journal.rs` и `main.rs`.

**Прочитано построчно: 12/12 функций, 731 строка C (1–731).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| put_key | 23-37 | 15 | static: ключ потока 38 байт полями (владелец — `ack`/`pump`) | `capture.rs:51` `TcpFlowKey::wire_key`, `control.rs:1644` `r2o_udp_flow_wire_key` | E | Побайтово тот же порядок (family, low 16, high 16, порты BE, proto). Сверка раскладки — `d2o_control_frames_match_donor_wire_decoding` (tests/control.rs:47, разбор APPLIED-фикстур D2O). |
| d2k_plan_fits | 39-72 | 34 | отказ до установки: IPID=0 и длина посылки > предела | `control.rs:255` `r2o_plan_valid` (+`engine.rs:2091` запрет POISON_IPID_ZERO), `main.rs:986` проверка `max_emit` | P | Ветвь длины покрыта `name_plan_отклоняется_если_..._mtu` (control.rs:2766): `send_maxlen=1` — отказ, 1500 — успех. Ветвь `POISON_IPID_ZERO` реализована в `validate_runtime_plan`, но теста на неё нет. |
| ack | 84-110 | 27 | static: подтверждение команды с trial/area/binding | `control.rs:1898` `send_ack`; `r2k-core/control.rs:1983` `encode_ack_with_identifiers_profile` | E | `v22_control_server_greets_with_profile_release_and_raw_bound_ack` (control.rs:2494); ACK-фикстуры D2O в tests/control.rs:47. |
| ack_trial | 112-123 | 12 | static: ACK с trial ID (в т.ч. на отказ) | `control.rs:1898` (поле `Ack::trial_id`), `r2k-core/control.rs:1945` `encode_ack_for_trial` | E | `http_probe_plan_matches_only_its_source_port_and_acknowledges_trial_id` (control.rs:3489) и `encodes_http_probe_command_and_round_trips_its_correlated_ack` (tests/control.rs:493). |
| d2k_ctlsrv_greet | 125-145 | 21 | первое событие: версия провода, maxlen, release | `control.rs:2093` `encode_greeting_profile` при accept | E | `v22_control_server_greets_...` (control.rs:2494) и `control_server_accepts_reconnect_...` (control.rs:2343) читают `EVENT_PROTOCOL`. |
| d2k_ctlsrv_peer_closed | 147-150 | 4 | снять пробные планы при отключении контроллера | `main.rs:1415` `name_plans.clear_probes()`; `control.rs:600` `clear_probes` | E | `clearing_disconnected_http_probes_keeps_the_permanent_plan` (control.rs:3703). |
| canonical_address | 152-157 | 6 | static: family 4 требует нулевой хвост 16-байтного адреса | `control.rs:1612` `addr_plan_key` | E | `удаление_адреса_разделяет_формы_и_удаляет_одну` (control.rs:2793): `body[5]=1` даёт `ACK_BAD_ARGS`. |
| addr_shape_valid | 163-167 | 5 | допустимые формы адресной привязки (1,2,3,5,6) | `control.rs:1628` `valid_addr_shape`, `:1635` `addr_plan_matches_shape` | P | Валидные формы покрыты тестами адресов; отказа для недопустимой формы (0/4/7) в тестах не найдено. |
| read_probe_flow | 169-187 | 19 | static: разобрать flow адресного опыта, отвергнуть неканонический IPv4 | `control.rs:1695` `r2o_udp_addr_probe_flow_key` + `r2k-core/control.rs:1703` `valid_udp_addr_probe_flow` | **P** | **Ветви сверены:** C `b[0]!=4 && b[0]!=6` → -1; family 6 — копия 16+16 байт; family 4 — байты `b[5..17]` и `b[21..33]` обязаны быть нулевыми, копируются `b[1..5]`/`b[17..21]`; `src_port=b[33..35]`, `dst_port=b[35..37]`, `transport=b[37]`; **порты, адреса и transport не проверяются**. Rust `r2o_udp_addr_probe_flow_key` строит ключ из `SocketAddr` с `proto=17`; `valid_udp_addr_probe_flow` требует family 4/6, `flow[37]==17`, **оба порта ≠0**, старшие 12 байт IPv4 нулевые и младшие 4 ≠0 для обоих адресов (IPv6 — любой ненулевой блок). **Расхождения:** C принимает transport≠17 и нулевые порты/адреса; R2O отвергает. Голос C проводит через эту же команду при `src_port=0` (`ctlsrv.c:302-304`), R2O вынес в `SET_VOICE_ADDR_PROBE 0x0095`. Тестов SET/DEL/FIND адресного опыта в дереве нет. |
| d2k_ctlsrv_command | 189-509 | 321 | диспетчер команд, разбор тел, ACK, установка в таблицу | `control.rs:260` `NamePlans::handle`; `main.rs:68` `handle_control_command` (stall budgets); `control.rs:1988` `arm_client_shape` | **P** | Покрыты SET_NAME/BOUND/PROBE/ADDR/SUFFIX/BYPASS/DEL_*/HTTPS/ARM_SHAPE/STALL_BUDGETS (control.rs:2633-3896). **Подтверждённые расхождения:** (1) ~~`SET_HTTPS` TTL~~ — **закрыто 2026-11-12**: R2O обрезает TTL до **7 суток** (`MAX_HTTPS_TTL_SECONDS`), а кодировщик принимает любой `u32`; (2) `ARM_SHAPE`: C принимает transport 6/17 (`ctlsrv.c:341`), R2O — только 6 (`control.rs:2002`); (3) `SET_ADDR_PROBE`: C допускает `src_port=0` для голоса (`ctlsrv.c:302-304`), R2O generic-проба требует оба порта ≠0, а голос вынесен в `SET_VOICE_ADDR_PROBE` 0x0095, отсутствующую в C; (4) `DEL_NAME_PROBE`: C не проверяет shape (`ctlsrv.c:422-437`), R2O проверяет; (5) адресные опыты не тестированы; (6) `SET_NAME`/`SET_SUFFIX`: C не проверяет `shape` (передаёт `b[1+len]` в plantab), Rust `encode_set_name`/`encode_set_suffix` отвергает неизвестные формы; (7) `DEL_NAME`: C принимает любую пару `transport` (6/17) + `shape != ANY`, Rust `encode_delete_name` — только 6 с 1/2/4/6/7/8..13 или 17 с 3/5. C `DEL_NAME_BOUND`/`DEL_ADDR_PROBE` идемпотентны и всегда ACK OK — R2O так же. ARM_SHAPE: C `ctlsrv.c:335-344` проверяет `len==3+b[0]`, transport 6/17, family 4/6; при готовом слоте шлёт `EV_CLIENT_TCP` (transport 6) с TCP-опциями и `EV_SHAPE` (`:345-375`), затем ACK OK. R2O `arm_client_shape` (`control.rs:2002`) отвергает 17 и отдаёт только `EVENT_CLIENT_SHAPE` с `tcp_has_timestamp`. SET_ADDR_PROBE: C `ctlsrv.c:285-309` требует `fixed=KEY_LEN+16+4`, transport 17, `dst_port!=0`, lease 1..MAX, trial≠0; `src_port=0` допустим как голосовой wildcard (`:302-303`). Rust `encode_set_addr_probe` → `udp_addr_probe_flow` требует `source.port()!=0 && destination.port()!=0` (`control.rs:1679-1680`), `valid_udp_addr_probe_flow` — те же два порта (`:1707-1711`); голос вынесен в `SET_VOICE_ADDR_PROBE 0x0095` (`:1583-1610`), которой в C нет. DEL_NAME_PROBE: C `ctlsrv.c:422-438` проверяет только `len==5+b[0]`, family 4/6 и `probe_port!=0`; shape (`b[1+b[0]]`) передаётся в `d2k_plantab_del_name_probe_family` без проверки. Rust `encode_delete_name_probe` (`control.rs:1909-1929`) требует `valid_tcp_probe_shape(shape)` (`is_tcp_plan_shape`), family 4/6 и `source_port!=0` — неизвестная/не-TCP форма отвергается там, где C принял бы. SET_NAME/SET_SUFFIX: C `ctlsrv.c:208-261` проверяет только `len>=hdr` и family 4/6; shape (`b[1+len]`) передаётся в plantab без проверки. Rust `encode_set_name` (`control.rs:1360-1391`) допускает только {MODERN,LEGACY,QUIC,GRANDFATHER,VOICE,ECH_TCP,HTTP}+TCP-context, `encode_set_suffix` (`:1480-1504`) — {MODERN,LEGACY,QUIC,ECH_TCP}+TCP-context и совместимый план; неизвестная форма отвергается там, где C принял бы. SET_NAME_PROBE: C `:217-261` `hdr=5+b[0]`, family 4/6, shape без проверки; Rust `encode_set_name_probe` (`:1827-1854`) требует совместимый план, family 4/6 и `source_port!=0`. DEL_NAME: C `:407-421` принимает любую форму кроме ANY для transport 6/17; Rust `encode_delete_name` (`:1856-1879`) — только 6 с {MODERN,LEGACY,GRANDFATHER,ECH_TCP,HTTP}+context или 17 с {VOICE,QUIC}. |
| d2k_ctlsrv_pump | 511-694 | 184 | выгрузить новые записи журнала в события с раскладкой по типам | `main.rs:2728` `send_journal_updates`, `:2709` `send_journal_snapshot`; `flow_journal.rs:202` `to_event_frame`; `r2k-core/control.rs:1204` `translate_event_to_v22` | **P** | **Ветви C сверены:** `added<=*seen` → выход; `from = fresh>=have ? 0 : have-fresh`; `HELLO_SNI/HELLO_NONAME→EV_HELLO` (name_len+name); `SUSPECT→EV_SUSPECT` (code,d_ttl,d_ref_ttl,d_tos,d_ipid BE2,d_planned,d_client_shape,num clamp u16 BE); `PLAN_APPLIED` — `continue`, не отдаётся; `PLAN_DONE→EV_APPLIED` (plan_id16+trial_id16); `REFUSED/DAMAGED/UNSENT→EV_REFUSED` (code+plan_id+trial_id); `SHAPE` — для `key.proto==6` сначала `EV_CLIENT_TCP` с TCP-опциями из `shape_tcp_options_family`, затем `EV_SHAPE` с hello из `shape_family` по `key.proto`/family; `EXCHANGE→EV_EXCHANGE` (code,d_tos,num 4 BE,d_server_hello,d_planned); default skip; для APPLIED/REFUSED добавляются client_shape (только REFUSED), execution_id 8 BE и binding 28. **Rust:** `send_journal_updates` шлёт каждую запись как `EVENT_R2O_JOURNAL_ENTRY` (`flow_journal.rs:202-262`: version, kind id, at_ns, execution_id, key, code, name_len, name[32], num u32, ttl/ref_ttl/tos, server_hello, planned, client_shape, client_is_low, elapsed_ms, ip_id, mapped_ip/port, plan_id, trial_id, binding+28); dedicated `EVENT_HELLO/APPLIED/REFUSED/CLIENT_SHAPE` идут отдельными путями (`main.rs:3093,3715,3737`). Legacy v22 собирает `translate_event_to_v22`: `CLIENT_SHAPE→LEGACY_CLIENT_TCP` (опции **пустые**)+`LEGACY_SHAPE`; `R2O_TCP_EARLY_RST/RST_CUT` несут ttl/ref_ttl/tos/ip_id, а `REPEAT/SILENT/RST_AFTER_APP/FIN_RETRY/STALL` передают в legacy-suspect нули; `R2O_TCP_EXCHANGE→LEGACY_EXCHANGE` с полями. **Расхождения:** (1) C не отдаёт `PLAN_APPLIED`, R2O шлёт его как journal entry (контроллер только печатает); (2) v22 `LEGACY_CLIENT_TCP` без TCP-опций, C — реальные; (3) часть legacy-suspect теряет d_ttl/d_ref_ttl/d_tos/d_ipid; (4) C-события строятся из журнала при каждом pump, R2O v48 — из того же журнала, но иным форматом. |
| d2k_ctlsrv_http80_event | 697-731 | 35 | событие HTTP-портала/ответа с измерениями | `control.rs:3136` `send_http_portal_event`, `:3148` `send_http_response_event`; `r2k-core/control.rs:852` `HttpResponseEvent::event_body` | P | `decodes_r2o_http_response_context_and_measurements` (tests/control.rs:977), `control_decoder_accepts_http_portal_response_events` (tests/capture_shape.rs:150). Отличие: R2O кодирует `code 1..4` и всегда несёт хвост status/body/request_no; C для портала без ответа хвост не шлёт. |

Итог по файлу: E 6, P 6, N 0. Пробелы: TTL HTTPS (обрезка vs отказ), ARM_SHAPE для
UDP, пустые TCP-опции в v22 CLIENT_TCP, адресные опыты без тестов, формат HTTP-события.

**Построчная сверка a378:** все 12 функций прочитаны. Совпадают: `put_key` 38 байт
полями; `ack`/`ack_trial` (trial/area/binding, reason только при ok=0); greet
`PROTO` с версией/maxlen/release; `peer_closed` → clear_probes; canonical_address;
read_probe_flow family/хвост; диспетчер SET_NAME/BOUND/SUFFIX/PROBE/ADDR,
ADDR_PROBE, ARM_SHAPE, DEL_SUFFIX/BYPASS/DEL_NAME/BOUND/PROBE, SET_HTTPS,
STALL_BUDGETS, DEL_ADDR/PROBE, неизвестная → BAD_ARGS; pump-раскладка журнала;
http80_event code 1..4. **Расхождения:** перечисленные TTL/ARM/ADDR_PROBE/DEL_NAME_PROBE,
плюс `SET_NAME`/`SET_SUFFIX` без проверки shape, `DEL_NAME` с любой парой
transport+shape, v22 CLIENT_TCP с пустыми TCP-опциями, HTTP-событие C без хвоста
для портала.

---

## datapath/include/d2k_plans.h (2 функции)

**Прочитано построчно: 2/2 функции, 381 строка C (1–381).** Сверено с `r2k-core/control.rs:306-320` (`BindingContext`, `is_known`) и `delete_name_bound`/`binding_for_plan` (проверки `kind/family/shape/temporary/epoch`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| d2k_binding_known | 98-102 | 5 | static inline: `b`, `generation!=0`, `kind!=0`, хотя бы один ненулевой байт `epoch` | `r2k-core/control.rs:317-319 BindingContext::is_known` | **P** | **Подтверждённое отличие:** R2O `is_known` проверяет только `generation != 0 && epoch.iter().any(!=0)`, **без `kind != 0`**. C при `kind=0` считает identity неизвестной. В `delete_name_bound`/`binding_for_plan` `kind` проверяется отдельно (`==1/2/...`), но сам предикат известности шире. Тест `control.rs:3587`. |
| d2k_binding_equal | 103-108 | 6 | static inline: обе identity known; generation/kind/family/shape/temporary равны; epoch 16 байт равны | `BindingContext` derived `Eq/PartialEq` (`control.rs:306`) + проверки в `delete_name_bound` | **P** | R2O сравнивает `BindingContext` целиком через derived `PartialEq`, включая `kind/family/shape/temporary/epoch`; C дополнительно требует `d2k_binding_known` для обеих сторон. Отдельной функции «equal with known» нет: вызывающий проверяет `is_known` отдельно, а `is_known` не требует `kind`. Для известных контекстов с `kind!=0` результаты совпадают. |

Итог: E 0, P 2, N 0. Обе функции — inline-предикаты identity; поведение распределено по
`delete_name_bound` и `binding_for_plan`.

---

## datapath/plan_apply.c (15 функций)

Компиляция проверенного плана в список посылок. R2O: `crates/r2k-core/src/plan/apply.rs`
(`impl Plan`, `Actions`, `Emission`).

**Прочитано построчно: 15/15 функций, 931 строка C (1–931).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| anchor_offset | 26-80 | 55 | static: вычислить якорь разреза или отказать | `plan/apply.rs:862` `anchor_offset` | E | `sni_middle_anchor_is_clamped_inside_short_payload_and_requires_sni` (tests/apply.rs:96). |
| cmp_size | 82-85 | 4 | static: qsort-компаратор size_t | `plan/apply.rs:920` `points.sort_unstable()` | E | `split_owns_original_and_reverse_order_preserves_sequence_ranges` (tests/apply.rs) — порядок кусков. |
| split_points | 90-118 | 29 | static: якорь+смещение, сортировка, дедуп, отброс краёв | `plan/apply.rs:908` `split_points` | E | Тот же тест: куски и их границы. |
| tls_ch_layout | 120-154 | 35 | static: разметка ClientHello (rnd/session id), три разных отказа | `plan/apply.rs:970` `tls_client_hello_layout` | E | `tls_fake_modifiers_copy_session_id_randomize_and_keep_repeat_bytes_equal` (tests/apply.rs). |
| random_bytes | 156-163 | 8 | static: 32 случайных байта из `/dev/urandom` | `plan/apply.rs:1019` `secure_random` (`getrandom`) | E | Тот же тест: `TLS_MOD_RND` меняет random/SID. |
| wr16 | 165-167 | 3 | static: записать u16 BE | `plan/apply.rs:1036` `write_u16` | E | Наследует тест `tls_fake_modifiers...` (перезапись длин записи). |
| wr24 | 168-171 | 4 | static: записать u24 BE | `plan/apply.rs:1041` `write_u24` | E | Тот же тест (длина рукопожатия). |
| fake_tls_bytes | 173-237 | 65 | static: собрать копию приманки с правкой random/SID | `plan/apply.rs:531` `fake_tls_bytes` | E | `tls_fake_modifiers...` (tests/apply.rs) — оба профиля, DUPSID и RND. |
| emit_fake | 239-266 | 28 | static: заполнить `d2k_emit` из приманки и порчи | `plan/apply.rs:486` `emit_fake` | E | `no_action_plan_passes_original_and_fake_only_plan_keeps_original`, `interleaved_fakes...` (tests/apply.rs). |
| emit_vec_free | 268-272 | 5 | static: освободить массив посылок и owned_bytes | `plan/apply.rs:61` `Emission` (Vec) + `Drop` | E | Владение выражено типами (`Vec<u8>`, `Vec<Emission>`); утечек нет по построению, отдельный free не нужен. |
| emit_overhead | 285-295 | 11 | static: заголовки IP+TCP/UDP, MD5/TS-опция | `plan/apply.rs:737` `emit_overhead` | E | `max_emit`-тест (tests/apply.rs:251) и `route_segment_cap...` (tests/apply.rs). |
| d2k_plan_max_emit | 297-341 | 45 | верхняя оценка одной посылки плана | `plan/apply.rs:418` `Plan::max_emit` | E | `assert_eq!(plan.max_emit(), 171)` (tests/apply.rs:251); используется в `r2o_plan_valid`. |
| d2k_plan_apply | 343-873 | 531 | превратить план+пакет в посылки, судьбу оригинала и причину отказа | `plan/apply.rs:155` `Plan::apply` | **P** | 17 тестов tests/apply.rs покрывают split/fake/overlay/order/pace/settle/delay/udplen/qsplit/qdeny/oob/metric. **Подтверждённые расхождения:** (1) OOB-ветвь: Rust ставит `wire_profile` только `first`/`urgent` (`apply.rs:284-285`); `suffix` и его сегменты остаются с 0, C на `finalize` проставляет профиль **всем** посылкам (`plan_apply.c:812`). (2) qsplit-ветвь возвращает `Actions` в `apply.rs:203-250` до `apply_timing`/`wire_profile` (`:636-657`, `:403-405`), поэтому `delay_us` и `wire_profile` к qsplit-посылке не применяются; C применяет оба после цикла (`plan_apply.c:803-812`). (3) `MAX_EMISSIONS = 26` в Rust (`plan.rs:10`, `apply.rs:9,335,704`); C в `plan_apply.c` не ограничивает число посылок 26 — предел 65536 относится только к числу сегментов (`:830`), а отказ >26 приходит позже из `session.c:2517` (`D2K_RESULT_MAX`). Наблюдаемый отказ сессии совпадает, слой и текст ошибки различаются. `emit_fake` C копирует `ts_up/autottl`-поля, Rust переносит `ts_up` через флаг `POISON_TS_UP`, а autottl вычисляет в `ttl` по `reference_ttl` (`apply.rs:764-781`); для одного и того же `reference_ttl` результат совпадает, при смене TTL между apply и отправкой C пересчитал бы, Rust — нет. |
| d2k_actions_cancel | 891-921 | 31 | правила отмены недосланного исполнения | `plan/apply.rs:104` `Actions::cancel` | E | `cancellation_drops_only_after_payload_bytes_were_emitted` (tests/apply.rs). |
| d2k_actions_free | 923-931 | 9 | освободить посылки | `plan/apply.rs:61` `Emission` + `Actions` (RAII) | E | Освобождение автоматическое; отдельных ошибок/утечек нет по типам. |

Итог по файлу: E 14, P 1, N 0. Главные отличия — потеря `wire_profile` в OOB-суффиксе,
обход `delay_us` в qsplit и место отказа при >26 посылках (D2O тоже отказывает в session,
но позже).
у OOB-суффикса.

**Построчная сверка a378:** все 15 функций прочитаны. Подтверждены три расхождения
`d2k_plan_apply` (`plan_apply.c:343-873`) с `apply.rs:155-405/636-735`:
(1) OOB: C на `finalize` проставляет `wire_profile` всем посылкам (`:812`), Rust — только
`first` и `urgent`; `suffix` и результат его сегментации остаются с профилем 0;
(2) qsplit: Rust возвращает `Actions` до `apply_timing` и общего присвоения `wire_profile`,
поэтому `delay_us` и `wire_profile` не применяются; C применяет и паузу, и профиль после
всех ветвей (`:803-812`); (3) `MAX_EMISSIONS=26` в Rust против отсутствия такого предела
в `plan_apply.c`: 65536 там ограничивает только число сегментов (`:830`), а отказ >26
приходит позже из `session.c:2517` (`D2K_RESULT_MAX`) — наблюдаемый отказ сессии совпадает,
слой и текст ошибки разные. Остальные helper'ы (`anchor_offset`, `split_points`,
`tls_ch_layout`, `fake_tls_bytes`, `emit_fake`, `max_emit`, `cancel`) совпадают с тестами
`tests/apply.rs`; autottl в Rust вычисляется в `ttl` по `reference_ttl`, в C хранится
полями и пересчитывается на отправке.

---

### Углублённая сверка plan_apply.c (15 функций)

- **`anchor_offset` (26–80) ↔ `apply.rs:862`:** якоря 0/payload_start,
  1/sni_start, 2/sni_end, 3/hello_middle, 4/record_end (отказ),
  5/sni_middle. C зажимает середину имени `<2→2`, `>=payload_len→
  payload_len-1`; Rust — те же зажимы, но `sni_off+sni_len` через
  `checked_add` и ошибка `invalid-sni`. Для валидного входа
  эквивалентно; на 32-битной сборке C-сложение без проверки — P.
- **`split_points` (90–118) ↔ `apply.rs:908`:** якорь+offset, отброс
  `v<=0 || v>=payload_len`, сортировка и дедуп. Совпадает; C
  `long v = (long)base + offset` на 32-битном `long` может
  переполниться при экстремальном offset, Rust — checked. P.
- **`tls_ch_layout` (120–154) ↔ `apply.rs:970`:** `n>=44`, `0x16`,
  major 3, `b[5]==1`; `rec_len+5==hs_len+9`; `n>rec_len+5` — отказ;
  `allow_prefix` решает, можно ли начало приветствия; session-id
  `<=32` и в пределах пришедших байт. Три разных текста отказа
  сохранены. Совпадает.
- **`random_bytes`/`wr16`/`wr24` (156–171) ↔ `apply.rs:1019/1036/
  1041`:** `/dev/urandom` заменён `getrandom`; запись u16/u24 BE
  совпадает.
- **`fake_tls_bytes` (173–237) ↔ `apply.rs:531`:** `TLS_MOD_RND`
  рандомизирует random и session id; `TLS_MOD_DUPSID` копирует SID
  клиента с пересчётом длин записи/рукопожатия. Для
  `WIRE_TCP_TEMPLATE` C не меняет длину, копирует SID только при
  равной длине и повторяет ту же мутацию при `repeats`; Rust
  `append_fake_repeats` делает то же. Совпадает.
- **`emit_fake` (239–266) ↔ `apply.rs:486`:** payload по id,
  `tls_mod`, затем ttl/poison/seq_shift/ts_up/autottl
  (delta/min/max). Совпадает.
- **`emit_overhead`/`d2k_plan_max_emit` (285–341) ↔ `apply.rs:737/
  418`:** IP 20 + TCP 20/UDP 8, MD5 +20, TCPTS_BACK +12; fake
  body `payload + (DUPSID?32:0)`, ограничение `segment_size`;
  seqovl считается только приставкой; `udplen` — `1200+udplen` для
  QUIC (`proto==2`) или `1+udplen`. Rust `emit_overhead`/`max_emit`
  те же; тест `max_emit()==171` (`tests/apply.rs:251`).
- **`d2k_plan_apply` (343–873) ↔ `apply.rs:155`:** проверены ветви
  пустой нагрузки, proto HTTP mismatch, `qdeny→DROP`, HTTP+
  input/udplen/qsplit отказ, `input_tls`, `input_len` (префикс
  приветствия с проверкой объявленной длины/SNI/разреза),
  OOB-три посылки, split, `owns_payload`, fake before/between,
  reverse только payload, pace/settle/delay, finalize
  `wire_profile`, сегментация prefix+body, fate DROP/PASS.
  **Расхождения:** OOB `suffix.wire_profile=0`; qsplit обходит
  `delay_us`; `MAX_EMISSIONS=26` против 65536 в C (наблюдаемый
  отказ совпадает из-за `D2K_RESULT_MAX=26` в session).
- **`d2k_actions_cancel` (891–921) ↔ `apply.rs:104`:** `partial =
  emitted<n`; `stream_damaged = payload_out && partial`; fate
  DROP при отправленной нагрузке, иначе PASS. Совпадает.
- **`d2k_actions_free` (923–931):** RAII `Vec<Emission>`; утечек
  нет по построению.

**Итог:** 13 helper'ов/обёрток — E/P, `d2k_plan_apply` — P с тремя
подтверждёнными расхождениями; новых N нет.

## datapath/plan_parse.c (17 функций)

Разбор канонического плана. R2O: `crates/r2k-core/src/plan.rs` (`Plan::parse`, `scan`,
`check_references`), поля `Plan`.

**Прочитано построчно: 17/17 функций, 630 строк C (1–630).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| rd16 | 23-25 | 3 | static: u16 BE | `plan.rs:892` `read_u16` | E | `rejects_bad_header_lengths_records_and_unknown_versions` (tests/plan.rs). |
| rd32 | 27-30 | 4 | static: u32 BE | `plan.rs:902` `read_u32` | E | Тот же тест. |
| fail | 32-36 | 5 | static: записать текст ошибки | `plan.rs:67` `PlanError::new` | P | Тексты R2O другие; проверяется только факт отказа, не текст. |
| scan | 45-220 | 176 | первый проход: счётчики, проверки типов/длин/minexec | `plan.rs:687` `scan` | E | `rejects_bad_header_lengths_records_and_unknown_versions`, `rejects_dangling_references_and_invalid_operation_combinations` (tests/plan.rs). |
| check_refs | 224-325 | 102 | второй проход: ссылки, сочетания операций, порядок, одиночное перекрытие | `plan.rs:499` `check_references` | E | `rejects_dangling_references_and_invalid_operation_combinations` (tests/plan.rs). |
| d2k_find_payload | 327-334 | 8 | найти приманку по id | `plan.rs` — `self.payloads.iter().find(...)` (apply.rs:611, :1287 и др.) | E | `parses_payload_fake_and_cross_references` (tests/plan.rs). |
| d2k_find_poison | 336-343 | 8 | найти порчу по id | `plan.rs` — `self.poisons.iter().find(...)` (apply.rs:624, :744) | E | Тот же тест. |
| d2k_plan_load | 345-566 | 222 | полная загрузка: заголовок, scan, записи, check_refs, транспорт | `plan.rs:190` `Plan::parse`, `:167` `parse_wire` | **P** | **Подтверждённые расхождения по `REC_AUTOTTL`:** (1) повторная запись для той же порчи в C применяет «последний побеждает» (`plan_parse.c:473-486`), Rust `autottl.replace` отвергает повтор (`plan.rs:301-309`); (2) C разрешает `AUTOTTL` только **после** своей `POISON` (поиск идёт по уже разобранным `p->poisons`, `:477-481`), Rust собирает `autottls` в вектор и разрешает после всего прохода (`plan.rs:224,260-310`), поэтому `AUTOTTL` перед `POISON` C отвергает, Rust принимает. Остальное совпадает: 7 тестов tests/plan.rs, legacy `D2KP` через `parse_wire`, magic `R2OP`, scan/check_refs. C/Rust differential на оба порядка AUTOTTL нет. |
| d2k_plan_free | 568-581 | 14 | освободить план | `Drop` (`Vec<Payload>`, `vec!`) | E | Владение типами; утечек нет по построению. |
| d2k_plan_poison_used | 583-592 | 10 | OR всех флагов порчи | `plan.rs:327` `poison_used` | E | `parses_payload_fake_and_cross_references` + `max_emit`-тест. |
| d2k_plan_flow_needs | 594-599 | 6 | нужен ли потоку TCPTS (шаблон+TCPTS_BACK) | `engine.rs:1860-1869` — прямая проверка `wire_profile==TEMPLATE && POISON_TCPTS_BACK` и наличия TS-опции, иначе `FlowUnfit` | P | Логика перенесена в решатель, отдельной функции нет; тест на `FlowUnfit` по отсутствию TS-опции не найден. |
| d2k_plan_quic_deny | 601-603 | 3 | флаг запрета QUIC | `plan.rs:333` `quic_deny` | E | `quic_deny_drops_without_sending_anything` (tests/apply.rs). |
| d2k_plan_guards | 605-607 | 3 | байт защит TCP | `Plan::guards` (plan.rs:137), исполнение — `engine.rs:1453,1586-1594,2078-2089` | E | Тест `r2o_передний_сброс_чужой_rst_до_runtime_и_...` (main.rs:5961) с `GUARD_RST_ALIEN`. |
| d2k_plan_transport | 609-611 | 3 | транспорт плана | `Plan::transport` (plan.rs:134) | E | `parses_measured_tcp_context_and_wire_contract`, `permits_http_only...` (tests/plan.rs). |
| d2k_plan_proto | 613-615 | 3 | протокол плана | `Plan::proto` (plan.rs:135) | E | Те же тесты. |
| d2k_plan_stream_input | 617-621 | 5 | потоковый вход: TCP + wire + input | `plan.rs:337` `stream_input` | P | Тело тождественно; используется в `control.rs:614-621`. Прямого теста на предикат нет — покрыт косвенно через `has_tls_candidate`. |
| d2k_plan_id | 623-630 | 8 | id плана или NULL | `Plan::id` (plan.rs:133) | E | `round_trips_an_applied_http_probe_with_its_exact_binding_identity` (tests/control.rs:724). |

Итог по файлу: E 14, P 3, N 0. Пробелы: текст ошибок, `flow_needs` как отдельная
функция, прямой тест `stream_input`.

**Построчная сверка a378:** все 17 функций прочитаны. `scan`/`check_refs` совпадают с
`plan.rs:687-845/499-685` по всем типам записей, длинам, minexec и сочетаниям. Отличия
сосредоточены в `REC_AUTOTTL`: C применяет повторную запись к той же порче по принципу
«последний побеждает» и требует, чтобы `AUTOTTL` шла после своей `POISON`; Rust отвергает
повтор и разрешает ссылку после всего прохода, поэтому принимает `AUTOTTL` перед `POISON`.
Из-за этого `d2k_plan_load` — P. `d2k_find_payload`/`d2k_find_poison`/
`d2k_plan_poison_used`/`transport`/`proto`/`id` эквивалентны; `flow_needs` разнесён в
`engine.rs`, `stream_input` покрыт косвенно `has_tls_candidate`.

### Углублённая сверка plan_parse.c (17 функций)

- **`rd16`/`rd32` (23–30) ↔ `plan.rs:892/902`:** big-endian
  `read_u16`/`read_u32`, точные границы; E.
- **`fail` (32–36) ↔ `PlanError::new` (`plan.rs:67`):** текст
  ошибки другой, факт отказа тот же; P.
- **`scan` (45–220) ↔ `plan.rs:687-845`:** построчно совпадает:
  заголовок записи 4 байта и проверка `off+ln<=len`; `INPUT/
  SETTLE/SEGMENT` требуют minexec≥3; `IPFRAG` ≥7 и форма 1..4;
  `UDPLEN` ≥9 и ненулевой прирост; `QSPLIT` ≥10 форма 1;
  `QDENY` ≥11 форма 1; `OOB` ≥8, якорь ≤5, ровно один байт,
  не более одной записи; `ID` 16; `PROTO` 2, HTTP требует TCP
  и minexec≥11; `PAYLOAD` ≥2; `POISON` 8, MD5 требует ≥12;
  `AUTOTTL` ≥13, 5 байт, min≤max; `SPLIT` 4; `FAKE` 10/11,
  tlsmod≥8 и только RND/DUPSID; `SEQOVL` 4; `ORDER` 1; `PACE` 4;
  `DELAY` ≥6 и ненулевой; `INPUT` 12, `input_len!=0`,
  `sni_off<=input_len`, `sni_len<=input_len-sni_off`; `WIRE` ≥4,
  профиль 1/2, template≥8; `INPUT_TLS` ≥5 и пустая; `SETTLE` 4
  ненулевая; `SEGMENT` 4, 1..65535; `GUARD` 1, только
  `RST_ALIEN`; неизвестный тип — отказ; записей ≤65535.
  **Отличие:** C `REC_AUTOTTL` при повторе для той же порчи
  действует «последний побеждает» (`plan_parse.c:482`), Rust
  отвергает повтор (`plan.rs:307`, `autottl.replace`).
- **`check_refs` (224–325) ↔ `plan.rs:499-685`:** совпадает:
  MD5 требует minexec≥12, TCP и detect-tcp; ipfrag — UDP без
  TCP-операций; udplen — UDP без ipfrag/разрезов/seqovl/order/
  input/settle/segment/wire/guards/oob; qsplit — UDP без
  ipfrag/udplen/прочих; qdeny — UDP и план без воздействий;
  oob — minexec≥8, TCP, `proto=1`, `input_tls`, wire, без
  splits/seqovl/fakes/ipfrag/pace/settle/delay; ссылки
  fake/seqovl на существующие payload/poison; `PLACE_BETWEEN`
  требует разрезов; placement только before/between; order
  forward/reverse; seqovl ≤1. Rust дополнительно проверяет
  autottl minexec/диапазон в `check_references`, но те же
  условия уже есть в `scan`.
- **`d2k_find_payload`/`d2k_find_poison` (327–343) ↔
  `payloads.iter().find`/`poisons.iter().find`:** эквивалентно;
  E.
- **`d2k_plan_load` (345–566) ↔ `plan.rs:167 parse_wire`,
  `:190 parse`:** C принимает только `D2KP`; Rust `parse` — только
  `R2OP`, а `parse_wire` принимает **оба** (legacy `D2KP`
  переклеивает magic). R2O принимает надмножество. Повторные
  `ipfrag/udplen/qsplit/qdeny` C отвергает в `scan`, Rust —
  `set_once_*`; повторный `autottl` — см. выше. Массивы calloc
  заменены `Vec` с capacity.
- **`d2k_plan_free` (568–581):** RAII; E.
- **`d2k_plan_poison_used`/`quic_deny`/`guards`/`transport`/
  `proto`/`id`:** прямые методы `plan.rs:327/333/134/135/133`,
  E. `flow_needs` — P: логика `wire_profile==TEMPLATE &&
  TCPTS_BACK` размазана по `engine.rs:1860-1869` и не имеет
  отдельной функции/теста. `stream_input` — P: тело тождественно
  `plan.rs:337`, используется `control.rs:614-621`, прямого
  теста предиката нет.

**Итог:** 14 E, 3 P, 0 N. Новые подтверждённые отличия —
legacy-`D2KP` принимается только через `parse_wire`, а повторный
`autottl` R2O отвергает, C — нет.

## datapath/plans.c (75 функций)

Таблица планов по целям: ключи имя/адрес/суффикс, LRU-вытеснение, точные пробы, поиск на
пакетном пути. R2O-аналог — `NamePlans` в `crates/r2o-datapath/src/control.rs`
(`HashMap`-ключи вместо уплотнённого массива, `Cell<u64>`-часы вместо `last_used_ns`).

**Прочитано построчно: 75/75 функций, 1273 строки C (1–1273).**

**Построчная сверка a378:** все 75 функций прочитаны. Подтверждены: `area_name_valid`
принимает односложные/чисто цифровые имена (Rust `canonical_name` — нет);
`d2k_plantab_shape_misses` в R2O **всегда 0** (поле не инкрементируется, N);
`clear_probes` C снимает и name-записи с `qdeny`, R2O их оставляет; `set_addr_probe`
C — одна `probes[cap]` (2048) с QUIC/VOICE/ANY, Rust — `addr_probes`/`voice_addr_probes`
по 64; `probe_count` C считает все, Rust — только неистёкшие addr; `set_addr_shaped`
Rust дополнительно проверяет `addr_plan_matches_shape`/`r2o_plan_valid`; legacy
`del_name`/`del_addr` C снимают все формы, Rust — одну; `find_target` C имеет
name-probe по порту при пустом имени, `h.any`/ANY, grandfather и односторонний
UDP→addr переход, R2O — только exact+ECH→MODERN+общий addr-fallback; `has_ech_target`
прямого аналога нет (`?`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| bind_context | 94-102 | 9 | static: owner, `generation=++next_binding` (пропуск 0 на UINT64_MAX), kind/family/shape/temporary, `trial_id=0` | `control.rs:1592 next_generation`, `:878-887`/`:915-924` вставка, `:690 binding_for_plan` | **P** | C generation — монотонный `next_binding`; Rust — `revision+1` на каждую вставку. Identity выдаётся при вставке, отдельной функции нет; проверяется через `binding_for_plan` в APPLIED-тестах. |
| d2k_plantab_new | 104-130 | 27 | создать таблицу на cap записей и 16-байтовый epoch | `control.rs:146` `NamePlans::with_capacity` | E | `exact_name_addr_probe_tables_share_lru_capacity` (control.rs:2633). |
| d2k_plantab_free | 132-149 | 18 | освободить планы и массивы | `Drop` (`HashMap<String, InstalledPlan>`) | E | Владение типами; утечек нет по построению. |
| name_eq | 154-167 | 14 | static: ASCII case-insensitive, равная длина | `control.rs:2233` `canonical_name` (lowercase) + `String`-равенство | **P** | C понижает A-Z по месту; Rust канонизирует имя при вставке. Эквивалентно для сохранённых имён; теста на план в верхнем регистре и поиск в нижнем нет (HTTPS-тест `EXAMPLE.TEST` — отдельный путь). |
| shape_transport | 169-175 | 7 | static: QUIC→17; MODERN/LEGACY/ECH/контекст 8–13→6; иначе 0 | `control.rs:859-868`, `:955-960`, `:1597-1603` `valid_domain_area_context` | **P** | C-правило размазано по трём `match`; Rust `valid_domain_area_context` даёт TCP для 1/2/6/8–13 и QUIC для 3, VOICE не входит. Отдельного предиката нет. |
| area_name_valid | 177-191 | 15 | static: DNS-суффикс: 1..253, метки 1..63, LDH, без ведущего/хвостового дефиса; **односложное и чисто цифровое допустимы** | `control.rs:2233` `canonical_name`, `domain.rs:8-58` | **P** | **Подтверждённое расхождение:** Rust `canonical_name` требует ≥2 метки и хотя бы один нецифровой символ; C принимает `localhost` и `12345`. `SET_SUFFIX`/`SET_BYPASS` с таким именем C примет, R2O вернёт `ACK_BAD_ARGS`. Тест control.rs:3075 это не покрывает. |
| suffix_member | 193-197 | 5 | static: имя входит в суффикс по границе метки | `control.rs:1605` `domain_suffix_member` | E | `исключение_снимает_suffix_только_для_точного_имени...` (control.rs:3075): `other.googlevideo.com` получает план, `failed...` — нет. |
| area_exact | 199-207 | 9 | static: найти запись площади по (имя, транспорт, форма, family) | ключ `SuffixPlanKey`/`DomainBypassKey` (control.rs:64-78, HashSet/HashMap) | E | Тест control.rs:3075 (установка/поиск/удаление). |
| area_set | 209-226 | 18 | static: поставить план суффикса с проверкой формы/транспорта/family | `control.rs:928` `set_suffix` (и `:988` `set_domain_bypass`) | P | Тест control.rs:3075. Отличие: C принимает любой транспорт, равный `shape_transport(shape)`; R2O ограничивает набор форм TCP 1/2/6/8-13 и QUIC 3. |
| d2k_plantab_set_suffix_family | 228-237 | 10 | поставить план изученного суффикса | `control.rs:928` `set_suffix` | E | `исключение_снимает_suffix...` (control.rs:3075). |
| d2k_plantab_set_bypass_family | 239-244 | 6 | поставить исключение семейства (bypass) | `control.rs:988` `set_domain_bypass` | E | Тот же тест: bypass подавляет суффикс, затем снимается. |
| area_del | 246-253 | 8 | static: снять запись площади с уплотнением | `control.rs:1021` `delete_domain_area` | E | Тот же тест (DEL_BYPASS/DEL_SUFFIX). |
| d2k_plantab_del_suffix_family | 255-258 | 4 | снять суффикс | `control.rs:1021` `delete_domain_area(body, true)` | E | Тот же тест. |
| d2k_plantab_del_bypass_family | 260-263 | 4 | снять исключение | `control.rs:1021` `delete_domain_area(body, false)` | E | Тот же тест. |
| area_bypassed | 265-273 | 9 | static: имя исключено для (family, shape) | `control.rs:1557` `name_is_bypassed` | E | Тот же тест. |
| area_match | 275-284 | 10 | static: самый длинный подходящий суффикс при точном `(shape, family)` и `suffix_member` | `control.rs:1569-1590` `find_in_domain` (`max_by_key(len)`) | **P** | Логика совпадает: точные `transport/family/shape`, `domain_suffix_member`, максимум по длине суффикса. Тест покрывает один суффикс; выбор самого длинного из нескольких не проверен. |
| d2k_plantab_revision | 286-286 | 1 | ревизия таблицы | `control.rs:586` `revision` | E | `conditional_http_delete...` (control.rs:3587) сверяет `revision` до/после. |
| d2k_plantab_has_ech_target | 288-314 | 27 | есть ли ECH-привязка имени/адреса для трёх ECH-форм, с учётом `only_sport` и BYPASS; затем суффиксы | — | **P** | Прямого предиката нет, но это **не N**: R2O удерживает любой неполный TLS-заголовок (`hold.rs:574-590`, `incomplete_tls_head`) и выставляет ECH-форму по факту `ech_offer` (`engine.rs:1053-1059`). То есть обычный случай «ECH-target → удержание обрывка» покрыт **шире** C. Не воспроизведены C-исключения: `only_sport`, BYPASS для не-точных записей, отдельные `ECH_NO_TS`/`ECH_TS`, суффиксный поиск; адресного differential нет. |
| d2k_plantab_stream_candidate | 316-319 | 4 | префильтр: есть ли потоковый план по имени/адресу | `control.rs:612` `has_tls_candidate(family)` | P | R2O префильтр только по family, без имени/адреса/sport; используется в `main.rs:1699`. |
| d2k_plantab_stream_candidate_family | 321-325 | 5 | то же с family | `control.rs:612` `has_tls_candidate` | P | То же: нет учёта имени и порта; тестов на точность префильтра нет. |
| d2k_plantab_stream_candidate_target | 327-350 | 24 | family, bypass для не-точных, `stream_input`, `only_sport`, имя/адрес/sport, суффиксы transport 6 + stream_input + suffix_member + bypass | `control.rs:612-637` `has_tls_candidate` | **P** | **Расхождения:** Rust проверяет plans family + shape!=HTTP + `stream_input`, suffix transport 6/family/`stream_input`, addr shapes MODERN/LEGACY/ECH; **не проверяет bypass, имя/адрес/sport**. Поэтому `has_tls_candidate` может вернуть true для исключённого имени и не различает пробный порт; C для не-точных записей bypass учитывает. |
| find_name_skip | 357-367 | 11 | static: запись имени без порта; опционально мимо HTTP | `control.rs:1493` `find` по `NamePlanKey{host,family,shape}` | P | HTTP-запись в R2O — отдельный shape-ключ, поэтому «пропустить HTTP» не нужно; но и «любая форма» одним поиском не выражается. |
| find_name | 369-371 | 3 | static: запись имени без порта | `control.rs:1493` `find` | E | Выбор по имени в `tls_probe_plan...`/`http_probe_plan...` (control.rs:3489, 3637). |
| find_name_shape_port | 385-395 | 11 | static: запись ровно (имя, форма, порт, family) | `control.rs:1493` `find` + `probes: NameProbeKey` | E | `tls_probe_plan_matches_only_its_source_port_and_reports_temporary_applied` (control.rs:3637). |
| find_name_port | 401-412 | 12 | static: портовая запись имени при неизвестной форме | `control.rs:548-571` — поиск probe по `(host, family, shape)` и bridge-shape | E | `tls_probe_plan...` (control.rs:3637): проба находится по своему порту. |
| d2k_plantab_http_candidate | 414-422 | 9 | префильтр HTTP: exact name+family+SHAPE_HTTP+`only_sport==sport`+`proto==HTTP` | `control.rs:624-628` `has_http_candidate(family)` | **P** | **Расхождение:** Rust проверяет только family+SHAPE_HTTP, без `sport` и `proto==HTTP`; префильтр шире C. C для неверного порта/прото вернёт 0, R2O — true. Вызывается `main.rs:1701`. |
| d2k_plantab_find_http | 424-431 | 8 | план для HTTP-запроса: проба своего порта, иначе постоянная | `control.rs:495-509` (`select` + `NameProbeKey` для порта 80) | E | `http_probe_plan_matches_only_its_source_port_and_acknowledges_trial_id` (control.rs:3489). |
| find_addr_shape | 439-450 | 12 | static: адресная запись ровно (адрес, family, форма) | `control.rs:1504` `find_addr` | E | `discord_voice_class_plan_matches_only_discord_voice_requests` (control.rs:3186), `удаление_адреса...` (control.rs:2793). |
| find_addr | 452-454 | 3 | static: любая форма адреса (для снятия/учёта промаха) | `control.rs:1504` `find_addr` (с ECH-fallback) | E | Те же тесты; снятие адреса в control.rs:2793. |
| modern_shape_for_ech | 465-469 | 5 | static: ECH-форма → соответствующая MODERN-форма | `control.rs:534-539` `fallback_shape` в `select` | E | `tls_план_работает_для_sni_с_ech_...` (control.rs:2823). |
| scan_name | 471-486 | 16 | static: один проход — `any`/`shaped`/`modern(ECH)`/`grandfather` по имени, HTTP-запись пропускается | `control.rs:569-581` — цепочка `find(shape/bridge/fallback/grandfather)` + `find_in_domain` | **P** | C за один проход заполняет `h.any` (любая не-HTTP запись), `h.shaped` (точная `seen_shape`), `h.modern` (`modern_shape_for_ech(seen_shape)`) и `h.grandfather`. Rust делает отдельные поиски и **не имеет** ветки `h.any`/`SHAPE_ANY`: запись с формой 0 не будет найдена. R2O-контроллер такие планы не ставит (valid shapes 1/2/3/5/6), но C-путь шире. |
| scan_addr | 488-502 | 15 | static: один проход по адресу — `any`/`shaped`/`modern(ECH)`/`grandfather` | `control.rs:1504-1520` `find_addr`, `:1522-1540` `find_addr_fallback` | **P** | C собирает `any`, `shaped` (если `seen_shape!=ANY`), `modern(ECH)`, `grandfather`. Rust `find_addr` ищет **только** точную форму и ECH→MODERN; grandfather/ANY-ветки нет. `find_addr_fallback` дополнительно проверяет `name_has_transport_binding`/`name_is_bypassed`, чего в C `scan_addr` нет (это в `find_target`). Счётчик `shape_misses` не ведётся. |
| oldest | 518-529 | 12 | static: самая старая запись (LRU) | `control.rs:211` `exact_victim` | E | `name_plan_table_evicts_lru_and_delete_releases_a_slot` (control.rs:2663). |
| take_free_or_evict | 541-569 | 29 | static: свободный слот или вытеснение LRU с уплотнением | `control.rs:234` `make_room_exact` | E | `exact_name_addr_probe_tables_share_lru_capacity` (control.rs:2633): общая ёмкость имя+адрес+проба. |
| d2k_plantab_set_name_shaped | 571-574 | 4 | поставить план имени с формой | `control.rs:832` `set_name` (shape — часть ключа) | E | `условие_..._tls_форма` (control.rs:2844) и shape-тесты. |
| d2k_plantab_set_name_probe | 576-580 | 4 | поставить пробный план имени на один порт | `control.rs:1092` `set_name_probe` | E | `http_probe_plan...` (control.rs:3489), `tls_probe_plan...` (control.rs:3637). |
| probe_transport | 584-588 | 5 | static: транспорт пробы (из плана, иначе по форме) | `control.rs:1129` (`plan.transport != 6`), `:859-868` | P | Вывод транспорта из формы без плана в R2O не нужен: проба всегда TCP/proto 1/HTTP. |
| d2k_plantab_set_name_family | 590-667 | 78 | основная установка имени: ключ (имя, форма, порт, family), замена пробы того же порта, grandfather-правило | `control.rs:832` `set_name`, `:1092` `set_name_probe` | P | Тесты shape/probe/bound (control.rs:2700-3896). Отличия: C при `sport` снимает прежнюю пробу того же (имя, family, порт, транспорт) — R2O `retain` по (host, family, port) без транспорта; C хранит `SHAPE_ANY` и grandfather в общем массиве — R2O различает их ключом. |
| d2k_plantab_set_name | 672-676 | 5 | legacy: поставить имя как grandfather | `control.rs:832` `set_name` (контроллер шлёт форму явно) | P | Legacy-входа без формы нет; совместимость обеспечивает shape=GRANDFATHER в ключе. |
| d2k_plantab_set_addr | 678-681 | 4 | legacy: адрес как grandfather | `control.rs:891` `set_addr` (форма обязательна) | P | C legacy-вход только для тестов датапата; командой сокета не используется. В R2O такого входа нет. |
| d2k_plantab_set_addr_family | 686-690 | 5 | legacy: адрес без формы → grandfather | `control.rs:891` `set_addr` | P | То же: форма обязательна (`valid_addr_shape`), grandfather по сокету не принимается — совпадает с C `ctlsrv`. |
| d2k_plantab_set_addr_shaped | 692-721 | 30 | адресная привязка ровно (адрес, family, форма); C отвергает только ANY/HTTP и HTTP-протокол плана | `control.rs:891-927` `set_addr` | **P** | **Расхождение на негодном входе:** Rust дополнительно требует `addr_plan_matches_shape` (MODERN/LEGACY/ECH→TCP TLS, QUIC→valid_quic, VOICE→UDP voice) и `r2o_plan_valid`; C такие планы принял бы. Для валидного входа эквивалентно. Тест `удаление_адреса_разделяет_формы...` (control.rs:2793) проверяет **удаление** двух форм, а не приём; отдельного теста set-валидации нет. |
| d2k_plantab_del_name_probe_family | 813-828 | 16 | снять пробную запись по (имя, shape, порт, family); C shape не проверяет | `control.rs:1362-1388` `delete_name_probe` | **P** | Rust требует `valid_tcp_probe_shape(shape)`; C принимает любую shape (в т.ч. 0) и просто не находит запись. На валидном входе совпадает; на shape 0/неизвестной ACK различается. Тест `conditional_http_delete...` покрывает name-bound, не probe-delete. |
| drop | 728-741 | 14 | static: снять запись, сохранив уплотнение | `HashMap::remove` (control.rs:1408, 1473, 1489) | E | `name_plan_table_evicts_lru_and_delete_releases_a_slot` (control.rs:2663). |
| d2k_plantab_del_name | 743-745 | 3 | legacy: снять ВСЕ записи имени (v4) | `control.rs:1389` `delete_name` (одна форма) | P | Семантика разная: C legacy снимает все формы, R2O — только точный ключ (как v9 `DEL_NAME`). Широкого удаления в R2O нет. |
| d2k_plantab_del_name_family | 747-765 | 19 | снять все формы имени в family | `control.rs:1389` `delete_name` | P | То же: удаляется один shape-ключ, а не все формы. |
| d2k_plantab_del_name_shaped | 773-790 | 18 | снять постоянную запись (имя, транспорт, форма, family), пробы не трогать | `control.rs:1389` `delete_name` | E | `conditional_http_delete_preserves_replacements_and_removes_only_its_binding` (control.rs:3587). |
| d2k_plantab_del_name_bound | 792-806 | 15 | условное снятие по identity (generation/epoch/kind) | `control.rs:1416` `delete_name_bound` | E | Тот же тест: замена с другой identity не удаляется. |
| d2k_plantab_del_name_probe | 808-811 | 4 | снять пробную запись по порту | `control.rs:1362` `delete_name_probe` | E | `http_probe_plan...` (control.rs:3489) снимает пробу. |
| d2k_plantab_del_addr | 830-832 | 3 | legacy: снять адрес целиком (все формы) | `control.rs:1479` `delete_addr` (одна форма) | P | Семантика разная: широкого удаления адреса в R2O нет (v7 шлёт форму). |
| d2k_plantab_del_addr_family | 837-842 | 6 | снять все формы адреса | `control.rs:1479` `delete_addr` | P | То же: одна форма. |
| d2k_plantab_del_addr_shaped | 844-848 | 5 | снять ровно форму адреса | `control.rs:1479` `delete_addr` | E | `удаление_адреса_разделяет_формы...` (control.rs:2793). |
| trial_id_valid | 850-855 | 6 | static: trial id не весь нулевой | inline `iter().all(\|b\| *b == 0)` (control.rs:1198, 1277, 1329) | P | Три копии вместо функции; тестов на нулевой id не найдено. |
| probe_flow_valid | 860-874 | 15 | static: UDP, dst port≠0, family 0/4/6, ненулевые src/dst; `src_port=0` — голосовой wildcard | `r2k-core/control.rs:1701-1717` `valid_udp_addr_probe_flow` | **P** | **Расхождение:** C допускает `family=0` (внутренние вызовы) и `src_port=0` (голос); Rust требует family 4/6 и оба порта ≠0, а голос вынесен в `voice_addr_probes`. Control-путь C тоже требует family 4/6 (`read_probe_flow`), но wildcard-порт — реален. Тестов нет. |
| probe_flow_equal | 876-887 | 12 | static: равенство flow | ключ `[u8; KEY_LEN]` в `HashMap` (control.rs:88) | P | Равенство по ключу тривиально, но адресные опыты не тестированы. |
| probe_drop | 889-895 | 7 | static: снять запись опыта | `HashMap::remove`/`retain` (control.rs:607, 1291) | E | `clearing_disconnected_http_probes_keeps_the_permanent_plan` (control.rs:3703) — очистка проб. |
| d2k_plantab_clear_probes | 897-910 | 14 | снять пробные записи и QUIC-запреты (`qdeny`) | `control.rs:600-611` `clear_probes` | **P** | C удаляет name-записи с `only_sport` **или** `d2k_plan_quic_deny` и все probe-записи. Rust чистит `probes`, `voice_addr_probes`, `addr_probes`, но **не удаляет `qdeny`-записи** из `plans`. После отключения контроллера C снимает QUIC-запрет, R2O оставляет. Тест `clearing_disconnected_http_probes...` (control.rs:3703) покрывает только probes. |
| d2k_plantab_set_addr_probe | 912-961 | 50 | временный план на точный flow с trial id и lease; одна таблица для QUIC/VOICE/ANY, ёмкость `cap` (2048) | `control.rs:1260-1317` `set_addr_probe`, `:1197` `set_voice_addr_probe` | **P** | **Расхождения:** (1) C хранит QUIC и VOICE в одной `probes[]` с `shape` из proto (2/3/ANY) и ёмкостью `cap`; Rust — `addr_probes` (только QUIC, `valid_quic_plan`) и `voice_addr_probes`, обе по **64**. При >64 одновременных опытов C примет, R2O вернёт `NO_ROOM`. (2) C допускает `src_port=0` для голоса; Rust generic-проба — нет. Тестов COMMAND_SET_ADDR_PROBE нет. |
| d2k_plantab_del_addr_probe | 963-976 | 14 | снять ровно (flow, generation) | `control.rs:1318` `delete_addr_probe` | P | Тестов нет. |
| find_probe | 978-1006 | 29 | static: поиск опыта, ленивое истечение, wildcard-порт только для голоса | `control.rs:804` `addr_probe_binding_at_hook`, `:764` `voice_address_binding` | P | Голосовая часть покрыта (`временная_voice_запись...`, control.rs:3239), адресная — нет. |
| d2k_plantab_find_addr_probe | 1008-1012 | 5 | поиск точного адресного опыта | `control.rs:804` `addr_probe_binding_at_hook` | P | Тестов нет; поиск дополнительно требует authenticated Initial и клиентского направления. |
| d2k_plantab_find_voice_probe | 1014-1018 | 5 | поиск голосового опыта (wildcard клиентского порта) | `control.rs:764` `voice_address_binding` | E | `временная_voice_запись_соответствует_только_с_заданным_и_целым_адресом` (control.rs:3239), `stun_...` (3278). Ключ R2O не содержит клиентского порта — wildcard выражен структурно. |
| d2k_plantab_probe_count | 1020-1022 | 3 | число всех пробных записей (`probe_used`, включая voice) | `control.rs:186-191` `r2o_probe_count` | **P** | C считает все занятые `probes[]` (QUIC и VOICE); Rust `r2o_probe_count` — только `addr_probes` (voice не входит), причём только неистёкшие. Числа расходятся. Тестов нет. |
| shape_fits | 1044-1052 | 9 | static: grandfather→1; MODERN↔ECH_TCP, MODERN_NO_TS↔ECH_NO_TS, MODERN_TS↔ECH_TS; иначе `entry_shape!=0 && equal` | `control.rs:569-581` — цепочка exact/bridge/fallback/grandfather | **P** | C-предикат расщеплён на цепочку поисков; ECH-перенос и grandfather покрыты тестами (control.rs:2823). В C `entry_shape==0` (ANY) не проходит `shape_fits` — ANY используется отдельной ветвью `h.any`; в R2O отдельного предиката и ANY-ветки нет. |
| shape_is_udp | 1054-1056 | 3 | static: QUIC/VOICE | `matches!(shape, SHAPE_QUIC \| SHAPE_VOICE)` + `find_addr_fallback` (`control.rs:1522-1540`) | **P** | **Одностороннее правило C:** при UDP-наблюдении и TCP-записи имени разрешается адресный fallback (`goto check_addr`, `plans.c:1190-1200`); при TCP-наблюдении и UDP-записи — нет (`shape_misses++`, NULL). Rust `find_addr_fallback` проверяет только наличие привязки **того же** транспорта, поэтому TCP-поток к имени, у которого есть только QUIC/VOICE-план, может получить адресный план, чего C не делает. |
| d2k_plantab_shape_misses | 1058-1060 | 3 | счётчик «нашли, но форма не подошла» | `control.rs:193` `r2o_shape_misses` | N | Поле `shape_misses` объявлено и читается, но **нигде не инкрементируется** (grep по `shape_misses` — только объявление/инициализация/геттер) → всегда 0. |
| d2k_plantab_find | 1062-1066 | 5 | поиск плана по имени, затем адресу | `control.rs:410` `select` | P | R2O `select` разбирает пакет и сам извлекает SNI/HTTP/QUIC; порядок «имя → суффикс → адрес» сохранён, но набор ветвей другой (см. `find_target`). |
| d2k_plantab_find_sport | 1068-1072 | 5 | поиск с местным портом потока | `control.rs:410` `select` (`tcp.source_port` для проб) | P | Порт учитывается только для проб; отдельного входа с sport нет. |
| d2k_plantab_find_family | 1074-1079 | 6 | поиск с family | `control.rs:410` `select` (`view.family`) | P | Family берётся из пакета; отдельного входа нет. |
| d2k_plantab_find_target | 1081-1236 | 156 | ядро поиска: probe-by-port при пустом имени → точная форма+порт → своя форма → grandfather → суффикс → адрес; счёт промахов | `control.rs:419-600 select_with_quic_host_at_hook`, `:1493-1590 find/find_addr/find_addr_fallback/find_in_domain` | **P** | Тесты TLS/ECH/QUIC/HTTP/voice/probe (control.rs:2823-3896). **Подтверждённые отличия:** (1) `shape_misses` C инкрементирует, R2O — нет; (2) R2O добавляет TCP-контекст 8–13 и bridge-shape (control.rs:529-539); (3) односторонний кросс-транспортный переход C (UDP→addr, TCP→NULL) заменён общим `find_addr_fallback`, который разрешает и TCP→addr; (4) C при пустом имени и `sport_be` ищет **name-probe по порту** (`plans.c:1093-1112`), R2O UDP-путь имеет только `addr_probe_binding_at_hook`, а TCP без SNI уходит в `find_addr`; (5) C имеет `h.any`/ANY и grandfather/ANY в `scan_addr`, R2O `find`/`find_addr` — только exact+ECH→MODERN; (6) ECH→MODERN в `find_addr` **есть** (`control.rs:1509-1517`), поэтому прежнее утверждение об отсутствии ECH-адресного fallback неверно; отсутствуют grandfather/ANY. |
| d2k_plantab_count | 1238-1240 | 3 | число занятых записей | `control.rs:178` `r2o_plan_count` | E | `exact_name_addr_probe_tables_share_lru_capacity` (control.rs:2633) и eviction-тест сверяют counts. |
| d2k_plantab_capacity | 1242-1244 | 3 | ёмкость таблицы | `control.rs:182` `r2o_plan_capacity` | E | `name_plan_table_evicts_lru...` (control.rs:2663) сверяет capacity. |
| d2k_plantab_binding | 1246-1257 | 12 | identity установленного плана (generation/kind/family/shape/temporary/epoch) | `control.rs:380` `http_name_binding_context`, `:690` `binding_for_plan` | E | `bound_http_set_returns_its_trial_id_and_installed_binding` (control.rs:2700); APPLIED-фикстуры D2O (tests/control.rs:47). |
| d2k_plantab_set_name_trial | 1259-1267 | 9 | поставить пробный план с trial id | `control.rs:1092` `set_name_probe` (trial_id) | E | `http_probe_plan_matches_only_its_source_port_and_acknowledges_trial_id` (control.rs:3489). |
| d2k_plantab_trial | 1268-1273 | 6 | trial id установленного временного плана | `control.rs:690` `binding_for_plan` (`PlanBinding.trial_id`) | E | `tls_probe_plan...reports_temporary_applied` (control.rs:3637), voice-тесты (control.rs:3239). |

Итог по файлу: E 34, P 39, N 1, ? 1. Ключевые пробелы: счётчик промахов по форме мёртв;
нет ECH-удержания; адресные опыты без тестов; префильтры кандидатов грубее C; legacy-удаления
«все формы» отсутствуют; поиск ядра отличается набором ветвей.

---

## datapath/raw.c (17 функций)

Сырой сокет: пределы длины, MTU маршрута, отправка без ожидания. R2O:
`crates/r2o-datapath/src/raw.rs` (`RawSocket`).

**Прочитано построчно: 17/17 функций, 524 строки C (1–524).** Сверено с `raw.rs:34-224` (`RawSocket`/open/send), `:270-357` (maxlen/MTU), `:484-550` (`r2o_route_mtu`), `:559-651` (`outgoing_packet`/IPv4-IPv6-фрагменты), `:653-675` (`set_option`); тесты `raw.rs:231,786,820,836,874`.

**Построчная сверка a378:** все 17 функций прочитаны. C держит IPv4+IPv6+fragment
сокеты в одном объекте; fragment-сокет открывается лениво и **обязательно** с
`IP_NODEFRAG` (`raw.c:387-391`), иначе отказ. `RawSocket` R2O — один сокет на
семейство, `IP_HDRINCL`/`IPV6_HDRINCL`/`SO_MARK` есть, **`IP_NODEFRAG` отсутствует**;
mark обязателен. Совпадают: `pick_maxlen`/`adopt_egress`/`route_maxlen` (порог
1280/576, кэш 16), `MSG_DONTWAIT`, EINTR, EMSGSIZE-понижение, busy=EAGAIN/ENOBUFS,
счётчики sent/errors/busy. `d2k_raw_limits` (`CANT_IPID|CANT_IPSUM`) как API нет;
`CANT_IPSUM` не выражен.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| if_mtu | 64-81 | 18 | static: MTU интерфейса через `SIOCGIFMTU` | `raw.rs:301` `r2o_interface_mtu` (sysfs `/sys/class/net/<if>/mtu`) | P | Механизм другой (sysfs), ioctl-путь не проверен; теста на чтение MTU реального интерфейса нет. |
| pick_maxlen | 92-116 | 25 | static: предел по named iface или наименьшему MTU поднятых (без loopback) | `raw.rs:270` `r2o_pick_maxlen` | P | `общий_предел_берёт_наименьший...` (raw.rs:836) тестирует выбор через инъекцию; сам обход sysfs и fallback 1500 против `D2K_RAW_MTU_FALLBACK` не сверены. |
| route_mtu | 140-176 | 37 | static: MTU маршрута к адресу (UDP connect + `IP_MTU`/`IPV6_MTU`) | `raw.rs:484` `r2o_route_mtu` | P | Код тождествен по смыслу, но требует root/kernel; теста нет. |
| say | 181-191 | 11 | static: текст ошибки с сохранением errno | `io::Error` + `eprintln!` | P | Формат другой; errno сохраняет `io::Error`. |
| d2k_raw_open | 193-256 | 64 | открыть IPv4 raw, `IP_HDRINCL`, `SO_MARK` при mark≠0, вычислить maxlen; `fd6/fragment_fd=-1` | `raw.rs:48-93 RawSocket::open` | **P** | **Подтверждённые отличия:** C создаёт только IPv4 `fd`, а `fd6`/`fragment_fd` открывает лениво; mark=0 допустим (`if (mark != 0)` `:234`), R2O требует **ненулевой** mark (`raw.rs:55-60`). R2O — один объект на одно семейство (`AF_INET`/`AF_INET6` + `IPPROTO_RAW`, `IP_HDRINCL`/`IPV6_HDRINCL`, `SO_MARK`, `raw.rs:62-92`); C держит IPv4+IPv6+IPv4-fragment+IPv6-fragment в одном `d2k_raw`. Тестов open на живой системе нет. |
| d2k_raw_close | 258-269 | 12 | закрыть fd/фрагментный сокет | `Drop for RawSocket` (`OwnedFd`) | E | Владение типами; утечек нет по построению. |
| d2k_raw_limits | 271-273 | 3 | маска ограничений способа отправки (`CANT_IPID\|CANT_IPSUM`) | нет API; `engine.rs:2091` отвергает `POISON_IPID_ZERO` | P | `CANT_IPSUM` в R2O не выражен (суммы считает wire); маска как интерфейс отсутствует. |
| d2k_raw_maxlen | 275-279 | 5 | предел посылки, никогда не 0 | `raw.rs:96` `maxlen` | E | `предел_маршрута_учитывает_объявленный_интерфейс...` (raw.rs:820). |
| d2k_raw_adopt_egress | 281-303 | 23 | принять наименьший MTU выходных ifindex (если предел не объявлен) | `raw.rs:106` `r2o_adopt_egress` | E | `общий_предел_берёт_наименьший...` (raw.rs:836): фильтр `< FLOOR`, дубли, `None`. |
| blend | 306-309 | 4 | static: маршрут против общего предела при объявленном iface | `raw.rs:351` `r2o_effective_route_maxlen` | E | `предел_маршрута_учитывает_объявленный_интерфейс_и_запасной_mtu` (raw.rs:820). |
| d2k_raw_route_maxlen | 311-313 | 3 | MTU маршрута для dst[4] | `raw.rs:119` `packet_route_maxlen` | P | Вход — пакет, а не 4 байта; IPv6-путь и fallback на общий предел не сверены. |
| d2k_raw_route_maxlen_family | 315-339 | 25 | кэш из 16 маршрутов, порог 1280/576, запись кольцом | `raw.rs:136` `r2o_route_maxlen`, `:367` `R2oRouteMtuCache` | E | `кэш_mtu_сохраняет_только_полезные_маршруты_и_ограничен` (raw.rs:786); порог и вытеснение. |
| d2k_raw_prepare | 341-404 | 64 | ленивая подготовка IPv6/fragment-сокета, проверка длин и контекста фрагмента | `raw.rs:559-651 outgoing_packet/ipv4_udp_fragment/ipv6_udp_fragment` | **P** | **Подтверждённые отличия:** C для IPv6 `pkt[6]==44` вызывает `d2k_ip6frag_prepare` (AF_PACKET); иначе лениво открывает `fd6` с `IPV6_HDRINCL`+`SO_MARK` (`:353-372`). Для IPv4-фрагмента требует `pkt[0]==0x45`, `pkt[9]==17`, ненулевой IPID и открывает отдельный `fragment_fd` с `IP_HDRINCL` + **обязательным `IP_NODEFRAG`** (`ENOPROTOOPT`, если опции нет) + `SO_MARK` (`:374-399`). R2O `ipv4_udp_fragment`/`ipv6_udp_fragment` только валидируют фрагмент и шлют через один `RawSocket`; `IP_NODEFRAG` отсутствует, отдельного fragment-сокета и ленивого `fd6` нет. Тест `raw.rs:874 raw_sender_accepts_only_well_formed_ipv4_and_ipv6_udp_fragments`. |
| d2k_raw_send | 406-512 | 107 | `sendto(MSG_DONTWAIT)`, EINTR-повтор, EMSGSIZE → снизить предел | `raw.rs:147` `send_packet`, `:155` `send_packet_inner` | **P** | **Совпадает:** `sendto(MSG_DONTWAIT)` в цикле, повтор только на EINTR (`raw.rs:186-222`), короткая запись — ошибка, EMSGSIZE при длине выше 1280/576 понижает route-кэш и общий предел, busy считается для EAGAIN/EWOULDBLOCK/ENOBUFS (`record_send_outcome`), счётчики sent/errors/busy. **Отличия:** C выбирает отдельный `fragment_fd` для IPv4-фрагментов и `fragments6` для IPv6; Rust шлёт всё через один `RawSocket` своего семейства без `IP_NODEFRAG`; реальная root-отправка в тестах не выполнялась. |
| d2k_raw_sent | 514-516 | 3 | счётчик успешных посылок | `raw.rs:100` `send_stats().sent` | E | `raw_send_stats_count_success_and_busy_errors_like_d2o` (raw.rs:231). |
| d2k_raw_errors | 518-520 | 3 | счётчик ошибок | `raw.rs:100` `send_stats().errors` | E | Тот же тест. |
| d2k_raw_busy | 522-524 | 3 | счётчик EAGAIN/ENOBUFS | `raw.rs:100` `send_stats().busy` | E | Тот же тест. |

Итог по файлу: E 8, P 9, N 0. Главные отличия: один сокет на семейство, обязательный
mark, нет `IP_NODEFRAG`, нет ленивого открытия, нет маски ограничений.

---

## datapath/routemark.c (23 функции)

Сопоставление fwmark/выходных интерфейсов и политика Keenetic. R2O:
`crates/r2o-datapath/src/r2o_route.rs` (`R2oRouteGate`, `R2oRoutePolicy`, парсеры).

**Прочитано построчно: 23/23 функции, 343 строки C (1–343).** Сверено с `r2o_route.rs:84-243` (`R2oRoutePolicy`, `R2oRouteGate`, `r2o_set_rules/set_default_ifindices/set_policy/mark_is_routed/route_mark`), `:372-395` (`r2o_refresh`), `:679-811` (запросы/парсеры), `:950-954` (`r2o_route_add_ifindex`); аналога текстового `describe` в R2O нет.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| rd16h | 27-27 | 1 | static: u16 host order через `memcpy` | `u16::from_ne_bytes` (`r2o_route.rs:1098` и др.) | **E** | `r2o_разбор_правил_учитывает_маску_инверсию_и_завершение_дампа` (`r2o_route.rs:1109`). |
| rd32h | 28-28 | 1 | static: u32 host order | `u32::from_ne_bytes` (`:735`, `:747`) | **E** | Те же тесты разбора. |
| wr16h | 29-29 | 1 | static: записать u16 host order | `to_ne_bytes` (`:683`, `:696`) | **E** | `r2o_запросы_содержат_семейство_последовательность_и_адрес_поиска` (`:1086`). |
| wr32h | 30-30 | 1 | static: записать u32 host order | `to_ne_bytes` (`:685`, `:698`) | **E** | Тот же тест. |
| d2k_routemark_init | 32-34 | 3 | `memset` всего состояния, включая `rules_read*`/`policy_on` | `impl Default for R2oRouteGate` (`:107-116`) | **E** | Все тесты создают `R2oRouteGate::default()`; поля-`Option` дают «неизвестно». |
| d2k_routemark_request | 36-46 | 11 | `RTM_GETRULE`, `NLM_F_REQUEST/DUMP`, seq, family в `fib_rule_hdr[0]` | `r2o_route_rule_request` (`:679-690`) | **E** | Совпадает: длина 28, тип 34, flags 0x301, seq, family; тест `:1086`. |
| nl_error | 49-51 | 3 | `body_len>=4` → знаковый errno, иначе 0 | `r2o_kernel_error` (`:863-872`) | **P*** | **Отличие только в коротком теле:** C возвращает 0 и парсер даёт общую ошибку «ответ не разобран»; Rust возвращает `Malformed`. Оба отвергают дамп, но классификация разная; теста на `NLMSG_ERROR` короче 4 байт нет. |
| d2k_routemark_parse | 53-95 | 43 | обход `NEWRULE`: family[0], flags[8..12] invert, FWMARK/FWMASK (alen≥8), mask по умолчанию `0xffffffff` при ненулевой метке, `mask==0` пропуск, DONE→1 | `r2o_route_parse_rules` (`:711-766`) | **P** | **Совпадает:** FWMARK/FWMASK, `mark &= mask`, invert-правила **пропускаются** в обеих реализациях, `mask=0` пропуск, DONE, ошибка на хвосте ≥4. **Подтверждённые отличия:** (1) C принимает **любой** `family` и кладёт его в селектор, Rust — только 2/10, остальные пропускает; (2) C при `*n >= cap` всё равно увеличивает `*n` (переполнение видно вызывающему и обрезается в `merge`), Rust `r2o_dump_rules` при >32 правилах **возвращает ошибку** (`:437-443`); (3) `nl_error` на коротком теле. Тест `:1109`. |
| d2k_routemark_lookup_request | 103-120 | 18 | `RTM_GETROUTE` без dump, `rtmsg.dst_len=al*8`, `RTA_DST` = 192.0.2.1/2001:db8::1 | `r2o_route_lookup_request` (`:691-710`) | **E** | Совпадает: family 2/10, длина 36/48, `NLM_F_REQUEST`, probe-адреса; тест `:1086`. |
| add_oif | 122-128 | 7 | static: пропуск 0, дедуп, запись только при `*n < cap`, иначе только счётчик | `r2o_route_add_ifindex` (`:950-954`) | **E** | Дедуп/ноль совпадают; предел 16 проверяется в `r2o_lookup_default` (`:505-511`), тест `:1137`. |
| route_oifs | 132-152 | 21 | обход `RTA_OIF` (alen≥8) и `RTA_MULTIPATH` (rtnexthop len≥8), ошибка на битой длине | `r2o_route_attributes` (`:876-911`), `r2o_route_parse_multipath` (`:913-948`) | **E** | Та же раскладка/выравнивание/дедуп; тест `:1137` (OIF+multipath+нулевой hop). |
| d2k_routemark_lookup_parse | 154-173 | 20 | `NEWROUTE`, `rtm_type != RTN_UNICAST` → 2, иначе OIF; хвост ≥4 → -1 | `r2o_route_parse_lookup` (`:769-797`) | **E** | Rust `NoRoute` соответствует C-коду 2 (вызывающий переводит в 3); тест `:1137` + `r2o_ошибки_...` (`:1161`). |
| d2k_routemark_watch_relevant | 175-190 | 16 | NEW/DEL RULE → 1; NEW/DEL ROUTE с `rtm_dst_len==0` (или коротким телом) → 1; битый хвост → 1 | `r2o_route_watch_relevant` (`:800-811`) | **E** | Совпадает; тест `r2o_уведомления_обновляют_состояние...` (`:1189`). |
| d2k_routemark_clear_oifs | 192-199 | 8 | family 2/10: `changed = oifs_read`, `oifs_read=0`, `n=0` | `r2o_set_default_ifindices(family, None)` (`:131-157`) | **P** | Состояние эквивалентно (`None` = «неизвестно», как `read=0/n=0`), но C **возвращает признак изменения**, а Rust-сеттер — нет; вызывающий не может отличить сброс от отсутствия изменений. Теста на маршрут без OIF нет. |
| d2k_routemark_set_oifs | 201-213 | 13 | `ok==0` → без изменений; cap 16; `changed = !read или n!=old или memcmp`; `read=1` | `r2o_set_default_ifindices` (`:131-157`) | **P** | Rust дополнительно дедуплицирует и выбрасывает 0 (после `add_oif` это no-op), состояние `Some(vec)` соответствует `read=1`; **признак `changed` не возвращается**. `r2o_устройства_по_умолчанию...` (`:1053`). |
| d2k_routemark_set | 215-227 | 13 | `rules_read4=read6=1`, cap 32, `changed` по длине и тройкам mark/mask/family, копия | `r2o_set_rules` (`:118-130`) | **P** | Хранение `Option<Vec>` эквивалентно `read+n`, `mark &= mask`; **нет возврата `changed`** и отдельных `rules_read4/6`; Rust фильтрует селекторы чужого семейства. Влияние на удержание/refresh не проверено. |
| d2k_routemark_merge | 229-267 | 39 | успешное семейство заменяет, упавшее — прежние селекторы; `found`, `truncated`, `rules_read` обновляется через `ok` | `r2o_refresh` (`:372-397`) | **P** | Сохранение прежнего набора при ошибке есть (сеттер вызывается только при `Ok`). **Не перенесены:** `st->found`, `st->truncated`, `routes4_ok/routes6_ok`, `changed`; Rust не сообщает, сколько правил найдено и было ли усечение. |
| d2k_routemark_set_policy | 269-275 | 7 | `policy_on=1`, `policy_none`, `policy_mark = mark & mask`, mask | `r2o_set_policy(Some(R2oRoutePolicy))` (`:170-172`), `R2oRoutePolicy::new` (`:88-95`) | **E** | `Some(new(false,0,0))` = `policy_on=1, none=1`; `Some(new(true,..))` = активная политика; `None` = исходное `policy_on=0`. Тест `r2o_политика_отделяет_чужие_потоки...` (`:1008`). |
| policy_match | 277-280 | 4 | `policy_on && !none && have_mark && (mark^policy_mark)&mask==0` | `R2oRoutePolicy::r2o_matches` (`:97-99`) | **E** | `found`/`None` заменяют `policy_on/none`, `have_mark` — `Option`; тест `:1008`. |
| d2k_routemark_routed | 282-296 | 15 | 0 → 0; OTHER/OUTSIDE → 1; своя политика → 0; неизвестное семейство → 1 (fail closed); совпадение правила → 1 | `r2o_mark_is_routed` (`:175-199`) | **E** | Построчно совпадает; тест `:979`. |
| d2k_routemark_client | 298-302 | 5 | нет метки/0/probe/own → 0, иначе routed ? mark : 0 | первые ветви `r2o_route_mark` (`:202-220`) | **P** | Логика «клиентской» метки совпадает, но отдельной функции нет: Rust в той же функции дальше применяет outdev-гейт и может вернуть `OTHER_DEV` вместо 0. Тест покрывает политику/свои метки (`:1008`), не границу client/gate. |
| d2k_routemark_gate | 304-325 | 22 | policy_on+outbound: не own и не policy_match → OUTSIDE; client; не outbound/нет outdev → m; неизвестные oifs → 0; outdev не в списке → OTHER_DEV | `r2o_route_mark` (`:202-243`) | **E** | Совпадает: own-метки, OUTSIDE, routed, «нет списка — без гейта», OTHER_DEV; тесты `:1008`, `:1053`. |
| d2k_routemark_describe | 327-343 | 17 | текст `0xmark/0xmask v4, ...` или `нет`, обрезка по cap | — | **N** | Функции/строки описания набора правил в R2O нет; только отладочные сообщения `main.rs`. |

Итог по файлу: E 15, P 7, N 1. Пробелы: статус merge (`found/truncated/routes_ok`),
признак изменения набора правил и списка устройств, переполнение >32 правил (C усекает,
Rust ошибается), отсутствие текстового описания.

---

## datapath/routemark_nl.c (8 функций)

Rtnetlink: дампы правил, одиночный поиск маршрута, подписка на изменения. R2O:
`R2oRouteMonitor` в `crates/r2o-datapath/src/r2o_route.rs`.

**Прочитано построчно: 8/8 функций, 228 строк C (1–228).** Сверено с `r2o_route.rs:283-368` (`r2o_open_watch`/`r2o_drain_watch`), `:398-423` (`r2o_dump_rules`), `:425-446` (`r2o_lookup_default`), `:448-536` (`r2o_receive_request`), `:546-554` (`r2o_parse_io_error`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| parse_rules | 18-21 | 4 | static: адаптер сигнатуры под `d2k_routemark_parse` | замыкание в `r2o_dump_rules` (`r2o_route.rs:402-420`) | **E** | Тонкий адаптер; владелец `r2o_route_parse_rules`, тест `:1109`. |
| dump | 27-59 | 33 | static: `sendto`, до 4096 `recv`, EINTR, парсер до DONE; `-EAFNOSUPPORT/-EOPNOTSUPP` → пустой успех; иная ошибка ядра/разбор → -1 | `r2o_receive_request` (`:458-557`) + ветка `r2o_dump_rules` (`:406-412`) | **P** | **Совпадает:** sendto, буфер 32768, 4096 раундов, EINTR, DONE, ошибка ядра, SO_RCVTIMEO 200 мс. **Подтверждённое отличие:** C трактует `-EAFNOSUPPORT/-EOPNOTSUPP` как пустой успех для **любого** семейства; Rust делает это только для IPv6-правил (`family == Ipv6 && matches!(code, -97 / -95)`), для IPv4 — ошибка. |
| dump_rules | 61-67 | 7 | static: запрос правил family + `dump` с пределом `D2K_ROUTEMARK_MAX=32` | `r2o_dump_rules` (`:398-453`) | **P** | **Подтверждённое отличие:** C при >32 правилах не ошибается: парсер считает `*n` сверх cap, `merge` усекает и выставляет `truncated`; Rust при `selectors.len()+batch > 32` возвращает `InvalidData` и **не сохраняет** семейство (остаётся прежний набор). Тест на переполнение отсутствует. |
| lookup_route | 72-110 | 39 | static: один `RTM_GETROUTE`, до 4 `recv` по 8192; rc 1→0/2, rc 2→3; `ENETUNREACH/EHOSTUNREACH/ENETDOWN/EAFNOSUPPORT` → 3 | `r2o_lookup_default` (`:455-515`) | **P** | **Совпадает:** один lookup, коды 2/3, набор errno `-97/-100/-101/-113`, пустой Unicast → «нет устройства» (2). **Отличия:** C 4 раунда × 8192, Rust 4096 × 32768; C при исчерпании — «нет ответа», Rust — `Pending`/ошибка. Проверено парсером и живым IPv4-тестом, не всеми кодами. |
| dump_socket | 115-128 | 14 | static: `AF_NETLINK/SOCK_RAW/CLOEXEC`, `SO_RCVTIMEO=200000` | socket+SO_RCVTIMEO в `r2o_receive_request` (`:463-530`) | **E** | Флаги/таймаут совпадают; C переиспользует сокет до ошибки части, Rust создаёт на каждый запрос — наблюдаемое поведение то же. `r2o_монитор_читает_правила...` (`:1240`). |
| d2k_routemark_load | 130-177 | 48 | 4 независимые части: правила v4/v6, маршруты v4/v6; после ошибки — новый сокет; merge+oifs; `routes4_ok/routes6_ok`, первый текст ошибки, -1 если все части упали | `r2o_refresh` (`:372-397`) | **P** | **Совпадает:** порядок 4 частей, независимость семейств, сохранение прежнего при ошибке, `rc==2` → пустой список oifs (без гейта). **Не перенесены:** `routes4_ok/routes6_ok`, `st->found/truncated`, `changed`, «первая ошибка» как единый текст; Rust возвращает `Vec<String>` всех ошибок. Сокет на каждый запрос, а не после сбоя. |
| d2k_routemark_watch_open | 179-209 | 31 | `SOCK_NONBLOCK`, bind, 4 группы: 8/7 обязательны, 19/11 опциональны | `r2o_open_watch` (`:283-332`) | **E** | Группы/обязательность совпадают: `(8,true),(7,true),(19,false),(11,false)`; bind/CLOEXEC/NONBLOCK те же. `r2o_монитор_читает_правила...` (`:1240`) вызывает open, но результат намеренно не проверяется — обязательность IPv4 тестом не подтверждена. |
| d2k_routemark_watch_drain | 211-228 | 18 | до `D2K_ROUTEMARK_WATCH_READS=256`; `>0` → relevant, EINTR, ENOBUFS→1, иное/0 → вернуть накопленное; исчерпание → 1 | `r2o_drain_watch` (`:334-370`) | **P** | **Совпадает:** 256 чтений, `MSG_DONTWAIT`, EINTR, ENOBUFS→true, `EAGAIN` → вернуть накопленное, предел→true. **Отличие:** C на любую иную ошибку `recv` возвращает накопленный `any` (`routemark_nl.c:225`), R2O возвращает `Err(error)` (`r2o_route.rs:365`); C не различает «нет данных» и сбой сокета. Тест на границу отсутствует. |

Итог по файлу: E 4, P 4, N 0. Пробелы: обработка `EAFNOSUPPORT` для IPv4-правил,
переполнение >32 правил (C усекает с `truncated`, Rust ошибается), внешние
`routes4_ok/routes6_ok/found/truncated`, лимиты раундов lookup.

---

## 9a. Углублённая сверка 5 N-функций

**Прочитано построчно: 5/5 N-функций (`ctl.c:143-144,316`; `plans.c:1058-1060` + инкременты `:1140,:1209,:1233`; `routemark.c:327-343`).** В R2O подтверждено отсутствие отдельных геттеров `listen_fd`/`peer_fd`/`sent` и текстового `describe`; `shape_misses` объявлен, но не инкрементируется.

- **`d2k_ctl_listen_fd`/`d2k_ctl_peer_fd` (ctl.c 143–144):** C отдаёт
  наружу listen/peer fd для внешнего poll-цикла. R2O инкапсулирует оба
  дескриптора в `ControlServer` (`control.rs`), а `main.rs:1388` вызывает
  `control.poll()`; отдельного геттера нет. N — API-удобство, не потеря
  функциональности.
- **`d2k_ctl_sent` (ctl.c 316):** C считает кадры, поставленные в кольцо
  отправки. В R2O есть только `dropped_events` (`control.rs:1983`), счётчика
  `sent` нет. N — диагностика.
- **`d2k_plantab_shape_misses` (plans.c 1058–1060):** C-геттер
  `t->shape_misses`, и C **инкрементирует** его в трёх ветвях
  (`plans.c:1140`, `:1209`, `:1233`); используется для
  `quic_shape_miss` (`session.c:1270-1277`). R2O объявляет
  `shape_misses: Cell<u64>` и геттер `r2o_shape_misses`
  (`control.rs:92,166,193`), но **нигде не инкрементирует** — всегда 0.
  N подтверждён: это реальное расхождение диагностики, не packet-path.
- **`d2k_routemark_describe` (routemark.c 327–343):** C формирует текст
  `0xmark/0xmask v6|v4, ...` или `нет` для логов. В R2O функции/строки
  описания набора правил нет; маршрутная метка и выбор egress есть в
  `r2o_route.rs`/netlink. N — диагностика.

**Итог:** 5 N — четыре диагностических/API-величины и один реально
ненаблюдаемый счётчик `shape_misses`; packet-path они не меняют.

## 9b. Углублённая сверка plans/plan_parse/ctl/raw/routemark

- **`plans.c` (75 функций):** `d2k_plantab_new/free`,
  `bind_context`, `name_eq`, `shape_transport`, `area_name_valid`,
  `suffix_member`, `area_exact/set/del/bypassed/match`,
  `d2k_plantab_set/del_{suffix,bypass}_family`, `revision`,
  `find/scan_name/scan_addr`, `oldest`, `take_free_or_evict`,
  `set_name*`, `set_addr*`, `drop`, `del_*`, `probe_*`, `shape_fits`,
  `find_target`, `count/capacity/binding/trial` сверены с
  `control.rs NamePlans`/`select`/`find_in_domain`/`binding_for_plan`.
  Ёмкости совпадают: suffix 64, bypass 256, name plans 2048; LRU-
  вытеснение (`oldest`/`take_free_or_evict`) и `touch` покрыты
  `name_plan_table_evicts_lru_and_delete_releases_a_slot`,
  `exact_name_addr_probe_tables_share_lru_capacity`. **Пробелы:**
  `shape_misses` C инкрементирует, R2O — нет (N); `has_ech_target` —
  отдельного предиката нет (`?`); `find_target` (QUIC-first по sport,
  ECH→modern/grandfather, suffix, addr fallback) сложнее `select` и
  полного differential не имеет — P.
- **`plan_parse.c` (17 функций):** `rd16/rd32`, `fail`, `scan`,
  `check_refs`, `d2k_find_payload/poison`, `d2k_plan_load/free`,
  `poison_used/flow_needs/quic_deny/guards/transport/proto/stream_input/
  id` сверены с `r2k-core/src/plan.rs Plan::parse(_wire)` и
  `engine.rs` `flow_needs`/`quic_deny`. Счётчики записей, ссылки
  payload/poison, флаги и `minexec` проверяются; P — побайтового
  C/Rust differential парсера нет, только общие plan/apply тесты.
- **`ctl.c`/`ctlsrv.c`:** `say`, `set_nonblock`, `d2k_ctl_open/close/
  listen_fd/peer_fd/set_disconnect_hook/accept/drop_peer/flush/event/poll/
  dropped/sent` и `d2k_ctlsrv_*` сверены с `control.rs ControlServer`.
  **Расхождения:** C `D2K_CTL_OUT_RING=65536` (`ctl.c:21`), Rust
  `MAX_CONTROL_OUTPUT=128*1024` (`control.rs:28`) — R2O держит вдвое
  больший выходной буфер; `listen_fd`/`peer_fd`/`sent` отсутствуют
  (N); `d2k_ctl_open` удаляет свой путь и `listen(1)`, Rust ставит
  права 0600/backlog и не удаляет чужой не-сокет (P). Команды
  `SET_HTTPS`/`ARM_SHAPE`/адресные опыты — см. строки и раздел 10.
- **`raw.c` (17 функций):** `if_mtu`, `pick_maxlen`, `route_mtu`,
  `d2k_raw_open/close/limits/maxlen/adopt_egress/route_maxlen(_family)/
  prepare/send/sent/errors/busy` сверены с `r2o-datapath/src/raw.rs`.
  **Расхождения:** C допускает `mark=0` и не ставит `SO_MARK`; Rust
  требует ненулевой mark (`raw.rs:55-59`). C ставит `IP_NODEFRAG` и
  держит отдельные IPv4/IPv6/fragment-сокеты лениво; в Rust
  `IP_NODEFRAG` отсутствует, один сокет на семейство, mark обязателен.
  `d2k_raw_limits` (`CANT_IPID|CANT_IPSUM`) отдельного API не имеет:
  R2O отвергает `IPID_ZERO` в `engine.rs:2091`, суммы считает `wire.rs`.
  Route-MTU cache 16 и `EMSGSIZE`-понижение есть, тесты raw/route; P.
- **`routemark.c`/`routemark_nl.c` (31 функция):** `init/request/parse/
  lookup_request/lookup_parse/watch_relevant/clear_oifs/set_oifs/set/
  merge/set_policy/policy_match/routed/client/gate/describe` и
  `r2o_route.rs` (`r2o_set_rules/refresh/route_mark`) — P.
  **Расхождения:** C `d2k_routemark_merge` считает `found/truncated`,
  сохраняет правила упавшего семейства и `rules_read4/6`; Rust
  `r2o_set_rules` заменяет семейство без статуса `found/truncated`.
  `d2k_routemark_describe` — N; признак изменения набора правил и
  `merge`-статус не перенесены.
- **Вывод:** новый подтверждённый пробел — control-ring 64 КиБ vs
  128 КиБ; raw mark=0/`IP_NODEFRAG`; routemark merge status. Остальное —
  P на сложные ветви/дифференциалы.

## 9c. Углублённая сверка ctlsrv.c (12 функций)

**Прочитано построчно: 12/12 функций, 731 строка C (1–731).** Сверены тела
`put_key`, `d2k_plan_fits`, `ack`/`ack_trial`, `d2k_ctlsrv_greet`,
`d2k_ctlsrv_peer_closed`, `canonical_address`/`addr_shape_valid`,
`read_probe_flow`, `d2k_ctlsrv_command` (13 команд), `d2k_ctlsrv_pump` и
`d2k_ctlsrv_http80_event`; подтверждённые отличия перечислены ниже.

- **`put_key` (23–37):** 38-байтовый ключ полями: family, low/high адрес
  (4/16), low/high порт BE, proto. Совпадает с `TcpFlowKey::wire_key`
  (`capture.rs:51`) и `r2o_udp_flow_wire_key` (`control.rs:1644`);
  E, фикстуры `tests/control.rs:47`.
- **`d2k_plan_fits` (39–72):** `limits==0` → пропуск; `POISON_IPID_ZERO`
  при `CANT_IPID` → отказ; `maxlen>0 && max_emit>maxlen` → отказ. R2O:
  `r2o_plan_valid` + `max_emit` (`control.rs:255`, `main.rs:986`);
  ветвь длины покрыта `name_plan_отклоняется_..._mtu` (`control.rs:2766`),
  ветвь IPID_ZERO тестом не покрыта — P.
- **`ack`/`ack_trial` (84–123):** тело key38 + type2 + ok1 + reason1,
  опционально area_id16 (SUFFIX..DEL_BYPASS, SET_NAME_PROBE/BOUND) и
  binding28 (SET_NAME_BOUND); `ack_trial` всегда несёт trial16. R2O
  `send_ack`/`encode_ack_with_identifiers_profile` и `encode_ack_for_trial`;
  E по фикстурам.
- **`d2k_ctlsrv_greet` (125–145):** PROTO: key38 + version2 + maxlen4 +
  release-len1 + release. R2O `encode_greeting_profile`; E.
- **`d2k_ctlsrv_peer_closed` (147–150):** снимает пробные планы
  (`d2k_plantab_clear_probes`). R2O `name_plans.clear_probes()`
  (`main.rs:1415`); E.
- **`canonical_address` (152–157) / `addr_shape_valid` (163–167):**
  IPv4-хвост 16-байтного адреса обязан быть нулевым; формы
  1/2/3/5/6. R2O `addr_plan_key`/`valid_addr_shape` (`control.rs:1612,
  1628`); canonical — E, shape — P (нет теста на 0/4/7).
- **`read_probe_flow` (169–187):** разбор 38-байтового flow; **C
  допускает `src_port=0`** (голос «любой клиентский порт»), Rust
  `valid_udp_addr_probe_flow` требует оба порта ≠0 и ненулевые адреса.
  Это подтверждённое расхождение (см. строку).
- **`d2k_ctlsrv_command` (189–509):** 13 команд. Сверены тела, точные
  длины, ACK-коды, идемпотентные DEL. Расхождения: ~~SET_HTTPS 7 суток
  vs 6 часов~~ — **закрыто 2026-11-12** (датапат обрезает до 7 суток,
  кодировщик принимает любой `u32`); ARM_SHAPE 6/17 vs 6;
  SET_ADDR_PROBE `src_port=0` vs требование ≠0 + отдельная 0x0095;
  DEL_NAME_PROBE shape не проверяется в C. Остальные ветви
  (SET_NAME/BOUND/PROBE/ADDR, SUFFIX/BYPASS, DEL_*, STALL_BUDGETS)
  совпадают по полям и ACK.
- **`d2k_ctlsrv_pump` (511–694):** C раскладывает journal kind в
  события; `PLAN_APPLIED` не отдаёт, `PLAN_DONE→APPLIED`,
  `REFUSED/UNSENT/DAMAGED→REFUSED`, `SHAPE→CLIENT_TCP+SHAPE`,
  `HELLO/SUSPECT/EXCHANGE` — своими типами. R2O шлёт journal entries
  как R2O-only `EVENT_R2O_JOURNAL_ENTRY` (контроллер только печатает),
  а dedicated-события — отдельно; доказательства не подменяются.
  Пробел v22: пустые TCP-опции в `EVENT_LEGACY_CLIENT_TCP`.
- **`d2k_ctlsrv_http80_event` (697–731):** тело: key38 + code1 +
  host-len1 + host + execution8 + plan16 + trial16 + request_ms8 +
  path-len2 + path + binding28; при `response` — status2 +
  body_bytes8 + request_no8. R2O `HttpResponseEvent::event_body`
  (`r2k-core/control.rs:852`); P: R2O всегда несёт хвост, C для
  портала без ответа его не шлёт; код ответа кодируется иначе.

## 9d. Углублённая сверка plans.c: поиск плана

- **Порядок C (`d2k_plantab_find_target`, 1081–1236):**
  1. пустое имя + `sport_be`: name-probe по одному порту, при
     неоднозначности — NULL (`:1093-1112`);
  2. имя + порт: точная форма+порт, ECH→MODERN, ANY→name_port,
     grandfather, затем `shape_fits`; иначе `shape_misses++`;
  3. имя без порта: `scan_name` (shaped, ECH→modern, grandfather,
     BYPASS, suffix, `h.any`), `shape_fits`; при UDP-наблюдении и
     TCP-записи — `goto check_addr`; иначе `shape_misses++`/NULL;
  4. адрес: `scan_addr` (shaped, ECH→modern, grandfather, any),
     `shape_misses++` при несовпадении.
- **Rust:** `select_with_quic_host_at_hook` (`control.rs:419-600`)
  разбирает UDP/STUN/voice/QUIC и вызывает `addr_probe_binding_at_hook`,
  `find`, `find_in_domain`, `find_addr_fallback`; TCP — probes по
  `shape`/`bridge_shape` и порту, затем `find(shape/bridge/fallback/
  grandfather)`, `find_in_domain`, `find_addr_fallback`.
  `find` (`:1493`) — только точная форма; `find_addr` (`:1504`) —
  точная + ECH→MODERN; `find_in_domain` (`:1569`) — точная форма,
  `max_by_key(len)`; `find_addr_fallback` (`:1522`) — проверка
  привязки/ BYPASS того же транспорта, затем `find_addr`.
- **Подтверждённые различия:**
  1. `shape_misses` C инкрементирует в двух ветвях, R2O — нигде (N).
  2. R2O добавляет TCP-контекст 8–13 и bridge-shape — расширение,
     не пробел.
  3. Одностороннее правило C потеряно: TCP-поток к имени с
     QUIC/VOICE-планом в R2O может получить адресный план, C
     возвращает NULL.
  4. C ищет name-probe по порту при пустом имени; R2O UDP-путь
     имеет только addr-probe, TCP без SNI уходит в `find_addr`.
  5. C `scan_addr` поддерживает grandfather/ANY; R2O `find_addr` —
     только exact+ECH→MODERN.
  6. ECH→MODERN в `find_addr` **есть**; прежнее утверждение об
     отсутствии ECH-адресного fallback неверно.
  7. `d2k_plantab_has_ech_target` прямого аналога не имеет (`?`).

## 9e. Углублённая сверка plans.c: set/del/binding

- **`d2k_plantab_set_addr_shaped` (692–721) ↔ `control.rs:891-927
  set_addr`:** C проверяет family 4/6, `shape != ANY/HTTP`,
  `proto != HTTP`; затем `revision++`, поиск `(addr,shape)`,
  вытеснение/вставка, `bind_context`. Rust дополнительно требует
  `addr_plan_key` (канонический IPv4-хвост), `valid_addr_shape`,
  `addr_plan_matches_shape` (MODERN/LEGACY/ECH→TCP TLS, QUIC→
  `valid_quic`, VOICE→UDP voice) и `r2o_plan_valid`. **На негодном
  входе R2O строже**; для валидного — эквивалентно. Тест
  `control.rs:2793` проверяет удаление двух форм, не приём.
- **`drop` (728–741) ↔ `HashMap::remove`:** C сохраняет
  уплотнение переносом последней записи и `used--`; Rust
  `HashMap` не требует уплотнения; `revision++`/освобождение
  плана эквивалентны. E.
- **`d2k_plantab_del_name_family` (747–765):** C снимает **все**
  записи имени в family (все формы и пробы); Rust `delete_name`
  (`control.rs:1389`) снимает один `(name, transport, shape,
  family)`. Это legacy-API, control v9 ходит через
  `del_name_shaped`; P.
- **`d2k_plantab_del_name_shaped` (773–790):** C точно
  `(name, family, shape, only_sport=0, transport)`; Rust
  `delete_name` — тот же ключ. E; тест условного HTTP-удаления.
- **`d2k_plantab_del_name_bound` (792–806):** C требует
  `binding_known`, `kind==NAME`, `!temporary`, `binding_equal`;
  Rust `delete_name_bound` (`:1416`) проверяет ключ и binding;
  `is_known` не проверяет kind, но удаление проверяет отдельно. E.
- **`d2k_plantab_del_name_probe_family` (813–828):** C не
  проверяет shape; Rust требует `valid_tcp_probe_shape`. На
  валидном входе совпадает, на shape 0/неизвестной ACK
  различается. P.
- **`d2k_plantab_del_addr_family`/`_shaped` (837–848):** C
  `del_addr_family` снимает все формы, `del_addr_shaped` — одну;
  Rust `delete_addr` (`:1479`) — одну. Control использует shaped;
  broad-путь — P, shaped — E.
- **`d2k_plantab_binding` (1246–1257):** C возвращает 0 при
  `owner != t`, `!generation` или нулевом epoch; иначе
  generation/kind/family/shape/temporary/epoch. Rust
  `binding_for_plan` (`:690`) — pointer identity + generation/
  shape/trial; E по тестам APPLIED/bound HTTP.
- **`d2k_plantab_set_name_trial`/`trial` (1259–1273):** C ставит
  `binding_trial_id` только при успехе и отдаёт его только для
  temporary; Rust `set_name_probe`/`binding_for_plan` хранит
  trial_id в `ProbePlan`; E.

## 9f. Углублённая сверка plans.c: пробы

- **`probe_flow_valid` (860–874):** C требует UDP, `dst_port≠0`,
  family 0/4/6, ненулевые src/dst; `src_port=0` — голосовой
  wildcard. Rust `valid_udp_addr_probe_flow` (`r2k-core/control.rs:
  1701-1717`) требует family 4/6 и оба порта ≠0; голос — отдельная
  `voice_addr_probes`. Control-путь C тоже требует family 4/6, но
  wildcard-порт реален. P.
- **`probe_flow_equal` (876–887):** C сравнивает family/transport/
  оба порта/src/dst; Rust — равенство ключа `[u8; KEY_LEN]`. P.
- **`probe_drop` (889–895):** C освобождает план, обнуляет запись,
  `probe_used--`, `revision++`; Rust `HashMap::remove`/`retain`.
  E.
- **`d2k_plantab_clear_probes` (897–910):** C удаляет name-записи
  с `only_sport` **или** `d2k_plan_quic_deny` и все probe-записи.
  Rust `clear_probes` (`control.rs:600-611`) чистит
  `probes`/`voice_addr_probes`/`addr_probes`, но **не удаляет
  `qdeny`-записи** из `plans`. После disconnect C снимает
  QUIC-запрет, R2O оставляет. P.
- **`d2k_plantab_set_addr_probe` (912–961):** C хранит QUIC и
  VOICE в одной `probes[]`, shape из proto (2→QUIC, 3→VOICE,
  иначе ANY), ёмкость `cap` (2048), `bind_context(...,
  temporary=1)`. Rust — `addr_probes` (только QUIC,
  `valid_quic_plan`) и `voice_addr_probes`, обе по **64**; при
  >64 опытов C примет, R2O вернёт `NO_ROOM`. C допускает
  `src_port=0` для голоса, Rust generic — нет. P.
- **`d2k_plantab_del_addr_probe` (963–976):** C точный
  flow+trial; Rust точный key+trial. P (тестов нет).
- **`find_probe` (978–1006):** C лениво удаляет истёкшие, wildcard
  клиентского порта — только для voice; Rust
  `addr_probe_binding_at_hook`/`voice_address_binding`. P.
- **`d2k_plantab_find_addr_probe` (1008–1012):** C точный поиск;
  Rust `addr_probe_binding_at_hook` дополнительно требует
  authenticated Initial и клиентского направления. P.
- **`d2k_plantab_find_voice_probe` (1014–1018):** C wildcard
  клиентского порта; Rust `voice_address_binding` — ключ без
  клиентского порта. E (voice-тесты control.rs:3239/3278).
- **`d2k_plantab_probe_count` (1020–1022):** C считает все
  занятые `probes[]` (QUIC+VOICE); Rust `r2o_probe_count` — только
  неистёкшие `addr_probes`. P.

## 9g. Углублённая сверка plans.c: area/stream/http

- **`bind_context` (94–102) ↔ `control.rs:1592`:** C выдаёт
  `generation=++next_binding` (пропуск 0 на UINT64_MAX), пишет
  kind/family/shape/temporary и обнуляет trial_id. Rust
  `next_generation = revision+1` на каждую вставку; identity
  собирается в `binding_for_plan`. P.
- **`name_eq` (154–167) ↔ `canonical_name`:** C ASCII
  case-insensitive по месту; Rust канонизирует имя при вставке.
  P; теста на верхний регистр в плане нет.
- **`shape_transport` (169–175) ↔ `valid_domain_area_context`:**
  C: QUIC→17, TLS/ECH/контекст 8–13→6, иначе 0; Rust: TCP для
  1/2/6/8–13, QUIC для 3, VOICE не входит. P.
- **`area_name_valid` (177–191) ↔ `canonical_name`:** C допускает
  односложное и чисто цифровое имя (`localhost`, `12345`);
  Rust требует ≥2 метки и нецифровой символ. **Подтверждённое
  расхождение** для `SET_SUFFIX`/`SET_BYPASS`.
- **`suffix_member`/`area_exact`/`area_bypassed`/`area_del`/
  `set_suffix`/`set_bypass` ↔ `domain_suffix_member`/ключи/
  `set_suffix`/`set_domain_bypass`/`delete_domain_area`:** логика
  совпадает; E/P по строкам. `area_match` — точная shape/family,
  самый длинный суффикс; P (тест одного суффикса).
- **`has_ech_target` (288–314):** прямого Rust-предиката нет;
  три ECH-формы, `only_sport`, BYPASS и суффиксы C не выражены
  одной функцией. `?`.
- **`stream_candidate_target` (327–350) ↔ `has_tls_candidate`:**
  C учитывает bypass, `only_sport`, имя/адрес/sport; Rust —
  только family/shape/`stream_input` и суффиксы/адрес без bypass
  и без конкретной цели. P; возможен true для исключённого имени.
- **`find_name_skip`/`find_name`/`find_name_shape_port`/
  `find_name_port` (357–412) ↔ `NamePlanKey`/`NameProbeKey`:**
  C линейные сканы, Rust HashMap; E/P по строкам.
- **`http_candidate` (414–422) ↔ `has_http_candidate`:** C
  требует exact name/family/HTTP/port/proto HTTP; Rust — только
  family+HTTP. Префильтр R2O шире; P.
- **`find_http` (424–431) ↔ HTTP-путь `select` + `NameProbeKey`:**
  C проверяет `proto==HTTP`; Rust `set_name` для SHAPE_HTTP уже
  требует `transport=6/proto=HTTP`, поэтому для валидных планов
  эквивалентно. E.
- **`revision`/`count`/`capacity`:** C `revision/used/cap`;
  Rust `revision/plans.len()/capacity`. P.

## 10. Итоговые пробелы (что мешает ставить E)

1. **Счётчик промахов по форме мёртв.** `d2k_plantab_shape_misses` в R2O всегда 0 —
   `shape_misses` не инкрементируется ни в одной ветви `select`. В C это отдельный
   наблюдаемый факт («цель знаем, форма другая»), по которому контроллер отличает
   незнакомую цель от несовместимой формы.
2. **Предикат ECH-удержания не найден.** `d2k_plantab_has_ech_target` как отдельная
   функция отсутствует; R2O собирает неполный ClientHello общим путём `capture.rs`/
   `engine.rs`, поэтому поведение может быть покрыто, но адресного differential на
   «ECH-привязка → удерживать, иначе не удерживать» нет. Статус `?`, не `N`.
3. **Адресные опыты (`SET/DEL_ADDR_PROBE`) не покрыты тестами.** Реализация есть, но
   ни одна ветвь (lease, чужая generation, точный flow, wildcard голоса) не проверена.
4. **Префильтры кандидатов грубее.** `has_tls_candidate`/`has_http_candidate`/
   `has_quic_candidate` смотрят только family/shape, тогда как C учитывает имя, адрес и
   sport; возможны лишние удержания/захваты, но не пропуски планов.
5. **`d2k_plan_apply` ограничен 26 посылками** (`MAX_EMISSIONS`) против 65536 в C;
   D2O на выдаче в session тоже ограничивает 26 (`D2K_RESULT_MAX`, session.c:2517),
   поэтому наблюдаемый отказ совпадает, различаются слой и текст ошибки. Это P, не N.
6. **OOB-суффикс теряет `wire_profile`** в `Plan::apply` (apply.rs:280-291).
7. **Legacy-удаления «все формы» отсутствуют**: `del_name`/`del_addr`/`del_*_family`
   удаляют один shape-ключ; по сокету C тоже шлёт форму, но внутренние вызовы C шире.
8. **Управляющий слой:** нет `listen_fd`/`peer_fd` и счётчика `sent`; disconnect-hook
   реализован в цикле; ~~`SET_HTTPS` отвергает TTL > 6 часов~~ (**закрыто 2026-11-12:**
   обрезка до 7 суток, кодировщик принимает любой `u32`); ARM_SHAPE не обслуживает UDP;
   v22 CLIENT_TCP идёт с пустыми TCP-опциями.
9. **raw:** один сокет на семейство, обязательный mark, нет `IP_NODEFRAG` и ленивого
   fragment/IPv6-сокета; реальная отправка в тестах не выполнялась (нужен root).
10. **routemark:** нет `describe`, нет `found/truncated` статуса merge и признака изменения
    набора правил; `EAFNOSUPPORT` для IPv4-дампа правил трактуется как ошибка.

## 11. Ограничения аудита

- Проверка статическая: тела функций C прочитаны полностью, Rust-функции сопоставлены по
  коду и вызовам. Differential-прогоны C↔Rust в рамках этого аудита не запускались;
  цитируемые тесты — существующие тесты дерева R2O, а не новые.
- Поведение на живом роутере (raw send, rtnetlink на конкретном ядре, NFQUEUE, MTU
  маршрута) не проверялось: оборудование и root-доступ не предоставлялись.
- `E` означает «эквивалент подтверждён существующим тестом/фикстурой», а не «проверено в
  production». Пункты с оговорками в колонке «доказательство/пробел» остаются `P`.

