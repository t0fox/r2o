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
| E | 99 |
| P | 80 |
| N | 4 |
| ? | 0 |
| **Всего** | **183** |

По файлам:

| Файл | Функций | E | P | N | ? |
|---|---:|---:|---:|---:|---:|
| datapath/plans.c | 75 | 38 | 37 | 0 | 0 |
| datapath/routemark.c | 23 | 15 | 7 | 1 | 0 |
| datapath/plan_parse.c | 17 | 14 | 3 | 0 | 0 |
| datapath/raw.c | 17 | 8 | 9 | 0 | 0 |
| datapath/plan_apply.c | 15 | 8 | 7 | 0 | 0 |
| datapath/ctl.c | 14 | 6 | 5 | 3 | 0 |
| datapath/ctlsrv.c | 12 | 7 | 5 | 0 | 0 |
| datapath/routemark_nl.c | 8 | 3 | 5 | 0 | 0 |
| datapath/include/d2k_plans.h | 2 | 0 | 2 | 0 | 0 |

---

## datapath/ctl.c (14 функций)

Транспорт управляющего сокета: открытие, один пир, кольцо исходящих кадров, разбор кадров.
R2O-аналог — `crates/r2o-datapath/src/control.rs` (`ControlServer`), плюс цикл в
`crates/r2o-datapath/src/main.rs` (вызывает `poll()` напрямую, без epoll-регистрации fd).

**Прочитано построчно: 14/14 функций, 316 строк C (1–316).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| say | 66-74 | 9 | static: форматирование текста ошибки (владелец — `d2k_ctl_open`) | `control.rs:1798` `ControlServer::open` — текст через `io::Error::new`/`format!` | P | C `if (!err \|\| cap == 0) return;`; `va_start`/`vsnprintf(err,cap,fmt,ap)`/`va_end`. Rust не имеет буферного форматтера: ошибки возвращаются `io::Error`/`String`; тексты иные, причина отказа сохраняется. |
| set_nonblock | 76-79 | 4 | static: `O_NONBLOCK` на fd | `control.rs:1852` `listener.set_nonblocking(true)`, `:2088` `peer.set_nonblocking(true)` | E | `control_server_accepts_reconnect_pending_after_previous_peer_closes` (control.rs:2343): без nonblocking цикл `accept_peer` завис бы. |
| d2k_ctl_open | 81-127 | 47 | создать AF_UNIX listener, снять старый файл, listen(1) | `control.rs:1798` `open`, `:1807` `open_with_profile` | P | `control_socket_is_private_to_its_owner` (control.rs:2325). Отличия: R2O не удаляет чужой не-сокет и занятый живой сокет, ставит права 0600, backlog по умолчанию. |
| d2k_ctl_close | 129-141 | 13 | закрыть оба fd и снять свой файл сокета | `control.rs:2220` `impl Drop for ControlServer` | E | C `if (!c) return;`; `close(pfd)` при `>=0`; `close(lfd)` при `>=0` и `unlink(c->path)`; `free(c)`. Rust `Drop` закрывает listener/peer и удаляет путь сокета; `control_socket_is_private_to_its_owner` (`control.rs:2325`) проверяет удаление пути и права 0600. |
| d2k_ctl_listen_fd | 143-143 | 1 | вернуть listen fd для внешнего цикла | `control.rs:1883` `poll` | N | C `return c ? c->lfd : -1`. R2O не отдаёт listen fd: `main.rs:1388` вызывает `control.poll()`, дескриптор инкапсулирован в `ControlServer`; отдельного getter-а нет. |
| d2k_ctl_peer_fd | 144-144 | 1 | вернуть fd пира | `control.rs:2084` `accept_peer`/`:2210` `disconnect` | N | C `return c ? c->pfd : -1`. В R2O пир хранится внутри `ControlServer`; публичного `peer_fd` нет, цикл использует `poll`/`read_peer`. |
| d2k_ctl_set_disconnect_hook | 146-150 | 5 | повесить hook на разрыв | `main.rs:1409-1415` — цикл сам вызывает `name_plans.clear_probes()` при `!is_connected()` | P | Hook в объекте отсутствует; эквивалент распределён по циклу. Тест `clearing_disconnected_http_probes_keeps_the_permanent_plan` (control.rs:3703) проверяет очистку. |
| d2k_ctl_accept | 152-177 | 26 | принять одного пира, второго отвергнуть | `control.rs:2084` `accept_peer` | E | **Ветви C:** `!c \|\| lfd<0` → return; `accept(lfd)`; `fd<0` → return; если `pfd>=0` — `close(fd)` и return (второй контроллер отвергнут); `set_nonblock(fd)<0` → close/return; иначе `pfd=fd`, `out_head=out_used=0`, `in_len=0`; greet зовёт вызывающий. Rust `accept_peer`: accept, закрывает второго при живом пире, ставит nonblocking, сбрасывает буферы; `control_server_accepts_reconnect_pending_after_previous_peer_closes` (`control.rs:2343`). |
| drop_peer | 179-188 | 10 | закрыть пир, очистить буферы, позвать hook | `control.rs:2210` `disconnect` | E | C `connected=(pfd>=0)`; закрыть `pfd`, `pfd=-1`; `out_head=out_used=0`; `in_len=0`; если был connected — `disconnect_hook(ctx)`. Rust `disconnect` сбрасывает пир/буферы и состояние; `clear_probes` вызывает цикл `main.rs:1409-1415`. Тест reconnect (`control.rs:2343`) проверяет разрыв и нового пира. |
| d2k_ctl_flush | 190-215 | 26 | дослать кольцо, EAGAIN — на следующий раз | `control.rs:2176` `flush` | E | **Ветви C:** `!c \|\| pfd<0 \|\| out_used==0` → return; `tail=(out_head+RING-out_used)%RING`; `run=min(RING-tail,out_used)`; `write`; `n>0` — уменьшить и продолжить; `EINTR` — повторить; `EAGAIN/EWOULDBLOCK` — return; иначе `drop_peer` и return. Rust `flush` так же досылает непрерывный кусок, EAGAIN оставляет на следующий вызов, ошибка рвёт соединение; тест `control_server_sends_a_tls_hello_event...` (`control.rs:2460`). |
| d2k_ctl_event | 217-255 | 39 | положить кадр целиком или потерять и посчитать | `control.rs:1913` `send_event`, `:2164` `enqueue` | **P** | **Подтверждённое отличие размера:** C `D2K_CTL_OUT_RING=65536` (`ctl.c:21`), R2O `MAX_CONTROL_OUTPUT=128*1024` (`control.rs:28`). Оба кладут кадр целиком, при нехватке — `dropped++`/`dropped_events`; C дополнительно `sent++`, в R2O счётчика `sent` нет. `len>FRAME_MAX-2` → drop. Тесты `control.rs:2434`, `:2552-2583`. |
| d2k_ctl_poll | 257-313 | 57 | прочитать, разобрать кадры, рвать на невозможной длине | `control.rs:1883` `poll`, `:2110` `read_peer`, `:2138` `take_complete_frames` | **P** | C делает один `read` до EAGAIN и разбирает всё, что пришло; R2O `read_peer` читает блоками 8192 в цикле до EAGAIN, но не более `MAX_COMMANDS_PER_POLL=256` кадров (`control.rs:29,2114,2141`). Проверка длины `2..=FRAME_MAX`, разрыв на неверной длине/переполнении входа (`FRAME_MAX+4`) и удаление обработанного префикса совпадают. Reconnect-тест читает `EVENT_PROTOCOL`; границы `FRAME_MAX` — `take_complete_frames`. |
| d2k_ctl_dropped | 315-315 | 1 | счётчик потерянных кадров | `control.rs:1983` `dropped_events` | E | C `return c ? c->dropped : 0`; Rust `dropped_events` считает те же потери при отсутствии пира/нехватке места; `control_server_counts_each_event_without_connected_peer...` (`control.rs:2434`). |
| d2k_ctl_sent | 316-316 | 1 | счётчик поставленных в кольцо кадров | нет | N | C `return c ? c->sent : 0`; `sent++` только после успешной записи кадра в кольцо (`ctl.c:253`). В R2O отдельного `sent` нет: есть `dropped_events` и состояние peer, поэтому число принятых к отправке кадров не наблюдается. |

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
| ack | 84-110 | 27 | static: подтверждение команды с trial/area/binding | `control.rs:1899` `send_ack`; `r2k-core/control.rs:1986` `encode_ack_with_identifiers_profile` | E | **Ветви C:** body = key(38)+4+16+28; `memset`; `body[0]=4`; на offset 38 — `type` BE2, `ok` (1/0), `reason` (OK или код); `ok_cmds++`/`bad_cmds++`; если контроллер подключён: `len=42`, для `SET_SUFFIX..DEL_BYPASS`, `SET_NAME_PROBE`, `SET_NAME_BOUND` дописываются 16 байт `area_id`; для `SET_NAME_BOUND` — ещё 28 байт binding; событие ACK. Rust `send_ack` кодирует `encode_ack_with_identifiers_profile` с `trial_id`/`area_id`/`binding_context`; функция проверяет допустимость trial/area/binding по команде (bound требует оба). Тесты `v22_control_server_greets_...` (control.rs:2494), ACK-фикстуры tests/control.rs:47. |
| ack_trial | 112-123 | 12 | static: ACK с trial ID (в т.ч. на отказ) | `control.rs:1898` (поле `Ack::trial_id`), `r2k-core/control.rs:1945` `encode_ack_for_trial` | E | `http_probe_plan_matches_only_its_source_port_and_acknowledges_trial_id` (control.rs:3489) и `encodes_http_probe_command_and_round_trips_its_correlated_ack` (tests/control.rs:493). |
| d2k_ctlsrv_greet | 125-145 | 21 | первое событие: версия провода, maxlen, release | `control.rs:2093` `encode_greeting_profile` при accept | E | `v22_control_server_greets_...` (control.rs:2494) и `control_server_accepts_reconnect_...` (control.rs:2343) читают `EVENT_PROTOCOL`. |
| d2k_ctlsrv_peer_closed | 147-150 | 4 | снять пробные планы при отключении контроллера | `main.rs:1415` `name_plans.clear_probes()`; `control.rs:600` `clear_probes` | E | C `cx && cx->sess` → `d2k_plantab_clear_probes(session plans)`: снимает name-записи с `only_sport` **или** `qdeny`, затем все `probes[]` (QUIC/VOICE). Rust `clear_probes` теперь так же удаляет из `plans` записи с `plan.quic_deny()`, очищает `probes`/`voice_addr_probes`/`addr_probes` и увеличивает revision; постоянные планы остаются. Тесты `clearing_disconnected_http_probes_keeps_the_permanent_plan` (control.rs:3703) и `clearing_probes_removes_quic_deny_name_plans_like_d2o`. |
| canonical_address | 152-157 | 6 | static: family 4 требует нулевой хвост 16-байтного адреса | `control.rs:1613-1627` `addr_plan_key` | E | C: family 6 → 1 без проверки хвоста; family !=4 → 0; family 4 требует `ip[4..16]==0` (младшие 4 байта — адрес). Rust `addr_plan_key`: тело ровно 18; `body[0]==4` требует `body[5..17]` нулевыми и берёт `body[1..5]`; `body[0]==6` берёт 16 байт; иначе `None`. Тест `удаление_адреса_разделяет_формы_и_удаляет_одну` (control.rs:2793): `body[5]=1` даёт `ACK_BAD_ARGS`. |
| addr_shape_valid | 163-167 | 5 | допустимые формы адресной привязки (1,2,3,5,6) | `control.rs:1629-1634` `valid_addr_shape`, `:1636-1643` `addr_plan_matches_shape` | E | C принимает ровно `MODERN(1)`, `LEGACY(2)`, `QUIC(3)`, `VOICE(5)`, `ECH_TCP(6)`; 0/4/7 → 0. Rust `valid_addr_shape` — те же пять значений; `addr_plan_matches_shape` дополнительно требует TCP+TLS для 1/2/6, `valid_quic_plan` для 3, UDP+VOICE для 5. Тест `set_addr_accepts_measured_shapes_and_rejects_unmeasured`: ECH_TCP(6) принимается, 0/4/7 дают `ACK_BAD_ARGS` до разбора плана; формы 1/2/3/5 покрыты адресными/QUIC/voice-тестами. |
| read_probe_flow | 169-187 | 19 | static: разобрать flow адресного опыта, отвергнуть неканонический IPv4 | `control.rs:1695` `r2o_udp_addr_probe_flow_key` + `r2k-core/control.rs:1703` `valid_udp_addr_probe_flow` | **P** | **Ветви сверены:** C `b[0]!=4 && b[0]!=6` → -1; family 6 — копия 16+16 байт; family 4 — байты `b[5..17]` и `b[21..33]` обязаны быть нулевыми, копируются `b[1..5]`/`b[17..21]`; `src_port=b[33..35]`, `dst_port=b[35..37]`, `transport=b[37]`; **порты, адреса и transport не проверяются**. Rust `r2o_udp_addr_probe_flow_key` строит ключ из `SocketAddr` с `proto=17`; `valid_udp_addr_probe_flow` требует family 4/6, `flow[37]==17`, **оба порта ≠0**, старшие 12 байт IPv4 нулевые и младшие 4 ≠0 для обоих адресов (IPv6 — любой ненулевой блок). **Расхождения:** C принимает transport≠17 и нулевые порты/адреса; R2O отвергает. Голос C проводит через эту же команду при `src_port=0` (`ctlsrv.c:302-304`); R2O generic `set_addr_probe` теперь принимает этот wildcard с VOICE-планом и хранит в `voice_addr_probes`, DEL снимает; тест `generic_addr_probe_accepts_voice_wildcard_like_d2o`. Отдельная `SET_VOICE_ADDR_PROBE 0x0095` остаётся для R2O-контроллера. |
| d2k_ctlsrv_command | 189-509 | 321 | диспетчер команд, разбор тел, ACK, установка в таблицу | `control.rs:260` `NamePlans::handle`; `main.rs:68` `handle_control_command` (stall budgets); `control.rs:1988` `arm_client_shape` | **P** | Покрыты SET_NAME/BOUND/PROBE/ADDR/SUFFIX/BYPASS/DEL_*/HTTPS/ARM_SHAPE/STALL_BUDGETS (control.rs:2633-3896). **Подтверждённые расхождения:** (1) ~~`SET_HTTPS` TTL~~ — **закрыто 2026-11-12**: R2O обрезает TTL до **7 суток** (`MAX_HTTPS_TTL_SECONDS`), а кодировщик принимает любой `u32`; (2) ~~`ARM_SHAPE` transport 17~~ — **закрыто 2026-11-12**: R2O принимает 6/17, кэширует QSN-снимок и отдаёт `EVENT_LEGACY_SHAPE` (v22)/`EVENT_HELLO` (v48); пустое имя — wildcard; (3) ~~`SET_ADDR_PROBE` voice wildcard~~ — **закрыто 2026-11-12**: generic-команда с `src_port=0` и VOICE-планом принимается и хранится в `voice_addr_probes`; отдельная 0x0095 остаётся для R2O-контроллера; (4) ~~`DEL_NAME_PROBE` shape~~ — **закрыто 2026-11-12**: C не проверяет shape (`ctlsrv.c:422-437`), R2O теперь тоже (family/port проверяются); (5) адресные опыты не тестированы; (6) `SET_NAME`/`SET_SUFFIX`: C не проверяет `shape` (передаёт `b[1+len]` в plantab), Rust `encode_set_name`/`encode_set_suffix` отвергает неизвестные формы; (7) `DEL_NAME`: C принимает любую пару `transport` (6/17) + `shape != ANY`, Rust `encode_delete_name` — только 6 с 1/2/4/6/7/8..13 или 17 с 3/5. C `DEL_NAME_BOUND`/`DEL_ADDR_PROBE` идемпотентны и всегда ACK OK — R2O так же. ARM_SHAPE: C `ctlsrv.c:335-344` проверяет `len==3+b[0]`, transport 6/17, family 4/6; при готовом слоте шлёт `EV_CLIENT_TCP` (transport 6) с TCP-опциями и `EV_SHAPE` (`:345-375`), затем ACK OK. R2O `arm_client_shape` теперь принимает 6/17: TCP — `EVENT_CLIENT_SHAPE`, QUIC — QSN-снимок (`EVENT_LEGACY_SHAPE` в v22, `EVENT_HELLO` в v48), пустое имя — wildcard; тест `arm_shape_serves_quic_snapshot_and_empty_name_is_wildcard`. SET_ADDR_PROBE: C `ctlsrv.c:285-309` требует `fixed=KEY_LEN+16+4`, transport 17, `dst_port!=0`, lease 1..MAX, trial≠0; `src_port=0` допустим как голосовой wildcard (`:302-303`). Rust generic `set_addr_probe` теперь принимает `src_port=0` с VOICE-планом (family 4) и кладёт запись в `voice_addr_probes`; generic DEL снимает её при совпадении trial. Точный (ненулевой) voice-порт generic-командой пока не принимается; тест `generic_addr_probe_accepts_voice_wildcard_like_d2o`. DEL_NAME_PROBE: C `ctlsrv.c:422-438` проверяет только `len==5+b[0]`, family 4/6 и `probe_port!=0`; shape (`b[1+b[0]]`) передаётся в `d2k_plantab_del_name_probe_family` без проверки. Rust `encode_delete_name_probe` теперь тоже не проверяет shape (family 4/6 и `source_port!=0` остаются) — поведение совпадает с C. SET_NAME/SET_SUFFIX: C `ctlsrv.c:208-261` проверяет только `len>=hdr` и family 4/6; shape (`b[1+len]`) передаётся в plantab без проверки. Rust `encode_set_name` (`control.rs:1360-1391`) допускает только {MODERN,LEGACY,QUIC,GRANDFATHER,VOICE,ECH_TCP,HTTP}+TCP-context, `encode_set_suffix` (`:1480-1504`) — {MODERN,LEGACY,QUIC,ECH_TCP}+TCP-context и совместимый план; неизвестная форма отвергается там, где C принял бы. SET_NAME_PROBE: C `:217-261` `hdr=5+b[0]`, family 4/6, shape без проверки; Rust `encode_set_name_probe` (`:1827-1854`) требует совместимый план, family 4/6 и `source_port!=0`. DEL_NAME: C `:407-421` принимает любую форму кроме ANY для transport 6/17; Rust `encode_delete_name` (`:1856-1879`) — только 6 с {MODERN,LEGACY,GRANDFATHER,ECH_TCP,HTTP}+context или 17 с {VOICE,QUIC}. |
| d2k_ctlsrv_pump | 511-694 | 184 | выгрузить новые записи журнала в события с раскладкой по типам | `main.rs:2728` `send_journal_updates`, `:2709` `send_journal_snapshot`; `flow_journal.rs:202` `to_event_frame`; `r2k-core/control.rs:1204` `translate_event_to_v22` | **P** | **Ветви C сверены:** `added<=*seen` → выход; `from = fresh>=have ? 0 : have-fresh`; `HELLO_SNI/HELLO_NONAME→EV_HELLO` (name_len+name); `SUSPECT→EV_SUSPECT` (code,d_ttl,d_ref_ttl,d_tos,d_ipid BE2,d_planned,d_client_shape,num clamp u16 BE); `PLAN_APPLIED` — `continue`, не отдаётся; `PLAN_DONE→EV_APPLIED` (plan_id16+trial_id16); `REFUSED/DAMAGED/UNSENT→EV_REFUSED` (code+plan_id+trial_id); `SHAPE` — для `key.proto==6` сначала `EV_CLIENT_TCP` с TCP-опциями из `shape_tcp_options_family`, затем `EV_SHAPE` с hello из `shape_family` по `key.proto`/family; `EXCHANGE→EV_EXCHANGE` (code,d_tos,num 4 BE,d_server_hello,d_planned); default skip; для APPLIED/REFUSED добавляются client_shape (только REFUSED), execution_id 8 BE и binding 28. **Rust:** `send_journal_updates` шлёт каждую запись как `EVENT_R2O_JOURNAL_ENTRY` (`flow_journal.rs:202-262`: version, kind id, at_ns, execution_id, key, code, name_len, name[32], num u32, ttl/ref_ttl/tos, server_hello, planned, client_shape, client_is_low, elapsed_ms, ip_id, mapped_ip/port, plan_id, trial_id, binding+28); dedicated `EVENT_HELLO/APPLIED/REFUSED/CLIENT_SHAPE` идут отдельными путями (`main.rs:3093,3715,3737`). Legacy v22 собирает `translate_event_to_v22`: `CLIENT_SHAPE→LEGACY_CLIENT_TCP` (опции **пустые**)+`LEGACY_SHAPE`; `R2O_TCP_EARLY_RST/RST_CUT` несут ttl/ref_ttl/tos/ip_id, а `REPEAT/SILENT/RST_AFTER_APP/FIN_RETRY/STALL` передают в legacy-suspect нули; `R2O_TCP_EXCHANGE→LEGACY_EXCHANGE` с полями. **Расхождения:** (1) C не отдаёт `PLAN_APPLIED`, R2O шлёт его как journal entry (контроллер только печатает); (2) v22 `LEGACY_CLIENT_TCP` без TCP-опций, C — реальные; (3) часть legacy-suspect теряет d_ttl/d_ref_ttl/d_tos/d_ipid; (4) C-события строятся из журнала при каждом pump, R2O v48 — из того же журнала, но иным форматом. |
| d2k_ctlsrv_http80_event | 697-731 | 35 | событие HTTP-портала/ответа с измерениями | `control.rs:3136` `send_http_portal_event`, `:3148` `send_http_response_event`; `r2k-core/control.rs:852` `HttpResponseEvent::event_body` | P | `decodes_r2o_http_response_context_and_measurements` (tests/control.rs:977), `control_decoder_accepts_http_portal_response_events` (tests/capture_shape.rs:150). Отличие: R2O кодирует `code 1..4` и всегда несёт хвост status/body/request_no; C для портала без ответа хвост не шлёт. |

Итог по файлу: E 6, P 6, N 0. Пробелы: точный voice-порт generic `SET_ADDR_PROBE`,
пустые TCP-опции в v22 CLIENT_TCP, адресные опыты без тестов, формат HTTP-события.

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
| anchor_offset | 26-80 | 55 | static: вычислить якорь разреза или отказать | `plan/apply.rs:862` `anchor_offset` | P | **Ветви C:** 0→0; 1 требует `have_sni`, иначе «начало имени: имени нет»; 2 требует `have_sni`, `sni_off+sni_len`; 3→`payload_len/2`; 5 требует `have_sni`, `sni_off+sni_len/2`, зажим `<2→2`, `>=payload_len→payload_len-1`; 4→отказ «конец записи TLS не поддержан»; default→«якорь не известен». Rust те же семь ветвей (`apply.rs:862-906`); для 2/5 `checked_add`, для 5 нижний зажим и `saturating_sub(1)` (при `payload_len=0` C уходит в `SIZE_MAX`, Rust даёт 0; `split_points` в обоих случаях точку отбрасывает). **Покрытие:** `split_owns...` — якорь 1; `interleaved...`/`settle...`/`route_segment...` — якорь 0; `sni_middle_anchor...` — якорь 5 и отсутствие SNI. Ветви 2/3/4/default отдельным тестом не покрыты — поэтому P. |
| cmp_size | 82-85 | 4 | static: qsort-компаратор size_t | `plan/apply.rs:920` `points.sort_unstable()` | E* | C возвращает -1/0/1 строгим сравнением `size_t`; Rust сортирует `Vec<usize>` тем же отношением. `interleaved_fakes...` (tests/apply.rs:53) задаёт разрезы 3 и 6 и проверяет возрастающие куски под `order reverse`; `split_owns...` (:31) — один разрез. Отдельного C/Rust differential нет. |
| split_points | 90-118 | 29 | static: якорь+смещение, сортировка, дедуп, отброс краёв | `plan/apply.rs:908` `split_points` | P | **Ветви C:** цикл `n_splits`; `anchor_offset(...)` ошибка → -1; `long v=base+offset`; `v<=0` или `(size_t)v>=payload_len` → `continue` (разрез вне нагрузки — не отказ); `pts[n++]=(size_t)v`; при `n>1` `qsort(cmp_size)` и дедуп соседних; `*n_out=n`. Rust (`apply.rs:908-923`): `i128`-сложение, тот же отбор `point>0 && point<len`, `try_reserve_exact`, `sort_unstable`, `dedup`. **Покрытие:** `split_owns...` (якорь 1, смещение 0) и `interleaved...` (якоря 0, смещения 3/6) проверяют нарезку/порядок; дедуп одинаковых точек и отброс `v<=0`/`v>=len` отдельным тестом не покрыты — P. |
| tls_ch_layout | 120-154 | 35 | static: разметка ClientHello (rnd/session id), три разных отказа | `plan/apply.rs:970` `tls_client_hello_layout` | P | **Ветви C:** `!b`/`n<44`/`b[0]!=0x16`/`b[1]!=3`/`b[5]!=1` → «не ClientHello или короче 44»; `rec_len=b[3..5]`, `hs_len=b[6..9]`; `rec_len+5!=hs_len+9` → «длины не сходятся»; `n>rec_len+5` → «пришло больше»; `!allow_prefix && (hs_len>n-9 \|\| rec_len>n-5)` → «только начало»; `sl=b[43]`; `sl>32 \|\| sl>n-44` → «session id выходит»; `rnd_off=11,sid_off=44,sid_len=sl`. Rust (`apply.rs:970-1012`) те же проверки и смещения; тексты длиннее, третий отказ назван отдельно. **Покрытие:** успешный путь — `tls_fake_modifiers...`; три отказа и `allow_prefix`/шаблонный профиль отдельными тестами не покрыты — P. |
| random_bytes | 156-163 | 8 | static: 32 случайных байта из `/dev/urandom` | `plan/apply.rs:1019` `secure_random` (`getrandom`) | E* | C `fopen("/dev/urandom","rb")`; `fread(out,1,n)`; `ferror`; `fclose`; успех только `got==n && !bad`. Rust `getrandom::getrandom(output)` с ошибкой `random-source`. `tls_fake_modifiers...` проверяет, что `TLS_MOD_RND` меняет random и session id; отказ источника не тестируется (внешнее состояние ОС). |
| wr16 | 165-167 | 3 | static: записать u16 BE | `plan/apply.rs:1036` `write_u16` | E* | C `b[off]=v>>8; b[off+1]=v`. Rust те же два байта. `tls_fake_modifiers...` с `DUPSID` проверяет перезапись длины записи после вставки session id; дифференциала нет. |
| wr24 | 168-171 | 4 | static: записать u24 BE | `plan/apply.rs:1041` `write_u24` | E* | C `b[off]=v>>16; b[off+1]=v>>8; b[off+2]=v`. Rust те же три байта в `write_u24`; `tls_fake_modifiers_copy_session_id_randomize_and_keep_repeat_bytes_equal` (tests/apply.rs:233) проверяет перезапись длины рукопожатия после вставки session id. Отдельного C/Rust differential нет. |
| fake_tls_bytes | 173-237 | 65 | static: собрать копию приманки с правкой random/SID | `plan/apply.rs:531` `fake_tls_bytes` | P | **Ветви C:** `!in->is_tls13 && wire_profile!=TCP_TEMPLATE` → отказ; `tls_ch_layout` для входа (allow_prefix только у шаблона) и приманки; шаблон: `malloc(pl->len)`, копия; `RND` → 32 байта в `fake_rnd` и `fake_sid_len` в SID; `DUPSID` только при равенстве длин SID; иначе: при `DUPSID` `out_len=pl->len-fake_sid_len+real_sid_len`, границы `>65540/<9/-5>65535/-9>0xffffff`; копия головы/SID/хвоста, `b[fake_sid-1]=real_sid_len`, `wr16(3)`/`wr24(6)`; `RND` → 32 байта в `fake_rnd`. Rust (`apply.rs:531-603`) те же ветви и границы; `checked_sub/checked_add`; `ptr`-арифметика заменена срезами. **Покрытие:** `tls_fake_modifiers...` — нешаблонный профиль, RND+DUPSID при равных SID; шаблонная ветвь, неравные SID и три отказа отдельно не покрыты — P. |
| emit_fake | 239-266 | 28 | static: заполнить `d2k_emit` из приманки и порчи | `plan/apply.rs:486` `emit_fake` | E | **Ветви C:** найти payload, иначе «фальшивка ссылается на нагрузку, которой нет»; `po = poison_id ? find : NULL`; `memset`; kind FAKE; `delay_us`; `seq`; `bytes/len` приманки; при `tls_mod` — `fake_tls_bytes`, `bytes=owned`; при порче — `ttl/flags/seq_shift/ts_up/autottl/autottl_delta/min/max`. Rust (`apply.rs:486-528`) те же шаги; `wire_profile` ставится сразу, C — на `finalize` всем посылкам; autottl вычисляется из `input.reference_ttl` в `poison_ttl` (`apply.rs:764-783`), C хранит поля и пересчитывает при отправке. `no_action...fake_only`, `tls_fake_modifiers...`, `interleaved...` покрывают fake/delay/ttl/poison/порядок. |
| emit_vec_free | 268-272 | 5 | static: освободить массив посылок и owned_bytes | `plan/apply.rs:61` `Emission` (Vec) + `Drop` | E* | C `if(!v) return`; цикл `free(v[i].owned_bytes)`; `free(v)`. Rust владеет байтами через `Vec<u8>` в `Emission`, массив — `Vec<Emission>`; освобождение при `Drop`, отдельных утечек нет по типам. Теста на освобождение нет — свойство выражено типами. |
| emit_overhead | 285-295 | 11 | static: заголовки IP+TCP/UDP, MD5/TS-опция | `plan/apply.rs:737` `emit_overhead` | P* | **Ветви C:** `hdr=20 + (transport==17 ? 8 : 20)`; при `po && transport!=17`: `MD5 → +20`, иначе `TCPTS_BACK → +12`; транспорт 0 считается TCP. Rust (`apply.rs:737-753`) те же константы и порядок `MD5`/`TCPTS_BACK`; `poison.map_or(0,...)` при `Some` всегда даёт флаги. **Покрытие:** `assert_eq!(plan.max_emit(), 171)` проверяет ветвь с порчей; UDP и `TCPTS_BACK` отдельно не проверены — P*. |
| d2k_plan_max_emit | 297-341 | 45 | верхняя оценка одной посылки плана | `plan/apply.rs:418` `Plan::max_emit` | P | **Ветви C:** `!p→0`; для каждой fake: payload, `body=pl->len + (DUPSID?32:0)`, зажим `segment_size`, `emit_overhead(po)+body`; для каждого seqovl: payload, зажим, overhead+body (только приставка); при `udplen`: `body=(proto==2?1200:1)+udplen`, `emit_overhead(NULL)+body`; максимум. Rust (`apply.rs:418-461`) те же три цикла и формула; `segment_body` = `min(segment_size)`; `udplen` — `usize::from`. **Покрытие:** `assert_eq!(plan.max_emit(), 171)` (`tests/apply.rs:251`) проверяет fake+DUPSID+overhead; seqovl и udplen-ветви отдельно не проверены — P. |
| d2k_plan_apply | 343-873 | 531 | превратить план+пакет в посылки, судьбу оригинала и причину отказа | `plan/apply.rs:155` `Plan::apply` | **P** | 17 тестов tests/apply.rs покрывают split/fake/overlay/order/pace/settle/delay/udplen/qsplit/qdeny/oob/metric. **Закрыто 2026-11-12:** OOB и qsplit проходят общий finalize — `wire_profile` ставится всем посылкам, `apply_timing` применяется, нарезка вызывается; тесты `urgent_oob_plan_sends_prefix_urgent_byte_and_suffix` (все три emission с `wire_profile=1`) и `quic_split_applies_delay_us_like_d2o` (`delay_us=25`). **Остаются:** (1) `MAX_EMISSIONS = 26` в Rust (`plan.rs:10`, `apply.rs:9,335,704`); C в `plan_apply.c` не ограничивает число посылок 26 — предел 65536 относится только к числу сегментов (`:830`), а отказ >26 приходит позже из `session.c:2517` (`D2K_RESULT_MAX`). Наблюдаемый отказ сессии совпадает, слой и текст ошибки различаются. (2) `emit_fake` C копирует `ts_up/autottl`-поля, Rust переносит `ts_up` через флаг `POISON_TS_UP`, а autottl вычисляет в `ttl` по `reference_ttl` (`apply.rs:764-781`); для одного и того же `reference_ttl` результат совпадает, при смене TTL между apply и отправкой C пересчитал бы, Rust — нет. |
| d2k_actions_cancel | 891-921 | 31 | правила отмены недосланного исполнения | `plan/apply.rs:104` `Actions::cancel` | E | **Ветви C:** `!out→return`; `memset`; `!a→fate=PASS`; `emitted=min(emitted,a->n)`; скан первых `emitted` на `kind==PAYLOAD`; `partial=emitted<a->n`; `stream_damaged=payload_out && partial`; `fate=payload_out?DROP:PASS`. Rust `sent=min(emitted,len)`; `any(kind==Payload)` по `[..sent]`; `partial`; `fate`; `stream_damaged=payload_out && partial`. Тест `cancellation_drops_only_after_payload_bytes_were_emitted` (tests/apply.rs:303): до нагрузки PASS/partial, после — DROP/damaged. |
| d2k_actions_free | 923-931 | 9 | освободить посылки | `plan/apply.rs:61` `Emission` + `Actions` (RAII) | E* | C `if(!a) return`; цикл `free(a->v[i].owned_bytes)`; `free(a->v)`; `v=NULL`, `n=0`. Rust `Actions` владеет `Vec<Emission>`, каждый `Emission` — `Vec<u8>`; освобождение при `Drop`, повторный вызов невозможен по заимствованию. Отдельного теста нет — свойство типов. |

Итог по файлу: E 14, P 1, N 0. OOB/qsplit проходят общий finalize; остаются место отказа
при >26 посылках (D2O тоже отказывает в session, но позже) и autottl-пересчёт.

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
| rd16 | 23-25 | 3 | static: u16 BE | `plan.rs:892` `read_u16` | E | C `(uint16_t)p[0]<<8 \| p[1]`; границы обеспечивают вызывающие (`scan`/`d2k_plan_load` уже проверили `off+4<=len`). Rust `read_u16` проверяет `offset+2` через `checked_add`/`get` и возвращает «обрезанное поле»; тесты `rejects_bad_header_lengths_records_and_unknown_versions` (обрезки 0/4/11/len-1) и `declared_record_count_is_exact_and_malformed_bytes_never_panic` (фаззинг до 1024 байт). |
| rd32 | 27-30 | 4 | static: u32 BE | `plan.rs:902` `read_u32` | E | C собирает четыре байта старшим вперёд. Rust `read_u32` — `u32::from_be_bytes` с `checked_add`/`get` и ошибкой «обрезанное поле»; те же тесты обрезки и фаззинга, что у `rd16`. |
| fail | 32-36 | 5 | static: записать текст ошибки через `snprintf` | `plan.rs:67` `PlanError::new` | P | C `if (err && errlen) snprintf(err,errlen,"%s",msg)` — молчание при нулевом буфере, обрезание по длине. Rust хранит `String` без предела и возвращает `Result`; тексты отказов почти дословные, но механизм/усечение иные. Тесты проверяют только `is_err()`, не текст. |
| scan | 45-220 | 176 | первый проход: счётчики, проверки типов/длин/minexec | `plan.rs:687` `scan` | E | `rejects_bad_header_lengths_records_and_unknown_versions`, `rejects_dangling_references_and_invalid_operation_combinations` (tests/plan.rs). |
| check_refs | 224-325 | 102 | второй проход: ссылки, сочетания операций, порядок, одиночное перекрытие | `plan.rs:499` `check_references` | E | **Ветви C:** MD5 — `minexec>=12 && transport==6 && wire==detect-tcp`; ipfrag — UDP и без splits/seqovl/order/input/input_tls/settle/segment/wire/guards; udplen — то же плюс без oob; qsplit — то же плюс без udplen/oob; qdeny — UDP и без ipfrag/udplen/qsplit/splits/seqovl/fakes/payloads/poisons/order/input/input_tls/settle/segment/wire/guards/oob/pace/delay; oob — minexec>=8, TCP, proto=1, input_tls, wire, без splits/seqovl/fakes/ipfrag/pace/settle/delay; fake/seqovl — payload_id!=0 и существует, poison_id!=0 и существует; PLACE_BETWEEN требует splits; placement только before/between; order только forward/reverse; seqovl<=1. Rust (`plan.rs:499-673`) те же условия и порядок групп; дополнительно перепроверяет autottl (minexec>=13, min<=max), который C уже проверил в `scan`. Тест `rejects_dangling_references_and_invalid_operation_combinations` покрывает висячую fake, BETWEEN без split, qdeny с payload и UDP+input; остальные сочетания — косвенно. |
| d2k_find_payload | 327-334 | 8 | линейный поиск приманки по id, NULL при отсутствии | `plan.rs` — `self.payloads.iter().find(...)` (`plan.rs:618`, `apply.rs:611,1287`) | E | C цикл `n_payloads`, сравнение `id`, возврат указателя или NULL. Rust `iter().find(\|payload\| payload.id == id)` в `check_references` и `apply_overlay`/`emit_fake`; `parses_payload_fake_and_cross_references` проверяет найденную приманку, `rejects_dangling_references...` — отсутствующую. |
| d2k_find_poison | 336-343 | 8 | линейный поиск порчи по id, NULL при отсутствии | `plan.rs` — `self.poisons.iter().find(...)` (`plan.rs:628`, `apply.rs:624,499`) | E | C цикл `n_poisons`, сравнение `id`, указатель или NULL. Rust `iter().find` в `check_references` и `emit_fake`/`apply_overlay`; `parses_payload_fake_and_cross_references` и `rejects_dangling...` покрывают найденную и отсутствующую порчу. |
| d2k_plan_load | 345-566 | 222 | полная загрузка: заголовок, scan, записи, check_refs, транспорт | `plan.rs:190` `Plan::parse`, `:167` `parse_wire` | **E** | **Ветви C:** `!buf \|\| len<12` → «короче заголовка»; `D2KP`; schema/minexec/flags/declared; `scan`; `seen==declared`; `calloc` плана и массивов по счётчикам; второй проход записей; `REC_AUTOTTL` ищет порчу **среди уже разобранных** (`plan_parse.c:473-486`) — до `POISON` отказ, повтор перезаписывает; `check_refs`; TCP-операции требуют transport 6; массивы освобождаются при ошибках. Rust (`plan.rs:190-325`) те же проверки/порядок; `REC_AUTOTTL` теперь разрешается сразу в цикле: `iter_mut().find(id)`, иначе ошибка «autottl ссылается на неизвестную порчу», повтор `poison.autottl = Some(...)` — последний побеждает. Тест `autottl_requires_preceding_poison_and_last_repeat_wins` (tests/plan.rs): AUTOTTL перед POISON → `Err`, два повтора → delta/min/max последнего. Остальное: 11 тестов tests/plan.rs, legacy `D2KP` через `parse_wire`, magic `R2OP`; C/Rust differential плана целиком нет. |
| d2k_plan_free | 568-581 | 14 | освободить байты приманок, массивы и план | `Drop` (`Vec<Payload>`, `Vec<Poison>`, ...) | E* | C `if(!p) return`; цикл `free(payloads[i].bytes)`; `free` пяти массивов и плана. Rust владеет `Vec<u8>`/`Vec<T>`; освобождение при `Drop`, повторное использование после `Drop` невозможно по заимствованию. Отдельного теста нет — свойство типов; утечек нет. |
| d2k_plan_poison_used | 583-592 | 10 | OR всех флагов порчи; NULL→0 | `plan.rs:327` `poison_used` | E | C `if(!p) return 0`; `used \|= poisons[i].flags`. Rust `fold(0, \|used, poison\| used \| poison.flags)`. Используется в `engine.rs:1861` для `flow_needs`; тест `tls_fake_modifiers...` задаёт флаги и проверяет `emit.poison`, `max_emit` учитывает флаги. |
| d2k_plan_flow_needs | 594-599 | 6 | нужен ли потоку TCPTS: шаблон+TCPTS_BACK | `engine.rs:1860-1869` — прямая проверка `wire_profile==TEMPLATE && poison_used()&TCPTS_BACK` и наличия TS-опции, иначе `FlowUnfit` | P | **Ветви C:** `!p \|\| wire_profile!=TCP_TEMPLATE → 0`; иначе `poison_used & TCPTS_BACK ? D2K_FLOW_NEED_TCPTS : 0`. Rust не имеет отдельной функции: `decide_tcp` проверяет template+флаг, затем `!input.is_http`, наличие TCP-опций и `tcp_timestamp_option_present`; при отсутствии TS — `FlowUnfit`. Rust добавляет условия (HTTP и фактическая опция), которых в чистом предикате C нет; отдельного теста на `FlowUnfit` по отсутствию TS не найдено. |
| d2k_plan_quic_deny | 601-603 | 3 | `p && p->qdeny` | `plan.rs:333` `quic_deny` | E | C возвращает `int` 0/1. Rust `const fn quic_deny(&self)->bool { self.qdeny != 0 }`. Тесты `quic_deny_drops_without_sending_anything` (tests/apply.rs:200) и `rejects_dangling_references_and_invalid_operation_combinations` (qdeny с payload) проверяют обе стороны. |
| d2k_plan_guards | 605-607 | 3 | `p ? p->guards : 0` | `Plan::guards` (`plan.rs:137`), исполнение `engine.rs:1453,1586-1594,2078-2089` | E | C возвращает байт защит. Rust поле `guards: u8`; `scan` принимает только `GUARD_RST_ALIEN` (0x01), `engine.rs` применяет его в четырёх точках. Тесты `rst_alien_guard_profiles_the_reverse_ttl_and_keeps_the_flow_alive` (engine.rs:4519), `rst_alien_guard_журналирует_чужой_сброс_до_ответа_один_раз` (:4794), `rst_alien_guard_после_tls_app_data_не_теряет_сигнал_объёма` (:4914), `rst_alien_guard_does_not_apply_without_a_successful_plan` (:4959), `rst_alien_guard_activates_for_a_valid_no_emission_plan` (:4995). |
| d2k_plan_transport | 609-611 | 3 | `p ? p->transport : 0` | `Plan::transport` (`plan.rs:134`) | E | C геттер. Rust поле; `parses_measured_tcp_context_and_wire_contract` (transport=6), `permits_http_only_with_tcp_and_executor_version_eleven` (TCP/UDP-отказы), `r2k_quic_ttl_probe_requires_exact_bounded_probe_shape` (transport=17 через предикаты). |
| d2k_plan_proto | 613-615 | 3 | `p ? p->proto : 0` | `Plan::proto` (`plan.rs:135`) | E | C геттер. Rust поле; `parses_measured_tcp_context_and_wire_contract` проверяет `proto==1`, `permits_http_only...` — HTTP=4 и отказы, `r2k_quic_ttl_probe...` — QUIC=2. |
| d2k_plan_stream_input | 617-621 | 5 | потоковый вход: TCP + wire detect/template + (input_tls \|\| input_len) | `plan.rs:337` `stream_input` | P | C: `p && transport==6 && (wire==DETECT_TCP \|\| wire==TEMPLATE) && (input_tls \|\| input_len)`; нулевой план → 0. Rust (`plan.rs:337-341`) те же три условия. Положительный путь проверен `parses_measured_tcp_context_and_wire_contract` (`assert!(parsed.stream_input())`); отрицательные ветви (не TCP, чужой wire, без input) отдельным тестом не покрыты — P. |
| d2k_plan_id | 623-630 | 8 | id плана или NULL | `Plan::id` (`plan.rs:133`) | E | C `p ? p->id : NULL`; при отсутствии REC_ID `calloc` уже дал 16 нулей. Rust поле `id: [u8;16]`, при отсутствии записи — нули (`Default`); `parses_minimal_canonical_plan` проверяет `id==[0;16]`, `round_trips_an_applied_http_probe_with_its_exact_binding_identity` (tests/control.rs:724) — перенос id через управляющий кадр. |

Итог по файлу: E 14, P 3, N 0. Пробелы: текст ошибок, `flow_needs` как отдельная
функция, отрицательные ветви `stream_input`.

**Построчная сверка a378:** все 17 функций прочитаны. `scan`/`check_refs` совпадают с
`plan.rs:687-845/499-685` по всем типам записей, длинам, minexec и сочетаниям. Расхождение
`REC_AUTOTTL` **закрыто 2026-11-12**: Rust теперь, как C, требует `AUTOTTL` после своей
`POISON` и при повторе применяет «последний побеждает» (тест
`autottl_requires_preceding_poison_and_last_repeat_wins`). `d2k_plan_load` — E.
`d2k_find_payload`/`d2k_find_poison`/`d2k_plan_poison_used`/`transport`/`proto`/`id`
эквивалентны; `flow_needs` разнесён в `engine.rs`, `stream_input` покрыт косвенно
`has_tls_candidate`.

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
  `set_once_*`; `AUTOTTL` теперь как C — после `POISON`, повтор
  перезаписывает (тест `autottl_requires_preceding_poison_and_last_repeat_wins`).
  Массивы calloc заменены `Vec` с capacity.
- **`d2k_plan_free` (568–581):** RAII; E.
- **`d2k_plan_poison_used`/`quic_deny`/`guards`/`transport`/
  `proto`/`id`:** прямые методы `plan.rs:327/333/134/135/133`,
  E. `flow_needs` — P: логика `wire_profile==TEMPLATE &&
  TCPTS_BACK` размазана по `engine.rs:1860-1869` и не имеет
  отдельной функции/теста. `stream_input` — P: тело тождественно
  `plan.rs:337`, используется `control.rs:614-621`, прямого
  теста предиката нет.

**Итог:** 14 E, 3 P, 0 N. Подтверждённое отличие — legacy-`D2KP`
принимается только через `parse_wire`; `AUTOTTL` закрыт.

## datapath/plans.c (75 функций)

Таблица планов по целям: ключи имя/адрес/суффикс, LRU-вытеснение, точные пробы, поиск на
пакетном пути. R2O-аналог — `NamePlans` в `crates/r2o-datapath/src/control.rs`
(`HashMap`-ключи вместо уплотнённого массива, `Cell<u64>`-часы вместо `last_used_ns`).

**Прочитано построчно: 75/75 функций, 1273 строки C (1–1273).**

**Построчная сверка a378:** все 75 функций прочитаны. Подтверждены: `area_name_valid`
принимает односложные/чисто цифровые имена (Rust `canonical_name` — нет);
`d2k_plantab_shape_misses` в R2O теперь частично (TCP `h.any`/`a.any`; UDP и probe-by-port — P);
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
| d2k_plantab_new | 104-130 | 27 | создать таблицу на cap записей и 16-байтовый epoch | `control.rs:146` `NamePlans::with_capacity` | E | C `cap==0→NULL`; `calloc` таблицы, `v` и `probes` по cap; при нехватке — `free` и NULL; `cap=cap`; epoch из `/dev/urandom`, при коротком чтении/отсутствии — нули. Rust `with_capacity` читает 16 байт тем же способом, `exact_capacity.max(1)`, HashMap-поля пусты. Тест `exact_name_addr_probe_tables_share_lru_capacity` (control.rs:2633) проверяет общую ёмкость. |
| d2k_plantab_free | 132-149 | 18 | освободить планы и массивы | `Drop` (`HashMap`-поля `NamePlans`) | E* | C `!t→return`; цикл по **cap**, а не used, освобождает `v[i].plan` и `probes[i].plan` (свободный хвост занулён, `d2k_plan_free(NULL)` — no-op); отдельно `suffix_used`; `free` probes/v/t. Rust освобождает HashMap-поля при `Drop`; владение типами, утечек нет. |
| name_eq | 154-167 | 14 | static: ASCII case-insensitive, равная длина | `control.rs:2233` `canonical_name` (lowercase) + `String`-равенство | **P** | C понижает A-Z по месту; Rust канонизирует имя при вставке. Эквивалентно для сохранённых имён; теста на план в верхнем регистре и поиск в нижнем нет (HTTPS-тест `EXAMPLE.TEST` — отдельный путь). |
| shape_transport | 169-175 | 7 | static: QUIC→17; MODERN/LEGACY/ECH/контекст 8–13→6; иначе 0 | `control.rs:859-868`, `:955-960`, `:1597-1603` `valid_domain_area_context` | **P** | C-правило размазано по трём `match`; Rust `valid_domain_area_context` даёт TCP для 1/2/6/8–13 и QUIC для 3, VOICE не входит. Отдельного предиката нет. |
| area_name_valid | 177-191 | 15 | static: DNS-суффикс: 1..253, метки 1..63, LDH, без ведущего/хвостового дефиса; **односложное и чисто цифровое допустимы** | `control.rs:2233` `canonical_name`, `domain.rs:8-58` | **P** | **Подтверждённое расхождение:** Rust `canonical_name` требует ≥2 метки и хотя бы один нецифровой символ; C принимает `localhost` и `12345`. `SET_SUFFIX`/`SET_BYPASS` с таким именем C примет, R2O вернёт `ACK_BAD_ARGS`. Тест control.rs:3075 это не покрывает. |
| suffix_member | 193-197 | 5 | static: имя входит в суффикс по границе метки | `control.rs:1605` `domain_suffix_member` | E | `исключение_снимает_suffix_только_для_точного_имени...` (control.rs:3075): `other.googlevideo.com` получает план, `failed...` — нет. |
| area_exact | 199-207 | 9 | static: найти запись площади по (имя, транспорт, форма, family) | ключи `SuffixPlanKey`/`DomainBypassKey` (control.rs:65-78) | E | C линейный проход `used`, сравнение `transport/shape/family` и `name_eq`; первый совпавший. Rust те же четыре поля в ключе HashMap; порядок не важен, дубликат ключа заменяется. Тест control.rs:3075 (установка/поиск/удаление суффикса и обхода). |
| area_set | 209-226 | 18 | static: поставить план суффикса с проверкой формы/транспорта/family | `control.rs:928` `set_suffix` (и `:988` `set_domain_bypass`) | P | Тест control.rs:3075. Отличие: C принимает любой транспорт, равный `shape_transport(shape)`; R2O ограничивает набор форм TCP 1/2/6/8-13 и QUIC 3. |
| d2k_plantab_set_suffix_family | 228-237 | 10 | поставить план изученного суффикса | `control.rs:928` `set_suffix` | P | C: `!t/!p` или транспорт плана не равен `shape_transport(shape)`, либо `shape==HTTP`, либо `proto==HTTP` → `free(p)`/`-2`; иначе `area_set` проверяет имя 1..253, `transport==shape_transport(shape)`, family 4/6. Rust `set_suffix` дополнительно ограничивает shape набором 1/2/3/6/8-13, требует `plan.transport==6 && proto==1` (TCP) или `valid_quic_plan` (QUIC), `r2o_plan_valid`; C такие планы принял бы. Тест control.rs:3075 покрывает штатный суффикс. |
| d2k_plantab_set_bypass_family | 239-244 | 6 | поставить исключение семейства (bypass) | `control.rs:988` `set_domain_bypass` | E | C `!t→-2`; `area_set` с явным transport, плана нет; проверяются имя, `transport==shape_transport(shape)`, family 4/6. Rust `set_domain_bypass` требует `valid_domain_area_context` (TCP 1/2/6/8-13 или QUIC 3, family 4/6) и точную длину тела; ключ `DomainBypassKey`. Тест control.rs:3075: bypass подавляет суффикс, затем снимается. |
| area_del | 246-253 | 8 | static: снять запись площади с уплотнением | `HashMap::remove` в `delete_domain_area` (control.rs:1021-1053) | E | C `!t/!name/!len→0`; `area_exact`; нет → 0; `free(e->plan)`; `*e=v[--used]`; зануление хвоста; `revision++`; 1. Rust удаляет точный `SuffixPlanKey` или `DomainBypassKey`; `revision` не меняется (счётчик ревизии в R2O инкрементируется только в `clear_probes`/`delete_name_bound`). Тест control.rs:3075. |
| d2k_plantab_del_suffix_family | 255-258 | 4 | снять суффикс | `control.rs:1021` `delete_domain_area(body, true)` | E | C `t ? area_del(t,t->suffixes,...) : 0`; ключ — имя/transport/shape/family. Rust `delete_domain_area` разбирает тело, проверяет `valid_domain_area_context`, удаляет `SuffixPlanKey`. Тест control.rs:3075 (DEL_SUFFIX). |
| d2k_plantab_del_bypass_family | 260-263 | 4 | снять исключение | `control.rs:1021` `delete_domain_area(body, false)` | E | C `t ? area_del(t,t->bypasses,...) : 0`. Rust удаляет `DomainBypassKey` после той же проверки контекста. Тест control.rs:3075 (DEL_BYPASS). |
| area_bypassed | 265-273 | 9 | static: имя исключено для (family, shape) | `control.rs:1558` `name_is_bypassed` | E | C цикл `bypass_used`, сравнение `family/shape`, непустого name и `name_eq`; transport не сравнивается. Rust `DomainBypassKey{name,transport,family,shape}` — transport входит в ключ, но для допустимых shape он однозначно следует из shape (`shape_transport`), поэтому наблюдаемый результат тот же. Тест control.rs:3075. |
| area_match | 275-284 | 10 | static: самый длинный подходящий суффикс при точном `(shape, family)` и `suffix_member` | `control.rs:1569-1590` `find_in_domain` (`max_by_key(len)`) | **P** | Логика совпадает: точные `transport/family/shape`, `domain_suffix_member`, максимум по длине суффикса. Тест покрывает один суффикс; выбор самого длинного из нескольких не проверен. |
| d2k_plantab_revision | 286-286 | 1 | ревизия таблицы | `control.rs:586` `revision` | E | C `return t ? t->revision : 0`; `revision++` в `area_set`/`area_del`/`set_name_family`/`set_addr_shaped`/`drop`/`probe_drop`/`set_addr_probe`. Rust поле `revision`, `revision()`; инкремент в `clear_probes`/`delete_name_bound`/`set_name`? Проверяется `conditional_http_delete...` (control.rs:3587) до/после. |
| d2k_plantab_has_ech_target | 288-314 | 27 | есть ли ECH-привязка имени/адреса для трёх ECH-форм, с учётом `only_sport` и BYPASS; затем суффиксы | — | **P** | Прямого предиката нет, но это **не N**: R2O удерживает любой неполный TLS-заголовок (`hold.rs:574-590`, `incomplete_tls_head`) и выставляет ECH-форму по факту `ech_offer` (`engine.rs:1053-1059`). То есть обычный случай «ECH-target → удержание обрывка» покрыт **шире** C. Не воспроизведены C-исключения: `only_sport`, BYPASS для не-точных записей, отдельные `ECH_NO_TS`/`ECH_TS`, суффиксный поиск; адресного differential нет. |
| d2k_plantab_stream_candidate | 316-319 | 4 | префильтр: есть ли потоковый план по имени/адресу | `control.rs:612` `has_tls_candidate(family)` | P | C вызывает `stream_candidate_family(..., family=4)`: имя/адрес/sport/`only_sport`/bypass/`stream_input`. Rust `has_tls_candidate(family)` смотрит только family и `plan.stream_input()` по `plans/suffix_plans/addr_plans`, без имени, адреса и порта. Префильтр R2O шире: может вернуть true для цели без плана. Используется в `main.rs:1699`. |
| d2k_plantab_stream_candidate_family | 321-325 | 5 | то же с family | `control.rs:612` `has_tls_candidate` | P | C передаёт `addr` только для family 4, затем `stream_candidate_target`. Rust — та же family-проверка без имени/адреса/порта; тестов на точность префильтра нет. |
| d2k_plantab_stream_candidate_target | 327-350 | 24 | family, bypass для не-точных, `stream_input`, `only_sport`, имя/адрес/sport, суффиксы transport 6 + stream_input + suffix_member + bypass | `control.rs:612-637` `has_tls_candidate` | **P** | **Расхождения:** Rust проверяет plans family + shape!=HTTP + `stream_input`, suffix transport 6/family/`stream_input`, addr shapes MODERN/LEGACY/ECH; **не проверяет bypass, имя/адрес/sport**. Поэтому `has_tls_candidate` может вернуть true для исключённого имени и не различает пробный порт; C для не-точных записей bypass учитывает. |
| find_name_skip | 357-367 | 11 | static: запись имени без порта; опционально мимо HTTP | `control.rs:1493` `find` по `NamePlanKey{host,family,shape}` | P | C цикл `used`: `kind==NAME`, `family`, `only_sport==0`, `!(skip_http && shape==HTTP)`, `name_eq`; первая подходящая любой формы. Rust `find` требует точный shape; выбор «любая форма»/grandfather разнесён по цепочке `find(shape/bridge/fallback/grandfather)` в `select`, а `find_name_skip` с `skip_http` прямого аналога не имеет. |
| find_name | 369-371 | 3 | static: запись имени без порта | `control.rs:1493` `find` | E | C `find_name_skip(...,0)`: первая не-портовая запись имени любой формы. Rust `find(bytes,family,shape)` ищет точный `(host,family,shape)`; в `select` перед ним перебираются shape/bridge/fallback/grandfather, что покрывает прежний выбор. Тесты TLS/ECH/HTTP (control.rs:2823-3896). |
| find_name_shape_port | 385-395 | 11 | static: запись ровно (имя, форма, порт, family) | `control.rs:1493` `find` + `probes` (`NameProbeKey`) | E | C цикл `used`: `kind==NAME`, `family`, `shape`, `only_sport==sport`, `name_eq`. Rust пробная запись — `NameProbeKey{name:{host,family,shape},source_port}` в `probes`; точное совпадение. Тест `tls_probe_plan_matches_only_its_source_port_and_reports_temporary_applied` (control.rs:3637). |
| find_name_port | 401-412 | 12 | static: портовая запись имени при неизвестной форме | `control.rs:548-571` — поиск probe по `(host,family,shape)` и bridge-shape | E | C `!sport→NULL`; цикл `used`, `kind==NAME`, `family`, `only_sport==sport`, `shape!=HTTP`, `name_eq`; первая. Rust в `select` ищет `NameProbeKey` с точной shape, затем с bridge-shape; для `seen_shape==ANY` отдельной ветки нет (R2O не ставит ANY). Тест control.rs:3637. |
| d2k_plantab_http_candidate | 414-422 | 9 | префильтр HTTP: exact name+family+SHAPE_HTTP+`only_sport==sport`+`proto==HTTP` | `control.rs:647-662` `has_http_candidate(family, source_port)` | E | C: `KEY_NAME`, `family`, `SHAPE_HTTP`, `only_sport==sport`, `proto==HTTP` → 1. Rust `has_http_candidate(family, source_port)`: при `0` — постоянные `plans` с shape HTTP (`only_sport=0`), при ненулевом — `probes` с точным `source_port`; proto HTTP гарантирован `set_name`/`set_name_probe`. `main.rs:1701` передаёт sport только для `controller_probe`, иначе 0 — как `session.c:2821`. Тест `http_candidate_respects_source_port_like_d2o`: постоянный план → `(4,0)` true, `(4,40000)` false; проба → `(4,40000)` true, `(6,40000)` false. |
| d2k_plantab_find_http | 424-431 | 8 | план для HTTP-запроса: проба своего порта, иначе постоянная | `control.rs:495-509` (`select` + `NameProbeKey` для порта 80) | E | C `!t/!name/!len→NULL`; `find_name_shape_port(HTTP,sport,family)`; если нет или `proto!=HTTP` → NULL; иначе `last_used_ns=now`, план. Rust при `request_host_range` и `destination_port==80` сначала ищет `probes` по `(host,family,HTTP,source_port)`, иначе `find(host,family,HTTP)`. Тест `http_probe_plan_matches_only_its_source_port_and_acknowledges_trial_id` (control.rs:3489). |
| find_addr_shape | 439-450 | 12 | static: адресная запись ровно (адрес, family, форма) | `control.rs:1505` `find_addr` | E | C `!addr`/family не 4/6 → NULL; цикл `used`, `kind==ADDR`, `family`, `any_shape \|\| shape`, `memcmp` 4/16 байт. Rust `AddrPlanKey{address,shape}` в `addr_plans`, точный поиск; `find_addr` дополнительно при `shape==ECH_TCP` берёт `MODERN`. Тесты `discord_voice...` (control.rs:3186), `удаление_адреса...` (control.rs:2793). |
| find_addr | 452-454 | 3 | static: любая форма адреса (для снятия/учёта промаха) | `control.rs:1505` `find_addr` (с ECH-fallback) | P | C `find_addr_shape(..., any_shape=1, 0)`: первая запись адреса любой формы. Rust `find_addr(address,shape)` требует точную форму и лишь `ECH_TCP→MODERN`; «любой формы» нет — широкое удаление адреса в R2O заменено точным `delete_addr`. Тесты control.rs:2793/3186 покрывают точные формы. |
| modern_shape_for_ech | 465-469 | 5 | static: ECH-форма → соответствующая MODERN-форма | `control.rs:534-539` `fallback_shape`; `:1509-1517` `find_addr` | P | C: `ECH_NO_TS(10)→MODERN_NO_TS(8)`, `ECH_TS(13)→MODERN_TS(11)`, иначе `MODERN(1)`. Rust `select` строит `fallback_shape` для 6/10/13 и перебирает его для имени/суффикса; `find_addr` делает fallback только для `ECH_TCP(6)→MODERN(1)`, без 10→8/13→11. Тест `tls_план_работает_для_sni_с_ech...` (control.rs:2823) покрывает ECH_TCP. |
| scan_name | 471-486 | 16 | static: один проход — `any`/`shaped`/`modern(ECH)`/`grandfather` по имени, HTTP-запись пропускается | `control.rs:569-581` — цепочка `find(shape/bridge/fallback/grandfather)` + `find_in_domain` | **P** | C за один проход заполняет `h.any` (любая не-HTTP запись), `h.shaped` (точная `seen_shape`), `h.modern` (`modern_shape_for_ech(seen_shape)`) и `h.grandfather`. Rust делает отдельные поиски и **не имеет** ветки `h.any`/`SHAPE_ANY`: запись с формой 0 не будет найдена. R2O-контроллер такие планы не ставит (valid shapes 1/2/3/5/6), но C-путь шире. |
| scan_addr | 488-502 | 15 | static: один проход по адресу — `any`/`shaped`/`modern(ECH)`/`grandfather` | `control.rs:1504-1520` `find_addr`, `:1522-1540` `find_addr_fallback` | **P** | C собирает `any`, `shaped` (если `seen_shape!=ANY`), `modern(ECH)`, `grandfather`. Rust `find_addr` ищет **только** точную форму и ECH→MODERN; grandfather/ANY-ветки нет. `find_addr_fallback` дополнительно проверяет `name_has_transport_binding`/`name_is_bypassed`, чего в C `scan_addr` нет (это в `find_target`). Счётчик `shape_misses` теперь ведётся в `note_tcp_shape_miss` после неудачи TCP-поиска, не в `scan_addr`. |
| oldest | 518-529 | 12 | static: самая старая запись (LRU) | `control.rs:211` `exact_victim` | E | C `used==0→NULL`; `victim=v[0]`; цикл `1..used`, строго `<` по `last_used_ns`; при равенстве побеждает меньший индекс. Rust `exact_victim` перебирает `plans/addr_plans/probes`, выбирает `used < oldest`; при равенстве — первый в порядке итерации HashMap (не детерминирован). Тест `name_plan_table_evicts_lru_and_delete_releases_a_slot` (control.rs:2663). |
| take_free_or_evict | 541-569 | 29 | static: свободный слот или вытеснение LRU с уплотнением | `control.rs:234` `make_room_exact` | E | C `used<cap` → `v[used]`; иначе `oldest`; `free(victim->plan)`; перенос последней записи на место victim; зануление last; `used--`; вернуть last. Rust `make_room_exact`: если `r2o_plan_count()<capacity` → true; иначе удаляет `exact_victim` из соответствующего HashMap; `None→false`. Тест `exact_name_addr_probe_tables_share_lru_capacity` (control.rs:2633). |
| d2k_plantab_set_name_shaped | 571-574 | 4 | поставить план имени с формой | `control.rs:832` `set_name` (shape — часть ключа) | E | C `set_name_probe(...,sport=0)` → `set_name_family(...,family=4)`. Rust `set_name` разбирает тело `SET_NAME`, форма в `NamePlanKey`; `set_name_probe` — отдельная команда с портом. Тесты shape/probe (control.rs:2700-3896). |
| d2k_plantab_set_name_probe | 576-580 | 4 | поставить пробный план имени на один порт | `control.rs:1093` `set_name_probe` | E | C `set_name_family(...,shape,sport,family=4)`; `sport` входит в ключ, для `sport!=0` снимается прежняя проба того же (имя,family,порт,transport). Rust `set_name_probe` требует `trial_id`, `source_port!=0`, `valid_tcp_probe_shape`; `probes.retain` по (host,family,port) без транспорта. Тесты control.rs:3489/3637. |
| probe_transport | 584-588 | 5 | static: транспорт пробы (из плана, иначе по форме) | `control.rs:1129-1130` (`plan.transport`), `:859-868` | P | C: `transport=d2k_plan_transport(p)`; если 0 — `shape==QUIC \|\| shape==VOICE ? 17 : 6`. Rust в `set_name_probe` требует `plan.transport==6`; вывод транспорта из формы без плана не нужен, поскольку проба всегда TCP/proto 1/HTTP. Для C-совместимости функция не перенесена отдельно. |
| d2k_plantab_set_name_family | 590-667 | 78 | основная установка имени: ключ (имя, форма, порт, family), замена пробы того же порта, grandfather-правило | `control.rs:832` `set_name`, `:1092` `set_name_probe` | P | Тесты shape/probe/bound (control.rs:2700-3896). Отличия: C при `sport` снимает прежнюю пробу того же (имя, family, порт, транспорт) — R2O `retain` по (host, family, port) без транспорта; C хранит `SHAPE_ANY` и grandfather в общем массиве — R2O различает их ключом. |
| d2k_plantab_set_name | 672-676 | 5 | legacy: поставить имя как grandfather | `control.rs:832` `set_name` (контроллер шлёт форму явно) | P | C `set_name_shaped(...,GRANDFATHER)`; grandfather не заводит отдельную запись при измеренной форме, а обновляет её. Rust `set_name` принимает shape из команды (1/2/3/5/6/7/8-13), grandfather — отдельный shape 0; правила «grandfather обновляет измеренную» в `set_name` нет. Legacy-входа без формы в R2O нет. |
| d2k_plantab_set_addr | 678-681 | 4 | legacy: адрес как grandfather | `control.rs:891` `set_addr` (форма обязательна) | P | C `set_addr_family(&addr_be,4,GRANDFATHER)`: отдельная запись адреса без формы, подходящая любой. Rust `set_addr` требует `addr_plan_key` (family+shape) и `valid_addr_shape`; grandfather-входа нет — командой сокета он и в C не используется. |
| d2k_plantab_set_addr_family | 686-690 | 5 | legacy: адрес без формы → grandfather | `control.rs:891` `set_addr` | P | C `set_addr_shaped(...,GRANDFATHER)`. Rust `set_addr` принимает только явную форму; `validate_runtime_plan`/`addr_plan_matches_shape` дополнительно проверяют план. Legacy-вход только для C-тестов датапата. |
| d2k_plantab_set_addr_shaped | 692-721 | 30 | адресная привязка ровно (адрес, family, форма); C отвергает только ANY/HTTP и HTTP-протокол плана | `control.rs:891-927` `set_addr` | **P** | **Расхождение на негодном входе:** Rust дополнительно требует `addr_plan_matches_shape` (MODERN/LEGACY/ECH→TCP TLS, QUIC→valid_quic, VOICE→UDP voice) и `r2o_plan_valid`; C такие планы принял бы. Для валидного входа эквивалентно. Тест `удаление_адреса_разделяет_формы...` (control.rs:2793) проверяет **удаление** двух форм, а не приём; отдельного теста set-валидации нет. |
| d2k_plantab_del_name_probe_family | 813-828 | 16 | снять пробную запись по (имя, shape, порт, family); C shape не проверяет | `control.rs:1386-1411` `delete_name_probe` | E | C `!t/!name/!len/!sport→0`; цикл `used`: `KEY_NAME`, `family`, `only_sport==sport`, `shape==shape`, `name_eq` → `drop`; возврат `n>0`; неизвестная shape просто не совпадает, отказа нет. Rust `delete_name_probe` проверяет длину, имя, family 4/6 и `source_port!=0`, **shape больше не проверяет**; удаляет `NameProbeKey` и в любом случае отвечает `ACK_OK`. Тесты `delete_name_probe_accepts_unknown_shape_like_d2o` (datapath) и `delete_name_probe_encodes_any_shape_like_d2o` (encoder). |
| drop | 728-741 | 14 | static: снять запись, сохранив уплотнение | `HashMap::remove` (control.rs:1408,1473,1489) | E | C `!e→0`; `revision++`; `free(e->plan)`; перенос последней записи на место e; зануление last; `used--`; 1. Rust удаляет по точному ключу из `plans`/`addr_plans`/`probes`; `revision` меняется не в каждом remove. Тест `name_plan_table_evicts_lru_and_delete_releases_a_slot` (control.rs:2663). |
| d2k_plantab_del_name | 743-745 | 3 | legacy: снять ВСЕ записи имени (v4) | `control.rs:1390` `delete_name` (одна форма) | P | C `del_name_family(...,4)`; цикл `find_name`+`drop` снимает все не-портовые записи имени любой формы. Rust `delete_name` разбирает transport/shape/family и удаляет **один** `NamePlanKey`; широкого удаления всех форм нет. |
| d2k_plantab_del_name_family | 747-765 | 19 | снять все формы имени в family | `control.rs:1390` `delete_name` | P | C `!t/!name/!len→0`; `for(;;) find_name` (любая форма, `only_sport==0`) + `drop`, счётчик; возврат `n>0`. Rust удаляет один точный ключ `(host,family,shape)` после проверки transport/shape; остальные формы остаются. Тест control.rs:3587 покрывает точное удаление. |
| d2k_plantab_del_name_shaped | 773-790 | 18 | снять постоянную запись (имя, транспорт, форма, family), пробы не трогать | `control.rs:1390` `delete_name` | E | C `!t/!name/!len/ANY/transport not 6/17→0`; цикл `used`, `kind==NAME`, `family`, `only_sport==0`, `shape`, `probe_transport(plan,shape)==transport`, `name_eq`; `drop`+повтор слота. Rust `delete_name` удаляет `NamePlanKey{host,family,shape}` после проверки transport 6/17 и shape. Тест `conditional_http_delete_preserves_replacements_and_removes_only_its_binding` (control.rs:3587). |
| d2k_plantab_del_name_bound | 792-806 | 15 | условное снятие по identity (generation/epoch/kind) | `control.rs:1417` `delete_name_bound` | E | C `!t/!name/!len/!known/kind!=NAME/temporary/transport not 6/17→0`; цикл `used`, не-портовая запись, `name_eq`, `probe_transport==transport`, `binding==expected` → `drop`, 1. Rust проверяет длину/transport/binding (kind<=4, family 0/4/6, shape), `canonical_plan_name`, `binding.is_known/kind==1/!temporary/family 4/6`, затем совпадение `epoch` и `generation`+transport; удаляет ключ. Тест control.rs:3587. |
| d2k_plantab_del_name_probe | 808-811 | 4 | снять пробную запись по порту | `control.rs:1363` `delete_name_probe` | E | C `del_name_probe_family(...,family=4)`. Rust `delete_name_probe` требует name 1.., shape/port/family, `valid_tcp_probe_shape`; удаляет `NameProbeKey`. Тест `http_probe_plan...` (control.rs:3489). |
| d2k_plantab_del_addr | 830-832 | 3 | legacy: снять адрес целиком (все формы) | `control.rs:1480` `delete_addr` (одна форма) | P | C `del_addr_family(&addr_be,4)`; `while(drop(find_addr(...)))` снимает все формы адреса. Rust `delete_addr` требует ровно 18 байт и удаляет один `AddrPlanKey{address,shape}`; широкого удаления нет. |
| d2k_plantab_del_addr_family | 837-842 | 6 | снять все формы адреса | `control.rs:1480` `delete_addr` | P | C `!t→0`; `while(drop(find_addr(addr,family))) n++`; возврат `n>0`. Rust удаляет одну форму; тест control.rs:2793 проверяет раздельное удаление форм. |
| d2k_plantab_del_addr_shaped | 844-848 | 5 | снять ровно форму адреса | `control.rs:1480` `delete_addr` | E | C `!t/ANY→0`; `drop(find_addr_shape(...,0,shape))`. Rust `delete_addr` проверяет family/shape (`valid_addr_shape`), удаляет `AddrPlanKey`. Тест `удаление_адреса_разделяет_формы...` (control.rs:2793). |
| trial_id_valid | 850-855 | 6 | static: trial id не весь нулевой | inline `iter().all(\|b\| *b == 0)` (control.rs:1199,1278,1330) | P | C `!id→0`; OR всех 16 байт, `any!=0`. Rust в `set_voice_addr_probe`/`set_addr_probe`/`delete_addr_probe` проверяет `iter().all(\|byte\| *byte==0)` и отвергает; отдельной функции нет. Тестов на нулевой id не найдено. |
| probe_flow_valid | 860-874 | 15 | static: UDP, dst port≠0, family 0/4/6, ненулевые src/dst; `src_port=0` — голосовой wildcard | `r2k-core/control.rs:1701-1717` `valid_udp_addr_probe_flow`; `control.rs:1341-1438` `set_addr_probe` | **P** | **Расхождение:** C допускает `family=0` (внутренние вызовы) и `src_port=0` (голос); Rust `valid_udp_addr_probe_flow` требует family 4/6 и оба порта ≠0. Generic `set_addr_probe` отдельно принимает `src_port=0` + VOICE-план (family 4) и хранит в `voice_addr_probes`; DEL снимает. C-ветви family 0 и отсутствие проверки адресов/transport всё ещё не воспроизведены. Тест `generic_addr_probe_accepts_voice_wildcard_like_d2o`. |
| probe_flow_equal | 876-887 | 12 | static: равенство flow | ключ `[u8; KEY_LEN]` в `HashMap` (control.rs:88) | E | C сравнивает `(family==6)`-класс, transport, `src_port_be`, `dst_port_be`, 4/16 байт src и dst. Rust ключ `[u8; KEY_LEN]` включает те же поля; равенство — `HashMap::get`. Тесты `r2o_временная_quic_привязка_проверяет_полный_поток_и_поколение` (точный QUIC-ключ) и `generic_addr_probe_accepts_voice_wildcard_like_d2o` (голосовой wildcard, SET/DEL с чужим trial). |
| probe_drop | 889-895 | 7 | static: снять запись опыта | `HashMap::remove`/`retain` (control.rs:607,1224,1292) | E | C `!t/!e/!used→return`; `free(plan)`; `memset`; `probe_used--`; `revision++`. Rust удаляет запись или `retain` по сроку; счётчик `probe_used` заменён вычислением. Тест `clearing_disconnected_http_probes_keeps_the_permanent_plan` (control.rs:3703). |
| d2k_plantab_clear_probes | 897-910 | 14 | снять пробные записи и QUIC-запреты (`qdeny`) | `control.rs:600-621` `clear_probes` | E | C цикл `used`: `kind==NAME && (only_sport \|\| d2k_plan_quic_deny(plan))` → `drop`; затем `probe_drop` всех `probes[]`. Rust `retain` удаляет из `plans` записи с `plan.quic_deny()`, очищает `probes`/`voice_addr_probes`/`addr_probes`, `revision++` при любом удалении. Постоянные name/addr-планы без qdeny сохраняются. Тесты `clearing_disconnected_http_probes...` (control.rs:3703) и `clearing_probes_removes_quic_deny_name_plans_like_d2o` (qdeny удалён, MODERN остался). |
| d2k_plantab_set_addr_probe | 912-961 | 50 | временный план на точный flow с trial id и lease; одна таблица для QUIC/VOICE/ANY, ёмкость `cap` (2048) | `control.rs:1325-1438` `set_addr_probe`, `:1260` `set_voice_addr_probe` | **P** | **Расхождения:** (1) C хранит QUIC и VOICE в одной `probes[]` с `shape` из proto (2/3/ANY) и ёмкостью `cap`; Rust — `addr_probes` (QUIC) и `voice_addr_probes`, обе по **64**. При >64 одновременных опытов C примет, R2O вернёт `NO_ROOM`. (2) ~~C допускает `src_port=0` для голоса; Rust generic-проба — нет~~ — **закрыто 2026-11-12**: generic SET с VOICE и `src_port=0` кладёт в `voice_addr_probes`, DEL снимает; точный voice-порт generic-командой не принимается. Тест `generic_addr_probe_accepts_voice_wildcard_like_d2o`. |
| d2k_plantab_del_addr_probe | 963-976 | 14 | снять ровно (flow, generation) | `control.rs:1460-1530` `delete_addr_probe` | E | C `!t/!flow/!trial→0`; цикл по `cap`, `used`, `probe_flow_equal`, `memcmp(trial_id)` → `probe_drop`, 1. Rust требует `body.len()==KEY_LEN+16`, ненулевой trial и совпадение с trial из кадра; для `src_port=0`, family 4, VOICE удаляет `voice_addr_probes`, иначе точный `addr_probes[key]`. Тесты `r2o_временная_quic_привязка_проверяет_полный_поток_и_поколение` (точный QUIC) и `generic_addr_probe_accepts_voice_wildcard_like_d2o` (wildcard: чужой trial не снимает, верный снимает). C возвращает 1/0, R2O ACK OK идемпотентно; точный voice-порт generic-командой не создаётся. |
| find_probe | 978-1006 | 29 | static: поиск опыта, ленивое истечение, wildcard-порт только для голоса | `control.rs:804` `addr_probe_binding_at_hook`, `:764` `voice_address_binding` | P | C `!t/!flow/!src_port→NULL`; цикл по `cap`; истёкшие `probe_drop`; wildcard `src_port==0` совпадает только при `voice`, с копией flow и `src_port=0`; иначе точное равенство; копирует trial_id. Rust: `addr_probe_binding_at_hook` требует QUIC client direction + authenticated Initial + точный ключ; `voice_address_binding` — IPv4/UDP/без фрагмента, STUN/Discord, wildcard выражен отсутствием клиентского порта в `VoiceProbeKey`. Тесты voice control.rs:3239/3278; адресные — нет. |
| d2k_plantab_find_addr_probe | 1008-1012 | 5 | поиск точного адресного опыта | `control.rs:804-830` `addr_probe_binding_at_hook` | E | C `find_probe(...,voice=0)`: wildcard-записи (src_port=0) не совпадают. Rust `addr_probe_binding_at_hook` ищет `addr_probes` по точному ключу; голосовой wildcard хранится отдельно в `voice_addr_probes` и этим путём не находится. Тест `r2o_временная_quic_привязка_проверяет_полный_поток_и_поколение`; authenticated Initial/клиентское направление — гейт вызывающего QUIC-пути, как в C. |
| d2k_plantab_find_voice_probe | 1014-1018 | 5 | поиск голосового опыта (wildcard клиентского порта) | `control.rs:764` `voice_address_binding` | E | `временная_voice_запись_соответствует_только_с_заданным_и_целым_адресом` (control.rs:3239), `stun_...` (3278). Ключ R2O не содержит клиентского порта — wildcard выражен структурно. |
| d2k_plantab_probe_count | 1020-1022 | 3 | число всех пробных записей (`probe_used`, включая voice) | `control.rs:186-194` `r2o_probe_count` | E | C `t ? t->probe_used : 0`: `probe_used` растёт в `set_addr_probe` и падает в `probe_drop`; истёкшие удаляются лениво (`find_probe`/`set_addr_probe`), поэтому счётчик включает и их. Rust `r2o_probe_count = addr_probes.len()+voice_addr_probes.len()` — обе карты, без фильтра по времени; `clear_probes` обнуляет. Тест `probe_count_counts_addr_and_voice_probes_like_d2o`: 1 addr + 1 voice → 2, после `clear_probes` → 0. |
| shape_fits | 1044-1052 | 9 | static: grandfather→1; MODERN↔ECH_TCP, MODERN_NO_TS↔ECH_NO_TS, MODERN_TS↔ECH_TS; иначе `entry_shape!=0 && equal` | `control.rs:569-581` — цепочка exact/bridge/fallback/grandfather | **P** | C-предикат расщеплён на цепочку поисков; ECH-перенос и grandfather покрыты тестами (control.rs:2823). В C `entry_shape==0` (ANY) не проходит `shape_fits` — ANY используется отдельной ветвью `h.any`; в R2O отдельного предиката и ANY-ветки нет. |
| shape_is_udp | 1054-1056 | 3 | static: QUIC/VOICE | `matches!(shape, SHAPE_QUIC \| SHAPE_VOICE)` + `find_addr_fallback` (`control.rs:1522-1540`) | **P** | **Одностороннее правило C:** при UDP-наблюдении и TCP-записи имени разрешается адресный fallback (`goto check_addr`, `plans.c:1190-1200`); при TCP-наблюдении и UDP-записи — нет (`shape_misses++`, NULL). Rust `find_addr_fallback` проверяет только наличие привязки **того же** транспорта, поэтому TCP-поток к имени, у которого есть только QUIC/VOICE-план, может получить адресный план, чего C не делает. |
| d2k_plantab_shape_misses | 1058-1060 | 3 | счётчик «нашли, но форма не подошла» | `control.rs:193` `r2o_shape_misses`, `:591-621` `note_tcp_shape_miss` | P | C инкрементирует в трёх ветвях `find_target` (`plans.c:1140,1209,1233`). Rust теперь инкрементирует после неудачи TCP-поиска, если для SNI есть name-запись той же family иной не-HTTP формы либо адресная запись — это покрывает `h.any`/`a.any` TCP-ветвей. UDP-переход `goto check_addr`, probe-by-port и точный порядок C не воспроизведены. Тест `shape_misses_count_known_name_with_wrong_tcp_shape`: план LEGACY + TLS1.3 пакет → select None, счётчик 1. |
| d2k_plantab_find | 1062-1066 | 5 | поиск плана по имени, затем адресу | `control.rs:410` `select` | P | R2O `select` разбирает пакет и сам извлекает SNI/HTTP/QUIC; порядок «имя → суффикс → адрес» сохранён, но набор ветвей другой (см. `find_target`). |
| d2k_plantab_find_sport | 1068-1072 | 5 | поиск с местным портом потока | `control.rs:548-571` (`select`, `tcp.source_port`) | P | C `find_family(...,family=4)` с портом; порт учитывается для проб. Rust `select` передаёт `tcp.source_port` в `NameProbeKey`; отдельного входа с sport нет. |
| d2k_plantab_find_family | 1074-1079 | 6 | поиск с family | `control.rs:419` `select_with_quic_host_at_hook` (`view.family`) | P | C `find_target(..., family==4 ? &addr_be : NULL, family, ...)`; family 6 без адреса. Rust family берётся из `PacketView`; отдельного входа нет. |
| d2k_plantab_find_target | 1081-1236 | 156 | ядро поиска: probe-by-port при пустом имени → точная форма+порт → своя форма → grandfather → суффикс → адрес; счёт промахов | `control.rs:419-600 select_with_quic_host_at_hook`, `:1493-1590 find/find_addr/find_addr_fallback/find_in_domain` | **P** | Тесты TLS/ECH/QUIC/HTTP/voice/probe (control.rs:2823-3896). **Подтверждённые отличия:** (1) `shape_misses` R2O инкрементирует только TCP-случай (name/addr), UDP/probe-by-port — нет; (2) R2O добавляет TCP-контекст 8–13 и bridge-shape (control.rs:529-539); (3) односторонний кросс-транспортный переход C (UDP→addr, TCP→NULL) заменён общим `find_addr_fallback`, который разрешает и TCP→addr; (4) C при пустом имени и `sport_be` ищет **name-probe по порту** (`plans.c:1093-1112`), R2O UDP-путь имеет только `addr_probe_binding_at_hook`, а TCP без SNI уходит в `find_addr`; (5) C имеет `h.any`/ANY и grandfather/ANY в `scan_addr`, R2O `find`/`find_addr` — только exact+ECH→MODERN; (6) ECH→MODERN в `find_addr` **есть** (`control.rs:1509-1517`), поэтому прежнее утверждение об отсутствии ECH-адресного fallback неверно; отсутствуют grandfather/ANY. |
| d2k_plantab_count | 1238-1240 | 3 | число занятых записей | `control.rs:178-189` `r2o_plan_count`/`exact_usage` | E | C `t ? t->used : 0` — только записи `v[]` (имена+адреса); name-пробы лежат там же с `only_sport`, но отдельного `probe_used` не имеют. Rust `r2o_plan_count = plans.len()+addr_plans.len()` — name+addr без name-проб; `exact_usage()` отдельно включает `probes` для общей ёмкости/вытеснения. Тест `plan_count_excludes_name_probes_like_d2o`: одна name-проба → count 0, exact_usage 1; capacity-тест control.rs:2633. |
| d2k_plantab_capacity | 1242-1244 | 3 | ёмкость таблицы | `control.rs:182` `r2o_plan_capacity` | E | C `t ? t->cap : 0`; Rust `exact_capacity` (не менее 1). Тест `name_plan_table_evicts_lru_and_delete_releases_a_slot` (control.rs:2663) сверяет capacity и вытеснение. |
| d2k_plantab_binding | 1246-1257 | 12 | identity установленного плана (generation/kind/family/shape/temporary/epoch) | `control.rs:690` `binding_for_plan`, `:1469-1476` `delete_name_bound` | E | C `!out→0`; зануление; `!t/!p/owner!=t/!generation→0`; нулевой epoch→0; копия generation/kind/family/shape/temporary/epoch; 1. Rust `binding_for_plan` возвращает `PlanBinding` с trial/generation/shape/temporary; epoch — поле `NamePlans`, проверяется в `delete_name_bound`. Тесты `bound_http_set...` (control.rs:2700), APPLIED-фикстуры. |
| d2k_plantab_set_name_trial | 1259-1267 | 9 | поставить пробный план с trial id | `control.rs:1093` `set_name_probe` | E | C `!sport \|\| !trial_id → free/-2`; `set_name_family`; при успехе копирует 16 байт trial в binding. Rust `set_name_probe` требует `trial_id: Some`, `source_port!=0`, `valid_tcp_probe_shape`; сохраняет trial в `ProbePlan`. Тесты control.rs:3489/3637. |
| d2k_plantab_trial | 1268-1273 | 6 | trial id установленного временного плана | `control.rs:690` `binding_for_plan` (`PlanBinding.trial_id`) | E | C зануляет out; при `t && p && owner==t && temporary` копирует `binding_trial_id`. Rust `binding_for_plan` для `probes`/`voice_addr_probes`/`addr_probes` возвращает trial_id и temporary=true, для постоянных — нули/false. Тест `tls_probe_plan...reports_temporary_applied` (control.rs:3637), voice control.rs:3239. |

Итог по файлу: E 38, P 37, N 0, ? 0. Ключевые пробелы: счётчик промахов по форме частичен (TCP);
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
| if_mtu | 64-81 | 18 | static: MTU интерфейса через `SIOCGIFMTU` | `raw.rs:301` `r2o_interface_mtu` (sysfs `/sys/class/net/<if>/mtu`) | P | C `!name \|\| !*name→0`; `socket(AF_INET,SOCK_DGRAM,0)`; нулевой `ifreq`; `snprintf(ifr_name,"%s",name)` (обрезает длинное имя); `ioctl(SIOCGIFMTU)`; успех и `mtu>0` → значение; `close`. Rust читает `mtu` из sysfs, отвергает имена с `/`, `\\`, `.`, `..`, парсит `usize` и фильтрует 0; механизм иной, ioctl-путь не проверен. Теста на реальный интерфейс нет. |
| pick_maxlen | 92-116 | 25 | static: предел по named iface или наименьшему MTU поднятых (без loopback) | `raw.rs:270` `r2o_pick_maxlen` | P | `общий_предел_берёт_наименьший...` (raw.rs:836) тестирует выбор через инъекцию; сам обход sysfs и fallback 1500 против `D2K_RAW_MTU_FALLBACK` не сверены. |
| route_mtu | 140-176 | 37 | static: MTU маршрута к адресу (UDP connect + `IP_MTU`/`IPV6_MTU`) | `raw.rs:484` `r2o_route_mtu` | P | C под `#ifdef IP_MTU`: `socket(family==6?AF_INET6:AF_INET,SOCK_DGRAM,0)`; `SO_MARK` только при `mark!=0`; sockaddr с портом 443 и адресом; `connect`; `getsockopt(IPPROTO_IPV6/IPPROTO_IP, IPV6_MTU/IP_MTU)`; `mtu>0`; `close`; без `IP_MTU` — 0. Rust `r2o_route_mtu` те же шаги, но `SOCK_DGRAM\|SOCK_CLOEXEC`, `IPPROTO_UDP`, `SO_MARK` ставится всегда (в т.ч. 0), `libc::IP_MTU`/`IPV6_MTU`;结果 0 при ошибке connect/getsockopt. Требует root/kernel, теста нет. |
| say | 181-191 | 11 | static: текст ошибки с сохранением errno | `io::Error` + `eprintln!` | P | C `!err \|\| cap==0→return`; сохраняет `errno`, `vsnprintf(err,cap,fmt,ap)`, восстанавливает `errno` (вызывающий читает его после сообщения). Rust возвращает `io::Error`/печатает; errno сохраняется внутри `io::Error`, отдельного буферного форматтера нет, тексты иные. |
| d2k_raw_open | 193-256 | 64 | открыть IPv4 raw, `IP_HDRINCL`, `SO_MARK` при mark≠0, вычислить maxlen; `fd6/fragment_fd=-1` | `raw.rs:48-93 RawSocket::open` | **P** | **Подтверждённые отличия:** C создаёт только IPv4 `fd`, а `fd6`/`fragment_fd` открывает лениво; mark=0 допустим (`if (mark != 0)` `:234`), R2O требует **ненулевой** mark (`raw.rs:55-60`). R2O — один объект на одно семейство (`AF_INET`/`AF_INET6` + `IPPROTO_RAW`, `IP_HDRINCL`/`IPV6_HDRINCL`, `SO_MARK`, `raw.rs:62-92`); C держит IPv4+IPv6+IPv4-fragment+IPv6-fragment в одном `d2k_raw`. Тестов open на живой системе нет. |
| d2k_raw_close | 258-269 | 12 | закрыть fd/фрагментный сокет | `Drop for RawSocket` (`OwnedFd`) | E* | C `!r→return`; `close(fd)` при `>=0`; `close(fragment_fd)` при `>=0`; `d2k_ip6frag_sender_close(&fragments6)`; `close(fd6)` при `>=0`; `free(r)`. Rust `OwnedFd` закрывает дескриптор при `Drop`; отдельный fragment/fd6 в R2O отсутствует, но все владеемые fd освобождаются типами. Утечек нет. |
| d2k_raw_limits | 271-273 | 3 | маска ограничений способа отправки (`CANT_IPID \| CANT_IPSUM`) | нет API; `engine.rs:2091` отвергает `POISON_IPID_ZERO` | P | C `r ? r->limits : (CANT_IPID\|CANT_IPSUM)`; `limits` выставляется в `d2k_raw_open` и не зависит от настроек. Rust отдельной маски нет: `CANT_IPSUM` не выражен (суммы считает wire), `CANT_IPID` заменён проверкой `engine.rs:2091`/`raw.rs:162-167` (нулевой IPv4 ID отвергается). |
| d2k_raw_maxlen | 275-279 | 5 | предел посылки, никогда не 0 | `raw.rs:96` `maxlen` | E | C `(r && r->maxlen) ? r->maxlen : D2K_RAW_MTU_FALLBACK` — ноль означал бы «предел не объявлен» и отключил бы проверку. Rust `maxlen()` возвращает `Cell`, `r2o_pick_maxlen` всегда даёт `>=1` (fallback 1500). Тест `предел_маршрута_учитывает_объявленный_интерфейс...` (raw.rs:820). |
| d2k_raw_adopt_egress | 281-303 | 23 | принять наименьший MTU выходных ifindex (если предел не объявлен) | `raw.rs:106` `r2o_adopt_egress` | E | C очищает `names[0]`; `!r/!oifs/!n/maxlen_declared→-1`; цикл `if_indextoname`+`if_mtu`, дописывает `"name mtu"` в names с обрезкой, пропускает `m<FLOOR`, берёт минимум; `!best→-1`; `best==egress_mtu→0`; иначе `egress_mtu=best`; `best==maxlen→0`; иначе `maxlen=best`, 1. Rust `r2o_adopt_egress`: declared→None; `r2o_select_egress_mtu` (ifindex 0/None и `<FLOOR` пропускаются) → минимум; тот же mtu → None; иначе `maxlen=mtu`, `Some(mtu)`. Тест `общий_предел_берёт_наименьший...` (raw.rs:836). |
| blend | 306-309 | 4 | static: маршрут против общего предела при объявленном iface | `raw.rs:351` `r2o_effective_route_maxlen` | E | C `maxlen_declared ? min(route,cap_all) : route`. Rust `(0,_)→maxlen`, `(route,true)→min(route,maxlen)`, `(route,false)→route`; ветвь route=0 — отсутствие ответа маршрута. Тест `предел_маршрута_учитывает_объявленный_интерфейс_и_запасной_mtu` (raw.rs:820). |
| d2k_raw_route_maxlen | 311-313 | 3 | MTU маршрута для dst[4] | `raw.rs:119` `packet_route_maxlen` | P | C `route_maxlen_family(r,dst,4)`. Rust `packet_route_maxlen(packet)` извлекает family и адрес из пакета (`r2o_packet_route_key`), для IPv4 — те же 4 байта; вход иной (пакет, а не `dst[4]`), IPv6-путь и fallback на общий предел отдельно не сверены. |
| d2k_raw_route_maxlen_family | 315-339 | 25 | кэш из 16 маршрутов, порог 1280/576, запись кольцом | `raw.rs:136` `r2o_route_maxlen`, `:367` `R2oRouteMtuCache` | E | C `cap_all=maxlen`; `!r/!dst/family not 4/6→cap_all`; `alen`; поиск по `ROUTE_CACHE` (mtu!=0, family, memcmp) → `blend`; промах → `route_mtu`; `m<1280/576→cap_all` без записи; иначе `route[next%16]={ip,family,mtu}`, `next++`, `blend`. Rust `r2o_get_or_lookup`: поиск по family+destination; промах → lookup; `<1280/576→0` без записи; при 16 записях `pop_front`; `push_back`; `r2o_effective_route_maxlen`. Тест `кэш_mtu_сохраняет_только_полезные_маршруты...` (raw.rs:786). |
| d2k_raw_prepare | 341-404 | 64 | ленивая подготовка IPv6/fragment-сокета, проверка длин и контекста фрагмента | `raw.rs:559-651 outgoing_packet/ipv4_udp_fragment/ipv6_udp_fragment` | **P** | **Подтверждённые отличия:** C для IPv6 `pkt[6]==44` вызывает `d2k_ip6frag_prepare` (AF_PACKET); иначе лениво открывает `fd6` с `IPV6_HDRINCL`+`SO_MARK` (`:353-372`). Для IPv4-фрагмента требует `pkt[0]==0x45`, `pkt[9]==17`, ненулевой IPID и открывает отдельный `fragment_fd` с `IP_HDRINCL` + **обязательным `IP_NODEFRAG`** (`ENOPROTOOPT`, если опции нет) + `SO_MARK` (`:374-399`). R2O `ipv4_udp_fragment`/`ipv6_udp_fragment` только валидируют фрагмент и шлют через один `RawSocket`; `IP_NODEFRAG` отсутствует, отдельного fragment-сокета и ленивого `fd6` нет. Тест `raw.rs:874 raw_sender_accepts_only_well_formed_ipv4_and_ipv6_udp_fragments`. |
| d2k_raw_send | 406-512 | 107 | `sendto(MSG_DONTWAIT)`, EINTR-повтор, EMSGSIZE → снизить предел | `raw.rs:147` `send_packet`, `:155` `send_packet_inner` | **P** | **Совпадает:** `sendto(MSG_DONTWAIT)` в цикле, повтор только на EINTR (`raw.rs:186-222`), короткая запись — ошибка, EMSGSIZE при длине выше 1280/576 понижает route-кэш и общий предел, busy считается для EAGAIN/EWOULDBLOCK/ENOBUFS (`record_send_outcome`), счётчики sent/errors/busy. **Отличия:** C выбирает отдельный `fragment_fd` для IPv4-фрагментов и `fragments6` для IPv6; Rust шлёт всё через один `RawSocket` своего семейства без `IP_NODEFRAG`; реальная root-отправка в тестах не выполнялась. |
| d2k_raw_sent | 514-516 | 3 | счётчик успешных посылок | `raw.rs:100` `send_stats().sent` | E | C `r ? sent : 0`; `sent++` после полной `sendto`/IPv6-фрагмента. Rust `record_send_outcome` увеличивает `sent` только на `Ok(())`; `send_stats().sent`. Тест `raw_send_stats_count_success_and_busy_errors_like_d2o` (raw.rs:231). |
| d2k_raw_errors | 518-520 | 3 | счётчик ошибок | `raw.rs:100` `send_stats().errors` | E | C `r ? errors : 0`; `errors++` при провале `d2k_raw_prepare`, IPv6-фрагмента, короткой/неудачной `sendto`. Rust `record_send_outcome` увеличивает `errors` для `Err`, если пакет >=20 байт и версия 4/6; prepare-ошибки в `send_packet_inner` возвращаются до `record_send_outcome`, но `outgoing_packet`/ID-проверка тоже дают `Err` и считаются. Тест raw.rs:231. |
| d2k_raw_busy | 522-524 | 3 | счётчик EAGAIN/ENOBUFS | `raw.rs:100` `send_stats().busy` | E | C `r ? busy : 0`; `busy++` при `EAGAIN/EWOULDBLOCK/ENOBUFS` в IPv6-фрагменте и `sendto`. Rust `record_send_outcome` проверяет `raw_os_error()` на те же три кода и увеличивает `busy`; тест raw.rs:231. |

Итог по файлу: E 8, P 9, N 0. Главные отличия: один сокет на семейство, обязательный
mark, нет `IP_NODEFRAG`, нет ленивого открытия, нет маски ограничений.

---

## datapath/routemark.c (23 функции)

Сопоставление fwmark/выходных интерфейсов и политика Keenetic. R2O:
`crates/r2o-datapath/src/r2o_route.rs` (`R2oRouteGate`, `R2oRoutePolicy`, парсеры).

**Прочитано построчно: 23/23 функции, 343 строки C (1–343).** Сверено с `r2o_route.rs:84-243` (`R2oRoutePolicy`, `R2oRouteGate`, `r2o_set_rules/set_default_ifindices/set_policy/mark_is_routed/route_mark`), `:372-395` (`r2o_refresh`), `:679-811` (запросы/парсеры), `:950-954` (`r2o_route_add_ifindex`); аналога текстового `describe` в R2O нет.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| rd16h | 27-27 | 1 | static: u16 host order через `memcpy` | `u16::from_ne_bytes` (`r2o_route.rs:883-887`, `:920-924`) | E | C `uint16_t v; memcpy(&v,p,2); return v;` — netlink передаёт поля в порядке хоста. Rust `u16::from_ne_bytes([..])` в разборе атрибутов/rtnexthop; тот же порядок. Тест `r2o_разбор_правил_учитывает_маску_инверсию_и_завершение_дампа` (r2o_route.rs:1109). |
| rd32h | 28-28 | 1 | static: u32 host order | `u32::from_ne_bytes` (`:735`, `:747`, `:789`, `:928`) | E | C `memcpy` четырёх байт в `uint32_t`. Rust `u32::from_ne_bytes` для fwmark/fwmask, ifindex и rtnexthop. Тесты разбора правил (r2o_route.rs:1109) и маршрута/multipath (:1137). |
| wr16h | 29-29 | 1 | static: записать u16 host order | `to_ne_bytes` (`:683-685`, `:696-698`, `:704-705`) | E | C `memcpy(p,&v,2)`. Rust `(value as u16).to_ne_bytes()` в заголовках запросов, длине/типе RTA_DST. Тест `r2o_запросы_содержат_семейство_последовательность_и_адрес_поиска` (r2o_route.rs:1086). |
| wr32h | 30-30 | 1 | static: записать u32 host order | `to_ne_bytes` (`r2o_route.rs:682`, `:685`, `:696`, `:699`) | E | C `memcpy(p,&v,4)` — netlink-поля в порядке хоста. Rust `to_ne_bytes` для длины сообщения и sequence; тест `r2o_запросы_содержат_семейство_последовательность_и_адрес_поиска` (`:1086`) проверяет длину/seq/адрес. |
| d2k_routemark_init | 32-34 | 3 | `memset` всего состояния, включая `rules_read*`/`policy_on` | `impl Default for R2oRouteGate` (`r2o_route.rs:108-115`) | E | C `if(r) memset(r,0,sizeof *r)` — `n=0`, `rules_read4/6=0`, `oifs_read4/6=0`, `policy_on=0`, `policy_none=0`, mark/mask=0. Rust `Default` даёт `Option::None` для правил/устройств/политики — те же «неизвестно/выключено». Все тесты создают `R2oRouteGate::default()`. |
| d2k_routemark_request | 36-46 | 11 | `RTM_GETRULE`, `NLM_F_REQUEST/DUMP`, seq, family в `fib_rule_hdr[0]` | `r2o_route_rule_request` (`:679-688`) | E | C `len=NLMSG_HDRLEN(16)+FIB_HDR(12)=28`; `!o \|\| cap<len→0`; `memset`; `wr32(len)`, `wr16(type=34)`, `wr16(flags=REQUEST\|DUMP=0x301)`, `wr32(seq)`, `body[0]=family`. Rust те же 28 байт, тип 34, flags 0x301, seq, family; тест `:1086` проверяет длину/тип/flags/seq/family. |
| nl_error | 49-51 | 3 | `body_len>=4` → знаковый errno, иначе 0 | `r2o_kernel_error` (`:863-872`) | **P*** | **Отличие только в коротком теле:** C возвращает 0 и парсер даёт общую ошибку «ответ не разобран»; Rust возвращает `Malformed`. Оба отвергают дамп, но классификация разная; теста на `NLMSG_ERROR` короче 4 байт нет. |
| d2k_routemark_parse | 53-95 | 43 | обход `NEWRULE`: family[0], flags[8..12] invert, FWMARK/FWMASK (alen≥8), mask по умолчанию `0xffffffff` при ненулевой метке, `mask==0` пропуск, DONE→1 | `r2o_route_parse_rules` (`:711-766`) | **P** | **Совпадает:** FWMARK/FWMASK, `mark &= mask`, invert-правила **пропускаются** в обеих реализациях, `mask=0` пропуск, DONE, ошибка на хвосте ≥4. **Подтверждённые отличия:** (1) C принимает **любой** `family` и кладёт его в селектор, Rust — только 2/10, остальные пропускает; (2) C при `*n >= cap` всё равно увеличивает `*n` (переполнение видно вызывающему и обрезается в `merge`), Rust `r2o_dump_rules` при >32 правилах **возвращает ошибку** (`:437-443`); (3) `nl_error` на коротком теле. Тест `:1109`. |
| d2k_routemark_lookup_request | 103-120 | 18 | `RTM_GETROUTE` без dump, `rtmsg.dst_len=al*8`, `RTA_DST` = 192.0.2.1/2001:db8::1 | `r2o_route_lookup_request` (`:691-708`) | E | C `al=family==10?16:4`; `len=16+12+4+al` (36/48); `!o \|\| cap<len \|\| family not 2/10→0`; `memset`; header type 26, flags REQUEST, seq; `rtmsg[0]=family`, `[1]=al*8`; `RTA_DST` len `4+al`, type 1, probe4/probe6. Rust те же длины/поля/адреса; family — enum v4/v6. Тест `:1086` проверяет 36 байт, тип, family, dst_len 32, адрес. |
| add_oif | 122-128 | 7 | static: пропуск 0, дедуп, запись только при `*n < cap`, иначе только счётчик | `r2o_route_add_ifindex` (`:950-954`) | E | C `!oif→return`; `have=min(*n,cap)`; дедуп по первым `have`; `if(*n<cap) oifs[*n]=oif`; `(*n)++` — при переполнении счётчик растёт, запись нет. Rust `if ifindex!=0 && !contains → push`; предел 16 проверяется в `r2o_lookup_default` (`:437-442`) и даёт ошибку. Для штатных ≤16 результат совпадает. Тест `r2o_разбор_маршрута...` (:1137) — дедуп/ноль. |
| route_oifs | 132-152 | 21 | обход `RTA_OIF` (alen≥8) и `RTA_MULTIPATH` (rtnexthop len≥8), ошибка на битой длине | `r2o_route_attributes` (`:876-911`), `r2o_route_parse_multipath` (`:913-948`) | E | C `off=RTMSG(12)`; цикл NLA-заголовка 4; `alen`/`atype&mask`; `alen<4 \|\| alen>remaining→-1`; `RTA_OIF && alen>=8` → `add_oif(rd32(+4))`; `RTA_MULTIPATH` → payload `off+4`, длина `alen-4`, цикл rtnexthop: `nl<8 \|\| nl>remaining→-1`, `add_oif(rd32(+4))`, `h+=align4(nl)`; `off+=align4(alen)`. Rust те же проверки/выравнивание/дедуп; тест `:1137` (OIF+multipath+нулевой hop). |
| d2k_routemark_lookup_parse | 154-173 | 20 | `NEWROUTE`, `rtm_type != RTN_UNICAST` → 2, иначе OIF; хвост ≥4 → -1 | `r2o_route_parse_lookup` (`:774-803`) | E | C `!oifs/!n/!buf→-1`; итератор; `NLMSG_ERROR` → `kerr`, -1; `NEWROUTE` и `body_len>=RTMSG`; `body[7]!=RTN_UNICAST→2`; `route_oifs==0?1:-1`; конец: хвост <4 → 0, иначе -1. Rust `Kernel`/`Malformed`, `NoRoute` для не-Unicast, `Unicast(ifindices)`, `Pending` при отсутствии NEWROUTE; тест `:1137` и ошибки `:1161`. |
| d2k_routemark_watch_relevant | 175-190 | 16 | NEW/DEL RULE → 1; NEW/DEL ROUTE с `rtm_dst_len==0` (или коротким телом) → 1; битый хвост → 1 | `r2o_route_watch_relevant` (`:806-817`) | E | C `!buf→0`; итератор; `NEWRULE/DELRULE→1`; `NEWROUTE/DELROUTE` и (`body_len<RTMSG \|\| body[1]==0`)→1; конец: хвост <4?0:1. Rust `r2o_route_messages` ошибка→true; `any`: rule→true; route и (`body<12 \|\| body[1]==0`)→true; иначе false. Тест `:1189`. |
| d2k_routemark_clear_oifs | 192-199 | 8 | family 2/10: `changed = oifs_read`, `oifs_read=0`, `n=0` | `r2o_set_default_ifindices(family, None)` (`:131-157`) | **P** | Состояние эквивалентно (`None` = «неизвестно», как `read=0/n=0`), но C **возвращает признак изменения**, а Rust-сеттер — нет; вызывающий не может отличить сброс от отсутствия изменений. Теста на маршрут без OIF нет. |
| d2k_routemark_set_oifs | 201-213 | 13 | `ok==0` → без изменений; cap 16; `changed = !read или n!=old или memcmp`; `read=1` | `r2o_set_default_ifindices` (`:131-157`) | **P** | Rust дополнительно дедуплицирует и выбрасывает 0 (после `add_oif` это no-op), состояние `Some(vec)` соответствует `read=1`; **признак `changed` не возвращается**. `r2o_устройства_по_умолчанию...` (`:1053`). |
| d2k_routemark_set | 215-227 | 13 | `rules_read4=read6=1`, cap 32, `changed` по длине и тройкам mark/mask/family, копия | `r2o_set_rules` (`:118-130`) | **P** | Хранение `Option<Vec>` эквивалентно `read+n`, `mark &= mask`; **нет возврата `changed`** и отдельных `rules_read4/6`; Rust фильтрует селекторы чужого семейства. Влияние на удержание/refresh не проверено. |
| d2k_routemark_merge | 229-267 | 39 | успешное семейство заменяет, упавшее — прежние селекторы; `found`, `truncated`, `rules_read` обновляется через `ok` | `r2o_refresh` (`:372-397`) | **P** | Сохранение прежнего набора при ошибке есть (сеттер вызывается только при `Ok`). **Не перенесены:** `st->found`, `st->truncated`, `routes4_ok/routes6_ok`, `changed`; Rust не сообщает, сколько правил найдено и было ли усечение. |
| d2k_routemark_set_policy | 269-275 | 7 | `policy_on=1`, `policy_none`, `policy_mark = mark & mask`, mask | `r2o_set_policy(Some(R2oRoutePolicy))` (`:170-172`), `R2oRoutePolicy::new` (`:88-95`) | **E** | `Some(new(false,0,0))` = `policy_on=1, none=1`; `Some(new(true,..))` = активная политика; `None` = исходное `policy_on=0`. Тест `r2o_политика_отделяет_чужие_потоки...` (`:1008`). |
| policy_match | 277-280 | 4 | `policy_on && !none && have_mark && (mark^policy_mark)&mask==0` | `R2oRoutePolicy::r2o_matches` (`:93-95`) | E | C возвращает `int`. Rust `found && ((mark ^ self.mark) & self.mask)==0`; `policy_on` выражен `Option::Some`, `policy_none` — `found=false`, `have_mark` — `Option<u32>`. Тест `r2o_политика_отделяет_чужие_потоки...` (`:1008`). |
| d2k_routemark_routed | 282-296 | 15 | 0 → 0; OTHER/OUTSIDE → 1; своя политика → 0; неизвестное семейство → 1 (fail closed); совпадение правила → 1 | `r2o_mark_is_routed` (`:175-198`) | E | C `!r \|\| !mark→0`; `mark==OTHER/OUTSIDE→1`; `policy_match(r,1,mark)→0`; family 10/2; `!rules_read→1`; цикл `sel.family==family && xor&mask==0→1`; иначе 0. Rust те же ветви; `rules=None→true`, `any` по правилам. Тест `:979`. |
| d2k_routemark_client | 298-302 | 5 | нет метки/0/probe/own → 0, иначе routed ? mark : 0 | первые ветви `r2o_route_mark` (`:202-220`) | **P** | Логика «клиентской» метки совпадает, но отдельной функции нет: Rust в той же функции дальше применяет outdev-гейт и может вернуть `OTHER_DEV` вместо 0. Тест покрывает политику/свои метки (`:1008`), не границу client/gate. |
| d2k_routemark_gate | 304-325 | 22 | policy_on+outbound: не own и не policy_match → OUTSIDE; client; не outbound/нет outdev → m; неизвестные oifs → 0; outdev не в списке → OTHER_DEV | `r2o_route_mark` (`:201-241`) | E | C `policy_on && outbound`: `own=have_mark && mark && (probe\|own)`; `!own && !policy_match→OUTSIDE`; `m=client`; `m \|\| !r \|\| !outbound \|\| !have_outdev→m`; family; `!oifs_read→0`; цикл oifs, совпал→0; иначе `OTHER_DEV`. Rust `policy.is_some() && outbound`: own/selected; `!own&&!selected→OUTSIDE`; затем клиентская метка; `!outbound→0`; `output_ifindex`/`default_ifindices` None→0; contains→0 иначе OTHER_DEV. Тесты `:1008`, `:1053`. |
| d2k_routemark_describe | 327-343 | 17 | текст `0xmark/0xmask v4, ...` или `нет`, обрезка по cap | — | N | C `!buf \|\| !cap→0`; `buf[0]=0`; `!r \|\| !n` → `snprintf("нет")`; цикл `%s0x%x/0x%x %s` с `", "` и `v6/v4`; возврат `min(w,cap-1)`. В R2O функции/строки описания набора правил нет — только отладочные сообщения `main.rs`; формат и обрезка не перенесены. |

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
| parse_rules | 18-21 | 4 | static: адаптер сигнатуры под `d2k_routemark_parse` | замыкание в `r2o_dump_rules` (`r2o_route.rs:402-420`) | E | C `return d2k_routemark_parse(out,cap,n,buf,len,kerr);` — только приведение сигнатуры. Rust `r2o_dump_rules` передаёт замыкание, вызывающее `r2o_route_parse_rules`; владелец проверен тестом `:1109`. |
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

## 9a. Углублённая сверка 5 бывших N-функций

**Прочитано построчно: 5/5 (`ctl.c:143-144,316`; `plans.c:1058-1060` + инкременты `:1140,:1209,:1233`; `routemark.c:327-343`).** В R2O подтверждено отсутствие отдельных геттеров `listen_fd`/`peer_fd`/`sent` и текстового `describe`; `shape_misses` теперь инкрементируется для TCP-ветвей.

- **`d2k_ctl_listen_fd`/`d2k_ctl_peer_fd` (ctl.c 143–144):** C отдаёт
  наружу listen/peer fd для внешнего poll-цикла. R2O инкапсулирует оба
  дескриптора в `ControlServer` (`control.rs`), а `main.rs:1388` вызывает
  `control.poll()`; отдельного геттера нет. N — API-удобство, не потеря
  функциональности.
- **`d2k_ctl_sent` (ctl.c 316):** C считает кадры, поставленные в кольцо
  отправки. В R2O есть только `dropped_events` (`control.rs:1983`), счётчика
  `sent` нет. N — диагностика.
- **`d2k_plantab_shape_misses` (plans.c 1058–1060):** C-геттер
  `t->shape_misses`, C инкрементирует его в трёх ветвях
  (`plans.c:1140`, `:1209`, `:1233`); используется для
  `quic_shape_miss` (`session.c:1270-1277`). R2O `note_tcp_shape_miss`
  (`control.rs:591-621`) инкрементирует после неудачи TCP-поиска для
  известного имени/адреса; UDP-переход и probe-by-port не
  воспроизведены. P, тест `shape_misses_count_known_name_with_wrong_tcp_shape`.
  Это диагностика, packet-path не меняется.
- **`d2k_routemark_describe` (routemark.c 327–343):** C формирует текст
  `0xmark/0xmask v6|v4, ...` или `нет` для логов. В R2O функции/строки
  описания набора правил нет; маршрутная метка и выбор egress есть в
  `r2o_route.rs`/netlink. N — диагностика.

**Итог:** 4 N — диагностические/API-величины; `shape_misses` закрыт
частично (P, TCP-ветви). Packet-path они не меняют.

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
  (`main.rs:1415`) теперь удаляет и qdeny-планы, и probe-записи; E,
  тесты `clearing_disconnected_http_probes...` и
  `clearing_probes_removes_quic_deny_name_plans_like_d2o`.
- **`canonical_address` (152–157) / `addr_shape_valid` (163–167):**
  IPv4-хвост 16-байтного адреса обязан быть нулевым; формы
  1/2/3/5/6. R2O `addr_plan_key`/`valid_addr_shape` (`control.rs:1612,
  1628`); canonical и shape — E (тест
  `set_addr_accepts_measured_shapes_and_rejects_unmeasured`: 6
  принимается, 0/4/7 отвергаются).
- **`read_probe_flow` (169–187):** разбор 38-байтового flow; **C
  допускает `src_port=0`** (голос «любой клиентский порт»), Rust
  `valid_udp_addr_probe_flow` требует оба порта ≠0 и ненулевые адреса.
  Это подтверждённое расхождение (см. строку).
- **`d2k_ctlsrv_command` (189–509):** 13 команд. Сверены тела, точные
  длины, ACK-коды, идемпотентные DEL. Расхождения: ~~SET_HTTPS 7 суток
  vs 6 часов~~ — **закрыто 2026-11-12** (датапат обрезает до 7 суток,
  кодировщик принимает любой `u32`); ~~ARM_SHAPE 6/17 vs 6~~ —
  **закрыто 2026-11-12** (QSN-снимок, `EV_SHAPE`/`EVENT_HELLO`);
  ~~SET_ADDR_PROBE `src_port=0` vs требование ≠0 + отдельная 0x0095~~ —
  **закрыто 2026-11-12** (generic voice wildcard);
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
  проверяет shape; Rust теперь тоже: неизвестная форма просто не
  совпадает, ACK остаётся OK. E, тесты
  `delete_name_probe_accepts_unknown_shape_like_d2o` и
  `delete_name_probe_encodes_any_shape_like_d2o`.
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
  Rust `clear_probes` (`control.rs:600-621`) теперь делает то же:
  `retain` по `plan.quic_deny()` и очистка трёх probe-карт; E,
  тест `clearing_probes_removes_quic_deny_name_plans_like_d2o`.
- **`d2k_plantab_set_addr_probe` (912–961):** C хранит QUIC и
  VOICE в одной `probes[]`, shape из proto (2→QUIC, 3→VOICE,
  иначе ANY), ёмкость `cap` (2048), `bind_context(...,
  temporary=1)`. Rust — `addr_probes` (только QUIC,
  `valid_quic_plan`) и `voice_addr_probes`, обе по **64**; при
  >64 опытов C примет, R2O вернёт `NO_ROOM`. C допускает
  `src_port=0` для голоса; Rust generic теперь принимает wildcard, точный
  voice-порт — нет. P.
- **`d2k_plantab_del_addr_probe` (963–976):** C точный
  flow+trial; Rust key+trial, generic voice wildcard снимается из
  `voice_addr_probes`. P, тесты QUIC-привязки и
  `generic_addr_probe_accepts_voice_wildcard_like_d2o`.
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
  занятые `probes[]` (QUIC+VOICE), включая лениво истёкшие; Rust
  `r2o_probe_count` теперь складывает `addr_probes` и
  `voice_addr_probes` без фильтра. E, тест
  `probe_count_counts_addr_and_voice_probes_like_d2o`.

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
   обрезка до 7 суток, кодировщик принимает любой `u32`); ~~ARM_SHAPE не обслуживает
   UDP~~ — **закрыто 2026-11-12** (QSN-снимок, `EV_SHAPE`/`EVENT_HELLO`);
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

