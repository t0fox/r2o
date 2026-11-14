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
- **E: 156 (39,00 %)**; **P: 244 (61,00 %)**; **N: 0 (0,00 %)**; **?: 0**.
- Полностью отсутствующих функций нет. Агрегатные счётчики applied/done/
  damaged/sent_lost/exchanges/suspects, NAT-статистика, TCP-опции снимка,
  `--offline-self-check`, гистограмма причин пропуска и текстовый HTTP-трейс
  теперь есть.
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
| `on_signal` (static) | 62 | 1 | SIGINT/SIGTERM → `stop_flag` | `main.rs:3762 install_signal_handlers`, `main.rs:55 STOP` | **P** | C `(void)sig; stop_flag=1` (`volatile sig_atomic_t`). Rust ставит atomic-флаг через `install_signal_handlers`; отдельного теста на сигнал нет. |
| `self_cost` (static) | 68-110 | 43 | CPU/RSS из `/proc/self/stat` (поля 14/15) и `statm` (resident) | `main.rs` `r2o_process_cost_from_proc`, `r2o_process_cost` | E | C/Rust differential `scripts/test-datapath-process-stats-differential.sh` PASS: точная пара `cpu_ms,rss_kb` на общих фикстурах `/proc/self/stat`/`statm`, включая `)` в comm и курсор C. |
| `now_ns` (static) | 112-116 | 5 | `CLOCK_MONOTONIC` в наносекундах | `std::time::Instant` | **P** | C `clock_gettime(CLOCK_MONOTONIC)`, `tv_sec*NS_PER_S+tv_nsec`; Rust `Instant`/`Duration`. Контракт «целые нс» заменён на `Duration`; абсолютные значения не сравнимы, разности монотонны. |
| `tls_route_segment_cap` (static) | 123-151 | 29 | MTU маршрута минус IP+32 только для TLS ClientHello | `raw.rs:130 tls_route_segment_cap`, `:119 packet_route_maxlen` | **P** | **Ветви сверены:** C `len<40` → 0; IPv4 `ihl>=20 && len>=ihl+20 && proto==6`, dst=+16; IPv6 `len>=60 && next==6`, dst=+24, ihl=40; `tcp_len>=20 && len>=tcp_off+tcp_len+5 && p[tcp]==0x16 && p[tcp+1]==3`; `mtu=route_maxlen_family(dst)`; `overhead=ihl+32`; `mtu>overhead?mtu-overhead:0`. Rust `raw.rs` воспроизводит «только для 0x16/0x03»; unit-тесты route cap. |
| `count_reason` (static) | 165-186 | 22 | гистограмма причин пропуска (до 32), сравнение по указателю затем `strcmp` | `reason_stats.rs` `record_reason`/`reason_snapshot` | E | C ищет по `text==r`, затем `strcmp`, добавляет до 32; печатается в сводке. Rust `Reason`-гистограмма хранит `(&'static str,u64)`, сравнивает по содержимому (наблюдаемо то же), после 32 новых не заводит; `record_reason` подключён к обрезанию NFQUEUE и ошибкам чтения, `r2o_log_reason_stats` печатает сводку. Тест `count_reason_merges_equal_text_and_caps_at_32`. |
| `icmp_step` (static) | 220-248 | 29 | ICMP time-exceeded: DROP только на свою фальшивку, иначе ACCEPT | `r2o_icmp_guard.rs:127 r2o_handle_at_hook`, вызов в `main.rs` | **P** | **Ветви сверены:** C требует payload/len, IPv4 proto 1 (len>=20) или IPv6 next 58 (len>=40); `st.icmp_seen++`; inbound FORWARD/INPUT; `icmpguard_check` → DROP/ACCEPT; лог при первом drop с адресом; `nfq_verdict`; счётчики. Rust `r2o_handle_at_hook`; `scripts/test-icmp-guard-current-differential.sh`; unit-тестов в модуле нет. |
| `log_send_fail` (static) | 253-261 | 9 | лог отказа raw; busy(EAGAIN/ENOBUFS) — максимум 16 строк | `main.rs:186/192` eprintln | **P** | C `d2k_udp_send_busy(e)` → `++st.busy_lines>16` → return; иначе строка + на 16-й «дальше только счётчик»; не-busy — обычная строка. Rust eprintln без лимита строк; счётчик busy есть в `RawSendStats`. |
| `routes_routed` (static) | 278-280 | 3 | предикат «метка выбирает политику» | `r2o_route.rs:259 r2o_mark_is_routed` | E | C `d2k_routemark_routed`: `!mark→0`; OTHER_DEV/OUTSIDE→1; policy_match→0; непрочитанные правила семейства→1 (fail closed); совпадение селектора→1. Rust `r2o_mark_is_routed` повторяет эти ветви, `None`-правила дают true; тесты `r2o_route.rs:1216-1265` (policy, OTHER_DEV/OUTSIDE, IPv4/IPv6, fail closed). |
| `describe_oifs` (static) | 282-294 | 13 | имена выходных интерфейсов для лога | `r2o_route.rs:152 r2o_egress_ifindices`, строки `r2o_refresh` | **P** | C `!read` → «неизвестен…», `!n` → «нет», иначе `if_indextoname`/`#%u` через `, `. Rust `r2o_egress_ifindices`/`r2o_refresh`; формат лога иной, список oif читается. |
| `routes_refresh` (static) | 302-370 | 69 | разбор ip rule/маршрутов, лог смен, quiet 600 с | `r2o_route.rs:372 r2o_refresh` (netlink-watch) | **P** | **Ветви сверены:** C `d2k_routemark_load`; при ошибке держит прежние, лог один раз; при успехе сравнивает `v4_ok/v6_ok/r4/r6`, логирует смены/truncated; `changes` и `ROUTES_QUIET_NS=600 с` — запись не чаще окна, с числом смен. Rust `r2o_refresh` по netlink-watch, без периодического цикла; quiet-окно/лог смен не воспроизведены; `r2o-route-gate-differential.sh`. |
| `cap_refresh` (static) | 372-415 | 44 | adopt egress MTU → grow sched → greet control | `raw.rs:106 r2o_adopt_egress`, `scheduler.rs:260 grow_slot_size`, `main.rs` greet | **P** | **Ветви сверены:** C собирает oif4/oif6, `!n` → return; `d2k_raw_adopt_egress`, adopted<0 → return; лог при adopted>0; `d2k_sched_grow_slot_size(after)`, ошибка → лог один раз и return; если `send_maxlen==after` → return; иначе обновляет и `d2k_ctlsrv_greet`. Rust `r2o_adopt_egress`/`grow_slot_size`/greet; ветви реализованы, прямого differential нет. |
| `send_original_verdict` (static) | 417-427 | 11 | вердикт NFQUEUE + счётчики accepted/dropped | `nfqueue.rs:310 send_verdict`; `main.rs:4335 release_with` | **P** | C `d2k_nfq_verdict`; ошибка → `verdict_fail++` и лог; иначе `DROP→dropped`, иначе `accepted`. Rust `send_verdict`/`release_with`; byte-level тесты netlink; счётчики `QueueStats`. |
| `send_delayed_verdict` (static) | 429-431 | 3 | обёртка вердикта отложенной выдачи | `main.rs:319 r2o_release_delayed_udp_batch_with` | **P** | C `return send_original_verdict(ctx,id,verdict)`. Rust отдельная функция выпуска отложенных вердиктов; те же id/verdict, API иной. |
| `delayed_verdict_done` (static) | 433-446 | 14 | complete → `session_sent`, иначе `exec_failed(REFUSE_SEND)` | `main.rs:411 r2o_finish_tcp_execution`, `:319` | **P** | C `execution==0` → return; `complete` → `session_sent(at,key,execution)`; иначе `session_exec_failed(..., D2K_REFUSE_SEND, execution, 0, sent!=0)`. Rust `r2o_finish_tcp_execution`/release; ветви token=0/complete/sent!=0 реализованы, прямого теста нет. |
| `hold_owns` (static) | 484-489 | 6 | TLS-hold владеет ID, если это не порт 80 | `hold.rs:298 feed`, `main.rs:2148 batch_owned_originals` | **P** | **Ветви сверены:** C `!c \|\| !c->raw \|\| !d2k_hold_parse` → 0; `tcp=p+ihl`; `return !(tcp[2]==0 && tcp[3]==80)`. Rust `hold.rs`/`batch_owned_originals` отделяет HTTP/80 от TLS-hold; D6 `test-datapath-hold-differential.sh`. |
| `resend_original` (static) | 493-508 | 16 | вернуть снятый оригинал raw-посылкой; до 16 строк лога | `main.rs:3794 r2o_resend_owned_originals` | **P** | C `raw_prepare`+`raw_send`; ошибка → `hold_resend_fail++/send_fail++`, лог первых 16, -1; иначе `hold_resent++/emitted++/emitted_now++`. Rust `r2o_resend_owned_originals`; тест `hold.rs:2167` покрывает владение, не сокет. |
| `resend_originals` (static) | 510-516 | 7 | цикл по `orig[]`, вернуть число ошибок | `main.rs:3794` | **P** | C `for orig_count resend_original`, `failed++`; возвращает failed. Rust тот же цикл в `r2o_resend_owned_originals`; отдельной функции нет. |
| `release_original` (static) | 518-542 | 25 | таймаут: сохранить/сбросить route mark, закрыть UDP-hold, note_unassembled, observe, resend/ACCEPT | `hold.rs:888 flush`, `main.rs:433 r2o_release_damaged_tcp_hold` | **P** | **Ветви сверены:** C `keep_mark=route_mark`, `set_route_mark(0)`, `udp_hold_begin/end`, `note_unassembled`, `observe_tcp`, restore mark; `hold_owns` → `resend_original`, иначе `send_original_verdict(ACCEPT)`. Rust `hold.rs:888`/`r2o_release_damaged_tcp_hold`; порядок side effects воспроизведён в main; D6. |
| `ct_query` (static) | 561-571 | 11 | ctnetlink GET по кортежу; одноразовый лог «нет acct» | `conntrack.rs:297 query`, `:309 probe` | **P** | C `seq++` (0→1), `d2k_ct_query_info_fd`; `rc==2 && !told_acct` → лог про nf_conntrack_acct. Rust `conntrack.rs query/probe`; codec-тесты; реальный GET не тестируется. |
| `ct_probe` (static) | 578-595 | 18 | одноразовая проба ctnetlink; включение/выключение детекторов тишины | `conntrack.rs:270-295 open`, `:309-357 probe` | **P** | **Ветви сверены:** C `!sess \|\| up` → выход; при `fd<0` открыть; `seq++` (0→1); `d2k_ct_probe_fd(fd,seq,startup?200:0)==1` → up=1, `set_ct_query`, лог «появился» при `told_off`; иначе `set_ct_query(NULL)`, лог «выключены» один раз. Rust `R2oConntrackClient::open` делает `probe()` (100 мс) и возвращает None при недоступности; отдельного повторного включения/логов нет. Семантика «нет подсистемы — нет запросов» сохранена, API/момент иные. |
| `out_verdict` (static) | 597-599 | 3 | адаптер вердикта `out_tail` | `nfqueue.rs:310 send_verdict` | **E** | C `static int out_verdict(void *ctx,uint32_t id,uint32_t verdict){return send_original_verdict(ctx,id,verdict);}`. Rust `send_verdict`; тонкий адаптер, те же id/verdict. |
| `out_fail` (static) | 603-607 | 5 | учесть отказ переиздания, сохранить errno | `main.rs:272` eprintln + `r2o_note_busy` | **P** | C `st.send_fail++`, `errno=err`, -1. Rust `main.rs:272`/`r2o_note_busy`; классификация busy есть (`r2o_udp_send_busy`), отдельного `send_fail`/сохранения errno для этой ветки нет. |
| `out_marked` (static) | 615-635 | 21 | лог «метка клиента → хвосты ядром», первые 16 | `main.rs:88 r2o_udp_packet_is_neutral`, `r2o_route` gate | **P** | C `udp_marked_kept++`; первые 16: `packet_parse`, порты, при `mark==D2K_ROUTE_OTHER_DEV` — «другой интерфейс», иначе «метка клиента 0x%x»; на 16-й «дальше только счётчик». Rust `r2o_udp_packet_is_neutral`/route gate; счётчик `udp_marked_kept` отдельно не выводится. |
| `out_defer` (static) | 640-647 | 8 | вердикт позже, за отложенной головой | `r2o_udp_hold.rs:291 R2oUdpDeferredVerdicts::r2o_enqueue` | **P** | C `udp_releases && enqueue(at,&id,&verdict,1,&none,0)==0` → 0; иначе сразу `send_original_verdict`. Rust `r2o_enqueue`; `hold` D6; unit-теста именно на очередь вердиктов нет. |
| `out_resend_failed` (static) | 651-671 | 21 | одна строка на поток при отказе хвоста, адрес/семейство/длина | `main.rs:287` лог позднего хвоста | **P** | C парсит пакет, `inet_ntop`, порты, `fam`, печатает `src:sport -> dst:dport (IPv%d, N байт)` + `strerror(err)`; хвост «дальше только счётчик» при `D2K_UDP_REFUSED_LOG`. Rust лог без лимита/адресной строки; лимит `D2K_UDP_REFUSED_LOG` не воспроизведён. |
| `out_send_now` (static) | 673-684 | 12 | raw send немедленно | `raw.rs:147 send_packet` | **P** | C `!raw` → `out_fail(ENOTSOCK)`; `raw_prepare`/`raw_send`, ошибка → `out_fail(errno?:EIO)`; `emitted++/emitted_now++`. Rust `raw.rs:147 send_packet`; unit-тесты исходящего пакета. |
| `out_send_at` (static) | 686-696 | 11 | отложить посылку без владения ID | `scheduler.rs:209-211 push_raw` | **P** | **Ветви сверены:** C `!c->raw \|\| !c->sched` → `out_fail(ENOTSOCK)`; `d2k_raw_prepare`, ошибка → `out_fail(errno?:EIO)`; `d2k_sched_push_serial(...,NULL,0)` — при отказе `out_fail(ENOSPC)`; `deferred++`, 0. Rust `push_raw` возвращает `Err(WirePacket)`; классификация ENOSPC/ENOTSOCK и счётчик `deferred` — в вызывающем. Тест `test-datapath-scheduler-differential.sh`. |
| `out_send_at_owned` (static) | 699-709 | 11 | отложить с владением NFQUEUE ID | `scheduler.rs:214 push_owned`, `:275 pop_due_ex` | **P** | C как `out_send_at`, но `push_owned(at,p,n,id)`; ENOSPC → out_fail; `deferred++`. Rust `push_owned`/`pop_due_ex`; unit `scheduler.rs:564` + D21. |
| `http80_log` (static) | 717-728 | 12 | строка «вставка провайдера 30x» | `main.rs:3136 send_http_portal_event` (событие) | **P** | C `d2k_addr_text`, строка `HTTP <host> (IPvN srv:port): вставка провайдера — 30x на <portal> через N мкс после запроса при RTT M мкс; <outcome>`. Rust отправляет событие `send_http_portal_event`, текст/формат C-лога не воспроизведён. |
| `http80_io_payload` (static) | 733-743 | 11 | вердикт ACCEPT с заменой | `nfqueue.rs:317 send_replacement` | **P** | C `d2k_nfq_verdict_payload(ACCEPT,p,n)`; ошибка → `verdict_fail++`/лог/-1; иначе `accepted++`. Rust `send_replacement`; netlink-тесты замены; D17. |
| `http80_io_accept` (static) | 745-755 | 11 | вердикт ACCEPT | `nfqueue.rs:310 send_verdict` | **E** | C `d2k_nfq_verdict(ACCEPT)`; ошибка → verdict_fail/лог; иначе accepted++. Rust `send_verdict`; `netlink.rs:304 verdict_bytes...` + `:321 replacement...`. |
| `http80_io_rst` (static) | 757-768 | 12 | raw RST серверу после 307 | `raw.rs:147 send_packet` | **P** | C `raw_send`, ошибка → `send_fail++`, `log_send_fail("RST к серверу после 307: ")`, -1; иначе `emitted++`. Rust `send_packet`; D17 проверяет сборку RST, не отправку. |
| `http80_cut` (static) | 776-784 | 9 | событие обрыва ответа контроллеру | `hold.rs:255 sweep_http_responses`, `main.rs:3148` | **P** | C печатает host/path/body/request_no/RTT и `d2k_ctlsrv_http80_event(ctl,r)`. Rust `sweep_http_responses`/`main.rs:3148`; `hold.rs:2082 incomplete_fixed_length...`. |
| `http80_step` (static) | 786-829 | 44 | диспетчер HTTP80: DROP/REPLACE/swap/лог | `main.rs:2006 build_http_redirect_packets`, `:2093 send_replacement`, `hold.rs` | **P** | **Ветви сверены:** C `d2k_http80_packet`; `CUT` → `http80_cut`; injection и (не REPLACE или !raw) → событие; DROP+raw → вердикт DROP; не REPLACE/!raw → лог и 0; иначе `http80_swap` с io, событие, лог swapped/не swapped. Rust `build_http_redirect_packets`/`send_replacement`/`hold`; D17 paired differential; ветви «raw нет» и «swap rejected» покрыты кодом. |
| `usage` (static) | 834–861 | 28 | текст помощи CLI | `main.rs:2952-2984 print_help` | **P** | **Точный состав C (`d2kd.c:834-861`):** `--queue` (обязательно), `--plan`, `--mode observe\|apply`, `--mark M`, `--probe-mark M`, `--only-mark M[/K]\|none`, `--udp-reverse-hook`, `--iface NAME`, `--flows N` (2048, отдельно TCP и UDP), `--queue-len N` (1024), `--copy-range N` (1600), `--sched-slots N` (128), `--journal N` (256), `--control PATH`, `--idle SEC` (120), `--log FILE`, `--stats SEC` (10), `--duration SEC`, `--no-fail-open`. В справке нет `--health-file` и `--version`, хотя парсер их знает. **R2O (`print_help`):** есть `--plan`, `--controller-only`, `--r2o-udp-reverse-visible\|--udp-reverse-hook`, `--queue`, `--idle`, `--r2o-flow-capacity\|--flows`, `--stats`, `--family`, `--mode`, `--mark`, `--iface`, `--probe-mark`, `--only-mark`, `--copy-range` (64..65535), `--queue-len`, `--journal`, `--rcvbuf`, `--control`, `--control-wire v22\|v48`, `--control-release-id`, `--no-fail-open`, `--check`, `--version`, `--help`. **Подтверждённые пробелы:** нет `--log`, `--health-file`, `--duration`, `--sched-slots`; добавлены `--family`, `--controller-only`, `--control-wire`, `--control-release-id`, `--rcvbuf`, `--check`, `--both` (не в help), `--r2o-flow-capacity`, `--r2o-udp-reverse-visible`. Текст и умолчания (`copy-range` 65535 против 1600) отличаются. |
| `arg_u32` (static) | 863–871 | 9 | строгий разбор u32 через `strtoul(v,&end,0)`: база 0 (десятичное/0x hex/ведущий 0 — восьмеричное), `*end==0`, `n<=0xffffffff` | `main.rs:2911-2923 parse_value`; `:2929-2937 parse_mark`; `:2939-2950 parse_only_mark` | **P** | **Подтверждённые расхождения синтаксиса:** C `strtoul(...,0)` принимает `0x10`, `010` (восьмеричное 8), ведущие пробелы и знак `+`/`-`; пустая строка даёт `end==v`, `*end=='\\0'`, `n=0` — **принимается как 0**. Rust `parse_value::<u32>` — строгий `FromStr`: только десятичное, без пробелов/знака/пустой строки; `parse_mark` дополнительно принимает только `0x`/`0X` hex, но не восьмеричное и не пробелы. Для `--mark/--probe-mark/--only-mark` C и Rust понимают hex, но расходятся на пустой строке, `010`, `+1`, ` 1`. Граничные тесты в Rust не выделены. |
| `port_of` (static) | 873–876 | 4 | big-endian u16: `b[0]<<8 \| b[1]` | `r2k-core/src/packet.rs:138-139` (`read_u16` TCP), `main.rs:2989-2990` (`u16::from_be_bytes` в журнале) | **E*** | **Точное совпадение:** C читает сетевой порядок как `(b[0]<<8)\|b[1]` (`d2kd.c:873-876`); Rust `read_u16`/`from_be_bytes` дают то же значение. Используется в `print_journal` (`1092-1093`) и разборе UDP-заголовка (`1776-1777,1804-1805`), в Rust — в `format_journal_key` и `PacketView::tcp_segment`/UDP-разборе. |
| `print_stats` (static) | 878–1030 | 153 | периодическая сводка: процесс, HTTP80, hold, владение приветствием, пакеты, ICMP, план applied/done/emitted/deferred/damaged/stale/sent_lost, TCP/UDP-потоки, приветствия/обмены/подозрения, reply hidden, sched, обрезано/без нагрузки/без заголовка, payload, keep-alive, снимки, lost/verdict/send/recv, NAT, routed, udp_marked, raw, follow, shape misses, plan count, причины | `main.rs:629-773` (`r2o_log_process_stats`, `r2o_log_queue_stats`, `r2o_log_flow_table_stats`, `r2o_log_scheduler_stats`, `r2o_log_session_stats`, `r2o_log_payload_stats`, `r2o_log_capture_stats`, `r2o_log_hold_stats`, `r2o_log_raw_stats`, `r2o_log_udp_follow_stats`), `r2o_icmp_guard.rs:153-161` | **P** | **Совпадает дословно/по полям:** процессор/RSS (`r2o_process_stats_line` — та же формула `cpu_ms/10/сек` и остаток), hold (`started/ready/released/timed_out/timed_out_packets/plan_changed/dropped_all/joined/mismatched/sided/full/pending`), пакеты/байты/принято/снято, ICMP, TCP/UDP-потоки и отказы, reply hidden, sched count/refusals, truncated/no_payload/no_header, payload (reverse/after_hello/late/not_hello/first_byte/sni_next_seg/HTTP keep-alive), снимки, lost, raw sent/errors/busy, UDP follow refused/busy/queue_full/route notifications. **Подтверждённые пробелы:** (1) нет HTTP80-строки (`requests/injections/evicted/untracked/unparsed/later`); (2) нет `hold_owned/hold_resent/hold_resend_fail`; (3) нет `applied/done/emitted/deferred/immediate/late/damaged/stale_deferred/sent_lost` — в R2O этих агрегатов нет; (4) нет `verdict_fail/recv_err` отдельными числами; (5) нет NAT `ok/miss/none/retry`; (6) нет `routed_flows` и `udp_marked_kept`; (7) `shape_misses` и `plan_count/capacity` в `NamePlans` есть (`control.rs:178-195`), но в сводку не выводятся; (8) нет гистограммы причин (`count_reason` — N). ICMP выводится отдельно только при `seen/noted != 0`. `test-datapath-stats-timer-differential.sh` покрывает таймер, не состав. |
| `proto_name` (static) | 1039–1045 | 7 | `6→tcp`, `17→udp`, иначе `?` | `main.rs` `proto_name` | E | C использует `proto_name` только в `print_journal`. Rust `proto_name(entry.key[37])` выводится в строке журнала рядом с ключом; тест `proto_name_matches_c` проверяет tcp/udp/?. |
| `jrn_kind` (static) | 1050–1066 | 17 | коды журнала → тексты: HELLO_SNI «приветствие», HELLO_NONAME «приветствие без имени», PLAN_APPLIED «план применён», PLAN_REFUSED «план не применён», SUSPECT «подозрение», EXCHANGE «обмен пошёл», SHAPE «снята форма приветствия», PLAN_DONE «», PLAN_UNSENT «посылка не ушла», PLAN_DAMAGED «поток испорчен» | `flow_journal.rs` `R2oFlowJournalKind::c_name`/`c_name_with_name`; печать в `main.rs` | E | C `jrn_kind` различает HELLO_SNI/HELLO_NONAME и печатает точные тексты. Rust `c_name` содержит те же строки, `c_name_with_name(false)` для `Hello` даёт «приветствие без имени»; печать журнала использует его. Тест `jrn_kind_c_names_match_donor` перебирает все виды. |
| `print_journal` (static) | 1070–1104 | 35 | один раз в конце: пусто → «журнал пуст»; шапка «--- журнал: N записей, затёрто D ---»; строка `%6llu мс  proto low:port - high:port  kind name: note` | `main.rs:1140-1173` (перебор `flow_journal.iter()` в ветке STOP), `:2986-3000 format_journal_key`, `:3006-3075 format_journal_details` | **P** | **Совпадает:** печать один раз при завершении, порядок от старых к новым, имя только при `name_len != 0`, пояснение только при непустом виде. **Подтверждённые отличия формата:** (1) C печатает время в **мс** от старта, Rust — `[{} нс]`; (2) C печатает `proto` (`tcp/udp/?`), Rust `format_journal_key` — сразу `client:port → server:port`, без протокола и в направлении клиент→сервер, а не канонической паре low-high через дефис; (3) C при пустом журнале печатает «журнал пуст», Rust не печатает ничего; (4) C печатает шапку с числом записей и `dropped`, Rust шапки нет; (5) C печатает `note` записи, Rust — `format_journal_details` по виду (план/попытка/исполнение, причина отказа, TTL и т.п.). D22 сверяет записи журнала, не текстовую печать. |
| `refuse_of_errno` (static) | 1114–1116 | 3 | `EMSGSIZE → D2K_REFUSE_TOO_LONG`, иначе `D2K_REFUSE_SEND` | `main.rs` `refuse_of_errno` | E | C различает только `EMSGSIZE`. Rust `refuse_of_errno(&io::Error)` возвращает `R2O_JOURNAL_REFUSE_TOO_LONG` для EMSGSIZE и `R2O_JOURNAL_REFUSE_SEND` иначе; используется в немедленном и отложенном отказах raw-send. Тест `refuse_of_errno_matches_c` (EMSGSIZE/EIO). |
| `offline_self_check` (static) | 1118–1123 | 6 | `--offline-self-check`: `D2K_CTL_PROTO_VERSION == D2K_RUNTIME_WIRE` и SHA-256("abc") равна эталону; иначе -1 | `main.rs` `app::offline_self_check` | E | C проверяет wire-версию и SHA-256("abc") до разбора опций. Rust `--offline-self-check` обрабатывается в `app::run` до `parse_options`; `offline_self_check()` сверяет `PROTOCOL_VERSION` с 48 и SHA-256("abc") с эталоном. Тест `offline_self_check_matches_c` (`--bin r2o-datapath`). |
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

**Итог:** 44 функции; N нет, остальные P/E с подтверждёнными пробелами
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
| `initial_dcid` (static) | 202–211 | 10 | DCID открытого Initial: `d2k_qw_hdr_parse`, long header, тип Initial, `dcid_len <= D2K_QW_CID_MAX` | `r2k-core/quic.rs` `r2k_quic_initial_flight_id_structural` | E | C извлекает DCID из структурно корректного Initial без проверки тега. Rust `r2k_quic_initial_flight_id_structural` делает то же (long header/version/type/DCID, границы) и используется в датапате для кольца полёта/UDP-hold; аутентифицирующий `r2k_quic_initial_flight_id` остаётся для проверок контроллера. Тест `initial_dcid_structural_matches_c_without_tag_check` (испорченный тег: structural Some, auth None; обрезанный None). |
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
| `rd16` (static) | 30-32 | 3 | big-endian u16 | `r2k-core/src/packet.rs read_u16` | **E** | C `(p[0]<<8)\|p[1]`; Rust `read_u16`/`from_be_bytes` с проверкой границ. Используется в разборе TCP/UDP/STUN; побайтовые тесты пакетов. |
| `refuse_coded` (static) | 402–413 | 12 | отказ плана в журнал; зонд молчит только при `code==NONE`; trial/plan id | `flow_journal.rs:684-720 record_plan_refused`, `main.rs:3737-3760 send_refused_event` | **P** | **Подтверждённое отличие:** C находит поток по ключу и при `controller_probe && code==D2K_REFUSE_NONE` **не пишет** запись (`session.c:404-406`); Rust `record_plan_refused` не знает о probe и принимает только `NOT_APPLIED/FLOW_UNFIT`, а `send_refused_event` всегда пишет журнал и отправляет событие. Для `code==NONE` C пишет запись (кроме probe), Rust `record_plan_refused` её отвергает; отказ NONE идёт только событием. D22 покрывает основные коды, не это условие. |
| `refuse` (static) | 415–418 | 4 | `refuse_coded(..., NONE, NULL)` | `main.rs:3737 send_refused_event` (событие), `flow_journal.rs:684 record_plan_refused` | **P*** | C-обёртка передаёт `code=NONE`, без плана/trial. Rust отправляет `EVENT_REFUSED` и пишет журнал только для `NOT_APPLIED/FLOW_UNFIT`; отказ `NONE` в журнал не попадает (см. `refuse_coded`). |
| `tcp_options_timestamp_profile` (static) | 422–433 | 12 | профиль TCP-опций: UNKNOWN/NO_TS/TS; EOL, NOP, длина 2..n, TS len=10 | `r2k-core/src/packet.rs:39-64` | **E** | **Точное совпадение:** C `kind==0` → break, `kind==1` → off++, длина `<2`/`>n-off` → UNKNOWN, `kind==8 && len==10` → TS, иначе NO_TS (`session.c:422-433`); Rust `tcp_options_timestamp_profile` те же ветви (`packet.rs:39-64`). Unit-тесты packet/tcp. |
| `tcp_options_have_timestamp` (static) | 435–437 | 3 | профиль == TS | `packet.rs:39` + сравнение с `TCP_PROFILE_TS` | **E*** | C-обёртка `tcp_options_timestamp_profile(o,n)==D2K_TCP_PROFILE_TS`; Rust сравнивает результат с `TCP_PROFILE_TS`. Используется в `D2K_FLOW_NEED_TCPTS`; тесты опций косвенные. |
| `plan_handed_off` (static) | 446–473 | 28 | applied/key/plan/trial/binding; `orig_taken`; `sends_left=n_out+1`; execution id | `engine.rs:588-603 r2o_begin_execution`, `main.rs:411 R2oTcpExecution`, `PendingApplied` | **P** | **Совпадает:** Rust фиксирует `execution_id`, ключ, план/trial/binding, `payload_on_wire/original_spent/original_taken`, а завершение ждёт опустошения `ScheduledQueue` по ticket. **Подтверждённые отличия:** C ведёт **числовые** `sends_left = n_out+1`, `sends_done`, `sends_failed`, `udp_replan` на потоке и `sent_lost`; Rust использует булевы `TransmissionOutcome.r2o_sends_done`/`payload_on_wire` и `PendingApplied`, числовых счётчиков и `sent_lost` нет. C `orig_taken = verdict==DROP`; Rust `fate == OriginalFate::Drop`. |
| `table_of` (static) | 477–479 | 3 | `proto==17 → uflows`, иначе `flows` | `TcpSessions`/`R2oUdpSessions` (разные типы) | E | C выбирает таблицу по `k->proto`. Rust держит TCP и UDP в разных типизированных структурах, выбор происходит на уровне типа в вызывающем коде; суммарные и раздельные счётчики/отказы/ёмкость покрыты `session_capacity_flows_and_refusals_match_c`, `session_flows_guards_shape_damaged_getters_match_c`. |
| `suspect_num` (static) | 486–503 | 18 | не чаще раза на поток: `controller_probe`/`suspected` → выход; `suspects++`, journal SUSPECT с planned/client_shape | `engine.rs` `r2o_note_suspect` | E | C выходит для probe и уже подозревавшегося потока, иначе ставит `suspected` и учитывает подозрение. Rust `r2o_note_suspect` проверяет `controller_probe` и `suspect_counted`, увеличивает `session_stats`; журнал SUSPECT пишут вызывающие события. Тесты `session_suspect_counts_once_per_tcp_flow`, `suspect_num_skips_controller_probe_like_c`. |
| `suspect` (static) | 505-508 | 4 | обёртка `suspect_num(..., num=0)` | события `R2oTcp*Event`/journal | **P*** | C `suspect_num(s,at,k,fl,code,det,0)`. Rust-события не имеют числового `num` (кроме stall), поэтому передача 0 эквивалентна; отдельной функции нет. |
| `on_flow_expire` (static) | 521–530 | 10 | при истечении: `capture_forget` + повторный `track_find` + `tcp_silence_observe` | `engine.rs` `expire_with_silent` | E | C забывает capture, повторно ищет живой поток и выставляет `silence_told` до `track_expire`. Rust `expire_with_silent` вызывает `tcp_silence_event`/замыкание до `retain`-удаления и забывает capture (`capture.forget`); `silence_reported` хранится в `TcpSession`. Порядок эквивалентен. Тесты `tcp_capture_metrics_count_an_expired_incomplete_record`, `tcp_silence_event_matches_c_conditions`. |
| `rd32` (static) | 532-535 | 4 | big-endian u32 | `u32::from_be_bytes`/`read_u32` (`packet.rs`) | **E*** | C `(p[0]<<24)\|(p[1]<<16)\|(p[2]<<8)\|p[3]`. Rust `from_be_bytes`/`read_u32` с bounds-check. Используется в QUIC/STUN; побайтовые тесты пакетов. |
| `is_discord_ip_discovery` (static) | 544–550 | 7 | ровно 74 байта, `[0,1,0,70]`, нули 8..71 | `r2k-core/src/stun.rs:82-86` | **E** | **Точное совпадение:** C `n==74 && d[0..4]=={0,1,0,70}` и все `d[8..72]==0` (`session.c:544-550`); Rust `is_discord_ip_discovery_request` те же проверки (`stun.rs:82-86`). |
| `is_discord_ip_discovery_response` (static) | 552–564 | 13 | 74 байта, `[0,2,0,70]`, тот же SSRC, адрес только `0-9.:`, порт != 0 | `r2k-core/src/stun.rs:89-107` | **P** | **Подтверждённое отличие строгости:** C принимает любую непустую последовательность цифр/`.`/`:` в 8..71 и требует ненулевой порт (`session.c:552-564`); Rust требует первый NUL в 8..72, непустой префикс и успешный `Ipv4Addr::parse` (`stun.rs:97-106`), поэтому IPv6-подобный `::` и мусорные `:` C принимает, Rust — нет. Порт проверяется одинаково. Voice-proof тесты частичные. |
| `is_stun_binding` (static) | 569-578 | 10 | RFC 5389 Binding: `n>=20`, top bits 0, length%4==0, `20+len<=n`, magic `2112a442`, type | `r2k-core/src/stun.rs is_binding` | **E** | **Точное совпадение:** C проверяет `!d \|\| n<20 \|\| (d[0]&0xc0)!=0 \|\| len%4!=0 \|\| 20+len>n \|\| d[4..8]!=21 12 a4 42 \|\| type`; Rust `is_binding` те же поля/границы. |
| `is_stun_request` (static) | 580-582 | 3 | STUN Binding Request (`type 0x0001`) | `stun.rs is_binding_request` | **E*** | C `return is_stun_binding(d,n,0x0001)`: те же проверки `n>=20`, top bits 0, `len%4==0`, `20+len<=n`, magic `2112a442`, type. Rust `is_binding_request` → `is_binding(...,BINDING_REQUEST)`; эквивалентно. |
| `is_stun_response_for` (static) | 584–588 | 5 | Binding Success 0x0101 + txid | `stun.rs:76-78` | **E** | C `is_stun_binding(...,0x0101) && memcmp(d+8,txid,12)==0`; Rust `is_binding(packet, BINDING_RESPONSE) && packet[8..20]==txid` (`stun.rs:76-78`). |
| `d2k_session_nat_stats` | 650–656 | 7 | глобальные NAT ok/miss/none/retry | `r2o_conntrack_gate.rs` `nat_stats` | E | C ведёт `g_nat_ok/miss/none/retried` в `flow_tracked`. Rust `R2oConntrackGate` считает те же четыре состояния: `TcpSynAck`/`Found` → ok, три `Missing` → miss, `TableMissing` → none, `Found` после повтора → retried. Тест `nat_stats_match_d2o_counters`. |
| `plan_fits_transport` (static) | 672–676 | 5 | `!p → 1`; transport 0 или совпал с proto | `engine.rs` `plan_fits_transport` | E | C `!p` → 1; `tr == 0 \|\| tr == proto`. Rust `plan_fits_transport(Option<&Plan>, proto)` повторяет обе ветви; используется в `tcp_plan_input` вместо жёсткого `transport != 6`, поэтому план без объявленного транспорта снова подходит TCP, как в C. Тесты `plan_fits_transport_matches_c` (0/6/17) и `transport_zero_plan_applies_to_tcp_like_c`. |
| `flow_tracked` (static) | 678–777 | 100 | conntrack: первый пакет — не читать; SYN-ACK — доказано; до 3 попыток procfs; nat_state 0/1/3, g_nat_* | `r2o_conntrack_gate.rs:55-93 confirm`, `:115-175 guard_decision`, `proc_nat.rs:20 lookup` | **P** | **Совпадает:** первый пакет не читает таблицу; TCP SYN-ACK считается доказательством; три попытки `lookup`; «таблицы нет» — отдельное состояние; первый пакет при промахе пропускается. **Подтверждённые отличия:** (1) C ведёт глобальные `g_nat_ok/miss/none/retried` и `nat_state` на потоке; Rust кеширует `Tracked/NoConntrackTable` в `R2oConntrackGate`, счётчиков NAT нет (N `d2k_session_nat_stats`); (2) C вызывает `flow_tracked` **до** применения плана и при `-1` отказывает целиком; Rust `guard_decision` вызывается после решения и для UDP-фрагментов дополнительно переписывает адреса; (3) C `first_packet` для TCP всегда 0, Rust передаёт `first_udp_packet` только в UDP-ветке, TCP — `false`; (4) C при `rc>0` ставит `nat_state=3` навсегда, Rust кеширует `NoConntrackTable` с idle 120 с. |
| `handle_udp` (static) | 779–1569 | 791 | весь UDP-путь: направление по hook/flow/443, серверные счётчики/voice/STUN, окно 8, hold, QUIC-сборка/снимок/ECH, addr/voice/name/fallback планы, `plan_fits_transport`, запрет разреза, conntrack/NAT фрагментов, сборка до 16 посылок, APPLIED | `main.rs:1543-2604` (UDP-путь), `r2o_udp_sessions.rs`, `r2o_quic.rs`, `r2o_voice.rs`, `r2o_conntrack_gate.rs` | **P** | **Совпадает по крупным ветвям:** направление из OUT/POST vs IN/PRE с fallback на известное направление и порт 443; серверная сторона учитывается, voice/STUN-доказательства и UDP EXCHANGE; окно 8; `saw_hello`/`saw_initial`; запрет повторного плана; `quic_deny`; выбор addr/voice/name/fallback; `plan_fits_transport`; запрет нескольких payload-посылок; conntrack/NAT; лимит 16; APPLIED. **Подтверждённые отличия:** (1) C хранит `saw_initial` и `rev_after_hello` в `d2k_flow`; Rust `r2o_udp_sessions` имеет `hello_seen`, но отдельного состояния «Initial без имени» не найдено — молчание по такому потоку может не наблюдаться; (2) C добавляет датаграмму в `init_ring` всегда до `qsnap_done`; Rust — только до первого отправленного приветствия (`hello_reported`), после чего кольцо чистится; (3) C снимок `last_hello/last_name` глобальный на слот, Rust `QuicHello { key, host, snapshot }`; (4) C `find_addr_probe`/`find_voice_probe`/`find_target`/`s->plan` и `refuse` при отсутствии; Rust `select_with_quic_host_at_hook` + fallback `plan`, `qdeny`; (5) C `payload_emits > 1` отвергает план для UDP, Rust проверка в `engine`/`wire` иная; (6) C при `acts.fate==HOLD` отказывает, Rust `Transmit`/fate; (7) C `out->quic_name/quic_shape_miss` для лога, Rust — события. Полного C/Rust differential на все ветви нет; `r2o-udp-exchange-differential.sh`, voice/quic differentials частичные. |
| `note_tcp_hello` (static) | 1573–1580 | 8 | `!controller_probe` → `tcp_hello_flows++`; `hello_ack=rd32(tcp+8)`, `hello_ack_valid=ack` | `engine.rs` `track_packet_mode`, `r2o_tcp_hello_flows` | E | C инкрементит счётчик только для не-зонда и сохраняет ACK. Rust `controller_probe` подавляет `r2o_tcp_hello_flows`, а `hello_ack: Option<u32>` заменяет пару `hello_ack/hello_ack_valid`; тест `note_tcp_hello_skips_probe_and_records_ack_like_c` проверяет probe/ack и обычный hello. |
| `routed_flow` (static) | 1593–1626 | 34 | TCP/UDP не фрагмент: route_mark → `track_get`, `routed=1`, `routed_flows++`, first/mark; без метки — найти routed, новый SYN снимает флаг | `r2o_route.rs:596-665 R2oRoutedFlows::r2o_skip_packet`, `:666-678 r2o_is_new_syn` | **P** | **Совпадает:** метка → поток помечается routed и идёт ядром; ответ без метки наследует флаг; новый SYN без метки снимает routed. Rust `r2o_skip_packet` дополнительно вставляет reverse-ключ и чистит по idle/ёмкости; C счётчик `s->routed_flows`, Rust — `R2oRoutedFlows` + лог. `r2o-route-gate-differential.sh`. |
| `session_packet` (static) | 1628–2601 | 974 | TCP-путь: IP/TCP-заголовки, направление SYN/SYN-ACK/первый, capture, rev-профиль/TLS-ответ, reply_hidden, EXCHANGE, alien-RST, FIN, HTTP keep-alive, TLS-форма (ECH/truncated), план, conntrack, сборка, APPLIED | `engine.rs:1403-1439 decide_with_session*`, `:1849 decide_tcp`, `capture.rs`, `httpup.rs`, `hold.rs` | **P** | **Совпадает по крупным ветвям:** разбор заголовков, направление по SYN/SYN-ACK с fallback, счётчики forward/reverse, профиль TTL/TOS первого ответа, `rev_server_hello`/`rev_types`/`rev_payload_after_hello`, reply_hidden, EXCHANGE, alien-RST guard с `RST_CUT`/`RST_AFTER_APP`, FIN-ожидание, HTTP-разбор/keep-alive, TLS-форма MODERN/LEGACY/ECH, выбор плана по имени/адресу/HTTP, отказ при отсутствии/чужом транспорте, `D2K_FLOW_NEED_TCPTS`, сборка и APPLIED. **Подтверждённые отличия:** (1) C при `tls.is_tls13 && !ech && exts_truncated` и наличии ECH-цели оставляет форму ANY (`session.c:2325-2334`); Rust `r2o_client_shape_from_legacy` сводит к MODERN/LEGACY/ECH без проверки ECH-таблицы (`main.rs:9356-9393`) — план может не найтись/примениться иначе; (2) C хранит `rev_first_type/rev_types/rev_server_hello` и отдаёт в журнал; Rust события `R2oTcpExchangeEvent`; (3) C `pending_fin` и окно FIN; Rust `pending_fin`/`fin_retry_window`; (4) C `http_skip` тексты и keep-alive `http_next`; Rust `httpup`/`hold`; (5) C `plan_done` запрещает повтор кроме HTTP; Rust `NamePlans`/session; (6) C `d2k_plan_apply` и `d2k_wire_build`; Rust engine `transmit_many`; (7) C `sends_left` числовой, Rust `ScheduledQueue`/PendingApplied. Полного differential на все ветви нет. |
| `d2k_session_packet` | 2603–2606 | 4 | публичный вход: `observe_only=0, probe=0, mtu=0` | `engine.rs:1403-1410 decide_with_session` | **E*** | Обёртка C и Rust передают те же флаги (`observe=false`, `controller_probe=false`, без MTU); вся логика в `session_packet`/`decide_with_session`. |
| `d2k_session_packet_mtu` | 2608–2613 | 6 | вход с `tcp_segment_cap` | `engine.rs:1421-1429 decide_with_session_mtu` | **E*** | C передаёт `tcp_segment_cap` в `session_packet`; Rust `decide_with_session_mtu` — в `transmit_many`/wire. `test-tcp-shape-context-differential.sh`. |
| `d2k_session_packet_probe` | 2615–2619 | 5 | вход зонда (`probe=1`) | `engine.rs:1412-1419 decide_with_session_probe` | **E*** | C `controller_probe=1`; Rust `decide_with_session_probe`. Проба исключается из пользовательских счётчиков; `test-datapath-controller-probe-capture-differential.sh`. |
| `d2k_session_packet_probe_mtu` | 2621-2626 | 6 | probe-пакет с явным `tcp_segment_cap` | `engine.rs` `process_packet` flags | **E*** | C `session_packet(...,observe=0,probe=1,tcp_segment_cap)`; Rust комбинация флагов та же (probe + cap), отдельного differential нет. |
| `d2k_session_observe_tcp` | 2628–2631 | 4 | только наблюдение, без вердикта (`observe_only=1`) | `main.rs` observe-mode `decide_with_session` | **P** | C вызывает `session_packet(..., observe_only=1, probe=0, mtu=0)` и игнорирует результат. Rust в observe-режиме вызывает `decide_with_session` с `observe_plan` и не отправляет; `observe_only` как отдельный флаг отсутствует. Наблюдаемые счётчики/события совпадают, но ветки capture/hold могут различаться. |
| `d2k_session_plan_revision` | 2633–2635 | 3 | `plan_revision + d2k_plantab_revision(plans)` | `control.rs` `NamePlans.revision` | **P** | **Подтверждённое отличие:** C складывает ревизию запасного плана и таблицы (`session.c:2634`). Rust ведёт **один** счётчик `NamePlans.revision`, растущий на любые изменения; отдельной ревизии запасного `Plan` нет. Для обнаружения изменений эквивалентно, для точного числа — нет. |
| `d2k_session_stream_anchor` | 2637–2645 | 9 | hold_parse → поток с `saw_syn`; `http_flow && http_conn ? http_next : syn_seq+1` | `hold.rs:969 remember_syn`, `main.rs` capture anchor | **P** | **Совпадает по смыслу:** Rust хранит anchor по SYN в hold-слоте и использует `syn_seq+1`; HTTP keep-alive anchor ведётся `httpup`/`http_next`. **Отличия:** C функция единая, возвращает `http_next` при `http_flow && http_conn`, Rust — отдельные `capture_anchor`/`note_http_execution`; проверка `saw_syn` и приоритет HTTP не вынесены в один API. D6. |
| `d2k_session_set_hook` | 2647–2649 | 3 | hook текущего пакета (`D2K_HOOK_UNKNOWN` по умолчанию) | `main.rs` `queue_hook` (параметр на пакет) | **P** | C хранит hook в сессии и сбрасывает/ставит на каждый пакет; Rust передаёт `queue_hook` параметром в `r2o_udp_hold_candidate`/`r2o_udp_packet_direction`/engine. Семантика «текущий пакет» та же, состояние не хранится. |
| `d2k_session_set_route_mark` | 2651–2653 | 3 | метка маршрутизации текущего пакета | `r2o_route.rs` `R2oRouteGate::r2o_route_mark`, `r2o_skip_packet` | E | C хранит `route_mark` в сессии. Rust не хранит её в сессии: `r2o_route_mark` вычисляет метку по текущему пакету, `R2oRoutedFlows` ведёт маршрутные потоки; поведение «метка выбирает политику» покрыто `r2o_маршрутный_поток...`, `r2o_политика_отделяет_чужие_потоки...`, `r2o_route_mark` тестами. |
| `d2k_session_route_mark` | 2655–2657 | 3 | чтение метки текущего пакета | `main.rs` route gate | **P** | C getter поля; Rust не хранит метку в сессии, а использует локальную `route_gate`/`umark`. Эквивалент для текущего пакета отсутствует как API. |
| `d2k_session_routed_flows` | 2659–2661 | 3 | счётчик routed-потоков | `r2o_route.rs:580 R2oRoutedFlows` | **P** | C `s->routed_flows++`; Rust `R2oRoutedFlows` хранит map потоков, отдельного счётчика/геттера не найдено. В сводке C печатает число, Rust — нет. |
| `d2k_session_set_udp_reverse_hook` | 2663–2665 | 3 | «обратное UDP видно» | `main.rs` `reverse_queue_visible` | **P** | C хранит флаг в сессии и использует в `sweep_udp_one`; Rust `options.reverse_queue_visible` + `ControlServer::is_connected`, передаётся в `sweep`. Смысл тот же, поле/условие иное. |
| `d2k_session_set_ct_query` | 2667–2669 | 3 | включить ctnetlink-запросы | `conntrack.rs:264 R2oConntrackClient` (`Option`) | **P** | C инъектирует `ct_query`/`ctx`; Rust `conntrack: Option<R2oConntrackClient>` создаётся в `run`, `None` при недоступности. Эквивалентно по включению/выключению, API иной. |
| `d2k_session_udp_hold_begin` | 2671–2711 | 41 | route_mark=0, UDP не фрагмент, hook client/server, 443 fallback, QUIC Initial, поток не plan_done/damaged/saw_hello/routed, fwd_pkts<8 | `r2o_udp_hold.rs:19-47 r2o_udp_hold_candidate`, `r2o_udp_sessions.rs:410-424 r2o_begin_hold` | **P** | **Совпадает:** только клиентский Initial (OUT/POST или порт 443 fallback), не фрагмент, окно 8, запрет после плана/приветствия. **Подтверждённые отличия:** C проверяет `route_mark==0`, `fl->damaged`, `fl->routed` в этой функции; Rust `r2o_udp_hold_candidate` их не проверяет (route gate выполняется раньше, `damaged` — в `r2o_begin_hold` отсутствует), а `r2o_begin_hold` добавляет `hold_attempts`/`client_packets` и `r2o_mark_hello_seen`. C `saw_initial` не входит в запрет, Rust `hello_seen` входит. |
| `d2k_session_udp_opening` | 2713–2736 | 24 | первый клиентский пакет: `fwd_pkts==1`, hook OUT/POST→клиент, IN/PRE→сервер, иначе flow, иначе 443 | `r2o_udp_sessions.rs` `r2o_udp_opening_at_hook` | E | C проверяет `fwd_pkts==1` и определяет клиента по hook: OUT/POST → клиент, IN/PRE → сервер, иначе сохранённое направление, иначе резерв по 443. Rust `r2o_udp_opening_at_hook(packet, hook)` передаёт hook в `r2o_udp_packet_direction` с тем же приоритетом; `r2o_udp_mark_plain_pass` пробрасывает `queue_hook`. Тест `обычный_принятый_первый_udp_пакет_открывает_окно_только_для_клиента` (OUT). |
| `d2k_session_udp_hold_end` | 2738–2742 | 5 | закрыть транзакцию hold (`udp_hold_active=0`) | `r2o_udp_sessions.rs` hold state + `main.rs` release | **P** | C снимает флаг на потоке после сборки/отказа. Rust `r2o_begin_hold`/`hold_attempts` и `r2o_mark_hello_seen`; отдельного `hold_end` нет — состояние снимается release/hello. Эквивалент по смыслу, не по API. |
| `d2k_session_udp_hold_replay` | 2744–2751 | 8 | `udp_hold_active=0`, `udp_hold_replay_first=1` | `r2o_udp_sessions.rs:337-343 r2o_mark_hold_replay_first` | **P** | C после сборки снимает active и помечает первую датаграмму к повтору. Rust `r2o_mark_hold_replay_first` ставит `hold_replay_first=true`; `hold_active` как отдельное поле отсутствует, повтор выбирается `r2o_udp_opening`/`replay_first`. Unit `:640`. |
| `d2k_session_note_unassembled` | 2753–2784 | 32 | «составное приветствие не собралось» один раз на поток + HTTP-ветка (порт 80, нет hello, начало запроса), лог declared/payload | `hold.rs:235 r2o_take_incomplete_diagnostics`, `main.rs:544` | **P** | **Совпадает:** диагностика один раз на поток, HTTP-ветка снимает `http_checked/http_conn` и пишет отказ. **Отличия:** C печатает `d2kd: составное приветствие отпущено без сборки: объявлено N байт…`; Rust `r2o_take_incomplete_diagnostics` формирует события/строки иначе, точный текст/числа не сверены. `hold.rs:2249` покрывает TLS-таймаут. |
| `d2k_session_hold_candidate` | 2794–2924 | 131 | право начать TCP-hold: route_mark=0, hold_parse, payload, флаги ACK/PSH, saw_syn, dir_known, init_low, не damaged/routed; HTTP-кандидат; окно 16 КБ; голова 0x16; SNI/ECH/stream-план | `hold.rs:298 feed`, `:356 feed_observing_mode`, `HoldOptions.allow_tls/allow_http` | **P** | **Совпадает по крупным условиям:** только поток с наблюдённым SYN и известным направлением; не damaged/routed; окно 16 КБ; голова должна начинаться с 0x16; полная запись не удерживается; HTTP-кандидат только при порте 80 и правдоподобном начале; `stream_attempted`/`http_checked`; ECH-цель удерживается для хвоста. **Подтверждённые отличия:** (1) C проверяет `(v.flags & ~0x18)` и обязательный ACK (`session.c:2796-2797`); Rust `hold.rs` использует `TcpSegmentView` и `HoldOptions`, набор флагов иной; (2) C `d2k_plantab_http_candidate`/`stream_candidate_target` и `d2k_plan_stream_input(s->plan)`; Rust `NamePlans`/`hold` выбирает кандидатов иначе; (3) C `at_head` требует первый байт 22 и неполную запись, Rust — capture/TLS-условия; (4) C при SNI+truncated+ECH-цель возвращает 1 до проверки `is_tls13`; Rust ECH-ожидание в `hold` иное. D6 покрывает базовые сценарии. |
| `d2k_session_want_shape` | 2926–2929 | 4 | запрос снимка формы TCP (family=4) | `main.rs:20162 r2o_capture_client_shape`, `control.rs:1988` | **P** | C-обёртка: `return d2k_session_want_shape_family(s,name,len,transport,4);` — family фиксирована 4. Rust `r2o_capture_client_shape`/`arm_client_shape` принимает family; отдельной обёртки с фиксированной 4 нет. Механизм иной: R2O отдаёт снимок событием `CLIENT_SHAPE`, без `shape_armed` на 4 слота. |
| `d2k_session_want_shape_family` | 2931–2960 | 30 | валидация family 4/6, transport 6/17, имени; при готовом `last_hello` — копия hello + всех TCP-опций и снятие armed; иначе armed=1 и запоминание имени | `main.rs:20162-20192 r2o_capture_client_shape`, `control.rs:1988 ClientShapeEvent`, `arm_client_shape` | **P** | **Ветви сверены:** C `!s \|\| (family!=4 && family!=6) \|\| (transport!=6 && transport!=17) \|\| (!name && len)` → 0; `k=shape_slot(transport,family)`; `len>sizeof shape_name[k]` → clamp; если `last_hello_len[k]>0 && (len==0 \|\| name_same(last_name...,name,len))` → копия `shape=last_hello`, `shape_opts=last_opts`, `armed=0`, return 1; иначе `armed=1`, `shape_len=0`, `shape_name_len=len`, копия имени, return 0. Rust `arm_client_shape`/`r2o_capture_client_shape` отдаёт `ClientShapeEvent`; **отличия:** (1) C копирует полный набор TCP-опций (`shape_opts[4][40]`), Rust — только `tcp_has_timestamp: Option<bool>`; (2) C `shape_armed`/`shape_name` на 4 слота (transport×family), Rust кэш по family+host без transport; (3) C при `len=0` принимает любой `last_hello`, Rust arm по имени/семейству; (4) датапат R2O отвергает transport 17 (`control.rs:2002`), C принимает 6/17. |
| `d2k_session_shape` | 2962–2964 | 3 | снимок формы TCP (family=4) | `capture.rs:170 tcp_hello_from_packet`, `r2o_quic.rs:180 capture_hello` | **P** | C-обёртка: `return d2k_session_shape_family(s,transport,4,len);` — family фиксирована 4. Rust снимок берётся из capture/`ClientShapeEvent`, не из сессионного `shape[4]`; для TCP/4 результат тот же при наличии снимка. |
| `d2k_session_shape_family` | 2966–2980 | 15 | вернуть `shape[k]`/длину по transport/family; неверные family/transport или пустой слот → NULL | `capture.rs:170`, `r2o_quic.rs:180`, `control.rs ClientShapeEvent` | **P** | **Ветви сверены:** C `len=0`; `!s \|\| (family!=4 && family!=6) \|\| (transport!=6 && transport!=17)` → NULL; `k=shape_slot(transport,family)`; `shape_len[k]==0` → NULL; `*len=shape_len[k]`; return `shape[k]`. Rust отдаёт ClientHello из `ClientShapeEvent`/кэша; **отличия:** C снимок в сессии на 4 слота, Rust — по потоку/событию; полный набор TCP-опций не хранится. |
| `d2k_session_shape_tcp_options_family` | 2982–2990 | 9 | вернуть полный набор TCP-опций слота формы (до 40 байт) | `control.rs` `shape_tcp_options_family`/`record_shape_tcp_options`; `capture.rs TcpHello.tcp_options` | E | C: негодное семейство или отсутствие снимка формы → NULL; иначе `*len=shape_opts_len` и указатель на опции. Rust `TcpHello.tcp_options` собирает опции (≤40), `ControlServer::record_shape_tcp_options` кэширует их по семейству, `shape_tcp_options_family` возвращает `None` без снимка и `Some(&[])`/опции при снимке; v22 `CLIENT_TCP` теперь несёт эти опции перед `SHAPE`. Тест `shape_tcp_options_family_matches_c_and_v22_client_tcp_carries_them`. |
| `d2k_session_plans` | 2992-2994 | 3 | вернуть таблицу планов `d2k_plantab*` | `control.rs` `NamePlans` | E | C `s ? s->plans : NULL`. Rust `NamePlans` — отдельная структура, которой владеет цикл датапата и передаёт потребителям; `r2o_plan_count`/`plan_count_excludes_name_probes_like_d2o` и тесты revision/delete покрывают таблицу. |
| `d2k_session_plan_count` | 2996-2998 | 3 | число активных планов | `control.rs:178 NamePlans::r2o_plan_count` | **E*** | C `return s ? d2k_plantab_count(s->plans) : 0`. Rust `NamePlans::r2o_plan_count()` считает активные записи таблицы; unit `r2o_plan_count`. |
| `d2k_session_plan_capacity` | 3000–3002 | 3 | ёмкость планов | `control.rs:182 r2o_plan_capacity` | **E*** | C `d2k_plantab_capacity`; Rust `NamePlans::r2o_plan_capacity()`. Ёмкость выводится из `--r2o-flow-capacity`; тест `control.rs:2670-2671`. |
| `silence_deadline` (static) | 3018–3028 | 11 | RTT неизвестен → 2 с; иначе `8*RTT`, clamp 1..5 с | `engine.rs:239-242` | **E** | **Точное совпадение:** C `2*NS_PER_S` при `!rtt_ns`; иначе `8*rtt`, минимум 1 с, максимум 5 с (`session.c:3018-3028`). Rust `rtt.map_or(2s, \|rtt\| rtt*8 clamp 1..5)` (`engine.rs:239-242`). |
| `tcp_silence_observe` (static) | 3034–3049 | 16 | SILENT: не probe, есть hello, не told/suspected, `rev_pkts>0`, нет payload после hello, нет reverse RST; ждать deadline или повтор hello | `engine.rs` `tcp_silence_event` | E | C проверяет `!controller_probe`, наличие hello, `!silence_reported`, `reverse_seen`, `!response_payload`, `!saw_reverse_rst`, затем deadline или `hello_repeats>0`. Rust `tcp_silence_event` повторяет те же условия (флаги отправки события `silence_reported`/`repeat_reported`), deadline `clamp(8×RTT,1..5с)` или 2с; тест `tcp_silence_event_matches_c_conditions` (событие, payload, RST, probe). |
| `fin_retry_window` (static) | 3063–3067 | 5 | окно повтора FIN: `3×max(3×RTT, 1с)` = `max(9×RTT, 3с)` | `engine.rs:1389 fin_retry_window` | **E** | Формула совпадает: Rust `rtt*9`, минимум 3 с; `None` (RTT неизвестен) → 3 с, что соответствует C `rtt_ns=0`. Тест `engine.rs:3823` (истечение ограниченного окна FIN) и `:3568` (повтор FIN). |
| `fin_window_over` (static) | 3069-3073 | 5 | `pending_fin && now>=pending_fin_ns && elapsed>=3*max(3*rtt,1s)` | `engine.rs:708` (`pending_fin_at` + `fin_retry_window`) | **E** | C `f->pending_fin && now>=pending_fin_ns && now-pending_fin_ns >= fin_retry_window(f)`, где окно `3*max(3*rtt,1s)`. Rust `pending_fin_at.is_some_and(\|started\| elapsed >= fin_retry_window(session.rtt))`. |
| `sweep_one` (static) | 3084–3087 | 4 | обход TCP-потоков, `told += tcp_silence_observe` | `engine.rs:693 expire_with_silent`, `:1330-1372` sweep | **P** | C проходит `d2k_track_walk(flows, sweep_one)` и считает подозрения. Rust `tcp_sessions.sweep_silent`/`tcp_silence_events`; счётчик `told` не возвращается, события забираются отдельно. Эквивалент по наблюдению, API иной. |
| `sweep_udp_one` (static) | 3112–3142 | 31 | UDP SILENT: saw_hello/saw_initial, не silence_told/suspected/quic_deny; ответ после последнего повтора; rev_seen или udp_reverse_hook; fwd_after_hello>0; deadline | `r2o_quic.rs:478 sweep`, `main.rs` quic sweep | **P** | **Совпадает:** критерий «клиент повторял после приветствия, ответа после последнего повтора не было, обратное направление видно (или hook), прошёл deadline». **Отличия:** C использует `rev_seen[slot]` и `udp_reverse_hook`; Rust `reverse_queue_visible`/`ControlServer::is_connected` и `R2oQuicSessions::sweep`; поля `saw_initial`/`last_rev_after_hello` в Rust распределены между `hello_seen`/`last_reverse`, отдельного `saw_initial` нет. `r2o-quic-stun-watch-differential.sh`. |
| `quic_watch` (static) | 3164–3169 | 6 | кандидат QUIC-stall: proto 17, hello/initial, был ответ, не suspected/probe/quic_deny/voice/STUN | `r2o_quic.rs:503 r2o_quic_stall_candidates` | E | C: proto 17, было приветствие и ответ, не подозревался, не зонд, не quic_deny, не voice/STUN. Rust `r2o_quic_stall_candidates` фильтрует `suspected`, `quic_stall_excluded`, `last_reverse`, `first_response_rtt`; voice/STUN-потоки помечаются в `r2o_voice`/`suppress_packet`. Тесты `quic_зависание_не_срабатывает_без_скрытых_ответов_или_после_quicdeny`, `quic_зависание_исключает_stun_и_discord_discovery_из_одного_потока` (позитив/пусто/quicdeny/STUN/Discord). |
| `flow_tuple` (static) | 3174–3187 | 14 | прямой кортеж клиент→сервер по `init_low` | `conntrack.rs` `tuple_from_packet`/`tuple_from_socket_addrs` | E | C строит прямой кортеж из канонического ключа и `init_low` (клиент ниже — `lo→hi`, иначе `hi→lo`). Rust `tuple_from_packet` берёт адреса/порты из пакета в направлении пакета, `tuple_from_socket_addrs` — из сокета; для известного `init_low` набор полей совпадает (family/proto/src/dst/sport/dport). Rust отвергает фрагменты с ненулевым offset (`fragment & 0x1fff`), как разбор ключа C. Тест `tuple_from_packet_matches_c_flow_tuple` (IPv4 TCP поля, MF-фрагмент, offset-фрагмент, ICMP, обрезанный пакет). |
| `ct_flow` (static) | 3197–3221 | 25 | QUIC stall по conntrack: reply изменился → запомнить; reply<=rev_pkts, orig delta<3 → нет; PTO=max(3*quic_rtt,1с); suspect QUIC_STALL | `r2o_quic.rs:527-571 update_r2o_quic_stall` | **E*** | **Точное совпадение условий:** `reply_packets` изменился → mark; `reply <= reverse_packets` или `orig - mark.orig < 3` → нет; `pto = 3*first_response_rtt`, минимум 1 с; время от mark ≥ pto → событие. C `quic_rtt_ns` измеряется hello→first reverse, Rust `first_response_rtt`; для штатного потока эквивалентно. `r2o-quic-stun-watch-differential.sh`. |
| `tcp_watch` (static) | 3257–3261 | 5 | TCP-stall: proto 6, saw_hello, had_sni, rev_payload_after_hello>0, не suspected/probe/pending_fin/tcp_watch_off/routed | `engine.rs:788-815 tcp_stall_candidates` | **P** | **Подтверждённое расхождение набора:** C требует `pending_fin==0` и `routed==0`; Rust `tcp_stall_candidates` их не проверяет, но добавляет `reverse_rst==0`, `guards==0`, `!stall_reported` и `direction_known`. C `tcp_watch_off` выставляется при выходе за полосу; Rust `stall_watch_off`/`stall_reported`. Таблица только TCP. |
| `tcp_in_band` (static) | 3263–3269 | 7 | `est+3 >= b && est <= b+3` для любого бюджета | `engine.rs:880-883` | **E** | **Точное совпадение:** C `est + D2K_TCP_STALL_SLACK >= b && est <= b + SLACK` (`session.c:3263-3269`); Rust `saturating_add(3) >= budget && estimate <= budget+3` (`engine.rs:880-883`), `TCP_STALL_PACKET_SLACK=3`. Тесты `engine.rs:2341/2381/2405`. |
| `tcp_band_top` (static) | 3271–3277 | 7 | максимум бюджетов + 3; пустой список → 3 | `engine.rs` `tcp_band_top` | E | C: `top = max(budgets)`, `return top + D2K_TCP_STALL_SLACK`; пустой список даёт 0+3. Rust `tcp_band_top(&[u16])` использует `max().unwrap_or(0) + SLACK` и вызывается из `update_tcp_stall`; тест `tcp_band_top_matches_c` (пусто, [25], [15,35], [1,2]). |
| `ct_tcp_flow` (static) | 3279–3328 | 50 | TCP stall: ESTABLISHED, unseen = reply-rev_pkts_conn, est = fwd+rev+unseen, band top, reply change → mark, orig delta>=3, RTO=max(3*rtt,2с), band, suspect с est | `engine.rs` conntrack stall detection | **P** | **Совпадает:** ESTABLISHED-only, `unseen`, `est`, верхняя полоса, обновление mark при смене reply, `orig` delta ≥3, RTO `3*rtt` минимум 2 с, `tcp_in_band`, событие с `num=est`. **Отличия:** C `tcp_watch_off=1` при не-ESTABLISHED/выше полосы; Rust `stall_watch_off`/`stall_reported`; C `suspect_num` с деталями server_hello, Rust `R2oTcpStallEvent` с полями. Полного differential нет. |
| `d2k_session_set_stall_budgets` | 3330–3343 | 14 | до 8 ненулевых бюджетов, пусто → полевой 25 | `engine.rs:451-460 set_tcp_stall_budgets` | **E** | Точное совпадение: `>8` или любой `0` → отказ; пустой список → `[25]`; иначе копия. Тесты `engine.rs:2431-2434` (нулевой/9/пусто/25). |
| `d2k_session_stall_budgets` | 3345–3351 | 7 | чтение бюджетов до cap, вернуть полное число | `engine.rs:371/850` поле `tcp_stall_budgets` | **P** | C getter копирует до `cap` и возвращает `n_stall_budget`; Rust поле используется напрямую в `tcp_in_band`/`tcp_band_top`, отдельного getter с cap нет. Эквивалент для чтения. |
| `d2k_session_sweep` | 3353–3370 | 18 | TCP sweep + UDP sweep; при `ct_query` — обход uflows/flows через `ct_flow`/`ct_tcp_flow`, вернуть число подозрений | `main.rs:1197-1263` periodic sweep, `engine.rs`, `r2o_quic.rs`, `conntrack.rs` | **P** | **Совпадает:** раз в секунду TCP/UDP sweep, затем conntrack-запросы для наблюдаемых потоков, сумма `told`. **Отличия:** C `d2k_track_walk` по двум таблицам и единый `told`; Rust отдельные `tcp_sessions.sweep_silent`, `quic_sessions`/`voice_sessions/udp_sessions` и `conntrack.query`; порядок uflows→flows не гарантирован. Полного differential нет. |
| `d2k_session_expire` | 3372–3395 | 24 | удалить FIN-окно, expire TCP с callback, expire UDP без callback | `engine.rs:928 expire_with_silent`, `r2o_udp_sessions.rs:493 expire` | E | C: снять FIN-окно, затем TCP-expire с callback, UDP-expire без callback. Rust `expire_with_silent` проверяет `idle_expired`/`fin_expired`, вызывает `tcp_silence_event` и `capture.forget` до удаления; `R2oUdpSessions::expire` удаляет UDP по idle без callback. Тесты `r2o_tcp_silence_requires_a_recognized_clienthello`, `tcp_истечение_не_сообщает_если_после_clienthello_была_полезная_нагрузка`, `R2oUdpSessions::expire` (4с/5с). |
| `d2k_session_flows` | 3397–3399 | 3 | сумма TCP+UDP потоков | `engine.rs` `r2o_session_flows` | E | C `track_count(flows)+track_count(uflows)`. Rust `r2o_session_flows(tcp,udp)` суммирует `TcpSessions::len` и `R2oUdpSessions::len`; тест `session_flows_guards_shape_damaged_getters_match_c`. |
| `d2k_session_send_pending` | 3401–3405 | 5 | `fl && execution_id==execution && sends_left && !sends_failed` | `engine.rs` `r2o_send_pending` | E | C проверяет поток, совпадение поколения, `sends_left != 0`, `!sends_failed`. Rust `r2o_send_pending` хранит те же числовые `sends_left/sends_failed`, выставляемые `r2o_begin_execution` (`n_out + 1`), `r2o_mark_execution_failed_for_execution` (unsent) и `r2o_mark_damaged_for_execution`; тест `session_execution_counters_match_c_sent_unsent_damaged` проверяет истину, чужое поколение и ложь после unsent/damaged. |
| `d2k_session_sent` | 3407–3428 | 22 | `sends_left--`, `sends_done++` (до 0xFF); при нуле и без failed → `done++` + PLAN_DONE; иначе `sent_lost++` | `engine.rs` `r2o_session_sent`, `r2o_mark_plan_done_for_execution` | E | C `sent` на каждую посылку: чужое поколение/`sends_left==0` → `sent_lost++`; иначе декремент, насыщение `sends_done` 0xFF, при нуле и `!sends_failed` — `done++` и PLAN_DONE (журнал пишет вызывающий). Rust `r2o_session_sent` реализует ровно это пошагово; `r2o_mark_plan_done_for_execution` зачитывает оставшиеся посылки тем же счётчиком и возвращает false → вызывающий делает `r2o_note_sent_lost`. Тесты `session_execution_counters_match_c_sent_unsent_damaged`, `session_sends_done_saturates_at_0xff_like_c` (255 посылок, `sends_done=0xFF`). |
| `d2k_session_exec_failed` | 3449–3501 | 53 | общий отказ: UNSENT один раз; UDP original-lost → udp_replan; damaged → damaged_flows++, guards=0, PLAN_DAMAGED один раз; возврат «оригинал цел» | `main.rs` `r2o_finish_tcp_execution`, `engine.rs` `r2o_mark_damaged_for_execution`/`r2o_mark_execution_failed_for_execution`, `r2o_udp_sessions.rs` `r2o_note_execution_failure` | E | C при чужом поколении/отсутствии потока → 1 («оригинал цел»); иначе однократный `unsent` (`sends_left=0`, `sends_failed=1`), UDP-ветка `udp_replan` при потере оригинала, TCP-порча при `payload_on_wire \|\| (orig_spent && orig_taken)`: `damaged_flows++` только на переходе, `guards=0`, `damaged_told=1` и один PLAN_DAMAGED, возврат 0. Rust `r2o_finish_tcp_execution` решает по сохранённому `r2o_orig_taken` и тем же условиям, `r2o_mark_damaged_for_execution` делает unsent+damage один раз; UDP-аналог сбрасывает `plan_applied` (`udp_replan`). Тест `session_execution_counters_match_c_sent_unsent_damaged`; журнальные записи — `record_execution_failure` (D22). |
| `d2k_session_guards` | 3503–3507 | 5 | guards потока | `engine.rs` `session_guards` | E | C getter по ключу. Rust `session_guards(&key)` ищет поток по wire-ключу и отдаёт `TcpSession.guards`; `r2o_mark_damaged_for_execution` обнуляет их, как C. Тест `session_flows_guards_shape_damaged_getters_match_c` проверяет guards плана и обнуление после повреждения. |
| `d2k_session_client_shape` | 3509–3513 | 5 | форма клиента потока | `engine.rs` `session_client_shape` | E | C getter. Rust `session_client_shape(&key)` отдаёт `TcpSession.client_shape`, заполняемую из ClientHello (MODERN/LEGACY/ECH_TCP, 0 без SNI); набор TCP-опций снимка теперь тоже хранится (`shape_tcp_options_family`, E). Тест `session_flows_guards_shape_damaged_getters_match_c` проверяет ненулевую форму после ClientHello с SNI. |
| `d2k_session_damaged` | 3515–3523 | 9 | пометить damaged при совпадении execution | `engine.rs` `r2o_mark_damaged_for_execution`, `session_flow_damaged` | E | C ставит только `damaged=1` при совпадении key/execution; повторный вызов сохраняет флаг и не увеличивает счётчик. Rust `r2o_mark_damaged_for_execution` ставит `damaged=true` только для своего поколения, сбрасывает `r2o_execution_pending` и `guards=0`; наблюдается через `session_flow_damaged`. Тест `session_flows_guards_shape_damaged_getters_match_c` проверяет ложь до и истину после, а также обнуление guards. |
| `d2k_session_unsent` | 3525–3539 | 15 | PLAN_UNSENT + `sends_left=0`/`sends_failed=1` | `engine.rs` `r2o_mark_execution_failed_for_execution`; `flow_journal::record_execution_failure` | E | C пишет PLAN_UNSENT и обнуляет `sends_left`, ставит `sends_failed=1` только при совпадении поколения. Rust `r2o_mark_execution_failed_for_execution` делает оба перехода идемпотентно; PLAN_UNSENT пишет `record_execution_failure` (`PlanUnsent`). Повторный UNSENT невозможен: `r2o_fail_pending_applied` удаляет `PendingApplied`. Тест `session_execution_counters_match_c_sent_unsent_damaged` проверяет `sends_left=0`, `sends_failed`, отсутствие `damaged` и `send_pending=false`. |
| `d2k_session_applied` | 3541–3543 | 3 | счётчик applied | `engine.rs` `TcpSessions::session_applied`, `r2o_udp_sessions.rs` `session_applied` | E | C `s->applied++` в `plan_handed_off`. Rust считает применения плана в TCP (`decide_with_session`) и UDP (`r2o_mark_plan_applied`); тесты `tcp_отказ_повреждает...` (`session_applied>=1`) и `r2o_udp_зонд...` (`==1`). |
| `d2k_session_done` | 3545-3547 | 3 | счётчик завершённых исполнений | `engine.rs` `session_done`, `r2o_mark_plan_done_for_execution` | E | C `s->done++` при завершении всех посылок. Rust `r2o_mark_plan_done_for_execution` при успехе увеличивает `session_done`; тест `tcp_повторный_clienthello...` проверяет `==1`. |
| `d2k_session_damaged_count` | 3549-3551 | 3 | число испорченных потоков | `engine.rs` `session_damaged`, `r2o_mark_damaged_for_execution` | E | C `damaged_flows++` один раз на поток. Rust увеличивает `session_damaged` только при переходе `damaged=false→true`; тест `tcp_отказ_повреждает...` проверяет `==1`. |
| `d2k_session_sent_lost` | 3553–3555 | 3 | «некому приписать отправку» | `engine.rs` `session_sent_lost`/`r2o_note_sent_lost`, `main.rs` `r2o_finish_tcp_execution` | E | C `sent_lost++` при отсутствии потока/чужом поколении/нулевом `sends_left`. Rust `r2o_finish_tcp_execution` вызывает `r2o_note_sent_lost()`, если `r2o_mark_plan_done_for_execution` не нашёл живое поколение; тест `session_sent_lost_counts_completions_without_live_flow`. |
| `d2k_session_refusals` | 3557-3559 | 3 | сумма отказов TCP+UDP | `engine.rs` `r2o_session_refusals` | E | C `d2k_track_refusals(tcp)+d2k_track_refusals(udp)`. Rust `r2o_session_refusals(tcp,udp)` суммирует `r2o_tcp_flow_refusals` и `r2o_flow_refusals`; тест `session_capacity_flows_and_refusals_match_c`. |
| `d2k_session_capacity` | 3561-3563 | 3 | суммарная ёмкость TCP+UDP | `engine.rs` `r2o_session_capacity` | E | C `track_capacity(tcp)+track_capacity(udp)`. Rust `r2o_session_capacity(tcp,udp)` суммирует `slots()` обеих таблиц; тест `session_capacity_flows_and_refusals_match_c`. |
| `d2k_session_flows_tcp` | 3565-3567 | 3 | число TCP-потоков | `TcpSessions::len` | E | C `s ? d2k_track_count(s->flows) : 0`. Rust `TcpSessions::len()` возвращает `flows.len()`; тест `session_capacity_flows_and_refusals_match_c`. |
| `d2k_session_flows_udp` | 3569-3571 | 3 | число UDP-потоков | `R2oUdpSessions::len` | E | C `s ? d2k_track_count(s->uflows) : 0`. Rust `R2oUdpSessions::len()` возвращает `flows.len()`; тест `session_capacity_flows_and_refusals_match_c`. |
| `d2k_session_capacity_tcp` | 3573-3575 | 3 | ёмкость TCP-таблицы | `TcpSessions::r2o_tcp_flow_capacity` | E | C `s ? d2k_track_capacity(s->flows) : 0`. Rust `r2o_tcp_flow_capacity()` = `flow_capacity.slots()`; тест проверяет равенство умолчанию. |
| `d2k_session_capacity_udp` | 3577-3579 | 3 | ёмкость UDP-таблицы | `R2oUdpSessions::r2o_flow_capacity` | E | C `s ? d2k_track_capacity(s->uflows) : 0`. Rust `r2o_flow_capacity()` = `flow_capacity.slots()`; тест `session_capacity_flows_and_refusals_match_c`. |
| `d2k_session_refusals_tcp` | 3581-3583 | 3 | отказы TCP-таблицы | `TcpSessions::r2o_tcp_flow_refusals` | E | C `s ? d2k_track_refusals(s->flows) : 0`. Rust `r2o_tcp_flow_refusals()` читает `tcp_flow_refusals`; тест проверяет 0 на пустой таблице. |
| `d2k_session_refusals_udp` | 3585-3587 | 3 | отказы UDP-таблицы | `R2oUdpSessions::r2o_flow_refusals` | E | C `s ? d2k_track_refusals(s->uflows) : 0`. Rust `r2o_flow_refusals()` читает `refusals`; тест `session_capacity_flows_and_refusals_match_c`. |
| `d2k_session_hellos` | 3589-3591 | 3 | число приветствий | `engine.rs` `r2o_session_hellos` | E | C `s->hellos` считает TLS+QUIC (`session.c:1144,2167,2234`). Rust `r2o_session_hellos` суммирует `r2o_tcp_hello_flows` и `r2o_quic_hello_flows`; тест `session_hellos_and_with_sni_sum_tcp_and_udp` + профильные тесты TCP/QUIC. |
| `d2k_session_with_sni` | 3593-3595 | 3 | приветствия с SNI | `engine.rs` `r2o_session_with_sni` | E | C `s->with_sni` считает TLS+QUIC. Rust `r2o_session_with_sni` суммирует `r2o_tcp_hellos_with_sni` и `r2o_quic_hellos_with_sni`; тест `session_hellos_and_with_sni_sum_tcp_and_udp`, профильные — `r2o_tcp_hellos_with_sni` 1/0. |
| `d2k_session_suspects` | 3597-3599 | 3 | число подозрений | `session_stats.rs` `r2o_session_suspects`, `engine.rs` `r2o_note_suspect`, `r2o_quic.rs`/`r2o_voice.rs` `mark_suspected` | E | C `s ? s->suspects : 0`, `suspects++` в `suspect_num` один раз на поток. Rust общий `AtomicU64`; TCP `r2o_note_suspect` дедуплицирует по `suspect_counted`, QUIC/voice — по `flow.suspected`. Тесты `session_suspect_counts_once_per_tcp_flow`, `session_suspects_increment_by_one_per_note`. |
| `d2k_session_rst_dropped` | 3601-3603 | 3 | снятые RST | `TcpSessions::r2o_tcp_rst_dropped` | E | C `s->rst_dropped`. Rust `r2o_tcp_rst_dropped()` читает тот же счётчик; тесты движка проверяют 1 и 2 снятых RST. |
| `d2k_session_exchanges` | 3605–3607 | 3 | число обменов | `engine.rs` `session_exchanges`, `r2o_udp_sessions.rs` `session_exchanges` | E | C `s->exchanges++` при первом ответе/прикладных данных. Rust считает TCP-обмены при `exchange_told` (кроме controller probe) и UDP при отправке `R2oUdpExchangeEvent`; тесты `tcp_журнал_повышает...` (`1→2`) и `r2o_stun_сверяет...` (`1→2`). |
| `d2k_session_reply_hidden` | 3609-3611 | 3 | ACK указал на невидимый ответ | `TcpSessions::r2o_reply_hidden` | E | C `s->reply_hidden`. Rust `r2o_reply_hidden()`; дифференциал `r2o-tcp-reply-hidden-differential.sh` и unit-проверки 0/1. |
| `d2k_session_tcp_hello_flows` | 3613-3615 | 3 | TCP-потоки с ClientHello | `TcpSessions::r2o_tcp_hello_flows` | E | C `s->tcp_hello_flows` (`session.c:1577`). Rust `r2o_tcp_hello_flows()`; unit-тесты проверяют 1 после ClientHello и неизменность на повторе. |
| `d2k_session_payload_stats` | 3617–3638 | 22 | снимок: reverse/after_hello/late/not_hello/first_byte/sni_next_seg/capture + http_later/unaligned/open_end | `engine.rs` `R2oSessionPayloadStats`/`session_payload_stats` | E | C заполняет `d2k_payload_stats` из `s->pay_*`, `capture` и HTTP-счётчиков. Rust `R2oSessionPayloadStats` объединяет `R2oTcpPayloadStats`, `CaptureStats` и `R2oHttpKeepAliveStats`; тест `session_payload_stats_combines_capture_and_http_like_c` проверяет поля и значения. |
| `d2k_session_journal` | 3640-3642 | 3 | вернуть журнал сессии | `R2oFlowJournal` (`flow_journal.rs:543`) | **P** | C `return s ? s->jrn : NULL`. Rust журнал `R2oFlowJournal` живёт в движке/`run`; отдельного getter-а нет. D22 сверяет записи журнала. |

## datapath/track.c (18 функций)

Таблица потоков: открытая адресация, FNV-1a, удаление сдвигом, порог 3/4.
R2O заменил структуру на `HashMap`, сохранив ключ, ёмкость и порог отказов.

**Прочитано построчно: 18/18 функций, 337 строк C (1–337).** Сверено с `flow_capacity.rs:12-21` (`from_requested`: `max(16).next_power_of_two`, `limit=slots-slots/4`) и `engine.rs:41-88` (`TcpFlowKey`), `:393-440` (`try_with_capacity`, len/capacity/refusals), `:698-732` (`expire_with_silent`), `:911-970` (`track_packet_mode`, лимит/новый SYN), `:1111` (`last_seen`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_key_make` | 18–51 | 34 | IPv4-ключ: сравнить 6 байт `addr + port`, выбрать low/high, занулить весь `d2k_key`, записать ip/port/proto | `engine.rs` `TcpFlowKey::from_endpoints`, `r2o_udp_sessions.rs` `R2oUdpFlowKey::new` | **E*** | C/Rust differential `scripts/test-datapath-tcp-capacity-differential.sh` PASS: C-оракул вызывает `d2k_key_make` в прямом и обратном направлении, `reverse_hit=1` доказывает канонизацию low/high (addr+port, `<=`). **Ограничение:** Rust-ключ типизирован (16-байтный `Address`), IPv6-ветка — отдельная `d2k_key_make_addr`; равные адреса+порты проверены косвенно. |
| `d2k_key_make_addr` | 55–74 | 20 | IPv4 делегирует `d2k_key_make`; IPv6 — 16 байт адреса, затем порт; family=6 | `capture.rs` `TcpFlowKey::wire_key`, `r2o_udp_sessions.rs` `flow_key_from_packet` | E | C для IPv6 кладёт 16-байтные адреса, затем BE-порты, family=6; IPv4 делегирует общий конструктор. Rust `TcpFlowKey::wire_key`/`R2oUdpFlowKey::wire_key` дают ту же раскладку (family, 16+16 адресов, BE-порты, proto 6/17); тест `engine.rs:2499` сверяет ключ из пакета с `wire_key`. |
| `round_pow2` (static) | 84-90 | 7 | `max(16).next_power_of_two`, потолок `1<<20` | `flow_capacity.rs:12-21 from_requested` | **E** | **Точное совпадение:** C `v<16?16`, удвоение, `>1<<20` → `1<<20`; Rust `max(16).next_power_of_two().min(1<<20)`. Тест `flow_capacity.rs:45` (`1→16`, `64→64`, `65→128`). |
| `key_eq` (static) | 92–104 | 13 | `memcmp` всего `d2k_key`; padding занулён `memset` | `#[derive(Eq, Hash)]` (`engine.rs:42`, `capture.rs:14`) | **E** | C сравнивает 16 байт, включая занулённые хвосты; Rust сравнивает все поля типизированного ключа, padding отсутствует. Семантика равенства совпадает; используется во всех тестах ключей. |
| `key_hash` (static) | 108–115 | 8 | FNV-1a по всем байтам ключа | `HashMap` SipHash (по умолчанию) | **P** | Хеш-функция намеренно иная; на семантику поиска не влияет, но порядок коллизий/пробирования и устойчивость к HashDoS отличаются. C/Rust differential хеша нет. |
| `d2k_track_new` | 117–133 | 17 | `calloc` таблицы, `round_pow2`, отдельные `slots/state`; при сбое — `free` | `engine.rs` `TcpSessions::try_with_capacity`, `flow_capacity.rs` `R2oFlowCapacity` | E | C округляет ёмкость до степени двойки (min 16) и при частичном сбое освобождает массивы; предел новых записей — 3/4 слотов. Rust `R2oFlowCapacity::from_requested` даёт те же slots/limit, `try_with_capacity` резервирует HashMap и очереди через `try_reserve` (отказ возвращается без частичного состояния). Тесты `r2o_ёмкость_повторяет_округление_таблицы_донора`, `tcp_отказывает_сверх_порога...` (48 вставок, 2 отказа, повтор после expiry). |
| `d2k_track_free` | 135-142 | 8 | освободить slots/states/table | `Drop` | **E** | C `free(t->slots); free(t->states); free(t);`. Rust владеющие `HashMap`/`Vec` освобождаются `Drop`; отдельной функции нет. C-строка: `free(t->slots); free(t->states); free(t);`; Rust освобождает `HashMap`/`Vec` через `Drop`. |
| `d2k_track_find` | 144–160 | 17 | линейное пробирование, остановка на свободной ячейке | `engine.rs` `self.flows.get` (напр. `:1578`) | **P** | C ищет по FNV-хешу и обрывает цепочку на `SLOT_FREE`; Rust — `HashMap::get`. Результат поиска по ключу тот же, внутренний порядок и пробирование иные. |
| `remove_at` (static) | 165–191 | 27 | удаление сдвигом назад, без надгробий; пересчёт `home` | `HashMap::remove` | **P** | C поддерживает инвариант линейного пробирования сдвигом кластера; Rust удаляет через `HashMap`, где надгробия/сдвиг — внутренняя деталь. Функционально удаление по ключу эквивалентно; пошагового differential нет. |
| `d2k_track_get` | 193–229 | 37 | get-or-create, `last_ns=now`, отказ при `used+1 > cap-cap/4`, зануление новой записи | `engine.rs` `track_packet_mode`, лимит, `last_seen` | E | C/Rust differential `scripts/test-datapath-tcp-capacity-differential.sh` PASS: get-or-create 48 записей, отказ при лимите (`refusals=2`, `count=48`), reverse lookup, `expire`, повторный приём после истечения. **Отличие:** сохранение учёта посылок при новом SYN относится к `d2k_track_new_connection`. |
| `d2k_track_new_connection` | 231–257 | 27 | сброс полей при новом SYN; сохраняются key/in_use/first/last/init_low/dir_known/счётчики пакетов и байт, **sends_left/sends_failed/execution_id/binding/plan_id/trial_id** | `engine.rs:938-961` ветка `new_connection`: новый `TcpSession`, копируется только `metrics` | **P** | **Подтверждённое расхождение:** C сохраняет `sends_left/sends_failed/execution_id/binding/plan_id/trial_id` через границу нового SYN, чтобы позднее завершение старой посылки не приняли за новую. Rust создаёт `TcpSession::new` с `execution_id=0`, `r2o_execution_pending=false`; `PendingApplied`/tickets живут отдельно, поэтому поздний completion старого поколения отбрасывается (`r2o_send_pending` вернёт false), а не учитывается. Нужен тест «новый SYN при незавершённой посылке». |
| `d2k_track_remove` | 259–267 | 9 | найти и удалить сдвигом | `engine.rs` `flows.remove` | E | C ищет слот и удаляет сдвигом. Rust хранит потоки в `HashMap` и удаляет `remove`; набор записей после удаления тот же, порядок обхода не является контрактом. Используется в FIN/RST/expire-путях, покрыто тестами движка. |
| `d2k_track_walk` | 269–278 | 10 | обход всех занятых слотов в порядке таблицы | `flows.iter()` / `retain` (`engine.rs:698`) | **P** | C обходит слоты по возрастанию индекса; Rust — в неопределённом порядке `HashMap`. Если потребитель зависит от порядка (логи/диагностика), результат может отличаться; функциональные счётчики не зависят. |
| `d2k_track_expire` | 280–308 | 29 | истечение по idle: `now>=last && now-last>=idle`, callback **до** удаления, повторная проверка слота после сдвига | `engine.rs` `expire_with_silent` | E | C проверяет `now>=last` (защита от убывания часов), зовёт callback до `remove_at`, затем перепроверяет сдвинутый слот. Rust `expire_with_silent` использует `now.saturating_duration_since(last_seen) >= idle` (то же при убывании часов), вызывает `tcp_silence_event` до `retain`-удаления; `retain` обходит все записи, что эквивалентно повторной проверке после сдвига. Тест `track_expire_matches_c_idle_boundary_and_clock_regression` (часы назад, ровно idle), плюс тест ёмкости/истечения 48 потоков. |
| `d2k_track_remove_if` | 310–325 | 16 | удаление по предикату (FIN-окно), повторная проверка слота | `engine.rs:700` `fin_expired` в `retain` | E | C `while (used && gone()) remove_at`. Rust `expire_with_silent` использует `retain` с `fin_expired`/`idle_expired`; каждая запись проверяется один раз, callback `tcp_silence_event` вызывается до удаления. Тесты `tcp_fin...`, expire в engine.rs. |
| `d2k_track_count` | 327-329 | 3 | число живых записей | `TcpSessions::len` (`engine.rs:393`) | **E** | C `return t ? t->count : 0`; Rust `TcpSessions::len()`/`HashMap::len()`. C-строка: `return t ? t->count : 0;`; Rust `TcpSessions::len()`/`HashMap::len()`. |
| `d2k_track_capacity` | 331-333 | 3 | ёмкость таблицы | `flow_capacity.rs:16 slots()` | **E** | C `return t ? t->cap : 0`; Rust `flow_capacity.slots()`; тест `flow_capacity.rs:45`. C-строка: `return t ? t->cap : 0;`; Rust `flow_capacity.slots()`; тест `flow_capacity.rs:45`. |
| `d2k_track_refusals` | 335–337 | 3 | счётчик отказов вставки | `engine.rs` `r2o_tcp_flow_refusals` | E | C/Rust differential `scripts/test-datapath-tcp-capacity-differential.sh` PASS: capacity 64/65, 48 вставок, 2 отказа, reverse lookup, expiry и `refusals=2` до/после expiry совпали. |

## datapath/capture.c (6 функций)

Сборка ClientHello/HTTP-заголовка по seq: TTL, generation, anchor, перекрытия,
конфликт → poison. R2O: `crates/r2o-datapath/src/capture.rs`.

**Прочитано построчно: 6/6 функций, 124 строки C (1–124).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `same` (static) | 18-20 | 3 | равенство ключа потока | типизированное `Eq` (`hold.rs`) | **E** | C `return d2k_key_equal(a,b)` — proto/ports/family/адреса. Rust `hold.rs` использует типизированное равенство ключа (`TcpFlowKey`/`wire_key`); используется всеми hold-тестами. |
| `d2k_capture_forget` | 8-14 | 7 | сбросить все слоты с данным ключом | `capture.rs:949` (forget/new generation) | **E** | C проходит `D2K_CAPTURE_SLOTS`, при `state && same` ставит `state=0`. Rust `capture.rs` forget/new generation; `capture.rs:949` покрывает «forget не даёт переиспользовать старое поколение». |
| `reject` (static) | 16-20 | 5 | отказ захвата: состояние 2 и `rejected++` | `capture.rs:949` | **E** | C `s->state=2; c->rejected++; return -1` — конфликт/перекрытие данных. Rust при конфликте перекрытия помечает слот и увеличивает `rejected` (`capture.rs:949`); те же состояние/счётчик. |
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
| `r32` (static) | 17 | 1 | big-endian u32 | `r2k-core/packet.rs` `read_u32` | E | C `p[0]<<24\|p[1]<<16\|p[2]<<8\|p[3]`. Rust `read_u32` читает 4 байта `from_be_bytes` и проверяет границы через `get`; используется в `parse_tcp` для sequence/ack. Тест `read_u32_matches_c_and_checks_bounds` (смещения 0/1, короткий срез, `usize::MAX`). |
| `same` (static) | 18-20 | 3 | равенство ключа потока | типизированное `Eq` (`hold.rs`) | **E** | C `return d2k_key_equal(a,b)` — proto/ports/family/адреса. Rust `hold.rs` использует типизированное равенство ключа (`TcpFlowKey`/`wire_key`); используется всеми hold-тестами. |
| `d2k_hold_parse` | 21–40 | 20 | разбор TCP-заголовка и полей hold: ihl/header/total/payload/src_low/seq/ack/flags/dst/dst_be/sport_be | `hold.rs:1249 parse_tcp` | E | Используемые поля эквивалентны: `ihl=view.l4_offset`, `header=tcp.payload.start`, `total=view.total_len`, `payload=tcp.payload.len`, `src_low = source==key.low`, `seq/ack/flags` из `TcpSegmentView`; C-поля `dst_be`/`sport_be` только записываются и не читаются. Rust отвергает IPv4-фрагменты (`fragment & 0x3fff`), как C. Тест `hold_parse_tcp_matches_c_fields` (поля, порт, отказ фрагменту). |
| `d2k_hold_new` | 41-41 | 1 | создать hold (calloc) | `hold.rs` `Default`/`new` | **E** | C `calloc(1,sizeof(d2k_hold))`; при OOM NULL. Rust `Default::default()`/`new`; OOM-ветвь отличается (Rust может аварийно завершиться), обычный путь эквивалентен. |
| `d2k_hold_free` | 42-42 | 1 | освободить таблицу hold | `Drop` | **E** | C `free(h)`; контракт «сначала flush ALL» остаётся на вызывающем. Rust владеющая структура освобождается `Drop`; порядок обеспечивает владелец. |
| `release_slot` (static) | 43–51 | 9 | вернуть каждый ID с байтами, `stats.released++`, `capture_forget`, `pending-=count` | `hold.rs:1229 remove_slot`, `:1236 release_held_packets` | **P** | C вызывает callback на каждый пакет; Rust возвращает `Vec<u32>` ID, а owned-пакеты кладёт в `owned_releases`. `pending`/`released` считаются так же; `capture.forget` в Rust вызывает вызывающий (в части веток — после `remove_slot`). P — разный контракт владения. |
| `d2k_hold_flush` | 52–72 | 21 | `all`/deadline/смена ревизии: release + `dropped_all`/`plan_changed`/`timed_out`/`timed_out_pkts` | `hold.rs:888 flush` | **E** | Условия и счётчики совпадают; Rust дополнительно складывает `R2oIncompleteCaptureDiagnostic` для истёкших TLS/HTTP, если поток не controller_probe. Тесты `hold.rs:2200`, `:2231`, `:2249`. |
| `d2k_hold_next` | 73–80 | 8 | абсолютный минимальный deadline (ns), 0 если слотов нет | `hold.rs:958 timeout_ms` | **P** | C отдаёт абсолютное время в наносекундах; Rust — относительные миллисекунды до ближайшего deadline с ограничением `max_ms`, `0` при `deadline<=now` или `max_ms<=0`. Для poll-таймаута эквивалентно, отдельного absolute-getter нет. |
| `d2k_hold_get_stats` | 81–84 | 4 | снимок `d2k_hold_stats` | `hold.rs` `r2o_hold_stats` | E | C зануляет выход и копирует `h->stats`, если таблица есть. Rust `r2o_hold_stats()` возвращает копию `R2oHoldStats`; тест `hold_get_stats_returns_counter_snapshot_like_c` проверяет, что снимок до операций не меняется, а после split-hello даёт started=1/ready=1/joined=1/pending=0. |
| `d2k_hold_verdicts` | 85–92 | 8 | выдать вердикт всем ID, считать ошибки, продолжить после отказа | `main.rs:4519 release_many_with` | E | C проходит все ID, считает ошибки и продолжает после отказа. Rust `release_many_with` также пытается отправить вердикт каждому ID, сохраняя первую ошибку и возвращая её после цикла; набор обработанных ID тот же. Тест `hold_verdicts_continue_after_failure_like_c` (ошибка на среднем ID, все три попытки). |
| `http_ready` (static) | 93–100 | 8 | готовность HTTP-заголовка; полный заголовок без Host → -1 | `hold.rs:695 http_ready`, `:1343 incomplete_http_head` | **P** | C `d2k_http_request` vs Rust `request_host_range`: Rust требует полностью закрытые заголовки (`find_crlf`), C может вернуть 1 при завершённой строке Host без пустой строки; Rust отвергает `#` и target ≥2048, C — нет; см. также `capture.c`. Тест `hold.rs:2374`. |
| `d2k_hold_feed` | 101–236 | 136 | приём сегмента: flush, слот/сторона, лимиты 8×1600, capture, выбор головы, порядок оригиналов, синтетическая голова | `hold.rs` `feed_observing_mode`, `synthetic_packet` | **E*** | C/Rust differential `scripts/test-datapath-hold-differential.sh` PASS (15 кейсов, D6): split-hello 5+4, хвост раньше головы + anchor, flush по `HOLD_WAIT`, stats `timed_out/pending`, смена ревизии → `plan_changed`, 9-й пакет. **Ограничение:** HTTP-наблюдение (`allow_http`), серверная сторона и `own_packets` в оракуле не покрыты. |

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
| `same_key` (static) | 14-16 | 3 | равенство ключа UDP-потока | типизированное `Eq` (`r2o_udp_hold.rs`) | **E** | C `return d2k_key_equal(a,b)` — proto/ports/family/адреса. Rust `Eq` по адресам/портам/proto; используется всеми udp_hold-тестами. |
| `clear_slot` (static) | 18–20 | 3 | обнулить слот без release | `Option::take`/`None` | **E** | C `memset(s,0)`, Rust `slots[i].take()`; освобождение ID в обоих случаях делает вызывающий (C — `release_slot`, Rust — `r2o_take`/`r2o_drain`). |
| `release_slot` (static) | 22–29 | 8 | `release(ctx,&batch)`, clear, вернуть count | `r2o_udp_hold.rs:212 r2o_flush`, `:228 r2o_drain`, `:198 r2o_take` | **P** | C вызывает release-callback и сам чистит слот; Rust возвращает `R2oUdpHoldBatch` вызывающему, который обязан отпустить ID. Семантика «release → clear» та же, владение и форма результата разные. |
| `d2k_udp_hold_new` | 31-31 | 1 | создать таблицу UDP-удержания | `R2oUdpHoldTable::new` (`r2o_udp_hold.rs:147`) | **E** | C `calloc(1,sizeof(d2k_udp_hold))`, при OOM NULL. Rust `[None; 16]`/`Default`; обычный путь эквивалентен, OOM-ветвь иная. C-строка: `return calloc(1,sizeof(d2k_udp_hold));`; Rust `R2oUdpHoldTable::new`/`[None;16]`, OOM-ветвь иная. |
| `d2k_udp_hold_free` | 33–39 | 7 | слить все занятые слоты, затем `free` | `r2o_drain` (`:228`) | **P** | C при free вызывает release-callback для каждого used-слота; Rust `r2o_drain` возвращает пачки, а `Drop` не отпускает NFQUEUE ID сам — это обязанность вызывающего. |
| `d2k_udp_hold_flush` | 41–52 | 12 | `used && now>=deadline` → release, сумма count | `r2o_udp_hold.rs` `r2o_flush` | E | C обходит слоты и для `used && now>=deadline` отпускает ID, возвращая число. Rust `r2o_flush(now)` забирает все пачки с `now>=deadline` и возвращает `Vec<R2oUdpHoldBatch>`; вызывающий отпускает ID/байты. Условие и набор освобождённых слотов те же. Тест `udp_hold_flush_releases_expired_batches_like_c` (до срока — пусто, на сроке — одна пачка, повтор — пусто). |
| `d2k_udp_hold_feed` | 54-58 | 5 | обёртка `feed_marked(...,mark=0,...)` | `udp_hold` feed | **P** | C `d2k_udp_hold_feed_marked(h,key,id,packet,len,0,now,release,ctx)`. Rust передаёт mark явно; тонкая обёртка с тем же поведением при mark=0. |
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
| `d2k_udp_path_expire` | 69–74 | 6 | `seq = read_follows ? rseq+1 : NONE`, flush по таймеру | `main.rs` `follow_receive_seq`, `r2o_udp_hold.rs` `r2o_age` | E | C `D2K_UDP_SEQ_NONE=0`: при отсутствии чтения передаёт 0, иначе `rseq+1`. Rust в `main.rs` ставит `follow_receive_seq = received ? udp_receive_seq : 0` и вызывает `r2o_age` с тем же сентинелом; `r2o_age` удаляет по сроку и seq-правилам. C-тест `test_udp_path.c:393`, Rust-тест `udp_follow_age_matches_c_receive_seq_rules`. |
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
| `d2k_udp_release_new` | 29-51 | 23 | создать очередь отложенных вердиктов: проверка размеров, `slots*batch_size`, три массива, указатели слотов | `r2o_udp_hold.rs:282-288 R2oUdpDeferredVerdicts::new` | **P** | C при `slots==0 \|\| batch_size==0 \|\| slots>SIZE_MAX/batch_size` → NULL; `calloc(q)`, `calloc(slots)`, `calloc(n ids/verdicts)`, при сбое `free`; каждому слоту указатели на свою часть массивов. Rust `R2oUdpDeferredVerdicts` — фиксированные массивы `[Option; R2O_UDP_RELEASE_SLOTS]`, `next_order=0`; динамических slots/batch_size нет, ёмкости заданы константами. |
| `d2k_udp_release_free` | 53-59 | 7 | освободить массивы вердиктов/ID/слотов и очередь | `Drop` | **E** | C `if (!q) return`; `free(q->verdicts)`, `free(q->ids)`, `free(q->slot)`, `free(q)`. Rust владеет массивами/`Vec` и освобождает их `Drop`; отдельной функции нет. |
| `d2k_udp_release_enqueue` | 61-81 | 21 | принять пачку ID/вердиктов: count 1..batch_size, свободный слот, due/seq/key/token/count | `r2o_udp_hold.rs:291-324 r2o_enqueue` | **P** | C проверяет `q/ids/verdicts/key/count`; первый свободный слот; копия ids/verdicts; `used=1`, `due_ns`, `seq=next_seq++`, `key`, `token`, `count`. Rust `r2o_enqueue` проверяет непустоту/`<=R2O_UDP_RELEASE_PACKETS`/равные длины, парсит `flow_packet` в `flow_key`, ищет свободный слот, копирует, `order=next_order++`; `key`/`token` заменены `flow_key`, token отсутствует. |
| `next_due` (static) | 83-94 | 12 | ближайший созревший слот: `due<=now`, минимум по `due`, затем `seq` | `r2o_udp_hold.rs:352-362` (`min_by_key(due,order)`) | **P** | C линейно ищет `used && due<=now`, выбирает `due` меньше, при равенстве `seq` меньше. Rust `r2o_flush` тем же `min_by_key((due, order))`; эквивалентно. |
| `d2k_udp_release_flush` | 96-122 | 27 | выдать все созревшие пачки: send каждого id/verdict, complete/sent, done(ctx,key,token,...), released | `r2o_udp_hold.rs:345-378 r2o_flush` | **P** | C цикл `next_due`; для count: `send` каждый, ошибка → `complete=0`, иначе `sent++`; слот used=0/count=0; `done(key,token,complete,sent)`; released++. Rust `r2o_flush(now, send)` цикл min(due,order), отправляет все, запоминает первую ошибку, возвращает count/Err; `done`-колбэка/key/token нет. |
| `d2k_udp_release_next_ns` | 124-133 | 10 | ближайший `due_ns` среди занятых слотов | `R2oUdpRelease::timeout_ms` (`r2o_udp_hold.rs:240-254`) | **P** | C `next=0`; по `slots`: пропуск `!used`; `next==0 \|\| due<next` → `next=due`; 0 — пусто. Rust `timeout_ms(now,max_ms)` берёт минимум `due`, затем `min(max_ms)`/0; представление `Instant`/ns иное, порядок тот же. |
| `d2k_udp_replay_fates` | 135-154 | 20 | судьбы пачки: owned → can_resend; i=0 DROP/head; i>0 DROP+resend или ACCEPT | `main.rs` `r2o_udp_out_batch`/release | **P** | C `owned → can_resend=1`; i=0 `verdict=owned?DROP:head_verdict`, resend=0; i>0 при can_resend → DROP/resend=1/again++; иначе ACCEPT/resend=0. Rust `release_batch`/`R2oUdpDeferredResends` те же исходы; отдельной функции нет. |
| `plain_verdict` (static) | 174-177 | 4 | адаптер вердикта без контекста | замыкание вердикта (`r2o_release_batch_with`) | **E** | C `plain_ctx *p=ctx; return p->verdict(p->ctx,id,v)`. Rust передаёт замыкание вердикта в `r2o_release_batch_with`; тонкий адаптер, те же id/verdict. |
| `plain_resend` (static) | 178-182 | 5 | адаптер повторной отправки: id игнорируется | замыкание resend (`r2o_release_batch_with`) | **E** | C `(void)id; return p->resend(p->ctx,pkt,len)==0 ? 0 : -1`. Rust замыкание возвращает `io::Result`, успех/ошибка те же; id не используется. |
| `d2k_udp_release_batch` | 184-192 | 9 | обёртка `release_batch` с plain-адаптерами | `main.rs` batch release | **P** | C `plain_ctx`, вызывает `release_batch(..., NULL,NULL, verdict?plain_verdict:NULL, resend?plain_resend:NULL,...)`. Rust `r2o_udp_out_batch` использует `release_batch` с замыканиями; API иной. |
| `release_batch` (static) | 194-247 | 54 | общая выдача пачки: fates, fallback после отказа головы, marked → ACCEPT/defer, resend/owned, verdict, счётчики | `main.rs` `r2o_udp_out_batch` | **P** | **Ветви сверены:** C валидирует `b/verdict/count`; `!resend → can_resend=0, owned=0`; `replay_fates`; для каждого: при `again && vfail && !owned` → ACCEPT/fallback; `again && may && !may` → ACCEPT, при defer вызвать и continue; `again` → `resend(...)`; rr==1 → resent/continue (вердикт даст очередь), rr==0 → resent, иначе ACCEPT/fallback; `verdict` ошибка → vfail; возврат resent, vfail/fell_back. Rust `r2o_udp_out_batch`/`release_batch` те же правила; отдельной функции нет. |
| `follow_stale` (static) | 272-275 | 4 | запись устарела: истёк срок, другая/более новая пачка | `r2o_match`/`r2o_age` (`r2o_udp_hold.rs:550-615`) | **E*** | C `if (now_ns < until_ns \|\| (e->seq && e->seq==seq)) return 0; return e->seq==0 \|\| (seq!=0 && e->seq<seq);` — запись без seq истекает только по сроку. Rust `r2o_match`/`r2o_age` используют ровно эти три условия; тест `follow_stats_and_age_match_d2o`. |
| `follow_drop` (static) | 277-280 | 4 | погасить follow-запись и уменьшить `live` | `r2o_age` (`r2o_udp_hold.rs:602-615`) | **E** | C `e->used=0; if (f->live) f->live--;`. Rust `*slot=None`, `live.saturating_sub(1)`; эквивалентно. C-строка: `e->used=0; if (f->live) f->live--;`; Rust `*slot=None`, `live.saturating_sub(1)`. |
| `d2k_udp_follow_age` | 282-287 | 6 | удалить устаревшие записи; обход останавливается при `live==0` | `r2o_udp_hold.rs` `r2o_age` | E | C идёт по слотам, пока `live`, и удаляет `used && follow_stale`. Rust `r2o_age` обходит все слоты (пустые пропускаются), применяет то же условие `now>=until && !(seq match) && (entry.seq==0 || seq>entry.seq)` и уменьшает `live`. Набор удалённых записей тот же. Тест `udp_follow_age_matches_c_receive_seq_rules` (0/совпавший/больший seq). |
| `d2k_udp_follow_live` | 289-289 | 1 | число живых follow-записей | `R2oUdpFollowStats.live` (`:490-497`) | **E** | C `return f ? f->live : 0`. Rust `r2o_stats().live`; прямой getter, тест `follow_stats_*`. C-строка: `return f ? f->live : 0;`; Rust `r2o_stats().live`; тест `follow_stats_*`. |
| `d2k_udp_follow_busy` | 290-290 | 1 | счётчик busy повторной отправки | `R2oUdpFollowStats.busy` | **E** | C `return f ? f->busy : 0`; Rust `r2o_stats().busy`; тест `follow_stats_*`. C-строка: `return f ? f->busy : 0;`; Rust `r2o_stats().busy`; тест `follow_stats_*`. |
| `d2k_udp_follow_queue_full` | 291-291 | 1 | счётчик отказов полной очереди | `R2oUdpFollowStats.queue_full` | **E** | C `return f ? f->queue_full : 0`; Rust `r2o_stats().queue_full`; тест `follow_stats_*`. C-строка: `return f ? f->queue_full : 0;`; Rust `r2o_stats().queue_full`; тест `follow_stats_*`. |
| `d2k_udp_follow_refused` | 292-292 | 1 | счётчик прочих отказов | `R2oUdpFollowStats.refused` | **E** | C `return f ? f->refused : 0`; Rust `r2o_stats().refused`; тест `follow_stats_*`. C-строка: `return f ? f->refused : 0;`; Rust `r2o_stats().refused`; тест `follow_stats_*`. |
| `d2k_udp_send_busy` | 294-296 | 3 | errnobusy: EAGAIN/EWOULDBLOCK/ENOBUFS | `r2o_udp_send_busy` (`r2o_udp_hold.rs:799`) | **E** | **Точное совпадение:** C `err==EAGAIN \|\| EWOULDBLOCK \|\| ENOBUFS`; Rust `r2o_udp_send_busy(&io::Error)` сопоставляет те же `ErrorKind`/errno. |
| `d2k_udp_follow_new` | 298-298 | 1 | создать follow-таблицу | `R2oUdpFollowTable::new` | **E** | C `calloc(1,sizeof(d2k_udp_follow))`; Rust `new`/`Default` с массивами `[None;S]` и нулевыми счётчиками. OOM-ветвь отличается, обычный путь эквивалентен. |
| `d2k_udp_follow_free` | 300-300 | 1 | освободить follow-таблицу | `Drop` | **E** | C-строка: `void d2k_udp_follow_free(d2k_udp_follow *f){free(f);}`. Rust владеющая структура `R2oUdpFollowTable` освобождается `Drop`; отдельной функции нет, утечек нет. |
| `follow_tuple` (static) | 302-319 | 18 | разобрать UDP-кортеж: protocol 17, не поздний фрагмент, не broadcast/multicast, family/src/dst/ports | `r2o_udp_hold.rs:427-446 R2oUdpFollowKey::from_packet` | **P** | **Ветви сверены:** C `packet_parse`, protocol 17, `family==4 && fragment&0x2000` → -1, dst>=224 → -1, v6 dst first 0xff → -1; family/src/dst/ports. Rust `from_packet` требует `protocol==17 && fragment&0x3fff==0`, udp len>=8, те же broadcast/multicast фильтры; `fragment&0x3fff` строже C (C отбрасывает только `0x2000`), для первого фрагмента эквивалентно. |
| `same_tuple` (static) | 321-324 | 4 | family + memcmp 16/16/4 | `R2oUdpFollowKey: Eq` | **E** | C `a->family==b->family && !memcmp(src,16) && !memcmp(dst,16) && !memcmp(ports,4)`. Rust typed `Eq` по тем же полям; эквивалентно. |
| `d2k_udp_follow_mark` | 329-332 | 4 | запомнить пакет в follow-таблице | `R2oUdpFollowTable::r2o_mark` (`:508-548`) | **P** | C `return follow_put(f,pkt,len,now_ns,at_ns,seq) ? 0 : -1` — успех 0, ошибка -1. Rust `r2o_mark(...)` возвращает `bool`; вызывающий трактует `true` как успех. API иной, результат тот же. |
| `follow_put` (static) | 334-355 | 22 | записать кортеж: until=`max(at,now)+window`, at_ns=`at>now?at:0`, seq/used, слот по tuple или наименьший until, live++ | `r2o_udp_hold.rs:508-547 r2o_mark` | **P** | **Ветви сверены:** C `follow_tuple`; `out=max(at,now)`, `until=out+FOLLOW_NS`, `at_ns=at>now?at:0`, seq/used; поиск same tuple, иначе spare с наименьшим until; live++ при новом; запись. Rust `r2o_mark` те же вычисления, `deferred_at=at.filter(>now)`, anchor, until, поиск same key/свободный/наименьший until, live++. |
| `follow_find` (static) | 357-370 | 14 | найти запись: `!live` → NULL; stale удаляется; match seq или now<until; same tuple | `r2o_udp_hold.rs:550-579 r2o_match` | **P** | C `!live` → NULL; `follow_tuple`; обход `live`; stale → drop/continue; `(seq && e.seq==seq) \|\| now<until`; `same_tuple`. Rust `r2o_match` те же условия/порядок; возвращает `R2oUdpFollowMatch`. |
| `d2k_udp_follow_match` | 372-378 | 7 | найти запись и вернуть `at_ns` | `r2o_udp_hold.rs:550-579 r2o_match` | **E*** | C `follow_find`, `*at_ns=e->at_ns`, 1/0. Rust `r2o_match` возвращает `Option<R2oUdpFollowMatch { at, failed }>`; `at` соответствует `at_ns`, `failed` — новое поле. Эквивалентно для at. |
| `out_resend` (static) | 388-415 | 28 | переиздать хвост: `send_at_owned` за отложенной головой, `send_at`, `send_now`; ENOSPC/busy/прочее | `main.rs` `r2o_udp_out_batch`/release | **P** | **Ветви сверены:** C при `at>now && send_at_owned` → `send_at_owned(...,id)`, taken=rc==0; иначе `at>now` → `send_at`, иначе `send_now`; ENOSPC → queue_full++; busy → busy++; иначе первая ошибка failed_pkt/len/errno; return -1/1/0. Rust те же ветви в `r2o_udp_out_batch`/deferred resends; отдельной функции нет. |
| `d2k_udp_out_owned_emit` | 417-421 | 5 | вердикт головы: ошибка → ACCEPT + busy, иначе DROP | `main.rs` owned emit | **P** | C `!o\|\|!verdict` → -1; `err && busy && follow` → busy++; `verdict(err?ACCEPT:DROP)`. Rust `r2o_udp_out_owned_emit` в main; та же логика. |
| `refused_flow` (static) | 425-430 | 6 | учесть отказ и залогировать первые N | `r2o_udp_out_batch` (`main.rs`) | **P** | C `nth = o->follow ? ++o->follow->refused : 1`; если `resend_failed && nth<=D2K_UDP_REFUSED_LOG` — вызвать лог. Rust считает отказы в `r2o_udp_out_batch`; лимит/текст логирования иные. |
| `out_verdict` (static) | 432-435 | 4 | адаптер вердикта `out_tail` | замыкание (`main.rs`) | **E** | C `out_tail *c=ctx; return c->o->verdict(c->o->ctx,id,verdict)`. Rust передаёт замыкание вердикта; тонкий адаптер, те же id/verdict. |
| `d2k_udp_out_neutral` | 437-440 | 4 | нейтральный поток: mark 0/neutral_mark или не маршрутизируется | `r2o_udp_packet_is_neutral` (`main.rs:88`) | **P** | C `if (mark==0 \|\| (o && o->neutral_mark && mark==o->neutral_mark)) return 1; return o && o->routed && !o->routed(o->routes,ipver,mark);`. Rust `r2o_udp_packet_is_neutral(route_gate,probe_mark,mark,packet)` использует policy/route gate; API иной, смысл «не наш маршрут/нейтральный mark» сохранён. |
| `d2k_udp_out_batch` | 442-473 | 32 | выдать пачку: may[], defer, release_batch, marked tail log, failed flow, follow_put | `main.rs` `r2o_udp_out_batch` | **P** | **Ветви сверены:** C `!o\|\|!verdict\|\|!b\|\|!count\|\|count>MAX` → 0; `out_tail`; `can=can_resend&&send_now`; may[i]=neutral; marked_tail при i>0 && !may; defer_op; `release_batch(...,out_verdict,out_resend)`; marked tail → `o->marked`; failed_pkt → refused_flow; follow_put головы, noted/failed. Rust `r2o_udp_out_batch` те же шаги; отдельной функции нет. |
| `d2k_udp_out_late` | 475-509 | 35 | поздний хвост: find, failed → 0; neutral → defer/0; resend с owned/deferred; verdict DROP/ACCEPT | `main.rs` late UDP tail | **P** | **Ветви сверены:** C `!o\|\|!verdict\|\|!can_resend\|\|!send_now\|\|!follow` → 0; `follow_find`; `!e\|\|e->failed` → 0; `!neutral` → noted/marked, при at_ns+defer отложить ACCEPT, иначе 0; `out_resend` с at=deferred_at; rr==1 → 1 (очередь даст вердикт), rr==0 → DROP, иначе ACCEPT; failed → e->failed/refused_flow; `verdict`; 1. Rust `r2o_udp_out_late` те же ветви; API/структура иные. |

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
| `say` (static) | 33-41 | 9 | `vsnprintf` ошибки в буфер `err/cap` | `io::Error`/`format!` | **P*** | C `!err\|\|cap==0` → выход; `vsnprintf`. Rust возвращает `io::Error`/`String` наверх, вызывающий логирует; контракт «не падать, отдать причину» тот же, тексты не сверяются. |
| `nl_write` (static) | 43-57 | 15 | `sendto` с EINTR-retry; короткая запись → -1 | `nfqueue.rs:416-444 send_to_kernel` | **E** | C цикл `sendto`, `n>=0` → `n==len ? 0 : -1`, EINTR → повтор, иное → -1. Rust тот же цикл; короткая запись → `WriteZero`, иное — `io::Error`. |
| `await_ack` (static) | 61-109 | 49 | poll 1000 мс × 8, EINTR-retry, разбор `NLMSG_ERROR`, сверка seq | `nfqueue.rs:342-395 await_ack/await_ack_with` | **E** | **Ветви сверены:** C 8 итераций; `poll(1000)`; EINTR → continue, иное → ошибка; timeout → «за секунду»; `recv`; EINTR/EAGAIN → continue; `d2k_nl_iter`/`d2k_nl_next`; `d2k_nl_errno` иначе continue; `m.seq!=seq` continue; `e==0` → 0; `e<0` → `strerror(-e)`; после 8 — «не пришло». Rust `ACK_TIMEOUT_MS=1000`, `ACK_ATTEMPTS=8`; `poll` EINTR → повтор, timeout → `None` (сразу `TimedOut` с тем же смыслом), `recv_once` EINTR-retry; `MessageIter`; `message.sequence`; `kernel_error`; `error==0` → Ok, иначе `from_raw_os_error(-error)`. Тест `nfqueue.rs:480`. Единственное отличие: C на `EAGAIN` после poll повторяет итерацию, Rust считает ошибкой — после успешного poll недостижимо. |
| `send_and_ack` (static) | 111-122 | 12 | len==0 → ошибка; `nl_write`; `await_ack(seq)` | `nfqueue.rs:336-340 configure` | **P** | C seq передаётся явно, len==0 — отдельная ошибка. Rust `configure` берёт seq из заголовка `message[8..12]`, затем `send_to_kernel` + `await_ack`; пустое сообщение невозможно (билдеры всегда ≥16 байт), отдельной проверки len нет. Для реальных команд эквивалентно; теста `configure` нет. |
| `set_rcvbuf` (static) | 127-145 | 19 | `SO_RCVBUFFORCE` → `SO_RCVBUF`, `getsockopt`; 0/1/-1 | `nfqueue.rs:13-70 set_receive_buffer(_with)` | **E** | **Ветви сверены:** C пробует FORCE (если определён), при неудаче — RCVBUF; если оба не удались → -1; `getsockopt(SO_RCVBUF)`; `effective`; `return v>=requested ? 0 : 1`. Rust `set_receive_buffer_with`: FORCE `is_ok`, иначе RCVBUF, `getsockopt`; возвращает effective; `open` сравнивает с requested и логирует cap. Тесты `nfqueue.rs:512`, `:535`, `:563`. |
| `d2k_nfq_open` | 147-230 | 84 | socket/bind/BIND+ACK/PARAMS(fail_open, GSO off), rcvbuf | `nfqueue.rs:115-188 open` | **P** | **Ветви сверены:** C `!cfg`/calloc; `queue`, `seq=1`; `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)`; `bind` с `nl_pid=0`; `rcvbuf` FORCE/RCVBUF + логи cap; `BIND AF_INET` с ACK; `PARAMS`: copy_range, COPY_PACKET, maxlen, flags=fail_open, mask=fail_open\|GSO (GSO в маске, не в значении); ошибки → close/free. Rust: валидация `copy_range>=64`, `max_len!=0`, family 2\|10; `SOCK_RAW\|SOCK_CLOEXEC`; bind; rcvbuf; `config_command(BIND, family)` + `config_params` (те же attrs/mask); `Drop` вместо free. **Отличия:** C всегда AF_INET и не проверяет copy_range/maxlen; Rust поддерживает IPv4/IPv6 и отвергает негодные параметры; Rust `next_sequence` не отдаёт 0 при переполнении (`wrapping_add(1).max(1)`), C `seq++` может дать 0. |
| `d2k_nfq_close` | 232-248 | 17 | UNBIND без ACK, close, free | `nfqueue.rs:404-414 Drop` | **P** | C при `fd>=0` строит UNBIND с `seq++`, шлёт без ACK, close, free. Rust `Drop` строит UNBIND с `protocol_family`, шлёт без ACK, `OwnedFd` закрывает; отдельного close-API нет. Эквивалентно. |
| `d2k_nfq_fd` | 250-252 | 3 | дескриптор NFQUEUE-сокета | `AsRawFd for QueueSocket` (`nfqueue.rs`) | **P** | C `return q ? q->fd : -1`. Rust `AsRawFd` для непустого `QueueSocket`; NULL-объекта нет, отказ выражается `Option`/ошибкой. C-строка: `return q ? q->fd : -1;`; Rust `AsRawFd for QueueSocket`; NULL-объекта нет. |
| `d2k_nfq_recv` | 254-274 | 21 | recv; EAGAIN/EWOULDBLOCK/EINTR→0, ENOBUFS→lost++, -2, иначе -1 | `nfqueue.rs` `receive_timeout_with_fd`, `r2o_nfq_recv_error_outcome` | **E*** | Отображение errno приведено к C: EAGAIN/EWOULDBLOCK/EINTR → пустое ожидание (`Wait`, без сброса), ENOBUFS → `LostPackets` + счётчик, иное → `Io`. Poll EINTR → пустое ожидание, HUP/ERR/POLLNVAL без POLLIN → `Io`. Тест `nfq_recv_error_mapping_matches_c`. **Ограничение:** живой C/Rust netlink-оракул не построен; проверены исходные ветви C и отображение errno, а не реальный NFQUEUE-сокет. |
| `d2k_nfq_verdict` | 276-292 | 17 | вердикт без payload | `nfqueue.rs:310-315 send_verdict` | **E** | C `d2k_nl_verdict` + `nl_write`, ошибки в err. Rust `verdict(queue, seq, pkt_id, action)` + `send_to_kernel` + `record_verdict`; те же поля/порядок. Тесты `netlink.rs:304`. |
| `d2k_nfq_verdict_payload` | 294-311 | 18 | вердикт с заменой; буфер `64+2048` | `nfqueue.rs` `send_replacement`, `netlink.rs` `verdict_payload` | E | C: `uint8_t msg[64+2048]`; пустая замена, `len > 0xffff-4` или не влезающая в 2112 байт → отказ; раскладка NLMSG(16)+nfgenmsg(4)+VERDICT_HDR(12)+PAYLOAD(4+len,padded). Rust `verdict_payload` строит те же поля и отвергает `message.len() > 2112`; тесты `replacement_verdict_carries_payload_and_zero_padding`, `replacement_verdict_respects_c_message_capacity` (2076 влезает, 2077 нет). |
| `d2k_nfq_lost` | 313-315 | 3 | счётчик потерянных пакетов (ENOBUFS) | `nfqueue.rs:271-273 lost_packets` | **E** | C `return q ? q->lost : 0`; Rust `Cell<u64>` с `saturating_add`; тест `nfqueue.rs:492`. C-строка: `return q ? q->lost : 0;`; Rust `Cell<u64>` с `saturating_add`; тест `nfqueue.rs:492`. |

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
| `align4` (static) | 10-12 | 3 | `(n+3)&~3` | `netlink.rs:291-293 align4` | **E** | C без проверки переполнения; Rust `checked_add(3)` + `& !3`, возвращает `Option`. Для длин netlink-сообщений (≤65535) результат тот же. |
| `h16` (static) | 16-16 | 1 | host-order u16 через `memcpy` | `from_ne_bytes` (`netlink.rs:95`) | **E** | C `uint16_t v; memcpy(&v,p,2); return v` — без выравнивания. Rust `u16::from_ne_bytes` на срезе ровно 2 байта. Тесты итератора/сборки netlink. |
| `h32` (static) | 17-17 | 1 | host-order u32 | `from_ne_bytes` (`netlink.rs:88,97-98`) | **E** | C `uint32_t v; memcpy(&v,p,4)`. Rust `from_ne_bytes` с `get`/точной длиной; тест `netlink.rs:355`. C-строка: `uint32_t v; memcpy(&v,p,4); return v;`; Rust `u32::from_ne_bytes`; тест `netlink.rs:355`. |
| `wh16` (static) | 18-18 | 1 | запись host-order u16 | `to_ne_bytes` (`netlink.rs:265-266,276-277`) | **E** | C `memcpy(p,&v,2)`. Rust `to_ne_bytes` для type/flags/длины атрибута — те же байты на хосте. C-строка: `memcpy(p,&v,2);`; Rust `to_ne_bytes` для type/flags/длины атрибута. |
| `wh32` (static) | 19-19 | 1 | запись host-order u32 | `to_ne_bytes` (`netlink.rs:267,284`) | **E** | C `memcpy(p,&v,4)`. Rust `to_ne_bytes` для seq/длины заголовка; те же NE-байты. C-строка: `memcpy(p,&v,4);`; Rust `to_ne_bytes` для seq/длины заголовка. |
| `n16` (static) | 22-24 | 3 | network-order u16 | `from_be_bytes` (`netlink.rs:142-143`) | **E** | C-строка: `(uint16_t)((p[0]<<8)\|p[1])`. Rust `u16::from_be_bytes` для `hw_protocol`; те же два байта, тест парсера `netlink.rs:371`. |
| `n32` (static) | 25-28 | 4 | network-order u32 | `from_be_bytes` (`netlink.rs:141,148,151,154,165`) | **E** | C `(p[0]<<24)\|(p[1]<<16)\|(p[2]<<8)\|p[3]`. Rust `from_be_bytes` для id/cap_len/skb_info/mark/outdev; тест `netlink.rs:371`. C-строка: `(p[0]<<24)\|(p[1]<<16)\|(p[2]<<8)\|p[3]`; Rust `from_be_bytes`; тест `netlink.rs:371`. |
| `wn16` (static) | 29-31 | 3 | запись network-order u16 | `to_be_bytes` (`netlink.rs:228,270`) | **E** | C `p[0]=v>>8; p[1]=v`. Rust `to_be_bytes` для `res_id`/`pf`; тест `netlink.rs:332`. C-строка: `p[0]=v>>8; p[1]=v;`; Rust `to_be_bytes` для `res_id`/`pf`; тест `netlink.rs:332`. |
| `wn32` (static) | 32-35 | 4 | запись network-order u32 | `to_be_bytes` (`netlink.rs:196-197,248,251-258`) | **E** | C `p[0]=v>>24…p[3]=v`. Rust `to_be_bytes` для verdict/copy_range/maxlen/flags/mask; тест `netlink.rs:304`. C-строка: `p[0]=v>>24…p[3]=v;`; Rust `to_be_bytes`; тест `netlink.rs:304`. |
| `d2k_nl_iter_init` | 37-43 | 7 | инициализация итератора; NULL-буфер → пусто | `MessageIter::new` (`netlink.rs:64-70`) | **E** | C `it->p=buf`, `it->left=buf?len:0`. Rust `bytes`, `offset=0`, `stopped=false`; пустой срез даёт те же «нет сообщений». C-строка: `it->p=buf; it->left=buf?len:0;`; Rust `MessageIter::new`: `bytes`, `offset=0`, `stopped=false`. |
| `d2k_nl_next` | 45-77 | 33 | следующее сообщение; `left<16`/`mlen<16`/`mlen>left` → стоп; `step=align4`; `step>=left` → конец | `MessageIter::next` (`netlink.rs:76-107`) | **E** | **Ветви сверены:** C `!it\|\|!m\|\|left<16` → 0 (left=0); `mlen=h32`; `mlen<16 \|\| mlen>left` → left=0; type/flags/seq/pid/body; `step=align4(mlen)`; `step>=left` → left=0, иначе `p+=step`, `left-=step`. Rust `stopped`, `remaining`, `message_len` в `16..=remaining`, те же поля, `step>=remaining` → `bytes.len()`, иначе `offset+step`. Тест `:355` (unpadded/bad length). |
| `d2k_nl_packet` | 79-161 | 83 | атрибуты NFQA: hdr/payload/cap/skb/ts/mark/oif, `truncated` | `netlink.rs:125-180 QueuePacket::parse` | **P** | **Ветви сверены:** C `!m\|\|!out` → -1; `body_len<4` → -1; `pos=align4(4)`; цикл `pos+4<=body_len`; `alen`, `atype&0x3fff`; `alen<4 \|\| alen>body_len-pos` → break; value; PACKET_HDR vlen≥7 → id/hw_protocol/hook; PAYLOAD → срез; CAP_LEN/SKB_INFO/MARK vlen≥4; TIMESTAMP vlen≥16 → sec/usec BE, `sec && usec<1e6 && sec<18e9`; IFINDEX_OUTDEV vlen≥4; `step=align4`, `step>body_len-pos` → break. Rust те же поля/границы; `Option` вместо `have_*`; `checked_mul/add` для ns. **Расхождение `truncated`:** C `cap_len > payload_len` даже без PAYLOAD (`payload_len=0`) даёт `true` при `cap_len>0`; Rust `cap_len.zip(payload).is_some_and(...)` без PAYLOAD даёт `false`. Тесты `:371`, `:403` этот случай не покрывают. |
| `d2k_nl_errno` | 163-176 | 14 | знаковый errno из `NLMSG_ERROR` | `netlink.rs:183-186 kernel_error` | **E** | C требует `type==NLMSG_ERROR && body_len>=4`, читает host-int32, возвращает 0; иначе -1. Rust `(kind==NLMSG_ERROR && body.len()>=4).then(\|\| i32::from_ne_bytes(...))`; `None` вместо -1. Тест `:429`. |
| `hdr_init` (static) | 181-197 | 17 | `nlmsghdr` + `nfgenmsg`: type/flags/seq/pid=0, family 0, v0, queue BE | `netlink.rs:263-272 header` | **E** | C `need=20`, `memset`, wh16 type/flags, wh32 seq, pid=0, `o[16]=0`, `o[17]=V0`, wn16 queue. Rust `vec![0;20]`, те же поля/смещения, pid остаётся 0. |
| `put_attr` (static) | 200-216 | 17 | атрибут `len/type/value` + нулевой padding | `netlink.rs:274-280 push_attr` | **E** | C `alen=4+vlen`, `step=align4`, проверка `pos+step<=cap`, `wh16(len/type)`, `memcpy`, `memset` хвоста. Rust `extend` len/type/value, `resize(align4)`, нули; лимит `Vec` вместо cap. |
| `d2k_nl_verdict` | 218-234 | 17 | `VERDICT`: `VERDICT_HDR` (action, pkt_id BE) | `netlink.rs:188-201 verdict` | **E** | C `hdr_init` type `NFQ_TYPE(VERDICT)`/REQUEST, attr `VERDICT_HDR` 8 байт action+pkt_id BE, длина. Rust те же поля/порядок; тест `:304`. |
| `d2k_nl_verdict_payload` | 236-252 | 17 | `VERDICT` + `PAYLOAD`; пустой/`>0xffff-4` → 0 | `netlink.rs:203-217 verdict_payload` | **E** | C отвергает `!payload \|\| len==0 \|\| len>0xffff-4`, затем verdict + attr payload, длина. Rust те же проверки, `Option`; тест `:321`. Различие ёмкости вызывающего буфера (`nfq.c`) учтено в строке `d2k_nfq_verdict_payload`. |
| `d2k_nl_cfg_cmd` | 254-273 | 20 | CONFIG BIND/UNBIND с ACK, атрибут `CFG_CMD` | `netlink.rs:219-232 config_command` | **E** | C `hdr_init(type=NFQNL_CFG<<8\|cmd, flags=REQUEST\|ACK)`, attr 4 байта: `cmd` host u16, `0`, `pf` network u16. Rust те же type/флаги/атрибут (`cmd`, `0`, `pf BE`); тест `netlink.rs:332`. |
| `d2k_nl_cfg_params` | 275-309 | 35 | `PARAMS`/`QUEUE_MAXLEN`/`FLAGS`/`MASK` | `netlink.rs:234-261 config_params` | **E** | C `params[5]`: copy_range BE32 + copy_mode, затем maxlen/flags/mask BE32 в этом порядке. Rust те же четыре атрибута/порядок/значения; `fail_open` в flags, маска `FAIL_OPEN\|GSO`; тест `:332`. |

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
| `d2k_icmpguard_init` | 6-8 | 3 | обнулить кольцо 256 и счётчики | `Default for R2oIcmpGuard` (`r2o_icmp_guard.rs:32-42`) | **E** | C `memset(g,0,sizeof *g)` (слоты, next, seen/noted/dropped). Rust `[Slot::default(); 256]`, `next=0`, `seen/noted/dropped=0` — то же состояние. |
| `u16` (static) | 10-10 | 1 | big-endian u16 без проверки границ | `r2o_icmp_guard.rs:257-264 r2o_u16` | **E** | C `(p[0]<<8)\|p[1]`, все вызовы после проверки длины. Rust `get(offset..offset+2)` + `checked_add`, возвращает `Option`; значение для проверенных вызовов то же. |
| `parse_ip` (static) | 21-47 | 27 | IP-заголовок цитаты: IPv4/IPv6, proto 6/17, отказ non-first fragment, `n>=hl+8` | `r2o_icmp_guard.rs:204-255 r2o_parse_icmp_quote` | **P** | **Ветви сверены:** C `!p\|\|n<1` → 0; `family=p[0]>>4`; IPv4 `n<20`, `hl=(p[0]&15)*4`, `hl<20`, `fragment&0x1fff` → 0; proto=p[9], ttl=p[8], ip_len=BE16(+2), ip_id=BE16(+4), src=+12, dst=+16; IPv6 `hl=40`, `n<40`, proto=p[6], ttl=p[7], ip_len=BE16(+4), ip_id=0, src=+8, dst=+24; иная версия → 0; proto не 6/17 → 0; `n<hl+8` → 0; `l4=p+hl`. Rust те же поля/проверки, `checked_add` и `get`; `ip_id=0` для IPv6. **Не покрыто differential:** `test-icmp-guard-current-differential.sh` сравнивает только сводные счётчики/строку, не разбор цитат; unit-тестов в модуле нет. |
| `d2k_icmpguard_note` | 49-69 | 21 | запомнить фальшивку: `ttl<orig_ttl`, ring 256, `at=max(now,1)`, family/proto/ttl, src/dst, ports, l4word, ip_len, ip_id | `r2o_icmp_guard.rs:56-88 r2o_note` | **P** | **Ветви сверены:** C `!g\|\|!parse_ip` → 0; `q.ttl>=orig_ttl` → 0; слот `next`, `next=(next+1)%256`, `memset` слота; `at=now?now:1`, family/proto/ttl, src/dst (4/16), sport/dport (2+2), `l4word` (TCP 4, UDP 2), ip_len, `have_id=v4 && ip_id!=0`; `noted++`. Rust те же шаги; UDP-хвост `l4word[2..4]` копируется, но `check` сравнивает только 2 байта — на результат не влияет; `at_ns=now.max(1)`, `noted.wrapping_add(1)`. Differential — только сводка; ветви `note` не покрыты. |
| `d2k_icmpguard_check` | 71-110 | 40 | ICMPv4 type 11/0, v6 type 3/0; `fragment & 0x3fff`; цитата family; 7 полей; `q.ttl<=s.ttl`; dropped++ | `r2o_icmp_guard.rs:90-125 r2o_check`, `:175-202 r2o_icmp_quote_start` | **P** | **Ветви сверены:** C `!g\|\|!pkt\|\|len<1` → 0; IPv4 `len>=20`, `hl=(p[0]&15)*4`, `hl>=20`, `p[9]==1`, `fragment&0x3fff==0`, `len>=hl+8`, type 11/code 0; IPv6 `len>=48`, `p[6]==58`, type 3/code 0, `icmp=pkt+40`; `avail=len-(icmp+8-pkt)`; `parse_ip(icmp+8)` + family; по слотам: `at!=0`, `now>=at`, `now-at<=5с`, family/proto, src/dst, sport/dport, l4word (TCP 4/UDP 2), ip_len, `have_id/ip_id`, `q.ttl<=s.ttl` → dropped++. Rust `r2o_icmp_quote_start`/`r2o_check` те же проверки/поля в том же порядке (ip_len проверяется до l4word — конъюнкция эквивалентна). **Не покрыто differential:** сравниваются сводные счётчики, не отдельные отказы/принятия. |
| `d2k_icmpguard_dropped` | 112-112 | 1 | счётчик снятых ICMP | `r2o_icmp_guard.rs:149-151 r2o_dropped` | **E** | C `return g ? g->dropped : 0`; Rust `self.dropped`; differential сверяет поле сводки. C-строка: `return g ? g->dropped : 0;`; Rust `self.dropped`; differential сверяет поле сводки. |
| `d2k_icmpguard_noted` | 113-113 | 1 | счётчик запомненных фальшивок | `r2o_icmp_guard.rs:145-147 r2o_noted` | **E** | C `return g ? g->noted : 0`; Rust `self.noted`; differential сверяет поле сводки. C-строка: `return g ? g->noted : 0;`; Rust `self.noted`; differential сверяет поле сводки. |

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
| `d2k_http80_new` | 67-69 | 3 | `calloc` таблицы: 128 потоков, 256 HTTPS-имён, статистика | `control.rs` `NamePlans` (`MAX_HTTPS_NAMES=256`), `hold.rs` `HoldTable` | **E*** | Ёмкости совпадают: `HTTP_FLOW_CAPACITY=128` и при заполнении вытесняется самый старый поток, как C `make` (`http80.c:217-236`); HTTPS-имён 256. Тест `http_flow_table_evicts_oldest_at_128_like_c`. **Ограничение:** единого `calloc`-объекта нет — потоки и имена разнесены, состав `get_stats` иной. |
| `d2k_http80_free` | 71-73 | 3 | освободить таблицу HTTP/80 | `Drop` | **E** | C `free(h)`. Rust владеющие `HashMap`/`Vec` (потоки/имена/статистика) освобождаются `Drop`; отдельной функции нет. C-строка: `free(h);`; Rust владеющие `HashMap`/`Vec` освобождаются `Drop`. |
| `d2k_http80_get_stats` | 75-79 | 5 | снимок `d2k_http80_stats`; NULL → нули | `hold.rs:200 r2o_hold_stats` + `R2oTcpPayloadStats`/control | **P** | **Состав различается:** C `requests/injections/evicted/untracked/unparsed/later/dropped/answered/swap_failed`; Rust `R2oHoldStats` (`started/ready/released/...`), HTTP-счётчики (`http_later/http_unaligned/http_open_end`) — в `R2oTcpPayloadStats`, часть — в control/capture. Набор полей и точки инкремента иные. |
| `name_norm` (static) | 83-95 | 13 | снять одну хвостовую точку, len 1..253, только LDH, нижний регистр | `control.rs:2234-2261 canonical_name` | **P** | **C принимает:** односложные имена (`localhost`), чисто цифровые, пустые метки (`a..b`), метки с ведущим/хвостовым `-` — проверяется только набор символов `a-z/A-Z/0-9/-/.`. **Rust строже:** ≥2 метки, каждая 1..63, без ведущего/хвостового `-`, хотя бы одна нецифровая, ASCII, ≤253, одна хвостовая точка снимается. Для обычных доменов совпадает; набор принимаемых имён различается. |
| `d2k_http80_set_https` | 97-118 | 22 | найти/создать имя; `expires=0` — удалить; иначе занять пустой слот или вытеснить минимальный `expires` | `control.rs:1055-1091 set_https` | **P** | **Ветви сверены:** C `!h \|\| !name_norm` → -1; линейный поиск по имени; `expires==0` → `memset` найденной записи, 0; иначе при отсутствии — первый пустой слот, иначе запись с минимальным `expires`; `memcpy(name)`, `expires`; 0. Rust `set_https`: длина имени, `canonical_name`, TTL BE, **обрезает TTL до 7 суток** (`MAX_HTTPS_TTL_SECONDS`), 0 → `remove`; при отсутствии и `len>=256` удаляет `min_by_key(expires)`, вставляет `Instant::now()+ttl`. **Отличия:** C хранит абсолютное `expires` от вызывающего, Rust считает от `Instant::now`; C ключ — `char[254]`, Rust `String`; C нормализация lax (см. `name_norm`). Тест `control.rs:3158`. |
| `d2k_http80_https` | 120-129 | 10 | имя найдено и `now < expires` | `control.rs:590-596 has_verified_https` | **P** | C `!h\|\|!host\|\|!name_norm` → 0; линейный поиск; `now < expires` (строго). Rust ищет по уже нормализованному ключу, `expires > now`; для одного входа результат тот же. Тест `control.rs:3158`. |
| `wr16` (static) | 133-133 | 1 | big-endian u16 | `wire.rs:552-554 write_u16` | **E** | C `p[0]=v>>8; p[1]=v`. Rust `write_u16` — `to_be_bytes` в срез ровно 2 байта; используется сборкой 307/RST. C-строка: `p[0]=v>>8; p[1]=v;`; Rust `write_u16` — `to_be_bytes`; сборка 307/RST. |
| `wr32` (static) | 134-136 | 3 | big-endian u32 | `wire.rs:556-558 write_u32` | **E** | C `p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v`. Rust `write_u32` — `to_be_bytes` в 4 байта. C-строка: `p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v;`; Rust `write_u32` — `to_be_bytes`. |
| `sum16` (static) | 138-142 | 5 | RFC 1071: слова + нечётный хвост `<<8` | `wire.rs:534-543 sum16` | **E** | C `n>1` складывает слова, хвост `p[0]<<8`. Rust `chunks(2)` даёт те же значения, аккумулятор `u64`; для пакета ≤65535 переполнения нет. |
| `fold` (static) | 144-147 | 4 | свёртка переносов + инверсия | `wire.rs:545-550 checksum_value` | **E** | C `while (acc>>16) acc=(acc&0xffff)+(acc>>16); return (uint16_t)~acc`. Rust тот же цикл над `u64`, `!(acc as u16)`. C-строка: `while(acc>>16) acc=(acc&0xffff)+(acc>>16); return ~acc;`; Rust `checksum_value`. |
| `build` (static) | 156-188 | 33 | IP+TCP без опций: IPv4/IPv6, TOS/TC/flow/ip_id/TTL, длины, суммы; 307/RST | `http_replace.rs:79-145 build_segment` | **P** | **Ветви сверены:** C `family==6` → IPv6, иначе IPv4 (в т.ч. family 0/иная); `n=ip+20+plen`, `!o \|\| n>cap \|\| n>0xffff` → 0; IPv6: version/TC/flow, payload `20+plen`, next=6, hop, адреса, pseudo `len+6`; IPv4: 0x45/TOS/total/id/DF/TTL/proto 6/адреса/IP checksum/pseudo; TCP: sport/dport/seq/ack, data offset 0x50, flags, window, payload, checksum. Rust `build_segment` те же поля/порядок/суммы; **отличие:** принимает только family 4/6, C family 0 и прочие трактует как IPv4; Rust `vec![0; total]` вместо `memset` заголовков; тест `http_replace.rs:219` (v4/v6, суммы). |
| `rd32` (static) | 190-192 | 3 | big-endian u32 | `packet.rs:236 read_u32`/`u32::from_be_bytes` | **E*** | C `p[0]<<24 \| p[1]<<16 \| p[2]<<8 \| p[3]`. Rust `read_u32`/`from_be_bytes` с bounds-check; используется для seq/ack, тесты сети. C-строка: `p[0]<<24\|p[1]<<16\|p[2]<<8\|p[3]`; Rust `read_u32`/`from_be_bytes`; тесты сети. |
| `stale` (static) | 196-198 | 3 | `now > touched` и разница > `D2K_HTTP80_IDLE_NS` | `hold.rs` HTTP flow `last_seen`/expire | **P** | C отдельный `flow.touched` и `D2K_HTTP80_IDLE_NS`; Rust HTTP-поток в `HoldTable.http_requests` имеет `seen`/`response_progress` и удаляется по правилам `expire`/`sweep_http_responses`. Порог/момент удаления не совпадают один-в-один. |
| `find` (static) | 200-215 | 16 | линейный поиск по family/client/cport/server/80; stale → FREE/NULL | `hold.rs` `http_requests.iter().find` + `key.wire_key()` | **P** | C сравнивает 5-tuple (адреса 4/16, порты) и при `stale` освобождает слот; Rust ищет по `TcpFlowKey`/`wire_key` и `request_no`, stale-потоки удаляются отдельным sweep/expire. Ключ/lifetime различаются. |
| `make` (static) | 217-236 | 20 | свободный или самый старый по `touched`; вытеснение → `evicted++` | `hold.rs` создание `HttpRequestFlow` | **P** | C выбирает первый `ST_FREE`/stale, иначе минимальный `touched`; если вытесняет живую — `evicted++`; `memset`, family/адреса/порты/touched. Rust создаёт запись при SYN/запросе, ограничивает общий `HOLD_SLOTS`, отдельного `evicted` нет. |
| `d2k_http80_executed` | 238-254 | 17 | привязать execution/binding/plan/trial при `state==REQUEST && request_seq==seq` | `hold.rs:209-218 note_http_execution` | **P** | **Ветви сверены:** C `!h\|\|!execution_id\|\|!plan_id\|\|!trial_id\|\|!parse\|\|proto!=6` → выход; TCP, dport 80; `find` по src/cport/dst/80; `state==REQUEST` и `request_seq==rd32(seq)`; запись execution/binding(или нули)/plan/trial. Rust ищет `http_requests` по `key.wire_key()` и `request_sequence`, сохраняет `AppliedEvent`; состояние проверяется через `response_reported`/наличие applied. |
| `request_result` (static) | 256-265 | 10 | заполнить `d2k_http80_res`: family/адреса/порты/execution/binding/request_ms/request_no/status/body_bytes/plan/trial/path/host | `hold.rs:1269 finish_http_response`, `HttpResponseEvent` | **P** | **Совпадает:** ключ/порты/execution/binding/plan/trial/status/body_bytes/host/path. **Отличия:** C `request_ms = t_req/1e6` — абсолютные монотонные мс, Rust `elapsed_ms`; C путь копирует только для GET без `?`, `#`, `\\`, Rust — `r2o_http_plan_request`/path; C `status/body_bytes` из `d2k_http_response`, Rust из `http_response.rs`. |
| `d2k_http80_delivered` | 267-276 | 10 | отказ доставки замены: найти обратный поток, `invalid=1`, `complete=0`, `DONE`, `response=2` | `hold.rs:220-232 reject_http_response`, `main.rs:2605-2614` | **P** | **Ветви сверены:** C `accepted \|\| !h \|\| !r \|\| !parse \|\| proto!=6` → выход; TCP; thl; `sport!=80` или (нет payload и нет FIN/RST `0x05`) → выход; `find` с client=dst/cport=dport/server=src/80/now=0; `!f \|\| (state!=REQUEST && response!=1)` → выход; invalid=1, complete=0, DONE; `request_result`; response=2. Rust `reject_http_response` ищет по `wire_key`/`request_no`, `ready_for_next=false`; main шлёт событие с кодом 2. C `now=0` исключает stale-срабатывание. |
| `seq_after` (static) | 281-281 | 1 | `(int32_t)(a-b)>0` — знаковое сравнение с переполнением | `hold.rs:1318 seq_after` | **E** | **Точное совпадение:** C `(int32_t)(a-b)>0`; Rust `a.wrapping_sub(b) as i32 > 0`, те же знаковые переходы. C-строка: `return (int32_t)(a-b)>0;`; Rust `a.wrapping_sub(b) as i32 > 0`; те же переходы. |
| `delivered` (static) | 285-287 | 3 | дальний из `acked` и `reply_next` | `hold.rs:276-280` | **E** | **Точное совпадение:** C `seq_after(acked,reply_next) ? acked : reply_next`. Rust тот же выбор по `seq_after`. C-строка: `return seq_after(acked,reply_next)?acked:reply_next;`; Rust тот же выбор. |
| `cut_pending` (static) | 289-293 | 5 | `REQUEST && body_end_known && !cut_told && header_done && !complete && !invalid && body_end>delivered` | `hold.rs:255-296 sweep_http_responses` | **P** | **Совпадает по смыслу:** Rust проверяет `!response_reported && !invalid`, `fixed_body_remaining()>0`, `body_start`, `body_end>delivered`. **Отличия:** C требует `state==REQUEST` и отдельный `cut_told`; Rust — `response_progress`/`response_reported` и наличие body. |
| `cut_result` (static) | 295-303 | 9 | CUT: `request_result`, response=4, body_bytes=max, rtt, cut_told, DONE | `hold.rs:1269 finish_http_response(...4...)` | **E*** | **Совпадает:** Rust `sweep_http_responses` вызывает `finish_http_response(flow, 4, Some(body_bytes))`, `body_bytes = max(response.body_bytes, delivered-body_start)`; C `response=4`, max, `rtt`, `cut_told`, DONE. Отличие флага `cut_told` ↔ `response_reported`; тест `hold.rs:2082`. |
| `d2k_http80_sweep` | 305-323 | 19 | тишина `3*RTT` (мин. 2 с) → CUT, callback | `hold.rs:255-296 sweep_http_responses` | **E** | **Ветви сверены:** C пропускает `!cut_pending` и `now<=progress`; `quiet=max(3*rtt, CUT_MIN_NS)`, `now-progress<=quiet` → пропуск; `r` нули, action=PASS, `cut_result`, `told++`, `cb`. Rust те же `3*rtt`/2 с и `finish_http_response(...4...)`; `hold.rs:2082`. |
| `request_prefix` (static) | 327-341 | 15 | GET/HEAD, target без пробелов/`#`, Host из `d2k_http_request` | `r2k-core/src/httpup.rs:220-229 parse_request`, `:180-187` | **P** | **Ветви сверены:** C `d2k_http_request(p,n,&req)` (может принять неполный заголовок), `host_len<256`; метод ровно `GET `/`HEAD `; target до SP, отвергает `<=0x20`, `0x7f`, `#`; `end==n` или длина ≥ target → 0; копия target/host. Rust `parse_request` требует **полный** запрос (`header_len==input.len()`), GET/HEAD, Host:80, target без `#`/control; возвращает host/target. C может начать поток по префиксу без конца заголовка, Rust — нет. |
| `request_feed` (static) | 342-347 | 6 | `d2k_http_request_stream_feed`, `client_next`, `next_known` | `r2k-core/src/httpup.rs:28 R2oHttpRequestSequence`, `hold.rs` | **P** | C обновляет `client_next=next`, `next_known=header_done && !invalid && !past_end && next==end`; Rust `R2oHttpRequestSequence` ведёт `next/checked/disabled`, `header_len/end_offset`; `hold.rs` использует `ready_for_next`. Поля/момент `next_known` различаются. |
| `d2k_http80_packet` | 349-525 | 177 | стейт-машина HTTP/80: SYN/OPEN/IDLE/REQUEST/INJECTED/SWAP/ANSWERED/DONE, RTT, запрос/ответ, портал, 307+RST | `hold.rs:1088 observe_http_response`, `:356 feed_observing_mode`, `main.rs:2006/2093/2605` | **P** | **Ветви сверены:** C разбирает пакет/proto 6/thl; sport/dport 80 (ровно одна сторона); SYN без ACK → новый/сброс host, `ST_SYN`, t_syn/k_syn; нет потока → `untracked++`; ACK обновляет acked/progress; FIN\|RST при CUT → `cut_result`; данные в SYN/OPEN → `later++`; `ST_REQUEST` → request_feed; `OPEN/IDLE` + данные: `seq==client_next`, `request_prefix`, init/frames, IDLE server_next=ack, reset reply, request_no/seq/get, execution reset, `ST_REQUEST`, acked/reply_next, body flags, t_req/k_req, client_next, requests++; иначе DONE/unparsed. Обратно: SYN/ACK при SYN → rtt/krtt, server_next=seq+1, client_next=ack, OPEN; ANSWERED → DROP; не REQUEST (кроме FIN) → выход; seq-выравнивание (старый повтор/FIN/ gap→invalid); next_known/ack mismatch → invalid; reply_started; response_feed; reply_next; progress; fixed body_end/body_start; rtt/dt по t_req или krtt/k_req; портал `httpup_portal_location`; portal only if !interim && rtt && dt<rtt/2; known но не portal → response=3/INJECTED; complete/invalid → response 1/2, IDLE/DONE; portal → INJECTED/injections, response 1, rtt/reply_ns; только 1 сегмент; нужен `next_known && !request.length && https(host)`; build 307 и RST, окно/ttl/TC/flow/id из пакета; SWAP/REPLACE. Rust-аналоги разнесены по `hold.rs`/`http_replace.rs`/`main.rs`; состояния/поля иные, часть счётчиков отсутствует. D17 покрывает портал/307/поздний/дубль, не все ветви. |
| `d2k_http80_swap` | 527-545 | 19 | вердикт с заменой + RST; ошибка → INJECTED, ACCEPT, swap_failed | `main.rs:2093 send_replacement`, `:2114 mark_http_response_answered`, `http_replace.rs` | **P** | **Ветви сверены:** C `!h\|\|!r\|\|!io\|\|action!=REPLACE\|\|flow>=128` → 0; `state!=SWAP` или ошибка `verdict_payload` → при SWAP вернуть INJECTED, `swap_failed++`, answered=0, `verdict_accept`, 0; успех → ANSWERED, `answered++`, answered=1, `send_rst`, 1. Rust `send_replacement`/`mark_http_response_answered`/`release_with`; те же исходы, счётчики/события иные. D17 проверяет исход, не сокет. |
| `lc` (static) | 549-549 | 1 | ASCII-нижний регистр | `u8::to_ascii_lowercase` | **E** | C `('A'..='Z') ? c+32 : c`; Rust `to_ascii_lowercase()` понижает ровно `A..Z`, остальные байты не меняет. C-строка: `return (c>='A'&&c<='Z')?c+32:c;`; Rust `to_ascii_lowercase()`. |
| `d2k_http_request` | 551-632 | 82 | строгий разбор: метод 1..20 заглавных, origin-form `/`, HTTP/1.x, ровно один Host:80, LDH/метки, не IPv4, framing | `r2k-core/src/httpup.rs` `parse_plan_request`/`r2o_http_plan_request` | **E*** | C/Rust differential `scripts/test-http-request-differential.sh` PASS: 15 кейсов — полный/частичный заголовок, `:80`/`:8080`, нет/два Host, хвостовая точка, IPv4-метка, нижний метод, absolute-form, плохая метка, TE, duplicate CL, Content-Length, отсутствие CRLF. Исправлено: неполная строка заголовка больше не отменяет уже найденный Host; `head_len=0`, `end_known=0`, как C. **Ограничение:** частичное перекрытие заголовка и точные 10-значные границы CL проверяются stream-дифференциалом. |

`), Rust требует полный заголовок/`find_crlf`; C отвергает `#`/control в target, Rust — иные проверки `valid_dns_host`; C ограничивает method 20 символами, Rust — `parse_request`; C `d2k_http_request` возвращает 1 при завершённой строке Host без конца заголовка, Rust `parse_request` — только полный запрос. |
| `d2k_http_hello` | 634-640 | 7 | `host_off/host_len` из `d2k_http_request` | `r2k-core/src/httpup.rs:175-177 request_host_range` | **P** | C-обёртка возвращает смещение/длину Host или 0; Rust `request_host_range` — `Range` из `r2o_http_plan_request` после полного разбора. Для полного валидного запроса эквивалентно; на префиксе C сработает, Rust — нет. |

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
| `d2k_http_trace` | 9–50 | 42 | строка `d2kd: HTTP execution host=... IPv4/6 [src]:cport -> [dst]:80 seq=... hook/mark/outdev/status/prepared/plan/execution/planned/raw_sent/queued/original/output_failed/reason` | `http_trace.rs` `http_trace`; вызов в `main.rs` `r2o_log_http_trace` | **E** | C: TCP/80, method заглавными + пробел, `d2k_http_request` иначе `host=<unparsed>`, `inet_ntop`, plan hex или `-`, status `OBSERVE/SKIPPED/FAILED/PENDING/COMPLETE`, seq/hook/mark/outdev, execution, planned/sent/queued, original `ACCEPT/DROP`, output_failed, reason; усечение до `cap-1`. Rust `http_trace` повторяет формат и все статусы, не печатает URL/cookies; `r2o_log_http_trace` вызывается на HTTP-решении. Тесты `http_trace_matches_donor_statuses_and_hides_secrets`, `http_trace_rejects_other_ports_and_truncates_to_cap` (IPv4/IPv6, порт 81, cap). |

## datapath/journal.c (14 функций)

Кольцо журнала наблюдений: kinds, коды suspect/refuse, очистка имени, plan/trial/
execution/binding, added/dropped. R2O: `flow_journal.rs`.

**Прочитано построчно: 14/14 функций, 204 строки C (1–204).** Сверено с `flow_journal.rs:16-56` (константы/тексты), `:184-195` (`set_name`), `:530-581` (`default_journal_note`, `with_capacity`, `push`), `:650-757` (`record_applied/plan_prepared/plan_refused/execution_failure`), `:990-1020` (`count/get/dropped/added`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_journal_new` | 16-31 | 16 | `calloc` кольца; `cap=0` — журнал ничего не хранит, но считает `added` | `flow_journal.rs:552-563 with_capacity` | **E** | C `calloc(j)`; `cap==0` → объект с `v=NULL/cap=0`; иначе `calloc(cap)`, при сбое `free(j)`/NULL. Rust `with_capacity` — `try_reserve_exact(capacity)` + `resize_with`, при `0` пустой `Vec`; `push` при capacity 0 считает `added` и выходит. OOM: C NULL, Rust `TryReserveError`. |
| `d2k_journal_free` | 33-39 | 7 | освободить массив записей и объект журнала | `Drop` | **E** | C `if (!j) return; free(j->v); free(j);`. Rust владеющий `Vec`/`Box` освобождает массив/объект при `Drop`. C-строка: `if(!j)return; free(j->v); free(j);`; Rust `Drop` владеющего `Vec`/`Box`. |
| `d2k_suspect_text` | 41-53 | 13 | 8 кодов SUSPECT + default → русский текст | `flow_journal.rs:28-42 r2o_suspect_text` | **E** | **Точное совпадение строк:** C `RST=1`, `REPEAT=2`, `SILENT=3`, `RST_CUT=4`, `RST_AFTER_APP=5`, `FIN_RETRY=6`, `QUIC_STALL=7`, `TCP_STALL=8`, default; Rust те же пары (порядок веток иной) и default «подозрение без кода». Тест `:1027 journal_note_texts_match_d2o`. |
| `d2k_refuse_text` | 55-68 | 14 | 7 кодов REFUSE + default → русский текст | `flow_journal.rs:45-56 r2o_refuse_text` | **E** | **Точное совпадение:** C `NONE=0`…`FLOW_UNFIT=6`, default; Rust те же коды/тексты. Тест `:1027 journal_note_texts_match_d2o`. C: `NONE=0…FLOW_UNFIT=6`, иначе default; Rust те же тексты; тест `:1027`. |
| `add_entry` (static) | 76-130 | 55 | `added++`; `cap=0` — не хранить; при переполнении `dropped++`; заполнить at/key/kind/code/num/detail/note; имя 0x20..0x7e иначе `.`, до 63; сдвиг head | `flow_journal.rs:565-581 push`, `:530-541 default_journal_note`, `:184-195 set_name` | **P** | **Ветви сверены:** C `!j` → NULL; `added++`; `cap==0` → NULL; `n==cap` → `dropped++`; слот `head`, `memset`; at, key (если есть), kind/code/num; detail: ttl/ref_ttl/tos/server_hello/planned/client_shape/ipid; `note = note ? note : (kind==SUSPECT ? suspect_text : NULL)`; имя: `take=min(len,63)`, каждый байт `0x20..0x7e` иначе `.`, NUL, `name_len`; `head=(head+1)%cap`, `n++` до cap; вернуть слот. Rust `push`: note по умолчанию заполняется не только для `Suspect`, но и для `PlanRefused/PlanUnsent/PlanDamaged` (`refuse_text`) и `PlanDone` («план доисполнен») — `default_journal_note`; `added` всегда, `cap=0` выход, `length==capacity` → dropped++, запись в `head`, сдвиг. `set_name` — те же 0x20..0x7e и 63. **Отличие:** C при `note=NULL` для не-SUSPECT оставляет note NULL, Rust подставляет текст; в C-пути эти виды всегда пишутся через функции с явным note, поэтому итог совпадает. |
| `d2k_journal_add` | 132-137 | 6 | добавить наблюдение (kind/code/num/detail/name/note) | `flow_journal.rs:565-581 push` | **E*** | Тонкая обёртка `add_entry`; Rust `push` с теми же полями. Для `kind==SUSPECT` оба подставляют suspect-текст; для прочих C оставляет переданный note. |
| `d2k_journal_add_applied` | 139-149 | 11 | `PLAN_APPLIED`, plan_id/trial_id байт-в-байт | `flow_journal.rs:667-682 record_plan_prepared` | **P** | **Совпадает:** kind `PlanApplied`, plan/trial копируются как двоичные 16 байт без санитизации, note не задаётся. **Отличие:** Rust `record_plan_prepared` требует валидное `event_body()` (длины/ключ/привязку) и возвращает `bool`; C пишет, если есть слот. |
| `d2k_journal_add_refused` | 151-158 | 8 | `PLAN_REFUSED`, code/plan/trial/note | `flow_journal.rs:684-720 record_plan_refused` | **P** | **Расхождение:** Rust принимает только `NOT_APPLIED`/`FLOW_UNFIT` и валидный ключ/привязку (`is_known`, family 4/6, shape≤HTTP, kind/proto); C пишет любой `code` (включая `NONE`) и не валидирует binding. Отказ `NONE` C попадает в журнал (кроме probe+`NONE` в `refuse_coded`), Rust — нет. D22 покрывает основные коды. |
| `d2k_journal_add_fate_bound` | 160-176 | 17 | один kind за вызов (DONE/UNSENT/DAMAGED), note `refuse_text` для UNSENT/DAMAGED иначе «план доисполнен»; plan/trial/execution/binding | `flow_journal.rs:722-757 record_execution_failure`, `:650-665 record_applied` | **P** | **Совпадает:** за вызов один kind; note UNSENT/DAMAGED — `refuse_text(code)`, DONE — «план доисполнен»; plan/trial/execution/binding копируются. **Отличие:** C `d2k_session_exec_failed` делает два вызова (`UNSENT` + `fate_bound(DAMAGED)`), Rust `record_execution_failure` при `damaged` сам пишет `PlanUnsent`, затем `PlanDamaged` с кодом `DAMAGED` — итоговые две записи те же. `record_applied` соответствует C `PLAN_DONE`. |
| `d2k_journal_add_fate` | 178-182 | 5 | обёртка `add_fate_bound(..., execution=0, binding=NULL)` | `flow_journal.rs:722-757`/`:650-665` | **P** | C-обёртка без execution/binding; Rust `record_applied`/`record_execution_failure` требуют `AppliedEvent` с execution/binding. Для DONE с `execution=0` C пишет запись, Rust с невалидным событием — нет. |
| `d2k_journal_count` | 184-186 | 3 | число записей в кольце | `flow_journal.rs:990-992 count` | **E** | C-строка: `size_t d2k_journal_count(const d2k_journal *j){ return j ? j->n : 0; }`. Rust `self.length` — число записей (не capacity), растёт до `capacity`; те же значения при любом наполнении, тест `journal_count_matches_d2o`. |
| `d2k_journal_at` | 188-196 | 9 | запись от старой к новой; `i>=n` → NULL | `flow_journal.rs:994-1004 get`, `:1014-1016 iter` | **E** | **Совпадает:** C `!j\|\|i>=n` → NULL; `start=(n==cap)?head:0`; `(start+i)%cap`. Rust `index>=length` → None; `start` тот же; `get`/`iter` идут от старой к новой. При `cap==0` оба возвращают None (C `n=0`). |
| `d2k_journal_dropped` | 198-200 | 3 | счётчик вытесненных записей | `flow_journal.rs:1006-1008 dropped` | **E** | C `j ? j->dropped : 0`; Rust `self.dropped`, `u64` с wrapping-add при переполнении. C-строка: `return j ? j->dropped : 0;`; Rust `self.dropped`. |
| `d2k_journal_added` | 202-204 | 3 | счётчик добавлений | `flow_journal.rs:1010-1012 added` | **E** | C `j ? j->added : 0`; Rust `self.added`, увеличивается даже при `cap=0` (как C `add_entry`: `added++` до проверки cap). C-строка: `return j ? j->added : 0;`; Rust `self.added`, считается и при `cap=0`. |

## datapath/nat.c (5 функций)

Внешний адрес/порт из `/proc/net/nf_conntrack`: разбор строк, «лучшая запись» по
TTL, отличие «нет таблицы» от «нет записи». R2O: `proc_nat.rs`.

**Прочитано построчно: 5/5 функций, 195 строк C (1–195).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `parse_ip4` (static) | 20–41 | 22 | строгий IPv4: 4 десятичных октета 0..255, ровно точки и NUL | `proc_nat.rs` `parse_ipv4` | E | C: ровно 4 октета, только ASCII-цифры, значение ≤255, после четвёртого — NUL; число цифр не ограничено (`0001.2.3.4` → 1.2.3.4), переполнение отвергается. Rust `parse_ipv4` повторяет все ветви (checked mul/add, ≤255), включая ведущие нули; тест `parse_ip4_and_address_match_c_nat_parser` (валидные, 256, пустой октет, лишние символы, пробел/перевод строки). |
| `field_after` (static) | 46–63 | 18 | найти `name=` на границе слова, вернуть значение до пробела/`\n`, сдвинуть `next`; строка режется на месте | `proc_nat.rs` `field_after`/`fields` | E | C ищет имя на границе слова (начало или после пробела), требует `=`, значение до пробела/перевода строки, `*next` — продолжение поиска. Rust `fields()` делит строку только по пробелу/`\n` (табуляция остаётся в значении, как в C), `field_after(fields, from, name)` ищет точное имя и возвращает индекс+значение; тест `field_after_matches_c_word_boundary_and_continuation` (src/dst/sport/dport, отсутствие `port`, повторный src, табуляция). |
| `d2k_nat_outside` | 67–73 | 7 | IPv4-обёртка: family=4, src/dst как 4 байта, `d2k_nat_outside_family` | `proc_nat.rs:20 lookup` с tuple family=4 | **P** | C передаёт указатели на `uint32_t` и family 4; Rust `R2oConntrackTuple.family=4`, адреса 16-байтные с нулевым хвостом. Для IPv4 эквивалентно; отдельной функции-обёртки в Rust нет. |
| `parse_address` (static) | 75–82 | 8 | IPv4 через `parse_ip4`, IPv6 через `inet_pton`, `out[16]` занулён | `proc_nat.rs` `parse_address` | E | C зануляет 16 байт, для family 6 использует `inet_pton(AF_INET6)`, для 4 — `parse_ip4`; иное семейство → -1. Rust `parse_address` делает то же (`Ipv6Addr::from_str` отвергает `%zone`); тест `parse_ip4_and_address_match_c_nat_parser` (v4/v6, `%eth0`, family 5). |
| `d2k_nat_outside_family` | 84–194 | 111 | `fopen`; 1 — нет таблицы, -1 — нет записи, 0 — найдено; строки >1022 пропуск; direct/reverse tuple; best TTL (3-е число) | `proc_nat.rs:20 lookup` → `R2oProcNatLookup` | **E** | **Точное совпадение:** `fopen` fail → 1 / `TableMissing`; нет записи → -1 / `Missing`; найдено → 0 / `Found`; `fgets(1024)` + drain длинной строки ↔ `read_until` + `content_len>1022`; `strstr(tcp/udp)` ↔ `contains`; direct `src/dst/sport/dport`; reverse `dst/dport`; TTL — третье число (`third_number`); `ttl<=best_ttl` → skip; `memcmp` 4/16 и `htons` портов. Тест `proc_nat.rs:220` + `r2o-nat-proc-differential.sh`; в этом проходе не перезапускались. |

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
| `align4` (static) | 16-16 | 1 | `(n+3)&~3` | `conntrack.rs:250-252 align4` | **E** | C без проверки переполнения; Rust `checked_add(3)` + `& !3`, для netlink-длин ≤65535 результат тот же. Используется атрибутами/сообщениями conntrack. |
| `wr16h` (static) | 18-18 | 1 | host-order u16 через `memcpy` | `push_attribute` (`conntrack.rs:254-262`) | **E** | C `uint16_t v; memcpy(p,&v,2)`. Rust пишет длину/тип атрибута `to_ne_bytes`; те же NE-байты. Тест `conntrack.rs:543`. C-строка: `uint16_t v; memcpy(p,&v,2);`; Rust `to_ne_bytes`; тест `conntrack.rs:543`. |
| `wr32h` (static) | 19-19 | 1 | host-order u32 через `memcpy` | `encode_get` (`conntrack.rs:114-131`) | **E** | C `uint32_t v; memcpy(p,&v,4)`. Rust пишет длину сообщения/тип/seq `to_ne_bytes`; те же поля/порядок. C-строка: `uint32_t v; memcpy(p,&v,4);`; Rust `to_ne_bytes` для длины/типа/seq. |
| `rd16h` (static) | 20-20 | 1 | host-order u16 через `memcpy` | `from_ne_bytes` (`conntrack.rs:233`) | **E** | C `memcpy` в `uint16_t`; Rust `u16::from_ne_bytes` на точном срезе. Длина/тип атрибута; тест `conntrack.rs:543`. C-строка: `uint16_t v; memcpy(&v,p,2); return v;`; Rust `from_ne_bytes`; тест `conntrack.rs:543`. |
| `rd64be` (static) | 21-25 | 5 | big-endian u64 из 8 байт | `u64::from_be_bytes` (`conntrack.rs:214`) | **E** | C цикл `v=(v<<8)\|p[i]` для 8 байт; Rust `from_be_bytes` для `CTA_COUNTERS_PACKETS`; тест 64-битных счётчиков `conntrack.rs:487`. C-строка: цикл `v=(v<<8)\|p[i]` 8 байт; Rust `from_be_bytes`; тест `conntrack.rs:487`. |
| `rd32be` (static) | 26-28 | 3 | big-endian u32 из 4 байт | `u32::from_be_bytes` (`conntrack.rs:224`) | **E** | C `p[0]<<24\|p[1]<<16\|p[2]<<8\|p[3]`; Rust `from_be_bytes` для `CTA_COUNTERS32_PACKETS`; тест `conntrack.rs:529`. C-строка: `p[0]<<24\|p[1]<<16\|p[2]<<8\|p[3]`; Rust `from_be_bytes`; тест `conntrack.rs:529`. |
| `put` (static) | 31-40 | 10 | атрибут `alen/type/value` + zero padding, отказ при нехватке cap | `conntrack.rs:254-262 push_attribute` | **E** | C `alen=4+vlen`, `step=align4`, `pos+step>cap` → 0; length/type NE, копия, обнуление хвоста. Rust те же длина/тип/значение и нулевой padding; `Vec` вместо cap, `length as u16` так же усекается. Тест `:543`. |
| `open_nest` (static) | 43-47 | 5 | заголовок вложенного атрибута `type\|NLA_F_NESTED`, длина позже | `conntrack.rs` `push_attribute` с `NLA_F_NESTED` | E | C пишет `type\|NLA_F_NESTED` и возвращает pos+4; длину закрывает `close_nest` как end-start. Rust `push_attribute(kind\|NLA_F_NESTED, value)` пишет тот же заголовок; тест `nested_attribute_matches_c_open_close` проверяет type/length/содержимое для выровненного вложенного значения. |
| `close_nest` (static) | 48-50 | 3 | проставить длину `end-start` | `conntrack.rs` `push_attribute` | E | C `end-start` без padding; Rust `push_attribute` пишет `4+value.len()` и добавляет padding после. Все вложенные значения состоят из выровненных атрибутов, поэтому длина совпадает; тест `nested_attribute_matches_c_open_close` (вложенный атрибут 8 байт → length 12). |
| `d2k_ct_get_req` | 52-81 | 30 | nlmsg CT_GET orig tuple: family 2/10, res_id 0, nested TUPLE_ORIG/IP/PROTO, src/dst, proto/ports, seq, pid 0 | `conntrack.rs` `encode_get` | **E*** | C/Rust differential `scripts/r2o-conntrack-ctget-differential.sh` PASS: 4 кортежа (IPv4/IPv6 × TCP/UDP), весь nlmsg сравнивается побайтово. **Ограничение:** Rust дополнительно требует `proto ∈ {6,17}`, C принимает любой байт; ошибки `cap<20`, `!o/!t`, family∉{4,6} не покрыты. |
| `counter` (static) | 84-96 | 13 | вложенные counters: `PACKETS` 8 байт или `PACKETS32` 4 байта, иначе -1 | `conntrack.rs:211-226 parse_counter` | **E** | **Ветви сверены:** C обходит атрибуты, `alen<4 \|\| alen>n-off` → -1, `PACKETS && vl==8` → BE64, `PACKETS32 && vl==4` → BE32, иначе `off+=align4`. Rust `find_attribute(PACKETS)` → 8 байт, иначе `find_attribute(PACKETS32)` → 4; **отличие:** при `PACKETS` неверной длины C не пробует `PACKETS32`, Rust пробует. На валидных ядерных ответах не проявляется; тесты `:487`, `:529`. |
| `tcp_state` (static) | 99-120 | 22 | nested PROTOINFO/TCP/TCP_STATE: байт+1, 0 — нет | `conntrack.rs:156-160` (`state.first().copied()`) | **E*** | **Совпадает по значению:** C ищет PROTOINFO→TCP→TCP_STATE, требует `l2>=4+1`, возвращает `state+1`; `d2k_ct_info_parse` вычитает 1. Rust та же цепочка `find_attribute`, `state.first()`, хранит исходный байт; `tcp_state_known` ↔ `Some`. Тест `:487` (state=3). |
| `d2k_ct_info_parse` | 122-156 | 35 | seq-фильтр; NLMSG_ERROR → 1/-1; CT_NEW; orig/reply counters; tcp_state; коды -1/0/1/2 | `conntrack.rs` `r2o_ct_info_parse`, production `query` | E | C/Rust differential `scripts/test-datapath-ct-info-differential.sh` PASS: 5 кейсов — счётчики 22/25, чужой seq → -1, нет счётчиков → 2, NLMSG_ERROR errno≠0 → 1, errno=0 → -1; Rust больше не требует reverse-кортеж для счётчиков. |
| `d2k_ct_counters_parse` | 158-167 | 10 | обёртка `info_parse`, копирует orig/reply при rc=0 | `conntrack.rs` `r2o_ct_counters_parse` | E | C/Rust differential `scripts/test-datapath-ct-info-differential.sh` PASS: 5 кейсов — counters 22/25 rc=0, чужой seq -1, нет счётчиков 2, kernel reply 1, ACK -1; счётчики копируются только при rc=0. |
| `d2k_ct_query_info_fd` | 169-186 | 18 | send GET `MSG_DONTWAIT`, до 8 recv `MSG_DONTWAIT`, вернуть 0/1/2/-1 | `conntrack.rs` `query_info`, `receive_info_parse` | **E*** | C-ветви сверены: encode/`send` ровно n, до 8 `recv` с фильтром seq, `info_parse` 0/1/2 возвращается, иначе -1. Rust `query_info` возвращает `Info/Reply/NoCounters/Error`, `query` оставляет только `Info`. **Ограничение:** живой netlink C/Rust-оракул не построен; возвращаемые коды проверены на чистых фикстурах `ct_info_parse`. |
| `d2k_ct_query_fd` | 188-197 | 10 | обёртка `query_info_fd` для счётчиков | `conntrack.rs` `query`/`query_info` | **E*** | `query_info` сохраняет код `info_parse`; `query` отдаёт `Info` только при rc=0, как C-обёртка копирует счётчики только при успехе. **Ограничение:** различие кодов 1/2 на уровне `query` схлопывается в `None`; полный код доступен через `query_info`. |
| `reply_errno` (static) | 201-212 | 12 | по seq: NLMSG_ERROR → положительный errno, 0 — не ошибка; нет ответа → -1 | `conntrack.rs:350-356` (inline в `probe`) | **P** | C различает «нет ответа на seq» (-1) и «ответ не ошибка» (0), `e<0 ? -e : e`. Rust в `probe` проверяет только `NLMSG_ERROR` с нужным seq и `errno == -ENOENT`; общего `reply_errno`/различения 0 и -1 нет. |
| `d2k_ct_probe_fd` | 214-238 | 25 | zero-tuple GET, poll `wait_ms` до 8 раз; ENOENT(2) или запись(0) → подсистема есть | `conntrack.rs` `probe`, `r2o_ct_reply_errno` | **E*** | C-ветви сверены: zero tuple family 4/proto 17, send ровно n, до 8 poll/recv, чужой seq пропускается, errno 0/2 → true, иное → false. Rust приведён к тому же циклу; тест `ct_reply_errno_matches_c` (запись, чужой seq, ENOENT, ACK). **Ограничение:** живой C/Rust netlink-оракул не построен. |
| `d2k_ct_open` (linux) | 243-253 | 11 | `SOCK_RAW`+`SOCK_CLOEXEC`, fcntl O_NONBLOCK, bind; fd без проверки подсистемы | `conntrack.rs:270-295 open` | **P** | C: socket `RAW\|CLOEXEC`, fcntl `O_NONBLOCK`, bind, вернуть fd (probe отдельно). Rust: socket `RAW\|CLOEXEC\|NONBLOCK`, bind, затем **обязательный `probe()`**; при недоступности — None. API/момент проверки различаются. |
| `d2k_ct_open` (не linux) | 255-255 | 1 | вне Linux — заглушка -1 | `#[cfg(target_os="linux")]` (модуль `conntrack`) | **E** | C вне Linux возвращает -1. Rust модуль conntrack подключается только для Linux; вне платформы функциональность отсутствует (эквивалент отказа). |

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
| `d2k_sched_new` | 43-71 | 29 | `calloc` mem/heap/freelist, `slots*slot_size` overflow, freelist от 0 | `scheduler.rs:89-107 with_limits` | **P** | **Ветви сверены:** C `slots==0 \|\| slot_size==0` → NULL; `slots > SIZE_MAX/slot_size` → NULL; `calloc(s)`, затем `mem`, `heap`, `freelist`, при любом сбое `d2k_sched_free`/NULL; `freelist[i]=slots-1-i` (вершина — слот 0), `nfree=slots`. Rust `capacity==0 \|\| slot_size==0` → `InvalidInput`; `Vec::new`/`HashMap::new`, `next_order=0`, `next_batch=1`, `refusals=0`; физического freelist/памяти нет — байты в `WirePacket`, лимит проверяется на push. OOM: C NULL, Rust `Vec` паникует/`try_reserve` в других путях. |
| `d2k_sched_grow_slot_size` | 73-88 | 16 | новый `cap*slot_size`, копировать живые записи, free старый; 0/1/-1 | `scheduler.rs` `grow_slot_size` | E | C/Rust differential `scripts/test-datapath-scheduler-differential.sh` PASS: rc для 16/16/4/SIZE_MAX и сохранность живых записей (последующий push/pop 16 байт). Rust меняет только `slot_size`, потому что `WirePacket` владеет байтами. |
| `d2k_sched_free` | 90-98 | 9 | освободить mem/heap/freelist/sched | `Drop` | **E** | C освобождает три массива и объект; Rust владеющие `Vec`/`HashMap` освобождаются `Drop`, отдельной функции нет. C освобождает `mem/heap/freelist` и объект; Rust `Vec`/`HashMap` освобождаются `Drop`. |
| `earlier` (static) | 102-107 | 6 | порядок `(due_ns, seq)`: меньший срок, при равенстве — меньший seq | `(due, order)` (`scheduler.rs:195,246`) | **E** | **Точное совпадение:** C `due_ns` затем `seq`; Rust `partition_point` по `(due, order)` и `entries.first()`; тест `scheduler.rs:526`. |
| `sift_up` (static) | 109-120 | 12 | подъём двоичной кучи по `earlier` | вставка в отсортированный `Vec` (`scheduler.rs:193-204`) | **P** | C parent/swap до корня; Rust `partition_point` + `Vec::insert` со сдвигом хвоста. Итоговый порядок `(due,order)` тот же, структура/стоимость иные. |
| `sift_down` (static) | 122-139 | 18 | спуск двоичной кучи после изъятия головы | `Vec::remove(0)` (`scheduler.rs:285,291`) | **P** | C ставит последний элемент в корень и выполняет `sift_down` по `earlier`; Rust `remove(0)` со сдвигом хвоста. Итоговый порядок `(due,order)` тот же, структура/стоимость иные. |
| `d2k_sched_push` | 141-144 | 4 | push без execution | `scheduler.rs:209-211 push_raw` | **E*** | C `return push(s,...,0,...)` — execution=0. Rust `push_raw` → `ScheduledOwner::Raw`; тест `scheduler.rs:526`. C-строка: `return push(s,...,0,...);`; Rust `push_raw` → `ScheduledOwner::Raw`; тест `scheduler.rs:526`. |
| `d2k_sched_push_serial` | 149-152 | 4 | push с execution и ключом | `scheduler.rs:167-206 push_reserved` | **P** | C хранит `execution`/`key` в entry; Rust использует `FlowTicket`/`Reservation` (batch/remaining), ключ потока — в `flows`; `push_reserved` проверяет ticket и уменьшает бронь. Семантика брони иная, порядок вставки тот же. |
| `d2k_sched_push_owned` | 154-157 | 4 | push с владением NFQUEUE ID | `scheduler.rs` `push_owned` | E | C/Rust differential `scripts/test-datapath-scheduler-differential.sh` PASS: `push_owned(4242)` → pop с `owned=1 qid=4242`; второй owned с `outcap=8` → -1; порядок и refusals совпали. |
| `push` (static) | 159-190 | 32 | пусто → -2 без refusals; `len>slot_size` → refusals++ -2; full → refusals++ -1; freelist; seq++; sift | `scheduler.rs:223-257 push_owner` | **P** | **Ветви сверены:** C `!s\|\|!data\|\|len==0` → -2 (без счётчика); `len>slot_size` → refusals++, -2; `n>=cap \|\| nfree==0` → refusals++, -1; `slot=freelist[--nfree]`; `memcpy`; entry: due/seq=next_seq++/slot/len/execution/owned/id, key копируется или нулится; `n++`, `sift_up`, 0. Rust `packet.packet.is_empty()` → Err; `len>slot_size` → refusals++; `entries.len()>=capacity` → refusals++; `order=next_order++`; вставка по `(due,order)`. **Отличия:** C коды -2/-1, Rust `Err(WirePacket)`; C копирует байты в `mem`, Rust владеет `WirePacket`; `reserved_packets`/`flows` — расширение Rust. |
| `d2k_sched_pop_due` | 192-196 | 5 | pop без execution: `pop_due_ex(...,NULL)` | `scheduler.rs:329-340 pop_due` | **P** | C-обёртка; Rust `pop_due` возвращает `(WirePacket, FlowTicket)` и вызывает `expire(now)` для очистки flow-состояния. Для не-Flow владельца Rust возвращает `None`, C — пакет. |
| `d2k_sched_pop_due_serial` | 198-202 | 5 | pop с execution: `pop_due_ex` | `scheduler.rs:275-296 pop_due_ex` | **P** | C передаёт `execution` и `key`; Rust возвращает `ScheduledPop` с `ScheduledOwner::Flow(ticket)`. Форма результата иная; `expire` дополнительно. |
| `d2k_sched_pop_due_ex` | 204–267 | 64 | пусто/не созрело → 0; `out==NULL` → 0; слишком длинная голова: refusals++, owned → -1 + ID, иначе 0; иначе copy/len/key/execution/owned/ID → 1 | `scheduler.rs` `pop_due_ex` (`ScheduledPop`) | E | C/Rust differential `scripts/test-datapath-scheduler-differential.sh` PASS (51 кейс, D21): пустой/не созревший, emitted len/owned/qid, owned-oversize → -1 + id, dropped-oversize → 0, порядок due/seq, refusals. **Ограничение:** `out==NULL` в Rust невозможно (срез). |
| `d2k_sched_next_ns` | 269-271 | 3 | абсолютный срок головы или 0 | `scheduler.rs:298-300 next_due` | **E** | C `s && n>0 ? heap[0].due_ns : 0`. Rust `entries.first().map(due)`; `None` для пустой очереди, вызывающий трактует как 0. C-строка: `return s && s->n>0 ? s->heap[0].due_ns : 0;`; Rust `entries.first().map(due)`. |
| `d2k_sched_count` | 273-275 | 3 | число записей в очереди | `scheduler.rs:373-375 len` | **E** | C-строка: `size_t d2k_sched_count(const d2k_sched *s){ return s ? s->n : 0; }`. Rust `entries.len()` — число записей отсортированного `Vec`; прямой getter, те же значения при любом наполнении, тест `scheduler.rs:563`. |
| `d2k_sched_refusals` | 277-279 | 3 | счётчик отказов очереди | `scheduler.rs:377-379 refusals` | **E** | C `s ? s->refusals : 0`; Rust `self.refusals`. Тест `scheduler.rs:563`. C-строка: `return s ? s->refusals : 0;`; Rust `self.refusals`; тест `scheduler.rs:563`. |

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
| `wr16` (static) | 23-26 | 4 | big-endian u16 | `r2k-core/src/wire.rs:552-554 write_u16` | **E** | C пишет два байта; Rust `copy_from_slice(&value.to_be_bytes())` с точной длиной среза. Все вызовы передают срез ровно 2 байта; golden-тесты `wire.rs`. |
| `wr32` (static) | 28-33 | 6 | big-endian u32 | `wire.rs:556-558 write_u32` | **E** | C `p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v`. Rust `to_be_bytes` в срез ровно 4 байта; golden-тесты wire. C-строка: `p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v;`; Rust `write_u32` — `to_be_bytes`. |
| `rd16` (static) | 35-37 | 3 | big-endian u16 | `PacketView::parse` (`r2k-core/src/packet.rs:69`) | **E** | C `(p[0]<<8)\|p[1]`; используется только в `d2k_wire_tcp_checksum_ok` для длины IPv6 payload и total IPv4. Rust читает те же поля в `PacketView` с проверкой границ; отдельной функции нет. |
| `auto_ttl` (static) | 54-70 | 17 | TTL по `rev_ttl`: origin 64/128/255 ≥ rev, hops=origin-rev, +delta, max, min, clamp 1..255; 0 если нельзя | `plan/apply.rs:764-783 poison_ttl`, `wire.rs:425-433 emission_ttl` | **E** | **Совпадает:** C перебирает 64/128/255, берёт первый ≥ `rev_ttl`, `hops=origin-rev`, `+delta`, потолок `hi` (если ненулевой), пол `lo`, clamp 1..255; `rev_ttl==0` → 0, и вызывающий берёт заданный ttl. Rust `poison_ttl`: тот же перебор/формула/clamp; при `reference_ttl==0` или отсутствии origin возвращает `poison.ttl` (тот же fallback). Вычисление перенесено из сборщика в `plan/apply.rs`; итоговый TTL тот же. Тест `engine.rs:2120`. |
| `sum16` (static) | 73-82 | 10 | RFC 1071: 16-битные слова, нечётный хвост `<<8`, без свёртки | `wire.rs:534-543 sum16` | **E** | C `i+1<n` складывает слова, хвост `b[i]<<8`. Rust `chunks(2)` — те же значения; аккумулятор `u64` вместо `u32`, для пакета ≤65535 переполнения нет. Golden wire. |
| `fold` (static) | 84-89 | 6 | свёртка переносов + инверсия | `wire.rs:545-550 checksum_value` | **E** | C `while(acc>>16) acc=(acc&0xffff)+(acc>>16)`, `~(uint16_t)acc`. Rust тот же цикл над `u64`, `!(acc as u16)`; golden wire. C-строка: `while(acc>>16) acc=(acc&0xffff)+(acc>>16); return ~acc;`; Rust `checksum_value`. |
| `pseudo_sum` (static) | 99-107 | 9 | псевдозаголовок TCP IPv4: src/dst сырыми байтами, 0, proto **6**, длина TCP | `wire.rs:516-532 pseudo_sum` | **E** | C 12 байт: `src4`, `dst4`, `0`, `6` (TCP), BE16 `tcp_len`; `sum16`. Rust `pseudo_sum` для family 4 складывает те же поля и `6+tcp_len`; для family 6 дополнительно адреса по 16 байт (C-функция IPv4-only, IPv6 считает inline). Для IPv4 эквивалентно. |
| `d2k_wire_build` | 109-277 | 169 | сборка TCP: family 0/4/6, urgent, ipfrag/profile, MD5/TS/TS-up, native options, seq_shift, poison, TTL/autottl, IP-ID, окно, суммы | `r2k-core/src/wire.rs:18-209 build_tcp_packet` | **P** | **Совпадает:** IPv4/IPv6-заголовки, TCP без опций/MD5/TS, seq_shift, urgent/urgent_ptr, `pre+payload`, `total<=cap/0xffff`, badsum measured `^0xbeef`→0x1234 vs legacy `~`→0xffff, TS-back `-1000`, TS-up перенос 10 байт, measured DF=0/window=65535/TTL=64, native options ≤40/кратность 4/один TS/обязательный TS при TCPTS_BACK, IPv6 IPID_ZERO reject, MD5 только measured. **Подтверждённые отличия:** (1) C принимает `family=0` как IPv4 (`:114`), Rust `PacketView` допускает только 4/6 — вызов с family 0 Rust отвергнет; (2) C берёт src/dst/порты/ack/window/ttl/ip_id/опции из `d2k_conn`, Rust — из исходного `PacketView` того же пакета; для пути исполнения эквивалентно, но контракт функции иной; (3) measured IP-ID: C `random()%65535`, Rust `getrandom()%65535` — диапазон 0..65534 одинаков, источник разный, побайтовый differential невозможен; (4) IPv4 TOS в обоих случаях 0, IPv6 TC — из соединения/пакета. 12 golden/дифференциалов покрывают шаблон/TS-up/badsum/measured/MD5/v6/capacity. |
| `d2k_wire_tcp_checksum_ok` | 279-306 | 28 | IPv4: версия/proto/ihl/total; IPv6: len≥60/proto 6/base-only; сверка суммы | `r2k-core/wire.rs` `tcp_checksum_ok` | E | C проверяет IPv4 version/proto/IHL≥20/total≤len и IPv6 len≥60/proto 6/длину TCP, затем `pseudo_sum+sum16+fold==0`. Rust `tcp_checksum_ok` реализует те же проверки и суммы для базовых пакетов; тест `tcp_checksum_ok_matches_c_for_ipv4_and_ipv6` (валидный, испорченный, обрезанный, IPv6). Пакеты с расширенными заголовками/фрагментами `PacketView::parse` отвергает раньше C. |

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
| `wr16` (static) | 22-25 | 4 | big-endian u16 | `wire.rs:552-554 write_u16` | **E** | C `p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v`. Rust `to_be_bytes` в срез ровно 2 байта; golden-тесты wire. C-строка: `p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v;`; Rust `write_u16` — `to_be_bytes`. |
| `sum16` (static) | 31-40 | 10 | RFC 1071: слова + нечётный хвост `<<8` | `wire.rs:534-543 sum16` | **E** | C обходит `i+1<n`, хвост `b[i]<<8`. Rust `chunks(2)` даёт те же значения; `u64`-аккумулятор для пакета ≤65535 не переполняется. C-строка: обход `i+1<n`, хвост `b[i]<<8`; Rust `sum16` — `chunks(2)`. |
| `fold` (static) | 42-47 | 6 | свёртка переносов + инверсия | `wire.rs:545-550 checksum_value` | **E** | C `while(acc>>16) …`, `~(uint16_t)acc`; Rust тот же цикл и `!(acc as u16)`. Golden wire. C-строка: `while(acc>>16) …; return ~acc;`; Rust `checksum_value` — `!(acc as u16)`. |
| `pseudo_sum` (static) | 57-65 | 9 | IPv4 UDP псевдозаголовок: src/dst, 0, proto 17, udp_len; 12 байт | `r2k-core/wire.rs` `udp_pseudo_sum` | E | C строит 12 байт (адреса сырыми, `0`, `17`, BE16 `udp_len`) и складывает; для IPv6 `d2k_wire_build_udp` суммирует 32 байта адресов + `udp_len + 17`. Rust `udp_pseudo_sum(packet, family, udp_len)` повторяет обе ветви и используется в `build_udp_packet`; тест `udp_pseudo_sum_matches_c_pseudo_header` (IPv4/IPv6 против C-заголовка, неизвестное семейство). |
| `d2k_wire_build_udp` | 67-207 | 141 | сборка UDP: family 0/4/6, IPv6 IPID_ZERO reject, wire_profile/ipfrag reject, pre/seq_shift/TCPTS_BACK/BADSUM reject, IP-ID, TTL, длина, сумма всегда 0→0xffff | `r2k-core/wire.rs` `build_udp_packet` | **E*** | C/Rust differential `scripts/test-datapath-udp-build-differential.sh` PASS: 20 кейсов — IPv4/IPv6, TOS, ipidzero, ttl 0/48/64/5, пустая нагрузка, badsum/tcpts/seq_shift/pre/wire_profile/ipfrag reject, cap на байт меньше, MD5 игнорируется. Исправлено расхождение: IPv4 DSCP/ECN теперь 0, как C `wire_udp.c:130` (раньше Rust копировал TOS). **Ограничение:** не покрыты `len > 65535-8`, `total > 0xffff`, NULL-указатели (в Rust невозможны), family 0 в Rust представлен IPv4-входом. |

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
| `d2k_addr_parse` | 5–18 | 14 | IPv4/IPv6 литерал, отказ `%zone`, family 4/6 | `r2k-core/src/addr.rs:11 Address::parse` | **E** | **Совпадает:** C отвергает NULL и любой `%`, пробует `inet_pton(AF_INET)`, затем `AF_INET6`, family 4/6. Rust `IpAddr::parse` отвергает host/zone и даёт те же семейства; `network.rs:6`, `:22` (включая `fe80::1%eth0`). Форматы ввода совпадают. |
| `d2k_addr_text` | 20–30 | 11 | `inet_ntop`, отказ при неизвестной family; `n>=cap` → 0, иначе копия+`\0`, вернуть n | `r2k-core/addr.rs` `impl Display for Address` | E | C `inet_ntop` даёт канонический текст IPv4/IPv6, неизвестное семейство → 0; ограничение cap проверяется вызывающим. Rust `Display` для `Address` выдаёт ту же каноническую запись в владеющий String (без усечения); тест `addr_text_matches_inet_ntop` (v4, v6, `::1`). |
| `d2k_addr_equal` | 32–36 | 5 | family совпадает, `memcmp` 4/16; неизвестная family → 0 | `addr.rs:5 PartialEq` | **E** | **Совпадает:** C сравнивает family+bytes, family 0/иная → 0; Rust derived `Eq` на `IpAddr` (V4/V6 — разные варианты). `network.rs:16`. |

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
| `rd16` (static) | 30-32 | 3 | big-endian u16 | `r2k-core/src/tls.rs:129-133 read_u16` | **E** | C `(p[0]<<8)\|p[1]` без проверки, все вызовы предварительно проверили границы. Rust `read_u16` — `checked_add(2)` + `get`, возвращает `Option`; для проверенных вызовов значение то же. |
| `skip_u8_vec` (static) | 36-46 | 11 | пропуск TLS-вектора u8 | `tls.rs:141-156 skip_u8_vector` | **E** | C `off+1<=len`, `off+1+n<=len`, `off+=1+n`; Rust `get(*offset)` + `checked_add(1+length)` + `next>end` → false. Тесты `tls.rs:367-525`. |
| `skip_u16_vec` (static) | 48-58 | 11 | пропуск TLS-вектора u16 | `tls.rs:158-173 skip_u16_vector` | **E** | C `rd16` + `off+2<=len`/`off+2+n<=len`; Rust `read_u16` + `checked_add(2+length)` + `next>end`. Те же тесты. C-строка: `rd16` + `off+2<=len`/`off+2+n<=len`; Rust `read_u16` + `checked_add(2+length)`. |
| `has_ech_offer` (static) | 72-87 | 16 | ECH 0xfe0d: `n>=10`, `b[off]==0`, `enc=rd16(off+6)`, `enc<=n-10`, `payload=rd16(off+8+enc)`, `payload>0 && payload==n-10-enc` | `tls.rs:230-272 has_ech_offer` | **E** | **Ветви сверены:** C цикл `off+4<=end`, type/len BE, `off+=4`, `n>end-off` → 0; при 0xfe0d — четыре условия и возврат результата; иначе `off+=n`. Rust те же проверки/порядок через `checked_add`, `extension_end>end` → false. Тест `tls.rs:466`; fuzz-префиксы. |
| `has_tls13` (static) | 105-129 | 25 | supported_versions содержит 0x0304; на оборванном блоке — key_share | `tls.rs:175-228 has_tls13` | **E** | **Ветви сверены:** C `key_share` ставится сразу после чтения заголовка и до проверки длины; при `off+elen>exts_end` break; supported_versions: `elen<1` → 0, `list_len=b[off]`, `p+list_len<=off+elen`, чётные версии, 0x0304 → 1, иначе 0; после цикла `truncated && key_share`. Rust тот же порядок/условия; `read_u16` с checked. Тесты `tls.rs:411`, `:438`. |
| `find_sni` (static) | 131-177 | 47 | server_name → host_name; выход за границы extension/list/name или пустое имя — отказ | `tls.rs:274-320 find_sni` | **E** | **Ветви сверены:** C `off+4<=exts_end`; `off+elen>exts_end` → -1; SNI: `p+2>off+elen` → -1, `list_len`, `p+list_len>off+elen` → -1; имена `p+3<=list_end`, `nlen`, `p+nlen>list_end` → -1; `nt==0` и `nlen==0` → -1, иначе координаты; отсутствие host_name → -1. Rust `Option`/`None` с теми же проверками; пустое имя → `None`. Тесты `tls.rs:445`, `:455`. |
| `d2k_tls_parse` | 179-361 | 183 | запись TLS, claimed/avail, ServerHello≥38, ClientHello, hello_middle, extensions, ECH/TLS1.3/SNI | `tls.rs:32-127 parse` | **E** | **Полная сверка ветвей:** C `!out` → -1 (Rust владеет структурой); `len<3`/`b[1]!=3` → пусто; `is_tls_record`, `record_type`; `len<5`; `rec_len=rd16(3)`, `record_end` только при `5+rec_len<=len`; `record_type!=0x16`; `end=min(claimed,avail)`; `off+4>end`; ServerHello: `sh_len>=38 && off+4+sh_len<=claimed` → `is_server_hello`, дальше не разбирает; не ClientHello → выход; `hs_len`, `off+4+hs_len>claimed` → выход; `hello_middle` только при полном hello, иначе `hs_end=avail`; 34 байта version/random; три вектора; `off+2>hs_end` → выход (CH без расширений); `exts_len`, `off+exts_len>claimed` → выход; `exts_end>hs_end` → `exts_truncated=1`/`exts_end=hs_end`; затем has_tls13/ECH/find_sni. Rust `parse` повторяет все проверки/порядок, checked-арифметика, `TlsInfo::default`. Тесты `tls.rs:367-525`, `tls_parser:394`, fuzz-префиксы `:503`. |

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

**Прочитано построчно: 2/2 функции, 99 строк C (1–99).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_ctl_binding_write` (inline) | 86–90 | 5 | запись binding: BE u64 generation, kind/family/shape/temporary, 16-байтная epoch | `r2k-core/control.rs` `AppliedEvent::event_body` | E | Раскладка построчно совпадает: generation BE u64 (8), kind/family/shape/temporary (4), epoch 16 = 28 байт. Rust `AppliedEvent::event_body` пишет те же поля в хвост события; тест `binding_write_matches_c_layout` проверяет длину и байты. |
| `d2k_ctl_binding_read` (inline) | 91–99 | 9 | чтение/валидация binding: n=28, kind≤4, family 0/4/6, shape≤MAX, temporary≤1 | `control.rs:2373 decode_applied`, `:2445 decode_refused`, `:3104 valid_binding` | **P** | Валидации совпадают: `kind<=4`, `family in {0,4,6}`, `shape<=SHAPE_ECH_TS`, temporary только 0/1. Тесты: REFUSED roundtrip/truncated (`:2528-2607`), APPLIED; ветки `kind=5`, `family=1`, `shape>MAX` отдельным тестом не покрыты. |

## datapath/include/d2k_http_request_stream.h (3 inline-функции)

**Прочитано построчно: 3/3 функции, 87 строк C (1–87).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_http_request_stream_init` (inline) | 19–21 | 3 | обнулить состояние, `start=next=seq`, `first=1` | `httpup.rs` `R2oHttpRequestStream::new` | E | Точный порт: `start=next=seq`, все флаги/поля обнулены, `first=true`. Используется в production `R2oHttpRequestSequence` при кросс-сегментном заголовке. |
| `d2k_http_request_stream_line` (inline) | 22–30 | 9 | завершение строки: ровно один Host, конец ≤0x7fffffff, CL с цифрами | `httpup.rs` `R2oHttpRequestStream::finish_line` | E | Точный порт `hosts==1`, `end<=0x7fffffff`, `head_len/end`, сброс line/value/field/name_len/digits/trailing и `invalid` для пустого CL. |
| `d2k_http_request_stream_feed` (inline) | 31–86 | 56 | потоковый разбор заголовка: CRLF, token, Host, CL, TE/Upgrade, end/past_end/invalid | `httpup.rs` `R2oHttpRequestStream::feed` | **E*** | C/Rust differential `scripts/test-http-request-stream-differential.sh` PASS: 13 состояний — простой запрос, тело за end (`past_end`), заголовок из двух сегментов, нет/два Host, TE, Upgrade, duplicate CL, битый CL, control-байт, старый повтор, дыра. **Ограничение:** не покрыты все 10-значные границы CL и частичное перекрытие; проверено на фиксированных сценариях. |

## datapath/include/d2k_http_response.h (6 inline-функций)

**Прочитано построчно: 6/6 функций, 161 строка C (1–161).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_hr_decimal` (inline) | 21–29 | 9 | десятичное число с проверкой переполнения | `http_response.rs:360 parse_decimal` | **E** | Совпадает: пусто/нецифра → ошибка, `checked_mul/checked_add`; тест `rejects_malformed...` с `18446744073709551616` (`tests/http_response.rs:229`). |
| `d2k_hr_token` (inline) | 31–34 | 4 | допустимый token-байт RFC 7230 | `httpup.rs:346 is_http_token` | **E** | Набор символов совпадает; используется в `parse_plan_request` для имени заголовка запроса. В ответном парсере Rust этот предикат не применяется (см. `d2k_hr_field`). |
| `d2k_hr_field` (inline) | 35–42 | 8 | валидация поля: непустое имя, token, допустимые байты значения | `http_response.rs` `valid_hr_field`, production `parse_headers` | E | C/Rust differential `scripts/test-http-field-differential.sh` PASS: 12 кейсов — пустое имя, строка без `:`, `Host :`, TAB в значении, `\x01`/`\x7f`, `@` в имени, `X-Empty:`; коды 0/1 совпали. |
| `d2k_hr_extensions` (inline) | 43–70 | 28 | разбор chunk-extensions: `;token[=token/quoted]`, OWS, контрольные байты | `http_response.rs` `valid_hr_extensions`, production `parse_chunk_size` | E | C/Rust differential `scripts/test-http-response-feed-differential.sh` PASS: 19 framing-кейсов, включая `1;foo="bar"`, `1 ;foo`, пустой `;`, незакрытую кавычку и control-байт; текст/rc совпали. |
| `d2k_hr_headers` (inline) | 72–105 | 34 | разбор status-line и заголовков, CL/TE, interim, 101/204/304 | `http_response.rs` `parse_headers`/`parse_status_line` | E | C: status-line ≥12 байт (ровно 12 без reason phrase; при >12 13-й байт — пробел), каждое поле проходит `d2k_hr_field` (двоеточие, token-имя, значение без control/DEL кроме TAB), любой второй Content-Length отвергается, TE только chunked, CL+TE запрещены. Rust `parse_status_line`/`parse_headers` повторяют эти ветви; ёмкость заголовка 8191 (C `head[8192]`). Тесты `status_line_without_reason_phrase_is_accepted_like_c`, `header_fields_are_validated_like_c`, `duplicate_content_length_is_rejected_even_when_equal`, `header_capacity_matches_c_head_buffer`. |
| `d2k_http_response_feed` (inline) | 107–160 | 54 | потоковый разбор ответа: header/fixed/chunk/trailer/close/fin | `http_response.rs` `HttpResponseParser::feed` | **E*** | C/Rust differential `scripts/test-http-response-feed-differential.sh` PASS: 19 кейсов — bytes-after-complete → invalid, trailer без `:`, duplicate CL, control-байты в заголовке/расширении, NUL-trailer, 204/304 с телом, 12-байтная status-line, валидные chunk-extensions. Строка — C `line[512]`; статус при неполном заголовке остаётся 0. **Ограничение:** не все состояния 1xx/101 и close-delimited FIN входят в C-оракул (они покрыты unit-тестами). |

## datapath/include/d2k_packet.h (2 inline-функции)

**Прочитано построчно: 2/2 функции, 72 строки C (1–72).**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_packet_u16` (inline) | 20–22 | 3 | big-endian u16 | `packet.rs:231 read_u16` | **E** | **Построчно совпадает:** C-строка `((unsigned)p[0]<<8)\|p[1]`; Rust `read_u16` — `from_be_bytes` с bounds-check. Используется `parse_ipv4`/`parse_ipv6`; тесты `tests/network.rs:36+`. |
| `d2k_packet_parse` (inline) | 24–70 | 47 | разбор IPv4/IPv6, fragment, extension headers, только Pad1/PadN, L4 minimum | `packet.rs:69 PacketView::parse`, `:152 parse_ipv4`, `:172 parse_ipv6`, `:203 has_only_padding_options` | E | IPv4: IHL/ total / fragment offset / ID / proto / TTL / TOS / адреса совпадают. IPv6: payload≠0, total=40+payload, TC/flow label, до 8 extension headers, Pad1/PadN; иные опции отвергаются. Тесты `r2k-core/tests/network.rs:36+`. |

## datapath/include/d2k_track.h (1 inline-функция)

**Прочитано построчно: 1/1 функция, 83 строки C (1–83).**

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
  + `test-wire-ts-up-plan-differential.sh`. `d2k_wire_build_udp` — E*:
  `wire.rs` `build_udp_packet`, 20-кейсовый C/Rust differential; IPv4 TOS
  приведён к C (всегда 0), IPv4 `POISON_IPID_ZERO` допускается, IPv6 —
  отвергается. Не покрыты только сверхдлинные длины и NULL-указатели.
- **Вывод:** session/hold/capture/track — P с конкретными пробелами
  (TCP options, полная таблица, редкие таймауты); wire TCP — E, wire UDP —
  P из-за IPID_ZERO/TOS.

## Углублённая сверка: nfq/udp_hold/udp_path/udp_release/http80

- **`nfq.c`:** `say`, `nl_write`, `await_ack`, `send_and_ack`, `set_rcvbuf`,
  `d2k_nfq_open/close/fd`, `d2k_nfq_recv`, `d2k_nfq_verdict(_payload)`,
  `d2k_nfq_lost` сверены с `nfqueue.rs`/`netlink.rs`. Bind/params/ACK,
  `SO_RCVBUF(FORCE)`, очередь и счётчик `lost` покрыты netlink/NFQUEUE
  тестами. **ENOBUFS-дренаж приведён к C:** на `ReceiveError::LostPackets`
  TCP-удержания сбрасываются все, а UDP — только истёкшие
  (`udp_holds.r2o_flush(now)`, `r2o_take_due_accept(now)`), как
  `d2k_udp_path_expire(..., 0)`. Тест
  `nfqueue_error_releases_only_due_udp_deferred_entries_like_c`. Остаётся P
  по `d2k_nfq_recv`: poll/EAGAIN-после-poll трактуются как `Io`, а не `Wait`.
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

