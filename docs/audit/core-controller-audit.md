# Аудит паритета D2O (C) → R2O (Rust): core и controller

Дата аудита: 2026-11-07. Источники: production-файлы `E:\d2o\core\*.c` (без `test_*`), `E:\r2o\crates\r2o-controller/src`, `E:\r2o\crates\r2k-core/src`, тесты и дифференциалы `E:\r2o\crates\*/tests`, `E:\r2o\scripts`, документы `functional-parity-matrix.md` и `parity-function-inventory.md`.

Аудит выполнен только по исходникам и существующим тестам. Ничего не собиралось и не запускалось: в PATH нет `git`, `cargo`, `rustc`. Все «исторические» доказательства помечены явно; они не перепроверены в этом окружении.

Смежные документы того же аудита: `docs/audit/function-index.md` (полный индекс C-функций), `docs/audit/datapath-detect-audit.md` (datapath + detect), `docs/audit/panel-router-vps-telegram-audit.md`, `docs/audit/matrix-consistency-audit.md`. Настоящий отчёт дополняет их разрезом core/controller и не заменяет их.

## 1. Резюме

1. Инвентарь C: 46 production-файлов, **1214** определений (1163 уникальных имён; повторы вроде `say`, `append_fmt`, `free`), найденных эвристическим парсером. Из них минимум два ложных срабатывания (`memcmp`/`strcmp` в `sched.c`, дубль `voice_trial_owned`) и несколько helper-макросов; фактически около **1210** функций.
2. Крупнейшие модули: `sched.c` — 286 определений (282 по счётчику проекта + 2 ложных + 2 пограничных), `verify.c` — 74, `httpsearch.c` — 66, `catalog.c` — 60, `quicprobe.c` — 57, `compose.c` — 53.
3. Rust-контроллер — не построчный порт. Он перестроен в `main.rs` (≈1,5 МБ), `discovery.rs`, `r2o_resource_limit.rs`, `fetch.rs`, `quic_replay.rs`, `http_search.rs` и набор специализированных модулей. Прямое соответствие «C-функция → Rust-функция» существует для протокольных кодеков, парсеров и планов; для планировщика соответствие идёт на уровне подсистем.
4. Доказанный паритет по контрактным весам матрицы: **80/89 = 89,89 %** (последняя запись матрицы, №171). Это не функция-уровневый процент: многие функции покрыты только косвенно, а часть C-кода в текущем production-пути вообще не вызывается. **Примечание сводного аудита:** 80/89 — legacy-агрегат; после нормализации 2026-11-08 строгая оценка текущей ревизии — 118/271 = 43,54 %, carry с явно помеченными `304` — 181/271 = 66,79 % (`docs/audit/README.md`, `docs/audit/validation-2026-11-08.md`).
5. Наиболее сильные доказанные участки: control-события (`d2k_link_next`), fallback-планы (`d2k_fallback_plan`), JSON-каталог и atomic save, QUIC Initial/QSN и HTTP/3, TLS 1.2 response probe, HTTP search lifecycle, Discord voice discovery/arm, IP-фрагментация, resource-limit gate, ряд scheduler cooldown/dead-address сценариев.
6. Наиболее слабые участки: CLI-совместимость `d2kask`/`d2kfetch`/`d2kvoice`/`d2kc` (нет прямых differential-тестов stdout/exit/JSON для большинства ветвей), `udpruntime.c` (raw UDP-отправка планов из контроллера), `p256.c`/`x25519.c`/`crypto.c` (заменены зависимостями, прямых C/Rust-векторов почти нет), диагностический учёт аллокатора/madvise, sysctl TCP timestamps, health/log/self-check у `d2kc`.
7. Обнаружены фактические расхождения поведения, а не только отсутствие тестов:
   - `d2kfetch` JSON: `level` не выдаёт 5/6 (blockpage/legal denial), `name_ok` выводится из наличия TLS, а не из проверки имени сертификата, `location` всегда строка, а не `null`;
   - `d2kask`: Rust отклоняет нечисловой `--ip` и невалидный ClientHello с кодом 1/2, тогда как C доходит до «ни один вопрос не задан» и возвращает 0; Rust запрещает повтор флагов, C берёт последний;
   - `d2kvoice`: C `--wait 0` означает default 3000 мс, Rust — ноль; Rust `--voice-list` принимает только `--conntrack`, C принимает любые флаги; различается блок «Приём»;
   - `d2kc`: C usage → exit 2, R2O `--serve` при ошибке аргументов → exit 1; отсутствуют `--measure-mark`, `--log`, `--health-file`, `--https-cache`, `--release-id`, `--self-check`; нет периодической сводки событий и health-file;
   - `plantlv`/`plan_text`: C принимает заголовок `d2k-plan`, Rust — только `r2o-plan` (каталог переписывает заголовок при импорте, но автономный компилятор — нет); C не требует `minexec>=13` для `autottl`, Rust требует.
8. `verdict.c` и `meas.c` в текущем `d2kc` не вызываются: production-путь идёт через `detect/`-дерево и хуки `d2k_sched_tcp_*`. Матрица, тем не менее, сопоставляет `meas.c` с Rust `classify::TcpProbeBackend`. Это надо переформулировать: Rust-классификатор — преемник `detect/`, а не API `d2k_meas*`.
9. Rust-код без C-аналога: `--watch`, `--journal`, `--http-candidates`, `--import-donor-catalog`, `--quic-budget`, `--control` у `r2o-fetch`, конкурентное слияние каталога (`merge_concurrent_changes`), отдельные Rust-модули `r2o_late_rx`/`r2o_quic_deny`/`r2o_resource` (в C логика встроена в `sched.c`) и HTTP/3-обвязка на `quinn`/`h3`.
10. Матрица содержит слишком широкие пункты с весом >1, смешивающие независимые контракты (scheduler/cooldown/queue, discovery, ACK/APPLIED, каталог, TLS 1.2 response, QUIC-лестница, Discord voice trial, HTTP search, firewall). Их следует разбить; предложение — в разделе 8.

## 2. Методика и легенда

Статусы:

| Статус | Значение |
|---|---|
| `equivalent` | Есть Rust-реализация и конкретный тест/дифференциал, который напрямую проверяет данный контракт (для исторических — с пометкой `hist.`). |
| `partial` | Реализация есть, но не покрыты существенные ветви/ошибки/таймеры/CLI-формат, либо тест покрывает только часть контракта. |
| `implemented-unproven` | Реализация есть, прямого теста/дифференциала не найдено. |
| `missing` | Rust-аналога нет. |
| `not-applicable` | Helper/OS-клей/тест-хук/мёртвый C-путь либо замена стандартной библиотекой/зависимостью без собственной функции. |

Правила:
- «Equivalent» не ставится по факту компиляции, наличия похожего имени или mock-теста.
- Для функций, заменённых `rustls`/`ring`/`quinn`/`hpke`/`serde_json`, статус зависит от наличия протокольного differential: если он есть — `partial`/`equivalent` с указанием, что прямой функции нет; если нет — `implemented-unproven`.
- Тесты, найденные только как C-тесты D2O без Rust-пары, доказательством Rust-паритета не считаются.

## 3. Сводка по файлам

| C-файл | Функций | Основной Rust-владелец | Покрытие | Итоговый статус |
|---|---:|---|---|---|
| `d2kask.c` | 24 | `ask.rs`, `main.rs::run_r2o_ask` | C `test_d2kask`, Rust unit `ask::tests`, `r2o-ask-differential.sh` (без сравнения stdout) | `partial` |
| `d2kfetch.c` | 6 | `src/bin/r2o-fetch.rs`, `fetch.rs` | `r2o_fetch_cli.rs`, `r2o-fetch-cli-differential.sh` (DNS + QUIC refusal) | `partial` |
| `d2kvoice.c` | 4 | `voice_measure.rs`, `voice_targets.rs` | Rust unit, Discord arm differential; CLI-дифференциала нет | `partial` |
| `d2kc.c` | 28 | `main.rs::{serve_catalog,watch_events}`, `diagnostics.rs`, `live.rs` | process/persistence/diagnostics tests; полного CLI-дифференциала нет | `partial` |
| `link.c` | 43 | `r2k-core/control.rs`, `main.rs::ControlClient` | `control.rs` tests, `d2o_control_differential.c`, ack/persist fixtures | декодирование `equivalent`, кодирование `partial` |
| `compose.c` | 53 | `ask.rs`, `classify.rs`, `r2o_fallback.rs`, `plan_text.rs`, `main.rs` | `r2o-fallback-differential.sh`, classifier differentials, ask unit | fallback `equivalent`, properties/compose `partial`, TCP profile `missing` |
| `plantlv.c` | 20 | `plan_text.rs` | `plan_text.rs` tests | `partial` |
| `props.c` | 5 | `quic_replay.rs`, `main.rs` QUIC worker | QUIC differentials/units | `partial` |
| `udpplan.c` | 12 | `quic_replay.rs`, `voice_discovery.rs`, `voice_measure.rs` | fallback/QUIC/voice arm differentials | `partial` |
| `udpruntime.c` | 8 | `r2k-core/plan`, datapath engine; raw UDP sender отсутствует | datapath apply tests | `partial`/`missing` |
| `net4.c` | 4 | `std::net`, `quic_replay::r2o_quic_address_is_local`, `voice_targets` | local-address policy differential | `partial` (private — `equivalent`) |
| `volume.c` | 19 | `r2o_volume.rs`, `fetch.rs::{r2o_fetch_measure_tx_volume,r2o_fetch_measure_rx_volume}` | `r2o_volume.rs` unit, fetch CLI ladder tests | `partial` |
| `catalog.c` | 60 | `catalog.rs` | `r2o-catalog-persist/sync`, catalog tests | загрузка/сохранение `equivalent`, parser internals `partial` |
| `domain.c` | 4 | `domain.rs` | Rust unit | `implemented-unproven` |
| `groups.c` | 14 | `groups.rs` | Rust unit | `implemented-unproven` |
| `match.c` | 3 | `catalog.rs::is_compatible_with`, `catalog.rs::match_fingerprint` | catalog/known-plan tests | `partial` |
| `meas.c` | 13 | `classify.rs` (преемник `detect/`), `r2o_quic_http3` fresh ports | `r2o-meas-differential.sh`, port-claim units | `partial`; `d2k_meas` в C мёртв |
| `measured.c` | 12 | `classify_measured.rs`, `r2o_rx_volume.rs` | measured plan tests, raw split differentials | `partial` |
| `verdict.c` | 7 | `classify.rs` (иной API) | classifier differentials | `not-applicable` (мёртвый C-путь) |
| `diagnostics.c` | 41 | `diagnostics.rs` | `r2o-diagnostics-differential.sh`, unit | отчёт/tick `equivalent`, memory/madvise `missing` |
| `httpsearch.c` | 66 | `main.rs` HTTP search worker, `http_search.rs` | `r2o-http-search-differential.sh`, 12+ C fixtures | lifecycle `equivalent`, runner `partial` |
| `httpsprobe.c` | 22 | `https_probe.rs`, `response.rs` | panel/ECH tests | `partial`; `d2k_httpsprobe_lost` отсутствует |
| `httpup_logic.c` | 17 | `r2k-core/httpup.rs` | Rust unit | `implemented-unproven`/`partial` |
| `h3.c` | 9 | crate `h3` + `r2o_quic_http3.rs` | HTTP/3 differentials | `partial` |
| `hello.c` | 19 | `r2k-core/tls.rs`, `controller/hello.rs`, `r2o_tls.rs` | hello/ECH tests, classifier differentials | `partial` |
| `tls12.c` | 26 | `rustls` + `fetch.rs` replay | TLS verify/shared fixtures | `partial` (замена зависимостью) |
| `tls13.c` | 23 | `rustls` + `r2o_tls.rs` | TLS verify/ECH differentials | `partial` (замена зависимостью) |
| `tls13core.c` | 24 | `rustls`, `ech.rs` (HPKE), `hello.rs` | ECH differentials/units | `partial` |
| `verify.c` | 74 | `fetch.rs`, `response.rs`, `ech.rs`, `https_probe.rs` | TLS/HTTP/ECH/Gateway differentials | ядро `equivalent`/`partial`, бюджет/QUIC `partial` |
| `verify_quic_replay.c` | 2 | `quic_replay.rs` + `fetch.rs` | QUIC differentials | `partial` |
| `quic.c` | 21 | `r2k-core/quic.rs` | RFC 9001 vectors, QUIC hello differential | `equivalent`/`partial` |
| `quicarms.c` | 8 | `quic_replay.rs` | QUIC strategy units | `partial` |
| `quicconn.c` | 36 | `quinn`/`rustls`, `r2o_quic_http3.rs` | HTTP/3 full-stage | `partial` |
| `quichello.c` | 13 | `r2o_tls.rs`, `quic_replay.rs` | hello rename/split tests | `partial` |
| `quicprobe.c` | 57 | `quic_replay.rs`, `fetch.rs` | 29+ QUIC fixtures, many differentials | `partial` (большинство ветвей покрыто) |
| `quicsnap.c` | 6 | `r2k-core/quic_snapshot.rs` | snapshot tests | `equivalent`/`partial` |
| `quicsnap_reseal.c` | 2 | `r2k-core/quic.rs::r2k_quic_initial_reseal_for_dcid` | RFC vectors | `partial` |
| `quicwire.c` | 28 | `r2k-core/quic.rs`, `wire.rs` | RFC 9001/9369 vectors | `equivalent` for wire primitives |
| `sched.c` | 286 | `main.rs`, `discovery.rs`, `r2o_resource_limit.rs`, специализированные модули | 20+ scheduler differentials | `partial` по подсистемам |
| `stun.c` | 5 | `r2k-core/stun.rs`, `voice_measure.rs` | `tests/stun.rs`, C `test_stun` | `partial` |
| `voice.c` | 14 | `voice_measure.rs`, `voice_targets.rs` | unit + voice discovery differential | `partial`; raw arm `missing` |
| `voice_discovery.c` | 7 | `voice_discovery.rs` | `test-discord-voice-discovery-arm-differential.sh` | `partial`/`equivalent` |
| `ipfrag.c` | 8 | `r2k-core/wire.rs`, datapath `raw.rs` | `test-ipfrag-differential.sh` | `equivalent` |
| `crypto.c` | 28 | RustCrypto `aes`/`aes-gcm`/`hkdf`/`sha2`, `ring` | RFC 9001 vectors | `equivalent` для QUIC-примитивов, остальное `partial` |
| `p256.c` | 22 | `rustls`/`ring` (P-256 ECDHE) | TLS 1.2 differentials | `implemented-unproven` |
| `x25519.c` | 11 | `hpke` `X25519HkdfSha256`, `rustls` | ECH/QUIC tests | `partial` |

## 4. Детальные таблицы

В таблицах ниже перечислены все функции, сгруппированные только там, где helper тривиален или где подсистема уже сгруппирована в самом задании (`sched.c`). Если имя функции не выписано в таблице отдельной строкой, оно входит в указанную группу/диапазон и наследует её статус; полный перечень имён с номерами строк для каждого файла — в Приложении A. Статус группы относится ко всем её членам, если в тексте не названо исключение.

### 4.1. `link.c` (43)

Клиентская сторона AF_UNIX-протокола. Rust-кодеки находятся в `r2k-core/src/control.rs`; транспорт и корреляция ACK — в `main.rs::ControlClient` (14495/14660).

| C-функция (строка) | Rust-аналог (файл:строка) | Ветви/состояния и отличия | Тесты | Статус |
|---|---|---|---|---|
| `execution_context` (45) | `control.rs:decode_applied` (1846), `decode_refused` (1918) | 8-байтовый execution ID + binding; неполный контекст — отказ. | `refused_decodes_exact_trial...`, `round_trips_an_applied_http_probe...` | `equivalent` |
| `say` (56) | форматирование ошибок `Result<_, String>` | Тексты ошибок не совпадают дословно. | — | `not-applicable` |
| `wait_readable` (70), `read_exact` (92), `write_all` (108) | `main.rs:wait_for_control_frame` (14434), `read_optional_frame` (14404), `ControlClient::exchange_command_with_timeout` (20344) | C повторяет `poll/recv/send` на EINTR и не перезапускает бюджет после начала кадра; Rust использует `read_timeout`/`write_timeout` 2 с и циклы. | `ask_accepts_a_plan_ack...`; `r2o-control-dropped-differential.sh` | `partial` |
| `hex_nibble` (133), `hex_decode` (140) | `plan_text.rs:hex` (648), `ask.rs:decode_hex` (214) | В link.c hex — это план; Rust компилирует текст плана, а не hex-строку. | `plan_text.rs` tests | `not-applicable` (иная форма) |
| `d2k_link_open` (161) | `main.rs:ControlClient::connect` (14661) | C путь обязателен; Rust — тот же `UnixStream::connect`, таймауты 2 с. | `control_cli` tests | `partial` |
| `d2k_link_close` (191) | `Drop for ControlClient` (14660+) | Закрытие сокета. | — | `not-applicable` |
| `d2k_link_peer_closed` (197) | EOF/`read_optional_frame` в `watch_events` (15391) | C `poll(POLLHUP/POLLERR)`; Rust ловит `Ok(None)` и выходит из цикла. | process tests | `partial` |
| `d2k_link_next` (223) | `control.rs:event` (2261) + `decode_hello` (2084), `decode_ack` (1597), `decode_applied` (1846), `decode_refused` (1918), `decode_http_*` (2582/2627) | Все типы событий, ключ потока 38 байт, IPv4-tail, опциональные поля, REFUSED/APPLIED identity. | `d2o_control_differential.c` (C `d2k_link_next` vs Rust), `control.rs` tests | `equivalent` (историческое; прямой differential) |
| `d2k_link_set_name` (524) | `control.rs:encode_set_name` (916) | Имя ≤255, транспорт 6/17, hex-план, форма, семейство; пробный порт 0. | `encodes_http_probe_command...`, `tcp_probe_encoder...` | `partial` |
| `d2k_link_set_name_probe` (531) | `control.rs:encode_set_name_probe` (1377) | Ненулевой `sport_be` → `SET_NAME_PROBE`, trial ID. | те же + `ask` unit | `partial` |
| `send_name_plan` (538) | внутренний код `encode_set_name`/`encode_set_name_probe` | Сборка кадра, предел `D2K_CTL_FRAME_MAX`, порядок name/shape/family/port/plan/trial. | `control.rs` tests | `partial` |
| `d2k_link_set_name_family` (632) | `encode_set_name` (916) | Явное семейство 4/6. | `control.rs` tests | `partial` |
| `d2k_link_set_name_bound` (639) | `encode_set_name_bound` (948) | Постоянная привязка с 16-байтовым binding token. | `bound_set_name_round_trips...` | `partial` |
| `d2k_link_del_name_bound` (645) | `encode_delete_name_bound` (1432) | Условное удаление по binding; проверка kind/temporary. | `conditional_http_delete_serializes...` | `partial` |
| `d2k_link_set_name_probe_trial` (659) | `encode_set_name_probe` (1377) | Требует ненулевой порт; trial ID. | `ask` unit | `partial` |
| `area_context_valid` (670) | `control.rs:valid_domain_area_context` (1108) | TCP-формы 1/2/6/…; UDP-форма 3. | `catalog_area_command_wire_matches_donor` | `equivalent` |
| `d2k_link_set_suffix_family` (677) | `encode_set_suffix` (1035) | SET_SUFFIX с trial-контекстом. | catalog sync tests | `partial` |
| `d2k_link_set_https` (686) | `encode_set_https` (1330) | Имя ≤253, TTL u32. | `encodes_the_exact_https_name...` | `partial` |
| `d2k_link_set_stall_budgets` (707) | `encode_set_tcp_stall_budgets` (1345) | ≤8 бюджетов, нули запрещены. | `control.rs` test (270) | `partial` |
| `send_area_key` (731) | `encode_domain_area_key` (1088) | Имя + транспорт/форма/семейство + 16 байт area ID. | `catalog_area_command_wire_matches_donor` | `partial` |
| `d2k_link_del_suffix_family` (754) | `encode_delete_suffix` (1061) | DEL_SUFFIX. | catalog sync tests | `partial` |
| `d2k_link_set_bypass_family` (758) | `encode_set_bypass` (1070) | SET_BYPASS. | catalog sync tests | `partial` |
| `d2k_link_del_bypass_family` (762) | `encode_delete_bypass` (1079) | DEL_BYPASS. | catalog sync tests | `partial` |
| `d2k_link_area_identified` (767) | `encode_domain_area_key`/`encode_set_suffix` с id | Идентифицируемая area-команда. | catalog sync tests | `partial` |
| `addr_shape_ok` (783) | `control.rs:valid_addr_shape` (1019) | Только измеренные формы TLS/ECH/QUIC/voice. | `encode_set_addr` tests | `equivalent` |
| `d2k_link_set_addr` (789), `d2k_link_set_addr_family` (794) | `encode_set_addr` (974) | IPv4/IPv6, форма, план; запрет HTTP-формы. | `control.rs` test (191..238) | `partial` |
| `addr_probe_flow_bytes` (852) | `control.rs:udp_addr_probe_flow` (1224), `valid_udp_addr_probe_flow` (1255) | 38-байтовый ключ потока, UDP only, src_port 0 разрешён для voice. | `control.rs` test (130) | `equivalent` |
| `d2k_link_set_addr_probe` (868), `..._family` (877) | `encode_set_addr_probe` (1186) | trial ID, lease ≤ max, план, запрет нулевого trial. | тот же тест | `partial` |
| `d2k_link_del_addr_probe` (911), `..._family` (919) | `encode_delete_addr_probe` (1209) | trial ID + ключ потока. | тест (148) | `partial` |
| `d2k_link_arm_shape` (939), `..._family` (944) | `encode_arm_shape` (803) | Имя + транспорт + семейство. | `arm_shape_roundtrips...` | `equivalent` |
| `d2k_link_del_name_family` (981) | `encode_delete_name` (1406) | Имя/транспорт/форма/семейство. | тест (695) | `partial` |
| `d2k_link_del_name_probe` (1014), `..._family` (1020) | `encode_delete_name_probe` (1459) | Пробное удаление по имени/форме/порту/семейству. | `ask` unit + classify tests | `partial` |
| `d2k_link_del_addr` (1051), `..._family` (1056) | `encode_delete_addr` (999) | IPv4/IPv6 + форма. | тест (227) | `partial` |
| `d2k_ev_outer_appdata` (1079) | `control.rs:decode_tcp_exchange` (2426) + `seen_types` | Бит 23 в маске, не сравнение первого типа. | `tcp_exchange_round_trips...` | `equivalent` |



### 4.2. `compose.c` (53)

Ключевой модуль свойств инспектора, пяти вопросов, fallback-плеч и `d2k_compose`. Rust-владельцы: `ask.rs`, `classify.rs`, `r2o_fallback.rs`, `plan_text.rs`.

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `d2k_net_whitelist_count` (13), `d2k_net_whitelist_name` (110) | `r2o_rx_volume.rs:1` (`data/r2o_tcp1620_whitelist.txt`), `main.rs` network whitelist | C-список генерируется Makefile из `profiles/tcp1620_whitelist.txt`; Rust-ассет статический. Проверяется решение, не побайтовое равенство списков. | `r2o-net-whitelist-probe-differential.sh`, `network_whitelist_probe_decisions_matches_d2o` | `partial` |
| `wr16be` (140), `rd16be` (151), `wr32be` (152) | `plan_text.rs:push_u16/push_u32` (733/737), `control.rs` encoders | Запись big-endian. | `plan_text.rs` tests | `equivalent` |
| `tlv_rec` (157), `tlv_header` (176), `plan_tlv_stamp_ident` (200) | `plan_text.rs:compile_text` (67), `ask.rs:question_plan` (426) | Сборка TLV и подстановка Plan ID; Rust компилирует текст и проверяет `Plan::parse`. | `compiles_payload_poison_fake_and_split...`, `built_question_plan_is_accepted...` | `partial` |
| `overlap_plan_tlv` (244), `reorder_plan_tlv` (274), `badsum_fake_plan_tlv` (292), `checksum_plan_tlv` (318) | `ask.rs:question_plan` (426) → `plan_text_for_poison` | Пять вопросов: seqovl, disorder, badsum-fake, checksum-filler. | `question_order_and_plan_parameters_match_the_five_donor_probes` | `partial` |
| `to_hex` (328) | `ask.rs:hex` (374) | Hex-представление плана. | — | `not-applicable` |
| `ev_matches_flow` (340), `wait_for_event3` (368), `wait_for_event` (423) | `main.rs:wait_for_command_ack` (20380), `r2o_read_control_batch` (14462), `wait_for_ask_proof` (18470) | Сверка ключа потока, типа команды, таймаута и пропуск чужих событий. | `pass_waits_for_matching_applied_and_server_hello_events`, `unrelated_refusal_does_not_finish_an_ask_question` | `partial` |
| `props_bind_any` (485), `d2k_props_bind` (526), `d2k_props_bind_family` (530), `d2k_props_bind_udp` (534), `d2k_props_bind_udp_family` (538) | `ask.rs` + `classify.rs::BoundTcpProbe::open` (main.rs 390) | Занять локальный порт до установки плана; IPv6 `V6ONLY`. | `ask` unit + `candidate_confirmation_uses_datapath_mark...` | `partial` |
| `d2k_props_contact` (542), `contact_on` (547), `contact_on_family` (553) | `ask.rs:run_r2o_ask` (481), `classify.rs` contact | Непомеченный `connect + send` без чтения; сохраняет сокет открытым. | `ask` unit; classifier differential | `partial` |
| `tcp_timestamps_read` (567), `tcp_timestamps_write` (580), `connect_with_tcp_profile` (589) | — | C временно меняет sysctl `/proc/sys/net/ipv4/tcp_timestamps` на время `connect()`. Rust управляет наличием TS только в raw-SYN (`raw_probe.rs:raw_offer_timestamps`, 673), для обычного connect переключения нет. | — | `missing` |
| `d2k_props_contact_on_family_tcp_profile` (638) | `main.rs`/`classify.rs` без sysctl-профиля | Частичная замена: raw-путь задаёт TS, plain-путь — нет. | raw profile tests | `partial` |
| `build_fake_body` (755) | `ask.rs:question_plan` (426) | Двойная длина правды, decoy в голове только для parse; Rust повторяет. | `question_order...` | `equivalent` |
| `d2k_props_question_plan` (798) | `ask.rs:question_plan` (426) | Порядок вопросов donor: overlap, reorder, checksum, parse, duplicates. | `question_order...` | `partial` |
| `d2k_props_question_passed` (845) | `ask.rs:record_question_passed` (486) | Запись свойств только по проходу; parse пишет два поля. | `protocol_parse_requires_control...` | `equivalent` |
| `question_retire` (866) | `main.rs:delete_name_probe` (18232) | Снятие ровно своей пробы по имени/форме/порту/семейству. | `ask` trace tests, classify retries | `partial` |
| `d2k_props_ask` (881), `d2k_props_ask_traced` (900) | `main.rs:run_r2o_ask` (230) | Полный цикл пяти вопросов; Rust разбит на линейный код с `R2oAskProof`. | `ask` unit; `r2o-ask-differential.sh` | `partial` |
| `append_fmt` (1193), `emit_header_proto` (1215), `emit_header` (1229), `append_hex` (1233) | `plan_text.rs` builders, `ask.rs:compose_badsum_fake_plan` (364) | Сборка текста `d2k-plan`; Rust использует `r2o-plan`. | `plan_text.rs` tests | `partial` |
| `overlap_plan_text` (1241) | `ask.rs:question_plan(LeftOverlap)` | `payload 1 0f`, `seqovl payload=1 poison=0`. | `question_order...` | `equivalent` |
| `reorder_plan_text` (1263) | `ask.rs:question_plan(Reorder)` | Два split + reverse + pace 12000. | тест (525) | `equivalent` |
| `badsum_fake_plan_text` (1288) | `ask.rs:compose_badsum_fake_plan` (364) | `payload 1`, `poison badsum`, `fake repeats/gap/place`, pace 15000. | `compose_builds_donor...` | `equivalent` |
| `checksum_plan_text` (1312) | `ask.rs:question_plan(Checksum)` | 64×0x0f filler, repeats=1, gap=0. | тест (530) | `equivalent` |
| `build_decoy_hello` (1319) | `ask.rs:compose_plan_texts` (309) → `hello::modern/legacy_client_hello` | C строит decoy профилем по `target_shape`; Rust — тем же профилем. Для UNKNOWN C берёт legacy; Rust условие `shape == MODERN`, иначе legacy. | `hello.rs` tests | `equivalent` |
| `parse_protocol_plan_text` (1353) | `ask.rs:question_plan(ProtocolParse)` | Decoy в голове, хвост filler, fake badsum. | тест (535) | `equivalent` |
| `duplicates_plan_text` (1363) | `ask.rs:question_plan(Duplicates)` | Repeats=2, gap=20000; C в `d2k_props_ask` использует filler, Rust — тоже (decoy=None). | тест (550) | `equivalent` |
| `body_room` (1374) | `r2o_fallback.rs` (`send_cap.saturating_sub(120)`), `ask.rs` (341) | C вычитает 60+60; Rust — 120. Численно совпадает, но выражено иначе. | `r2o-fallback-differential.sh` | `equivalent` |
| `everything_plan_text` (1395) | `ask.rs:compose_plan_texts` (339) | Единственный кандидат при пустом векторе; Rust формирует тот же набор директив. | `compose_builds_donor...` | `partial` |
| `d2k_fallback_arms` (1491) | `r2o_fallback.rs:arm` (114), `FallbackQueue::next` (93) | 49 плеч, порядок donor. | `fallback_queue_batches_and_tried_hashes_match_donor`, `d2o_fallback_differential.c` (hist.) | `equivalent` |
| `fb_arm_at` (1504) | `r2o_fallback.rs:arm` (114) | Индексация head/fake/ttl/seqovl/dup. | тот же differential | `equivalent` |
| `d2k_fallback_plan` (1543) | `r2o_fallback.rs:plan` (168) | Полный текст плана для индекса; сравнивается с C побайтово. | `r2o-fallback-differential.sh` (hist.) | `equivalent` |
| `d2k_arm_plan` (1552) | `r2o_fallback.rs:plan` (168) | C поддерживает `md5` только измеренным сборщиком и отвергает здесь; Rust `md5` не имеет и также не строит. Segment cap, oob, disorder_pos. | тот же differential | `partial` (нет отдельного C/Rust теста на все ветви) |
| `d2k_compose` (1753) | `ask.rs:compose_plan_texts` (299) | Порядок веток donor; отличие: Rust не проверяет `target_shape` для decoy при `UNKNOWN`. | `compose_builds_donor_ordered_plans...` | `partial` |



### 4.3. CLI-модули

#### `d2kask.c` (24)

| C-функция (строка) | Rust-аналог (файл:строка) | Вызывающий путь и покрытие | Тесты/дифференциалы | Статус |
|---|---|---|---|---|
| `need_value` (120) | `ask.rs:parse_ask_options` (44) | Разбор `--ask`; проверяет наличие значения у флага. Rust отклоняет неизвестный/повторный флаг, C — только неизвестный. | `ask::tests::ask_options_reject_ambiguous_snapshot_sources_and_bad_marks` | `partial` (повтор флага) |
| `parse_flag_u16` (134) | `ask.rs:parse_positive_port` (168) | `--port`: C `strtoul` 1..65535; Rust `u16` + запрет 0. | `ask_options_keep_capture_inputs_and_c_defaults` | `equivalent` (диапазон/0) |
| `parse_flag_u32` (157) | `ask.rs:parse_mark` (190) | `--mark`: база 0, hex/octal/decimal, запрет минуса. | `ask_options_reject...bad_marks` | `equivalent` |
| `parse_flag_ms` (179) | `ask.rs:parse_positive_ms` (179) | `--arm-wait-ms`: >0, иначе отказ. | тот же тест | `equivalent` |
| `parse_args` (196) | `ask.rs:parse_ask_options` (44) | Обязательные `--control/--ip/--sni`, взаимоисключения, `--control-sni` требует `--arm-wait-ms`. Отличия: Rust строго парсит `IpAddr`, C передаёт строку в `inet_pton` позже; Rust запрещает дубли. | `ask_options_keep...`, `ask_options_reject...` | `partial` |
| `hex_nibble` (303) | `ask.rs:decode_hex` (214) | Разбор hex-снимков. | `saved_hex_reader_accepts_comments_and_rejects_non_hex_data` | `equivalent` |
| `save_hex` (322) | `main.rs:save_ask_snapshot` (680) | Формат `# снимок …` + 32 байта в строке; C пишет в `--save-trigger/--save-control`, Rust — те же имена. | unit-теста формата нет | `partial` |
| `read_hex_file` (351) | `ask.rs:read_hex_file` (209) | Комментарии `#`, пробелы, чётность, пустой файл, потолок 2048. | `saved_hex_reader...` | `equivalent` |
| `wait_shape` (416) | `main.rs:wait_for_client_shape` (18304) | Ожидание `D2K_EV_SHAPE` с общим бюджетом; пропуск чужих событий. Rust использует `ControlClient` и таймаут `ASK_WAIT`/`--arm-wait-ms`. | `ask_accepts_a_plan_ack_that_arrives_after_the_generic_three_second_deadline` (косвенно) | `partial` |
| `pval_str` (462) | `main.rs:r2o_tri_state` (708) | Тройственная логика → «да/нет/не измерено». | `protocol_parse_requires_control...` | `equivalent` |
| `print_header` (470) | `main.rs:run_r2o_ask` (230) | C печатает `d2kask: спрашиваем…`, цель, имя, сокет, метку; Rust — только цель/имя/сокет/метку без заголовка. | нет | `partial` |
| `print_snapshot` (478) | `main.rs:run_r2o_ask` (230) | C печатает SNI **и вид** приветствия (`MODERN/LEGACY/UNKNOWN`); Rust печатает только длину и SNI. | нет | `partial` |
| `pos_decided` (513), `pos_value` (530) | `main.rs:run_r2o_ask` (230) | Логика «вопрос задан/решён»; C учитывает побочный `validates_checksum` от `parses_l7`, Rust использует `record_question_passed` и `DpiProps`. | `protocol_parse...only_its_proven_fields` | `partial` |
| `step_rc_str` (541), `step_rc` (886) | `main.rs:r2o_print_ask_trace` (14622) | Текстовые причины остановки шага. Наборы причин совпадают не полностью (Rust объединяет часть ветвей). | нет | `partial` |
| `ack_code_str` (563) | `main.rs:r2o_ask_ack_reason` (14593) | `OK/BAD_PLAN/BAD_ARGS/NO_ROOM` → русский текст. | `ask` unit (косвенно) | `equivalent` |
| `print_seen_types` (575) | `main.rs:r2o_ask_print_seen_types` (14603) | Маска TLS-типов 20..23 → текст. | нет | `equivalent` |
| `print_step` (597) | `main.rs:r2o_print_ask_trace` (14622) | План/обмен/причина; Rust печатает `план N байт`, `обмен …`, но без части C-полей (`ack_code` в тексте, `err`). | нет | `partial` |
| `print_question` (626) | `main.rs:run_r2o_ask` (230) | Печать одного из 5 вопросов; Rust перечисляет вопросы циклом и не воспроизводит C-текст «спрошен: нет/да» дословно. | нет | `partial` |
| `all_unknown` (676) | `ask::DpiProps::default` + `run_r2o_ask` | Определение «ни один зонд не прошёл». | нет | `partial` |
| `print_not_asked_at_all` (684) | `main.rs:run_r2o_ask` (332) | C печатает 5 блоков; Rust — 5 строк «не задан». | нет | `partial` |
| `print_vector` (698) | `main.rs:run_r2o_ask` (643) | Итоговый вектор; порядок полей Rust: overlap, reorder, checksum, parses_l7, duplicates — совпадает с C. | нет | `partial` |
| `print_plans` (707) | `main.rs:run_r2o_ask` (664) | Печать `d2k_compose`; Rust вызывает `compose_plan_texts` и печатает планы. | `compose_builds_donor_ordered_plans...` | `partial` |
| `main` (727) | `main.rs:r2o_ask_command` (192) → `run_r2o_ask` (230) | Коды: 2 — вход, 1 — среда, 0 — прогон. Rust сохраняет коды, но иначе трактует невалидный IP/снимок (см. расхождения). | `ask_help_exposes...`; `r2o-ask-differential.sh` (только C `test_d2kask` + Rust unit) | `partial` |

#### `d2kfetch.c` (6)

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `json_string` (41) | `serde_json::json!`/`serde_json::to_string` | C вручную экранирует и валидирует UTF-8; serde делает это иначе для невалидных последовательностей. Ключи JSON почти совпадают. | `r2o_fetch_cli.rs` (схема) | `partial` |
| `vol_verdict_code` (64) | `src/bin/r2o-fetch.rs:r2o_verdict` (226) | `unreachable/cut/passed/short`; Rust-строки те же. | `r2o_json_keeps_transmit_and_receive_ladder_results_separate` | `equivalent` |
| `usage` (74) | `src/bin/r2o-fetch.rs:print_help` (693) | Rust добавляет `--quic-budget`, `--control`; C — нет. | `r2o_help_...` | `partial` |
| `resolve_first` (104) | `ToSocketAddrs` (`run` 167) | Оба берут первый адрес; C `getaddrinfo(AF_UNSPEC, SOCK_STREAM)`, Rust `(name, port).to_socket_addrs()`. | `r2o_json_reports_an_empty_address_without_falling_back_to_dns` | `partial` |
| `snapshot_wire` (117) | `fetch.rs:r2o_fetch_snapshot_wire_len` (29), `src/bin/r2o-fetch.rs` (142) | C взводит `ARM_SHAPE(transport=6)` и ждёт `D2K_EV_SHAPE`; Rust использует `.snapshot`-сокет datapath. | `r2o_fetch_snapshot_precedes_address_validation`, `r2o_fetch_quic_snapshot_preserves_client_hello_wire_length` | `partial` |
| `main` (157) | `src/bin/r2o-fetch.rs:run` (22) | Сценарии TCP/QUIC/ladder/json/exit; отличия в `level`, `name_ok`, `location`, тексте non-JSON. | `r2o_fetch_cli.rs` (12), `r2o-fetch-cli-differential.sh` (DNS + marked QUIC refusal) | `partial` |

#### `d2kvoice.c` (4)

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `usage` (22) | `main.rs:r2o_voice_check_command` (716) | Rust-строка использования содержит те же флаги, кроме `--list` (у Rust отдельная команда `--voice-list`). | нет | `partial` |
| `split_hostport` (39) | `voice_measure.rs:r2o_parse_voice_address` (803) | C требует ровно `IPv4:port`; Rust `SocketAddrV4`. C `strtoul` без проверки хвоста, Rust строгий. | `r2o_parse_voice_options` unit (косвенно) | `partial` |
| `verdict_word` (50) | `voice_measure.rs:r2o_format_voice_measurement` (296) | Семь вердиктов и русские формулировки совпадают. | unit на формат (косвенно) | `equivalent` |
| `main` (63) | `main.rs:r2o_voice_check_command` (716), `r2o_voice_list_command` (740) | Коды 0/1/2 совпадают. Отличия: `--wait 0`, строгость `--voice-list`, блок «Приём», отсутствие C-поля `fake_arm`/`arm_copies`. | `voice_measure` unit; `test-discord-voice-discovery-arm-differential.sh` (arm, не CLI) | `partial` |

#### `d2kc.c` (28)

| C-функции (строки) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `on_signal` (111), `now_ms` (113) | `main.rs:install_r2o_controller_signal_handlers` (85), `Instant` | SIGINT/SIGTERM → флаг остановки; Rust дополнительно полагается на игнор SIGPIPE от std. | process tests | `equivalent` |
| `save_atomic` (119) | `catalog.rs:save_atomic` (464), `main.rs:R2oCatalogPersistence::persist` (1761) | C tmp+rename; Rust — lock + merge + save_atomic. | `r2o-catalog-persist-differential.sh`, `r2o-catalog-sync-differential.sh` | `equivalent` (но Rust шире по семантике) |
| `self_mem` (127) | `diagnostics.rs:process_memory` (474), `read_smaps` (570) | C читает `/proc/self/status`; Rust — статус/smaps. Периодической сводки RSS в цикле контроллера нет. | `process_memory_follows_pidfiles...` | `partial` |
| `sched_say` (150) | `println!`/`eprintln!` | Формат и адресат отличаются; C использует `quiet`-слоты. | нет | `partial` |
| `http_search_portal` (168), `hs_open_port` (176), `hs_close_port` (210) | `main.rs:HttpSearchWorker`, `ControlClient` | Порты и runner HTTP-поиска. | `r2o-http-search-differential.sh` | `partial` |
| `hs_hex` (212), `hs_set_probe` (221), `hs_del_probe` (235), `hs_set_plan` (246), `hs_del_plan` (259), `hs_start` (271), `hs_changed` (277) | `main.rs:` HTTP search ops, `control.rs` encoders | Команды/порты проб. | HTTP search fixtures | `partial` |
| `http_portal` (287), `http_push` (310), `http_save` (317), `http_probe_done` (324), `hs_say` (357), `poison_cmp` (365), `hs_measured_poisons` (368) | `main.rs:run_http_search_task` (21047), `https_probe.rs`, `http_search.rs` | HTTPS-портал, сохранение кэша, measured poisons. | `r2o-http-search-differential.sh`, panel HTTPS tests | `partial` |
| `usage` (394) | `main.rs:print_help` (1431) | Набор флагов не совпадает (см. раздел 5). | нет | `partial` |
| `offline_self_check` (406) | — | В R2O `--self-check` для контроллера отсутствует. | — | `missing` |
| `diagnostic_event` (415), `diagnostic_limit` (418) | `diagnostics.rs:record` (189) | Запись событий/лимитов. | `r2o-diagnostics-differential.sh` | `partial` |
| `diagnostic_tick` (421) | `diagnostics.rs:tick` (223), `write_report` (332) | Интервал 1/60 с, атомарная запись `report.json`, отключение при удалении каталога. | `diagnostic_tick_lifecycle_matches_d2o`, differential | `equivalent` |
| `main` (470) | `main.rs:serve_catalog` (1655) → `watch_events` (15191) | Главный цикл: события, sync-порции, tick, live, save, shutdown. | `test-controller-process-reapply-qemu.py`, catalog tests | `partial` |

### 4.4. `plantlv.c` (20)

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `b64_value` (126), `parse_base64` (133) | `plan_text.rs:base64_value` (710), `base64` (675) | Base64 для `payload-pad64`; C проверяет padding-биты, Rust — через общий декодер. | `plan_text.rs` tests | `partial` |
| `say` (163) | `Result<_, String>` | Тексты ошибок иные. | — | `not-applicable` |
| `hex_nib` (171), `parse_hex` (178) | `plan_text.rs:hex_nibble` (666), `hex` (648) | Чётность, пустая строка, недопустимый символ. | `plan_text.rs` tests | `equivalent` |
| `anchor_by_name` (206) | `plan_text.rs:anchor` (721) | Шесть якорей: payload_start=0 … sni_middle=5. | `plan_text.rs` tests | `equivalent` |
| `split_fields` (219) | `line.split([' ', '\t'])` (81) | C ограничивает 8 полей; Rust `MAX_DIRECTIVES=8`. | `plan_words_only_split_on_ascii_space_and_tab` | `equivalent` |
| `parse_uint` (235), `parse_int` (248), `kv_u32` (259), `str_u32` (265) | `plan_text.rs:number` (623), `kv_number` (640), `parse_autottl` (631) | Строгие десятичные, знак только у `seqshift`/`autottl`. | `plan_text.rs` tests | `equivalent` |
| `plan_free` (272) | `Drop`/`Vec` | Освобождение. | — | `not-applicable` |
| `parse_text` (277) | `plan_text.rs:compile_text` (67) | Все директивы; C принимает `d2k-plan`, Rust — `r2o-plan`; C не требует `minexec>=13` для `autottl`, Rust требует (Plan::parse/scan). | `plan_text.rs` tests | `partial` |
| `put` (691), `put_u8` (696), `put_u16` (697), `put_u32` (698), `put_rec` (702) | `plan_text.rs:push_u16` (733), `push_u32` (737), сборка records (521..601) | Порядок записей donor: ID, PROTO, payload, poison(+autottl), split, fake, seqovl, ORDER, PACE, INPUT, SETTLE, SEGMENT, INPUT_TLS, DELAY, WIRE, IPFRAG, UDPLEN, QSPLIT, QDENY, OOB, GUARD. | `compiles_payload_poison_fake_and_split...` | `partial` |
| `d2k_plan_text_to_tlv` (709) | `plan_text.rs:compile_text` (67) | Канонический TLV; Rust дополнительно валидирует `Plan::parse` и `validate_runtime_plan`. | `plan_text.rs` tests | `partial` |
| `d2k_plan_text_to_hex` (847) | `ask.rs:hex` (374) | Hex от TLV. | — | `equivalent` |

### 4.5. `props.c` (5)

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `original_probe` (35) | `quic_replay.rs` `r2o_quic_original_fallback_candidates` (506), `r2o_quic_ask_donor_parallel` (891) | Снимок/нейтральное имя, вызов проводного зонда. | `r2o_quic_donor_parallel_control_matches_d2o` | `partial` |
| `original_data` (47) | `quic_replay.rs` data-stage/HTTP3 helpers | Data-stage того же адреса/имени. | `d2o_quic_data_stage_loopback.c`, HTTP/3 differentials | `partial` |
| `wire_measure` (52) | `quic_replay.rs:r2o_quic_base_result` (289), `r2o_quic_strategy_attempt_decision` (368) | Общая обвязка «arm + probe + data». | unit + differentials | `partial` |
| `d2k_quic_original_measure` (80) | `r2o_quic_original_fallback_candidates` (506), `main.rs:run_quic_discovery_candidate` (18576) | Перебор original arms. | `test-quic-*` | `partial` |
| `d2k_quic_strategy_measure` (85) | `r2o_quic_strategy_attempt_decision` (368), `r2o_quic_adaptive_split_candidate` (557) | Сначала вопросы стратегии, fallback — original. | `r2o_quic_*` tests | `partial` |

### 4.6. `udpplan.c` (12)

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `append_fmt` (2), `emit_header_proto` (22), `append_hex` (36) | `plan_text.rs` builders, `r2o_fallback.rs` formatting | Сборка текста плана. | `plan_text.rs` tests | `partial` |
| `quic_arm_found` (44) | `quic_replay.rs:R2oQuicCandidateKind` (193) | Классификация найденного плеча. | unit | `partial` |
| `quic_split_plan_text` (56) | `quic_replay.rs` directives (`quicsplit 1`), `discovery.rs:2173` | Текст `r2o-plan 1 10 … quicsplit 1`. | `discovery` tests | `partial` |
| `quic_plan_text` (66) | `quic_replay.rs:r2o_quic_blob_candidate` (586), `r2o_quic_adaptive_split_candidate` (557) | Junk/blob/ttl/frag/udplen/quicsplit, pace. | `r2o_quic_*` tests | `partial` |
| `d2k_quic_arm_plan` (173) | `r2o_quic_blob_candidate` (586), `r2o_quic_adaptive_split_candidate` (557) | Проверки сочетаний (split/frag/udplen). | unit | `partial` |
| `d2k_quic_compose_plan` (188) | `r2o_quic_blob_candidate`/`r2o_quic_fragment_candidates` (490) | Композиция arm + props. | unit | `partial` |
| `d2k_quic_delay_plan` (205) | `quic_replay.rs` `delay 15000` (directives) | Задержка перед первой посылкой. | `test-quic-short-control` (косвенно) | `partial` |
| `d2k_voice_arm_plan` (219) | `voice_discovery.rs:r2o_voice_arm_plan_text` (8), `voice_measure.rs:r2o_measured_voice_arm_plan_text` (269) | `proto udp voice`, payload/poison/fake/order/pace. | `test-discord-voice-discovery-arm-differential.sh`, `measured_voice_arm_plan_preserves...` | `equivalent` (текст плана) |
| `d2k_voice_plan` (241) | `voice_discovery.rs:r2o_voice_arm_plan` (20) | Copies=1 для discovery; measured — 6. | тот же differential | `partial` |
| `d2k_quic_question_plan` (246) | `quic_replay.rs` candidates + `main.rs` QUIC discovery | Вопросы QUIC → план. | QUIC differentials | `partial` |

### 4.7. `udpruntime.c` (8)

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `udp_next_fragment_id` (1) | `r2k-core/wire.rs:build_udp_fragments` (287) | Rust генерирует случайные IPv4/IPv6 ID через `getrandom`; C — mutex + `d2k_t13_random`, пропуск нуля. | `ipfrag.rs` tests, `test-ipfrag-differential.sh` | `equivalent` |
| `d2k_udp_batch_free` (32) | `Drop`/`Vec` | Освобождение. | — | `not-applicable` |
| `d2k_udp_plan_build` (33) | `r2k-core/plan/apply.rs`, datapath `engine.rs` | C строит батч wire-пакетов заранее (включая ipfrag/udplen и отказ `ipidzero`); Rust применяет план к пакету в datapath. Отдельной функции «план → батч» в контроллере нет. | `apply.rs` tests, `test-udp-compose-exact` | `partial` |
| `udp_raw_init` (101), `udp_raw_close` (107) | datapath `raw.rs` raw sender | Инициализация/закрытие raw-сокета; в контроллере отсутствует. | `test-raw-egress-mtu-netns.sh` (datapath) | `missing` (в контроллере) |
| `udp_raw_prepare` (113), `udp_raw_send` (131) | datapath `raw.rs` | IPv4 `IP_HDRINCL`, IPv6 fragment sender, SO_MARK. | `test-ipfrag-differential.sh`, `test-raw6-send-differential.sh` | `partial` (datapath) |
| `d2k_udp_plan_send` (147) | нет прямого аналога в контроллере | C отправляет fake/ipfrag/udplen измерительные пакеты из контроллера; R2O voice-замер шлёт только обычный UDP, QUIC — через quinn. | — | `missing` |

### 4.8. `net4.c` (4)

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `d2k_ip4_parse` (2) | `std::net::Ipv4Addr::from_str`, `parse_ask_options` (97) | Строгий разбор; C запрещает ведущие нули? C допускает `01` как 1; Rust std тоже допускает? Проверка нужна отдельно. | `parse_ask_options` tests | `partial` |
| `d2k_ip4_text` (32) | `Display for Ipv4Addr` | Формат `a.b.c.d`. | `voice_targets` tests | `partial` |
| `d2k_ip4_private` (40) | `quic_replay.rs:ipv4_is_local` (24), `voice_targets.rs:r2o_is_private` (150) | 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, 0.0.0.0. | `r2o_quic_local_address_policy_matches_d2o` | `equivalent` |
| `d2k_ip6_private` (53) | `quic_replay.rs:r2o_quic_address_is_local` (23) | ::/127, fc00::/7, fe80::/10, ff00::/8, v4-mapped → ipv4_is_local. | тот же тест | `equivalent` |

### 4.9. `volume.c` (19)

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `rx_wire_partial` (58) | `r2o_volume.rs:r2o_volume_rx_wire_partial` (136) | TLS record partial: handshake, name_ok=1, TLS 1.2/1.3, wire ≥ минимум. | `r2o_volume.rs` unit | `equivalent` |
| `d2k_volume_rx_partial` (66) | `r2o_volume.rs:r2o_volume_rx_partial` (68) | Объединяет wire-partial и HTTP-body partial. | unit | `equivalent` |
| `d2k_volume_rx_pair_agrees` (78) | `r2o_volume_rx_pair_agrees` (80) | Один домен, согласованная версия/framing. | unit | `equivalent` |
| `d2k_volume_rx_needs_repeat` (103) | `r2o_volume_rx_needs_repeat` (112) | Один обрыв + один полный 2xx выше полосы → нужен третий. | unit | `equivalent` |
| `d2k_volume_rx_evidence` (111) | `r2o_volume_rx_evidence` (125), `r2o_volume_rx_wire_evidence` (147), `r2o_volume_rx_body_evidence` (190) | Байтовое и пакетное доказательство, gzip-контроль, допуск `D2K_VOLUME_SLACK`, `measured_path`. | `r2o_volume.rs` unit (5) | `partial` (нет C/Rust differential на все ветви) |
| `d2k_vol_verdict_name` (215) | `r2o-fetch.rs` verdict_human (232), `src/bin/r2o-fetch.rs:r2o_label` (440) | Тексты вердиктов TX. | fetch CLI tests | `partial` |
| `now_ms` (224), `nap_ms` (230), `clamp_ms` (237) | `Instant`/`sleep`/`clamp` | Системные helper. | — | `not-applicable` |
| `fill_pad` (243) | `fetch.rs:r2o_volume_padding` (2457) | C берёт `/dev/urandom`, Rust — случайные печатные символы. | `tx_packet_budget...` | `partial` |
| `connect_bounded` (259) | `fetch.rs:connect_target`/`connect_marked` (2929/2941) | Неблокирующий connect, 8 с, SO_MARK; Rust использует `TcpStream` + deadline/mark. | fetch/socket tests | `partial` |
| `drain_head_tls` (325) | `fetch.rs:r2o_drain_head_response` (2474) + rustls | C читает по байту через `d2k_tls_read`/`d2k_tls12_read`; Rust читает из `StreamOwned` до пустой строки. | `d2k_meas_send_timeout`, fetch tests | `partial` |
| `drain_head_plain` (351) | `r2o_drain_head_response` (2474) | Poll/recv по байту; Rust — `Read` с таймаутом. | fetch tests | `partial` |
| `resource_retry_path` (377) | `fetch.rs:r2o_fetch_resource_scan_allowed` (1300), `r2o_resource.rs` | Выбор публичного CSS-пути того же имени; Rust имеет resource hints. | `r2o_fetch_rx_*` tests | `partial` |
| `rx_probe` (411) | `fetch.rs:r2o_fetch_rx_probe` (1381) | Повтор при пустом/раннем ответе, gap 500 мс, 6 с. | unit | `partial` |
| `measure_response_volume` (440) | `fetch.rs:r2o_fetch_measure_rx_volume_once` (1578) | identity-1/2/3 + gzip, retry path, unmeasured/short. | `r2o_volume.rs`, fetch tests | `partial` |
| `probe_response_volume` (554) | `fetch.rs:r2o_fetch_measure_rx_volume` (1331) | Один повтор по названной причине; сохранение `rx_short`. | fetch tests | `partial` |
| `d2k_volume_probe_path` (595) | `fetch.rs:r2o_fetch_measure_tx_volume_with_roots` (1741) | 10 HEAD-шагов, X-Pad, RTT→timeout, 50 мс между запросами, затем RX. | `r2o_fetch_cli.rs` ladder tests | `partial` |
| `d2k_volume_probe` (729) | `r2o_fetch_measure_tx_volume` (1733) | Без path. | — | `partial` |

### 4.10. `catalog.c` (60), `domain.c` (4), `groups.c` (14), `match.c` (3)

`catalog.c` разбит на группы; полный перечень имён — в Приложении A.

| Группа C-функций (строки) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| JSON-примитивы: `set_err` (1), `jpeek` (73), `jeat` (89), `jeat_null_if_present` (106), `jparse_raw_int` (197), `jparse_i32` (241), `jparse_u8` (252), `jparse_u16` (263), `jparse_bool_i` (274), `jparse_string_dyn` (286), `jparse_string_fixed` (404), `read_fixed_digits` (424), `eat_lit` (447), `jskip_value` (545), `parse_object` (629), `parse_array` (692), `grow` (667) | `serde_json` + `Catalog` derive | C-парсер ручной; Rust — serde. Ошибки/пределы глубины заданы иначе (`check_json_depth` 1101). | catalog tests | `not-applicable` (замена) / `partial` (сообщения/лимиты) |
| Время: `floor_div` (119), `days_from_civil` (156), `civil_from_days` (166), `format_rfc3339` (180), `jparse_rfc3339` (456) | `time` crate, `catalog.rs:parse_timestamp` (1131), `format_timestamp` (1142) | RFC3339 парсинг/форматирование. | catalog tests | `partial` |
| `handle_signal_key` (723), `parse_signal` (743) | `catalog.rs` `Signal` serde, `same_signal` (1052) | Сигналы fingerprint. | catalog/known-plan tests | `partial` |
| `handle_fp_key` (756), `parse_fp` (789) | `Fingerprint::is_compatible_with` (59) | Совместимость fingerprint. | `d2o_known_plans` | `partial` |
| `handle_plan_key` (798), `parse_plan` (817), `elem_plan` (821) | `catalog.rs` Plan serde, `merge_plan` (836) | План, successes, enabled, timestamps. | catalog tests | `partial` |
| `handle_binding_key` (834), `parse_binding` (886), `elem_binding` (891) | `catalog.rs` Binding serde, `merge_binding` (868) | Привязки, family/shape/transport, donor-совместимость. | catalog tests | `partial` |
| `d2k_cat_shape_fits` (905) | `main.rs:group_shape_fits` (2556), `live.rs:group_shape_fits` (284) | «Не измерено» совместимо с любой; измеренные разные — нет. | Rust test в live/main (косвенно) | `equivalent` |
| `handle_box_key` (918), `parse_box` (940), `elem_box` (944) | `catalog.rs` BoxRecord serde | Коробки. | catalog tests | `partial` |
| `handle_domain_observation` (953), `parse_domain_observations` (972) | `catalog.rs:domain_state`, `groups.rs:restore` (12) | Восстановление групп из наблюдений, недоверие кэшу групп. | `catalog_restore_derives_groups...` | `partial` |
| `handle_net_whitelist_key` (991) | `catalog.rs` NetworkWhitelist serde | Белое имя сети. | `network_whitelist_probe_decisions_matches_d2o` | `partial` |
| `handle_catalog_key` (1001), `parse_catalog_obj` (1028) | `catalog.rs:Catalog` serde, `validate` (518) | Верхний уровень, schema, revision. | catalog tests | `partial` |
| `prune_unavailable_domain_groups` (1036) | `groups.rs:rebuild` (306), `groups.rs:oldest_expired` (436) | Удаление недоступных/просроченных групп. | groups tests | `partial` |
| `free_box` (1062), `d2k_catalog_free` (1072) | `Drop` | Освобождение. | — | `not-applicable` |
| `d2k_catalog_memory_bytes` (1084) | — | Оценка памяти каталога в R2O отсутствует. | — | `missing` |
| `read_whole_file` (1103), `d2k_catalog_load` (1145) | `catalog.rs:load` (366) | Загрузка; Rust поддерживает lock/merge и нормализацию `d2k-plan`→`r2o-plan`. | `r2o-catalog-persist-differential.sh` | `equivalent` |
| `write_json_string` (1198), `wr_indent` (1220), `write_json_array` (1230), `write_signal_elem` (1242), `write_fp` (1259), `write_plan_elem` (1268), `write_binding_elem` (1282), `write_box_elem` (1334), `write_domain_key` (1353), `write_domain_observation` (1359), `write_domain_group` (1367) | `catalog.rs:to_json_at` (422), serde | Формат JSON. Rust сериализует через serde; порядок ключей/пробелы могут отличаться, но контракт — схема. | `r2o-catalog-persist/sync` | `partial` |
| `d2k_catalog_save` (1374), `d2k_catalog_save_atomic` (1445) | `catalog.rs:save_atomic` (464) | Tmp+rename; Rust — с блокировкой и merge. | `r2o-catalog-persist-differential.sh` | `equivalent` |

| C-функция (файл:строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `d2k_domain_normalize` (domain.c:6) | `domain.rs:normalize` (8) | ASCII DNS, нижний регистр, отказ пустых/недопустимых. | `normalizes_ascii_dns_names...` | `implemented-unproven` |
| `rule_exists` (domain.c:31) | `domain.rs:registrable_domain` (62), `psl` crate | PSL wildcard/exception. | `finds_registrable_domains...` | `implemented-unproven` |
| `d2k_domain_base` (domain.c:42) | `domain.rs:registrable_domain` (62) | Базовый домен. | тот же тест | `implemented-unproven` |
| `d2k_domain_member` (domain.c:66) | `domain.rs:is_member` (74) | Граница метки + registrable suffix. | `membership_requires_a_label_boundary...` | `implemented-unproven` |
| `d2k_group_key_make` (groups.c:9), `d2k_group_key_same` (19) | `groups.rs:validate_key` (396), `catalog.rs:validate_group_key` (1065) | Ключ группы (suffix/family/transport/shape). | groups tests | `implemented-unproven` |
| `valid` (24), `member` (38), `votes` (45), `failures` (61), `add_group` (72), `rebuild` (103), `cover` (122) | `groups.rs:restore` (12), `rebuild` (306), `covering_group` (421), `votes` (455), `failures` (502), `add_group` (515) | Внутренние операции групп. | groups tests | `implemented-unproven` |
| `d2k_group_learn` (133) | `groups.rs:learn` (62) | Обучение, исключения участников, лимиты. | `learning_deduplicates_hosts...`, `capacity_reenable...` | `implemented-unproven` |
| `d2k_group_restore` (246) | `groups.rs:restore` (12) | Восстановление из наблюдений. | `catalog_restore_derives_groups...` | `implemented-unproven` |
| `d2k_group_match` (274) | `groups.rs:match_domain` (338) | Сопоставление домена с группой. | groups tests | `implemented-unproven` |
| `d2k_group_forget` (294) | `groups.rs:forget_failures` (251) | Сброс неудач. | groups tests | `implemented-unproven` |
| `d2k_group_expire` (311) | `groups.rs:expire_failures` (284) | Просрочка неудач. | groups tests | `implemented-unproven` |
| `same_evidence` (match.c:38) | `catalog.rs:is_compatible_with` (59) | Сравнение сигналов. | catalog tests | `partial` |
| `d2k_fp_same` (match.c:75) | `catalog.rs:is_compatible_with` (59) | Полное совпадение fingerprint. | `known_plans` tests | `partial` |
| `d2k_catalog_match` (match.c:127) | `catalog.rs:match_fingerprint` (512) | Поиск коробки. | known-plan tests | `partial` |

### 4.11. `meas.c` (13), `measured.c` (12), `verdict.c` (7)

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `nap_us` (52) | `thread::sleep` | — | — | `not-applicable` |
| `d2k_mark_real` (57) | `response.rs:set_socket_option` (136), `connect_marked` (2941) | SO_MARK; C вызывает harness-хук. | `production_socket_probe_mark_matches_d2o_setsockopt_result` | `partial` |
| `d2k_accept_serverhello` (74) | `response.rs:r2o_accept_serverhello` (1211) | Первая запись TLS — ServerHello. | `socket_*` tests, response fixtures | `equivalent` |
| `d2k_accept_tls_record` (96), `d2k_accept_any` (101) | `response.rs:receives_tls_record` (516), `scan12` (1167) | Классификация записей. | response tests | `partial` |
| `cuts_valid` (106) | `classify.rs`/`raw_probe.rs` split validation | Проверка точек разреза. | `measured_split_plans_match_donor` | `partial` |
| `send_all` (118) | `response.rs` write loops, `raw_probe.rs` | Частичные записи, EINTR. | `d2o_meas_eintr.rs`, `d2o_meas_send_timeout.rs` | `partial` |
| `connect_bounded` (138) | `response.rs:connect_until` (198), `dial_probe_target` (643) | Неблокирующий connect + deadline + mark. | socket tests | `partial` |
| `d2k_meas_once` (175) | `classify.rs::TcpProbeBackend` | Один TCP-зонд: connect, write, accept. | `r2o-meas-differential.sh` (hist.) | `equivalent` (в рамках контракта) |
| `d2k_meas` (269) | `classify::run_with_backend` | Повторы, tally, controls. | `r2o-meas-differential.sh` | `partial` |
| `udp_now_ms` (307) | `Instant` | — | — | `not-applicable` |
| `d2k_udp_port_claim` (313) | `r2o_quic_http3.rs:r2o_quic_port_was_recently_claimed` (121) | Окно «недавно занятых» UDP-портов, 16 попыток. | `quic_candidate_trials_use_fresh_conntrack_tuples`, quic unit | `partial` |
| `d2k_udp_port_forget_all` (341) | сброс состояния в тестах `r2o_quic_http3` | Явного API сброса в production нет. | — | `partial` |

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `append_fmt` (2), `append_hex` (22) | `classify_measured.rs` formatting | Сборка текста. | measured tests | `partial` |
| `d2k_white_decoy_hello` (30) | `raw_probe.rs:build_variant` (2236), `select_bridge_decoy` (602) | Белая приманка/ECH-композит. | `white_hello_ts_composite...`, `d2o_white_ts_composite_differential.c` | `partial` |
| `template_plan` (46) | `classify_measured.rs` plan builder (143/170) | `wire tcp-template-v1`/`detect-tcp-v1`. | measured_plan tests | `partial` |
| `d2k_rx_volume_plan_named` (84), `..._client` (90), `d2k_rx_volume_plan` (112) | `r2o_rx_volume.rs:r2o_rx_volume_plan_for_client` (26), `candidate` (62) | RX-volume кандидат: segment, poison (tcpts/badsum), fake, split. | `r2o_rx_volume` test (184) | `equivalent` (план) |
| `measured_payload` (119) | `classify_measured.rs` payload selection | — | measured tests | `partial` |
| `d2k_tcp_split_plan` (140) | `classify_measured.rs` split plan (240) | `split payload_start +1`, `split sni_middle +0`, reverse, pace. | measured split differential | `partial` |
| `d2k_arm_plan_measured_cap` (153) | `classify_measured.rs` send-cap logic | Учёт `send_maxlen`. | measured tests | `partial` |
| `d2k_arm_plan_measured` (387) | `classify_measured.rs` measured arm plan | Большой набор измеренных стратегий. | `r2o-measured-split-differential.sh`, raw split differentials | `partial` |

`verdict.c`:

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `looks_like_tls` (10), `reverse_note` (37), `pause_note` (64) | `classify.rs` verdict notes | — | C `test_verdict` | `not-applicable` |
| `stop_requested` (82), `classify_cancelled` (96), `d2k_classify_cancelable` (104) | `classify.rs` cancel token (CancellationToken) | Rust использует `AtomicBool`/cancel. | classifier tests | `partial` |
| `d2k_classify` (336) | `classify::run_with_backend_progress` | **Нет production-вызова в текущем D2O**: `d2kc` использует `detect/`-хуки, не `verdict.c`. Rust-классификатор — преемник `detect/`, а не этого API. | `test-classifier-*` (для detect/), C `test_verdict` | `not-applicable` (для этого API) |

### 4.12. `diagnostics.c` (41)

| C-группа (строки) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `copy` (98), `js` (105), `number` (131), `value` (213) | `diagnostics.rs` JSON-хелперы | Экранирование/числа. | — | `not-applicable` |
| `d2k_diag_new` (132), `free` (133) | `diagnostics.rs:Recorder::new` (172), `Drop` | Кольцевой буфер событий/сэмплов. | `records_only_while_enabled_and_exports_d2o_ring_shape` | `equivalent` |
| `d2k_diag_bytes` (134), `event_count` (135), `sample_count` (136) | `Recorder` counts | Счётчики. | тест выше | `equivalent` |
| `d2k_diag_memory_history_count` (137), `memory_enable` (138), `memory_active` (139), `atomic_read` (140), `atomic_peak` (141), `memory_acquire` (145), `memory_release` (152), `memory_alloc_failure` (157), `memory_snapshot` (161), `memory_counts` (170) | — | Собственный учёт аллокаций/mmap в C; Rust использует `/proc/self/status` и `smaps`, счётчиков acquire/release/peak нет. | — | `missing` |
| `d2k_diag_set_madvise` (180) | — | Запись madvise-статистики; в Rust нет. | — | `missing` |
| `record_anomaly` (181), `d2k_diag_record_write_error` (188) | `Recorder::record` (189) + `d2o_event_text` (387) | Аномалии/ошибки записи. | differential | `partial` |
| `d2k_diag_record` (192), `d2k_diag_record_limit` (202) | `Recorder::record` (189), `tick` (223) | События и лимиты. | `r2o-diagnostics-differential.sh` | `equivalent` |
| `compact_kib` (218), `compact_bytes_kib` (221), `compact_bytes` (222), `compact_count` (223) | `diagnostics.rs` formatting | Человекочитаемые размеры. | — | `partial` |
| `proc_pid_dir_present` (225), `optional_proc_status` (230), `read_proc` (238), `read_detail` (260), `read_status` (305) | `process_memory` (474), `process_detail` (512), `read_fd_count` (541), `read_smaps` (570) | `/proc` чтение, PID reuse, first detail. | `first_process_detail_survives_process_exit_like_d2o`, `process_memory_follows_pidfiles...` | `equivalent` |
| `write_detail` (310), `write_limit_reason` (329), `write_limit_reason_state` (344), `write_memory_tracking` (357), `write_madvise` (370), `write_anomalies` (382) | `write_report` (332), serde JSON | Формат отчёта; madvise/allocator-поля отсутствуют. | `diagnostics_id_and_counts_match_d2o` | `partial` |
| `d2k_diag_sample` (395) | `Recorder::tick` (223) | Периодический сэмпл 1/60 с. | `diagnostic_tick_lifecycle_matches_d2o` | `equivalent` |
| `d2k_diag_write` (469) | `write_report` (332) | Атомарная запись `report.json`/`report.new`. | differential | `equivalent` |

### 4.13. `httpsearch.c` (66), `httpsprobe.c` (22), `httpup_logic.c` (17), `h3.c` (9)

`httpsearch.c`:

| C-группа (строки) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `mono_ms` (37) | `Instant` | — | — | `not-applicable` |
| `d2k_hs_answer_name` (43), `d2k_hs_judge` (61), `hs_path_ok` (99), `hs_read` (110), `d2k_hs_probe_run` (132) | `http_search.rs:judge` (850), `read_probe_response` (310), `read_response_head` (367), `read_response_body` (400) | Судья ответа, безопасный путь, чтение ответа. | `d2o_http_judge_differential.c`, `r2o-http-search-differential.sh` | `equivalent` |
| `d2k_hs_candidate_count` (253), `candidate_key` (254), `poison_key_spec` (258), `known_key` (289), `candidate_text` (296), `stable_id` (329), `fresh_id` (336) | `http_search.rs:candidate_keys` (627), `candidate_key_from_plan_text` (631), `candidate_text` (686), `measured_poison_keys` (719), `stable_id` (780), `poison_key_spec` (796) | Ключи и тексты кандидатов, стабильные ID. | `d2o_http_baseline/queue/durable` fixtures | `equivalent` |
| `say` (444), `host_ok` (454), `rec_find` (470), `rec_get` (479), `same_program` (502), `failed_live` (512), `remember_live_failure` (522) | `main.rs` HTTP worker, `http_search.rs:record_*` (3889..) | Записи/живые неудачи. | HTTP search differential | `partial` |
| `d2k_httpsearch_test_add_failures` (555), `test_add_records` (569) | — | Тестовые хуки C, не production. | — | `not-applicable` |
| `d2k_httpsearch_measured_poison` (581), `d2k_hs_plan_poisons` (610) | `http_search.rs:measured_poison_keys` (719), `main.rs:run_http_search_task` (21047) | Измеренные отравы. | `d2o_http_*` | `partial` |
| `d2k_httpsearch_new` (646), `free` (668), `busy` (678), `plan_of` (682) | `main.rs:HttpSearchWorker` (5895) | Жизненный цикл. | HTTP search tests | `equivalent` |
| `diagnostic_counts` (689), `diagnostics` (709) | `main.rs:r2o_http_search_diagnostic_event` (4253) | Диагностика HTTP. | `d2o_http_diagnostic_differential.c` | `equivalent` |
| `diagnostic_end` (712), `finish` (724), `open_job` (732), `revoke_owned` (754), `all_failed` (761), `install` (806), `install_ack` (820), `confirmed` (845), `trial_executed` (896), `judge_trial` (904), `next_candidate` (957), `add_cand` (1007), `build_cands` (1014), `build_fallback` (1043), `start` (1056), `start_next` (1095), `live_owner` (1105) | `main.rs:run_http_search_task` (21047), `run_http_trial_task` (21293), `advance_http_candidate` (20915), `install_http_candidate` (20044) | Кандидаты, trial, install, fallback, live owner. | `d2o_http_baseline/queue/judge/durable/rollback/applied_window/https_gate/cut_context/response_state/no_executed`, differential | `equivalent` (scoped) |
| `d2k_httpsearch_bound_failure` (1115), `control` (1135), `cut` (1172), `portal` (1192), `ack` (1231), `applied` (1264), `result` (1291), `tick` (1399), `push_all` (1431) | `main.rs` HTTP search/ControlClient; `http_search.rs` | События, cut, portal, ACK/APPLIED, tick, повторная установка. | differential + fixtures | `equivalent`/`partial` |
| `d2k_httpsearch_save` (1446), `load` (1475) | `main.rs` persistence HTTP планов, `http_search.rs` | `http-plans.txt`; Rust хранит в каталоге/планах. | `d2o_http_durable_differential.c` | `partial` |
| `runner_main` (1527), `d2k_hs_runner_new` (1541), `free` (1557), `wake_fd` (1566), `start` (1568), `done` (1583) | `main.rs:HttpSearchWorker` thread + `try_result` | C — отдельный поток и wake-fd; Rust — worker loop/каналы. | process tests | `partial` |

`httpsprobe.c`:

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `d2k_https_classify` (32), `d2k_https_upgrade` (42), `d2k_https_ttl` (46), `d2k_https_state_name` (57) | `https_probe.rs` state/TTL, `response.rs:probe_https_state` (550) | Классификация HTTPS-состояния. | `r2o-ech-rx-ladder-differential.sh` / panel tests | `partial` |
| `mono_ms` (69) | `Instant` | — | — | `not-applicable` |
| `https_connect` (77), `https_tls` (148), `first_flight` (171), `d2k_https_probe_real` (203) | `response.rs:probe_https_name` (256), `https_connection` (317), `https_socket` (484) | TCP/TLS/первый полёт, таймауты. | TLS verify differentials | `partial` |
| `host_ok` (274), `cache_find` (285), `cache_put` (292), `worker` (314) | `https_probe.rs:submit` (139), `cached_state` (166), `insert_cache` (225) | Кэш/worker. | `https_cache_round_trip...` | `partial` |
| `d2k_httpsprobe_new` (351), `free` (377), `wake_fd` (393), `portal` (397), `done` (430), `state` (451), `save` (476), `load` (507) | `https_probe.rs:new` (107), `try_result` (176), `restore_cached` (205), `load_cache` (251), `save_cache` (305) | Жизненный цикл и кэш. | `https_cache_persists_negative...`, panel tests | `partial` |
| `d2k_httpsprobe_lost` (460) | — | Счётчик потерянных проб отсутствует. | — | `missing` |

`httpup_logic.c`:

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `ascii_alnum` (16), `dns_host` (21), `host_equal` (37), `known_portal_host` (46), `find_crlf` (53), `parse_request` (60), `strncasecmp` (105/113) | `r2k-core/httpup.rs:valid_dns_host` (390), `valid_http_name_host` (350), `find_crlf` (382), `parse_request` (220), `same_host` (468), `known_portal_host` (492) | Разбор запроса/хоста. | `httpup.rs` tests | `implemented-unproven` |
| `d2k_httpup_request_safe` (132) | `httpup.rs:request_safe` (164) | Только безопасный bodyless GET/HEAD. | `accepts_only_safe_bodyless...` | `implemented-unproven` |
| `build_redirect` (137) | `httpup.rs:build_redirect` (504) | HTTPS-redirect. | `builds_the_exact_https_redirect...` | `implemented-unproven` |
| `portal_marker` (151), `redirect_location_host` (172), `portal_answer` (193) | `httpup.rs:portal_marker` (474), `parse_location_host` (452), `portal_response` (191) | Признаки портала. | `recognizes_the_same_portal_location...` | `implemented-unproven` |
| `d2k_httpup_portal_response` (227), `d2k_httpup_request_target` (240), `d2k_httpup_portal_location` (253), `d2k_httpup_redirect_https` (264) | `httpup.rs` public API (164..208) | Публичные обёртки. | `httpup.rs` tests | `implemented-unproven` |

`h3.c`:

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `d2k_h3_control` (19) | `r2o_quic_http3.rs` control stream via `h3` crate | Управляющие потоки HTTP/3. | HTTP/3 differentials | `partial` |
| `prefix_int` (30), `prefix_int_read` (51) | `r2o_quic_http3.rs`/`h3` varint | Префиксные целые. | HTTP/3 tests | `partial` |
| `d2k_h3_request` (73) | `r2o_quic_http3.rs:build request`/`h3` | QPACK-заголовки запроса. | HTTP/3 tests | `partial` |
| `huff_status` (126), `static_status` (148), `name_is_status` (171), `decode_section` (176), `d2k_h3_status` (262) | `h3` crate + `r2o_quic_http3.rs` | Разбор `:status`, Huffman/static table. Rust не повторяет таблицы вручную. | HTTP/3 differentials | `partial` |

### 4.14. `hello.c` (19), `tls12.c` (26), `tls13.c` (23), `tls13core.c` (24)

`hello.c`:

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `rd16` (51), `rd24` (54), `wr16` (57), `wr24` (61), `skip_u8_vec` (69), `skip_u16_vec` (80), `parse_hello` (128) | `r2k-core/tls.rs:read_u16` (129), `read_u24` (135), `skip_u8_vector` (141), `skip_u16_vector` (158), `parse` (32) | Разбор ClientHello, границы расширений. | `parses_complete_tls13...`, `partial_key_share...` | `equivalent`/`partial` |
| `d2k_hello_complete` (274) | `tls.rs:parse` + `is_client_hello`, `record_end` | Полнота записи. | `complete_supported_versions...` | `partial` |
| `d2k_hello_shape` (283) | `tls.rs:is_tls13`, `has_ech_offer`; `ask.rs:hello_shape` (282) | MODERN/LEGACY/ECH/UNKNOWN. Rust ECH→shape ECH_TCP. | `clienthello_shape...` | `partial` |
| `d2k_hello_sni` (308) | `tls.rs:find_sni` (274), `controller/hello.rs:locate_sni` (61) | SNI offset/length. | `distinguishes_application_record...` | `partial` (нет прямого C/Rust differential) |
| `d2k_hello_ech_offer` (322) | `tls.rs:has_ech_offer` (230) | Структурная проверка ECH offer. | `recognizes_only_structurally_consistent_ech_offer` | `partial` (нет прямого C/Rust differential) |
| `d2k_hello_alpn` (349) | `r2o_tls.rs:r2o_tls_client_hello_non_http_alpn` (121) | Список ALPN. | `captured_non_http_alpn...` | `partial` (нет прямого C/Rust differential) |
| `d2k_alpn_is_http` (377) | `r2o_tls_client_hello_non_http_alpn` (121) | HTTP/1.1 vs не-HTTP. | тот же | `partial` |
| `splice_sni` (409), `hex_nibble` (462), `hex_decode` (480), `d2k_hello_rename` (500) | `controller/hello.rs:rename_sni` (135), `quic.rs:r2k_quic_client_hello_rename_sni` (1113) | Замена SNI с пересчётом длин. | `r2o_tls.rs` tests, QUIC rename tests | `partial` |
| `d2k_hello_without_sni` (537) | `quic.rs:r2k_quic_client_hello_rename_sni(..., None)` (1113); для TLS отдельной функции нет | Удаление SNI. | QUIC test (1412) | `partial` |
| `d2k_hello_from_profile` (578) | `controller/hello.rs:client_hello_from_profile` (245), `legacy_client_hello` (284), `modern_client_hello` (289) | Профили `legacy.hex`/`modern.hex`. | `hello.rs` tests | `partial` (нет C/Rust differential) |

`tls12.c`:

| C-группа (строки) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `tls12_dispose` (98), `say` (102), `now_ms` (110), `put16/get16` (116/117), `read_exact` (119), `write_all` (155) | `rustls`/`StreamOwned` + `response.rs` socket helpers | Низкоуровневый record I/O. | — | `not-applicable` (замена) |
| `prf` (183), `d2k_tls12_prf_for_test` (214), `tr_add` (220), `nonce_of` (228), `aad_of` (235), `send_plain` (246), `send_sealed` (258), `read_record` (287), `hs_next` (355), `ch12_build` (415) | `rustls` TLS 1.2 | PRF/AEAD/record. Rust не имеет собственного TLS 1.2 стека; crypto — `ring`. | `r2o-tls-verify-differential.sh`, `test_tls12.c` (C only) | `partial` |
| `d2k_tls12_connect` (492), `d2k_tls12_resume` (532), `tls12_finish` (556) | `r2o_tls.rs:r2o_tls_client_connection` (53) + `fetch.rs` | Handshake/resume. | TLS verify differential | `partial` |
| `d2k_tls12_write` (750), `d2k_tls12_read` (756), `d2k_tls12_peer_name` (795), `d2k_tls12_free` (797), `rx_wire_bytes` (799), `rx_record_missing` (800) | `fetch.rs:StreamOwned`, `response.rs` | Чтение/запись, счётчики wire, missing record. | `d2o_tls_response_*` | `partial` |

`tls13.c`:

| C-группа (строки) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `tls_dispose` (83), `say` (87), `now_ms` (95), `read_exact` (102), `write_all` (138), `put16/get16` (160/161), `nonce_of` (165), `read_record` (175), `write_record` (236), `traffic_keys` (260) | `rustls` TLS 1.3 + `r2o_tls.rs` | Низкоуровневые записи/ключи. | — | `not-applicable` (замена) |
| `tls_connect_internal` (265), `d2k_tls_connect` (525), `d2k_tls_connect_alpn` (531) | `r2o_tls.rs:r2o_tls_client_connection_with_alpn` (63), `fetch.rs` | Handshake, ALPN. | `r2o-tls-verify-differential.sh` | `partial` |
| `d2k_tls_connect_ech` (538), `d2k_tls_ech_accepted` (548) | `r2o_tls.rs:r2o_tls_ech_client_connection` (274), `ech.rs` | ECH handshake. | ECH differentials | `partial` |
| `d2k_tls_write` (550), `d2k_tls_read` (562), `d2k_tls_peer_name` (603), `d2k_tls_free` (605), `rx_wire_bytes` (610), `rx_record_missing` (611), `d2k_tls_version` (613) | `fetch.rs` + `rustls` | I/O и метаданные. | TLS response tests | `partial` |

`tls13core.c`:

| C-группа (строки) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `put16/get16` (16/17), `d2k_t13_random` (21) | `rustls`/`ring::rand` | — | — | `not-applicable` |
| `der_len` (53), `ascii_lower` (64), `name_matches` (73), `cert_name_ok` (106), `d2k_t13_cert_name_ok12` (166), `d2k_t13_cert_name_ok` (177) | `response.rs:https_certificate_name_matches` (333), `https_dns_name_matches` (447) | SAN/CN, wildcard, IDN. | `https_probe_matches_only_a_single_donor_wildcard_label`, IP SAN test | `partial` |
| `d2k_t13_ch_build` (197) | `r2o_tls.rs:r2o_tls13_client_hello` (340), `r2o_tls_ech_client_hello` (305) | Сборка ClientHello. | `r2o_tls.rs` tests | `partial` |
| `d2k_t13_derive_secret` (361), `schedule_hs` (368), `schedule_ap` (383), `finished_mac` (396) | `rustls` | Key schedule. | — | `not-applicable` (замена) |
| `d2k_t13_sh_version` (407), `sh_parse` (428), `flight_next` (479) | `rustls`/`response.rs` | Разбор ServerHello/flight. | response tests | `partial` |
| `ech_host_ok` (492), `d2k_ech_config_parse` (510), `hpke_extract` (570), `hpke_expand` (583), `ech_hpke` (598), `d2k_t13_ech_build` (621), `d2k_t13_ech_accepted` (684) | `ech.rs:r2o_ech_parse_https_reply` (269), `r2o_ech_select_config` (364), HPKE setup (82/117) | ECH config/HPKE/Accepted. Rust использует `hpke` crate, не собственную реализацию. | ECH tests/differentials | `partial` |

### 4.15. `verify.c` (74)

| C-группа (строки) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `verify_now_ms` (52), `dns16` (58), `ech_dns_name` (62), `d2k_ech_resolve` (90) | `ech.rs:r2o_ech_dns_name` (482), `r2o_ech_query_resolver` (182), `resolve_ech_config` (158) | DNS HTTPS/ECH lookup. | ECH differentials | `partial` |
| `find_hdr_end` (193), `find_eol` (203), `lower_ascii` (210), `span_eq_ascii_ci` (214), `has_cf_challenge` (227) | `r2k-core/http_response.rs`, `fetch.rs:r2o_fetch_ascii_contains` (2822), `r2o_fetch_is_cloudflare_challenge` (1312) | Границы заголовков, Cloudflare challenge. | `http_response.rs` tests | `equivalent` |
| `read13` (273), `read12` (278), `body_read_reason` (298), `body_say` (304), `body_feed` (308), `body_byte` (317), `body_exact` (331), `body_line` (352), `read_http_body` (380) | `r2k-core/http_response.rs:HttpResponseParser`, `fetch.rs:r2o_fetch_body_encoding` (2268) | Content-Length/chunked/close-delimited, заголовки, тело. | `test-http-chunk-framing-differential.sh`, `http_response.rs` (10) | `equivalent` (scoped) |
| `read_status_buf` (457), `read_status_rd` (699), `d2k_http_read_response` (730) | `http_response.rs:parse_response_head` (527), `fetch.rs` | Статус/заголовки/тело. | тот же differential | `partial` |
| `d2k_verify_probe` (739), `write13` (750), `write12` (755) | `fetch.rs:r2o_fetch_detailed` (768), `response.rs:probe_trigger` (695) | Базовый TCP/TLS probe. | `r2o-tls-verify-differential.sh`, classifier differentials | `equivalent`/`partial` |
| `redirect_path` (762), `https_redirect_response` (799) | `fetch.rs:r2o_fetch_same_origin_redirect` (2673), `r2o_fetch_external_https_redirect` (2723), `r2o_fetch_http_outcome` (2748) | Redirect/portal. | `same_origin_redirects...` | `partial` |
| `d2k_verify_budget_set` (822), `get` (823) | `fetch.rs` per-probe budget/`R2oQuicHttp3Budget` | C — глобальный бюджет; Rust — бюджет запроса/QUIC. | `d2o_probe_budget_differential.c` | `partial` |
| `d2k_verify_tcp_timestamps_set` (826), `get` (829) | `raw_probe.rs:raw_offer_timestamps` (673) | C — sysctl-профиль; Rust — опция raw SYN. | `test-d2o-shared-fixtures.sh` | `partial` |
| `d2k_verify_quic_form_set` (837), `d2k_verify_tcp_data_packets` (850), `budget_say` (877) | `fetch.rs`, `r2o_quic_http3.rs` | QUIC form, TCP_INFO packets. | `test-quic-*` | `partial` |
| `gateway_header_end` (885), `gateway_header_value` (892), `gateway_connection_upgrade` (905), `gateway_json_hello` (917), `gateway_fill` (976), `request_gateway_websocket` (1000) | `fetch.rs:r2o_gateway_websocket_exchange` (2099), `r2o_gateway_*` (1895..1969) | Discord Gateway Upgrade 101, `Sec-WebSocket-Accept`, текстовый фрейм, `op=10`. | `d2o_verify_differential.rs` (16, hist.) | `equivalent` |
| `read_eof` (1132), `budget_tcp` (1146) | `fetch.rs` read loop | Дочитывание до EOF. | HTTP reader tests | `partial` |
| `fd_peer_spoke` (1217), `fd_packets` (1223) | `r2o_tcp_counters` (2516), `fd_packets` | TCP_INFO. | fetch tests | `partial` |
| `request_complete_page` (1238), `request_page_budget` (1247) | `fetch.rs:r2o_fetch_with_roots_and_encoding...` (817..880) | GET/HEAD, бюджет, тело. | fetch tests | `partial` |
| `verify_contact` (1349), `d2k_props_contact_on_family_tcp_profile` (1360) | `classify.rs` contact, `response.rs:connect_until` (198) | Непомеченный сокет/срок. | classifier differentials | `partial` |
| `verify_probe13_internal` (1365), `verify_probe13_on` (1444) | `fetch.rs:r2o_fetch_detailed` (768) | TLS 1.3 probe. | TLS differentials | `partial` |
| `ech_http_denial` (1451), `d2k_verify_probe_ech_on` (1462), `ech_origin_on` (1478) | `ech.rs`, `fetch.rs:r2o_fetch_ech_connected_stream` (692) | ECH denial/origin. | ECH differentials | `partial` |
| `d2k_verify_replay_on` (1499) | `fetch.rs:r2o_verify_tls_replayed_client_hello` (285) | Повтор сохранённого ClientHello. | `r2o_tls.rs` tests | `partial` |
| `d2k_verify_probe_on` (1564), `alpn_on` (1578) | `fetch.rs:r2o_verify_tls_connected_stream_with_alpn` (201) | ALPN/connected stream. | fetch tests | `partial` |
| `verify_probe12_internal` (1636), `probe12_on` (1703) | `response.rs:scan12` (1167), `fetch.rs` | TLS 1.2 probe. | `test-d2o-shared-fixtures.sh` | `partial` |
| `identity_on` (1710), `gzip_on` (1717), `baseline` (1724), `path_on` (1744), `close` (1759) | `fetch.rs` encoding/baseline/close | identity/gzip/base/path. | fetch/volume tests | `partial` |
| `d2k_verify_probe_quic` (1768), `quic_app_silent` (1780), `h3_read_headers` (1799), `quic_recv_chunk` (1816), `budget_quic` (1836), `qb_request` (1953), `qb_recv` (1960), `qb_progress` (1964), `qb_packets` (1967) | `r2o_quic_http3.rs:measure_with_wire_len` (816), `wait_with_stall` (1278), `r2o_quic_http3_*` | HTTP/3 GET, stall, бюджет, app bytes. | `test-quic-http3-full-stage-differential.sh`, `test-quic-short-control-differential.sh` | `partial`/`equivalent` (scoped) |
| `d2k_verify_probe_quic_on` (1975), `path_on` (1983), `mark_on` (1991) | `fetch.rs:r2o_fetch_quic_with_budget` (483) | QUIC probe с path/mark. | fetch CLI QUIC tests | `partial` |

`verify_quic_replay.c`:

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `replay_now_ms` (23) | `Instant` | — | — | `not-applicable` |
| `d2k_verify_quic_replay_on` (29) | `fetch.rs:r2o_verify_tls_replayed_client_hello` (285) + `quic_replay.rs:QuicReplayProbe` (639) | C повторяет пачку QUIC-датаграмм; Rust повторяет ClientHello через TCP/TLS и отдельно replay QUIC. Прямого differential на эту функцию нет. | `r2o_tls.rs` tests, QUIC differentials (косвенно) | `partial` |

### 4.16. `quic*.c` (21+8+36+13+57+6+2+28), `stun.c` (5), `ipfrag.c` (8)

`quic.c`:

| C-группа (строки) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `rd16` (97), `read_varint` (110), `parse_initial_header` (149), `d2k_quic_is_initial` (182), `decrypt_initial` (191), `collect_crypto_frames` (239), `skip_u8_vec` (434), `skip_u16_vec` (446) | `r2k-core/quic.rs:parse_initial_header` (796), `open_initial` (908), `collect_initial_crypto_frames` (632), `read_varint` (1057) | Разбор/дешифрование Initial. | `r2k-core/quic.rs` tests, `r2o-quic-hello-differential.sh` | `equivalent`/`partial` |
| `find_sni` (458), `find_client_hello_sni` (503), `crypto_stream_of` (552), `d2k_quic_client_hello` (567), `d2k_quic_dgrams_hello` (607), `d2k_quic_hello_name` (661), `d2k_quic_hello_incomplete` (672), `d2k_quic_sni` (687) | `quic.rs:find_client_hello_sni` (1107), `find_client_hello_sni_result` (1161), `r2k_quic_initial_client_hello_from_datagrams` (374) | SNI/полнота. | `extracts_sni_from_authenticated_v1_and_v2_initials` | `partial` |
| `d2k_quic_assembly_init` (708), `feed` (712), `complete` (780) | `quic.rs:collect_initial_crypto_frames`/`open_initial`, datapath `r2o_quic.rs` | Сборка нескольких Initial. | `r2o_quic.rs` tests | `partial` |
| `put_split_frame` (824), `d2k_quic_initial_split_crypto` (841) | `quic.rs:initial_split_crypto` (167), `splits_rfc_9001...` | Разрез CRYPTO на два кадра. | RFC 9001/9369 vectors | `equivalent` |

`quicarms.c`:

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `d2k_quic_original_blob` (12), `ask_q` (30), `ask_frag` (112), `ask` (125), `d2k_quic_original_arms` (142) | `quic_replay.rs:r2o_quic_original_fallback_candidates` (506), `r2o_quic_fragment_candidates` (490) | Оригинальная лестница. | QUIC differentials | `partial` |
| `strategy_ask` (227), `prop_word` (244), `d2k_quic_strategy_arms` (248) | `quic_replay.rs:r2o_quic_strategy_attempt_decision` (368), `r2o_quic_adaptive_split_candidate` (557) | Стратегия/адаптивный split. | QUIC tests | `partial` |

`quicconn.c`:

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `qc_dispose` (209), `say` (218), `now_ms` (226), `crypto_put` (243), `crypto_ready` (254), `build_ack` (265), `seal_level` (281), `send_level` (352), `tp_put_int` (367), `tp_build` (380), `tp_server_parse` (418), `tp_server_ee` (460), `frames_in` (479), `recv_dgram` (702), `crypto_frame` (820), `first_flight` (836), `prepare_retry` (898) | `quinn`/`rustls` + `r2o_quic_http3.rs` | C — собственный QUIC-стек; Rust — `quinn`. | HTTP/3 full-stage, QUIC differentials | `partial` |
| `d2k_qc_first_initial` (928), `d2k_qc_connect` (966) | `r2o_quic_http3.rs:r2o_quic_http3_get` (684), `r2o_quic_http3_measure` (719) | Подключение. | HTTP/3 tests | `partial` |
| `d2k_qc_stream_send` (1288), `recv` (1377), `app_progress` (1425) | `r2o_quic_http3.rs:measure_with_wire_len` (816), `wait_with_stall` (1278) | Поток/прогресс/stall. | HTTP/3 differentials | `partial` |
| `peer_name` (1430), `rx_wire_bytes` (1431), `datagrams` (1432), `handshake_done` (1436), `rtt_ms` (1437), `dgrams` (1438), `outbound` (1443), `ping` (1454), `fd` (1459), `local` (1461), `local_addr` (1470), `release` (1478), `close` (1486) | `r2o_quic_http3.rs` (datagrams/ping/wire bytes), `R2oQuicFetchResult` | Метрики/локальный адрес. | HTTP/3/fetch tests | `partial` |

`quichello.c`:

| C-функция (строка) | Rust-аналог | Тесты | Статус |
|---|---|---|---|
| `select_probe_profile` (34), `split_point` (69), `put_crypto` (80), `prepare` (124), `seal_one` (183), `probe_initial_sized` (235), `d2k_quic_probe_initial` (276), `d2k_quic_probe_initial_longer` (281), `d2k_quic_prepare_target` (287), `d2k_quic_hello_rename` (312), `d2k_quic_hello_ask` (330), `d2k_quic_hello_split` (412), `d2k_quic_hello_recid` (457) | `r2k-core/quic.rs:r2k_quic_initial_build` (261), `initial_split_crypto` (167), `r2k_quic_initial_reseal_for_dcid` (338), `r2k_quic_client_hello_rename_sni` (1113) | RFC vectors, QUIC hello differentials | `partial` |

`quicprobe.c`:

| C-группа (строки) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `qp_addr_parse` (173), `resolve_family` (181), `resolve_real` (209), `d2k_quic_build_pool` (254) | `quic_replay.rs:r2o_quic_address_pool` (56), `r2o_quic_next_question_address` (78) | Пул адресов. | `r2o_quic_residual_control_and_address_pool_match_d2o` | `partial` |
| `qp_varint` (320), `qp_parse_hdr` (337), `qp_dcid_of` (411), `qp_donor_unauth_reply` (456), `qp_verify_server_response` (494), `qp_build_vn_trigger` (574) | `quic_replay.rs:r2o_quic_build_vn_probe` (159), `r2o_quic_ask_donor_version_negotiation` (960) | VN/DCID/verify. | `r2o_quic_version_negotiation_*` | `partial` |
| `nap_us` (622), `qp_open_fresh` (637), `qp_send_one` (716), `qp_head_of` (806), `qp_verify_aead` (815), `qp_verify_bound` (835), `d2k_quic_verify_bound` (880), `d2k_quic_verify_response` (890), `qp_verify_vn` (898), `qp_recv_ttl` (937), `qp_send_fragmented` (1004), `qp_neutral_control_sni` (1045) | `r2k-core/quic.rs` + `quic_replay.rs` verify helpers | AEAD/VN/fragment/neutral control. | QUIC differentials | `partial` |
| `quic_ask_core` (1064), `d2k_quic_hello_recid` (1228), `quic_ask_ex` (1405), `quic_fragment` (1418), `qp_progress` (1432), `quic_ask_arm` (1437), `qp_arm_first_send` (1500), `qp_now_ms` (1510), `quic_arm_data` (1516), `d2k_quic_data_stage` (1591) | `quic_replay.rs:QuicReplayProbe` (639), `r2o_quic_direct_data_action` (255), `r2o_quic_trial_data_verdict` (417) | Лестница, data stage. | `test-quic-*`, `d2o_quic_data_stage_loopback.c` | `partial` |
| `quic_ask` (1832), `qp_ask_vn` (1855), `quic_ask_ttl` (1869), `quic_ask_copies` (1886), `quic_ask_srcport` (1898), `quic_ask_split` (1909), `quic_ask_longer` (1924), `quic_ask_frames` (1931), `quic_ask_control` (1942) | `quic_replay.rs:r2o_quic_*_candidates` (449..) | Вопросы. | QUIC tests | `partial` |
| `reason_set` (1957), `reason_append` (1964), `budget_left` (1984), `qp_pinned_or_next` (2018), `qp_dyn_wait` (2089), `d2k_quic_budget_ms` (2096), `qp_outcome` (2111), `qp_questions_step` (2118), `d2k_quic_props_findings` (2275), `arm_budget_left` (2326), `arm_budget_spent` (2329), `classify_run` (2337), `d2k_quic_classify` (2920), `d2k_quic_base` (2924), `d2k_quic_run_seeded` (2928), `d2k_quic_run` (2933) | `quic_replay.rs:r2o_quic_base_result` (289), `r2o_quic_direct_action` (276), `r2o_quic_short_control_data_verdict` (433), `main.rs:run_quic_discovery_candidate` (18576) | Бюджет/исход/классификация. | 29 QUIC fixtures, matrix rows | `partial` (широкое, но не полное покрытие) |

`quicsnap.c` / `quicsnap_reseal.c`:

| C-функция | Rust-аналог | Тесты | Статус |
|---|---|---|---|
| `d2k_qsnap_is` (13), `parse` (17), `pack` (49), `client_hello` (75), `sni` (82), `form` (91) | `r2k-core/quic_snapshot.rs` (5 функций) | `quic_snapshot.rs` tests | `equivalent`/`partial` |
| `reseal_one` (24), `d2k_qsnap_recid` (75) | `quic.rs:r2k_quic_initial_reseal_for_dcid` (338) | RFC vectors | `partial` |

`quicwire.c`:

| C-группа (строки) | Rust-аналог | Тесты | Статус |
|---|---|---|---|
| `salt_for` (41), `label_key/iv/hp` (44..), `d2k_qw_varint_*` (56..107), `long_type_*` (119..), `d2k_qw_long_hdr_*` (142..204), `d2k_qw_hdr_parse` (204), `pn_len/decode` (277/295), `initial_secret` (317), `keys_from_secret` (327), `nonce_of` (344), `seal` (351), `open` (396), `retry_verify` (454), `retry_build` (481), `ranges_*` (525..566) | `r2k-core/quic.rs` (derive_initial_keys 849, seal/open 968/908, header_mask 1022, packet_nonce 1033, retry_integrity_valid 569) + `r2k-core/wire.rs` | RFC 9001/9369 vectors, `quicwire` tests | `equivalent` (примитивы) |

`stun.c`:

| C-функция (строка) | Rust-аналог | Тесты | Статус |
|---|---|---|---|
| `rd16` (19), `rd32` (23), `d2k_stun_request` (27), `parse_xor_mapped` (52), `d2k_stun_parse_response` (85) | `r2k-core/stun.rs` (11 функций), `voice_measure.rs:r2o_ask_voice` (600) | `tests/stun.rs`, C `test_stun`; прямого differential нет | `partial` |

`ipfrag.c`:

| C-функция (строка) | Rust-аналог | Тесты | Статус |
|---|---|---|---|
| `d2k_ipfrag_shape` (5), `d2k_ipfrag_cuts` (18), `wr16` (46), `sum16` (47), `fold` (51), `d2k_udpfrag_build_ex` (52), `d2k_udpfrag_build` (85), `d2k_udpfrag6_build_ex` (91) | `r2k-core/wire.rs:build_udp_fragments` (287), `udp_fragment_cuts` (373), `checksum_value` (538) | `test-ipfrag-differential.sh`, `ipfrag.rs` tests | `equivalent` |

### 4.17. `voice.c` (14), `voice_discovery.c` (7)

| C-функция (строка) | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|
| `is_voice_port` (42) | `voice_targets.rs:r2o_is_voice_port` (161) | 50000–50099, 1400, 3478–3481, 5349, 19294–19344. | `voice_targets` tests | `equivalent` |
| `field_val` (65) | `voice_targets.rs:r2o_field` (131) | Поиск `name=` на границе слова; C ограничивает значение 64 байтами. | `voice_targets` tests | `partial` |
| `d2k_voice_targets` (84) | `voice_targets.rs:r2o_read_voice_targets` (26) | `/proc/net/nf_conntrack`, прямой кортеж, приватные адреса, сортировка по пакетам, top-8. | `voice_targets` tests | `partial` |
| `send_one` (173) | `voice_measure.rs:r2o_ask_voice` (600) | C отправляет через `d2k_udp_plan_send` (с fake/poison); Rust — обычный `UdpSocket::send_to` без raw-плана. | `voice_measure` tests | `partial`/`missing` (raw arm) |
| `ms_since` (205) | `Instant::elapsed` | — | — | `not-applicable` |
| `voice_ask` (214) | `voice_measure.rs:r2o_ask_voice` (600) | STUN-запрос/ответ, таймаут, tally. | unit | `partial` |
| `voice_resolve` (299) | `voice_measure.rs:r2o_resolve_voice_control` (581) | `stun.cloudflare.com:3478`. | unit | `partial` |
| `voice_blob_load` (323) | `voice_measure.rs` assets `stun.bin`, `quic_initial_dbankcloud_ru.bin` (12..21) | Профили приманок. | unit (косвенно) | `partial` |
| `voice_alive` (349) | `voice_measure.rs:R2oVoiceObservation`/conntrack | Наблюдение живого потока. | unit | `partial` |
| `voice_ask_real` (365), `voice_ask_arms` (371) | `voice_measure.rs:r2o_ask_voice_with_arm` (608) | Лестница приманок 1/6 копий. Rust только строит план, не отправляет. | `test-discord-voice-discovery-arm-differential.sh` | `partial` |
| `say_reason` (403), `add_reason` (410) | `voice_measure.rs` reason building | Текст причины. | unit | `partial` |
| `d2k_voice_run` (434) | `voice_measure.rs:r2o_measure_voice` (141) | Вердикты Clear/Blocked/NoUdp/NoCall/Flaky/NoOracle/Unmeasured, контроли, `marked`. | unit; Discord differential | `partial` |
| `nibble` (voice_discovery.c:16), `d2k_voice_discovery_prefix` (22) | `voice_discovery.rs:r2o_voice_arm_plan_text` (8), prefix parsing | 20-байтовый prefix. | `test-discord-voice-discovery-arm-differential.sh` | `equivalent` |
| `d2k_discovery_response` (41), `milliseconds` (49), `discovery_probe` (54) | `voice_discovery.rs` probe/trace | IP Discovery запрос/ответ, SSRC, таймаут. | тот же differential | `partial` |
| `local_failure` (102) | `voice_discovery.rs` local error → verdict | Локальная ошибка vs блок. | unit | `partial` |
| `d2k_voice_discovery_search` (110) | `voice_discovery.rs:r2o_search_discovery_endpoint` | Серия Discovery, cutoff/prefix. | differential | `partial`/`equivalent` (scoped) |

### 4.18. `crypto.c` (28), `p256.c` (22), `x25519.c` (11)

| C-группа | Rust-замена | Что доказано | Статус |
|---|---|---|---|
| AES: `xtime` (33), `d2k_aes_sbox_byte` (70), `aes128_key_expand` (80), `sub_bytes` (112), `shift_rows` (118), `mix_columns` (131), `add_round_key` (142), `aes128_encrypt_block` (148), `d2k_aes128_ecb` (167) | crate `aes` 0.8/0.9 (`r2k-core/quic.rs:header_mask` 1022) | Header protection QUIC: RFC 9001 A.2/A.3, RFC 9369 vectors в `quic.rs`. | `equivalent` (для HP) |
| SHA-256: `rotr32` (175), `sha256_compress` (201), `sha256_init` (230), `update` (240), `final` (267), `d2k_sha256` (292) | crate `sha2` (`r2k-core/quic.rs`), `ring` | SHA-256 для HKDF/QUIC; отдельных project-векторов нет, есть RFC-векторы QUIC. | `partial` |
| HMAC/HKDF: `d2k_hmac_sha256` (301), `d2k_hkdf_extract` (331), `d2k_hkdf_expand_label` (350), `_ctx` (355) | `hkdf`/`sha2`; `ring` в rustls | QUIC initial keys проверены RFC 9001; TLS 1.2/1.3 HKDF — внутри rustls. | `partial` |
| GCM/GHASH: `gf128_h_table` (449), `gf128_mul_fast` (463), `ghash` (476), `d2k_ghash_for_test` (538), `inc32` (545), `gctr` (556), `consttime_eq16` (580), `d2k_aes128_gcm_encrypt` (592), `decrypt` (627) | `aes-gcm` 0.10 (`r2k-core/quic.rs`) | AEAD Initial/QUIC; tag comparison. `d2k_ghash_for_test` — тестовый API, прямого аналога нет. | `equivalent` (GCM), `not-applicable` (GHASH test) |
| P-256: `fe_*`, `ge`, `is_zero`, `sub_raw`, `add_raw`, `to_mont`, `from_mont`, `fe_inv`, `pt_*`, `scalar_ok` (31..262) | `ring`/`rustls` P-256 ECDHE | Прямого Rust-модуля нет; P-256 используется только TLS 1.2 ECDHE. Проверка — через TLS differential, не через векторы p256. | `implemented-unproven` |
| P-256 public API: `d2k_p256_public` (268), `keypair` (282), `ecdh` (291) | `ring::agreement::ECDH_P256` (внутри rustls) |同上. | `implemented-unproven` |
| X25519 helper: `car25519` (32), `sel25519` (52), `pack25519` (63), `unpack25519` (84), `A/Z/M/S` (91..106), `inv25519` (109) | crate `x25519-dalek`/`hpke` | — | `not-applicable` (замена) |
| `d2k_x25519` (119), `d2k_x25519_base` (170) | `hpke::kem::X25519HkdfSha256` (`ech.rs`), rustls QUIC | ECH HPKE и QUIC key share. | ECH tests, QUIC differentials | `partial` |

### 4.19. `sched.c` (286)

C-планировщик — ядро контроллера. Rust-реализация распределена: `main.rs` (state machine, события, задачи, voice, QUIC worker, HTTP), `discovery.rs` (выбор планов/привязок), `r2o_resource_limit.rs` (gate), `r2o_late_rx.rs`, `r2o_quic_deny.rs`, `r2o_fallback.rs`, `ech.rs`. Ниже — подсистемы; полный список имён с номерами строк — в Приложении A.

| Подсистема | C-функции | Rust-аналог | Покрытие/отличия | Тесты | Статус |
|---|---|---|---|---|---|
| Конфигурация/дефолты | `refuse_is_permanent`, `refuse_is_damage`, `verify_default`, `bind_default`, `verify_rx_default`, `verify_rx_gzip_default`, `mark_default`, `classify_unconfigured`, `voice_default`, `d2k_sched_new`, `d2k_sched_free`, `d2k_sched_set_send_cap`, `d2k_sched_set_say`, `d2k_sched_set_measure_mark` | `main.rs:R2oDiscoveryWorker::new` (8853), `r2o_new_with_runner` (11034), `R2oCatalogPersistence`; `measurement_gate` | Дефолтные хуки заменены прямыми вызовами. `mark`/`measure_mark` разделены в C; в R2O один `--mark`. | process/serve tests | `partial` |
| Ресурсы и лимиты | `d2k_sched_cpu_parse`, `cpu_read_proc`, `meminfo_field`, `d2k_sched_meminfo_parse`, `mem_read_proc`, `read_u64_file`, `ct_read_proc`, `res_sample`, `res_valid`, `cpu_free_pct`, `mem_reserve_kb`, `mem_short`, `ct_short`, `ct_pct`, `meas_state`, `measure_slots`, `limiter_text`, `measure_started`, `measure_limit_update` | `r2o_resource_limit.rs:R2oAdaptiveLimit` (160), `R2oMeasurementGate` (445), `r2o_measurement_worker_cap` (136), `r2o_system_measurement_worker_cap` (140), `r2o_scheduler_tick` (480), `r2o_try_acquire*` (557..) | CPU EWMA 1/10 с, память 20 %/32 МБ, conntrack 60 %, grow/shrink, start gap 250 мс. | `r2o-resource-limit-differential.sh`, `worker_permit` tests | `equivalent` (scoped) |
| Время/утилиты | `sched_mono_ms`, `wall_s`, `say`, `say_quiet`, `verdict_name`, `signal_of`, `signal_human`, `fp_add`, `volume_bucket`, `is_volume_kind`, `is_rx_volume_kind`, `box_volume_bucket_agrees`, `server_is_low`, `client_ip_of`, `server_of`, `same_flow`, `remember`, `recall`, `flowkey_same`, `is_hex_digit`, `fnv1a`, `tried_add`, `plan_ident` | `main.rs` helpers (`r2o_volume_bucket` 2963, `r2o_discovery_suspect_signal` 2924, `flow_key` 20505), `r2o_fallback.rs:tried_key` (52) | Чистые helper; часть семантики (quiet slots, FNV key) воспроизведена. | fallback/scheduler tests | `partial` |
| Cooldown/dead/quiet | `cooldown_find_endpoint`, `cooldown_find_challenge`, `dead_find`, `dead_step`, `dead_clear`, `is_late_volume_suspicion`, `cooldown_blocks`, `cooldown_clear_endpoint`, `cooldown_clear_nonchallenge`, `clear_backoff_ms`, `cooldown_victim`, `cooldown_record`, `late_close_what`, `note_clean_handshake`, `clean_handshake_recent` | `main.rs:r2o_record_discovery_cooldown` (11555), `r2o_record_discovery_challenge` (11643), `r2o_late_trigger_blocked` (11607), `R2oDeadAddress` (7453), `R2oCleanHandshakeCache` (6934..6986) | 10/30/60 мин clear-backoff, 10 мин incomplete, 60 мин challenge, 30 мин dead-address, 60 с clean handshake, 30 с late-RST. | `r2o-scheduler-cooldown-differential.sh`, `r2o-scheduler-dead-address-differential.sh` (hist.) | `equivalent` (scoped) |
| Stall budgets | `box_stall_budget`, `budget_listed`, `name_stall_budgets`, `tcp_stall_in_name_band`, `stall_budgets_push` | `main.rs:r2o_box_tcp_stall_budget` (1974), `r2o_tcp_stall_budgets` (1986), `r2o_tcp_stall_budgets_for_name` (2003), `r2o_tcp_stall_in_name_band` (2026) | Бюджеты по имени/полосе, отправка `SET_TCP_STALL_BUDGETS`. | control.rs test, scheduler fixtures | `partial` |
| Очередь/слоты задач | `task_of`, `task_free_slot`, `task_watching_slot`, `measurements_in_flight`, `queued_measurements`, `launch_task`, `launch_or_queue`, `task_budget`, `note_worker_start_failure` | `main.rs:R2oDiscoveryQueue` (8107..), `r2o_enqueue_quic_discovery` (8297), `r2o_take_ready_quic_discovery` (8323), `launch` logic в `watch_events` | 64 задачи, TCP preference, queued expiry 10 мин, start gap, worker permits. | `r2o-queue-order-differential.sh`, `r2o-discovery-coalesce-differential.sh` | `equivalent`/`partial` |
| Клиентский hello/форма | `tcp_hello_kind`, `hello_fits_client`, `quic_pack_ech`, `quic_named_find`, `client_offers_ts`, `client_tcp_profile`, `take_shape_opts`, `drop_client_opts`, `fill_hellos`, `question_shape`, `probe_shape`, `task_wire_shape`, `binding_wire_shape`, `stamp_plan_id`, `bind_confirmed` | `main.rs:R2oTcpHelloCache` (6934..), `r2o_handle_client_shape_event` (8434), `r2o_client_hello_shape` (8084), `r2o_discovery_plan_shape` (5647), `discovery.rs` | Кэши ClientHello, shape/family, ECH. | `client_shape_event_remembers_hello...`, classifier differentials | `partial` |
| Worker lifecycle | `worker_arg_alloc`, `worker_arg_free`, `d2k_sched_ech_baseline_result`, `worker_volume`, `worker_volume_cut`, `seed_input_of`, `d2k_sched_progress_note`, `ask_settle`, `sched_quic_yield`, `sched_quic_progress`, `worker_run_body`, `worker_run`, `quic_text_is_split`, `quic_client_multi`, `quic_split_unfit`, `start_worker`, `join_worker`, `box_ensure`, `task_done` | `main.rs` worker threads (`watch_events` 15191), `r2o_late_rx` worker, `r2o_resource_limit` permits, `r2o_discovery_*_progress` (7237..) | C pthread + `pthread_join`; Rust `std::thread` + каналы, stop/join, RSS-тест. | `test-worker-memory-differential.sh`, `r2o-worker-permit-differential.sh` | `partial` |
| Свойства/verify | `prop_close`, `contact_close`, `ver_close`, `task_reset`, `box_injects_rst`, `rst_guard_wanted`, `plan_arm_rst_guard`, `prop_send_next`, `prop_finish`, `task_fail`, `verify_confirm`, `partial_finish` | `classify.rs` property probes, `main.rs:r2o_run_discovery_candidate_trial*` (5042..), `r2o_confirm_discovery_outcome` (4692), `r2o_discovery_*` | Пять вопросов, RST-guard, partial clear. | classifier/measured differentials | `partial` |
| QUIC deny | `quic_deny_find`, `quic_deny_install`, `quic_deny_active`, `quic_deny_recheck`, `quic_deny_tick` | `r2o_quic_deny.rs` (16 функций), `main.rs:r2o_install_quic_deny` (19657), `r2o_remove_quic_deny` (19765) | 16 слотов, TTL, перепроверка. | unit в `r2o_quic_deny.rs` | `partial` |
| RX volume/whitelist/fallback | `rx_decoy_name`, `net_whitelist_undecided`, `net_whitelist_needs_probe`, `sched_probe_cap`, `vol_cut_measured`, `vol_cut_kb`, `rx_ladder_pending`, `next_rx_volume_plan`, `refill_from_fallback`, `budget_uncountable_note`, `budget_cut_reject` | `main.rs:r2o_discovery_volume_*` (2687..2868), `r2o_discovery_network_whitelist_probe` (2797), `r2o_rx_volume.rs`, `r2o_fallback.rs` | RX-лестница, белое имя, fallback refill по 8. | `r2o-net-whitelist-probe-differential.sh`, `r2o-fallback-differential.sh` | `partial`/`equivalent` |
| Кандидаты/ACK/install | `claim_early_refusal`, `ack_reason_text`, `candidate_trial_matches`, `exec_refusal`, `local_refusal_verdict`, `install_next`, `binding_for`, `known_plans`, `budget_rank`, `binding_beats`, `bound_plan_here`, `own_rank_before`, `own_first_plans`, `verdict_proves_block`, `clear_measured_shape`, `clear_binding_matches`, `forget_clear_target_bindings`, `plan_id_is_ours`, `applied_trial_is_ours`, `applied_of_candidate` | `main.rs:r2o_catalog_*` (2054..2161), `r2o_discovery_*` (2971..), `discovery.rs:own_first_plans` (158), `known_plans` (274), `r2o_ask_applied_matches` (20459) | Ordering по бюджету/привязкам, own-first, clear bindings, APPLIED identity. | `r2o-ack-applied-persist-differential.sh`, `r2o-known-plans-differential.sh`, `r2o-own-first-differential.sh` | `partial`/`equivalent` |
| События | `d2k_sched_event`, `on_suspect`, `on_shape`, `on_applied`, `on_refused_foreign`, `on_refused_unfit`, `on_refused`, `on_exchange`, `group_record`, `record_shape`, `own_first_continue`, `rx_saved_bootstrap`, `layered_rx_result`, `queued_before`, `quic_yield_tick`, `queued_pick`, `queued_release`, `voice_pending_dispatch`, `d2k_sched_tick`, `remeasure_snapped`, `quic_note_multi`, `quic_own_initial`, `start_search`, `search_report`, `verify_confirm`, `partial_finish`, `candidate_path`, `ladder_candidate_at`, `ladder_candidate`, `watch_shape`, `client_alpn_nonhttp`, `d2k_qsnap_is`, `say_question_trace` | `main.rs:note_datapath_event` (11508), `r2o_queue_tcp_suspect` (18366), `r2o_capture_client_shape` (18438), `r2o_complete_outcome` (12955), `apply_discovery_outcome*` (20113..), `main.rs` QUIC/voice event paths | Suspect/shape/exchange/applied/refused; порядок и дедупликация. | 20+ scheduler/classifier differentials | `partial` |
| Area/sync/persistence | `addr_binding_shape`, `newer_name_binding`, `area_key_same`, `area_find`, `area_store`, `area_retry_delay`, `area_failure`, `area_ack_reason`, `area_reason_name`, `area_retry_due`, `area_plan`, `own_exact_confirmed`, `desired_area`, `desired_has_key`, `write_live_groups`, `sync_area_send`, `area_exceptions_ready`, `area_exception_groups_suspended`, `group_exception_status`, `sync_areas`, `plan_text_max_emit`, `d2k_sched_sync`, `d2k_sched_sync_pending`, `d2k_sched_sync_step`, `plan_by_id`, `wake_loop`, `d2k_sched_wake_fd`, `d2k_sched_active` | `main.rs:CatalogSyncCursor` (3505), `catalog_commands*` (2137..), `catalog_area_*` (3333..), `write_live_groups` (6347), `sync_areas` (6588), `R2oCatalogPersistence` (1704) | Порции по 8 команд, area retry 15 с…5 мин, ACK 5 с, swap_remove, save 60 с. | `r2o-catalog-sync-differential.sh`, `r2o-catalog-persist-differential.sh`, area tests | `equivalent` (scoped) |
| Ресурсы/ECH/каталог | `has_other_family_target_plan`, `remember_resources`, `remember_measured_path`, `public_resource_peer`, `select_resource_path`, `ech_rr_known`, `ech_rr_store`, `ech_chal_has`, `ech_chal_add`, `ech_pick_witness`, `ech_witness_untried`, `ech_witness_reject`, `ech_witness_add`, `ech_witness_transport_proof`, `ech_witness_rx_cut`, `fresh_trial_id` | `main.rs` resources (2570..2705), `ech.rs`, `discovery.rs:r2o_ech_witness_candidates` (486), `r2o_ech_witness_challenge_order` (559), `R2oEchWitnessCache` (6810..) | ECH RR 6 ч/30 мин, 32 witness, ресурсные пути 1 ч. | `r2o-ech-rx-ladder-differential.sh`, `r2o-layered-rx-differential.sh` | `partial`/`equivalent` |
| Voice | `voice_trial_send`, `voice_ip_fmt`, `voice_ip_text`, `voice_ip_text2`, `voice_trial_owned`, `voice_trial_same_context`, `voice_start`, `voice_finish_measure`, `voice_observe`, `voice_confirm`, `voice_fail`, `is_voice_class`, `is_telegram_tunnel_domain` | `voice_discovery.rs`, `voice_measure.rs`, `main.rs:R2oVoiceDiscoveryWorker` (8853), `R2oVoiceTrialContext` (14942), `confirm_r2o_voice_trial` (15065), `renew_r2o_voice_trial` (15000) | Lease 120 с, renewal 60 с, trial 10 мин, pending grace 2 мин, endpoint change, NAK retention. | `test-discord-*` differentials, `test-discord-scheduled-udp-differential.sh` | `partial`/`equivalent` (scoped) |
| Диагностика/live | `json_str`, `json_time`, `level_name`, `task_phase`, `live_binding_for`, `live_autopick_status`, `props_text`, `probes_word`, `verdict_to_plans`, `d2k_sched_diagnostics`, `d2k_sched_limit_diagnostics`, `worker_type`, `d2k_sched_diagnostic_counts`, `d2k_sched_diagnostic_madvise`, `d2k_sched_diagnostic_madvise_reset`, `d2k_sched_write_live` | `live.rs` (snapshot/write), `diagnostics.rs`, `main.rs:r2o_live_searches` (11351), `r2o_live_status` (11413), `r2o_diagnostic_event` (11515), `r2o_live_snapshot` | Формат live.json и diagnostics; madvise-поля отсутствуют. | `r2o-diagnostics-differential.sh`, panel live tests | `partial`; `madvise` — `missing` |
| Прочие | `addr_probe_remove`, `question_retire`, `candidate_retire`, `trial_retire`, `box_id_for`, `quic_addr_start`, `installed_family_ready`, `binding_covering`, `queued_family_ready`, `family_recovery_eligible`, `group_path`, `family_recovery_start` | `main.rs:r2o_family_recovery_*` (4664..4862), `discovery.rs:has_covering_binding` (787), `r2o_quic_discovery_probe_path` (2669), `R2oQuicDenyCache` | Family recovery, QUIC address trial. | family recovery tests | `partial` |

## 5. CLI: флаги, значения по умолчанию, stdout/stderr, коды выхода, JSON

### 5.1. `d2kc` ↔ `r2o-controller --serve`

| Возможность | D2O `d2kc` | R2O `r2o-controller --serve` | Статус |
|---|---|---|---|
| Управляющий сокет | `--control ПУТЬ` (обязателен) | позиционный `СОКЕТ` (обязателен) | `equivalent` (форма разная) |
| Каталог | `--catalog ФАЙЛ`, default `/opt/d2k/catalog.json` | позиционный `КАТАЛОГ.json` (обязателен) | `partial` (нет default) |
| `--live` | есть; default — рядом с каталогом (`live.json`) | есть; default — рядом с каталогом | `equivalent` |
| `--log` | есть; `freopen` stdout+stderr, line-buffered | **нет** | `missing` |
| `--https-cache` | есть; default `https-cache.txt` рядом с каталогом | **нет отдельного флага**; путь `https-cache.json` рядом с каталогом | `partial` (формат и имя иные) |
| `--mark` | default `0x2d` | `--mark N`, default отсутствует (None) | `partial` |
| `--measure-mark` | есть; default = `--mark` | **нет**; отдельной метки измерений нет | `missing` |
| `--health-file` | default `/tmp/d2k/d2kc.health`, heartbeat раз в 1 с | **нет** | `missing` |
| `--discover` | нет (поиск всегда включён) | `--discover` (без него только наблюдение) | `partial` (иной default) |
| `--version` | `d2kc release=%s wire=%u`, exit 0 | `r2o-controller release=%s wire=%u`, exit 0 | `equivalent` (префикс иной) |
| `--release-id` | есть, печатает ID, exit 0/1 | **нет** | `missing` |
| `--self-check` | есть, SHA-256 «abc» + wire, exit 0/1 | **нет** для контроллера | `missing` |
| `--help` | нет (usage на ошибку) | есть, exit 0 | `partial` (Rust шире) |
| Ошибка аргументов | usage → stderr, exit **2** | usage → stderr, exit **1** | расхождение |
| Нет каталога | начинает с пустого, exit 0 | `Catalog::load` → ошибка, exit 1 | расхождение (если файла нет) |
| Битая связь с датапатом | exit 1 | `Err` → exit 1 | `equivalent` |
| Штатная остановка | exit 0, save-on-exit | exit 0, `persist_on_shutdown` | `equivalent` |

stdout: C печатает `d2kc: запущен…`, периодическую сводку `событий …`, `каталог сохранён`, `останавливаюсь`. R2O печатает `каталог загружен…`, `каталог синхронизирован…`, `каталог сохранён после изменения`, сообщения Discovery/HTTP/voice; периодической 15-минутной сводки и self_mem-строки нет. stderr: обе стороны — ошибки; тексты различаются.

### 5.2. `d2kask` ↔ `r2o-controller --ask`

| Флаг | D2O | R2O | Статус |
|---|---|---|---|
| `--control` | обязателен | обязателен | `equivalent` |
| `--ip` | обязателен, строка; проверка IP позже в `d2k_props_ask` | обязателен, строгий `IpAddr` | расхождение (невалидный IP: C → «не измерено»/exit 0, Rust → exit 2) |
| `--port` | 1..65535, default 443 | 1..65535, default 443 | `equivalent` |
| `--sni` | обязателен, непустой | обязателен, 1..253 байта | `partial` (верхняя граница) |
| `--control-sni` | требует `--arm-wait-ms` | требует `--arm-wait-ms` | `equivalent` |
| `--control-hex` | взаимоисключим с `--control-sni` | взаимоисключим | `equivalent` |
| `--hello-hex` | взаимоисключим с `--arm-wait-ms` | взаимоисключим | `equivalent` |
| `--arm-wait-ms` | >0, иначе отказ | >0, иначе отказ | `equivalent` |
| `--mark` | default 0, база 0 | default 0, база 0 | `equivalent` |
| `--save-trigger/--save-control` | есть | есть | `equivalent` |
| Повтор флага | последний выигрывает | ошибка «указан больше одного раза» | расхождение |
| `--help` | нет | есть, exit 0 | `partial` |
| Коды | 2 вход, 1 среда, 0 прогон | 2 вход, 1 среда, 0 прогон | `equivalent` (но причины разные) |

stdout: C печатает заголовок `d2kask: спрашиваем настоящую коробку DPI`, цель/имя/сокет/метку, снимок с SNI **и видом** приветствия, предупреждения, пять блоков вопросов с планом/обменом/меткой/ответом, итоговый вектор, планы. R2O печатает цель/имя/сокет/метку без заголовка, снимок без вида, пять строк вопросов, вектор и планы. Дословного differential stdout нет — только C `test_d2kask` + Rust unit.

### 5.3. `d2kfetch` ↔ `r2o-fetch`

| Флаг | D2O | R2O | Статус |
|---|---|---|---|
| `--name` | обязателен | обязателен | `equivalent` |
| `--ip` | опционально; пустая строка → DNS failed | опционально; пустая строка → dns_failed JSON | `equivalent` (по differential) |
| `--port` | `atoi`, default 443, без проверки | `u16`, default 443, ошибка на мусор | расхождение (ошибка) |
| `--path` | default `/` | default `/` | `equivalent` |
| `--wire` | default 0 → профиль | `0` → профиль | `equivalent` |
| `--deadline` | `atoi`, default 15000, отрицательное не проверяется | `u64`, default 15000, ошибка | расхождение (ошибка) |
| `--tls12` | есть | есть | `equivalent` |
| `--ladder` | есть | есть | `partial` (JSON/TX/RX формат) |
| `--quic` | есть | есть | `partial` (budget/JSON) |
| `--quic-budget` | **нет** | есть, default 25, 0 отключает | Rust-only |
| `--mark` | база 0 | база 0, строгая | `equivalent` |
| `--snapshot[=МС]` | default 60000 | default 60000 | `equivalent` |
| `--control` | **нет** (путь по умолчанию) | есть, default `R2O_CONTROL_SOCKET`/`/opt/r2o/run/r2o-datapath4.sock` | Rust-only |
| `--json` | есть | есть | `partial` (см. ниже) |
| `--version`/`-v` | есть; печатает `d2kfetch <D2K_RELEASE_ID>` | есть (`-v`, `-V`, `--version`); печатает `r2o-fetch <CARGO_PKG_VERSION>` | `partial` (разный источник версии) |
| `--help`/`-h` | нет | есть | Rust-only |
| Коды | 0 complete, 1 cut, 2 local refusal/DNS/usage | 0 complete/budget passed, 1 cut, 2 local refusal/DNS/usage | `partial` (QUIC budget) |

JSON `schema:2`: ключи TCP почти совпадают. Расхождения:
- `level`: C выдаёт 0..6 (`NOT_MEASURED/TRANSPORT/HANDSHAKE/APPLICATION/CHALLENGE/BLOCKPAGE/DENIED`); Rust TCP — только 0/1/2/3/4 (4 = CF challenge), 5/6 не выводятся;
- `name_ok`: C — результат проверки имени сертификата; Rust — `1`, если TLS установлен, иначе `-1`;
- `location`: C может вывести `null`; Rust выводит `""`;
- `cloudflare_challenge`/`body_*` для QUIC: C и Rust дают `null`, но C считает `quic_stream_bytes`, Rust — `app_bytes`;
- Rust добавляет `shape:"combined"` при `--ladder --quic`; C такого режима не имеет.

### 5.4. `d2kvoice` ↔ `r2o-controller --voice-check/--voice-list`

| Флаг | D2O | R2O | Статус |
|---|---|---|---|
| `--addr IP:ПОРТ` | IPv4:port, обязателен для явной цели | то же | `equivalent` |
| `--control` | default `stun.cloudflare.com:3478` | default тот же | `equivalent` |
| `--conntrack` | default `/proc/net/nf_conntrack` | default тот же | `equivalent` |
| `--wait` | default 3000; `0` → default | default 3 с; `0` → 0 мс | расхождение |
| `--mark` | default 0 | `None`/0 | `equivalent` |
| `--list` | есть, можно с другими флагами | `--voice-list [--conntrack]`, остальные флаги — ошибка | расхождение |
| `--discovery` | есть | есть | `equivalent` |
| Коды | 0 clear, 1 иначе, 2 аргументы; list 0/1 | то же | `equivalent` |

stdout: базовые строки `Разговор:`, `Вердикт:`, `Зондов:`, `ВНИМАНИЕ:` совпадают. Блок `Приём:` различается: C печатает `fake_arm ×arm_copies` при `discovery_verified`; Rust печатает `stun-before-discovery ×1`/`Discovery-серия подтверждена`/`Приманка: кандидат …`. C-поле `r.fake_arm` в Rust отсутствует.

### 5.5. Прочие CLI R2O без C-аналога

`r2o-controller --classify`, `--probe-response`, `--set-name`, `--set-addr`, `--del-addr`, `--apply-catalog`, `--check-catalog`, `--clear-catalog`, `--import-donor-catalog`, `--watch`, `--journal`, `--http-candidates`. В D2O это либо внутренние API (`d2k_link_*`, `d2k_classify`), либо отсутствует. Они расширяют CLI и не являются паритетными командами.

## 6. Состояния, таймеры и побочные эффекты controller

### 6.1. Главный цикл

| Параметр | D2O | R2O |
|---|---|---|
| Период tick | `TICK_MS=3000` | `measurement_gate.r2o_scheduler_tick()` при отсутствии событий; tick-дедлайн в цикле |
| Чтение control | до 256 событий за круг; после HUP — до EOF | `r2o_read_control_batch(..., 256)`; `Ok(None)` → выход |
| Приветствие датапата | 2000 мс, обязательное совпадение версии/релиза | `ControlClient::connect` + `2 с` read/write; проверка протокола в `--serve` |
| Live-файл | 2000 мс | 2000 мс |
| Сводка событий | 15 мин | **нет** |
| Сохранение каталога | 60 с, только при `revision != dirty` | 60 с, только `dirty` |
| HTTP push all | 30 мин | HTTP-поиск переустанавливает по событиям/каталогу; отдельного 30-мин push нет |
| Диагностика | tick 1 с, запись 60 с | `Recorder::tick`, интервал внутри `diagnostics.rs` |
| Остановка | SIGINT/SIGTERM → `stop_asked` | SIGINT/SIGTERM → `R2O_CONTROLLER_STOP` |

### 6.2. Задачи, trial, очередь

| Состояние/таймер | D2O | R2O |
|---|---|---|
| Максимум задач | `SCHED_MAX_TASKS=64` | очередь/слоты `R2oDiscoveryQueue`, 64 |
| Время жизни задачи | `SCHED_TASK_LIFE_MS=10 мин` | `R2O_DISCOVERY_TASK_LIFETIME=10 мин` |
| Отдых после задачи | `SCHED_REST_MS=2 мин` | `R2O_DISCOVERY_TASK_REST=120 с` |
| Ожидание voice-trial | `SCHED_VOICE_PENDING_GRACE_MS=2 мин` | `R2O_VOICE_PENDING_GRACE=120 с` |
| Время жизни voice-trial | `SCHED_TASK_LIFE_MS`/lease | `R2O_VOICE_TRIAL_TASK_LIFETIME=600 с` |
| Продление lease | `D2K_ADDR_PROBE_LEASE_MAX_MS/2` | `R2O_VOICE_TRIAL_RENEW_INTERVAL = lease/2` |
| Стартовый разнос | `SCHED_START_GAP_MS=250` | `R2oMeasurementGate::r2o_with_start_gap` (250 мс) |
| Settle trial | `SCHED_TRIAL_SETTLE_MS=50` | `D2O_TRIAL_SETTLE_MS` (50) |
| Шаг свойств | `SCHED_PROP_STEP_MS=5000` | `ASK_WAIT`/probe deadlines 5 с |
| Шаг verify | `SCHED_VERIFY_STEP_MS=5000` | 5 с |
| Повторы unsent | `SCHED_UNSENT_RETRIES=2` | `r2o_discovery_candidate_retry_count` |
| Bare retries | `SCHED_BARE_RETRIES=1` | `r2o_discovery_candidate_retryable` |
| Arm verify retries | `SCHED_ARM_VERIFY_RETRIES=2` | candidate retry logic |
| Очередь задач | queued expiry 10 мин | `r2o_expire_queued` (10 мин) |
| Кандидатский deadline | последние 9 с (тест) | `d2o_candidate_deadline_keeps_the_last_nine_seconds` |

### 6.3. Cooldown/backoff

| Причина | D2O | R2O |
|---|---|---|
| Clear, 1-я | 10 мин | `R2O_DISCOVERY_CLEAR_RETRY_FIRST=600 с` |
| Clear, 2-я | 30 мин | `...SECOND=1800 с` |
| Clear, max | 60 мин | `...MAX=3600 с` |
| Incomplete | 10 мин | `R2O_DISCOVERY_INCOMPLETE_RETRY=600 с` |
| HTTP challenge | 60 мин | `R2O_DISCOVERY_CHALLENGE_RETRY=3600 с` |
| Dead address | 30 мин | `r2o_saved_address_recheck` (1800 с) |
| Late RST only | 30 с | `r2o_record_late_rst_only_cooldown` (30 с) |
| Clean handshake | 60 с | `R2O_CLEAN_HANDSHAKE_TTL=60 с` |
| QUIC found | — | 60 мин |
| QUIC inconclusive | — | 10 мин |
| QUIC failure | — | 2 мин |
| Voice discovery | `SCHED_QUIET_MS=10 мин` | `R2O_VOICE_DISCOVERY_COOLDOWN=120 с` + clean 10 мин |
| ECH RR yes/no | 6 ч / 30 мин | `R2O_DISCOVERY_ECH_RR_*` = 6 ч / 30 мин |
| ECH witness | 32 | `R2O_ECH_WITNESS_LIMIT=32` |
| Area retry | 15 с … 5 мин | `area_retry_delay` (15 с … 300 с) |
| Area ACK | 5 с | `CatalogSyncCursor` deadline 5 с |

### 6.4. Побочные эффекты

Файлы:
- каталог: C `catalog.json` (tmp+rename; save 60 с и на выходе); R2O `catalog.json` + lock + `merge_concurrent_changes` + `save_atomic` (60 с и на выходе).
- live: C `live.json` каждые 2 с; R2O `live.json` каждые 2 с (`live::snapshot/write_snapshot`).
- HTTPS-кэш: C `https-cache.txt` текстовый; R2O `https-cache.json` (serde, TTL).
- HTTP-планы: C отдельный `http-plans.txt`; R2O хранит HTTP-планы в каталоге.
- diagnostics: C `diagnostics/report.json` (tmp+rename, лимит `D2K_DIAG_REPORT_MAX`); R2O `diagnostics/report.json` через `Recorder::write_report`.
- health: C `/tmp/d2k/d2kc.health`; R2O контроллер health-файл не пишет.
- log: C `--log` перенаправляет stdout/stderr; R2O — нет.

Сокеты:
- AF_UNIX control (C `d2k_link_open`, R2O `ControlClient`).
- UDP-сокеты измерений (C ephemeral + `d2k_udp_port_claim`; R2O ephemeral + `r2o_quic_port_was_recently_claimed`).
- TCP-сокеты проб (C `connect_bounded`, R2O `connect_until/connect_marked`).
- raw-сокеты: C в контроллере для UDP-планов/QUIC; R2O — в datapath (`raw.rs`) и `raw_probe.rs` для TCP SYN.

Control frames:
- `SET_NAME`, `SET_NAME_PROBE`, `SET_NAME_BOUND`, `DEL_NAME`, `DEL_NAME_PROBE`, `DEL_NAME_BOUND`, `SET_ADDR`, `DEL_ADDR`, `SET_ADDR_PROBE`, `DEL_ADDR_PROBE`, `SET_SUFFIX`, `DEL_SUFFIX`, `SET_BYPASS`, `DEL_BYPASS`, `SET_HTTPS`, `SET_TCP_STALL_BUDGETS`, `ARM_SHAPE`, `SET_VOICE_ADDR*`.
- события: HELLO, SUSPECT, EXCHANGE, APPLIED, REFUSED, ACK, SHAPE, CLIENT_TCP, HTTP_RESPONSE, HTTP_PORTAL, STATS, PROTO.

Diagnostics:
- C: `d2k_diag_record`, `record_limit`, `sample`, `write`; счётчики allocator/madvise.
- R2O: `Recorder::record/tick/write_report`, process memory/smaps/fd; allocator/madvise отсутствуют.

### 6.5. Переходы candidate/trial

| Фаза | D2O | R2O |
|---|---|---|
| Постановка в очередь | `on_suspect` → `launch_or_queue`; `T_QUEUED`, `queued_ms` | `r2o_queue_tcp_suspect` (18366) → `R2oDiscoveryQueue::enqueue` (8107); `R2oDiscoveryQueueEntry` (7085) |
| Допуск | `launch_task`, `SCHED_START_GAP_MS`, permits | `R2oMeasurementGate::r2o_acquire_discovery` (649), `r2o_acquire_family_recovery` (641), `r2o_try_acquire_queued` (588) |
| Trial | `prop_send_next`/`verify_confirm`/`task_fail`, `SCHED_PROP_STEP_MS` | `r2o_run_discovery_candidate_trial_with_retries` (5106), `r2o_repeat_candidate_trials` (5412), `r2o_discovery_candidate_retryable` (5494) |
| Установка | `install_next`, ACK `SET_NAME_PROBE`, `APPlied`/`REFUSED` | `install_http_candidate` (20044), `r2o_install_quic_candidate` (19770), `CatalogSyncCursor::send_step` (3623), `ControlClient::exchange_command_with_timeout` (20344) |
| Подтверждение | `on_applied`, `applied_of_candidate`, `binding_for` | `remember_applied_event` (18568), `r2o_ask_applied_matches` (20459), `apply_discovery_outcome_with_input_and_persistence` (20140) |
| Провал/clear | `on_refused`, `task_fail`, `cooldown_record`, `catalog_changed` | `on_refused_*` в `watch_events`, `r2o_record_discovery_cooldown` (11555), `record_install_failure` (12566) |
| Повтор | `SCHED_UNSENT_RETRIES=2`, `SCHED_BARE_RETRIES=1`, `SCHED_ARM_VERIFY_RETRIES=2` | `r2o_discovery_candidate_retry_count` (5395), `r2o_repeat_candidate_trials` (5412), `r2o_discovery_candidate_retryable` (5494) |

### 6.6. Порядок остановки

D2O (`d2kc.c`): SIGINT/SIGTERM → `stop_asked` → `d2k_detect_stop_all()` → `d2k_httpsprobe_free` → `d2k_hs_runner_free` → `d2k_httpsearch_free` → `d2k_sched_free` → `d2k_diag_free` → save-on-exit → `d2k_link_close` → `d2k_catalog_free`. Возврат `1`, если связь с датапатом была потеряна.

R2O (`main.rs`): `R2O_CONTROLLER_STOP` → остановка family recovery (`r2o_stop_family_recovery`, 17898) и QUIC Discovery (`r2o_stop_quic_discovery`, 17935) → `worker.r2o_begin_shutdown()`/`r2o_join()` (4630/4641, 6330/6343) → обработка оставшихся команд HTTP search → `persist_on_shutdown` (1748) → закрытие control-сокета. Ошибки сборки/остановки агрегируются в один `Err` (17883..17894).



## 7. Пробелы

### 7.1. C-функции без прямого Rust-аналога

1. `d2kc.c`: `offline_self_check`, `--release-id`, `--self-check`, `--health-file`, `--log`, `--measure-mark`, `--https-cache`; `self_mem` только частично (`process_memory`).
2. `compose.c`: `tcp_timestamps_read`, `tcp_timestamps_write`, `connect_with_tcp_profile` — нет sysctl-профиля обычного `connect`.
3. `udpruntime.c`: `udp_raw_init`, `udp_raw_close`, `udp_raw_prepare`, `udp_raw_send`, `d2k_udp_plan_send` — нет raw-UDP отправки планов из контроллера; `d2k_udp_plan_build` только через datapath apply.
4. `diagnostics.c`: `d2k_diag_memory_*` (acquire/release/peak/alloc_failure/snapshot/counts/history), `d2k_diag_set_madvise` — нет учёта аллокатора/madvise.
5. `catalog.c`: `d2k_catalog_memory_bytes` — нет оценки памяти.
6. `httpsprobe.c`: `d2k_httpsprobe_lost` — нет счётчика потерянных проб.
7. `sched.c`: `d2k_sched_diagnostic_madvise`, `d2k_sched_diagnostic_madvise_reset` — нет madvise-статистики.
8. `p256.c`: все `fe_*`/`pt_*`/`scalar_ok` и `d2k_p256_*` — нет собственного Rust-модуля; только `ring` через rustls.
9. `verify.c`: `d2k_verify_budget_set/get` — нет глобального бюджета дерева; есть per-probe/QUIC бюджет.
10. `d2kc.c`: периодическая сводка `событий …` и `self_mem`-строка в stdout.

### 7.2. Rust-код без C-аналога

- CLI: `--watch`, `--journal`, `--http-candidates`, `--import-donor-catalog`, `--check-catalog`, `--clear-catalog`, `--apply-catalog`, `--set-name`, `--set-addr`, `--del-addr`, `--classify`, `--probe-response`.
- `r2o-fetch`: `--quic-budget`, `--control`, `--help`.
- `catalog.rs:merge_concurrent_changes` (конкурентное слияние) — C `d2k_catalog_save_atomic` не сливает.
- `r2o_resource_limit.rs:R2oMeasurementGate` — C-логика встроена в `sched.c`, но отдельного объекта/тестов не было.
- `r2o_late_rx.rs`, `r2o_quic_deny.rs`, `r2o_resource.rs`, `r2o_rx_volume.rs` — выделенные модули вместо частей `sched.c`.
- `r2o_quic_http3.rs` (quinn/h3, budget/PING/stall) — C имеет собственный QUIC-стек; API/метрики иные.
- `r2o-datapath`/`r2k-core` модули (`packet.rs`, `wake`, `flow_capacity`) — относятся к datapath, не к core/controller.

### 7.3. Слишком широкие/дублирующие пункты матрицы

- «Scheduler: cooldown, … (3)» — смешивает cooldown endpoint/family, dead-address и ring eviction.
- «Discovery: known-plan reuse, … (3)» — reuse, coalesce, permits.
- «ACK → … (3)» — APPLIED proof, donor confirmation, reapply.
- «JSON catalog, schema, atomic save (3)» — схема, atomic, merge.
- «TLS 1.2 response probe and verdicts (3)» — scan12, handshake, decide, follow-up.
- «QUIC 台阶… (3)» — residual/VN, neutral controls, fallback.
- «Discord voice trial: lease, renewal, … (3)» — lease, renewal, APPLIED.
- «HTTP search… (3)» — candidates, judge, confirmed/applied.
- «Firewall service… (2)» и «ABI/QEMU (2)» — две независимые подсистемы в одном пункте.
- Пункт «TCP measurement and core TLS/HTTP verifier outcomes/retry (2)» ссылается на `meas.c`, который в текущем `d2kc` не вызывается; фактический C-oracle — `detect/`, а не `core/meas.c`.

### 7.4. Известные расхождения, требующие RED-тестов

1. `d2kfetch` JSON `level` 5/6, `name_ok`, `location` null/"".
2. `d2kfetch` non-JSON текст (`TLS/HTTP/тело/итог/время` vs `маршрут/…`).
3. `d2kask` обработка невалидного IP/ClientHello и дублей флагов.
4. `d2kvoice` `--wait 0`, `--voice-list` с лишними флагами, блок `Приём`.
5. `d2kc` exit 2 vs 1 на usage, отсутствие default-каталога, health/log/self-check.
6. `plantlv` `d2k-plan` vs `r2o-plan`, `autottl` minexec.
7. `udpruntime` raw-UDP измерение.
8. `crypto/p256/x25519` — нет прямых C/Rust-векторов, только протокольные differentials.

## 8. Предлагаемое разбиение контрактов (веса, без баллов)

| Новый контракт | Что входит | Вес | Текущий статус |
|---|---|---:|---|
| C1. Control wire: события | `d2k_link_next`, все decode_* | 2 | `equivalent` (d2o_control_differential) |
| C2. Control wire: команды | `SET/DEL NAME/ADDR/AREA/BYPASS/HTTPS/STALL/ARM`, ACK correlation | 3 | `partial` (unit + отдельные wire fixtures) |
| C3. Link lifecycle | open/close/peer_closed/reconnect, EINTR, frame limits | 1 | `partial` |
| C4. Ask CLI | argv, snapshot, wait/retry, 5 вопросов, stdout, exit | 3 | `partial` |
| C5. Ask protocol | question plans, trace, retire, properties | 2 | `partial` |
| C6. Fetch CLI | TCP/QUIC/ladder/json/exit/stdout | 3 | `partial` |
| C7. Fetch JSON schema | ключи, level, name_ok, location, null-семантика | 2 | `partial` (есть расхождения) |
| C8. Volume TX | 10 HEAD, X-Pad, RTT-timeout, verdict | 2 | `partial` |
| C9. Volume RX | identity×2/×3, gzip, packet budget, retry path | 3 | `partial` |
| C10. Voice CLI | argv/defaults, verdicts, stdout, exit | 2 | `partial` |
| C11. Voice measurement | STUN control, arms, raw plan send, discovery | 3 | `partial`/`missing` (raw) |
| C12. Daemon CLI/lifecycle | flags, signals, health, log, self-check, exit | 2 | `partial` |
| C13. Daemon loop | tick/save/live/report/shutdown order | 3 | `partial` |
| C14. Catalog schema | load/save/validate/import | 2 | `equivalent` (scoped) |
| C15. Catalog concurrency | lock, merge, atomic rename | 2 | `partial` |
| C16. Domain/groups | normalize/base/member/learn/restore/match/expire | 2 | `implemented-unproven` |
| C17. Fingerprint match | fp_same/catalog_match | 1 | `partial` |
| C18. Scheduler state machine | task states, transitions, queue | 4 | `partial` |
| C19. Scheduler cooldowns | endpoint/family/dead/quiet/late-RST/clean-HS | 3 | `equivalent` (scoped) |
| C20. Scheduler events | suspect/shape/exchange/applied/refused | 4 | `partial` |
| C21. Scheduler install/ACK | install_next, APPLIED identity, retention | 3 | `partial` |
| C22. Area sync/persistence | sync_step, area ACK, save interval | 3 | `equivalent` (scoped) |
| C23. Scheduler diagnostics/live | live.json, counts, memory/madvise | 2 | `partial`/`missing` |
| C24. ECH | config parse, HPKE, RR, witness, ladder | 3 | `partial` |
| C25. QUIC wire | Initial/QSN/reseal/varint/AEAD | 3 | `equivalent` (RFC vectors) |
| C26. QUIC discovery | arms, strategy, data stage, HTTP/3 | 4 | `partial` |
| C27. HTTP/3 framing/budget | headers, body, FIN/RESET, stall, budget | 3 | `partial` |
| C28. HTTP search | candidates, judge, install, APPLIED, persistence | 3 | `equivalent` (scoped) |
| C29. HTTPS probe | cache, TTL, worker, portal | 2 | `partial` |
| C30. HTTP upgrade/portal | request_safe, redirect, portal, h3 status | 2 | `partial` |
| C31. TLS verifier | handshake, cert name, HTTP body, gateway WS | 4 | `equivalent`/`partial` |
| C32. Crypto replacement | AES/SHA/HMAC/HKDF/GCM/P-256/X25519 | 2 | `partial`/`implemented-unproven` |
| C33. UDP runtime | plan build, raw send, fragments, port claim | 2 | `partial`/`missing` |
| C34. STUN/Discord observation | request/parse, SSRC, endpoint change | 2 | `partial` |
| C35. IP fragmentation | v4/v6, 4 формы, checksums | 2 | `equivalent` |

### 8.1. Ограничения этого аудита

- Парсер C-функций эвристический; он не различает определения и редкие инициализаторы, поэтому счёт 1214/1163 — верхняя оценка. Ложные срабатывания отмечены.
- Ни один тест не запускался: `cargo`, `rustc`, `git` отсутствуют в PATH. Все ссылки на прохождение тестов — исторические, из матрицы/скриптов, и помечены `(hist.)` там, где это важно.
- «Equivalent» здесь означает «есть конкретный тест/дифференциал на этот контракт», а не «доказано для всех production-сценариев».
- Контрактный процент 80/89 = 89,89 % — из матрицы; он не пересчитывался и не является функциональным процентом по 1163 именам.
- Расхождения CLI/JSON, перечисленные в 7.4, требуют RED-тестов и не считаются закрытыми.


















## Приложение A. Полный инвентарь определений C (core/*.c, без test_*)

Строки — номера начала определения. Парсер эвристический: он может принять за функцию инициализатор структуры; такие случаи отмечены в разделе пробелов. `strncasecmp` в httpup_logic.c — совместимый helper, `memcmp`/`strcmp` в sched.c — ложные срабатывания.

Каждая функция ниже наследует статус своей группы/строки из раздела 4. Для файлов, где таблица называет диапазон (`quicconn.c`, `quicwire.c`, `p256.c`, `tls12.c`, `tls13.c`, `tls13core.c`, `verify.c`, `httpsearch.c`, `httpsprobe.c`), статус группы относится ко всем перечисленным здесь именам; исключения названы в тексте таблицы.


### catalog.c — 60

```
55 set_err, 79 jpeek, 92 jeat, 110 jeat_null_if_present, 148 floor_div, 156 days_from_civil, 166 civil_from_days, 185 format_rfc3339, 207 jparse_raw_int, 241 jparse_i32, 252 jparse_u8, 263 jparse_u16, 274 jparse_bool_i, 305 jparse_string_dyn, 408 jparse_string_fixed, 428 read_fixed_digits, 447 eat_lit, 462 jparse_rfc3339, 545 jskip_value, 629 parse_object, 667 grow, 692 parse_array, 723 handle_signal_key, 743 parse_signal, 756 handle_fp_key, 789 parse_fp, 798 handle_plan_key, 817 parse_plan, 821 elem_plan, 834 handle_binding_key, 886 parse_binding, 891 elem_binding, 905 d2k_cat_shape_fits, 918 handle_box_key, 940 parse_box, 944 elem_box, 953 handle_domain_observation, 972 parse_domain_observations, 991 handle_net_whitelist_key, 1001 handle_catalog_key, 1028 parse_catalog_obj, 1036 prune_unavailable_domain_groups, 1062 free_box, 1072 d2k_catalog_free, 1084 d2k_catalog_memory_bytes, 1103 read_whole_file, 1145 d2k_catalog_load, 1198 write_json_string, 1220 wr_indent, 1230 write_json_array, 1242 write_signal_elem, 1259 write_fp, 1268 write_plan_elem, 1282 write_binding_elem, 1334 write_box_elem, 1353 write_domain_key, 1359 write_domain_observation, 1367 write_domain_group, 1374 d2k_catalog_save, 1445 d2k_catalog_save_atomic
```

### compose.c — 53

```
107 d2k_net_whitelist_count, 110 d2k_net_whitelist_name, 150 wr16be, 151 rd16be, 152 wr32be, 162 tlv_rec, 186 tlv_header, 218 plan_tlv_stamp_ident, 258 overlap_plan_tlv, 277 reorder_plan_tlv, 296 badsum_fake_plan_tlv, 322 checksum_plan_tlv, 331 to_hex, 351 ev_matches_flow, 397 wait_for_event3, 423 wait_for_event, 494 props_bind_any, 526 d2k_props_bind, 530 d2k_props_bind_family, 534 d2k_props_bind_udp, 538 d2k_props_bind_udp_family, 542 d2k_props_contact, 547 d2k_props_contact_on, 553 d2k_props_contact_on_family, 567 tcp_timestamps_read, 580 tcp_timestamps_write, 591 connect_with_tcp_profile, 638 d2k_props_contact_on_family_tcp_profile, 786 build_fake_body, 798 d2k_props_question_plan, 845 d2k_props_question_passed, 874 question_retire, 881 d2k_props_ask, 889 step_rc, 900 d2k_props_ask_traced, 1203 append_fmt, 1221 emit_header_proto, 1229 emit_header, 1233 append_hex, 1245 overlap_plan_text, 1271 reorder_plan_text, 1288 badsum_fake_plan_text, 1312 checksum_plan_text, 1346 build_decoy_hello, 1356 parse_protocol_plan_text, 1367 duplicates_plan_text, 1384 body_room, 1397 everything_plan_text, 1499 d2k_fallback_arms, 1504 fb_arm_at, 1543 d2k_fallback_plan, 1552 d2k_arm_plan, 1763 d2k_compose
```

### crypto.c — 28

```
33 xtime, 70 d2k_aes_sbox_byte, 80 aes128_key_expand, 112 sub_bytes, 121 shift_rows, 131 mix_columns, 142 add_round_key, 151 aes128_encrypt_block, 167 d2k_aes128_ecb, 175 rotr32, 201 sha256_compress, 230 sha256_init, 242 sha256_update, 267 sha256_final, 292 d2k_sha256, 301 d2k_hmac_sha256, 331 d2k_hkdf_extract, 350 d2k_hkdf_expand_label, 355 d2k_hkdf_expand_label_ctx, 449 gf128_h_table, 463 gf128_mul_fast, 479 ghash, 538 d2k_ghash_for_test, 547 inc32, 560 gctr, 584 consttime_eq16, 596 d2k_aes128_gcm_encrypt, 627 d2k_aes128_gcm_decrypt
```

### d2kask.c — 24

```
120 need_value, 134 parse_flag_u16, 157 parse_flag_u32, 179 parse_flag_ms, 202 parse_args, 315 hex_nibble, 329 save_hex, 361 read_hex_file, 424 wait_shape, 462 pval_str, 470 print_header, 482 print_snapshot, 519 pos_decided, 530 pos_value, 547 step_rc_str, 565 ack_code_str, 579 print_seen_types, 597 print_step, 632 print_question, 676 all_unknown, 684 print_not_asked_at_all, 698 print_vector, 707 print_plans, 736 main
```

### d2kc.c — 28

```
111 on_signal, 113 now_ms, 122 save_atomic, 136 self_mem, 150 sched_say, 168 http_search_portal, 176 hs_open_port, 210 hs_close_port, 212 hs_hex, 221 hs_set_probe, 235 hs_del_probe, 246 hs_set_plan, 259 hs_del_plan, 271 hs_start, 277 hs_changed, 288 http_portal, 310 http_push, 317 http_save, 324 http_probe_done, 357 hs_say, 365 poison_cmp, 368 hs_measured_poisons, 394 usage, 406 offline_self_check, 415 diagnostic_event, 418 diagnostic_limit, 421 diagnostic_tick, 470 main
```

### d2kfetch.c — 6

```
41 json_string, 64 vol_verdict_code, 74 usage, 104 resolve_first, 117 snapshot_wire, 157 main
```

### d2kvoice.c — 4

```
22 usage, 39 split_hostport, 50 verdict_word, 63 main
```

### diagnostics.c — 41

```
98 copy, 105 js, 131 number, 132 d2k_diag_new, 133 d2k_diag_free, 134 d2k_diag_bytes, 135 d2k_diag_event_count, 136 d2k_diag_sample_count, 137 d2k_diag_memory_history_count, 138 d2k_diag_memory_enable, 139 d2k_diag_memory_active, 140 atomic_read, 141 atomic_peak, 145 d2k_diag_memory_acquire, 152 d2k_diag_memory_release, 157 d2k_diag_memory_alloc_failure, 161 d2k_diag_memory_snapshot, 170 d2k_diag_memory_counts, 180 d2k_diag_set_madvise, 181 record_anomaly, 188 d2k_diag_record_write_error, 192 d2k_diag_record, 202 d2k_diag_record_limit, 213 value, 218 compact_kib, 221 compact_bytes_kib, 222 compact_bytes, 223 compact_count, 225 proc_pid_dir_present, 230 optional_proc_status, 238 read_proc, 260 read_detail, 305 read_status, 310 write_detail, 329 write_limit_reason, 344 write_limit_reason_state, 357 write_memory_tracking, 370 write_madvise, 382 write_anomalies, 395 d2k_diag_sample, 469 d2k_diag_write
```

### domain.c — 4

```
6 d2k_domain_normalize, 31 rule_exists, 42 d2k_domain_base, 66 d2k_domain_member
```

### groups.c — 14

```
9 d2k_group_key_make, 19 d2k_group_key_same, 24 valid, 38 member, 45 votes, 61 failures, 72 add_group, 103 rebuild, 122 cover, 133 d2k_group_learn, 246 d2k_group_restore, 274 d2k_group_match, 294 d2k_group_forget, 311 d2k_group_expire
```

### h3.c — 9

```
19 d2k_h3_control, 30 prefix_int, 51 prefix_int_read, 73 d2k_h3_request, 126 huff_status, 148 static_status, 171 name_is_status, 176 decode_section, 262 d2k_h3_status
```

### hello.c — 19

```
51 rd16, 54 rd24, 57 wr16, 61 wr24, 69 skip_u8_vec, 80 skip_u16_vec, 128 parse_hello, 274 d2k_hello_complete, 283 d2k_hello_shape, 308 d2k_hello_sni, 322 d2k_hello_ech_offer, 349 d2k_hello_alpn, 377 d2k_alpn_is_http, 409 splice_sni, 462 hex_nibble, 480 hex_decode, 500 d2k_hello_rename, 537 d2k_hello_without_sni, 578 d2k_hello_from_profile
```

### httpsearch.c — 66

```
37 mono_ms, 43 d2k_hs_answer_name, 61 d2k_hs_judge, 99 hs_path_ok, 110 hs_read, 132 d2k_hs_probe_run, 253 d2k_hs_candidate_count, 254 d2k_hs_candidate_key, 258 poison_key_spec, 289 known_key, 296 d2k_hs_candidate_text, 329 stable_id, 336 fresh_id, 444 say, 454 host_ok, 470 rec_find, 479 rec_get, 502 same_program, 512 failed_live, 522 remember_live_failure, 555 d2k_httpsearch_test_add_failures, 569 d2k_httpsearch_test_add_records, 581 d2k_httpsearch_measured_poison, 610 d2k_hs_plan_poisons, 646 d2k_httpsearch_new, 654 drop_socket, 661 drop_probe, 668 d2k_httpsearch_free, 678 d2k_httpsearch_busy, 682 d2k_httpsearch_plan_of, 689 d2k_httpsearch_diagnostic_counts, 709 d2k_httpsearch_diagnostics, 712 diagnostic_end, 724 finish, 732 open_job, 754 revoke_owned, 761 all_failed, 806 install, 820 d2k_httpsearch_install_ack, 845 confirmed, 896 trial_executed, 904 judge_trial, 957 next_candidate, 1007 add_cand, 1014 build_cands, 1043 build_fallback, 1056 start, 1095 start_next, 1105 live_owner, 1115 d2k_httpsearch_bound_failure, 1135 d2k_httpsearch_control, 1172 d2k_httpsearch_cut, 1192 d2k_httpsearch_portal, 1231 d2k_httpsearch_ack, 1264 d2k_httpsearch_applied, 1291 d2k_httpsearch_result, 1399 d2k_httpsearch_tick, 1431 d2k_httpsearch_push_all, 1446 d2k_httpsearch_save, 1475 d2k_httpsearch_load, 1527 runner_main, 1541 d2k_hs_runner_new, 1557 d2k_hs_runner_free, 1566 d2k_hs_runner_wake_fd, 1568 d2k_hs_runner_start, 1583 d2k_hs_runner_done
```

### httpsprobe.c — 22

```
32 d2k_https_classify, 42 d2k_https_upgrade, 46 d2k_https_ttl, 57 d2k_https_state_name, 69 mono_ms, 77 https_connect, 148 https_tls, 171 first_flight, 203 d2k_https_probe_real, 274 host_ok, 285 cache_find, 292 cache_put, 314 worker, 351 d2k_httpsprobe_new, 377 d2k_httpsprobe_free, 393 d2k_httpsprobe_wake_fd, 397 d2k_httpsprobe_portal, 430 d2k_httpsprobe_done, 451 d2k_httpsprobe_state, 460 d2k_httpsprobe_lost, 476 d2k_httpsprobe_save, 507 d2k_httpsprobe_load
```

### httpup_logic.c — 17

```
16 ascii_alnum, 21 dns_host, 37 host_equal, 46 known_portal_host, 53 find_crlf, 60 parse_request, 105 strncasecmp, 113 strncasecmp, 132 d2k_httpup_request_safe, 137 build_redirect, 151 portal_marker, 172 redirect_location_host, 193 portal_answer, 227 d2k_httpup_portal_response, 240 d2k_httpup_request_target, 253 d2k_httpup_portal_location, 264 d2k_httpup_redirect_https
```

### ipfrag.c — 8

```
5 d2k_ipfrag_shape, 18 d2k_ipfrag_cuts, 46 wr16, 47 sum16, 51 fold, 52 d2k_udpfrag_build_ex, 85 d2k_udpfrag_build, 91 d2k_udpfrag6_build_ex
```

### link.c — 43

```
45 execution_context, 56 say, 70 wait_readable, 92 read_exact, 108 write_all, 133 hex_nibble, 144 hex_decode, 161 d2k_link_open, 191 d2k_link_close, 197 d2k_link_peer_closed, 223 d2k_link_next, 524 d2k_link_set_name, 531 d2k_link_set_name_probe, 538 send_name_plan, 632 d2k_link_set_name_family, 639 d2k_link_set_name_bound, 645 d2k_link_del_name_bound, 659 d2k_link_set_name_probe_trial, 670 area_context_valid, 677 d2k_link_set_suffix_family, 686 d2k_link_set_https, 707 d2k_link_set_stall_budgets, 731 send_area_key, 754 d2k_link_del_suffix_family, 758 d2k_link_set_bypass_family, 762 d2k_link_del_bypass_family, 767 d2k_link_area_identified, 783 addr_shape_ok, 789 d2k_link_set_addr, 794 d2k_link_set_addr_family, 852 addr_probe_flow_bytes, 868 d2k_link_set_addr_probe, 877 d2k_link_set_addr_probe_family, 911 d2k_link_del_addr_probe, 919 d2k_link_del_addr_probe_family, 939 d2k_link_arm_shape, 944 d2k_link_arm_shape_family, 981 d2k_link_del_name_family, 1014 d2k_link_del_name_probe, 1020 d2k_link_del_name_probe_family, 1051 d2k_link_del_addr, 1056 d2k_link_del_addr_family, 1079 d2k_ev_outer_appdata
```

### match.c — 3

```
38 same_evidence, 75 d2k_fp_same, 127 d2k_catalog_match
```

### meas.c — 13

```
52 nap_us, 61 d2k_mark_real, 87 d2k_accept_serverhello, 96 d2k_accept_tls_record, 101 d2k_accept_any, 109 cuts_valid, 124 send_all, 142 connect_bounded, 175 d2k_meas_once, 269 d2k_meas, 307 udp_now_ms, 313 d2k_udp_port_claim, 341 d2k_udp_port_forget_all
```

### measured.c — 12

```
10 append_fmt, 22 append_hex, 33 d2k_white_decoy_hello, 57 template_plan, 84 d2k_rx_volume_plan_named, 90 d2k_rx_volume_plan_client, 114 d2k_rx_volume_plan, 121 measured_payload, 140 d2k_tcp_split_plan, 153 d2k_arm_plan_measured_cap, 369 append_fmt, 387 d2k_arm_plan_measured
```

### net4.c — 4

```
7 d2k_ip4_parse, 32 d2k_ip4_text, 40 d2k_ip4_private, 53 d2k_ip6_private
```

### p256.c — 22

```
31 fe_copy, 34 ge, 41 is_zero, 48 sub_raw, 59 add_raw, 69 fe_add, 76 fe_sub, 84 fe_mul, 115 fe_sqr, 124 to_mont, 125 from_mont, 131 fe_inv, 143 fe_from_be, 150 fe_to_be, 161 pt_double, 192 pt_add, 235 pt_mul, 249 pt_affine, 262 scalar_ok, 268 d2k_p256_public, 282 d2k_p256_keypair, 291 d2k_p256_ecdh
```

### plantlv.c — 20

```
126 b64_value, 133 parse_base64, 163 say, 171 hex_nib, 180 parse_hex, 206 anchor_by_name, 221 split_fields, 237 parse_uint, 248 parse_int, 259 kv_u32, 268 str_u32, 272 plan_free, 277 parse_text, 691 put, 696 put_u8, 697 put_u16, 698 put_u32, 702 put_rec, 709 d2k_plan_text_to_tlv, 847 d2k_plan_text_to_hex
```

### props.c — 5

```
35 original_probe, 47 original_data, 52 wire_measure, 80 d2k_quic_original_measure, 88 d2k_quic_strategy_measure
```

### quic.c — 21

```
97 rd16, 110 read_varint, 149 parse_initial_header, 182 d2k_quic_is_initial, 191 decrypt_initial, 239 collect_crypto_frames, 434 skip_u8_vec, 446 skip_u16_vec, 458 find_sni, 503 find_client_hello_sni, 552 crypto_stream_of, 567 d2k_quic_client_hello, 607 d2k_quic_dgrams_hello, 661 d2k_quic_hello_name, 672 d2k_quic_hello_incomplete, 687 d2k_quic_sni, 708 d2k_quic_assembly_init, 712 d2k_quic_assembly_feed, 780 d2k_quic_assembly_complete, 824 put_split_frame, 841 d2k_quic_initial_split_crypto
```

### quicarms.c — 8

```
12 d2k_quic_original_blob, 30 ask_q, 112 ask_frag, 125 ask, 142 d2k_quic_original_arms, 227 strategy_ask, 244 prop_word, 248 d2k_quic_strategy_arms
```

### quicconn.c — 36

```
209 qc_dispose, 218 say, 226 now_ms, 243 crypto_put, 254 crypto_ready, 265 build_ack, 281 seal_level, 352 send_level, 367 tp_put_int, 380 tp_build, 418 tp_server_parse, 460 tp_server_ee, 479 frames_in, 702 recv_dgram, 820 crypto_frame, 836 first_flight, 898 prepare_retry, 928 d2k_qc_first_initial, 956 qc_no_sigpipe, 966 d2k_qc_connect, 1288 d2k_qc_stream_send, 1377 d2k_qc_stream_recv, 1425 d2k_qc_app_progress, 1430 d2k_qc_peer_name, 1431 d2k_qc_rx_wire_bytes, 1432 d2k_qc_datagrams, 1436 d2k_qc_handshake_done, 1437 d2k_qc_rtt_ms, 1438 d2k_qc_dgrams, 1443 d2k_qc_outbound, 1454 d2k_qc_ping, 1459 d2k_qc_fd, 1461 d2k_qc_local, 1470 d2k_qc_local_addr, 1478 d2k_qc_release, 1486 d2k_qc_close
```

### quichello.c — 13

```
34 select_probe_profile, 69 split_point, 80 put_crypto, 124 prepare, 183 seal_one, 235 probe_initial_sized, 276 d2k_quic_probe_initial, 281 d2k_quic_probe_initial_longer, 287 d2k_quic_prepare_target, 312 d2k_quic_hello_rename, 330 d2k_quic_hello_ask, 412 d2k_quic_hello_split, 457 d2k_quic_hello_recid
```

### quicprobe.c — 57

```
173 qp_addr_parse, 181 resolve_family, 209 resolve_real, 254 d2k_quic_build_pool, 320 qp_varint, 337 qp_parse_hdr, 411 qp_dcid_of, 456 qp_donor_unauth_reply, 494 qp_verify_server_response, 574 qp_build_vn_trigger, 622 nap_us, 637 qp_open_fresh, 716 qp_send_one, 806 qp_head_of, 815 qp_verify_aead, 835 qp_verify_bound, 880 d2k_quic_verify_bound, 890 d2k_quic_verify_response, 898 qp_verify_vn, 937 qp_recv_ttl, 1004 qp_send_fragmented, 1045 qp_neutral_control_sni, 1064 quic_ask_core, 1228 d2k_quic_hello_recid, 1405 quic_ask_ex, 1418 quic_fragment, 1432 qp_progress, 1437 quic_ask_arm, 1500 qp_arm_first_send, 1510 qp_now_ms, 1516 quic_arm_data, 1591 d2k_quic_data_stage, 1832 quic_ask, 1855 qp_ask_vn, 1869 quic_ask_ttl, 1886 quic_ask_copies, 1898 quic_ask_srcport, 1909 quic_ask_split, 1924 quic_ask_longer, 1931 quic_ask_frames, 1942 quic_ask_control, 1957 reason_set, 1964 reason_append, 1984 budget_left, 2018 qp_pinned_or_next, 2089 qp_dyn_wait, 2096 d2k_quic_budget_ms, 2111 qp_outcome, 2118 qp_questions_step, 2275 d2k_quic_props_findings, 2326 arm_budget_left, 2329 arm_budget_spent, 2337 classify_run, 2920 d2k_quic_classify, 2924 d2k_quic_base, 2928 d2k_quic_run_seeded, 2933 d2k_quic_run
```

### quicsnap_reseal.c — 2

```
24 reseal_one, 75 d2k_qsnap_recid
```

### quicsnap.c — 6

```
13 d2k_qsnap_is, 17 d2k_qsnap_parse, 49 d2k_qsnap_pack, 75 d2k_qsnap_client_hello, 82 d2k_qsnap_sni, 91 d2k_qsnap_form
```

### quicwire.c — 28

```
41 salt_for, 44 label_key, 47 label_iv, 50 label_hp, 56 d2k_qw_varint_read, 69 d2k_qw_varint_len, 77 d2k_qw_varint_write_w, 107 d2k_qw_varint_write, 119 long_type_v1, 132 long_type_wire, 142 d2k_qw_long_hdr_token_w, 176 d2k_qw_long_hdr_w, 186 d2k_qw_long_hdr_token, 196 d2k_qw_long_hdr, 204 d2k_qw_hdr_parse, 277 d2k_qw_pn_len, 295 d2k_qw_pn_decode, 317 d2k_qw_initial_secret, 327 d2k_qw_keys_from_secret, 344 nonce_of, 351 d2k_qw_seal, 396 d2k_qw_open, 454 d2k_qw_retry_verify, 481 d2k_qw_retry_build, 525 d2k_qw_ranges_reset, 529 d2k_qw_ranges_add, 560 d2k_qw_ranges_bytes, 566 d2k_qw_ranges_complete
```

### sched.c — 286

```
301 refuse_is_permanent, 320 refuse_is_damage, 388 verify_default, 415 bind_default, 420 verify_rx_default, 429 verify_rx_gzip_default, 438 mark_default, 451 classify_unconfigured, 482 voice_default, 488 d2k_sched_cpu_parse, 513 cpu_read_proc, 531 meminfo_field, 551 d2k_sched_meminfo_parse, 562 mem_read_proc, 573 read_u64_file, 584 ct_read_proc, 1114 client_alpn_nonhttp, 1139 fresh_trial_id, 1516 addr_probe_remove, 1557 question_retire, 1572 candidate_retire, 1592 trial_retire, 1603 say, 1615 say_quiet, 1634 d2k_sched_set_send_cap, 1639 d2k_sched_set_say, 1647 verdict_name, 1672 signal_of, 1699 is_rx_volume_kind, 1703 fp_add, 1746 volume_bucket, 1753 is_volume_kind, 1760 box_volume_bucket_agrees, 1798 server_is_low, 1807 client_ip_of, 1813 server_of, 1824 same_flow, 1841 remember, 1864 recall, 1871 cooldown_find_endpoint, 1886 cooldown_find_challenge, 1899 dead_find, 1915 dead_step, 1937 dead_clear, 1942 is_late_volume_suspicion, 1948 cooldown_blocks, 1975 cooldown_clear_endpoint, 1982 cooldown_clear_nonchallenge, 2000 clear_backoff_ms, 2012 cooldown_victim, 2032 cooldown_record, 2100 late_close_what, 2114 box_stall_budget, 2124 budget_listed, 2131 name_stall_budgets, 2153 tcp_stall_in_name_band, 2170 stall_budgets_push, 2193 task_of, 2204 task_free_slot, 2217 task_watching_slot, 2240 tcp_hello_kind, 2245 hello_fits_client, 2256 quic_pack_ech, 2268 quic_named_find, 2286 client_offers_ts, 2303 client_tcp_profile, 2320 flowkey_same, 2328 take_shape_opts, 2342 drop_client_opts, 2347 fill_hellos, 2377 strcmp, 2382 d2k_qsnap_is, 2519 worker_arg_alloc, 2529 worker_arg_free, 2538 d2k_sched_ech_baseline_result, 2561 worker_volume, 2632 worker_volume_cut, 2667 seed_input_of, 2680 d2k_sched_progress_note, 2700 ask_settle, 2707 sched_quic_yield, 2731 sched_quic_progress, 2735 sched_mono_ms, 2741 worker_run_body, 3255 worker_run, 3276 quic_text_is_split, 3280 quic_client_multi, 3293 quic_split_unfit, 3306 task_budget, 3331 note_worker_start_failure, 3339 start_worker, 3405 join_worker, 3430 box_ensure, 3459 wall_s, 3463 bind_confirmed, 3574 fnv1a, 3593 tried_add, 3598 plan_ident, 3607 is_hex_digit, 3635 question_shape, 3642 probe_shape, 3674 task_wire_shape, 3678 binding_wire_shape, 3684 stamp_plan_id, 3727 prop_close, 3738 contact_close, 3749 ver_close, 3762 task_reset, 3834 box_injects_rst, 3842 rst_guard_wanted, 3853 plan_arm_rst_guard, 3864 prop_send_next, 3974 prop_finish, 3993 task_fail, 4032 quic_deny_find, 4040 quic_deny_install, 4114 quic_deny_active, 4129 quic_deny_recheck, 4155 quic_deny_tick, 4183 task_done, 4195 rx_decoy_name, 4201 net_whitelist_undecided, 4211 net_whitelist_needs_probe, 4220 sched_probe_cap, 4224 vol_cut_measured, 4227 vol_cut_kb, 4233 rx_ladder_pending, 4242 next_rx_volume_plan, 4292 refill_from_fallback, 4394 claim_early_refusal, 4412 ack_reason_text, 4424 candidate_trial_matches, 4437 exec_refusal, 4468 ech_witness_transport_proof, 4476 ech_witness_rx_cut, 4485 local_refusal_verdict, 4539 install_next, 4760 binding_for, 4777 known_plans, 4866 budget_rank, 4869 binding_beats, 4881 bound_plan_here, 4906 own_rank_before, 4914 own_first_plans, 5057 verdict_proves_block, 5074 clear_measured_shape, 5082 clear_binding_matches, 5123 forget_clear_target_bindings, 5178 props_text, 5191 probes_word, 5209 verdict_to_plans, 5566 d2k_sched_new, 5612 d2k_sched_set_measure_mark, 5624 json_str, 5634 json_time, 5650 level_name, 5663 signal_human, 5685 task_phase, 5707 live_binding_for, 5723 live_autopick_status, 5811 d2k_sched_diagnostics, 5814 d2k_sched_limit_diagnostics, 5817 worker_type, 5826 d2k_sched_diagnostic_counts, 5876 d2k_sched_diagnostic_madvise, 5877 d2k_sched_diagnostic_madvise_reset, 5879 d2k_sched_write_live, 6051 d2k_sched_free, 6077 wake_loop, 6082 d2k_sched_wake_fd, 6084 d2k_sched_active, 6096 plan_by_id, 6112 d2k_sched_sync, 6127 d2k_sched_sync_pending, 6144 addr_binding_shape, 6171 newer_name_binding, 6195 area_key_same, 6200 area_find, 6206 area_store, 6214 area_retry_delay, 6223 area_failure, 6239 area_ack_reason, 6248 area_reason_name, 6260 area_retry_due, 6267 area_plan, 6278 own_exact_confirmed, 6297 desired_area, 6334 desired_has_key, 6347 write_live_groups, 6442 sync_area_send, 6520 area_exceptions_ready, 6534 area_exception_groups_suspended, 6553 group_exception_status, 6588 sync_areas, 6648 plan_text_max_emit, 6660 d2k_sched_sync_step, 6915 has_other_family_target_plan, 6939 remember_resources, 6969 remember_measured_path, 6985 public_resource_peer, 6995 select_resource_path, 7052 ech_rr_known, 7061 ech_rr_store, 7074 ech_chal_has, 7081 ech_chal_add, 7088 ech_pick_witness, 7118 ech_witness_untried, 7130 ech_witness_reject, 7140 ech_witness_add, 7152 start_search, 7332 box_id_for, 7424 voice_trial_send, 7446 voice_ip_fmt, 7450 voice_ip_text, 7454 voice_ip_text2, 7461 voice_trial_owned, 7469 voice_trial_same_context, 7481 voice_start, 7512 voice_finish_measure, 7616 quic_addr_start, 7628 measurements_in_flight, 7635 queued_measurements, 7649 res_sample, 7696 res_valid, 7698 cpu_free_pct, 7702 mem_reserve_kb, 7707 mem_short, 7711 ct_short, 7717 ct_pct, 7721 meas_state, 7741 measure_slots, 7750 limiter_text, 7767 measure_started, 7771 measure_limit_update, 7842 installed_family_ready, 7876 binding_covering, 7899 watch_shape, 7905 queued_family_ready, 7910 family_recovery_eligible, 7919 group_path, 7923 family_recovery_start, 7999 launch_task, 8029 launch_or_queue, 8070 voice_observe, 8090 voice_confirm, 8153 voice_fail, 8160 is_voice_class, 8167 is_telegram_tunnel_domain, 8181 on_suspect, 8578 memcmp, 8607 quic_own_initial, 8623 remeasure_snapped, 8690 quic_note_multi, 8732 on_shape, 9013 group_record, 9035 record_shape, 9043 budget_uncountable_note, 9072 budget_cut_reject, 9159 say_question_trace, 9175 ladder_candidate_at, 9185 ladder_candidate, 9189 candidate_path, 9207 search_report, 9262 verify_confirm, 9668 partial_finish, 9691 plan_id_is_ours, 9700 applied_trial_is_ours, 9708 applied_of_candidate, 9739 on_applied, 9900 on_refused_foreign, 9960 on_refused_unfit, 10053 on_refused, 10176 note_clean_handshake, 10202 clean_handshake_recent, 10217 on_exchange, 10325 d2k_sched_event, 10465 own_first_continue, 10528 rx_saved_bootstrap, 10574 layered_rx_result, 10658 queued_before, 10666 quic_yield_tick, 10703 queued_pick, 10728 queued_release, 10756 voice_pending_dispatch, 10784 d2k_sched_tick, 10907 voice_trial_owned
```

### stun.c — 5

```
19 rd16, 23 rd32, 27 d2k_stun_request, 52 parse_xor_mapped, 85 d2k_stun_parse_response
```

### tls12.c — 26

```
98 tls12_dispose, 102 say, 110 now_ms, 116 put16, 117 get16, 119 read_exact, 155 write_all, 183 prf, 214 d2k_tls12_prf_for_test, 220 tr_add, 228 nonce_of, 235 aad_of, 246 send_plain, 258 send_sealed, 287 read_record, 355 hs_next, 415 ch12_build, 492 d2k_tls12_connect, 532 d2k_tls12_resume, 556 tls12_finish, 750 d2k_tls12_write, 756 d2k_tls12_read, 795 d2k_tls12_peer_name, 797 d2k_tls12_free, 799 d2k_tls12_rx_wire_bytes, 800 d2k_tls12_rx_record_missing
```

### tls13.c — 23

```
83 tls_dispose, 87 say, 95 now_ms, 102 read_exact, 138 write_all, 160 put16, 161 get16, 165 nonce_of, 175 read_record, 236 write_record, 260 traffic_keys, 265 tls_connect_internal, 525 d2k_tls_connect, 531 d2k_tls_connect_alpn, 538 d2k_tls_connect_ech, 548 d2k_tls_ech_accepted, 550 d2k_tls_write, 562 d2k_tls_read, 603 d2k_tls_peer_name, 605 d2k_tls_free, 610 d2k_tls_rx_wire_bytes, 611 d2k_tls_rx_record_missing, 613 d2k_tls_version
```

### tls13core.c — 24

```
16 put16, 17 get16, 21 d2k_t13_random, 53 der_len, 64 ascii_lower, 73 name_matches, 106 cert_name_ok, 166 d2k_t13_cert_name_ok12, 177 d2k_t13_cert_name_ok, 197 d2k_t13_ch_build, 361 d2k_t13_derive_secret, 368 d2k_t13_schedule_hs, 383 d2k_t13_schedule_ap, 396 d2k_t13_finished_mac, 407 d2k_t13_sh_version, 428 d2k_t13_sh_parse, 479 d2k_t13_flight_next, 492 ech_host_ok, 510 d2k_ech_config_parse, 570 hpke_extract, 583 hpke_expand, 598 ech_hpke, 621 d2k_t13_ech_build, 684 d2k_t13_ech_accepted
```

### udpplan.c — 12

```
10 append_fmt, 28 emit_header_proto, 36 append_hex, 50 quic_arm_found, 59 quic_split_plan_text, 69 quic_plan_text, 173 d2k_quic_arm_plan, 188 d2k_quic_compose_plan, 205 d2k_quic_delay_plan, 219 d2k_voice_arm_plan, 241 d2k_voice_plan, 247 d2k_quic_question_plan
```

### udpruntime.c — 8

```
22 udp_next_fragment_id, 32 d2k_udp_batch_free, 33 d2k_udp_plan_build, 101 udp_raw_init, 107 udp_raw_close, 113 udp_raw_prepare, 131 udp_raw_send, 147 d2k_udp_plan_send
```

### verdict.c — 7

```
33 looks_like_tls, 53 reverse_note, 74 pause_note, 92 stop_requested, 96 classify_cancelled, 104 d2k_classify_cancelable, 336 d2k_classify
```

### verify_quic_replay.c — 2

```
23 replay_now_ms, 29 d2k_verify_quic_replay_on
```

### verify.c — 74

```
52 verify_now_ms, 58 dns16, 62 ech_dns_name, 90 d2k_ech_resolve, 193 find_hdr_end, 203 find_eol, 210 lower_ascii, 214 span_eq_ascii_ci, 227 has_cf_challenge, 273 read13, 278 read12, 298 body_read_reason, 304 body_say, 308 body_feed, 317 body_byte, 331 body_exact, 352 body_line, 380 read_http_body, 457 read_status_buf, 699 read_status_rd, 730 d2k_http_read_response, 739 d2k_verify_probe, 750 write13, 755 write12, 762 redirect_path, 799 https_redirect_response, 822 d2k_verify_budget_set, 823 d2k_verify_budget_get, 826 d2k_verify_tcp_timestamps_set, 829 d2k_verify_tcp_timestamps_get, 837 d2k_verify_quic_form_set, 850 d2k_verify_tcp_data_packets, 877 budget_say, 885 gateway_header_end, 892 gateway_header_value, 905 gateway_connection_upgrade, 917 gateway_json_hello, 976 gateway_fill, 1000 request_gateway_websocket, 1132 read_eof, 1146 budget_tcp, 1217 fd_peer_spoke, 1223 fd_packets, 1238 request_complete_page, 1247 request_page_budget, 1349 verify_contact, 1360 d2k_props_contact_on_family_tcp_profile, 1365 verify_probe13_internal, 1444 verify_probe13_on, 1451 ech_http_denial, 1462 d2k_verify_probe_ech_on, 1478 d2k_verify_probe_ech_origin_on, 1499 d2k_verify_replay_on, 1564 d2k_verify_probe_on, 1578 d2k_verify_probe_alpn_on, 1636 verify_probe12_internal, 1703 d2k_verify_probe12_on, 1710 d2k_verify_probe_identity_on, 1717 d2k_verify_probe_gzip_on, 1724 d2k_verify_probe_baseline, 1744 d2k_verify_probe_path_on, 1759 d2k_verify_close, 1768 d2k_verify_probe_quic, 1780 quic_app_silent, 1799 h3_read_headers, 1816 quic_recv_chunk, 1836 budget_quic, 1953 qb_request, 1960 qb_recv, 1964 qb_progress, 1967 qb_packets, 1975 d2k_verify_probe_quic_on, 1983 d2k_verify_probe_quic_path_on, 1991 d2k_verify_probe_quic_path_mark_on
```

### voice_discovery.c — 7

```
16 nibble, 22 d2k_voice_discovery_prefix, 41 d2k_discovery_response, 49 milliseconds, 54 discovery_probe, 102 local_failure, 110 d2k_voice_discovery_search
```

### voice.c — 14

```
42 is_voice_port, 65 field_val, 84 d2k_voice_targets, 173 send_one, 205 ms_since, 214 voice_ask, 299 voice_resolve, 323 voice_blob_load, 349 voice_alive, 365 voice_ask_real, 371 voice_ask_arms, 403 say_reason, 410 add_reason, 434 d2k_voice_run
```

### volume.c — 19

```
58 rx_wire_partial, 66 d2k_volume_rx_partial, 78 d2k_volume_rx_pair_agrees, 103 d2k_volume_rx_needs_repeat, 111 d2k_volume_rx_evidence, 215 d2k_vol_verdict_name, 224 now_ms, 230 nap_ms, 237 clamp_ms, 247 fill_pad, 259 connect_bounded, 325 drain_head_tls, 351 drain_head_plain, 393 resource_retry_path, 411 rx_probe, 440 measure_response_volume, 558 probe_response_volume, 595 d2k_volume_probe_path, 729 d2k_volume_probe
```

### x25519.c — 11

```
32 car25519, 54 sel25519, 63 pack25519, 84 unpack25519, 91 A, 92 Z, 94 M, 106 S, 109 inv25519, 119 d2k_x25519, 170 d2k_x25519_base
```


