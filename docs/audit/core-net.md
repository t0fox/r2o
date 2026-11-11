# Аудит паритета D2O (C) → R2O (Rust): сетевой срез core-net

- D2O-оракул: `a378e230947ebfd011439e1cac0f1e994d883aae` (worktree `/mnt/e/d2o-a378w`, общий git-dir `/mnt/e/d2o`).
- R2O: `d7b5a87971f689760ea3d061e246b54a7ae02f76` (ветка `main`; в рабочем дереве есть посторонние untracked-файлы, исходники не изменялись).
- Дата аудита: 2026-11-11.
- Срез: `r2o-tooling/audit/slice-core-net.csv` — **548** функций в 29 файлах (25 `.c` + 4 `.h`).
- Метод: прочитано тело каждой C-функции (строки `line..end_line`), найден Rust-аналог в `crates/`, проверены существующие тесты и дифференциалы. Сборка и тесты **не запускались**; статусы `E` опираются на наличие целевого теста/дифференциала в репозитории, а не на прогон в этом проходе.

## Легенда

| Статус | Значение |
|---|---|
| `E` | Есть Rust-реализация и целевой тест или C/Rust-дифференциал, напрямую проверяющий контракт функции (тест указан в колонке доказательства; в этом проходе не перезапускался). |
| `P` | Rust-реализация есть, но не все ветви/состояния/ошибки/форматы доказаны либо покрытие только косвенное. |
| `N` | Rust-реализации не найдено после поиска по `crates/` (включая случаи, где C-функция тестовая или серверная и в R2O не нужна). |
| `?` | Недостаточно данных: ложное срабатывание парсера среза или функцию не удалось однозначно сопоставить. |

`P` не означает «сломано»: это либо неполное доказательство, либо замена зависимости (`rustls`/`quinn`/`ring`), где построчной функции нет.

## Сводка

| Показатель | Значение |
|---|---:|
| Всего функций в срезе | 548 |
| `E` | 217 |
| `P` | 318 |
| `N` | 12 |
| `?` | 1 |

Доли: `E` — 39,60%, `P` — 58,03%, `N` — 2,19%, `?` — 0,18%.

Переклассификация после `deep-core-net.md`: `first_flight`/`d2k_qc_first_initial`
E→P, `d2k_qc_peer_name` E→N, `remember_live_failure` P→N,
`udp_raw_init/close/prepare/send`, `d2k_udp_plan_send`,
`d2k_vol_verdict_name` N→P.

Крупные владельцы Rust-кода: `r2o-controller/src/fetch.rs` (verify/volume/gateway), `r2o-controller/src/http_search.rs` + `main.rs` (HTTP search), `r2o-controller/src/quic_replay.rs` + `r2k-core/src/quic*.rs` (QUIC), `r2k-core/src/{tls,httpup,h3,stun,wire,http_response}.rs` (протокольные кодеки), `r2o-controller/src/{voice_*,https_probe,r2o_volume,r2o_tls,ech,hello}.rs`.

Ограничения: E/P выставлены по коду и имеющимся тестовым путям; production-поведение на живом роутере, аппаратные timing-сценарии и OpenWrt/musl в этом проходе не проверялись. Функции, заменённые зависимостями (`rustls`, `quinn`, `ring`, `hpke`), почти всегда `P`, даже если end-to-end дифференциал существует.

Строгая интерпретация: если учитывать только тесты, фактически перезапущенные в этом проходе, `E` было бы 0. Колонка `E` здесь означает «есть конкретный целевой тест/дифференциал в репозитории», а не «тест только что прошёл»; результат такого теста в этом проходе не перепроверялся.


## core/hello.c (19 функций)

Rust-владелец: `crates/r2o-controller/src/hello.rs` (почти построчный порт парсера и сборки ClientHello). Дифференциал: `scripts/test-controller-clienthello-differential.sh` (C-оракул `tests/d2o_tls_parse_differential.c` + `core/hello.c` против `examples/tg_cl12_tls_trace.rs`).

| C-функция | строки | размер | назначение | R2O-аналог | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `rd16` | 51-53 | 3 | big-endian u16 из буфера | `hello.rs:186 hello_u16` | E | хелпер; владелец `parse_hello` → `hello.rs:213 parse_hello_layout`, дифф `test-controller-clienthello-differential.sh` |
| `rd24` | 54-56 | 3 | big-endian u24 | `hello.rs:192 hello_u24` | E | хелпер; тот же владелец и дифф |
| `wr16` | 57-60 | 4 | запись big-endian u16 | `hello.rs:534 write_len(width=2)` | P | хелпер только для `splice_sni`/`rename`; прямого теста записи длин нет |
| `wr24` | 61-65 | 5 | запись big-endian u24 | `hello.rs:534 write_len(width=3)` | P | то же; границы `>0xffffff` проверяются в `write_len` |
| `skip_u8_vec` | 69-79 | 11 | пропуск TLS-вектора с 1-байтовой длиной | `hello.rs:198 hello_skip_u8_vec` | E | владелец `parse_hello_layout`; дифф ClientHello |
| `skip_u16_vec` | 80-90 | 11 | пропуск TLS-вектора с 2-байтовой длиной | `hello.rs:204 hello_skip_u16_vec` | E | владелец `parse_hello_layout`; дифф ClientHello |
| `parse_hello` | 128-272 | 145 | разбор записи ClientHello: длины, SNI-координаты, supported_versions, усечение расширений | `r2o-controller/src/hello.rs:213 parse_hello_layout` | E | побайтовый порт; дифф `test-controller-clienthello-differential.sh` (24+ кейсов: длины, усечения, SNI, ECH) |
| `d2k_hello_complete` | 274-281 | 8 | ровно одна полная запись+рукопожатие без хвоста | `hello.rs:344 hello_complete` | E | дифф ClientHello; unit `trailing_bytes_keep_shape_and_sni_but_not_complete` |
| `d2k_hello_shape` | 283-306 | 24 | MODERN/LEGACY/UNKNOWN по supported_versions | `hello.rs:366 hello_shape` | E | дифф ClientHello + unit `shape_distinguishes_modern_and_legacy_profiles` |
| `d2k_hello_sni` | 308-320 | 13 | координаты имени SNI | `hello.rs:383 hello_sni_bounds` | E | дифф ClientHello (sni-кейсы) |
| `d2k_hello_ech_offer` | 322-347 | 26 | валидация ECH-предложения и config_id | `hello.rs:391 hello_ech_offer` | E | дифф ClientHello (ech-duplicate/bad-type/enc-over/payload-mismatch) |
| `d2k_hello_alpn` | 349-375 | 27 | извлечь список ALPN из ClientHello | `r2o_tls.rs:121 r2o_tls_client_hello_non_http_alpn` | P | аналог возвращает только не-HTTP список и отвергает ECH; сырого списка и кодов ошибок C нет; покрыт косвенно `tests/d2o_verify_differential.rs:990` |
| `d2k_alpn_is_http` | 377-387 | 11 | есть ли в ALPN http/1.1, http/1.0, h2 | `r2o_tls.rs:121` (фильтр внутри) | P | отдельного предиката нет; логика встроена, тест только на общий результат |
| `splice_sni` | 409-452 | 44 | заменить SNI и пересчитать 6 длин записи | `hello.rs:439 rename_sni` | P | порт есть, но точное совпадение пересчёта длин дифференциалом не проверяется; используется `raw_probe.rs:625` |
| `hex_nibble` | 462-473 | 12 | hex-цифра → значение | `hello.rs:501 decode_profile` (через `to_digit(16)`) | P | отдельного хелпера нет; отличается обработка комментариев/пробелов |
| `hex_decode` | 480-498 | 19 | hex-строка → байты с проверкой чётности/ёмкости | `hello.rs:501 decode_profile` | P | принимает `#`-комментарии и пробелы; отрицательный результат — `None`, не код |
| `d2k_hello_rename` | 500-535 | 36 | обернуть CH в запись и заменить SNI | `hello.rs:439 rename_sni` | P | порт `rename_sni`; unit-теста и дифференциала на rename нет, вызов в `raw_probe.rs:625` |
| `d2k_hello_without_sni` | 537-576 | 40 | удалить расширение server_name и пересчитать длины | `r2k-core/src/quic.rs:1113 r2k_quic_client_hello_rename_sni(..., None)` | P | TLS-путь отдельной функции не имеет; QUIC-путь покрыт unit `quic.rs:1398-1420` |
| `d2k_hello_from_profile` | 578-609 | 32 | собрать ClientHello из встроенного профиля (modern/legacy) с подстановкой SNI | `hello.rs:549 client_hello_from_profile`, обёртки `legacy_client_hello`/`modern_client_hello` | E | unit `shape_distinguishes_modern_and_legacy_profiles`, `hello.rs` тесты профилей; используется fetch/httpsprobe |

## core/tls12.c (26 функций)

C-реализация минимального TLS 1.2 клиента (ECDHE+AES128-GCM, X25519/P-256) для зондов/измерений. В R2O построчного порта нет: стек заменён `rustls` с ограничением cipher suites и KX-групп (`r2o-controller/src/r2o_tls.rs:53`, ветка `tls12`). Дифференциал: `scripts/r2o-tls-verify-differential.sh` → `tests/d2o_verify_differential.rs` (в т.ч. `donor_and_r2o_reject_short_tls12_server_finished` с C-фикстурой `tls12`).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `tls12_dispose` | 98-100 | 3 | освободить сессию и снять учёт diagnostic memory | `r2o_tls.rs:53` (rustls, RAII) | P | владелец `d2k_tls12_connect`; отдельной функции нет, diag-учёт аллокатора не портирован |
| `say` | 102-108 | 7 | форматирование ошибки в буфер | нет (std `format!`/`io::Error`) | P | инфраструктурный хелпер стека; эквивалент по смыслу, отдельной функции нет |
| `now_ms` | 110-114 | 5 | монотонное время, мс | `std::time::Instant` | P | хелпер; прямого аналога-функции нет |
| `put16` | 116-116 | 1 | big-endian u16 | `u16::to_be_bytes` | P | хелпер записи заголовков |
| `get16` | 117-117 | 1 | big-endian u16 | `u16::from_be_bytes` | P | хелпер чтения заголовков |
| `read_exact` | 119-153 | 35 | дочитать n байт с дедлайном, учёт `rx_wire_bytes`/`rx_record_missing`, обработка EINTR/EOF | `fetch.rs:2464 R2oTlsTcpStream::read`, `:2975 set_deadline` | P | Абсолютный дедлайн в R2O есть: остаток пересчитывается на каждой итерации (`fetch.rs:963-986,1859-1901`), `WouldBlock/TimedOut/Interrupted` повторяются. Не совпадают poll-кванты ≤1 с, EINTR-семантика, тексты ошибок и точные `rx_wire_bytes`/`rx_record_missing`. |
| `write_all` | 155-171 | 17 | дослать буфер с MSG_NOSIGNAL | `fetch.rs` запись через rustls `Stream` | P | эквивалент std/rustls; EINTR-ветка не воспроизведена |
| `prf` | 183-212 | 30 | TLS 1.2 PRF (HMAC-SHA256, P_hash) | rustls (внутренний TLS1.2 PRF) | P | собственной функции нет; KAT C (`test_tls12.c`) в Rust не перенесён |
| `d2k_tls12_prf_for_test` | 214-218 | 5 | тестовый экспорт PRF | нет | N | используется только `test_tls12.c:44,58`; Rust-аналога и векторов нет |
| `tr_add` | 220-225 | 6 | накопить транскрипт рукопожатия | rustls (транскрипт внутри) | P | хелпер стека; собственная функция отсутствует |
| `nonce_of` | 228-233 | 6 | nonce = salt(4)+seq(8) для GCM | rustls/ring AEAD nonce | P | хелпер record-layer |
| `aad_of` | 235-242 | 8 | AAD записи TLS 1.2 (seq/type/version/len) | rustls/ring AEAD AAD | P | хелпер record-layer |
| `send_plain` | 246-256 | 11 | отправить открытую запись | rustls `write_tls` | P | собственной функции нет |
| `send_sealed` | 258-282 | 25 | зашифровать и отправить запись (explicit nonce, seq++) | rustls `write_tls` | P | cipher suite/группы совпадают с C, но формат записи проверяется только косвенно |
| `read_record` | 287-345 | 59 | прочитать запись, распознать открытый HTTP/CCS/alert, расшифровать | rustls `read_tls` + `R2oTlsRecordTracker` | P | **Ветка «открытый `HTTP/` вместо TLS» в fetch/replay не портирована явно:** rustls даёт общий `DecryptError`/`InvalidMessage`, а проверка `HTTP/` есть только в `response.rs:572` (HTTPS-проба). Проверки `rlen==0/>18432`, минимум 24 байта, CCS и AEAD-ошибки делегированы rustls с иными текстами. |
| `hs_next` | 355-407 | 53 | собрать handshake-сообщения из записей, CCS/alert | rustls handshake driver | P | собственная state-machine отсутствует |
| `ch12_build` | 415-485 | 71 | собрать TLS1.2 ClientHello (2 шифра, X25519/P-256, padding до `want_wire`) | rustls ClientHello + `r2o_client_hello_wire_len` (`r2o_tls.rs:53`, `fetch.rs:157 wire_len`) | P | Длина CH сверяется differential (tls13-pad), для tls12 отдельного кейса нет. **Расхождения:** C не шлёт ALPN, R2O всегда шлёт `http/1.1` (`r2o_tls.rs:59,110`); C объявляет P-384, но отвергает SKE с ним, R2O разрешает `SECP384R1` (`:96`) и принимает то, что C отвергает; sigalg-список rustls шире C. |
| `d2k_tls12_connect` | 492-522 | 31 | создать сессию, собрать/отправить CH, пройти handshake | `r2o_tls.rs:53 r2o_tls_client_connection(tls12=true)` | P | end-to-end TLS1.2 сверяется `donor_and_r2o_reject_short_tls12_server_finished` и `tests/fetch.rs` (TLS12-сервер); ветки ошибок C (группа/шифр) в rustls иные |
| `d2k_tls12_resume` | 532-551 | 20 | продолжить handshake по сохранённому полёту сервера (downgrade из tls13.c) | rustls (автосогласование версии в одном соединении) | P | отдельного resume нет; downgrade-путь покрыт только косвенно |
| `tls12_finish` | 556-748 | 193 | разбор ServerHello/Certificate/SKE/Done, ECDH, вывод ключей, CKE/CCS/Finished | rustls handshake | P | порт не построчный; поддерживаемые C группы/шифры воспроизведены конфигурацией rustls; ошибки «сервер требует клиентский сертификат» и выбор неподдерживаемой группы не имеют C/Rust differential |
| `d2k_tls12_write` | 750-754 | 5 | отправить application data | `fetch.rs` rustls `Stream::write_all` | P | эквивалент зависимости |
| `d2k_tls12_read` | 756-793 | 38 | прочитать app data, обработать alert/буферизацию | `fetch.rs:2464` + rustls `Stream::read` | P | эквивалент зависимости; close_notify-семантика не сопоставлена |
| `d2k_tls12_peer_name` | 795-795 | 1 | результат проверки имени сертификата | `fetch.rs` `peer_name_ok`, `response.rs:389 https_certificate_name_matches` | P | имя проверяется в `response.rs`; differential `donor_and_r2o_tls_results_match_for_matching_and_mismatched_certificate_names` |
| `d2k_tls12_free` | 797-797 | 1 | освободить сессию | RAII `Drop` | P | владелец `d2k_tls12_connect`; отдельной функции нет |
| `d2k_tls12_rx_wire_bytes` | 799-799 | 1 | счётчик принятых байт | `fetch.rs:1333 rx_tls_wire_bytes` | P | поле результата, не функция; сверяется в volume-дифференциалах |
| `d2k_tls12_rx_record_missing` | 800-800 | 1 | сколько байт записи не дочитано | `fetch.rs:2459 r2o_record_missing` | P | есть аналог трекера, но точное значение (uint32) не выдаётся |

## core/tls13.c (23 функции)

C-реализация TLS 1.3 клиента (X25519, HKDF-SHA256, AES-128-GCM) с веткой ECH и downgrade на TLS 1.2. R2O заменяет стек на `rustls`; собственная сборка ClientHello для повторов/позднего RX — `r2o_tls.rs:340 r2o_tls13_client_hello`, ECH — `r2o_tls.rs:274/305` + `ech.rs`. Дифференциалы: `scripts/r2o-tls-verify-differential.sh`, `scripts/r2o-ech-rx-ladder-differential.sh`, `tests/r2o_tls.rs`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `tls_dispose` | 83-85 | 3 | освободить сессию TLS1.3 и снять diag-учёт | `r2o_tls.rs` (rustls, RAII) | P | владелец `tls_connect_internal`; отдельной функции нет |
| `say` | 87-93 | 7 | форматирование ошибки | нет (std `format!`) | P | инфраструктурный хелпер |
| `now_ms` | 95-99 | 5 | монотонное время, мс | `std::time::Instant` | P | хелпер |
| `read_exact` | 102-136 | 35 | дочитать n байт с дедлайном и учётом `rx_wire_bytes`/`rx_record_missing` | `fetch.rs:2464 R2oTlsTcpStream::read`, `:2975 set_deadline` | P | Абсолютный дедлайн есть; различаются poll-кванты, EINTR, тексты и точная семантика `uint32` счётчиков. |
| `write_all` | 138-154 | 17 | дослать буфер с MSG_NOSIGNAL | `fetch.rs` rustls `Stream::write_all` | P | эквивалент std |
| `put16` | 160-160 | 1 | big-endian u16 | `u16::to_be_bytes` | P | хелпер |
| `get16` | 161-161 | 1 | big-endian u16 | `u16::from_be_bytes` | P | хелпер |
| `nonce_of` | 165-170 | 6 | nonce = iv XOR seq | rustls/ring AEAD nonce | P | хелпер record-layer |
| `read_record` | 175-234 | 60 | чтение записи, CCS/alert, снятие padding, расшифровка, внутренний тип | rustls `read_tls` + `R2oTlsRecordTracker` | P | Ветка открытого `HTTP/` в fetch явно не проверяется (только `response.rs:572`). **Расхождение:** C принимает открытый Handshake после установки ключей (206-212), rustls такой пакет отвергает. Padding/внутренний тип/AEAD — внутри rustls, тексты иные. |
| `write_record` | 236-258 | 23 | зашифровать app data с внутренним типом и тегом | rustls `write_tls` | P | формат записи C не сравнивается с rustls побайтно |
| `traffic_keys` | 260-263 | 4 | HKDF-Expand-Label key/iv | rustls (key schedule) | P | собственной функции нет |
| `tls_connect_internal` | 265-523 | 259 | полный handshake TLS1.3: CH/ECH, ServerHello, X25519, расписание ключей, Certificate, Finished, app keys | `r2o_tls.rs:53 r2o_tls_client_connection`, `r2o_tls.rs:274 r2o_tls_ech_client_connection` | P | end-to-end сверяется `r2o-tls-verify-differential.sh`; ветки ошибок C (ECH not accepted, Finished mismatch, малая точка) заменены поведением rustls и не сравнивались |
| `d2k_tls_connect` | 525-529 | 5 | TLS1.3 без ALPN/ECH | `r2o_tls.rs:53 r2o_tls_client_connection` | P | rustls предлагает TLS1.3+TLS1.2 и `http/1.1`; C-профиль расширений уже |
| `d2k_tls_connect_alpn` | 531-536 | 6 | TLS1.3 с явным списком ALPN | `r2o_tls.rs:63 r2o_tls_client_connection_with_alpn` | E | unit `tests/r2o_tls.rs:101 клиентское_рукопожатие_предлагает_http11_alpn`, `:115 предлагает_наборы_донора` |
| `d2k_tls_connect_ech` | 538-546 | 9 | TLS1.3 c ECH (origin + config) | `r2o_tls.rs:274 r2o_tls_ech_client_connection` | P | живой ECH-путь не сверялся с C; replay ECH покрыт `donor_and_r2o_require_server_hello_when_replaying_captured_ech` |
| `d2k_tls_ech_accepted` | 548-548 | 1 | флаг принятия ECH | `fetch.rs:986 connection.ech_status() == Accepted` | P | rustls проверяет статус; C-оракул для этого флага не подключён |
| `d2k_tls_write` | 550-560 | 11 | запись app data частями ≤16 КиБ, делегирование TLS1.2 | `fetch.rs` rustls `Stream::write_all` | P | эквивалент зависимости |
| `d2k_tls_read` | 562-601 | 40 | чтение app data, CCS/alert/handshake, буферизация, делегирование TLS1.2 | `fetch.rs:2464` + rustls `Stream::read` | P | эквивалент зависимости; close_notify не сопоставлен |
| `d2k_tls_peer_name` | 603-603 | 1 | результат проверки имени сертификата | `fetch.rs` `peer_name_ok` + `response.rs:389 https_certificate_name_matches` | E | differential `donor_and_r2o_tls_results_match_for_matching_and_mismatched_certificate_names` |
| `d2k_tls_free` | 605-608 | 4 | освободить TLS1.3/вложенный TLS1.2 | RAII `Drop` | P | отдельной функции нет |
| `d2k_tls_rx_wire_bytes` | 610-610 | 1 | суммарные принятые байты (обе версии) | `fetch.rs:1333 rx_tls_wire_bytes` | P | поле результата; сверяется косвенно в volume-тестах |
| `d2k_tls_rx_record_missing` | 611-611 | 1 | недобор байт записи (обе версии) | `fetch.rs:2459 r2o_record_missing` | P | аналог-трекер есть, точное значение не выдаётся |
| `d2k_tls_version` | 613-613 | 1 | 0x0304/0x0303/0 | `fetch.rs:994 protocol_version → "1.3"/"1.2"` | E | differential `d2o_verify_differential.rs:412` проверяет `tls == Some("1.2"/"1.3")` |

## core/tls13core.c (24 функции)

Ядро TLS 1.3/ECH: DER-разбор SAN, сборка ClientHello, расписание ключей, разбор ServerHello, HPKE для ECH. Часть перенесена почти построчно: `response.rs` (SAN), `r2o_tls.rs:340 r2o_tls13_client_hello`, `ech.rs`. Дифференциалы: `tests/response.rs::d2o_shared_tls_response_vectors_match`, `tests/r2o_tls.rs`, `scripts/r2o-ech-rx-ladder-differential.sh`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `put16` | 16-16 | 1 | big-endian u16 | `r2o_tls.rs:486 push_u16` | E | хелпер сборщика CH; владелец `d2k_t13_ch_build` → `r2o_tls13_client_hello`, unit `tests/r2o_tls.rs` |
| `get16` | 17-17 | 1 | big-endian u16 | `u16::from_be_bytes` | E | хелпер разбора ServerHello/сертификата; владельцы покрыты дифференциалами |
| `d2k_t13_random` | 21-27 | 7 | 32 случайных байта из /dev/urandom | `ring`/`getrandom` (через rustls, `ech.rs`) | P | прямого API нет; источник энтропии заменён зависимостью |
| `der_len` | 53-62 | 10 | длина DER-объекта | `response.rs:485 https_der_length` | E | differential `tests/response.rs:479 d2o_shared_tls_response_vectors_match` |
| `ascii_lower` | 64-64 | 1 | ASCII lower | `response.rs:508 lower_ascii` | E | входит в проверку SAN, покрыт differential |
| `name_matches` | 73-96 | 24 | сравнение DNS-имени, wildcard `*.` | `response.rs:503 https_dns_name_matches` | E | differential `d2o_shared_tls_response_vectors_match`, `d2o_verify_differential` (mismatch/invalid UTF-8/zero-length IP) |
| `cert_name_ok` | 106-154 | 49 | поиск subjectAltName, DNS/IP SAN, wildcard | `response.rs:389 https_certificate_name_matches` | E | differential `tests/response.rs:479`, `d2o_verify_differential.rs:719` |
| `d2k_t13_cert_name_ok12` | 166-175 | 10 | SAN из Certificate TLS1.2 (3-байтовые длины) | `response.rs:389 https_certificate_name_matches` | E | тот же парсер; TLS1.2-путь сверяется `donor_and_r2o_tls_results_match_...` |
| `d2k_t13_cert_name_ok` | 177-189 | 13 | SAN из Certificate TLS1.3 (context+3-байтовые длины) | `response.rs:389 https_certificate_name_matches` | E | тот же парсер; TLS1.3 differential |
| `d2k_t13_ch_build` | 197-357 | 161 | сборка TLS1.3 ClientHello: SNI, шифры, группы, sigalgs, ALPN, key_share, padding | `r2o_tls.rs:340 r2o_tls13_client_hello` | E | построчный порт; unit `tests/r2o_tls.rs:183 приветствие_добивается_до_заданной_длины`, `:212 session_id`, `:101/115 ALPN` |
| `d2k_t13_derive_secret` | 361-366 | 6 | Derive-Secret(Transcript-Hash) | rustls key schedule | P | собственной функции нет; KAT нет |
| `d2k_t13_schedule_hs` | 368-381 | 14 | early→handshake secret, c/s hs traffic | rustls key schedule | P | собственной функции нет |
| `d2k_t13_schedule_ap` | 383-394 | 12 | master secret, c/s ap traffic | rustls key schedule | P | собственной функции нет |
| `d2k_t13_finished_mac` | 396-403 | 8 | finished_key + HMAC(transcript) | rustls | P | собственной функции нет; C-векторов в Rust нет |
| `d2k_t13_sh_version` | 407-426 | 20 | версия из ServerHello.supported_versions (downgrade-детект) | rustls (version negotiation) | P | отдельной функции нет; downgrade-ветка C не сопоставлена |
| `d2k_t13_sh_parse` | 428-475 | 48 | разбор ServerHello, проверка 0x1301 и X25519 key_share | `r2o_tls.rs:200 r2o_tls_replay_client_hello` (критерий ServerHello) | P | replay-путь покрыт `donor_and_r2o_require_server_hello_when_replaying_captured_ech`; полный разбор отдан rustls |
| `d2k_t13_flight_next` | 479-490 | 12 | итератор handshake-сообщений в полёте | `r2o_tls.rs:200` (внутренний обход) | P | отдельной публичной функции нет |
| `ech_host_ok` | 492-508 | 17 | валидация публичного имени ECH | `ech.rs:464 r2o_ech_public_name` | P | логика близкая, но C-тестов/дифференциала на границы нет |
| `d2k_ech_config_parse` | 510-567 | 58 | разбор ECHConfigList: KEM 0x20, HKDF-SHA256/AES128, public_name, mandatory | `ech.rs:364 r2o_ech_select_config` | P | Rust получает конфиг из HTTPS RR (`ech.rs:158 resolve_ech_config`), а не из wire; выбор первого валидного и лимиты не сверялись |
| `hpke_extract` | 570-581 | 12 | HPKE labeled Extract | `hpke` crate (`ech.rs:63 R2oEchHpke`) | P | собственная реализация заменена зависимостью |
| `hpke_expand` | 583-596 | 14 | HPKE labeled Expand (1 блок) | `hpke` crate | P | то же; C-векторов нет |
| `ech_hpke` | 598-619 | 22 | X25519+HKDF setup для ECH (key/nonce) | `ech.rs:63` через `hpke` | P | то же |
| `d2k_t13_ech_build` | 621-682 | 62 | внешний/внутренний ClientHello с ECH, шифрование inner, padding | `r2o_tls.rs:305 r2o_tls_ech_client_hello` | P | Rust собирает ECH через rustls (`r2o_tls.rs:274`), не повторяет байтовую раскладку C; ECH-дифференциал проверяет RX-лестницу, не CH |
| `d2k_t13_ech_accepted` | 684-701 | 18 | подтверждение ECH по accept_confirmation в ServerHello | `fetch.rs:986 connection.ech_status()` | P | проверка делегирована rustls; C-оракул на accept_confirmation не подключён |

## core/verify.c (74 функции)

Проверочный зонд D2O: TCP/TLS 1.2/1.3 + HTTP/1.x, бюджет keep-alive, Discord Gateway WebSocket, QUIC/HTTP/3. В R2O основной преемник — `r2o-controller/src/fetch.rs` (страницы, бюджеты, Gateway), `r2k-core/src/http_response.rs` (HTTP-framing), `r2o_quic_http3.rs` (QUIC/H3), `ech.rs`. Дифференциалы: `scripts/r2o-tls-verify-differential.sh` (C `verify.o` как оракул), `scripts/test-http-chunk-framing-differential.sh`, `scripts/r2o-http-search-differential.sh`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `verify_now_ms` | 52-56 | 5 | монотонное время, мс | `std::time::Instant` | P | инфраструктурный хелпер |
| `dns16` | 58-58 | 1 | big-endian u16 DNS | `u16::from_be_bytes` | P | хелпер DNS-резолва ECH |
| `ech_dns_name` | 62-88 | 27 | разбор DNS-имени с компрессией, нижний регистр, лимит 253 | `ech.rs:482 r2o_ech_dns_name` | E | построчный порт; DNS-кейсы ECH-резолва в `tests`/`donor` (см. `ech.rs` unit) |
| `d2k_ech_resolve` | 90-184 | 95 | резолв HTTPS RR (type 65) через /etc/resolv.conf, выбор ECHConfig | `ech.rs:158 resolve_ech_config`, `:182 r2o_ech_query_resolver` | P | Rust резолвит через системный resolver/HTTPS-запрос, а не UDP к nameserver; SO_MARK и разбор секций не сопоставлены дифференциалом |
| `find_hdr_end` | 193-200 | 8 | найти CRLFCRLF | `http_response.rs:340 find_crlf` / `fetch.rs:2002 r2o_gateway_header_end` | E | framing покрыт `test-http-chunk-framing-differential.sh` |
| `find_eol` | 203-208 | 6 | найти CRLF | `http_response.rs:340 find_crlf` | E | тот же дифференциал |
| `lower_ascii` | 210-212 | 3 | ASCII lower | `response.rs:508 lower_ascii` | E | используется в SAN/заголовках, differential `d2o_shared_tls_response_vectors_match` |
| `span_eq_ascii_ci` | 214-221 | 8 | регистронезависимое сравнение | `response.rs:507 https_dns_name_bytes_match` / `fetch.rs` сравнения | P | отдельного хелпера нет; логика размазана по `fetch.rs`/`response.rs` |
| `has_cf_challenge` | 227-246 | 20 | `cf-mitigated: challenge` в заголовках | `fetch.rs:1378 r2o_fetch_is_cloudflare_challenge` | E | end-to-end differential `donor_and_r2o_accept_youtube_sized_response_headers`/fetch-тесты |
| `read13` | 273-276 | 4 | адаптер чтения TLS1.3 | `fetch.rs` rustls `Stream::read` | P | адаптер C-API; в Rust чтение напрямую |
| `read12` | 278-281 | 4 | адаптер чтения TLS1.2 | `fetch.rs` rustls `Stream::read` | P | то же |
| `body_read_reason` | 298-303 | 6 | текст причины обрыва тела | `http_response.rs`/`fetch.rs` ошибки | P | текст/классификация не сверяются |
| `body_say` | 304-306 | 3 | записать причину в err | `http_response.rs` (ошибки парсера) | P | хелпер |
| `body_feed` | 308-314 | 7 | накопить префикс тела + resource-scan | `http_response.rs:55 feed`, `fetch.rs` resource scan | E | framing differential; resource-scan — `donor_and_r2o_accept_youtube_sized_response_headers` |
| `body_byte` | 317-329 | 13 | побайтовое чтение тела с дедлайном | `http_response.rs:18 HttpResponseParser` | E | `test-http-chunk-framing-differential.sh` |
| `body_exact` | 331-350 | 20 | дочитать ровно n байт тела | `http_response.rs:18` (content-length) | E | тот же дифференциал |
| `body_line` | 352-375 | 24 | CRLF-строка chunked, лимит 127 | `http_response.rs:508 read_crlf_line` | E | тот же дифференциал (line_at_limit/line_over_limit) |
| `read_http_body` | 380-445 | 66 | body по Content-Length/chunked/до EOF, trailer | `http_response.rs:18 HttpResponseParser` | E | `test-http-chunk-framing-differential.sh`, `donor_and_r2o_accept_youtube_sized_response_headers` |
| `read_status_buf` | 457-697 | 241 | разбор статуса/заголовков, Location/кодировка/Connection, запуск тела, HTTP-reply классификация | `http_response.rs:281 parse_headers` + `fetch.rs:2836 r2o_fetch_http_outcome` | P | framing и часть заголовков покрыты дифференциалом; ветки 1xx/101/дубликатов Location/Connection и `http_reply` не все сверены |
| `read_status_rd` | 699-728 | 30 | выделить буфер и вызвать `read_status_buf` | `http_response.rs` (без malloc) | P | обёртка; лимит 64 КиБ проверяется |
| `d2k_http_read_response` | 730-737 | 8 | публичный API чтения HTTP-ответа | `http_response.rs:18 HttpResponseParser`, `http_search.rs:310 read_probe_response` | P | отдельного API нет; используется в двух местах |
| `d2k_verify_probe` | 739-742 | 4 | пробa TLS1.3 по IP/SNI | `fetch.rs:844 r2o_fetch_with_phase_timeout` | P | обёртка над `d2k_verify_probe_on`; end-to-end differential |
| `write13` | 750-753 | 4 | адаптер записи TLS1.3 | `fetch.rs` rustls `Stream::write_all` | P | адаптер |
| `write12` | 755-758 | 4 | адаптер записи TLS1.2 | `fetch.rs` rustls | P | адаптер |
| `redirect_path` | 762-795 | 34 | same-origin https-redirect → путь, фильтр управляющих | `fetch.rs:2761 r2o_fetch_same_origin_redirect` | E | differential `donor_and_r2o_send_the_same_default_verification_request` (redirect-кейсы) |
| `https_redirect_response` | 799-814 | 16 | внешний https-redirect 301/302/303/307/308 | `fetch.rs:2811 r2o_fetch_external_https_redirect` | E | тот же differential |
| `d2k_verify_budget_set` | 822-822 | 1 | глобальный бюджет пакетов | `process-wide` нет; бюджет в `FetchOptions.budget_packets` | P | в Rust параметр, а не глобал; CLI-совместимость не проверялась |
| `d2k_verify_budget_get` | 823-823 | 1 | чтение бюджета | `FetchOptions.budget_packets` | P | то же |
| `d2k_verify_tcp_timestamps_set` | 826-828 | 3 | профиль TCP timestamps (-1/0/1) | `FetchOptions`/raw probe `offer_ts` | P | глобального переключателя нет; raw-профиль (`raw_probe.rs:673`) иной по смыслу |
| `d2k_verify_tcp_timestamps_get` | 829-829 | 1 | чтение профиля | нет | N | прямого аналога глобального профиля нет |
| `d2k_verify_quic_form_set` | 837-840 | 4 | глобальная форма QUIC Initial | `FetchOptions`/`r2o_quic_http3` параметры формы | P | глобальной формы нет, передаётся явно |
| `d2k_verify_tcp_data_packets` | 850-865 | 16 | TCP_INFO data_segs in/out | `fetch.rs:2604 r2o_tcp_counters` | P | поля `data_packets` есть; ioctl/структура не сверены |
| `budget_say` | 877-883 | 7 | заполнить budget/note результата | `FetchResult` поля `packet_budget`/`body_*` | P | формат текста не сверяется |
| `gateway_header_end` | 885-890 | 6 | CRLFCRLF для Gateway | `fetch.rs:2002 r2o_gateway_header_end` | E | differential `donor_and_r2o_validate_the_discord_gateway_websocket_like_d2o` |
| `gateway_header_value` | 892-903 | 12 | значение заголовка по имени | `fetch.rs:2006 r2o_gateway_header_value` | E | тот же differential |
| `gateway_connection_upgrade` | 905-915 | 11 | есть ли токен Upgrade в Connection | `fetch.rs:2014 r2o_gateway_connection_upgrade` | E | тот же differential |
| `gateway_json_hello` | 917-974 | 58 | найти top-level `op` в JSON Hello, вернуть op=10 | `fetch.rs:2057 r2o_gateway_json_op` | E | тот же differential (op/не-op, вложенность) |
| `gateway_fill` | 976-998 | 23 | дочитать WebSocket-ответ до need с дедлайном | `fetch.rs:2147 r2o_gateway_fill` | E | тот же differential |
| `request_gateway_websocket` | 1000-1123 | 124 | GET Upgrade gateway.discord.gg, проверка 101/Accept, первый frame op=10 | `fetch.rs:2187 r2o_gateway_websocket_exchange` | E | `donor_and_r2o_validate_the_discord_gateway_websocket_like_d2o` |
| `read_eof` | 1132-1139 | 8 | обёртка чтения с фиксацией EOF/ошибки | `fetch.rs:2650 r2o_measure_http_packet_budget` (внутренний цикл) | P | отдельной структуры нет |
| `budget_tcp` | 1146-1213 | 68 | keep-alive бюджет: повторные GET до need пакетов, классификация CUT/NOT_APPLICABLE | `fetch.rs:2650 r2o_measure_http_packet_budget` | P | end-to-end бюджет не сверялся с C-оракулом |
| `fd_peer_spoke` | 1217-1222 | 6 | poll: говорил ли peer | `fetch.rs` (проверка читаемости сокета) | P | отдельной функции нет |
| `fd_packets` | 1223-1223 | 1 | счётчик пакетов через hook | `fetch.rs:2604 r2o_tcp_counters` | P | hook `d2k_verify_packets_hook` в Rust не портирован |
| `request_complete_page` | 1238-1245 | 8 | GET страницы без бюджета | `fetch.rs:804 r2o_fetch_with_encoding` | P | покрыто end-to-end differential |
| `request_page_budget` | 1247-1343 | 97 | GET с редиректами (3), gzip/identity, Gateway-ветка, бюджет | `fetch.rs:863 r2o_fetch_with_roots_and_encoding_detailed_with_timeouts` | E | differential `donor_and_r2o_send_the_same_default_verification_request` (точные байты запроса) |
| `verify_contact` | 1349-1363 | 15 | TCP-коннект с mark/TCP timestamp профилем | `fetch.rs:3017 connect_target`, `:3029 connect_marked` | P | mark поддержан; профиль timestamps — нет |
| `d2k_props_contact_on_family_tcp_profile` | 1360-1361 | 2 | ложное срабатывание парсера: хвост вызова внутри `verify_contact`, не определение | `fetch.rs:3017 connect_target` (владелец `verify_contact`) | ? | строки 1360-1361 — продолжение `return d2k_props_contact_on_family_tcp_profile(...)`; собственной функции нет |
| `verify_probe13_internal` | 1365-1442 | 78 | полный зонд TLS1.3: контакт, handshake, страница, бюджет, счётчики | `fetch.rs:863 r2o_fetch_with_roots_and_encoding_detailed_with_timeouts` | E | `r2o-tls-verify-differential.sh` (уровень, TLS, name_ok, complete, байты) |
| `verify_probe13_on` | 1444-1449 | 6 | обёртка TLS1.3 без ECH | `fetch.rs:844 r2o_fetch_with_phase_timeout` | E | тот же differential |
| `ech_http_denial` | 1451-1460 | 10 | HTTP 429 при ECH → CHALLENGE, не усиливать отказ | `main.rs:14528`/`:27016` (классификация 429) | E | unit `ECH witness 429 rate limits must match the donor challenge classification` |
| `d2k_verify_probe_ech_on` | 1462-1476 | 15 | ECH-зонд с готовым конфигом | `fetch.rs:738 r2o_fetch_ech_connected_stream` | P | ECH-дифференциал покрывает replay/RX, не живой зонд |
| `d2k_verify_probe_ech_origin_on` | 1478-1492 | 15 | резолв ECH по origin, сверка outer_name, зонд | `ech.rs:158 resolve_ech_config` + `fetch.rs:738` | P | сверка public_name и DNS-путь не сопоставлены |
| `d2k_verify_replay_on` | 1499-1562 | 64 | повтор снятого ClientHello, классификация ServerHello/alert/тишины | `fetch.rs:331 r2o_verify_tls_replayed_client_hello` | E | differential `donor_and_r2o_require_server_hello_when_replaying_captured_ech`, `...absolute_deadline_to_replayed_client_hello` |
| `d2k_verify_probe_on` | 1564-1568 | 5 | пробa TLS1.3, encoding=2 | `fetch.rs:844 r2o_fetch_with_phase_timeout` | E | `donor_and_r2o_send_the_same_default_verification_request` |
| `d2k_verify_probe_alpn_on` | 1578-1625 | 48 | TLS-проба с ALPN клиента, без прикладного уровня | `fetch.rs:225 r2o_verify_tls_connected_stream_with_alpn` | E | `donor_and_r2o_preserve_captured_mqtt_and_absent_alpn` |
| `verify_probe12_internal` | 1636-1701 | 66 | полный зонд TLS1.2 | `fetch.rs` с `tls12=true` | E | differential `donor_and_r2o_reject_short_tls12_server_finished` + `r2o-tls-verify-differential.sh` |
| `d2k_verify_probe12_on` | 1703-1708 | 6 | обёртка TLS1.2 | `fetch.rs` `tls12=true` | E | тот же differential |
| `d2k_verify_probe_identity_on` | 1710-1715 | 6 | identity-кодировка, TLS1.2/1.3 | `fetch.rs:434 r2o_d2o_verification_encoding` | P | выбор кодировки есть; отдельного differential на identity нет |
| `d2k_verify_probe_gzip_on` | 1717-1722 | 6 | gzip-кодировка, TLS1.2/1.3 | `fetch.rs:434` + `R2oFetchEncoding::Gzip` | P | то же |
| `d2k_verify_probe_baseline` | 1724-1742 | 19 | базовая проба с валидацией encoding/mark | `fetch.rs:844` + `FetchOptions` | P | композиция параметров, покрыта косвенно |
| `d2k_verify_probe_path_on` | 1744-1757 | 14 | проба с путём и encoding 0..2 | `FetchOptions.path` + `fetch.rs:804` | P | путь/кодировка покрыты page-differential |
| `d2k_verify_close` | 1759-1764 | 6 | закрыть fd результата | RAII `Drop`/`OwnedFd` | P | отдельной функции нет |
| `d2k_verify_probe_quic` | 1768-1771 | 4 | QUIC-проба по умолчанию | `fetch.rs:514 r2o_fetch_quic` | P | QUIC-дифференциалы отдельные (`r2o-quic-*`) |
| `quic_app_silent` | 1780-1791 | 12 | текст причины «handshake ok, app молчит» | `r2o_quic_http3.rs:217 R2oQuicHttp3Result.reason` | P | формат текста не сверяется |
| `h3_read_headers` | 1799-1811 | 13 | читать H3-поток до разбора статуса/лимита | `r2k-core/src/h3.rs:317 status` + `r2o_quic_http3.rs:690 get` | P | разбор статуса покрыт `r2k-core` тестами h3; цикл чтения — нет |
| `quic_recv_chunk` | 1816-1821 | 6 | адаптер приёма QUIC-потока | `r2o_quic_http3.rs` recv | P | адаптер |
| `budget_quic` | 1836-1950 | 115 | бюджет датаграмм HTTP/3, CUT/NOT_APPLICABLE | `r2o_quic_http3.rs:543 R2oQuicHttp3Budget`, `:600 R2oQuicHttp3Stall` | P | реализация есть, differential бюджета не найден |
| `qb_request` | 1953-1959 | 7 | отправить H3-запрос в бюджетном цикле | `r2o_quic_http3.rs` `send_request` | P | адаптер |
| `qb_recv` | 1960-1963 | 4 | приём H3-потока | `r2o_quic_http3.rs` recv | P | адаптер |
| `qb_progress` | 1964-1966 | 3 | прогресс app-байт | `r2o_quic_http3.rs:278 app_bytes_load` | P | адаптер |
| `qb_packets` | 1967-1971 | 5 | датаграммы tx+rx | `r2o_quic_http3.rs:1272 datagrams` | P | адаптер |
| `d2k_verify_probe_quic_on` | 1975-1979 | 5 | QUIC-проба с путём `/` | `fetch.rs:514 r2o_fetch_quic` | P | обёртка |
| `d2k_verify_probe_quic_path_on` | 1983-1989 | 7 | QUIC-проба с путём, mark=0 | `fetch.rs:514`, `r2o_quic_http3_get` | P | обёртка |
| `d2k_verify_probe_quic_path_mark_on` | 1991-2156 | 166 | полный QUIC/H3-зонд: connect, control-поток, запрос, статус, тело, бюджет, 451 | `r2o_quic_http3.rs:702 get_with_wire_len`, `:725 measure` | P | 451/дедлайны/бюджет не сверялись единым differential; покрыто частями `r2o_quic_http3` тестов |

## core/verify_quic_replay.c (2 функции)

Повтор снятой пачки QUIC Initial с новым DCID и проверка ответа. Порт: `r2o-controller/src/quic_replay.rs` (`QuicReplayProbe::prepare`, reseal снимка, `r2k_quic_snapshot_verify_bound_response`) + `r2k-core/src/quic_snapshot.rs`. Тесты: `r2k-core/tests/quic_snapshot.rs`, `quic.rs` (verify/retry), контроллерные snapshot-тесты.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `replay_now_ms` | 23-27 | 5 | монотонное время, мс | `Instant` | P | инфраструктурный хелпер |
| `d2k_verify_quic_replay_on` | 29-127 | 99 | разобрать снимок, перешифровать DCID, отправить все датаграммы, ждать связанный ответ, вернуть уровень/replay_proof | `quic_replay.rs:647 QuicReplayProbe`, `quic_snapshot.rs:79 reseal`, `:116 verify_bound_response` | P | функции-аналоги есть и покрыты unit; отдельного C/Rust differential именно для verify-quic-replay нет |

## core/httpsprobe.c (22 функции)

Асинхронный HTTPS-зонд (TCP 443 → first flight → TLS1.3/1.2) и кэш состояний `d2k-https`. В R2O: `r2o-controller/src/https_probe.rs` (воркер, кэш, save/load), `response.rs` (классификация и TLS-проба). Дифференциал: `scripts/test-controller-httpsprobe-differential.sh` (C `httpsprobe.o` против `examples/tg_cl13_httpsprobe_trace.rs`, кэш/состояния/загрузка).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_https_classify` | 32-40 | 9 | состояние HTTPS по connect/TLS/имени | `response.rs:90 classify_https_probe` | E | differential httpsprobe + unit `https_probe.rs:507 classify_matches_d2o_https_state_machine` |
| `d2k_https_upgrade` | 42-44 | 3 | нужно ли перепроверять состояние (served/tls-blocked) | `response.rs:149 should_redirect` | E | differential httpsprobe (набор состояний) |
| `d2k_https_ttl` | 46-55 | 10 | TTL кэша по состоянию (6ч/1ч/30м/2м) | `response.rs:140 ttl_seconds` | E | differential httpsprobe |
| `d2k_https_state_name` | 57-67 | 11 | имя состояния для файла | `response.rs:117 stored_name` | E | differential httpsprobe (state-names, unknown/probing) |
| `mono_ms` | 69-73 | 5 | монотонное время, мс | `std::time::Instant` | P | инфраструктурный хелпер |
| `https_connect` | 77-145 | 69 | nonblocking TCP 443 с SO_MARK и таймаутом, коды refused/no-answer | `response.rs:289 probe_socket`, `:254 connect_until` | P | логика близкая; live-дифференциала с refused/EINTR нет |
| `https_tls` | 148-165 | 18 | TLS1.3/1.2 handshake и peer_name | `response.rs:373 https_connection` | P | live-путь; покрыт `tests/response.rs` через локальный сервер, не C-оракул |
| `first_flight` | 171-201 | 31 | послать modern ClientHello, проверить первый TLS-байт | `response.rs:572 receives_tls_record`, `hello.rs:593 modern_client_hello` | P | ClientHello покрыт ClientHello-дифференциалом; сам first-flight — unit `https_probe_does_not_accept_a_plain_http_listener` |
| `d2k_https_probe_real` | 203-243 | 41 | полный зонд: connect+first flight+TLS1.3→1.2, дедлайн | `response.rs:606 probe_https_state` | P | unit `tests/response.rs:52-93`; C-дифференциала live-пробы нет |
| `host_ok` | 274-283 | 10 | валидация host (len≤253, [A-Za-z0-9.-]) | `https_probe.rs:86 cache_host_ok` | E | differential httpsprobe (bad-host, uppercase, dots) |
| `cache_find` | 285-290 | 6 | поиск записи кэша без учёта регистра | `https_probe.rs:94 cache_find` | E | differential httpsprobe |
| `cache_put` | 292-312 | 21 | вставка/вытеснение записи (не трогать активный probing) | `https_probe.rs:279 insert_cache` | E | differential httpsprobe (capacity 130, duplicates) |
| `worker` | 314-349 | 36 | поток: очередь job → probe → done + wake pipe | `https_probe.rs:130 impl HttpsProbeWorker` | P | воркер есть; живой пробинг и `lost` не сверялись |
| `d2k_httpsprobe_new` | 351-375 | 25 | создать кэш, pipe, поток | `https_probe.rs:131 new` | P | Rust использует канал/поток; ошибки создания pipe не сопоставлены |
| `d2k_httpsprobe_free` | 377-391 | 15 | остановить поток, закрыть fd, освободить | `https_probe.rs:464 impl Drop` | P | RAII; порядок остановки не сверялся |
| `d2k_httpsprobe_wake_fd` | 393-395 | 3 | fd для poll() | нет (Rust — канал/`try_result`) | P | механизм заменён; fd-контракт не нужен |
| `d2k_httpsprobe_portal` | 397-428 | 32 | по portal-событию: вернуть TTL/поставить job/дедуп | `https_probe.rs:189 submit`, `main.rs` portal-gating | P | unit `only_unowned_http_portal_responses_start_https_probe`; C/Rust differential на очередь нет |
| `d2k_httpsprobe_done` | 430-449 | 20 | забрать результаты, обновить кэш, разбудить | `https_probe.rs:236 try_result` | P | семантика пачки/потерь не сверялась |
| `d2k_httpsprobe_state` | 451-458 | 8 | состояние из кэша с учётом TTL | `https_probe.rs:226 cached_state` | E | differential httpsprobe + unit `cached_state_and_pending_lookup_follow_host_and_expiry` |
| `d2k_httpsprobe_lost` | 460-466 | 7 | счётчик потерянных результатов | нет | N | в `https_probe.rs` счётчика нет |
| `d2k_httpsprobe_save` | 476-505 | 30 | атомарная запись `d2k-https 2`, fsync+rename | `https_probe.rs:399 save_cache` | E | differential httpsprobe + unit round-trip |
| `d2k_httpsprobe_load` | 507-564 | 58 | разбор `d2k-https 1/2`, TTL-клампы, push upgrade-состояний | `https_probe.rs:320 load_cache`, `:388 load_verified` | E | differential httpsprobe (16+ кейсов: bad-host, non-utf8, duplicates, capacity) |

## core/httpup_logic.c (15 функций)

Логика HTTP-upgrade/порталов: безопасный разбор запроса, распознавание провайдерского портала, ответ 307. Перенесена почти построчно в `crates/r2k-core/src/httpup.rs` и используется контроллером/датапасом. Векторы — `crates/r2k-core/tests/httpup.rs`; косвенно участвует в `scripts/r2o-http-search-differential.sh` (линкуется `httpup_logic.o`).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `ascii_alnum` | 16-19 | 4 | ASCII-буква/цифра | `r2k-core/src/httpup.rs:390 valid_dns_host` (встроено) | E | хелпер; владелец `dns_host` → `valid_dns_host`, тесты `httpup.rs:78,108` |
| `dns_host` | 21-35 | 15 | валидация DNS-имени (метки ≤63, ≤253) | `httpup.rs:390 valid_dns_host` | E | `tests/httpup.rs:108 rejects_ambiguous_or_malformed...` |
| `host_equal` | 37-44 | 8 | сравнение хостов без регистра и конечной точки | `httpup.rs:468 same_host` | E | `tests/httpup.rs:78 распознаёт_порталы_операторов...`, `:69` |
| `known_portal_host` | 46-51 | 6 | входит ли хост в список 6 порталов | `httpup.rs:492 known_portal_host` | E | `tests/httpup.rs:78` |
| `find_crlf` | 53-58 | 6 | найти CRLF | `httpup.rs:382 find_crlf` | E | хелпер; владелец `parse_request`, тесты `:11,108` |
| `parse_request` | 60-130 | 71 | GET/HEAD без тела, HTTP/1.0/1.1, Host/Content-Length/TE, порт :80 | `httpup.rs:220 parse_request` | E | `tests/httpup.rs:11 accepts_only_safe_bodyless...`, `:108 rejects_ambiguous...` |
| `d2k_httpup_request_safe` | 132-135 | 4 | предикат безопасного запроса | `httpup.rs:164 request_safe` | E | `tests/httpup.rs:11` |
| `build_redirect` | 137-149 | 13 | собрать точный 307 с Location/Cache-Control/X-D2K | `httpup.rs:504 build_redirect` | E | `tests/httpup.rs:126 builds_the_exact_https_redirect...` |
| `portal_marker` | 151-170 | 20 | маркеры порталов в метках хоста | `httpup.rs:474 portal_marker` | E | `tests/httpup.rs:78` |
| `redirect_location_host` | 172-190 | 19 | выделить host из Location http/https | `httpup.rs:452 parse_location_host` | E | `tests/httpup.rs:69` |
| `portal_answer` | 193-225 | 33 | 30x+Location на другой узел, портал/маркер | `httpup.rs:191 portal_response` (внутри) | E | `tests/httpup.rs:49,57` |
| `d2k_httpup_portal_response` | 227-238 | 12 | запрос+upstream → 307 provider-portal | `httpup.rs:191 portal_response` | E | `tests/httpup.rs:49 upgrades_a_safe_request_only_after...` |
| `d2k_httpup_request_target` | 240-251 | 12 | host и origin-target запроса | `httpup.rs:169 request_target` | E | `tests/httpup.rs:31 extracts_normalized_host_and_origin_target` |
| `d2k_httpup_portal_location` | 253-262 | 10 | host портала из upstream-ответа | `httpup.rs:201 portal_location` | E | `tests/httpup.rs:69` |
| `d2k_httpup_redirect_https` | 264-277 | 14 | готовый 307 https-редирект | `httpup.rs:208 redirect_https` | E | `tests/httpup.rs:126` |

## core/httpsearch.c (66 функций)

Поиск HTTP-обхода: база → свои планы → split/checksum/продукт → fallback, с подтверждением APPLIED и живой привязкой. В R2O: `r2o-controller/src/http_search.rs` (judge, кандидаты, id, чтение ответа) и `main.rs` (`HttpSearchRecordCache:4464`, `run_http_search_task:22901`, `begin_http_search:19542`, `http_baseline_failure_action:22853`). Дифференциалы: `scripts/r2o-http-search-differential.sh` (набор C-фикстур `d2o_http_*_differential.c` против Rust-тестов), `tests/http_search.rs`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `mono_ms` | 37-41 | 5 | монотонное время, мс | `std::time::Instant` | P | инфраструктурный хелпер |
| `d2k_hs_answer_name` | 43-57 | 15 | русское имя ответа | `http_search.rs:17 enum Answer` (без функции имени) | P | текст причины формируется в `main.rs`; дословного соответствия нет |
| `d2k_hs_judge` | 61-95 | 35 | классификация HTTP-ответа: garbage/injected/decoy/early/real | `http_search.rs:850 judge` | E | differential `scripts/r2o-http-search-differential.sh` + inline `mod d2o_http_judge_differential` |
| `hs_path_ok` | 99-107 | 7 | допустимый путь для повтора | `http_search.rs:300 repeatable_path` | E | test `main.rs:28365 r2o_http_search_сохраняет_путь_повторяемого_запроса` |
| `hs_read` | 110-130 | 21 | чтение сокета с таймаутом, временем первого байта и префиксом | `http_search.rs:310 read_probe_response` | P | тайминги/префикс не сопоставлены побайтово |
| `d2k_hs_probe_run` | 132-246 | 115 | один зонд: connect, тайминги, 2 GET, classify, keep-alive | `main.rs:23385 run_http_baseline`, `http_search.rs:310 read_probe_response` | E | test `http_baseline_replays_donor_keepalive_paths_on_one_stream` + C-фикстура baseline |
| `d2k_hs_candidate_count` | 253-253 | 1 | число встроенных кандидатов | `http_search.rs:627 candidate_keys` | E | test `tests/http_search.rs:196 exposes_the_same_ordered_http_search_questions` |
| `d2k_hs_candidate_key` | 254-254 | 1 | ключ кандидата по индексу | `http_search.rs:627 candidate_keys` | E | тот же test |
| `poison_key_spec` | 258-287 | 30 | разбор `fake:` спецификации (ttl/badsum/seqshift, порядок) | `http_search.rs:796 poison_key_spec` | E | test `tests/http_search.rs:268 accepts_only_measured_poison_keys...` |
| `known_key` | 289-294 | 6 | известный ключ плана/кандидата | `http_search.rs:631 candidate_key_from_plan_text` | E | test `:210 recovers_only_exact_supported_keys_from_saved_plan_text` |
| `d2k_hs_candidate_text` | 296-324 | 29 | текст плана по ключу (fake/split/order) | `http_search.rs:686 candidate_text` | E | tests `:227,235,243,260` (точные тексты split/disorder/fake) |
| `stable_id` | 327-332 | 6 | FNV-1a id плана `d2k-http:` | `http_search.rs:780 stable_id` | E | test `:279 derives_the_r2o_stable_id_for_a_candidate` |
| `fresh_id` | 334-352 | 19 | случайный id с fallback на PRNG | `rand`/`getrandom` в `main.rs` | P | отдельной функции и fallback-ветки нет |
| `say` | 442-450 | 9 | лог через ops.say | `main.rs` logging/diagnostics | P | формат логов не сверяется |
| `host_ok` | 452-466 | 15 | валидация host, запрет числового TLD | `main.rs`/`http_search.rs` валидация имени | P | отдельного предиката с тем же правилом нет |
| `rec_find` | 468-475 | 8 | поиск записи host+family | `main.rs:4464 HttpSearchRecordCache` (HashMap) | P | структура заменена HashMap |
| `rec_get` | 477-496 | 20 | создание записи с лимитами памяти/учётом отказов | `main.rs:4464 HttpSearchRecordCache` | P | лимиты `D2K_HS_RECORD_MAX_BYTES` не сопоставлены |
| `same_program` | 500-508 | 9 | эквивалентность планов через TLV | `http_search.rs:775 candidate_program` | P | сравнение программ есть, TLV-путь иной; test только на алиасы |
| `failed_live` | 510-519 | 10 | поиск живого отказа по ключу/адресу | `main.rs` HttpSearchRecord (failures) | P | структура и семантика `evidence_lost` не сверены |
| `remember_live_failure` | 520-550 | 31 | учёт живого отказа: addr/binding/execution/request_ms, лимиты байт | нет | **N** | `HttpSearchRecord` (`main.rs:4468-4472`) содержит только `cut/repeat_path/repro_gap`; полей `failures/addr/binding/execution/request_ms` и счётчиков нет. `HttpLiveFailures` строится из `failed_http_programs` (выключенные привязки каталога), а не из живых отказов; `r2o_catalog_mark_flow_unfit` ставит только `recheck_since`. |
| `d2k_httpsearch_test_add_failures` | 553-566 | 14 | тестовый хук добавления отказов | нет | N | существует только под `D2K_HS_TESTING` |
| `d2k_httpsearch_test_add_records` | 567-576 | 10 | тестовый хук добавления записей | нет | N | только под `D2K_HS_TESTING` |
| `d2k_httpsearch_measured_poison` | 579-606 | 28 | регистрация измеренной poison-спеки | `http_search.rs:719 measured_poison_keys` | E | test `candidate_tests::measured_poison_requires_tls_and_an_actual_fake_reference` |
| `d2k_hs_plan_poisons` | 608-642 | 35 | poison-спеки, на которые ссылается fake в TLS-плане | `http_search.rs:719 measured_poison_keys` | E | тот же test (TLS/HTTP, ссылка/без ссылки) |
| `d2k_httpsearch_new` | 644-650 | 7 | создать состояние поиска | `main.rs:4464 HttpSearchRecordCache` | P | структура иная (per-task) |
| `drop_socket` | 652-657 | 6 | закрыть сокет через ops | RAII `TcpStream`/`OwnedFd` | P | отдельной функции нет |
| `drop_probe` | 659-664 | 6 | снять пробный план датапата | `main.rs` revoke/complete | P | хуки `del_probe` заменены командами контроллера |
| `d2k_httpsearch_free` | 666-674 | 9 | освободить записи/очередь | RAII `Drop` | P | отдельной функции нет |
| `d2k_httpsearch_busy` | 676-678 | 3 | есть ли активная задача | `main.rs` состояние задачи | P | булево состояние размазано |
| `d2k_httpsearch_plan_of` | 680-683 | 4 | ключ плана для host+family | `HttpSearchRecordCache` lookup | P | отдельной функции нет |
| `d2k_httpsearch_diagnostic_counts` | 687-706 | 20 | счётчики записей/очереди/отказов/лимитов | `diagnostics.rs:449-481` поля, `main.rs:16751` заполнение | P | часть счётчиков (`limit_hits`) не выставляется |
| `d2k_httpsearch_diagnostics` | 707-709 | 3 | подключить observer диагностики | `diagnostics.rs` observer | P | API иное |
| `diagnostic_end` | 710-721 | 12 | событие завершения (id/target/outcome/elapsed) | `main.rs:4864 r2o_http_search_diagnostic_event` | P | есть differential `d2o_http_diagnostic_differential.c`, но он не в `r2o-http-search-differential.sh`; прогон не подтверждён |
| `finish` | 722-728 | 7 | завершить: diagnostic_end, закрыть сокет, PH_IDLE | `main.rs:19570 complete_http_search` | P | жизненный цикл переписан на задачи |
| `open_job` | 730-748 | 19 | открыть сокет через ops, заполнить job | `main.rs` begin/run task | P | хуки портов заменены сокетами |
| `revoke_owned` | 752-757 | 6 | снять привязку плана | `main.rs:21622 revoke_http_search_owner` | E | test `http_owned_plan_rollback_matches_d2o` |
| `all_failed` | 759-802 | 44 | исходы «не измерено/конфликт/нестабильно/не найден» | `main.rs` completion disposition | E | test `http_no_executed_trial_matches_d2o` + C-фикстура no-executed |
| `install` | 804-816 | 13 | поставить план датапату с токеном | `main.rs` install/set_plan | E | test `confirmed_http_candidate_is_durable_before_catalog_flush_interval` |
| `d2k_httpsearch_install_ack` | 818-841 | 24 | подтверждение установки и привязки | `main.rs` ack handling | E | test `http_owned_plan_rollback_matches_d2o` |
| `confirmed` | 843-889 | 47 | подтверждённый кандидат: конфликты, install, запись rec | `http_search.rs:36 confirmed_applied`, `main.rs` | P | логика разделена; полного differential на конфликты нет |
| `trial_executed` | 894-900 | 7 | APPLIED на все запросы, порт/адрес совпали | `main.rs:http_applied_collection...` | E | test `http_applied_collection_requires_each_unique_execution_within_donor_window` |
| `judge_trial` | 902-953 | 52 | суд кандидата по REAL/CUT/INJECTED | `http_search.rs:850 judge` + `main.rs` | P | решение по кандидату в `main.rs`; differential только на judge/baseline |
| `next_candidate` | 955-1003 | 49 | переход к следующему кандидату/вопросу, запуск зонда | `main.rs:22901 run_http_search_task` | P | порядок вопросов покрыт unit, переходы — нет |
| `add_cand` | 1005-1010 | 6 | добавить кандидата без дублей | `main.rs:4638 http_search_candidates` | P | Vec без дублей, иная структура |
| `build_cands` | 1012-1039 | 28 | свои подтверждённые планы по seq | `main.rs:4638 http_search_candidates` | P | приоритет seq не сверен |
| `build_fallback` | 1041-1052 | 12 | split/disorder + measured/fake | `main.rs:4638`, `http_search.rs` | P | состав fallback покрыт unit кандидатов |
| `start` | 1054-1091 | 38 | старт поиска: контекст, job, PH_BASE | `main.rs:19542 begin_http_search` | P | стадии/дедлайны иные |
| `start_next` | 1093-1101 | 9 | взять следующую заявку из очереди | `main.rs` worker loop | P | очередь на канале |
| `live_owner` | 1103-1111 | 9 | найти запись-владельца живого запроса | `main.rs` owned_binding | P | структура иная |
| `d2k_httpsearch_bound_failure` | 1113-1131 | 19 | живой отказ под планом: отзыв, repro_gap, перезапуск | `main.rs` failure handling | P | покрыто косвенно rollback-тестом |
| `d2k_httpsearch_control` | 1133-1163 | 31 | диспетчер APPLIED/ACK/HTTP_RESPONSE/PORTAL | `main.rs` service_http_search_command | P | события обрабатываются в диспетчере |
| `d2k_httpsearch_cut` | 1170-1188 | 19 | запомнить обрыв тела и путь повтора | `main.rs` record cut | E | test `r2o_http_cut_context_survives_a_later_portal` |
| `d2k_httpsearch_portal` | 1190-1227 | 38 | старт или постановка в очередь по portal-событию | `main.rs:19583 enqueue_http_search` | E | test `http_search_queue_matches_the_unbounded_donor_queue` |
| `d2k_httpsearch_ack` | 1229-1260 | 32 | ACK пробного плана: отказ/запуск | `main.rs` ack handling | E | test `http_owned_plan_rollback_matches_d2o` |
| `d2k_httpsearch_applied` | 1262-1287 | 26 | сбор APPLIED: до 2 уникальных execution, binding/порт | `main.rs` applied collection | E | test `http_applied_collection_requires_each_unique_execution_within_donor_window` |
| `d2k_httpsearch_result` | 1289-1395 | 107 | результат зонда: база/кандидат, повторы, переход в PH_APPLIED | `main.rs:22853 http_baseline_failure_action`, `:23385 run_http_baseline` | E | differential `d2o_response_state_differential_preserves_portal_and_partial_head_outcomes`, baseline test |
| `d2k_httpsearch_tick` | 1397-1427 | 31 | таймауты ACK/APPLIED/BASE/RUN | `main.rs` deadline handling | P | таймеры на task/timeout, не tick |
| `d2k_httpsearch_push_all` | 1429-1442 | 14 | переустановить все сохранённые планы | `main.rs` restore/install loop | P | покрыто durable-тестом частично |
| `d2k_httpsearch_save` | 1444-1471 | 28 | атомарная запись `d2k-http-plans 1` | `main.rs`/`catalog.rs` persist | E | test `confirmed_http_candidate_is_durable_before_catalog_flush_interval` |
| `d2k_httpsearch_load` | 1473-1512 | 40 | разбор файла планов, known_key, install | `catalog.rs:391 load` (HTTP-планы) | P | отдельного загрузчика `d2k-http-plans` с теми же правилами не найдено |
| `runner_main` | 1525-1537 | 13 | поток однократного зонда | `std::thread`/async task | P | отдельной структуры нет |
| `d2k_hs_runner_new` | 1539-1553 | 15 | создать runner с pipe/cond | `std::thread` + канал | P | RAII |
| `d2k_hs_runner_free` | 1555-1562 | 8 | join/close/destroy | `JoinHandle`/Drop | P | RAII |
| `d2k_hs_runner_wake_fd` | 1564-1564 | 1 | fd пробуждения | нет (канал) | P | механизм заменён |
| `d2k_hs_runner_start` | 1566-1579 | 14 | запустить зонд, запрет параллельного | `main.rs` worker | P | планировка иная |
| `d2k_hs_runner_done` | 1581-1591 | 11 | забрать результат, join | `JoinHandle::join`/канал | P | RAII |

## core/h3.c (9 функций)

Кодирование/разбор HTTP/3: control-поток, QPACK-подобные префиксные целые, HEADERS-запрос, статус из HEADERS (static index + Huffman). Порт: `crates/r2k-core/src/h3.rs` (построчный). Дифференциал: `scripts/test-controller-h3-httpup-differential.sh` (C `h3.c` против `examples/tg_cl14_h3_httpup_trace.rs`), плюс unit-тесты в `h3.rs`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_h3_control` | 19-26 | 8 | control-поток: stream type 0 + пустой SETTINGS | `h3.rs:12 control`, `:390 frame_type_data` | E | differential h3 + unit `control_stream_is_type_plus_empty_settings` |
| `prefix_int` | 30-49 | 20 | QPACK/HTTP3 prefix integer write | `h3.rs:65 prefix_int` | E | хелпер; владелец `d2k_h3_request`, differential h3 |
| `prefix_int_read` | 51-71 | 21 | prefix integer read с защитой от переполнения | `h3.rs:92 prefix_int_read` | E | хелпер; владелец `d2k_h3_status`, differential h3 |
| `d2k_h3_request` | 73-121 | 49 | HEADERS: :method GET, :scheme https, :authority, :path | `h3.rs:338 request` | E | differential `test-controller-h3-httpup-differential.sh` + unit `request_root_matches_rfc_static_indices`, `request_non_root_...` |
| `huff_status` | 126-144 | 19 | декод 3 цифр статуса из Huffman-литерала | `h3.rs:122 huff_status` | E | differential h3 (`h3status` кейсы) + unit `status_reads_static_index_and_huffman_literal` |
| `static_status` | 148-166 | 19 | static table QPACK: индексы статусов | `h3.rs:165 static_status` | E | differential h3 (static25 и др.) |
| `name_is_status` | 171-174 | 4 | является ли static name `:status` | `h3.rs:185 name_is_status` | E | владелец `decode_section`; differential h3 |
| `decode_section` | 176-260 | 85 | разбор header-секции: static/literal/post-base, Huffman | `h3.rs:189 decode_section` | E | differential h3 + unit `status_handles_literal_name_and_post_base_forms`, `status_skips_unknown_frame...` |
| `d2k_h3_status` | 262-280 | 19 | статус из потока HEADERS | `h3.rs:317 status` | E | differential h3 |

## core/quicwire.c (28 функций)

QUIC-каркас: varint, long header, packet number, Initial keys, AEAD seal/open, Retry integrity, range-набор. В R2O — приватные функции `crates/r2k-core/src/quic.rs` (`derive_initial_keys`, `seal_initial`, `open_initial`, `retry_integrity_valid`, `decode_packet_number`, `read/write_varint`). Доказательства: RFC-векторы 9001/9369 в unit-тестах `quic.rs`, `tests/quic_snapshot.rs`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `salt_for` | 41-43 | 3 | соль Initial для v1/v2 | `quic.rs:849 derive_initial_keys` | E | helper; владелец `d2k_qw_initial_secret`, RFC 9001/9369 тесты |
| `label_key` | 44-46 | 3 | HKDF-label key (v1/v2) | `quic.rs:893 expand_label` (вызовы) | E | helper; владелец `d2k_qw_keys_from_secret`, RFC-тесты |
| `label_iv` | 47-49 | 3 | HKDF-label iv | `quic.rs:893 expand_label` | E | то же |
| `label_hp` | 50-52 | 3 | HKDF-label header protection | `quic.rs:893 expand_label` | E | то же |
| `d2k_qw_varint_read` | 56-67 | 12 | QUIC varint read | `quic.rs:1057 read_varint` | E | RFC 9001 Initial разбирается тестом `splits_rfc_9001_initial...` |
| `d2k_qw_varint_len` | 69-75 | 7 | длина varint по значению | `quic.rs:1070 write_varint` (выбор ширины) | E | helper; владелец `d2k_qw_varint_write_w`, тест `создаёт_аутентифицированный_quic_initial...` |
| `d2k_qw_varint_write_w` | 77-105 | 29 | varint с заданной шириной | `quic.rs:1070 write_varint` (ширина по значению) | P | принудительная ширина C не поддерживается; для Initial ширина подбирается отдельно |
| `d2k_qw_varint_write` | 107-109 | 3 | varint с автошириной | `quic.rs:1070 write_varint` | E | RFC-тесты Initial/фреймов |
| `long_type_v1` | 119-127 | 9 | wire→v1 тип long header (v2 mapping) | `quic.rs` (v2-константы в `parse_initial_header`/build) | E | test `splits_rfc_9369_initial_with_v2_keys_and_labels` |
| `long_type_wire` | 132-140 | 9 | v1→wire тип (v2 mapping) | `quic.rs` (сборка Initial/Retry) | E | тот же v2-тест |
| `d2k_qw_long_hdr_token_w` | 142-174 | 33 | long header с token и заданной шириной length | `quic.rs:261 r2k_quic_initial_build` (inline) | P | токен/ширина length как отдельный API не вынесены |
| `d2k_qw_long_hdr_w` | 176-184 | 9 | long header без token | `quic.rs:261 r2k_quic_initial_build` | E | test `создаёт_аутентифицированный_quic_initial_из_clienthello` |
| `d2k_qw_long_hdr_token` | 186-194 | 9 | long header с token, автоширина | `quic.rs` (только Initial без token) | P | 0-RTT/Retry-сборка не портирована |
| `d2k_qw_long_hdr` | 196-202 | 7 | long header без token, автоширина | `quic.rs:261` | E | тот же тест Initial |
| `d2k_qw_hdr_parse` | 204-273 | 70 | разбор long/short header, token, length, pn offset | `quic.rs:796 parse_initial_header` (+short path в quinn) | E | RFC-тесты Initial v1/v2 |
| `d2k_qw_pn_len` | 277-293 | 17 | минимальная длина packet number | нет (Rust использует pn_len=4) | P | фиксированная 4-байтовая длина валидна, но байтовый паритет с C отсутствует |
| `d2k_qw_pn_decode` | 295-313 | 19 | восстановление PN по largest | `quic.rs:1041 decode_packet_number` | E | используется в RFC-тесте split Initial |
| `d2k_qw_initial_secret` | 317-325 | 9 | Initial secret (client/server in) | `quic.rs:849 derive_initial_keys` | E | RFC 9001/9369 тесты |
| `d2k_qw_keys_from_secret` | 327-338 | 12 | key/iv/hp из secret | `quic.rs:853 derive_initial_keys_for_role` | E | RFC-тесты |
| `nonce_of` | 344-349 | 6 | nonce = iv XOR pn | `quic.rs:1033 packet_nonce` | E | helper; RFC-тесты |
| `d2k_qw_seal` | 351-394 | 44 | AEAD seal + header protection | `quic.rs:968 seal_initial` | E | RFC-тест split Initial (длина и аутентичность) |
| `d2k_qw_open` | 396-450 | 55 | header protection + AEAD open, PN decode | `quic.rs:908 open_initial` | E | test `refuses_when_authenticated_initial_is_modified`, split-тесты |
| `d2k_qw_retry_verify` | 454-479 | 26 | проверка Retry integrity tag | `quic.rs:569 retry_integrity_valid` | E | test в `quic.rs` (valid/corrupted retry) |
| `d2k_qw_retry_build` | 481-521 | 41 | собрать Retry (серверная роль) | нет | N | Rust только проверяет Retry; сборка не нужна клиентскому datapath |
| `d2k_qw_ranges_reset` | 525-527 | 3 | сброс набора диапазонов | нет (quinn reassembly) | P | пересборка делегирована quinn |
| `d2k_qw_ranges_add` | 529-558 | 30 | добавить/слить диапазон, fin | нет (quinn) | P | собственной реализации нет |
| `d2k_qw_ranges_bytes` | 560-564 | 5 | сумма покрытых байт | `r2o_quic_http3.rs` app-bytes счётчики (иной смысл) | P | диапазоны не портированы |
| `d2k_qw_ranges_complete` | 566-571 | 6 | завершён ли поток (fin покрыт) | quinn `RecvStream`/`finish` | P | функциональность зависимости, не функция |

## core/quic.c (21 функция)

Разбор QUIC Initial, извлечение ClientHello/SNI, инкрементальная сборка и split crypto-фрейма. Порт: `crates/r2k-core/src/quic.rs` (`parse_initial_header`, `open_initial`, `collect_initial_crypto_frames`, `initial_split_crypto`, `r2k_quic_initial_client_hello_from_datagrams`). Доказательства: RFC 9001/9369 unit-тесты, `tests/quic_snapshot.rs`, `scripts/r2o-quic-hello-differential.sh`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `rd16` | 97-99 | 3 | big-endian u16 | `u16::from_be_bytes` | E | хелпер; владельцы покрыты RFC-тестами |
| `read_varint` | 110-125 | 16 | QUIC varint | `quic.rs:1057 read_varint` | E | RFC-тесты Initial |
| `parse_initial_header` | 149-180 | 32 | long header только Initial v1/v2 | `quic.rs:796 parse_initial_header` | E | test `splits_rfc_9001_initial_without_changing_datagram_length`, v2-тест |
| `d2k_quic_is_initial` | 182-185 | 4 | предикат Initial | `quic.rs:107 is_authenticated_initial` | E | строже C (проверяет AEAD); тест `refuses_when_authenticated_initial_is_modified` |
| `decrypt_initial` | 191-216 | 26 | вывести client Initial keys и открыть пакет | `quic.rs:908 open_initial` | E | RFC-тесты split/SNI |
| `collect_crypto_frames` | 239-416 | 178 | разбор CRYPTO/ACK/PING/CONNECTION_CLOSE, сборка потока | `quic.rs:632 collect_initial_crypto_frames` | E | RFC-тест `opened_frames`/`crypto_stream` |
| `skip_u8_vec` | 434-444 | 11 | пропуск TLS-вектора u8 | `quic.rs:1321 skip_u8_vector` | E | хелпер; владелец `find_client_hello_sni`, RFC-тест SNI |
| `skip_u16_vec` | 446-456 | 11 | пропуск TLS-вектора u16 | `quic.rs:1338 skip_u16_vector` | E | то же |
| `find_sni` | 458-501 | 44 | поиск server_name в расширениях CH | `quic.rs:1107 find_client_hello_sni` (внутри) | E | RFC-тест `extracts_sni_from_authenticated_v1_and_v2_initials` |
| `find_client_hello_sni` | 503-544 | 42 | разбор CH до расширений и SNI | `quic.rs:1107 find_client_hello_sni` | E | тот же тест |
| `crypto_stream_of` | 552-565 | 14 | Initial → CRYPTO-поток | `quic.rs:721 open_initial` + `collect_initial_crypto_frames` | E | RFC-тест `opened_frames` |
| `d2k_quic_client_hello` | 567-589 | 23 | полный ClientHello из одного Initial | `quic.rs:374 r2k_quic_initial_client_hello_from_datagrams` (1 датаграмма) | E | RFC-тест SNI/CH |
| `d2k_quic_dgrams_hello` | 607-657 | 51 | ClientHello из нескольких Initial с общим DCID | `quic.rs:374 r2k_quic_initial_client_hello_from_datagrams` | E | test `fragmented_initials` + `r2o-quic-hello-differential.sh` |
| `d2k_quic_hello_name` | 661-670 | 10 | SNI из ClientHello | `quic.rs:249 initial_client_hello_sni` | E | RFC-тест SNI |
| `d2k_quic_hello_incomplete` | 672-685 | 14 | обрезан ли ClientHello в CRYPTO-потоке | нет прямого | P | Rust собирает поток до `crypto_end`, отдельного предиката нет |
| `d2k_quic_sni` | 687-706 | 20 | SNI из Initial | `quic.rs:249 initial_client_hello_sni`, `:606 r2k_quic_initial_sni_result_from_datagrams` | E | RFC-тест SNI v1/v2 |
| `d2k_quic_assembly_init` | 708-710 | 3 | сброс инкрементальной сборки | нет (batch-API) | P | пошагового состояния в Rust нет |
| `d2k_quic_assembly_feed` | 712-778 | 67 | добавить датаграмму, открыть, собрать CRYPTO, вернуть SNI | нет (batch `..._from_datagrams`) | P | инкрементальный API не портирован |
| `d2k_quic_assembly_complete` | 780-797 | 18 | полностью ли собрано рукопожатие | нет | P | проверка полноты в batch-функции |
| `put_split_frame` | 824-839 | 16 | записать CRYPTO-фрейм в буфер | `quic.rs:1085 append_crypto_frame` | E | хелпер; владелец `d2k_quic_initial_split_crypto`, RFC-тест split |
| `d2k_quic_initial_split_crypto` | 841-948 | 108 | разрезать CRYPTO по середине SNI, пересобрать Initial | `quic.rs:167 initial_split_crypto` | E | test `splits_rfc_9001_initial_without_changing_datagram_length`, v2-тест |

## core/quichello.c (13 функций)

Сборка QUIC Initial из профиля ClientHello: выбор профиля, переименование/удаление SNI, варианты probing (v2, split, longer, clear fixed bit), recid. R2O: `r2k-core/src/quic.rs:261 r2k_quic_initial_build`, `:1113 r2k_quic_client_hello_rename_sni`, `:338 r2k_quic_initial_reseal_for_dcid`; профиль — `r2o-controller/src/quic_replay.rs:98 r2o_quic_profile_snapshot`. Тесты: `quic.rs` (RFC 9001/9369, rename/reseal), `tests/quic_snapshot.rs`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `select_probe_profile` | 34-45 | 12 | копия профиля + MIPS-замена cipher list | `quic_replay.rs:98 r2o_quic_profile_snapshot` | E | тот же MIPS-переключатель `[0x13,0x03,0x13,0x01,0x13,0x02]`; профиль 275 байт проверяется |
| `split_point` | 69-77 | 9 | точка разреза CH по середине SNI | `quic.rs:167 initial_split_crypto` (поиск mid SNI) | E | test `splits_rfc_9001_initial_without_changing_datagram_length` |
| `put_crypto` | 80-95 | 16 | CRYPTO-фрейм в буфер | `quic.rs:1085 append_crypto_frame` | E | helper; владелец `d2k_quic_hello_ask`, RFC split-тест |
| `prepare` | 124-175 | 52 | разобрать Initial, извлечь CH, переименовать SNI, новые DCID/SCID/keys | `r2k_quic_initial_build` + `r2k_quic_client_hello_rename_sni` | E | test rename/reseal, профиль; IP-target удаление SNI покрыто `quic_client_hello_rename_sni(..., None)` |
| `seal_one` | 183-228 | 46 | собрать long header + padding до want + seal | `quic.rs:261 r2k_quic_initial_build` | E | test `создаёт_аутентифицированный_quic_initial...` (len 1200) |
| `probe_initial_sized` | 235-274 | 40 | Initial заданной длины из профиля с X25519 и SNI | `quic_replay.rs:98 r2o_quic_profile_snapshot` | E | профиль+rename+build(1200); длина и SNI проверяются |
| `d2k_quic_probe_initial` | 276-279 | 4 | Initial минимальной длины (1200) | `r2o_quic_profile_snapshot` | E | test `initial.len() == 1200` |
| `d2k_quic_probe_initial_longer` | 281-285 | 5 | Initial длиной INITIAL_LONGER | `quic.rs:261 r2k_quic_initial_build` (target_len) | P | Rust-обёртка всегда 1200; длинная цель не вызывается и не тестируется |
| `d2k_quic_prepare_target` | 287-310 | 24 | переименовать снятый Initial или собрать из профиля | `r2k_quic_client_hello_rename_sni` + `r2k_quic_initial_build` | P | композиция есть в `quic_replay.rs`, отдельной функции нет; fallback-порядок не тестирован |
| `d2k_quic_hello_rename` | 312-321 | 10 | переименовать CH внутри Initial | `quic.rs:1113 r2k_quic_client_hello_rename_sni` | E | tests `quic.rs:1398-1420` (rename/без SNI/повтор) |
| `d2k_quic_hello_ask` | 330-391 | 62 | варианты: plain/v2/split/longer/clear-fixed-bit | `initial_split_crypto`, `r2k_quic_initial_build` | P | v2-сборка и clear-fixed-bit в Rust не вынесены; split покрыт |
| `d2k_quic_hello_split` | 412-455 | 44 | два Initial: хвост CH и голова CH | нет прямого (split одним пакетом) | P | двухдатаграммный вариант не найден; `initial_split_crypto` даёт один пакет |
| `d2k_quic_hello_recid` | 457-548 | 92 | перешифровать Initial с новым DCID, сохранив длины | `quic.rs:338 r2k_quic_initial_reseal_for_dcid` | E | tests `quic.rs` (reseal сохраняет форму) + `quic_snapshot.rs:30` |

## core/quicsnap.c (6 функций)

Упаковка нескольких QUIC Initial в снимок `QSN` (для повторного использования/пересылки). Порт: `crates/r2k-core/src/quic_snapshot.rs` (`pack`, `parse`, `reseal`, `verify_bound_response`); тесты `r2k-core/tests/quic_snapshot.rs`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_qsnap_is` | 13-15 | 3 | проверка магии `QSN` | `quic_snapshot.rs:50 r2k_quic_snapshot_parse` (проверяет magic) | E | test `tests/quic_snapshot.rs` round-trip; magic проверяется парсером |
| `d2k_qsnap_parse` | 17-47 | 31 | разбор снимка: count, длины, точное потребление | `quic_snapshot.rs:50 r2k_quic_snapshot_parse` | E | `tests/quic_snapshot.rs:30` (pack→parse) |
| `d2k_qsnap_pack` | 49-73 | 25 | упаковать ≤4 датаграмм с 2-байтовыми длинами | `quic_snapshot.rs:23 r2k_quic_snapshot_pack` | E | test round-trip + лимиты `R2K_QUIC_SNAPSHOT_MAX_DATAGRAMS/BYTES` |
| `d2k_qsnap_client_hello` | 75-80 | 6 | ClientHello из всех Initial снимка | `quic.rs:374 r2k_quic_initial_client_hello_from_datagrams` | E | test `fragmented_initials`, `r2o-quic-hello-differential.sh` |
| `d2k_qsnap_sni` | 82-89 | 8 | SNI из снимка | `quic.rs:249 initial_client_hello_sni` + `r2k_quic_snapshot_parse` | E | RFC-тесты SNI + snapshot round-trip |
| `d2k_qsnap_form` | 91-104 | 14 | форма для shaping (n, dgram_len, ch_len) | `r2k-core/src/quic_snapshot.rs:13 R2kQuicSnapshot::datagrams`, `quic.rs` ClientHello | P | отдельной структуры `form` нет, но `n` и длины датаграмм выводятся из снимка, `ch_len` — из разбора ClientHello; адресного differential на форму нет. |

## core/quicsnap_reseal.c (2 функции)

Перешифровка снимка `QSN` под новый DCID. Порт: `r2k-core/src/quic_snapshot.rs:79 r2k_quic_snapshot_reseal`, `quic.rs:338 r2k_quic_initial_reseal_for_dcid`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `reseal_one` | 24-73 | 50 | открыть Initial старым ключом, собрать с новым DCID/ключами, сохранить длину | `quic.rs:338 r2k_quic_initial_reseal_for_dcid` | E | tests `quic.rs:1398-1420` (reseal формы), `quic_snapshot.rs:30` |
| `d2k_qsnap_recid` | 75-134 | 60 | новый DCID для всех Initial снимка и переупаковка | `quic_snapshot.rs:79 r2k_quic_snapshot_reseal` | E | test `tests/quic_snapshot.rs`; контроллер использует в `quic_replay.rs:679` |

## core/quicprobe.c (56 функций)

Низкоуровневый QUIC-зонд: пул адресов, разбор/проверка Initial и Retry, параллельные ask-циклы, arm-стратегии, вопросы свойств, этап данных HTTP/3 и классификатор `classify_run`. В R2O: `r2o-controller/src/quic_replay.rs` (пул, фильтр, кандидаты, ask), `r2k-core/src/quic.rs` (verify/data judge/wait), `r2o_quic_http3.rs` (этап данных), `main.rs:20496 r2o_run_quic_discovery_trial`. Дифференциалы: `test-controller-quic-pool-differential.sh`, `test-quic-budget-init-differential.sh`, `test-quic-app-bytes-differential.sh`, `test-quic-http3-full-stage-differential.sh`, `test-quic-short-control-differential.sh`, `d2o_quic_base_differential.c`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `qp_addr_parse` | 173-179 | 7 | IPv4/IPv6 из текста, запрет `%` | `quic_replay.rs:23 r2o_quic_address_is_local`, `std::net::IpAddr` | P | разбор через std; зона `%` не тестировалась |
| `resolve_family` | 181-208 | 28 | getaddrinfo в пул адресов семьи | `quic_replay.rs:56 r2o_quic_address_pool` | E | pool differential (v4/v6/дубли) |
| `resolve_real` | 209-211 | 3 | resolve только IPv4 | `quic_replay.rs:56` | E | pool differential |
| `d2k_quic_build_pool` | 254-295 | 42 | цель + DNS-адреса семьи, дедуп | `quic_replay.rs:56 r2o_quic_address_pool` | E | `test-controller-quic-pool-differential.sh` (q2_pool_trace) |
| `qp_varint` | 320-335 | 16 | QUIC varint | `quic.rs:1057 read_varint` | E | хелпер; RFC-тесты Initial |
| `qp_parse_hdr` | 337-405 | 69 | разбор Initial: DCID/SCID/token/length/pn | `quic.rs:796 parse_initial_header` | E | RFC 9001/9369 тесты |
| `qp_dcid_of` | 411-420 | 10 | версия и DCID из Initial | `quic.rs:796` (поля) | E | хелпер; покрыт verify-тестами |
| `qp_donor_unauth_reply` | 456-490 | 35 | распознать Retry/VN/чужой Initial без ключей | `quic.rs:441 r2k_quic_donor_response_matches`, `:475 verify_bound` | E | покрыто base differential и unit `quic.rs` |
| `qp_verify_server_response` | 494-544 | 51 | открыть ответный Initial ключами server initial | `quic.rs:422 r2k_quic_initial_verify_donor_response` | E | unit `quic.rs` (valid/wrong CID/corrupted) |
| `qp_build_vn_trigger` | 574-615 | 42 | 1200-байтовый grease-Initial для Version Negotiation | `quic_replay.rs:159 r2o_quic_build_vn_probe` | P | Rust собирает VN-пробу; прямого differential на байты нет |
| `nap_us` | 622-627 | 6 | nanosleep | `std::thread::sleep` | P | хелпер |
| `qp_open_fresh` | 637-697 | 61 | UDP-сокет со mark, src-port и защитой от свежего порта | `r2o_quic_http3.rs:71 r2o_quic_http3_udp_socket_fresh` | P | fresh-port логика есть; SO_MARK-ветка и удержание fd не сверены |
| `qp_send_one` | 716-789 | 74 | отправить Initial/снимок с prefix/split/fragment, вернуть fd | `quic_replay.rs:647 QuicReplayProbe` (send) | P | отправка есть; plan-цепочки `d2k_udp_plan_send` заменены прямым send |
| `qp_head_of` | 806-813 | 8 | первая датаграмма снимка | `quic_snapshot.rs:50 r2k_quic_snapshot_parse` | E | хелпер; snapshot-тесты |
| `qp_verify_aead` | 815-823 | 9 | проверить ответ по ключам клиентского Initial | `quic_snapshot.rs:116 verify_bound_response` | E | тесты snapshot/verify |
| `qp_verify_bound` | 835-878 | 44 | строгая проверка ответа: DCID/SCID/Retry tag | `quic.rs:475 r2k_quic_initial_verify_bound_response` | E | unit `quic.rs` (retry/corrupted/wrong CID) |
| `d2k_quic_verify_bound` | 880-882 | 3 | публичная обёртка | `quic.rs:475` | E | тот же unit |
| `d2k_quic_verify_response` | 890-892 | 3 | публичная обёртка AEAD-проверки | `quic.rs:422` | E | unit `quic.rs` |
| `qp_verify_vn` | 898-903 | 6 | проверить Version Negotiation ответ | `quic_replay.rs:967 r2o_quic_ask_donor_version_negotiation` | P | VN-ответ обрабатывается, отдельный verify не вынесен |
| `qp_recv_ttl` | 937-997 | 61 | recvmsg + IP_TTL/IPV6_HOPLIMIT | нет | N | приём TTL/hoplimit в Rust не портирован |
| `qp_send_fragmented` | 1004-1040 | 37 | отправка IP-фрагментами по плану | `r2k-core/src/wire.rs:294 build_udp_fragments` | P | сборка фрагментов есть; raw-отправка плана из контроллера отсутствует |
| `qp_neutral_control_sni` | 1045-1058 | 14 | `z<10hex>.example.com` | `quic_replay.rs:139 r2o_quic_neutral_control_snapshots` | E | unit `quic_replay` (формат/уникальность) |
| `quic_ask_core` | 1064-1403 | 340 | параллельные ask по repeats: отправка, poll, verify, RTT, TTL, итог | `quic_replay.rs:901 r2o_quic_ask_donor_parallel` | P | асинхронный аналог есть; счётчики/refused/TTL не сверены полностью |
| `quic_ask_ex` | 1405-1416 | 12 | обёртка core без crypto_split/longer | `quic_replay.rs:901` | P | то же |
| `quic_fragment` | 1418-1428 | 11 | ask с IP-фрагментацией | `quic_replay.rs:490 r2o_quic_fragment_candidates` | P | кандидаты есть, отправка фрагментами — нет |
| `qp_progress` | 1432-1435 | 4 | hook прогресса | `main.rs` progress callback | P | hook не портирован |
| `quic_ask_arm` | 1437-1477 | 41 | ask по arm-вопросу (fragment/split/neutral) | `quic_replay.rs:647 QuicReplayProbe` | P | arm-цикл в Rust иной |
| `qp_arm_first_send` | 1500-1508 | 8 | первый send Initial через план, local_port | `quic_replay.rs:647` | P | plan-send отсутствует |
| `qp_now_ms` | 1510-1514 | 5 | монотонное время | `Instant` | P | хелпер |
| `quic_arm_data` | 1516-1584 | 69 | этап данных по arm: connect, h3, суд | `quic_replay.rs:417 r2o_quic_trial_data_verdict`, `r2o_quic_http3` | P | композиция иная; verdict покрыт differential |
| `d2k_quic_data_stage` | 1591-1829 | 239 | control-поток, GET, статус, тело, stall/budget, CUT/PASS | `r2o_quic_http3.rs:847 measure_with_wire_len_and_max_duration` | P | stage-дифференциал `test-quic-http3-full-stage-differential.sh`; точные reason/бюджет-ветки не сверены |
| `quic_ask` | 1832-1839 | 8 | базовый ask AEAD | `quic_replay.rs:901` | P | обёртка |
| `qp_ask_vn` | 1855-1862 | 8 | ask Version Negotiation | `quic_replay.rs:967` | P | VN-путь есть |
| `quic_ask_ttl` | 1869-1874 | 6 | ask с prefix TTL | `quic_replay.rs:901` | P | TTL-префикс не портирован |
| `quic_ask_copies` | 1886-1892 | 7 | ask с copies | `quic_replay.rs:901` | P | копии в параллельном ask |
| `quic_ask_srcport` | 1898-1903 | 6 | ask с исходным портом | `r2o_quic_http3.rs:71` + probe | P | src-port в Rust не параметризован |
| `quic_ask_split` | 1909-1914 | 6 | ask с split ClientHello | `quic.rs:167 initial_split_crypto` | P | split есть, ask-режим не вынесен |
| `quic_ask_longer` | 1924-1930 | 7 | ask с удлинённым Initial | `quic.rs:261` (target_len) | P | цель 100 не используется |
| `quic_ask_frames` | 1931-1937 | 7 | ask с двумя CRYPTO-фреймами | `quic.rs:167 initial_split_crypto` | P | аналог один пакет, режим не вынесен |
| `quic_ask_control` | 1942-1950 | 9 | ask нейтрального контроля | `quic_replay.rs:139 neutral snapshots` | P | контроль есть, hook-цикл иной |
| `reason_set` | 1957-1962 | 6 | записать reason | `classify.rs` reason string | P | формат текста не сверяется |
| `reason_append` | 1964-1973 | 10 | дописать reason | `classify.rs:1248 append_reason` | P | аналог есть, тексты иные |
| `budget_left` | 1984-1999 | 16 | остаток бюджета по времени | `r2o_quic_http3.rs:557 R2oQuicHttp3Budget` | P | бюджет в пакетах, не в мс |
| `qp_pinned_or_next` | 2018-2027 | 10 | первый адрес или следующий при residual | `quic_replay.rs:78 r2o_quic_next_question_address` | E | pool differential |
| `qp_dyn_wait` | 2088-2093 | 6 | ожидание = clamp(3×RTT, floor, ceil) | `quic.rs:66 r2k_quic_dynamic_wait_ms` | E | `tests/quic_budget.rs:15` |
| `d2k_quic_budget_ms` | 2095-2104 | 10 | бюджет в мс: фикс или wait + 10×poll | нет прямого | P | Rust-бюджет в пакетах/дедлайнах, формула мс не портирована |
| `qp_outcome` | 2110-2115 | 6 | tally → YES/NO/UNKNOWN | `quic_replay.rs:276 r2o_quic_direct_action` | P | маппинг иной |
| `qp_questions_step` | 2117-2268 | 152 | вопросы свойств: reshape/split/srcport/junk, бюджет | `quic_replay.rs:449 r2o_quic_discovery_candidates` | P | набор кандидатов есть, обход вопросов иной |
| `d2k_quic_props_findings` | 2274-2323 | 50 | текстовые выводы по свойствам (split/2 datagrams/v2/fixed bit/port/fake) | нет | N | тексты и выводы не портированы |
| `arm_budget_left` | 2325-2325 | 1 | предикат остатка бюджета для arm | `quic_replay.rs` budget | P | тривиальный адаптер, отдельной функции нет |
| `arm_budget_spent` | 2328-2331 | 4 | увеличить бюджет на потраченное время | нет | P | динамического бюджета arm нет |
| `classify_run` | 2336-2917 | 582 | полный классификатор: base/VN/address/opaque, residual, arms, вопросы | `main.rs:20496 r2o_run_quic_discovery_trial`, `quic_replay.rs:289 r2o_quic_base_result` | P | логика переписана на async-задачу; покрыта `d2o_quic_base_differential.c` и HTTP/3 stage, не все ветви |
| `d2k_quic_classify` | 2919-2922 | 4 | публичный classify | `main.rs:20496` | P | обёртка |
| `d2k_quic_base` | 2923-2926 | 4 | только базовый вопрос | `quic_replay.rs:289 r2o_quic_base_result` | E | `d2o_quic_base_differential.c` + unit |
| `d2k_quic_run_seeded` | 2927-2931 | 5 | classify с заранее снятым base seed | нет (seed-структуры нет) | P | base seed не портирован |
| `d2k_quic_run` | 2932-2935 | 4 | публичный classify с arm | `main.rs:20496` | P | обёртка |

## core/quicarms.c (8 функций)

Лестница arm-стратегий QUIC: перебор blob/копий/TTL/IP-фрагментации, затем стратегии clearance/split/longer/frag. R2O: `r2o-controller/src/quic_replay.rs` (`r2o_quic_discovery_candidates`, `r2o_quic_original_fallback_candidates`, `r2o_quic_strategy_attempt_decision`). Дифференциал `r2o-diagnostics-differential.sh` (C `quicarms.c` + `d2o_quic_base_differential.c`) покрывает профиль/verify/parallel/VN/base, но не всю лестницу.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_quic_original_blob` | 12-17 | 6 | 5 встроенных blob'ов приманок + имена | `quic_replay.rs:586 r2o_quic_blob_candidate`, `:628 r2o_quic_blob_name` | E | differential `r2o_quic_profile_clienthello_matches_d2o_donor_shape` (profile) |
| `ask_q` | 30-104 | 75 | задать вопрос: бюджет, адрес, ask, data-stage, trace | `quic_replay.rs:647 QuicReplayProbe`, `:368 strategy_attempt_decision` | P | параллельный ask и base покрыты; пошаговый trace/retry не сверялся |
| `ask_frag` | 112-121 | 10 | проверить IP-фрагментацию и её форму 1..4 | `quic_replay.rs:490 r2o_quic_fragment_candidates` | P | кандидаты форм есть; фактическая отправка фрагментами не портирована |
| `ask` | 125-140 | 16 | собрать вопрос по blob/copies/ttl/frag/control | `quic_replay.rs:586 r2o_quic_blob_candidate` | P | метки/текст и параметры не сопоставлены |
| `d2k_quic_original_arms` | 142-219 | 78 | перебор приманок/копий/TTL, fake-split, frag | `quic_replay.rs:506 r2o_quic_original_fallback_candidates` | P | состав кандидатов есть; порядок и условия fake-split не сверены |
| `strategy_ask` | 227-242 | 16 | вопрос стратегии с одним retry, YES/NO/UNKNOWN | `quic_replay.rs:368 r2o_quic_strategy_attempt_decision` | P | решение есть, retry-семантика не тестировалась |
| `prop_word` | 244-246 | 3 | текст «прошло/не прошло/ответа нет» | нет | N | текстовые формулировки не портированы |
| `d2k_quic_strategy_arms` | 248-396 | 149 | лестница: TTL-lifetime → clearance → split → longer → frag → original | `quic_replay.rs:449 r2o_quic_discovery_candidates`, `:368 strategy_attempt_decision` | P | base decision покрыт differential; полная лестница и приоритеты — нет |

## core/quicconn.c (36 функций)

Собственный QUIC-клиент D2O (Initial/Handshake/1-RTT, transport params, STREAM, ACK, Retry). В R2O построчного порта нет: соединение и кадры обеспечивает `quinn`, TLS — `rustls`; собственная сборка Initial осталась в `r2k-core/src/quic.rs` (`r2k_quic_initial_build`). Дифференциалы QUIC покрывают Initial/снимки/HTTP-3 (`r2o-quic-hello-differential.sh`, `test-quic-http3-full-stage-differential.sh`, `d2o_quic_base_differential.c`).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `qc_dispose` | 209-211 | 3 | освободить соединение | `quinn::Connection` RAII | P | отдельной функции нет |
| `say` | 218-224 | 7 | формат ошибки | std `format!` | P | хелпер |
| `now_ms` | 226-236 | 11 | монотонное время | `Instant` | P | хелпер |
| `crypto_put` | 243-251 | 9 | сборка CRYPTO-потока по offset | quinn/rustls CRYPTO | P | заменено зависимостью |
| `crypto_ready` | 254-258 | 5 | длина непрерывного CRYPTO | quinn/rustls | P | заменено зависимостью |
| `build_ack` | 265-274 | 10 | ACK-кадр | quinn | P | заменено зависимостью |
| `seal_level` | 281-350 | 70 | запечатать пакет уровня, padding, PN | quinn | P | заменено зависимостью; байтовый паритет не проверяется |
| `send_level` | 352-363 | 12 | отправить пакет уровня | quinn | P | заменено зависимостью |
| `tp_put_int` | 367-374 | 8 | transport parameter varint | quinn | P | заменено зависимостью |
| `tp_build` | 380-403 | 24 | клиентские transport params (окна 30k/1452, streams) | quinn (свои значения) | P | значения quinn не сопоставлены с C |
| `tp_server_parse` | 418-453 | 36 | разбор серверных max_data/max_streams | quinn | P | заменено зависимостью |
| `tp_server_ee` | 460-473 | 14 | TP из EncryptedExtensions | quinn/rustls | P | заменено зависимостью |
| `frames_in` | 479-696 | 218 | разбор кадров: PADDING/ACK/CRYPTO/STREAM/MAX_*/NEW_CONNECTION_ID/PING/CLOSE | quinn | P | заменено зависимостью |
| `recv_dgram` | 702-815 | 114 | приём датаграммы, определение уровня, открытие | quinn | P | заменено зависимостью |
| `crypto_frame` | 820-829 | 10 | CRYPTO-кадр для первого полёта | `quic.rs:1085 append_crypto_frame` | E | хелпер; владелец `d2k_qc_first_initial`, RFC-тест |
| `first_flight` | 836-892 | 57 | первый полёт: Initial + CRYPTO ClientHello | `r2k-core/src/quic.rs:261 r2k_quic_initial_build` | P | Тест покрывает только запечатывание готового Initial; C собирает CH с `tp_build`/ALPN h3/`session_id=0`, R2O сырой путь использует снятый профиль, не TP. Построчной сборки CH из SNI+TP нет. |
| `prepare_retry` | 898-926 | 29 | обработать Retry: новый DCID/token | quinn | P | заменено зависимостью; retry-проверка есть в `quic.rs:569` |
| `d2k_qc_first_initial` | 928-954 | 27 | публичная сборка первого Initial | `quic.rs:261 r2k_quic_initial_build` | P | Initial из готового CH собирается, но C-функция строит CH из SNI+TP; этой сборки в R2O нет. P, не E. |
| `qc_no_sigpipe` | 956-964 | 9 | SO_NOSIGPIPE | `MSG_NOSIGNAL`/std | P | платформенный хелпер |
| `d2k_qc_connect` | 966-1286 | 321 | полный QUIC handshake клиента, early data, 1-RTT | `quinn::Endpoint::connect` (`r2o_quic_http3.rs`) | P | Заменено quinn; HTTP/3 stage-дифференциал сверяет исход, не handshake-байты. **Расхождения:** C не проверяет цепочку/подпись сертификата (только имя, `quicconn.c:1195-1197`), R2O использует webpki-корни (`r2o_quic_http3.rs:890`) и рвёт handshake при mismatch; C-`tp_build` не портирован — действуют quinn defaults; нет классификации отказа по числу Initial/Handshake. |
| `d2k_qc_stream_send` | 1288-1375 | 88 | отправить STREAM с контролем окна | quinn `SendStream` | P | заменено зависимостью |
| `d2k_qc_stream_recv` | 1377-1423 | 47 | принять STREAM, вернуть stream_id/данные | quinn `RecvStream` | P | заменено зависимостью |
| `d2k_qc_app_progress` | 1425-1428 | 4 | прогресс app-байт/complete | `r2o_quic_http3.rs:278 app_bytes_load` | P | счётчики counted-stream, семантика иная |
| `d2k_qc_peer_name` | 1430-1430 | 1 | результат проверки имени сертификата | нет | **N** | В `R2oQuicHttp3Result` нет поля имени/`name_ok`; differential `donor_and_r2o_tls_results_match...` запускает TCP-хелпер `"tls13"`, а не QUIC. C возвращает `name_ok` и продолжает handshake; R2O проверяет цепочку/имя через webpki и при mismatch рвёт handshake. |
| `d2k_qc_rx_wire_bytes` | 1431-1431 | 1 | принятые байты | `r2o_quic_http3.rs:1280 wire_bytes` | P | quinn stats, иная точка учёта |
| `d2k_qc_datagrams` | 1432-1435 | 4 | счётчики tx/rx датаграмм | `r2o_quic_http3.rs:1272 datagrams` | P | quinn stats |
| `d2k_qc_handshake_done` | 1436-1436 | 1 | завершён ли handshake | quinn `Connection` | P | заменено зависимостью |
| `d2k_qc_rtt_ms` | 1437-1437 | 1 | RTT | quinn `stats().rtt` | P | заменено зависимостью |
| `d2k_qc_dgrams` | 1438-1441 | 4 | tx/rx датаграммы | `r2o_quic_http3.rs:1272` | P | то же |
| `d2k_qc_outbound` | 1443-1452 | 10 | sent/acked PN, есть ли ACK | quinn stats | P | то же |
| `d2k_qc_ping` | 1454-1458 | 5 | послать PING | quinn keep-alive/`ping` | P | то же |
| `d2k_qc_fd` | 1459-1459 | 1 | fd сокета | quinn (нет публичного fd) | P | доступ к fd не нужен |
| `d2k_qc_local` | 1461-1468 | 8 | локальный IPv4/порт | `quinn::Connection::local_ip` | P | аналог есть в quinn |
| `d2k_qc_local_addr` | 1470-1476 | 7 | локальный адрес/семья/порт | `quinn::Connection::local_ip` | P | аналог есть |
| `d2k_qc_release` | 1478-1484 | 7 | отдать fd, не закрывая | нет (fd не вынимается) | P | контракт C не нужен |
| `d2k_qc_close` | 1486-1490 | 5 | закрыть соединение | `quinn::Connection::close`/Drop | P | RAII |

## core/ipfrag.c (8 функций)

Сборка IPv4/IPv6 UDP-фрагментов по 4 формам (прямой/обратный порядок, 3 фрагмента с перекрытием), контрольные суммы. Порт: `crates/r2k-core/src/wire.rs:294 build_udp_fragments_with_capacity`, `:380 udp_fragment_cuts`. Дифференциал: `crates/r2k-core/tests/ipfrag.rs::d2o_ipfrag_builder_matches_r2o_on_ipv4_ipv6_shapes` (C-оракул `tests/d2o_ipfrag_oracle.c`).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_ipfrag_shape` | 5-16 | 12 | план формы 1..4 (pos/reverse/three/overlap) | `wire.rs:380 udp_fragment_cuts(total, shape)` | E | C/Rust differential `d2o_ipfrag_builder_matches_r2o...` |
| `d2k_ipfrag_cuts` | 18-45 | 28 | вычисление 2/3 срезов с выравниванием и перекрытием | `wire.rs:380 udp_fragment_cuts` | E | тот же differential (offsets/lengths для shape 1..4) |
| `wr16` | 46-46 | 1 | big-endian u16 | `wire.rs:552 write_u16` | E | хелпер; владелец `d2k_udpfrag_build_ex`, differential |
| `sum16` | 47-50 | 4 | сумма 16-битных слов | `wire.rs:534 sum16` | E | хелпер; differential |
| `fold` | 51-51 | 1 | свёртка и инверсия контрольной суммы | `wire.rs:545 checksum_value` | E | хелпер; differential |
| `d2k_udpfrag_build_ex` | 52-83 | 32 | IPv4-фрагменты: UDP checksum, id/ttl/tos, spans | `wire.rs:299 build_udp_fragments_with_capacity` | E | test `ipv4_quic_fragment_shapes_preserve_udp_datagram_and_donor_order` + C oracle |
| `d2k_udpfrag_build` | 85-89 | 5 | IPv4-фрагменты с ttl=64/tos=0 | `wire.rs:294 build_udp_fragments` | E | хелпер-обёртка; differential |
| `d2k_udpfrag6_build_ex` | 91-129 | 39 | IPv6-фрагменты (48-байтовый заголовок, flow/tc/hop, id) | `wire.rs:299` (family 6) | E | test `ipv6_quic_fragment_shapes_use_rfc_offsets...` + C oracle |

## core/stun.c (5 функций)

STUN Binding request/response: XOR-MAPPED-ADDRESS для IPv4/IPv6, проверка transaction id. Порт: `crates/r2k-core/src/stun.rs` (`binding_request`, `parse_binding_response`, `parse_xor_mapped`). Тесты: `crates/r2k-core/tests/stun.rs` (RFC 5769 + C-векторы Discovery).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `rd16` | 19-21 | 3 | big-endian u16 | `stun.rs:161 read_u16` | E | хелпер; владелец `d2k_stun_parse_response`, тесты stun |
| `rd32` | 23-25 | 3 | big-endian u32 | `stun.rs:168 read_u32` | E | хелпер; тесты stun |
| `d2k_stun_request` | 27-45 | 19 | Binding request: type 0x0001, magic, random txid | `stun.rs:18 binding_request` | E | test `parses_rfc5769...`, `recognizes_only...` |
| `parse_xor_mapped` | 52-83 | 32 | XOR-MAPPED IPv4/IPv6 (port ^ magic>>16, IP ^ key) | `stun.rs:133 parse_xor_mapped` | E | test `parses_rfc5769_xor_mapped_v4_and_v6_addresses` |
| `d2k_stun_parse_response` | 85-123 | 39 | проверка типа/magic/txid, обход атрибутов с padding | `stun.rs:28 parse_binding_response` | E | tests `rejects_foreign_and_malformed...`, `...exact_transaction_id` |

## core/voice.c (14 функций)

Голосовой зонд Discord: цели из nf_conntrack, STUN-опрос с приманками, вердикты clear/blocked/no_udp/flaky/unmeasured. В R2O: `r2o-controller/src/voice_targets.rs` (разбор целей) и `voice_measure.rs` (`r2o_measure_voice`, `r2o_ask_voice`, `r2o_evaluate_voice`, `r2o_search_voice_arms`). Тесты: unit `voice_measure.rs` (15+ сценариев), `test-voice-list-differential.sh`, Discord voice differentials.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `is_voice_port` | 42-47 | 6 | входит ли порт в голосовые диапазоны | `voice_targets.rs:161 r2o_is_voice_port` | E | test `voice_targets.rs:231 принимает_только_границы_голосовых_диапазонов` |
| `field_val` | 65-82 | 18 | выделить `name=value` из строки conntrack | `voice_targets.rs:131 r2o_field` | E | tests `voice_targets.rs:182,199` + `test-voice-list-differential.sh` |
| `d2k_voice_targets` | 84-167 | 84 | разбор nf_conntrack: udp, публичный dst, voice-порт, агрегация, сортировка | `voice_targets.rs:17 r2o_parse_voice_targets`, `:26 r2o_read_voice_targets` | E | `test-voice-list-differential.sh` + 7 unit-тестов парсера |
| `send_one` | 173-203 | 31 | UDP-сокет, mark, STUN-запрос (опционально с приманкой) | `voice_measure.rs:608 r2o_ask_voice_with_arm` | E | tests `отправляет_копии_приманки...`, `соединённый_udp_оракул...` |
| `ms_since` | 205-209 | 5 | мс с момента | `Instant::elapsed` | P | хелпер |
| `voice_ask` | 214-297 | 84 | параллельные STUN-запросы, poll, RTT, tally | `voice_measure.rs:608 r2o_ask_voice_with_arm`, `:600 r2o_ask_voice` | E | tests `три_ответа...`, `частичный_ответ...`, `местная_ошибка...`, `voice_poll_interruption...` |
| `voice_resolve` | 299-321 | 23 | host:port → IPv4 | `voice_measure.rs:581 r2o_resolve_voice_control` | E | test `разбирает_параметры_адреса_контроля...`, `отклоняет_неполный_адрес...` |
| `voice_blob_load` | 323-340 | 18 | загрузить файл приманки из blob_dir/D2K_FAKE_DIR | `voice_measure.rs:485 r2o_search_voice_arms` (чтение файлов) | P | путь/env-фолбэк и проверка «лишний байт» не сопоставлены |
| `voice_alive` | 349-360 | 12 | состояние потока: answers/silent/young/unseen | `voice_measure.rs:553 r2o_voice_observation` | E | tests `ответный_флаг...`, `молодой_поток...`, `ответы_на_живом_потоке...` |
| `voice_ask_real` | 365-365 | 1 | вернуть указатель на voice_ask | нет (прямой вызов) | N | C-API function pointer не нужен/не портирован |
| `voice_ask_arms` | 371-399 | 29 | перебор 3 blob'ов × 1/6 копий | `voice_measure.rs:485 r2o_search_voice_arms` | E | test `непринятая_приманка_не_меняет_вердикт...` |
| `say_reason` | 403-408 | 6 | записать reason | `voice_measure.rs` reason string | P | текст не сверяется |
| `add_reason` | 410-417 | 8 | дописать reason | `voice_measure.rs` reason string | P | текст не сверяется |
| `d2k_voice_run` | 434-671 | 238 | полный вердикт: выбор потока, discovery, alive, direct STUN, контроль, arms | `voice_measure.rs:141 r2o_measure_voice`, `:352 r2o_evaluate_voice` | E | 15+ unit-тестов вердиктов; CLI-дифференциала нет (см. `r2o-fetch`/ask) |

## core/voice_discovery.c (7 функций)

Discord IP Discovery обход: разбор/сборка 20-байтового STUN-префикса в тексте плана, 3 обмена Discovery, поиск границы обрыва, подтверждение префиксом. В R2O: `r2o-controller/src/voice_discovery.rs` (`r2o_voice_discovery_prefix_from_plan_text`, `r2o_voice_arm_plan_text`, `r2o_search_discovery_endpoint`, `r2o_evaluate_r2o_discovery`). Дифференциалы: `r2o-discord-discovery-differential.sh`, `test-discord-voice-discovery-arm-differential.sh`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `nibble` | 16-21 | 6 | hex-цифра | `plan_text.rs:668 hex_nibble` | E | хелпер; владелец `d2k_voice_discovery_prefix`, тесты плана |
| `d2k_voice_discovery_prefix` | 22-39 | 18 | строгий разбор текста плана → 20-байтовый префикс + проверка заголовка | `voice_discovery.rs:26 r2o_voice_discovery_prefix_from_plan_text` | E | unit `main.rs:38753+` (план/префикс), Discovery-дифференциал |
| `d2k_discovery_response` | 41-48 | 8 | валидация 74-байтового Discovery-ответа (SSRC, IP, порт) | `voice_discovery.rs:728 evaluate_r2o_discovery` (внутри), `r2k-core/tests/stun.rs:102` | E | `tests/stun.rs:112 r2o_discovery_принимает_ответ...` |
| `milliseconds` | 49-53 | 5 | монотонное время | `Instant` | P | хелпер |
| `discovery_probe` | 54-99 | 46 | 3 обмена Discovery с опциональным префиксом, poll/recv | `voice_discovery.rs:505 r2o_probe_discovery_endpoint` | E | `r2o-discord-discovery-differential.sh` |
| `local_failure` | 102-109 | 8 | локальная ошибка/mark → UNMEASURED | `voice_discovery.rs:475 r2o_probe_shape_is_valid` | P | ветка есть в evaluate; отдельной функции нет |
| `d2k_voice_discovery_search` | 110-159 | 50 | поиск границы ответов, подтверждение STUN-префиксом, вердикт | `voice_discovery.rs:484 r2o_search_discovery_endpoint` | E | дифференциалы Discovery + arm |

## core/udpplan.c (12 функций)

Генерация текста плана `d2k-plan` для UDP-проб: QUIC arm (blob/copies/ttl/frag/split/udplen), delay, voice-приманка, вопрос. В R2O план представлен структурой `r2k_core::plan::Plan`, а не текстом; QUIC-кандидаты несут `directives` (`r2o-controller/src/quic_replay.rs:207 R2oQuicDiscoveryCandidate.directives`), voice-текст — `voice_discovery.rs:8 r2o_voice_arm_plan_text`, `voice_measure.rs:269 r2o_measured_voice_arm_plan_text`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `append_fmt` | 10-20 | 11 | безопасное дописывание в буфер | `String::push_str`/`format!` | P | хелпер; отдельной функции нет |
| `emit_header_proto` | 28-34 | 7 | шапка `d2k-plan 1 1` + нулевой id + proto | `compose_d2o.rs:37` (только TCP/TLS) | P | для QUIC шапка собирается иначе, общего эмиттера нет |
| `append_hex` | 36-42 | 7 | hex-кодирование payload | `http_search.rs:841 append_hex` | E | точный аналог; используется в candidate_text |
| `quic_arm_found` | 50-54 | 5 | годен ли arm для плана | `quic_replay.rs:193 R2oQuicCandidateKind` | P | перечисление видов есть, предиката нет |
| `quic_split_plan_text` | 59-64 | 6 | текст плана `quicsplit 1` | `quic_replay.rs:449` (`directives: "quicsplit 1\n"`) | P | директива совпадает, полный текст (id/order) собирается иначе |
| `quic_plan_text` | 69-171 | 103 | полный текст QUIC-плана по arm (frag/udplen/blob/ttl/pace) | `quic_replay.rs:207` directives + `r2k-core/src/plan.rs` | P | директивы портированы по одной; побайтового differential текста нет |
| `d2k_quic_arm_plan` | 173-186 | 14 | валидация arm → текст | `quic_replay.rs:207` | P | валидация в структуре Plan, не в эмиттере |
| `d2k_quic_compose_plan` | 188-203 | 16 | выбор плана по arm/props (junk/longer) | `quic_replay.rs:449 r2o_quic_discovery_candidates` | P | выбор кандидатов есть, композиция текста иная |
| `d2k_quic_delay_plan` | 205-217 | 13 | план `delay 15000` (D2K_QUIC_DELAY_US = D2K_PACE_SETTLE_US) | разбор `plan_text.rs:444`, `r2k-core/plan.rs:47/286 REC_DELAY`, применение `main.rs:3604`, фикстура `main.rs:26066` | P | C печатает `d2k-plan 1 6 … delay 15000` (`test_quic_arms.c:373`). В R2O есть разбор/применение и тестовая фикстура `r2o-plan 1 11 … delay 15000`, но **нет продюсера** delay-плана. Ссылка на `r2o_quic_deny.rs:203 r2o_delay` была ложной — это backoff deny-кэша (10/30/60 мин). |
| `d2k_voice_arm_plan` | 219-239 | 21 | текст voice-плана с приманкой и copies | `voice_measure.rs:269 r2o_measured_voice_arm_plan_text` | E | unit `measured_voice_arm_plan_preserves_payload_copy_count_and_voice_shape` |
| `d2k_voice_plan` | 241-243 | 3 | voice-план с D2K_VOICE_DECOY_REPEATS=10 | `voice_measure.rs:269 r2o_measured_voice_arm_plan_text`; `voice_discovery.rs:8` (copies=1) | E | Отдельной обёртки нет, но `test-controller-udpplan-differential.sh` вызывает C для copies=10 и сравнивает с Rust-текстом (шапка/id нормализуются); unit `measured_voice_arm_plan_preserves_payload_copy_count_and_voice_shape`. Тест есть, не перезапускался. |
| `d2k_quic_question_plan` | 247-266 | 20 | текст плана по вопросу (udplen/split/frag/ttl/blob) | `quic_replay.rs` candidates + `r2k-core/src/plan.rs` | P | разбор вопроса в структуру есть, эмиттер текста отсутствует |

## core/udpruntime.c (8 функций)

Сборка UDP-пакета/пачки из текста плана и отправка плана с контроллера: обычным sendto для нефрагментированных, raw IP_HDRINCL/IP_NODEFRAG — для IP-фрагментов. В R2O план применяется в датапате (`r2k-core/src/plan/apply.rs`), а контроллер шлёт QUIC-датаграммы напрямую (`quic_replay.rs`) без UDP-plan runtime.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `udp_next_fragment_id` | 22-30 | 9 | потокобезопасный IP id (random seed, инкремент) | `wire.rs` (случайный id) | P | глобального счётчика нет; id выбирается случайно на сборку |
| `d2k_udp_batch_free` | 32-32 | 1 | освободить буфер пачки | RAII `Vec` | P | отдельной функции нет |
| `d2k_udp_plan_build` | 33-93 | 61 | текст → TLV → план → emissions → IPv4/IPv6 пакеты/фрагменты | `r2k-core/src/plan/apply.rs` (apply emissions) | P | применение плана есть; сборка байтовой пачки из контроллера отсутствует |
| `udp_raw_init` | 101-106 | 6 | инициализация raw-sink (IPv6 frag sender) | `r2o-datapath/src/raw.rs:48 RawSocket::open`, `:35-44 OwnedFd` | **P** | Контроллерного sink нет, но датапат открывает raw IPv4/IPv6; C-специфичный `d2k_ip6frag_sender` заменён IPv6-raw. |
| `udp_raw_close` | 107-112 | 6 | закрыть raw-sink | `OwnedFd`/`Drop` (`raw.rs:35-44`) | **P** | RAII; отдельной функции нет. |
| `udp_raw_prepare` | 113-130 | 18 | подготовить raw-сокет/IPv6 frag route | `raw.rs:48-93`, `:155-167` | **P** | `IP_HDRINCL`/`IPV6_HDRINCL`/`SO_MARK` есть (`raw.rs:75,77,80`); **`IP_NODEFRAG` во всём R2O отсутствует**, mark обязателен, IPv6-путь иной. |
| `udp_raw_send` | 131-139 | 9 | sendto raw IPv4/IPv6 | `raw.rs:147-223` | **P** | Полный IP-пакет/фрагмент, `MSG_DONTWAIT`, EMSGSIZE-понижение MTU; C — блокирующий sendto, IPv6 через frag-sender. |
| `d2k_udp_plan_send` | 147-190 | 44 | отправить план с сокета: TTL/hoplimit, задержки, фрагменты, восстановление TTL | датапат: `engine.rs:1753`, `main.rs:3604`, `wire.rs:109/132`, `raw.rs:147` | **P** | Контроллерного API нет; проводное поведение реализовано в датапате: фрагменты, задержка, TTL в заголовке, raw-send. Нет socket TTL get/set/restore и `ECONNREFUSED → -2`. |

## core/volume.c (19 функций)

Измерение объёма ответа: лестница HEAD с растущим X-Pad, повторные identity-пробы, gzip-контроль, evidence обрыва по объёму/пакетам. R2O: `r2o-controller/src/r2o_volume.rs` (почти построчный порт evidence), `fetch.rs` (`r2o_fetch_measure_rx_volume*`, `r2o_fetch_rx_probe`, `r2o_fetch_measure_tx_volume`). Тесты: `crates/r2o-controller/tests/r2o_volume.rs`, `d2o_verify_differential.rs` (rx-volume), `fetch.rs` unit.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `rx_wire_partial` | 58-64 | 7 | partial-обрыв внутри TLS-записи | `r2o_volume.rs:136 r2o_volume_rx_wire_partial` | E | `tests/r2o_volume.rs` (wire partial кейсы) |
| `d2k_volume_rx_partial` | 66-72 | 7 | partial по TLS-записи или телу | `r2o_volume.rs:68 r2o_volume_rx_partial` | E | `tests/r2o_volume.rs:49+` |
| `d2k_volume_rx_pair_agrees` | 78-83 | 6 | согласованы ли две partial-пробы | `r2o_volume.rs:80 r2o_volume_rx_pair_agrees` | E | `tests/r2o_volume.rs:49,63,96` |
| `d2k_volume_rx_needs_repeat` | 103-109 | 7 | нужна ли третья проба | `r2o_volume.rs:112 r2o_volume_rx_needs_repeat` | E | `tests/r2o_volume.rs` |
| `d2k_volume_rx_evidence` | 111-213 | 103 | evidence: wire/body cut, slack, пакетный бюджет, reason | `r2o_volume.rs:125 r2o_volume_rx_evidence` | E | `tests/r2o_volume.rs:50,75,80,91` |
| `d2k_vol_verdict_name` | 215-222 | 8 | русское имя вердикта | `fetch.rs:486-493 r2o_label`; `r2o-fetch.rs:232-236` | **P** | Четыре состояния; `Short/Cut/Passed` совпадают дословно, `Unreachable` — «цель не ответила» вместо «мишень не ответила» (в JSON-пути снова «мишень»). Функции/теста нет. |
| `now_ms` | 224-228 | 5 | монотонное время | `Instant` | P | хелпер |
| `nap_ms` | 230-235 | 6 | sleep мс | `std::thread::sleep` | P | хелпер |
| `clamp_ms` | 237-241 | 5 | clamp int | `clamp` | P | хелпер |
| `fill_pad` | 247-257 | 11 | случайный X-Pad (alphabet, fallback) | `fetch.rs:2545 r2o_volume_padding` | P | padding есть; алфавит/фолбэк не сопоставлены |
| `connect_bounded` | 259-322 | 64 | nonblocking TCP connect с TCP_NODELAY/mark/таймаутом | `fetch.rs:3017 connect_target`, `:3029 connect_marked` | P | mark/таймаут есть; TCP_NODELAY и коды ошибок не сверены |
| `drain_head_tls` | 325-349 | 25 | дочитать HEAD-ответ до пустой строки через TLS | `fetch.rs` чтение заголовков | P | побайтовое чтение заменено парсером |
| `drain_head_plain` | 351-375 | 25 | то же для открытого TCP | `fetch.rs` | P | то же |
| `resource_retry_path` | 393-406 | 14 | выбрать другой resource-path для повтора | `fetch.rs:1366 r2o_fetch_resource_scan_allowed` + redirect | P | выбор пути повтора не вынесен |
| `rx_probe` | 411-427 | 17 | одна rx-проба с повтором при раннем обрыве | `fetch.rs:1447 r2o_fetch_rx_probe` | E | `d2o_verify_differential.rs` rx-volume тесты |
| `measure_response_volume` | 440-552 | 113 | identity×2 + third + gzip, evidence | `fetch.rs:1430 r2o_fetch_measure_rx_volume_with_fallback_path_and_timeouts` | P | e2e сверяется; ветки resource-retry/unmeasured не все сопоставлены |
| `probe_response_volume` | 558-593 | 36 | повтор по resource-path при коротком теле | `fetch.rs:1509 r2o_fetch_measure_rx_volume_with_fallback_path...` | P | fallback есть, условие `rx_short` не сверено |
| `d2k_volume_probe_path` | 595-727 | 133 | TCP+TLS, лестница HEAD 0..7 с X-Pad, таймаут×3 | `fetch.rs` rx/tx volume ladder | P | лестница портирована в fetch; точные размеры/таймауты не сверены |
| `d2k_volume_probe` | 729-732 | 4 | обёртка с path=NULL | `fetch.rs` volume probe | P | обёртка |

## core/include/d2k_http_reply.h (6 функций)

Inline-классификация HTTP-ответа: 451/2xx/3xx-портал, тело с маркерами РКН/порталов. Порт: `r2o-controller/src/fetch.rs:2836 r2o_fetch_http_outcome`, `:2873 r2o_fetch_portal_location`, `:2916 r2o_fetch_body_has_portal`, `:2906 r2o_fetch_ascii_contains`. Отдельного differential на эту функцию не найдено; используется в page/verify-дифференциалах.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_http_lower` | 9-11 | 3 | ASCII lower | `fetch.rs:2941`/`response.rs:508 lower_ascii` | P | хелпер; владелец classify, прямого теста нет |
| `d2k_http_equal` | 12-16 | 5 | регистронезависимое сравнение | `fetch.rs:2910 r2o_fetch_ascii_contains` | P | то же |
| `d2k_http_hostchar` | 17-21 | 5 | символ host для границ в теле | `fetch.rs:2941 r2o_fetch_http_host_char` | P | то же |
| `d2k_http_portal` | 22-26 | 5 | список 6 порталов по индексу | `fetch.rs:2873` (массив внутри) | P | список совпадает, отдельной функции нет |
| `d2k_http_location_portal` | 27-52 | 26 | host портала из Location (userinfo/port/точка) | `fetch.rs:2873 r2o_fetch_portal_location` | P | построчный порт; target-теста нет |
| `d2k_http_reply_classify` | 55-86 | 32 | HTTP 451/2xx/3xx/4xx → outcome+evidence | `fetch.rs:2836 r2o_fetch_http_outcome` | P | порт есть; покрыт косвенно `r2o-tls-verify-differential.sh`/page-тестами, не отдельным differential |

## core/include/d2k_ip6frag_send.h (9 функций)

Отправка IPv6-пакетов с фрагментацией через AF_PACKET: netlink route/neigh, MTU, MAC, SO_MARK, кеш 1 с. В R2O есть `r2o-datapath/src/raw.rs` (`RawSocket`: AF_INET/AF_INET6 IPPROTO_RAW, SO_MARK, route/MTU, IPv4/IPv6 UDP-фрагментация), но он в датапате, а не в контроллере; ручной neighbor-резолв заменён ядром.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_ip6frag_sender_init` | 34-36 | 3 | сброс sender, fd=-1 | `raw.rs:46 RawSocket::open` (RAII) | P | контейнер иной; отдельной init нет |
| `d2k_ip6frag_sender_close` | 37-40 | 4 | закрыть fd | `RawSocket` Drop | P | RAII |
| `d2k_f6_now` | 41-45 | 5 | монотонное время, мс | `Instant` | P | хелпер |
| `d2k_f6_attr` | 46-55 | 10 | rtattr в netlink-запрос | `r2o_route.rs:679/691` (сборка запросов) | P | отдельного attr-хелпера нет |
| `d2k_f6_query` | 56-72 | 17 | netlink-запрос с таймаутом 200 мс | `r2o_route.rs` (netlink сокет) | P | реализация в датапате, API иной |
| `d2k_f6_route` | 73-106 | 34 | RTM_GETROUTE IPv6 (src/dst/mark) → ifindex/gateway | `r2o_route.rs:691 r2o_route_lookup_request`, `:774 parse_lookup` | P | парсер запроса/ответа есть; контроллерный вызов отсутствует |
| `d2k_f6_neighbor` | 107-154 | 48 | RTM_GETNEIGH → MAC шлюза | нет (резолв ядром) | P | механизм заменён: RawSocket шлёт через IPPROTO_RAW |
| `d2k_ip6frag_prepare` | 155-195 | 41 | маршрут/MTU/MAC, AF_PACKET sendto, кеш | `raw.rs:484 r2o_route_mtu`, `:622 ipv6_udp_fragment` | P | функциональность в датапате; кеш/ошибки не сопоставлены |
| `d2k_ip6frag_send` | 196-204 | 9 | sendto с EINTR-повтором | `RawSocket::send` | P | аналог есть, контракт иной |

## core/include/d2k_quicprobe.h (9 функций)

Inline-решения QUIC-зонда: суд этапа данных, stall-детектор с PING, бюджет датаграмм. Порт: `r2k-core/src/quic.rs:31 r2k_quic_data_judge`, `r2o-controller/src/r2o_quic_http3.rs:543 R2oQuicHttp3Budget`, `:600 R2oQuicHttp3Stall`, `quic_replay.rs:417 r2o_quic_trial_data_verdict`. Дифференциалы: `test-quic-short-control-differential.sh`, `test-quic-budget-init-differential.sh`, `d2o_quic_http3_differential.c` в `r2o-diagnostics-differential.sh`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_quic_arm_data_judge` | 454-461 | 8 | handshake/status/bytes/complete → NO_HANDSHAKE/CUT/PASS | `quic.rs:31 r2k_quic_data_judge` | E | `tests/quic_data_judge.rs` + `test-quic-short-control-differential.sh` |
| `d2k_quic_arm_data_judge_limited` | 466-470 | 5 | NOT_RUN при переполнении заголовков | `quic_replay.rs:433 r2o_quic_short_control_data_verdict` | P | headers_too_long-ветка в Rust не выделена; short-control differential её не покрывает |
| `d2k_qstall_init` | 523-535 | 13 | stall: RTO=max(3×RTT,1000), отметки прогресса | `r2o_quic_http3.rs:600 R2oQuicHttp3Stall` | P | реализация есть, target-теста/дифференциала нет |
| `d2k_qstall_sent` | 540-543 | 4 | запомнить PN отправленного PING | `R2oQuicHttp3Stall` (probes_sent) | P | то же |
| `d2k_qstall_step` | 545-584 | 40 | GOING/PROBE/STALLED/ONEWAY по прогрессу/ACK/RTO | `r2o_quic_http3.rs:600` (`r2o_step`) | P | логика есть; границы и oneway не сверены |
| `d2k_qbudget_init` | 616-620 | 5 | need=2×budget (25 по умолчанию) | `r2o_quic_http3.rs:548 r2o_quic_http3_budget_datagrams`, `R2oQuicHttp3Budget::r2o_initialize` | E | `test-quic-budget-init-differential.sh` (0/1/25/u32 max) |
| `d2k_qbudget_ok` | 626-631 | 6 | бюджет набран, прогресс растёт, не stall | `R2oQuicHttp3Budget` | E | `d2o_quic_http3_differential.c` + full-stage differential |
| `d2k_qbudget_grew` | 637-639 | 3 | упрощённая проверка роста | `R2oQuicHttp3Budget` (grew) | E | тот же differential |
| `d2k_quic_arm_data_judge3` | 641-652 | 12 | расширенный суд: complete/budget/stalled/need_complete/headers | `quic_replay.rs:417 r2o_quic_trial_data_verdict`, `r2k_quic_data_judge` | E | `d2o_quic_http3_differential.c` (judge3) + full-stage |

## core/include/d2k_arm.h (1 функция)

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_arm_segment` | 78-83 | 6 | размер сегмента ARM с учётом send_cap | `r2k-core/src/plan/apply.rs:660 segment` (иная семантика) | P | расчёт размера посылки есть в плане; ARM-сегментация контроллера не вынесена, target-теста нет |

## Углублённая сверка: udpplan.c и udpruntime.c (20 функций)

- **Текстовые сборщики `udpplan.c`:** `append_fmt`, `emit_header_proto`,
  `append_hex`, `quic_arm_found`, `quic_split_plan_text`, `quic_plan_text`,
  `d2k_quic_arm_plan`, `d2k_quic_compose_plan`, `d2k_quic_delay_plan`,
  `d2k_voice_arm_plan`, `d2k_voice_plan`, `d2k_quic_question_plan` сверены с
  `r2o_fallback`/`classify_measured`/`r2o_quic_http3`. Формы quicsplit 1,
  ipfrag 1–4, udplen, fake/ttl/copies, voice-план и «нет воздействия» =
  `order forward` перенесены; отличия — заголовок `r2o-plan` вместо
  `d2k-plan` и иной слой сборки. C/Rust differential на все комбинации
  arm/props не заявлен, статусы P.
- **`udp_next_fragment_id` (22–30):** C под pthread-mutex берёт random
  seed из TLS RNG и выдаёт ненулевой 32-битный IPv4 fragment id. В R2O
  отдельного UDP-fragment-id генератора нет; raw-фрагментация UDP-планов
  не портирована — N.
- **`d2k_udp_batch_free`/`d2k_udp_plan_build` (32–93):** C компилирует
  текст плана в TLV, применяет `d2k_plan_apply`, отказывает при >1 payload,
  `POISON_IPID_ZERO` (SOCK_DGRAM не может сохранить IP ID), собирает
  IPv4/IPv6-фрагменты (`d2k_udpfrag_build_ex`/`d2k_udpfrag6_build_ex`) или
  `d2k_wire_build_udp`, а для `ORIG_PASS` добавляет оригинал ровно один раз.
  В R2O аналога нет: QUIC-план исполняет датапат, контроллер шлёт датаграммы
  напрямую — N.
- **`udp_raw_init`/`udp_raw_close`/`udp_raw_prepare`/`udp_raw_send`
  (101–139):** C на Linux открывает `AF_INET/SOCK_RAW/IPPROTO_RAW`, ставит
  `IP_HDRINCL`, `IP_NODEFRAG` и `SO_MARK`; для IPv6 использует
  `d2k_ip6frag_sender`; ошибка raw-prepare = UNSENT, без fallback на
  обычный датаграммный сокет. В R2O `raw_probe.rs:1876` ставит
  `IP_HDRINCL` только для TCP; UDP raw-sink, `IP_NODEFRAG` и IPv6-frag
  sender в контроллере отсутствуют — N.
- **`d2k_udp_plan_send` (147–190):** C берёт `IP_TTL`/`IPV6_UNICAST_HOPS`
  с исходного сокета, собирает batch, для фрагментов шлёт raw, для обычных
  посылок временно ставит TTL из пакета и восстанавливает исходный TTL даже
  после ошибки; `ECONNREFUSED` → `-2`. R2O шлёт QUIC обычным `UdpSocket`
  (`r2o_quic_http3.rs`/`quic_replay.rs`), без TTL/hoplimit и без
  восстановления — N.
- **`qp_recv_ttl` (937–997, `quicprobe.c`):** C принимает TTL/hoplimit
  через `recvmsg` (`IP_TTL`/`IPV6_HOPLIMIT`). В R2O приёма TTL нет — N.
- **Итог:** 12 текстовых сборщиков — P (формы перенесены, полного
  differential нет); 8 функций raw-UDP runtime/фрагментов/TTL — N.
  Это архитектурный пробел: R2O не исполняет UDP-плановые посылки с
  контроллера так, как C `d2k_udp_plan_send`, и не измеряет TTL ответа.

## Углублённая сверка: tls13.c (23) и quicconn.c (36)

- **TLS 1.3, C-стек:** `tls_dispose`, `say`, `now_ms`, `read_exact`,
  `write_all`, `put16`, `get16`, `nonce_of`, `read_record`, `write_record`,
  `traffic_keys` — собственный record layer и key schedule;
  `tls_connect_internal` (265–524) — ClientHello/HRR/ServerHello/
  EncryptedExtensions/Certificate/Finished, ECH и downgrade на TLS 1.2;
  `d2k_tls_connect*`/`d2k_tls_connect_ech`, `d2k_tls_ech_accepted`,
  `d2k_tls_write/read`, `d2k_tls_peer_name`, `d2k_tls_free`,
  `d2k_tls_rx_wire_bytes`, `d2k_tls_rx_record_missing`, `d2k_tls_version`.
  R2O заменяет это `rustls` (`r2o_tls.rs:53`, `r2o_tls13_client_hello`),
  ECH — `ech.rs`/HPKE, счётчики — `R2oTlsRecordTracker`. **Пробелы P:**
  построчного record layer/HRR/key update/session resumption/0-RTT нет;
  коды ошибок, тайминги и close_notify-семантика C не сопоставлены;
  ECH-путь проверяется `r2o-ech-rx-ladder-differential.sh`, но не
  побайтово против C. Дифференциалы `r2o-tls-verify-differential.sh`
  (16/16) и `test-controller-clienthello-differential.sh` (56) покрывают
  исходы/ClientHello, не весь стек.
- **QUIC, C-стек:** `qc_dispose`, `say`, `now_ms`, `crypto_put/ready`,
  `build_ack`, `seal_level`, `send_level`, `tp_put_int`, `tp_build`,
  `tp_server_parse/ee`, `frames_in`, `recv_dgram`, `crypto_frame`,
  `first_flight`, `prepare_retry`, `d2k_qc_first_initial`,
  `d2k_qc_connect`, `d2k_qc_stream_send/recv`, `d2k_qc_app_progress`,
  `d2k_qc_peer_name/rx_wire_bytes/datagrams/handshake_done/rtt_ms/
  dgrams/outbound/ping/fd/local/local_addr/release/close`. R2O использует
  `quinn-proto`/`quinn` (`r2o_quic_http3.rs`, `quic_replay.rs`,
  `r2k-core/src/quic.rs`). **Пробелы P:** C-ACK/loss/Retry/transport
  params и `prepare_retry` не имеют построчного аналога — поведение
  делегировано quinn; `d2k_qc_rtt_ms`/`outbound`/`dgrams` частично
  соответствуют состоянию HTTP3-бюджета; 0-RTT и точные packet-number/
  loss-правила не сверялись. Дифференциалы HTTP/3 18/18, app-bytes,
  budget-init, short-control и retry-сценарии покрывают исходы, но не
  внутреннюю state machine.
- **Вывод:** 59 функций остаются P (не N): клиентский путь работает через
  проверенные библиотеки, но C-стек не перенесён построчно. Это осознанная
  замена, а не отсутствие функциональности; для E нужны адресные
  differentials на record layer/ACK-loss/HRR/key update.

## Углублённая сверка: hello/tls13core/h3/httpup_logic (67)

- **`hello.c` (19):** `rd16`, `rd24`, `skip_u8_vec`, `skip_u16_vec`,
  `parse_hello`, `d2k_hello_complete`, `d2k_hello_shape`, `d2k_hello_sni`,
  `d2k_hello_ech_offer` — E: побайтовые порты в `hello.rs`, дифференциал
  `test-controller-clienthello-differential.sh` (24+ кейса: длины,
  усечения, SNI, ECH). `d2k_hello_from_profile` — E (профили
  modern/legacy, unit). **P:** `wr16`/`wr24` (нет прямого теста записи
  длин); `d2k_hello_alpn`/`d2k_alpn_is_http` — Rust
  `r2o_tls_client_hello_non_http_alpn` возвращает только не-HTTP список и
  отвергает ECH, сырого списка/кодов C нет; `splice_sni`/`d2k_hello_rename`
  — порт есть, побайтового differential на пересчёт 6 длин нет;
  `d2k_hello_without_sni` — TLS-путь отдельной функции не имеет, только
  QUIC-путь `r2k_quic_client_hello_rename_sni(..., None)`; hex-хелперы
  отличаются обработкой комментариев/пробелов.
- **`tls13core.c` (24):** `put16`, `get16`, `der_len`, `ascii_lower`,
  `name_matches`, `cert_name_ok`, `d2k_t13_cert_name_ok12/ok`,
  `d2k_t13_ch_build` — E: SAN/DER/wildcard и сборка ClientHello сверены
  `tests/response.rs::d2o_shared_tls_response_vectors_match`,
  `tests/r2o_tls.rs` (padding/session_id/ALPN), `d2o_verify_differential`.
  **P:** `d2k_t13_random` (источник заменён `rustls`/`getrandom`);
  `d2k_t13_derive_secret/schedule_hs/schedule_ap/finished_mac` — key
  schedule внутри rustls, C-векторов нет; `d2k_t13_sh_version/sh_parse/
  flight_next` — разбор ServerHello/итератор отдан rustls, полного
  C/Rust differential нет; `ech_host_ok`/`d2k_ech_config_parse` — Rust
  получает ECHConfig из HTTPS RR (`ech.rs:158`), а C разбирает wire
  ECHConfigList; выбор первого валидного/лимиты не сверялись;
  `hpke_extract/expand/ech_hpke` — заменены crate `hpke`; `d2k_t13_ech_build`
  — Rust собирает ECH через rustls, байтовая раскладка C не повторена;
  `d2k_t13_ech_accepted` — проверка делегирована rustls
  (`fetch.rs:986`), C-оракул на accept_confirmation не подключён.
- **`h3.c` (9):** `d2k_h3_control`, `prefix_int(_read)`, `d2k_h3_request`,
  `huff_status`, `static_status`, `name_is_status`, `decode_section`,
  `d2k_h3_status` — все E: `scripts/test-controller-h3-httpup-differential.sh`
  и unit `h3.rs` (static/literal/post-base/Huffman, request/control).
- **`httpup_logic.c` (15):** `ascii_alnum`, `dns_host`, `host_equal`,
  `known_portal_host`, `find_crlf`, `parse_request`,
  `d2k_httpup_request_safe`, `build_redirect`, `portal_marker`,
  `redirect_location_host`, `portal_answer`,
  `d2k_httpup_portal_response/request_target/portal_location/
  redirect_https` — все E: `tests/httpup.rs` (safe bodyless,
  ambiguous rejection, portal/307, exact Location/target, DNS-метки).
- **Вывод:** 67 функций; 9 h3 + 15 httpup + 13 hello + 7 tls13core — E,
  остальные P на ALPN/rename/without_sni/key schedule/ECH-байты.
  Новых N в блоке нет.

## Проверка полноты среза

Сверка выполнена скриптом: для каждого заголовка `## <файл>` считается число строк таблицы, начинающихся с `| \`имя\``; результат сравнивается с числом функций файла в `slice-core-net.csv`.

Команда:

```sh
python3 - <<'PY'
import csv, re, collections
rows = list(csv.DictReader(open('/mnt/e/r2o-tooling/audit/slice-core-net.csv')))
want = collections.Counter(r['file'] for r in rows)
doc = open('/mnt/e/r2o/docs/audit/core-net.md', encoding='utf-8').read().splitlines()
got, cur = collections.Counter(), None
for line in doc:
    m = re.match(r'^## (core/\S+)', line)
    if m:
        cur = m.group(1); continue
    if cur and re.match(r'^\| `[A-Za-z0-9_]+`', line):
        got[cur] += 1
print('CSV:', sum(want.values()), 'DOC:', sum(got.values()))
bad = [(f, want[f], got[f]) for f in want if want[f] != got[f]]
print('mismatches:', bad if bad else 'нет')
PY
```

Фактический вывод в этом проходе:

```
CSV: 548 DOC: 548
mismatches: нет
```

Итог: **548 из 548** функций присутствуют в таблицах ровно по одному разу; расхождений по файлам нет.

## Что подтверждено сильнее всего

- `hello.c`, `tls13core.c`, `h3.c`, `httpup_logic.c`, `ipfrag.c`, `stun.c` — построчные порты с целевыми тестами/дифференциалами (`test-controller-clienthello-differential.sh`, `test-controller-h3-httpup-differential.sh`, `tests/httpup.rs`, `tests/ipfrag.rs`, `tests/stun.rs`).
- `httpsprobe.c` — кэш/состояния/TTL и загрузка `d2k-https` покрыты `test-controller-httpsprobe-differential.sh`.
- `httpsearch.c` — ключевые решения (judge, кандидаты, APPLIED-окно, baseline, CUT, очередь, durable, rollback, no-executed) покрыты `r2o-http-search-differential.sh`.
- `quicwire.c`/`quic.c`/`quicsnap*.c` — RFC 9001/9369 unit-тесты и snapshot/reseal-тесты; `quicprobe.c` — пул, бюджет, data judge, base/VN через отдельные дифференциалы.

## Главные пробелы

- `tls12.c`/`tls13.c`/`quicconn.c` — собственные стеки C заменены `rustls`/`quinn`; end-to-end исходы сверяются, но record-layer, коды ошибок и тайминги не имеют построчного паритета.
- `quicprobe.c` — полная лестница `classify_run`/arm-стратегий переписана на async-задачи; дифференциалы покрывают base, пул, бюджет, HTTP/3-stage, но не все ветви `opaque`/`residual`/`arm`.
- `udpruntime.c` — raw UDP-отправка планов из контроллера отдельным API не портирована, но проводное поведение есть в датапате: `IP_HDRINCL`/`IPV6_HDRINCL`/`SO_MARK` (`raw.rs:75,77,80`), фрагменты/задержка/TTL в заголовке. **`IP_NODEFRAG` отсутствует**, mark обязателен, socket TTL get/set/restore и `ECONNREFUSED → -2` не портированы — P, не N.
- `udpplan.c` — QUIC-план в R2O представлен структурой и `directives`, а не полным текстом `d2k-plan`; побайтового differential текста нет.
- `volume.c` — evidence-функции покрыты unit-тестами, но лестница HEAD/повторов и resource-retry сверяются только косвенно.
- Диагностические тексты (`props_findings`, `verdict_name`, `prop_word`, `reason`-форматы) в Rust не воспроизведены дословно — это `N`/`P`, не влияющие на сетевой datapath, но влияющие на CLI/лог-паритет.

## Углублённая сверка N-функций (финальные 12)

- **`d2k_tls12_prf_for_test` (tls12.c 214–218):** тестовый экспорт PRF,
  используется `test_tls12.c:44,58`. R2O использует `rustls` TLS1.2 PRF;
  отдельного экспорта/вектора нет. **Не под `#ifdef`** — это обычный
  экспорт, а не только тестовая сборка. N — тестовый хук.
- **`d2k_verify_tcp_timestamps_get` (verify.c 829):** геттер
  thread-local `g_verify_tcp_timestamps`; `sched.c:2817-2819` ставит
  профиль из триггера, `verify.c:1361,1514` передают его в
  `d2k_props_contact_on_family_tcp_profile` → `compose.c:591-636`
  временно пишет `/proc/sys/net/ipv4/tcp_timestamps`. Это **packet-path**,
  не CLI: R2O fetch/replay используют обычный `TcpStream::connect`, а
  per-call `Option<bool>` есть только в `raw_probe.rs:673`. N.
- **`d2k_httpsprobe_lost` (httpsprobe.c 460–466):** счётчик потерянных
  результатов HTTPS-проб, читается `d2kc.c:349`. R2O использует
  ограниченный `SyncSender` и блокирующий `send` (`https_probe.rs:179`):
  при переполнении воркер блокируется, а не дропает; счётчика `lost` нет.
  N — диагностика.
- **`d2k_httpsearch_test_add_failures` (555–568) и
  `d2k_httpsearch_test_add_records` (569–578):** только под
  `D2K_HS_TESTING`, наполняют таблицу для тестов. Rust-тесты создают
  состояние иначе. N — тестовые хуки.
- **`d2k_qw_retry_build` (quicwire.c 481–521):** серверный QUIC Retry
  (version/DCID/SCID/token). R2O умеет только проверять
  `retry_integrity_valid` (`r2k-core/src/quic.rs:569`), не строит Retry.
  N — серверная роль.
- **`qp_recv_ttl` (quicprobe.c 937–997):** C читает TTL/hoplimit через
  `recvmsg` (`IP_RECVTTL`/`IPV6_HOPLIMIT`) и отдаёт в `quic_ask_core`
  (`ttl_in_out`, 1315-1329), питая TTL-плечо. Во всём R2O нет
  `recvmsg`/`IP_RECVTTL`/`IPV6_HOPLIMIT`; quinn/`UdpSocket` TTL не
  отдают. N — packet-path.
- **`d2k_quic_props_findings` (2275–2324):** текстовые выводы по
  split/2 datagrams/v2/fixed bit/port для журнала (`sched.c:11506`).
  В R2O есть имена кандидатов (`quic_replay.rs:628`), но нет функции
  выводов. N — диагностический текст.
- **`prop_word` (quicarms.c 244, static):** tri-state → слово для лога.
  R2O использует свои reason-строки; отдельной функции нет. N —
  диагностика.
- **`voice_ask_real` (voice.c 365):** function-pointer seam для подмены
  oracle в тестах (`test_voice.c:744`). R2O `voice_measure` вызывает
  замер напрямую (`voice_measure.rs:608`); API-шима нет, поведение не
  страдает. N — тестовый seam.
- **`d2k_qc_peer_name` (quicconn.c 1430):** C возвращает `name_ok` и
  продолжает handshake. В `R2oQuicHttp3Result` нет поля имени/`name_ok`;
  differential `donor_and_r2o_tls_results_match...` запускает TCP-хелпер
  `"tls13"`, не QUIC. R2O проверяет цепочку/имя через webpki
  (`r2o_quic_http3.rs:890`) и при mismatch рвёт handshake. N —
  controller/QUIC-поведение.
- **`remember_live_failure` (httpsearch.c 520–550):** C хранит
  addr/binding/execution/request_ms и лимиты байт. `HttpSearchRecord`
  (`main.rs:4468-4472`) содержит только `cut/repeat_path/repro_gap`;
  `HttpLiveFailures` строится из `failed_http_programs` (выключенные
  привязки каталога), а не из живых отказов. N — HTTP-search state.

Raw-UDP (`udp_raw_*`, `d2k_udp_plan_send`) после проверки — **P**:
`IP_HDRINCL`/`IPV6_HDRINCL`/`SO_MARK` есть (`raw.rs:75,77,80`), но
`IP_NODEFRAG` отсутствует, mark обязателен, socket TTL get/set/restore
и `ECONNREFUSED → -2` не портированы. `d2k_vol_verdict_name` — P:
`r2o_label` содержит те же состояния, отличается только «цель»/«мишень».

## Классификация N (12 функций)

| Причина | Функции | Влияние на packet path |
|---|---|---|
| Тестовые хуки/экспорт | `d2k_tls12_prf_for_test`, `d2k_httpsearch_test_add_failures`, `d2k_httpsearch_test_add_records` | нет: тестовые/CLI-хуки |
| Диагностика/тексты/счётчики | `d2k_httpsprobe_lost`, `d2k_quic_props_findings`, `prop_word` | нет: CLI/лог-паритет |
| Серверная роль / C-API | `d2k_qw_retry_build`, `voice_ask_real` | нет: клиентский datapath не строит Retry и не отдаёт function pointer |
| Packet-path | `d2k_verify_tcp_timestamps_get`, `qp_recv_ttl` | **есть риск**: профиль TCP TS не проброшен в fetch/replay; TTL/hoplimit ответа не принимается |
| Controller/HTTP search | `d2k_qc_peer_name`, `remember_live_failure` | **есть риск**: нет `name_ok`/проверки цепочки как в C; нет живых отказов HTTP-search |

Итог: 12 N, из них 4 реально влияют на поведение (TCP TS, TTL, QUIC
cert-name, HTTP live failures), остальные 8 — тестовые/диагностические/
серверные. Raw-UDP/TTL-отправка теперь P, а не N.

## Проверки, выполненные в этой сессии

Агент-аудитор тесты не запускал. Координатор дополнительно прогнал на
закреплённом D2O `a378e230` и текущем R2O:

```text
test-controller-clienthello-differential.sh      PASS (56 кейсов)
r2o-tls-verify-differential.sh                   PASS 16/16
r2o-ech-rx-ladder-differential.sh                PASS
r2o-layered-rx-differential.sh                   PASS
r2o-quic-hello-differential.sh                   PASS
r2o-quic-local-address-differential.sh           PASS
r2o-discovery-quic-stop-differential.sh          PASS
r2o-quic-stun-watch-differential.sh              PASS
test-quic-http3-full-stage-differential.sh       18/18 PASS
test-quic-app-bytes-differential.sh              VERDICT|match
test-quic-budget-init-differential.sh            все значения совпали
test-quic-short-control-differential.sh          VERDICT|match
```

Эти прогоны покрывают ядро `hello/tls/ech/quic/http3/voice`, но не каждый
E-ряд: если в строке назван другой тест, он не перезапускался и помечен как
«тест есть, прогон не заявлен». Замена C-стеков на `rustls`/`quinn` остаётся
P: end-to-end исходы сверяются, record-layer и коды ошибок — нет.

## Что не проверялось

- Прогон `cargo test`, дифференциалов и cross-build OpenWrt/musl в этом проходе не выполнялся.
- Живой роутер, реальные провайдерские блокировки, Discord/YouTube production-сценарии, timing и память не измерялись.
- Для `E` доказательством считается наличие теста/дифференциала в репозитории; его актуальный результат не перепроверялся.
