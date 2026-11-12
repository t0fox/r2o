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
| `E` | 226 |
| `P` | 308 |
| `N` | 13 |
| `?` | 1 |

Доли: `E` — 41,24%, `P` — 56,20%, `N` — 2,37%, `?` — 0,18%.

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
| `wr16` | 57-60 | 4 | запись big-endian u16 без проверки границ | `hello.rs:534-547 write_len(width=2)` | **P** | C пишет в уже проверенный буфер; Rust `write_len` дополнительно отвергает `value>u16::MAX`. Для валидных длин совпадает; используется `splice_sni`/`rename_sni`. |
| `wr24` | 61-65 | 5 | запись big-endian u24 | `hello.rs:534-547 write_len(width=3)` | **P** | Rust `write_len` проверяет `value>0xffffff`; C полагается на вызывающего. |
| `skip_u8_vec` | 69-79 | 11 | пропуск TLS-вектора с 1-байтовой длиной | `hello.rs:198 hello_skip_u8_vec` | E | владелец `parse_hello_layout`; дифф ClientHello |
| `skip_u16_vec` | 80-90 | 11 | пропуск TLS-вектора с 2-байтовой длиной | `hello.rs:204 hello_skip_u16_vec` | E | владелец `parse_hello_layout`; дифф ClientHello |
| `parse_hello` | 128-272 | 145 | разбор записи ClientHello: длины, SNI-координаты, supported_versions, усечение расширений | `r2o-controller/src/hello.rs:213 parse_hello_layout` | E | побайтовый порт; дифф `test-controller-clienthello-differential.sh` (24+ кейсов: длины, усечения, SNI, ECH) |
| `d2k_hello_complete` | 274-281 | 8 | ровно одна полная запись+рукопожатие без хвоста | `hello.rs:344 hello_complete` | E | дифф ClientHello; unit `trailing_bytes_keep_shape_and_sni_but_not_complete` |
| `d2k_hello_shape` | 283-306 | 24 | MODERN/LEGACY/UNKNOWN по supported_versions | `hello.rs:366 hello_shape` | E | дифф ClientHello + unit `shape_distinguishes_modern_and_legacy_profiles` |
| `d2k_hello_sni` | 308-320 | 13 | координаты имени SNI | `hello.rs:383 hello_sni_bounds` | E | дифф ClientHello (sni-кейсы) |
| `d2k_hello_ech_offer` | 322-347 | 26 | валидация ECH-предложения и config_id | `hello.rs:391 hello_ech_offer` | E | дифф ClientHello (ech-duplicate/bad-type/enc-over/payload-mismatch) |
| `d2k_hello_alpn` | 349-375 | 27 | требует `d2k_hello_complete`; ищет extension 0x0010; проверяет list_len==elen-2, непустые имена; копирует **сырой** список; 1/0/-1 | `r2o_tls.rs:121-198 r2o_tls_client_hello_non_http_alpn` | **P** | **Подтверждённые расхождения:** (1) C копирует сырой ALPN-список и отдельно `d2k_alpn_is_http`; Rust сразу отбрасывает HTTP-протоколы и возвращает только non-HTTP (`None` при HTTP). (2) Rust отвергает ECH (extension 0xfe0d → `None`), C ECH не проверяет. (3) Rust требует `extensions_end == end` (нет хвоста после extensions), C допускает `exts_len` меньше остатка handshake. (4) Rust `Some([])` для ClientHello без ALPN; C `0` и `len=0`. Ошибочная форма: C `-1`, Rust `None`. Покрыто косвенно `tests/d2o_verify_differential.rs:990`. |
| `d2k_alpn_is_http` | 377-387 | 11 | список имён: `http/1.1`, `http/1.0`, `h2`, границы `q+1+l<=len` | `r2o_tls.rs:151-171` (фильтр внутри) | **P** | C отдельный предикат; Rust сравнивает имена с теми же тремя HTTP-протоколами внутри `r2o_tls_client_hello_non_http_alpn`. Для валидного списка эквивалентно; отдельного предиката/теста в Rust нет. |
| `splice_sni` | 409-452 | 44 | заменить SNI, обновить 6 длин: name/list/ext/exts/hs24/rec | `hello.rs:439-480 rename_sni` | **P** | C и Rust обновляют одни и те же шесть полей одной дельтой; Rust дополнительно валидирует результат `locate_sni_for_record` и длину `new_len`. C использует `memmove`/фиксированные буферы, Rust `Vec`. Точного C/Rust differential на rename нет; `raw_probe.rs:625`. |
| `hex_nibble` | 462-473 | 12 | hex-цифра → значение, иначе -1 | `hello.rs:501-517 decode_profile` (`to_digit(16)`) | **P** | C helper только для чистого hex; Rust `decode_profile` режет строку по `#`, выкидывает пробелы и декодирует. На встроенных профилях (Makefile уже вырезал комментарии) эквивалентно. |
| `hex_decode` | 480-498 | 19 | чётная длина, `n<=cap`, hex → байты; -1 при ошибке | `hello.rs:501-517 decode_profile` | **P** | C не принимает комментарии/пробелы (ожидает чистый hex), Rust `decode_profile` их допускает; результат `None` вместо кода. Для сгенерированных профилей эквивалентно. |
| `d2k_hello_rename` | 500-535 | 36 | обернуть CH в TLS-запись, `splice_sni`, вернуть тело; `n>0xffff` или `n+5>4096` → -1 | `hello.rs:439 rename_sni`, `:482 locate_sni_for_record` | **P** | Rust `rename_sni` работает с записью/префиксом и обновляет 6 длин; `locate_sni_for_record` отдельно обрабатывает запись длиннее handshake. C оборачивает/разворачивает запись. Для полного CH эквивалентно; unit/differential на rename нет. |
| `d2k_hello_without_sni` | 537-576 | 40 | требует complete/!truncated/have_exts/have_sni; удаляет server_name, обновляет ext/hs/rec | `r2k-core/src/quic.rs:1113 r2k_quic_client_hello_rename_sni(..., None)` | **P** | **Пробел TLS-пути:** C умеет удалять SNI из произвольного TLS ClientHello с пересчётом длин; Rust отдельной TLS-функции не имеет, только QUIC-путь `rename_sni(..., None)` (unit `quic.rs:1398-1420`). |
| `d2k_hello_from_profile` | 578-609 | 32 | modern/legacy профиль → `splice_sni`; UNKNOWN → -1 | `hello.rs:549-598 client_hello_from_profile` + `legacy/modern_client_hello` | **E** | Unit `shape_distinguishes_modern_and_legacy_profiles`, тесты профилей; используется fetch/httpsprobe. Rust `decode_profile` допускает `#`/пробелы, C ждёт чистый hex из `hello_profiles.inc`. |

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
| `read_record` | 287-345 | 59 | 5-байтный заголовок; `HTTP/` → отдельная ошибка; `rlen==0` или `>REC_MAX` → отказ; CCS без тела; открытая запись копируется; зашифрованная: nonce=salt+explicit, AAD seq/type/ver, AES-GCM, seq++ | rustls `read_tls` + `R2oTlsRecordTracker` | **P** | **Подтверждённое расхождение:** C распознаёт открытый `HTTP/` в первых 5 байтах и возвращает «не TLS: открытый HTTP-ответ»; в Rust `fetch`/rustls это общий `DecryptError`/`InvalidMessage`, отдельная проверка `HTTP/` есть только в `response.rs:572` (HTTPS-проба). `rlen==0/>18432`, CCS и AEAD-ошибки делегированы rustls с иными текстами; C-счётчики `rx_wire_bytes/rx_record_missing` ведутся в `read_exact`, у Rust — трекер. |
| `hs_next` | 355-407 | 53 | собрать handshake-сообщения из записей, CCS/alert | rustls handshake driver | P | собственная state-machine отсутствует |
| `ch12_build` | 415-485 | 71 | ClientHello: version 3,3, random, пустой session_id, 2 шифра ECDHE_*_AES128_GCM_SHA256, группы X25519/0x0017/0x0018, EC formats, 4 sigalg, padding ext 21 до `want_wire` | rustls ClientHello + `r2o_client_hello_wire_len` (`r2o_tls.rs:53-115`, `fetch.rs:157 wire_len`) | **P** | **Совпадает:** два cipher suite и набор/порядок групп X25519→SECP256R1→SECP384R1 (`r2o_tls.rs:86-102`). **Подтверждённые расхождения:** (1) C **не шлёт ALPN**, Rust `r2o_tls_client_connection` всегда `alpn_protocols=[http/1.1]` (`:59,110`); (2) C объявляет P-384, но `tls12_finish` его не реализует, Rust `SECP384R1` разрешён и принимается; (3) sigalgs C — 4 значения (0x0403/0x0804/0x0401/0x0203), rustls список шире; (4) padding C — расширение 21 с нулями, Rust — `r2o_client_hello_wire_len` (свой механизм). Дифференциал длины CH есть для tls13, отдельного tls12-кейса нет. |
| `d2k_tls12_connect` | 492-522 | 31 | создать сессию, собрать/отправить CH, пройти handshake | `r2o_tls.rs:53 r2o_tls_client_connection(tls12=true)` | P | end-to-end TLS1.2 сверяется `donor_and_r2o_reject_short_tls12_server_finished` и `tests/fetch.rs` (TLS12-сервер); ветки ошибок C (группа/шифр) в rustls иные |
| `d2k_tls12_resume` | 532-551 | 20 | продолжить handshake по сохранённому полёту сервера (downgrade из tls13.c) | rustls (автосогласование версии в одном соединении) | P | отдельного resume нет; downgrade-путь покрыт только косвенно |
| `tls12_finish` | 556-748 | 193 | ServerHello/Certificate/SKE/Done, ECDH X25519/P-256, PRF/ключи, CKE/CCS/Finished; отказ на P-384 SKE и клиентском сертификате | rustls handshake (TLS12) | **P** | Порт не построчный; шифры/группы конфигурации rustls совпадают, но **C объявляет P-384 и отвергает SKE с ним, Rust `SECP384R1` принимает** (header, п. 13). Ошибки «сервер требует клиентский сертификат», неподдерживаемая группа и тексты C/Rust не имеют differential; `donor_and_r2o_reject_short_tls12_server_finished` покрывает только короткий Finished. |
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
| `read_record` | 175-234 | 60 | 5-байтный заголовок; `HTTP/` → ошибка; `rlen==0/>REC_MAX` → отказ; CCS без тела; **до ключей** открытая запись копируется, **после ключей** открытый не-APPDATA тоже копируется (206-212); APPDATA: nonce=iv^seq, GCM, снятие нулевой набивки, внутренний тип | rustls `read_tls` + `R2oTlsRecordTracker` | **P** | **Подтверждённые расхождения:** C распознаёт открытый `HTTP/` отдельной ошибкой; в Rust fetch/rustls это общий `DecryptError`/`InvalidMessage` (проверка `HTTP/` только в `response.rs:572`). C после установки ключей принимает открытый Handshake (ветка `!encrypted || hdr[0]!=REC_APPDATA`), rustls такой пакет отвергает. Padding/внутренний тип/AEAD — внутри rustls с иными текстами. |
| `write_record` | 236-258 | 23 | зашифровать app data с внутренним типом и тегом | rustls `write_tls` | P | формат записи C не сравнивается с rustls побайтно |
| `traffic_keys` | 260-263 | 4 | HKDF-Expand-Label key/iv | rustls (key schedule) | P | собственной функции нет |
| `tls_connect_internal` | 265-523 | 259 | session_id 32, ALPN http/1.1 или клиентский список, padding до `want_wire-5`, `offer_tls12 = !ech`, CH/ECH, ServerHello, downgrade TLS1.2, X25519, HKDF-расписание, серверный полёт до Finished, cert-name из транскрипта, CCS+Finished, app keys | `r2o_tls.rs:53-115 r2o_tls_client_connection`, `:274 r2o_tls_ech_client_connection`, `fetch.rs:963-1045` | **P** | Основные параметры совпадают: session_id 32, ALPN http/1.1 по умолчанию, TLS1.3+TLS1.2 без ECH, только TLS1.3 с ECH, padding до wire_len, Finished проверяется только для ECH (`verify_finished=true`). **Отличия:** C сам шлёт пустой CCS перед Finished и собирает/проверяет ключи вручную; rustls делает это внутри. C при ServerHello 0x0303 вызывает `d2k_tls12_resume`, rustls автосогласует TLS1.2 в том же соединении. Ветки ошибок C (ECH not accepted, Finished mismatch, малая точка) заменены rustls и не сравнивались. |
| `d2k_tls_connect` | 525-529 | 5 | TLS1.3 без ECH, `client_alpn=0` → ALPN `http/1.1`, `offer_tls12=1` | `r2o_tls.rs:53 r2o_tls_client_connection` | **P** | Rust предлагает TLS1.3+TLS1.2 и `http/1.1`; C-профиль расширений уже (4 sigalg, padding ext 21, session_id 32). End-to-end покрыт TLS-дифференциалом; побайтового CH нет. |
| `d2k_tls_connect_alpn` | 531-536 | 6 | TLS1.3 с явным списком ALPN (`client_alpn=1`) | `r2o_tls.rs:63-115 r2o_tls_client_connection_with_alpn` | **E** | Unit `tests/r2o_tls.rs:101 клиентское_рукопожатие_предлагает_http11_alpn`, `:115 предлагает_наборы_донора`; Rust подставляет тот же `alpn_protocols`. |
| `d2k_tls_connect_ech` | 538-546 | 9 | ECH: origin + config обязательны, ALPN `http/1.1`, только TLS1.3, `verify_finished=true` | `r2o_tls.rs:274-306 r2o_tls_ech_client_connection` | **P** | Rust: cipher TLS13_AES_128_GCM_SHA256, группы X25519/SECP256R1, ECH Enable, ALPN http/1.1, `verify_finished=true`. C требует origin/config; живой ECH-путь не сверялся, replay покрыт `donor_and_r2o_require_server_hello_when_replaying_captured_ech`. |
| `d2k_tls_ech_accepted` | 548-548 | 1 | флаг `t->ech_accepted` | `fetch.rs:987-993 connection.ech_status()==Accepted` | **P** | C ставит флаг после `d2k_t13_ech_accepted`; Rust при ECH требует `EchStatus::Accepted` и иначе ошибка, затем `ech_accepted=Some(true)`. C-оракул для флага не подключён. |
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
| `d2k_t13_ch_build` | 197-357 | 161 | CH: session_id≤32 (байты random), cipher_suites 0x1301[+0xc02b+0xc02f], SNI, ec_formats, groups X25519[+P-256], 9 sigalg, supported_versions [1.3(+1.2)], ALPN wire/str, psk_dhe_ke, extra, key_share X25519, padding 0x0015 | `r2o_tls.rs:340-500 r2o_tls13_client_hello` | **E** | Построчный порт: те же cipher/группы/9 sigalg/ALPN/psk/extra/key_share/padding и длины. Rust дополнительно ограничивает `pad_to/extra/session_id` 4096/32 и проверяет NUL в SNI. Unit `tests/r2o_tls.rs:183` (padding), `:212` (session_id), `:101/115` (ALPN). |
| `d2k_t13_derive_secret` | 361-366 | 6 | Derive-Secret(Transcript-Hash) | rustls key schedule | P | собственной функции нет; KAT нет |
| `d2k_t13_schedule_hs` | 368-381 | 14 | early→handshake secret, c/s hs traffic | rustls key schedule | P | собственной функции нет |
| `d2k_t13_schedule_ap` | 383-394 | 12 | master secret, c/s ap traffic | rustls key schedule | P | собственной функции нет |
| `d2k_t13_finished_mac` | 396-403 | 8 | finished_key + HMAC(transcript) | rustls | P | собственной функции нет; C-векторов в Rust нет |
| `d2k_t13_sh_version` | 407-426 | 20 | версия из ServerHello.supported_versions (downgrade-детект) | rustls (version negotiation) | P | отдельной функции нет; downgrade-ветка C не сопоставлена |
| `d2k_t13_sh_parse` | 428-475 | 48 | разбор ServerHello, проверка 0x1301 и X25519 key_share | `r2o_tls.rs:200 r2o_tls_replay_client_hello` (критерий ServerHello) | P | replay-путь покрыт `donor_and_r2o_require_server_hello_when_replaying_captured_ech`; полный разбор отдан rustls |
| `d2k_t13_flight_next` | 479-490 | 12 | итератор handshake-сообщений в полёте | `r2o_tls.rs:200` (внутренний обход) | P | отдельной публичной функции нет |
| `ech_host_ok` | 492-508 | 17 | валидация публичного имени ECH | `ech.rs:464 r2o_ech_public_name` | P | логика близкая, но C-тестов/дифференциала на границы нет |
| `d2k_ech_config_parse` | 510-567 | 58 | ECHConfigList: outer length, version 0xfe0d, config_id, KEM 0x20, key_len 32, suites 0x0001/0x0001, max_name, public_name (`ech_host_ok`), extensions + mandatory unknown; первый валидный | `ech.rs:364-440 r2o_ech_select_config`, `:158 resolve_ech_config` | **P** | Поля/проверки совпадают: outer length, version, config_id, kem 0x20, key_len 32, suite `[0,1,0,1]`, public_name, extensions length, mandatory bit. **Отличия:** Rust обычно получает config из HTTPS RR (`resolve_ech_config`) и затем выставляет `origin_name`; C парсит wire-список. Выбор первого валидного/лимиты `wire` 512 и `ech_host_ok` vs `r2o_ech_public_name` не сверялись differential. |
| `hpke_extract` | 570-581 | 12 | HPKE-v1 labeled Extract: `HPKE-v1` + suite + label + ikm → HMAC | `hpke` crate (`ech.rs:63 R2oEchHpke`) | **P** | Собственная реализация заменена crate `hpke`; C-векторов HPKE в Rust нет. |
| `hpke_expand` | 583-596 | 14 | HPKE-v1 labeled Expand, один HMAC-блок, out≤32 | `hpke` crate | **P** | То же; собственной функции/векторов нет. |
| `ech_hpke` | 598-619 | 22 | X25519 base/shared, context=enc + pk, info=`tls ech\\0` + config, HPKE extract/expand key/base_nonce | `ech.rs:63-130` через `hpke` | **P** | C вручную считает enc/dh/secret/key/nonce; Rust `hpke::setup_sender` с `X25519HkdfSha256/AesGcm128`. Байтового differential нет. |
| `d2k_t13_ech_build` | 621-682 | 62 | inner CH с ECH-расширением, outer CH с public_name, HPKE enc/config_id, AES-GCM шифрование inner, padding | `r2o_tls.rs:274-306 r2o_tls_ech_client_hello` (rustls) | **P** | Rust строит ECH через rustls `EchMode::Enable`, а не повторяет байтовую раскладку C (inner/outer, offset `39+sid`, `42+plain+16`). ECH-дифференциал проверяет RX-лестницу/повтор, не байты CH; C-оракул на `d2k_t13_ech_build` не подключён. |
| `d2k_t13_ech_accepted` | 684-701 | 18 | accept_confirmation: SHA-256(inner + ServerHello с обнулёнными 8 байтами), HKDF `ech accept confirmation`, сравнение 8 байт | `fetch.rs:987-993 connection.ech_status()==Accepted` | **P** | Rust проверяет статус rustls; C вручную считает HMAC/HKDF и сравнивает `sh[30..38]`. C-оракул на accept_confirmation не подключён; дифференциал ECH-RX проверяет исход, не эту функцию. |

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
| `span_eq_ascii_ci` | 214-221 | 8 | длина + посимвольное сравнение `lower_ascii(p[i])` с `s[i]`; `s` обязан быть в нижнем регистре | `http_response.rs:303-318 parse_headers` (`eq_ignore_ascii_case`), `fetch.rs:1378` | **P*** | C не приводит `s` к нижнему регистру; все вызовы передают литералы в нижнем регистре. Rust `eq_ignore_ascii_case` приводит обе стороны, на этих вызовах эквивалентно. Отдельного хелпера нет. |
| `has_cf_challenge` | 227-246 | 20 | после строки статуса: имя `cf-mitigated` без регистра, обрезка SP/TAB, значение `challenge` без регистра | `fetch.rs:1378-1391 r2o_fetch_is_cloudflare_challenge` | **E** | Rust делит заголовки по `\n`, пропускает статус, снимает `\r`, ищет первое `:`, `trim_ascii` (включая SP/TAB) и `eq_ignore_ascii_case(b"challenge")`. Эквивалентно; end-to-end differential `donor_and_r2o_accept_youtube_sized_response_headers`/fetch-тесты. |
| `read13` | 273-276 | 4 | адаптер `d2k_tls_read` под общий `read_fn` | `fetch.rs` rustls `Stream::read` | **P*** | C-адаптер ради единого разбора тела 1.2/1.3; в Rust чтение напрямую. |
| `read12` | 278-281 | 4 | адаптер `d2k_tls12_read` | `fetch.rs` rustls `Stream::read` | **P*** | То же для TLS 1.2. |
| `body_read_reason` | 298-303 | 6 | если TLS не дал текст: `n==0` → «сервер закрыл соединение посреди тела», иначе «ошибка чтения TLS в теле» | `fetch.rs:1180-1195`, `:1210` reason | **P** | C пишет причину только при пустом `err`; Rust формирует `reason` уровня fetch («TLS-поток оборвался до завершения…», `ошибка чтения HTTP-ответа`). Классификация/тексты различаются, отдельного differential нет. |
| `body_say` | 304-306 | 3 | перезаписать `err` сообщением парсера | `http_response.rs` `invalid` + `fetch.rs` reason | **P*** | C хранит текст каждой ошибки chunked; Rust парсер выставляет только `invalid`, общий reason формирует fetch. |
| `body_feed` | 308-314 | 7 | первые 4096 байт тела в `prefix` + полное тело в `d2k_resource_feed` | `r2o_resource.rs:429-553 R2oResourceBodyTap`, `fetch.rs:1140-1175` | **E** | Rust `prefix` тоже 4096 (`r2o_resource.rs:551-556`), resource-scan — `R2oResourceScan`; префикс идёт в `r2o_fetch_http_outcome`. Покрыто `donor_and_r2o_accept_youtube_sized_response_headers`. |
| `body_byte` | 317-329 | 13 | из буфера или TLS по 8192, дедлайн `until`, `body_read_reason` | `http_response.rs:55-122 feed` + `fetch.rs` цикл чтения | **E** | C тянет байт из TLS по требованию; Rust скармливает прочитанные блоки конечному автомату. Семантика границ/дедлайна та же; дифференциал `test-http-chunk-framing-differential.sh` (привязан к D2O `a63d9641`, для a378 не перезапускался). |
| `body_exact` | 331-350 | 20 | дочитать ровно n, накопить bytes, feed | `http_response.rs:55-90` `FixedBody` | **E** | Rust уменьшает `remaining` и завершает при 0; extra-байты после complete игнорируются, как C. Тот же дифференциал. |
| `body_line` | 352-375 | 24 | CRLF-строка chunked/трейлера, максимум 127 байт; переполнение помечает `local_limit` | `http_response.rs:226-271 feed_line_byte` (`LINE_CAPACITY=128`) | **P** | **Подтверждённое расхождение:** C при строке >127 ставит `s->local_limit=1` («наш предел»); Rust помечает парсер `invalid`, а `fetch.rs` выставляет `local_limit` только для переполнения заголовков (`!headers_complete && len>=65536`), поэтому переполнение chunk-строки даёт `local_limit=false`. Само обрамление (CRLF, LF без CR, пустой размер) совпадает; дифференциал привязан к `a63d9641`. |
| `read_http_body` | 380-445 | 66 | 204/304 без тела; Content-Length; chunked с trailer; иначе до EOF; `body_expected` | `http_response.rs:55-271`, `fetch.rs:1210-1245` | **P** | Обрамление совпадает (204/304, CL, chunked, close, overflow, trailer). **Подтверждённое расхождение `body_expected`:** C для chunked и close-delimited выставляет `body_expected = body_bytes`; Rust `fixed_body_remaining()` даёт `Some` только для Content-Length, для chunked/close `body_expected=None` (в observation — 0). Влияет на `R2oVolumeObservation.body_expected`. |
| `read_status_buf` | 457-697 | 241 | статус HTTP/1.0-1.1 100-599, NUL/управляющие, cf-challenge, CL/TE/CE/Connection/Location, 1xx, 101, тело, `http_reply` | `http_response.rs:160-321` + `fetch.rs:1200-1245` | **P** | **Совпадает:** заголовки 64 КиБ, NUL/управляющие, статус-строка, 1xx, 101→invalid, CL/TE, CE (несколько→Other), Location (дубликат→framing invalid), cf-challenge, 451, resource-scan. **Подтверждённые отличия:** (1) C при `framing_valid=false` (дубликат/не-chunked TE, дубликат Location, CL+TE) **не читает тело** — `complete=false` по короткому замыканию; Rust parser продолжает принимать тело (кроме invalid TE/CL+TE), поэтому `body_bytes` может быть больше; (2) C `101` возвращает код 0, Rust сохраняет `status=101` при `invalid`; (3) C Location ограничен `location_cap` и при переполнении остаётся пустым, Rust `String` без предела; (4) C `conn_close` учитывает HTTP/1.0 без keep-alive и тело без CL/chunked, Rust `r2o_http_connection_closes` — только явный `Connection: close`. |
| `read_status_rd` | 699-728 | 30 | malloc 65537, diag-учёт `TCP_TLS_RX`, вызов `read_status_buf`, free | `http_response.rs:18-36` (массив в структуре) | **P** | Лимит 65536+1 совпадает. **Отличие:** C выделяет буфер на куче и ведёт `d2k_diag_memory_acquire/release`; Rust держит `[u8; 65537]` внутри `HttpResponseParser` и не учитывает его в диагностической памяти. |
| `d2k_http_read_response` | 730-737 | 8 | публичный API: memset результата, `read_status_rd` с NULL-полями | `http_response.rs:18 HttpResponseParser`, `http_search.rs:310 read_probe_response` | **P** | C-API отдаёт `status/body_bytes/complete/location/reply/local_limit/connection_close`; Rust использует парсер напрямую в fetch и `read_probe_response`, единого API с теми же полями нет. |
| `d2k_verify_probe` | 739-742 | 4 | пробa TLS1.3 по IP/SNI | `fetch.rs:844 r2o_fetch_with_phase_timeout` | P | обёртка над `d2k_verify_probe_on`; end-to-end differential |
| `write13` | 750-753 | 4 | адаптер записи TLS1.3 | `fetch.rs` rustls `Stream::write_all` | P | адаптер |
| `write12` | 755-758 | 4 | адаптер записи TLS1.2 | `fetch.rs` rustls | P | адаптер |
| `redirect_path` | 762-795 | 34 | only `https://` same host (или `host:443`) или путь `/…`; `?`→`/?…`; отказ на `<=0x20`, `0x7f`, `#`, путь ≥cap | `fetch.rs:2761-2809 r2o_fetch_same_origin_redirect` | **P** | Построчное совпадение: authority до `/ ? #`, host без регистра, `:443`, `?` → `/`, фильтр `<=0x20/0x7f/#`, предел 1024. Rust возвращает `String`, C пишет в буфер. Unit `same_origin_redirects_are_safe_and_portals_match_donor_signatures`; **C/Rust differential редиректов нет** (дифференциал проверяет только `GET /`). |
| `https_redirect_response` | 799-814 | 16 | внешний 301/302/303/307/308: `https://`, ≥1 alnum в authority, только `.-:[]`, остальное без `<=0x20`/`0x7f` | `fetch.rs:2811-2834 r2o_fetch_external_https_redirect` | **P** | Логика совпадает посимвольно (те же статусы, префикс, набор символов authority, фильтр хвоста). Unit `same_origin_redirects_are_safe_and_portals_match_donor_signatures`; C/Rust differential нет. |
| `d2k_verify_budget_set` | 822-822 | 1 | thread-local бюджет пакетов | `FetchOptions.budget_packets` | **P** | C `__thread g_verify_budget`, ставится на одну проверку; Rust — поле параметров `FetchOptions`/`packet_budget`. Глобального состояния нет; CLI-совместимость не проверялась. |
| `d2k_verify_budget_get` | 823-823 | 1 | чтение thread-local бюджета | `FetchOptions.budget_packets` | **P** | Читателя-функции нет, бюджет передаётся явно. |
| `d2k_verify_tcp_timestamps_set` | 826-828 | 3 | thread-local профиль -1/0/1, иное→-1 | `FetchOptions`/raw probe `offer_ts` | **P** | **Подтверждённое расхождение:** C thread-local профиль влияет на connect (`compose.c`/`verify_contact`); Rust `raw_probe.rs:673` читает sysctl для `host_offers_ts`, а `FetchOptions` такого профиля не имеет. |
| `d2k_verify_tcp_timestamps_get` | 829-829 | 1 | чтение thread-local профиля | нет | **N** | Прямого аналога глобального/поточного профиля нет; см. `tcp_timestamps_write`/`connect_with_tcp_profile` в `core-state.md` (N). |
| `d2k_verify_quic_form_set` | 837-840 | 4 | thread-local форма QUIC Initial: `n>0` копируется, иначе сброс | `FetchOptions.wire_len` + параметры `r2o_quic_http3_measure` | **P** | В C форма живёт в `__thread` и ставится на одну проверку; в Rust передаётся явным аргументом (`wire_len`, форма Initial) в `r2o_quic_http3_*`. Глобального/поточного состояния нет. |
| `d2k_verify_tcp_data_packets` | 850-865 | 16 | `getsockopt(TCP_INFO)`, len≥160, `data_segs_in` по смещению 152, `data_segs_out` 156, сумма; не Linux → -1 | `fetch.rs:2602-2633 r2o_tcp_counters` (Linux), `#[cfg(not(linux))]` default | **P*** | Rust использует `libc::tcp_info` и `offset_of!(tcpi_data_segs_out)+size_of`, проверяет len≥конца поля и складывает `tcpi_data_segs_in+out` с saturating; C — жёсткие смещения 152/156 и порог 160. На modern Linux эквивалентно; на старом ядре C вернёт -1, Rust — `None`. |
| `budget_say` | 877-883 | 7 | `r->budget=outcome`, текст в `budget_note` через vsnprintf | `R2oVolumePacketBudget` + `r2o_volume_observation` | **P** | C хранит код и человекочитаемую заметку; Rust — enum `Passed/Cut/NotApplicable` и поля observation, текста заметки нет. Формат/тексты не сверяются. |
| `gateway_header_end` | 885-890 | 6 | первый CRLFCRLF, иначе `(size_t)-1` | `fetch.rs:2002-2004 r2o_gateway_header_end` | **E** | Rust `windows(4).position(== b"\\r\\n\\r\\n")` → `Option<usize>`; эквивалентно. Differential `donor_and_r2o_validate_the_discord_gateway_websocket_like_d2o`. |
| `gateway_header_value` | 892-903 | 12 | первое `:`, имя ровно той же длины и без регистра, обрезка SP/TAB; портит строку | `fetch.rs:2006-2013 r2o_gateway_header_value` | **E** | Rust: `colon != name.len()` и `eq_ignore_ascii_case`, затем `r2o_gateway_trim`; C `strncasecmp` и обрезка. Эквивалентно; тот же differential. |
| `gateway_connection_upgrade` | 905-915 | 11 | список токенов через запятую, токен `Upgrade` без регистра | `fetch.rs:2015-2020 r2o_gateway_connection_upgrade` | **E** | Rust `split(',')` + `trim` + `eq_ignore_ascii_case`; C вручную пропускает SP/TAB/запятые и обрезает хвост. Эквивалентно; тот же differential. |
| `gateway_json_hello` | 917-974 | 58 | top-level `op` в JSON: строки с `\\`, вложенность, число ≤100000, разделитель `,`/`}`; opcode возвращается только при разборе | `fetch.rs:2053-2135 r2o_gateway_json_op` | **E** | Построчно совпадает: старт `{`, глубина, строки/escape, `depth==1`, ключ `op`, число с overflow>100000, проверка `,`/`}`; Rust возвращает `Option<u64>`. Тот же differential. |
| `gateway_fill` | 976-998 | 23 | дочитать до `need`, предел буфера, дедлайн, ошибки «закрыл/тайм-аут» | `fetch.rs:2147-2190 r2o_gateway_fill` | **E** | Rust ставит read timeout на остаток дедлайна, обрабатывает 0/тайм-аут/иную ошибку теми же исходами; тексты чуть иные. Тот же differential. |
| `request_gateway_websocket` | 1000-1123 | 124 | фиксированный GET Upgrade, 101, `Upgrade: websocket` ровно один, `Connection: Upgrade`, точный `Sec-WebSocket-Accept`, первый text-frame op=10 | `fetch.rs:2192-2335 r2o_gateway_websocket_exchange` | **E** | Совпадают запрос/accept, буфер 4096, статус 101, счётчики Upgrade/Accept, маски, длины 126/127, JSON op=10. Rust строже к переполнению `frame+payload` (`checked_add`). `donor_and_r2o_validate_the_discord_gateway_websocket_like_d2o`. |
| `read_eof` | 1132-1139 | 8 | обёртка: `n==0`→eof, `n<0`→failed, `n>0`→bytes | `fetch.rs:2650-2740` (`eof` bool + parser.body_bytes) | **P** | C считает байты и различает eof/failed в структуре; Rust держит `eof: bool`, байты — в `HttpResponseParser.body_bytes()`, ошибки — по `ErrorKind`. Отдельной структуры нет. |
| `budget_tcp` | 1146-1213 | 68 | need=budget*2; проверка пакетов/conn_close/роста; повтор точного `req`; `budget_requests`; молчание→CUT, закрытие/битый ответ→NOT_APPLICABLE | `fetch.rs:2650-2745 r2o_measure_http_packet_budget` | **P** | **Подтверждённые расхождения:** Rust повторяет запрос, собранный из `options.path` (`build_request`), а не фактически отправленный (после redirect); общий `deadline` вместо сброса на каждый повтор; нет `budget_requests` и `fd_peer_spoke`; таймаут всегда `Cut`, тогда как C различает молчание и закрытие/битый ответ; нет роста счётчика/`conn_close` — оба `NotApplicable` (совпадает). C/Rust differential бюджета отсутствует. |
| `fd_peer_spoke` | 1217-1222 | 6 | `poll` с `POLLIN`, `POLLHUP`, `POLLERR`, таймаут 0 после неудачного чтения | нет | **P** | **Подтверждённый пробел:** в Rust budget-цикле после ошибки чтения peer не опрашивается; EOF/ошибка сразу дают `NotApplicable`, таймаут — `Cut`. C различает «сервер закрыл» и «коробка молчит». |
| `fd_packets` | 1223-1223 | 1 | `d2k_verify_packets_hook(fd)` | `fetch.rs:2650` `packet_counter(&stream.sock.socket)` | **P*** | C подменяемый hook; Rust замыкание `impl FnMut(&TcpStream)->Option<u32>`, в production — `r2o_tcp_counters`. |
| `request_complete_page` | 1238-1245 | 8 | `request_page_budget(..., io=NULL, budget=0)` | `fetch.rs:804 r2o_fetch_with_encoding` | **P** | C-обёртка без бюджета; Rust отдельного режима нет — бюджет опционален (`packet_budget: Option<u32>`). End-to-end differential покрывает обычный GET. |
| `request_page_budget` | 1247-1343 | 97 | GET с редиректами (3), gzip/identity, Gateway-ветка, бюджет | `fetch.rs:863-1363`, `:2650` | **P** | Differential `donor_and_r2o_send_the_same_default_verification_request` проверяет только байты `GET /`. **Подтверждённые расхождения:** (1) C передаёт в `budget_tcp` фактически отправленный `req` (`verify.c:1315,1329`), Rust на повторе строит `build_request` из `options.path` (`fetch.rs:2686`); (2) C сбрасывает `deadline_ms` на каждый повтор, Rust — общий `deadline`; (3) C следует same-origin redirect при `body_framing_valid` без `body_complete` (`verify.c:1297`), Rust требует `complete` (`fetch.rs:1251`); (4) C-классификация CUT/NotApplicable и `budget_requests` не воспроизведены; (5) Gateway-ветка C выбирается по `initial_path==NULL && host=="gateway.discord.gg"`, Rust — по `options.gateway`/цели (`fetch.rs:1050+`). |
| `verify_contact` | 1349-1363 | 15 | при mark: bind family, `d2k_mark_hook`, затем contact с `g_verify_tcp_timestamps` | `fetch.rs:3017 connect_target`, `:3029 connect_marked` | **P** | mark ставится до connect, family 4/6 поддержаны. **Подтверждённое расхождение:** C передаёт `g_verify_tcp_timestamps` (thread-local профиль) в contact; Rust `connect_target/marked` профиль TCP timestamps не принимает. |
| `d2k_props_contact_on_family_tcp_profile` | 1360-1361 | 2 | ложное срабатывание парсера: хвост вызова внутри `verify_contact`, не определение | `fetch.rs:3017 connect_target` (владелец `verify_contact`) | ? | строки 1360-1361 — продолжение `return d2k_props_contact_on_family_tcp_profile(...)`; собственной функции нет |
| `verify_probe13_internal` | 1365-1442 | 78 | path-check, Host-контроль, family, contact с mark/TS-профилем, TLS1.3/ECH, name_ok, page+budget, rx-байты, data_packets; **сокет остаётся открытым** | `fetch.rs:863-1363`, `:3017 connect_target` | **P** | Совпадают path/имя, TLS/ECH, name_ok, page, бюджет, rx-байты/пакеты, `local_refusal`. **Подтверждённые расхождения:** (1) C после зонда освобождает TLS-сессию, но **не закрывает fd** — «иначе FIN потеряет ячейку потока в датапате» (`verify.c:1437-1440`); Rust `FetchResult` не содержит fd, `TcpStream` закрывается при выходе из fetch; (2) C передаёт `g_verify_tcp_timestamps` в contact, Rust TCP-профиль не принимает; (3) C валидирует Host только как байты >32/≠127, Rust `FetchOptions::validate` дополнительно отвергает `/ \\ @ [ ]` и проверяет `ServerName`. `r2o-tls-verify-differential.sh` покрывает уровень/TLS/name_ok/complete/байты, не fd. |
| `verify_probe13_on` | 1444-1449 | 6 | обёртка TLS1.3 без ECH (`ech=NULL`) | `fetch.rs:844 r2o_fetch_with_phase_timeout` | **E** | C-обёртка пути NULL; Rust `r2o_fetch_with_phase_timeout` → TLS1.3/TLS1.2 без ECH. `r2o-tls-verify-differential.sh`. |
| `ech_http_denial` | 1451-1460 | 10 | status 429 и level не DENIED/BLOCKPAGE → CHALLENGE, reason «не усиливать отказ» | `main.rs:14518-14535 r2o_ech_witness_transport_proof`, `:27000+` unit | **E** | Rust принимает ECH-witness при `status==429 && !Blocked && !LegalDenial` (или cf-challenge), `complete`, TLS/ECH/name_ok. Unit `ECH witness 429 rate limits must match the donor challenge classification`. |
| `d2k_verify_probe_ech_on` | 1462-1476 | 15 | требует config+origin; probe13 encoding 0 + ECH; затем `ech_http_denial` | `fetch.rs:738-760 r2o_fetch_ech_connected_stream` | **P** | Rust требует `EchConfig`, делает Identity-запрос, при `ech_status()!=Accepted` возвращает ошибку, `ech_accepted=Some(true)`; 429-классификация — в witness-слое. C вызывает probe13 с encoding 0 и отдельно `ech_http_denial`. Живой ECH-зонд C/Rust differential не покрыт. |
| `d2k_verify_probe_ech_origin_on` | 1478-1492 | 15 | `d2k_ech_resolve(origin,dns_mark)`, точное `outer_name == config.public_name`, затем probe с mark только при `use_fd<0` | `ech.rs:158-220 resolve_ech_config`, `:150 r2o_ech_tls_config`, `main.rs:14490+` | **P** | Rust резолвит HTTPS RR через `/etc/resolv.conf` + UDP/53 с SO_MARK и строит `R2oEchConfig{public_name,origin_name,config_list}`; **сверка `outer_name == public_name` в `r2o_ech_tls_config` не выполняется** — её делает вызывающий discovery. DNS-путь/точное сравнение C/Rust differential не покрыты. |
| `d2k_verify_replay_on` | 1499-1562 | 64 | contact с TS-профилем, poll/recv 16 байт, ServerHello `16 03 ?? 02` → HANDSHAKE+replay_proof, alert, иное/тишина | `fetch.rs:331-... r2o_verify_tls_replayed_client_hello`, `r2o_tls_replay_client_hello` | **E** | Rust повторяет сохранённый ClientHello и проверяет ServerHello по донорскому критерию; differential `donor_and_r2o_require_server_hello_when_replaying_captured_ech`, `...absolute_deadline_to_replayed_client_hello`. Отличие: C учитывает TCP TS-профиль, Rust — нет. |
| `d2k_verify_probe_on` | 1564-1568 | 5 | probe13 encoding=2, path NULL | `fetch.rs:844 r2o_fetch_with_phase_timeout` | **E** | `donor_and_r2o_send_the_same_default_verification_request`. |
| `d2k_verify_probe_alpn_on` | 1578-1625 | 48 | TLS-проба с ALPN клиента, без прикладного уровня | `fetch.rs:225-330 r2o_verify_tls_connected_stream_with_alpn` | **E** | Rust завершает handshake, возвращает TLS/name_ok/handshake_verified и reason «приложение не измерялось»; differential `donor_and_r2o_preserve_captured_mqtt_and_absent_alpn`. |
| `verify_probe12_internal` | 1636-1701 | 66 | полный зонд TLS1.2 (contact, handshake, page, бюджет) | `fetch.rs` с `tls12=true` | **E** | `donor_and_r2o_reject_short_tls12_server_finished` + `r2o-tls-verify-differential.sh`; те же отличия fd/TS-профиля, что у probe13. |
| `d2k_verify_probe12_on` | 1703-1708 | 6 | обёртка TLS1.2 | `fetch.rs` `tls12=true` | **E** | Тот же differential. |
| `d2k_verify_probe_identity_on` | 1710-1715 | 6 | `encoding=0` (identity), TLS1.2/1.3 | `fetch.rs:434 r2o_d2o_verification_encoding` | **P** | `r2o_d2o_verification_encoding` выбирает Identity по пути; отдельного differential на identity-зонд нет. |
| `d2k_verify_probe_gzip_on` | 1717-1722 | 6 | `encoding=1` (gzip), TLS1.2/1.3 | `fetch.rs:434` + `R2oFetchEncoding::Gzip` | **P** | То же; gzip-путь покрыт page/RX-тестами косвенно. |
| `d2k_verify_probe_baseline` | 1724-1742 | 19 | базовая проба: encoding/mark, TS-профиль, path=NULL | `fetch.rs:844` + `FetchOptions` | **P** | Композиция параметров; C-профиль TCP timestamps в Rust отсутствует. |
| `d2k_verify_probe_path_on` | 1744-1757 | 14 | проба с путём и encoding 0..2 | `FetchOptions.path` + `fetch.rs:804` | **P** | Путь/кодировка покрыты page-differential; отдельных C/Rust кейсов на все encoding нет. |
| `d2k_verify_close` | 1759-1764 | 6 | `close(fd)` результата | RAII `Drop`/`OwnedFd` | **P** | C закрывает fd явно после использования; Rust не возвращает fd — сокет закрывается в fetch (см. `verify_probe13_internal`). |
| `d2k_verify_probe_quic` | 1768-1771 | 4 | обёртка `d2k_verify_probe_quic_on(-1, …, path="/")` | `fetch.rs:514 r2o_fetch_quic` | **P*** | Тонкая обёртка; QUIC-дифференциалы отдельные (`r2o-quic-*`). |
| `quic_app_silent` | 1780-1791 | 12 | reason: «рукопожатие прошло, приложение молчит», got/wire или closed | `r2o_quic_http3.rs` `R2oQuicHttp3Result.error/status/body_bytes` | **P** | C формирует три варианта текста с `got`, `wire`, `closed`; Rust возвращает поля результата и error, текст собирает вызывающий. Формат/тексты не сверяются. |
| `h3_read_headers` | 1799-1811 | 13 | цикл recv до `d2k_h3_status`, `got`/`status`/`closed`; 1 если cap заполнен без HEADERS | `r2o_quic_http3.rs:690-780`, `r2k-core/src/h3.rs:317 status` | **P** | C сам копит байты и зовёт `d2k_h3_status` после каждого recv; Rust читает через `h3::client` (`recv_response`) с `max_field_section_size=R2O_QUIC_HTTP3_HEADER_LIMIT`. Лимит/цикл/классификация «нашего предела» различаются по форме; unit h3 покрывает разбор статуса. |
| `quic_recv_chunk` | 1816-1821 | 6 | `d2k_qc_stream_recv(..., 200 мс)` | `r2o_quic_http3.rs` `stream.recv_data` | **P*** | C-адаптер с куском 200 мс; Rust использует async `recv_data` под общим deadline. |
| `budget_quic` | 1836-1950 | 115 | `d2k_qbudget`: need=budget*2; порог + рост app-байт; новый поток sid+4 на повтор; CUT при молчании, NOT_APPLICABLE при закрытии/неразобранном ответе/отсутствии роста | `r2o_quic_http3.rs:543-590 R2oQuicHttp3Budget`, `:592-720 R2oQuicHttp3Stall` | **P** | **Совпадает:** need=budget*2 (`r2o_quic_http3_budget_datagrams`), порог датаграмм, требование роста app-прогресса, Passed/NotApplicable. **Отличия:** C явно повторяет запрос новым двунаправленным потоком (sid+4) и ждёт полный ответ каждого; Rust считает бюджет внутри одного ответа (budget.step на headers/body) и завершает по `progress_mark`+RTO; CUT/OneWay/Stalled считаются по-разному (`R2oQuicHttp3Stall`). C/Rust differential бюджета QUIC нет. |
| `qb_request` | 1953-1959 | 7 | собрать H3 GET host/path (512) и `d2k_qc_stream_send(sid, fin=1)` | `r2o_quic_http3.rs` `send_request` | **P** | C вручную кодирует H3-запрос; Rust строит `http::Request` и отдаёт `h3::client`. Формат запроса/заголовки проверяются косвенно. |
| `qb_recv` | 1960-1963 | 4 | приём потока 200 мс | `r2o_quic_http3.rs` `recv_data` | **P*** | Адаптер. |
| `qb_progress` | 1964-1966 | 3 | `d2k_qc_app_progress` → bytes/complete | `r2o_quic_http3.rs:278 app_bytes_load` + `recv_data` | **P** | C отдаёт накопленные app-байты и полный ответ; Rust считает `app_bytes` и отдельно состояние конца потока. |
| `qb_packets` | 1967-1971 | 5 | `d2k_qc_datagrams` → tx+rx | `r2o_quic_http3.rs` `r2o_quic_http3_datagrams` | **P** | C возвращает `tx+rx`; Rust `datagrams` считается из статистики Quinn (проверить знак/состав: tx+rx). Отдельного C/Rust differential нет. |
| `d2k_verify_probe_quic_on` | 1975-1979 | 5 | path="/" | `fetch.rs:514 r2o_fetch_quic` | **P*** | Обёртка. |
| `d2k_verify_probe_quic_path_on` | 1983-1989 | 7 | path, mark=0 | `fetch.rs:514`, `r2o_quic_http3_get` | **P*** | C mark=0 означает «без метки»; Rust `mark=None`. |
| `d2k_verify_probe_quic_path_mark_on` | 1991-2156 | 166 | QUIC/H3-зонд: host-контроль, opts (h3, port 443, deadline 5000, pad_to, form, use_fd, mark), connect, name_ok/local, fd, SETTINGS, пауза 400 мс, GET stream 0, HEADERS (64 КиБ), 451, app-байты до `D2K_QUIC_ARM_DATA_BYTES`, data_judge, бюджет, **сокет остаётся открытым** | `r2o_quic_http3.rs:725-1200 r2o_quic_http3_measure_with_wire_len`, `fetch.rs:514` | **P** | **Совпадает:** QUIC connect, TLS1.3, name_ok, H3 GET, статус, 451→DENIED, тело, бюджет, header limit. **Подтверждённые отличия:** (1) C шлёт управляющий поток SETTINGS и ждёт 400 мс перед запросом; Rust `h3_client.build` создаёт control stream, но отдельной паузы 400 мс нет; (2) C держит UDP-сокет открытым через `d2k_qc_release` (та же причина — ячейка потока), Rust `UdpSocket` потребляется и закрывается при выходе из measure; (3) C применяет `d2k_quic_arm_data_judge` с порогом `D2K_QUIC_ARM_DATA_BYTES`, Rust возвращает поля, а решение о APPLICATION принимает вызывающий слой; (4) C форма `g_verify_quic_form`, Rust — только `wire_len`; (5) C default deadline 5000 мс, Rust — `options.deadline`. Единого C/Rust differential нет. |

## core/verify_quic_replay.c (2 функции)

Повтор снятой пачки QUIC Initial с новым DCID и проверка ответа. Порт: `r2o-controller/src/quic_replay.rs` (`QuicReplayProbe::prepare`, reseal снимка, `r2k_quic_snapshot_verify_bound_response`) + `r2k-core/src/quic_snapshot.rs`. Тесты: `r2k-core/tests/quic_snapshot.rs`, `quic.rs` (verify/retry), контроллерные snapshot-тесты.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `replay_now_ms` | 23-27 | 5 | монотонное время, мс | `std::time::Instant` | **P*** | static-хелпер; C `CLOCK_MONOTONIC` в мс, Rust `Instant` с `Duration` — монотонность та же, единицы пересчитываются. |
| `d2k_verify_quic_replay_on` | 29-127 | 99 | parse→recid(reseal)→parse, family по `:`, port 443, connect/getsockname, отправить **все** датаграммы, poll/recv 1600 до 3000 мс, `d2k_quic_verify_bound`, HANDSHAKE/replay_proof | `quic_replay.rs:639-790 QuicReplayProbe::{prepare,from_socket,run,r2o_run_inner}`, `quic_snapshot.rs:79-115 reseal`, `:116-124 verify_bound_response` | **P** | **Совпадает:** reseal всех датаграмм под один DCID, проверка bound-ответа (Initial/Retry) по первому пакету, HANDSHAKE/replay_proof, `foreign_responses`. **Подтверждённые отличия:** (1) C reseal'ит один раз за вызов и шлёт `out`; Rust `r2o_run_inner` **перезапечатывает заново на каждый `run`** (`:744-760`), т.е. новый DCID на повторный запуск; (2) C `deadline_ms` без верхнего предела (default 3000), Rust обрезает до 10 с (`R2O_QUIC_REPLAY_MAX_TIMEOUT`); (3) C при ошибке parse/reseal закрывает переданный `use_fd`, Rust владеет `UdpSocket` и закрывает его Drop; (4) C `static __thread fresh[D2K_SHAPE_MAX]`, Rust `Vec`; (5) C `inet_pton` + `connect`, Rust `SocketAddr` с проверкой `port!=0/ip!=unspecified`. C/Rust differential именно для verify-quic-replay нет. |

## core/httpsprobe.c (22 функции)

Асинхронный HTTPS-зонд (TCP 443 → first flight → TLS1.3/1.2) и кэш состояний `d2k-https`. В R2O: `r2o-controller/src/https_probe.rs` (воркер, кэш, save/load), `response.rs` (классификация и TLS-проба). Дифференциал: `scripts/test-controller-httpsprobe-differential.sh` (C `httpsprobe.o` против `examples/tg_cl13_httpsprobe_trace.rs`, кэш/состояния/загрузка).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_https_classify` | 32-40 | 9 | REFUSED→CLOSED; не CONNECTED→UNCONFIRMED; !server_tls→TLS_BLOCKED; !tls_ok→UNCONFIRMED; peer 1→SERVED, 0→OTHER_NAME, иначе UNCONFIRMED | `response.rs:90-107 classify_https_probe` | **E** | Построчно совпадает; differential httpsprobe + unit `classify_matches_d2o_https_state_machine`. |
| `d2k_https_upgrade` | 42-44 | 3 | SERVED/TLS_BLOCKED | `response.rs:149 should_redirect` | **E** | Совпадает; differential httpsprobe. |
| `d2k_https_ttl` | 46-55 | 10 | SERVED 6ч, TLS_BLOCKED 1ч, CLOSED/OTHER_NAME 30м, UNCONFIRMED 2м, иначе 0 | `response.rs:129-138 ttl_seconds` | **E** | Совпадает; differential httpsprobe. |
| `d2k_https_state_name` | 57-67 | 11 | served/closed/other-name/unconfirmed/probing/tls-blocked/unknown | `response.rs:109-126 stored_name/from_stored_name` | **E** | Для сохраняемых состояний имена совпадают; `probing`/`unknown` C печатает, но `save` их пропускает; Rust `from_stored_name` их отвергает. differential httpsprobe. |
| `mono_ms` | 69-73 | 5 | `CLOCK_MONOTONIC` в мс | `std::time::Instant` | **P*** | Инфраструктурный хелпер; единицы/происхождение те же, обёртки нет. |
| `https_connect` | 77-145 | 69 | socket, SO_MARK только при `mark!=0`, fcntl nonblock, connect+poll 1500, восстановление flags; refused на ECONNREFUSED/EHOSTUNREACH/ENETUNREACH, иначе NO_ANSWER | `response.rs:289-312 probe_socket`, `:254-287 connect_until`, `:540-570 https_socket` | **P** | **Подтверждённые отличия:** (1) C порт из глобального `d2k_https_probe_port` (по умолчанию 443, тесты меняют), Rust всегда `address.port()` (443); (2) C не ставит SO_MARK при `mark==0`, Rust `expected_mark=mark.unwrap_or(0x2d)` и затем **проверяет** mark через `get_socket_mark`; при `None` уходит 0x2d; (3) C при ошибке SO_MARK → NO_ANSWER, Rust → Unconfirmed; (4) C восстанавливает исходные flags, Rust `set_nonblocking(false)` + TCP_NODELAY. Коды refused/unreachable совпадают. Live-дифференциала с refused/EINTR нет. |
| `https_tls` | 148-165 | 18 | TLS1.3 или TLS1.2 отдельными стеками, peer_name из сертификата | `response.rs:373-380 https_connection`, `:606-692 probe_https_state` | **P** | C явно делает **два** соединения: TLS1.3, затем TLS1.2; Rust один rustls-connection с `with_protocol_versions(&[TLS13, TLS12])` и ручной проверкой имени. Итоговые состояния совпадают, но число CH/порядок попыток иной. Live-путь покрыт `tests/response.rs`, не C-оракулом. |
| `first_flight` | 171-201 | 31 | **донорский modern ClientHello** из `d2k_hello_from_profile`, send, poll 2000 мс, recv 2 байта, принять `0x16/0x15` + `0x03` | `response.rs:572-605 receives_tls_record` | **P** | **Подтверждённое расхождение:** C шлёт профиль `D2K_SHAPE_MODERN` (`hello_profiles.inc`), Rust — **ClientHello, сгенерированный rustls** (`https_connection`). Критерий первого байта тот же. Ошибка сборки CH у C → UNCONFIRMED, у Rust любая неудача → TLS_BLOCKED. Unit `https_probe_does_not_accept_a_plain_http_listener`. |
| `d2k_https_probe_real` | 203-243 | 41 | connect 1500; first flight; TLS1.3→1.2 в общем deadline 2500; при повторном отказе connect → NO_ANSWER; classify | `response.rs:606-692 probe_https_state` | **P** | **Совпадает:** таймауты 1500/2500/2000, first flight, TLS-проверка, состояния. **Отличия:** C два отдельных TLS-соединения (1.3 и 1.2) и склейка причин; Rust одно rustls-соединение; C при `ff<0` → UNCONFIRMED, Rust при неудаче CH → TLS_BLOCKED; C mark=0 отключает метку, Rust None→0x2d. C/Rust differential live-пробы нет. |
| `host_ok` | 274-283 | 10 | 1..253, только ASCII alnum/`-`/`.` | `https_probe.rs:86-93 cache_host_ok` | **E** | Построчно совпадает; differential httpsprobe (bad-host/uppercase/dots). |
| `cache_find` | 285-290 | 6 | линейный поиск без регистра | `https_probe.rs:94-100 cache_find` | **E** | Совпадает (`eq_ignore_ascii_case`); differential httpsprobe. |
| `cache_put` | 292-312 | 21 | обновить/вставить; пустой слот, затем самый старый stamp, **пропуская активный PROBING**; если нет — слот 0 | `https_probe.rs:279-318 insert_cache` | **E** | Rust не хранит PROBING в кэше (отдельный `pending`), поэтому пропуск активного зонда эквивалентен; жертва — min stamp. differential httpsprobe (capacity 130, duplicates). |
| `worker` | 314-349 | 36 | очередь job → probe → UNKNOWN/PROBING→UNCONFIRMED, ttl, done[17] + wake; при полном done `lost++` | `https_probe.rs:130-186` worker thread | **P** | **Подтверждённые отличия:** (1) C при полном `done` **отбрасывает** результат и инкрементит `lost`; Rust использует `sync_channel(16)` и **блокирующий `send`**, поэтому при неразобранных результатах воркер встаёт, счётчика потерь нет; (2) C отдельно хранит PROBING в кэше, Rust — `pending`; (3) C worker не завершается по idle, Rust завершается через 10 с (`HTTPS_PROBE_IDLE`) и перезапускается при submit. |
| `d2k_httpsprobe_new` | 351-375 | 25 | calloc, mutex/cond, pipe nonblock, pthread; ошибка pipe/потока → free/NULL | `https_probe.rs:131-188 new/r2o_ensure_worker` | **P** | Rust лениво создаёт поток и каналы; `new` не может вернуть NULL, при ошибке spawn `submit` вернёт false. C требует pipe+поток сразу. |
| `d2k_httpsprobe_free` | 377-391 | 15 | stop+broadcast+join, close pipe, destroy, free | `https_probe.rs:464-471 Drop` | **P*** | RAII: закрытие jobs, join; pipe отсутствует. Порядок остановки эквивалентен по смыслу. |
| `d2k_httpsprobe_wake_fd` | 393-395 | 3 | fd пробуждения для poll | нет (Rust — канал/`try_result`) | **P*** | Механизм заменён; fd-контракт не нужен. |
| `d2k_httpsprobe_portal` | 397-428 | 32 | проверка host/family/addr; cached upgrade + !answered → resend_ttl rc=2; иначе при месте в очереди job, PROBING на 10 с, rc=1; иначе 0 | `https_probe.rs:189-235 submit`, `main.rs:18992-19045` | **P** | **Совпадает:** host/family, дедуп pending/кэш, очередь 16, отказ при полной очереди. **Отличия:** C возвращает rc=2 и TTL для cached upgrade, Rust отдельно `cached_state`+`verified_names`; C ставит PROBING-запись, Rust `pending`; C `answered` проверяется внутри, Rust — в `target_from_portal`. C/Rust differential очереди нет. |
| `d2k_httpsprobe_done` | 430-449 | 20 | забрать до cap результатов, cache_put с полным ttl, memmove, повторный wake | `https_probe.rs:236-251 try_result`, `main.rs:17032-17060` | **P** | **Подтверждённое расхождение:** C отдаёт пачку и для **каждого** результата хранит полный `ttl_s`; Rust `try_result` отдаёт по одному и кладёт в кэш полный `state.ttl_seconds()`, но в `HttpsProbeResult.ttl_seconds` для не-upgrade состояний записывает **0**. `main.rs:17033` затем безусловно шлёт `SET_HTTPS(host, ttl_seconds)`, т.е. **SET_HTTPS с TTL=0** для closed/other-name/unconfirmed; C для них `SET_HTTPS` не шлёт, а вызывает `http_search_portal`. `lost` также отсутствует. |
| `d2k_httpsprobe_state` | 451-458 | 8 | cached state, если не истёк, иначе UNKNOWN | `https_probe.rs:226-231 cached_state` | **E** | Rust возвращает `Option`, C — UNKNOWN; differential httpsprobe + unit `cached_state_and_pending_lookup_follow_host_and_expiry`. |
| `d2k_httpsprobe_lost` | 460-466 | 7 | счётчик потерянных результатов | нет | **N** | В `https_probe.rs` счётчика нет; Rust-воркер блокируется на полном канале вместо потери. |
| `d2k_httpsprobe_save` | 476-505 | 30 | `d2k-https 2 <wall_s>`, все не-PROBING и не истёкшие, tmp+fflush+fsync+rename | `https_probe.rs:399-462 save_cache` | **E** | Формат/набор состояний/атомарность совпадают; Rust использует уникальный `.new.pid.nonce` и fsync каталога, C — `path.tmp`. differential httpsprobe + round-trip unit. |
| `d2k_httpsprobe_load` | 507-564 | 58 | v1/v2, откат при `written>wall_s`, strict `%lld`, TTL-кламп, upgrade→push | `https_probe.rs:320-397 load_cache/load_verified` | **E** | Формат/проверки/TTL-кламп совпадают; C push-массив заменён `load_verified`, причина «из кэша на диске» формируется вызывающим. differential httpsprobe (16+ кейсов). |

## core/httpup_logic.c (15 функций)

Логика HTTP-upgrade/порталов: безопасный разбор запроса, распознавание провайдерского портала, ответ 307. Перенесена почти построчно в `crates/r2k-core/src/httpup.rs` и используется контроллером/датапасом. Векторы — `crates/r2k-core/tests/httpup.rs`; косвенно участвует в `scripts/r2o-http-search-differential.sh` (линкуется `httpup_logic.o`).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `ascii_alnum` | 16-19 | 4 | ASCII-буква/цифра | `r2k-core/src/httpup.rs:390 valid_dns_host` (встроено `is_ascii_alphanumeric`) | **E*** | Хелпер; владелец `dns_host` → `valid_dns_host`, тесты `httpup.rs:78,108`. |
| `dns_host` | 21-35 | 15 | 1..253, без ведущей/хвостовой точки, метки 1..63, LDH, без ведущего/хвостового `-` | `httpup.rs:390-410 valid_dns_host`, `:350-357 valid_http_name_host` | **P** | Сам `valid_dns_host` совпадает с C. **Подтверждённое расхождение:** `parse_plan_request` вызывает `valid_http_name_host`, который дополнительно отвергает **последнюю метку из одних цифр** (`127`, `1.2.3.4`); C `dns_host` такие имена принимает. `tests/httpup.rs:108 rejects_ambiguous...`. |
| `host_equal` | 37-44 | 8 | снять по одной хвостовой точке, сравнить без регистра, непустые | `httpup.rs:468-472 same_host` | **E** | Совпадает; `tests/httpup.rs:78,69`. |
| `known_portal_host` | 46-51 | 6 | 6 известных порталов | `httpup.rs:492-502 known_portal_host` | **E** | Список и `same_host` совпадают; `tests/httpup.rs:78`. |
| `find_crlf` | 53-58 | 6 | первый CRLF до `end` | `httpup.rs:382-388 find_crlf` | **E*** | Rust `windows(2)` + `checked_add`; эквивалентно; владелец `parse_request`, тесты `:11,108`. |
| `parse_request` | 60-130 | 71 | GET/HEAD, HTTP/1.0/1.1, origin-target без控制/`#`, один Host, CL только `0`, запрет TE, порт только `:80`, финальный CRLFCRLF | `httpup.rs:220-229 parse_request`, `:231-344 parse_plan_request` | **P** | **Совпадает:** метод/версия/target, Host/CL/TE, `:80`, хвостовая точка, точный конец заголовков. **Подтверждённое расхождение:** Rust `parse_plan_request` помечает `boundary_known=false` при любом control-байте в строке заголовка и при невалидном HTTP-token имени; затем `parse_request` требует `end_offset==Some(header_len)` и отвергает запрос. C неизвестные/битые заголовки игнорирует (кроме Host/CL/TE) и control-байты не проверяет. Rust также отвергает all-digit last label (см. `dns_host`). `tests/httpup.rs:11,108`. |
| `d2k_httpup_request_safe` | 132-135 | 4 | предикат безопасного запроса | `httpup.rs:164-166 request_safe` | **P** | Тонкая обёртка; наследует более строгий `parse_request` Rust. `tests/httpup.rs:11`. |
| `build_redirect` | 137-149 | 13 | `HTTP/1.1 307`, `Location: https://host+target`, `Cache-Control: no-store`, `Connection: close`, `Content-Length: 0`, `X-D2K-HTTP-Upgrade: <reason>` | `httpup.rs:504-516 build_redirect` | **P** | **Подтверждённое расхождение:** C пишет `X-D2K-HTTP-Upgrade: provider-portal`, Rust — **`X-R2O-HTTP-Upgrade: provider-portal`**. Остальные строки/порядок/CRLF совпадают. Rust-тест `builds_the_exact_https_redirect...` фиксирует именно `X-R2O`, т.е. расхождение закреплено тестом. |
| `portal_marker` | 151-170 | 20 | 8 маркеров по меткам хоста | `httpup.rs:474-490 portal_marker` | **E** | Список/разбиение/регистр совпадают; `tests/httpup.rs:78`. |
| `redirect_location_host` | 172-190 | 19 | http/https, authority до `/ ? # :`, `dns_host` | `httpup.rs:452-466 parse_location_host` | **E** | Совпадает; `tests/httpup.rs:69`. |
| `portal_answer` | 193-225 | 33 | HTTP/1.x 301/302/303/307/308, ровно один Location, другой host, known/marker | `httpup.rs:411-450 portal_host` | **E** | Статус/дубликат Location/`same_host`/known+marker совпадают; C дополнительно требует `line_end==p` (пустая строка), Rust останавливается на пустой строке. `tests/httpup.rs:49,57`. |
| `d2k_httpup_portal_response` | 227-238 | 12 | parse_request + portal_answer → 307 provider-portal | `httpup.rs:191-199 portal_response` | **P** | Логика совпадает, но наследует расхождение `build_redirect` (`X-D2K`/`X-R2O`) и более строгий `parse_request`. `tests/httpup.rs:49`. |
| `d2k_httpup_request_target` | 240-251 | 12 | host и origin-target | `httpup.rs:169-173 request_target` | **P** | Совпадает для валидного запроса; наследует строгий разбор Rust (битые заголовки/all-digit host). `tests/httpup.rs:31`. |
| `d2k_httpup_portal_location` | 253-262 | 10 | host портала из upstream | `httpup.rs:201-206 portal_location` | **E** | Логика `portal_host`+known/marker совпадает; `tests/httpup.rs:69`. |
| `d2k_httpup_redirect_https` | 264-277 | 14 | готовый 307 по host/target, только `target[0]=='/'`, пределы 255/2047 | `httpup.rs:208-217 redirect_https` | **P** | **Подтверждённые отличия:** (1) Rust `valid_dns_host(host)` и запрет `<=0x20/0x7f/#` в target; C проверяет только длины и первый `/`; (2) заголовок `X-R2O` вместо `X-D2K`. `tests/httpup.rs:126`. |

## core/httpsearch.c (66 функций)

Поиск HTTP-обхода: база → свои планы → split/checksum/продукт → fallback, с подтверждением APPLIED и живой привязкой. В R2O: `r2o-controller/src/http_search.rs` (judge, кандидаты, id, чтение ответа) и `main.rs` (`HttpSearchRecordCache:4464`, `run_http_search_task:22901`, `begin_http_search:19542`, `http_baseline_failure_action:22853`). Дифференциалы: `scripts/r2o-http-search-differential.sh` (набор C-фикстур `d2o_http_*_differential.c` против Rust-тестов), `tests/http_search.rs`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `mono_ms` | 37-41 | 5 | монотонное время, мс | `std::time::Instant` | P | инфраструктурный хелпер |
| `d2k_hs_answer_name` | 43-57 | 15 | русское имя ответа | `http_search.rs:17 enum Answer` (без функции имени) | P | текст причины формируется в `main.rs`; дословного соответствия нет |
| `d2k_hs_judge` | 61-95 | 35 | классификация HTTP-ответа: garbage/injected/decoy/early/real | `http_search.rs:850 judge` | E | differential `scripts/r2o-http-search-differential.sh` + inline `mod d2o_http_judge_differential` |
| `hs_path_ok` | 99-107 | 7 | допустимый путь для повтора | `http_search.rs:300 repeatable_path` | E | test `main.rs:28365 r2o_http_search_сохраняет_путь_повторяемого_запроса` |
| `hs_read` | 110-130 | 21 | чтение сокета с таймаутом, временем первого байта и префиксом | `http_search.rs:310 read_probe_response` | P | тайминги/префикс не сопоставлены побайтово |
| `d2k_hs_probe_run` | 132-246 | 115 | один зонд: connect, тайминги, 2 GET, classify, keep-alive | `main.rs:23385 run_http_baseline`, `http_search.rs:310 read_probe_response`, `:527 parse_response_head` | **P** | C-фикстура baseline покрывает только нормальный keep-alive (2 GET, REAL). **Пробелы:** C переопределяет ответ в `INJECTED` при `reply.outcome == D2K_HTTP_BLOCKED` (`httpsearch.c:232`, `verify.c:652`), Rust тело не классифицирует — 403 с телом РКН останется REAL; 101 C считает CUT (`verify.c:660-662`), Rust — `Empty`/complete (`http_search.rs:338-341,590`); неверный CL/TE C возвращает как CUT, Rust — `InvalidData`/локальный отказ; C копит в `head` и тело, Rust judge видит только заголовки; нет общего дедлайна `3*d2k_hs_probe_ms`. |
| `d2k_hs_candidate_count` | 253-253 | 1 | число встроенных кандидатов | `http_search.rs:627 candidate_keys` | **P** | **Расхождение:** C `CANDS[]` содержит 4 элемента — `split, disorder, fake-badsum, fake-seqshift` (`httpsearch.c:250-254`); Rust возвращает 5 в другом порядке: `split, fake-badsum-whole, fake-badsum, disorder, fake-seqshift` (`http_search.rs:7-13`). `fake-badsum-whole` в C — отдельный вопрос `HQ_PRODUCT`, а не элемент `CANDS`. Rust-тест `tests/http_search.rs:196` утверждает расширенный список, а не C-список. |
| `d2k_hs_candidate_key` | 254-254 | 1 | ключ кандидата по индексу | `http_search.rs:627 candidate_keys` | **P** | Тот же рассинхрон: индексы 0..3 не совпадают с C (`split, disorder, fake-badsum, fake-seqshift`), на индексе 1 Rust отдаёт `fake-badsum-whole`; C-дифференциала публичного списка нет. |
| `poison_key_spec` | 258-287 | 30 | разбор `fake:` спецификации (ttl/badsum/seqshift, порядок) | `http_search.rs:796 poison_key_spec` | E | test `tests/http_search.rs:268 accepts_only_measured_poison_keys...` |
| `known_key` | 289-294 | 6 | известный ключ плана/кандидата | `http_search.rs:631 candidate_key_from_plan_text` | E | test `:210 recovers_only_exact_supported_keys_from_saved_plan_text` |
| `d2k_hs_candidate_text` | 296-324 | 29 | `d2k-plan 1 11`, id, `proto tcp http`, fake payload/poison/repeats, split, disorder+pace | `http_search.rs:686-717 candidate_text` | **P** | **Подтверждённое расхождение формата:** C пишет `d2k-plan 1 11`, Rust — `r2o-plan 1 11`. Эффекты/директивы (`payload 1`, `poison 1`, `fake … repeats=1`, `split sni_middle +0`, `order reverse`, `pace 12000`) совпадают; Rust-тесты `:227,235,243,260` фиксируют R2O-заголовок, C-байтового differential нет. |
| `stable_id` | 327-332 | 6 | FNV-1a по префиксу `d2k-http:` и ключу, 16 байт | `http_search.rs:780-795 stable_id` | **P** | **Подтверждённое расхождение:** C хеширует `"d2k-http:"`, Rust — `"r2o-http:"` (`http_search.rs:784`), поэтому для одного ключа получаются **разные 16-байтные id**. Тест `derives_the_r2o_stable_id_for_a_candidate` закрепляет R2O-id, C-вектора нет. |
| `fresh_id` | 334-352 | 19 | случайный id с fallback на PRNG | `rand`/`getrandom` в `main.rs` | P | отдельной функции и fallback-ветки нет |
| `say` | 442-450 | 9 | лог через ops.say | `main.rs` logging/diagnostics | P | формат логов не сверяется |
| `host_ok` | 452-466 | 15 | валидация host, запрет числового TLD | `main.rs`/`http_search.rs` валидация имени | P | отдельного предиката с тем же правилом нет |
| `rec_find` | 468-475 | 8 | поиск записи host+family | `main.rs:4464 HttpSearchRecordCache` (HashMap) | P | структура заменена HashMap |
| `rec_get` | 477-496 | 20 | создание записи с лимитами памяти/учётом отказов | `main.rs:4464 HttpSearchRecordCache` | P | лимиты `D2K_HS_RECORD_MAX_BYTES` не сопоставлены |
| `same_program` | 500-508 | 9 | эквивалентность планов через TLV | `http_search.rs:775 candidate_program` | P | сравнение программ есть, TLV-путь иной; test только на алиасы |
| `failed_live` | 510-519 | 10 | поиск живого отказа по ключу/адресу | нет | **N** | `HttpSearchRecord` (`main.rs:4468-4472`) содержит только `cut/repeat_path/repro_gap`; массива `failures` и полей addr/binding/execution/request_ms нет. `failed_http_programs` читает выключенные привязки каталога, а не живые отказы. N вместе с `remember_live_failure`. |
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
| `d2k_httpsearch_diagnostic_counts` | 687-706 | 20 | счётчики записей/очереди/отказов/лимитов | `diagnostics.rs:449-481` поля, `main.rs:16751-16762` заполнение | P | `http_failure_bytes` жёстко 0 (`main.rs:16762`), а `http_failure_limit_hits/record_limit_hits/alloc_failures` остаются 0, потому что массивов отказов и счётчиков нет (`diagnostics.rs:474-481`). Часть полей заполняется, часть — нет. |
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
| `d2k_httpsearch_save` | 1444-1471 | 28 | атомарная запись `d2k-http-plans 1`: `host family key wall`, `fflush/fsync/fclose/rename`, `unlink(tmp)` при ошибке | `main.rs`/`catalog.rs` persist (JSON-каталог) | **P** | C пишет отдельный файл `d2k-http-plans 1` с точным форматом и атомарной заменой; Rust сохраняет каталог JSON, файла и формата `d2k-http-plans` нет. C/Rust durable-дифференциал `d2o_http_durable_differential.c` сравнивает только маркер `persisted_before_flush=yes`, а не содержимое/формат файла; тест `confirmed_http_candidate_is_durable_before_catalog_flush_interval` проверяет каталог. **Фактические строки в a378 — 1446–1473; в реестре/CSV 1444–1471 (сдвиг extractor +2, см. `deep-core-verify.md`).** |
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

## Углублённая сверка: verify/volume/voice (114)

- **`verify.c` (74):** E — `ech_dns_name`/`d2k_ech_resolve` (DNS),
  `find_hdr_end/eol`, `lower_ascii`, `has_cf_challenge`, `body_feed/
  byte/exact/line`, `read_http_body`, `redirect_path`,
  `https_redirect_response`, `gateway_*`, `request_page_budget`,
  `verify_probe13_internal/on`, `d2k_verify_replay_on`,
  `d2k_verify_probe_on/alpn_on`, `verify_probe12_internal/on`:
  подтверждены `r2o-tls-verify-differential.sh` (16/16),
  `test-http-chunk-framing-differential.sh`,
  `donor_and_r2o_send_the_same_default_verification_request`,
  `donor_and_r2o_validate_the_discord_gateway_websocket_like_d2o`,
  replay/ECH differentials. **P:** `read_status_buf/rd` (1xx/101/
  дубликаты Location/Connection не все сверены); `d2k_verify_budget_set/
  get` (C глобальный бюджет, Rust `FetchOptions.budget_packets`);
  `d2k_verify_tcp_timestamps_set` (нет глобального переключателя);
  `d2k_verify_quic_form_set` (форма передаётся явно, не глобально);
  `d2k_verify_tcp_data_packets` (TCP_INFO поля есть, ioctl/структура не
  сверены); `budget_tcp`/`read_eof`/`fd_peer_spoke`/`fd_packets` (бюджет
  и хуки не сопоставлены с C-оракулом); `d2k_verify_probe_ech_on/
  ech_origin_on` (живой ECH-зонд, дифференциал только replay/RX);
  `d2k_verify_probe_identity/gzip/path/baseline` (композиция параметров);
  `d2k_verify_probe_quic`, `quic_app_silent`, `h3_read_headers`,
  `budget_quic` (QUIC/H3-исходы покрыты stage-дифференциалом, не
  построчно). **N:** `d2k_verify_tcp_timestamps_get` — глобального
  профиля TS нет; это packet-path (см. N-раздел). Строка
  `d2k_props_contact_on_family_tcp_profile` 1360-1361 — ложное
  срабатывание парсера (хвост вызова), помечена `?`.
- **`volume.c` (19):** E — `rx_wire_partial`, `d2k_volume_rx_partial/
  pair_agrees/needs_repeat/evidence`, `rx_probe`:
  `tests/r2o_volume.rs` + `d2o_verify_differential` rx-volume. **P:**
  `d2k_vol_verdict_name` (текст «цель»/«мишень»), `now_ms`, `nap_ms`,
  `clamp_ms`, `fill_pad` (алфавит/фолбэк), `connect_bounded`
  (TCP_NODELAY/errno), `drain_head_tls/plain`, `resource_retry_path`,
  `measure_response_volume`, `probe_response_volume`,
  `d2k_volume_probe_path/probe` (лестница HEAD 0..7, таймауты×3 и
  resource-retry не сверены побайтово). N нет.
- **`voice.c` (14):** E — `is_voice_port`, `field_val`,
  `d2k_voice_targets`, `send_one`, `voice_ask`, `voice_resolve`,
  `voice_alive`, `voice_ask_arms`, `d2k_voice_run`:
  `test-voice-list-differential.sh` + 15+ unit `voice_measure.rs`
  (копии/частичный ответ/локальная ошибка/verdicts). **P:**
  `ms_since`, `voice_blob_load` (путь/env-фолбэк и «лишний байт»),
  `say_reason`/`add_reason` (тексты). **N:** `voice_ask_real` —
  function-pointer seam не нужен/не портирован.
- **`voice_discovery.c` (7):** E — `nibble`, `d2k_voice_discovery_prefix`,
  `d2k_discovery_response`, `discovery_probe`,
  `d2k_voice_discovery_search`: `r2o-discord-discovery-differential.sh`
  + `test-discord-voice-discovery-arm-differential.sh`, unit STUN/
  prefix. **P:** `milliseconds` (Instant), `local_failure` (ветка внутри
  evaluate, отдельной функции нет). N нет.
- **Вывод:** verify/volume/voice — 114 функций; E покрывает HTTP/TLS/
  Gateway, volume-evidence и голосовые вердикты; P — глобальные
  budget/TS/QUIC-form, живой ECH, volume-ladder/resource-retry,
  voice-blob/тексты; N — `tcp_timestamps_get` и `voice_ask_real`.

## Углублённая сверка: quicprobe.c (56) и quicarms.c (8)

- **E (провод/проверка):** `resolve_family`, `resolve_real`,
  `d2k_quic_build_pool`, `qp_varint`, `qp_parse_hdr`, `qp_dcid_of`,
  `qp_donor_unauth_reply`, `qp_verify_server_response`, `qp_head_of`,
  `qp_verify_aead`, `qp_verify_bound`, `d2k_quic_verify_bound/response`,
  `qp_neutral_control_sni`, `qp_pinned_or_next`, `qp_dyn_wait`,
  `d2k_quic_base`, `d2k_quic_original_blob` — подтверждены
  `test-controller-quic-pool-differential.sh`,
  `test-quic-budget-init-differential.sh`, `d2o_quic_base_differential.c`
  и RFC/unit-тестами `quic.rs` (Initial v1/v2, Retry, corrupted).
- **P (провод есть, полного differential нет):** `qp_build_vn_trigger`
  (Rust `r2o_quic_build_vn_probe`, побайтового diff нет); `qp_open_fresh`
  (fresh-port 4096/480с есть, SO_MARK/удержание fd не сверены);
  `qp_send_one`/`qp_send_fragmented` (отправка Initial/фрагментов
  контроллером заменена прямым `UdpSocket`/датапатом, raw-плана нет);
  `quic_ask_core` (асинхронный `r2o_quic_ask_donor_parallel`; refused/TTL/
  счётчики не сверены); `d2k_quic_data_stage` (HTTP/3 stage 18/18, но
  budget/reason-ветки иные); `quic_ask_*` обёртки
  (`ttl/copies/srcport/split/longer/frames/control`) — TTL-prefix,
  source-port, 2 CRYPTO-фрейма и target_len 100 не вынесены в Rust-API;
  `budget_left`/`d2k_quic_budget_ms` — C бюджет в мс, Rust бюджет в
  пакетах/дедлайнах, формула мс не портирована; `arm_budget_spent`
  динамического бюджета arm нет; `qp_questions_step`/`classify_run` —
  async-задача покрывает base/VN/HTTP3, но не все ветви opaque/residual/
  arm; `quic_ask_arm`/`qp_arm_first_send`/`quic_arm_data` — arm-цикл и
  plan-send иные; `reason_set/append` — тексты иные.
- **N:** `qp_recv_ttl` (нет `recvmsg`/`IP_RECVTTL`/`IPV6_HOPLIMIT`;
  TTL-плечо и residual TTL не получают ответный TTL);
  `d2k_quic_props_findings` (текстовые выводы); `prop_word` (tri-state
  текст).
- **`quicarms.c`:** `d2k_quic_original_blob` E; `ask_q`, `ask_frag`,
  `ask`, `d2k_quic_original_arms`, `strategy_ask`,
  `d2k_quic_strategy_arms` — P: состав кандидатов/decision-функции есть,
  но фактическая отправка фрагментов, порядок fake-split и retry-семантика
  не сверены. `prop_word` — N.
- **Ключевой архитектурный пробел:** контроллерный raw-путь QUIC-плана
  (фрагменты/TTL-prefix/source-port/2 CRYPTO) не портирован; R2O применяет
  план в датапате или шлёт обычный `UdpSocket`. Это P для отправки, но N
  для `qp_recv_ttl` (обратный TTL не измеряется вовсе).

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

## Углублённая сверка: quicsnap/quicwire/quic/ipfrag/stun/quichello (83)

- **`quicsnap.c` (6):** `d2k_qsnap_is/parse/pack/client_hello/sni` — E:
  `r2k-core/src/quic_snapshot.rs` (`pack/parse`) + `quic.rs`
  (`initial_client_hello_from_datagrams`, SNI), тесты
  `tests/quic_snapshot.rs` (round-trip, ≤4 датаграммы, лимиты).
  `d2k_qsnap_form` — P: отдельной структуры `form` нет; `n` и длины
  выводятся из снимка, `ch_len` — из ClientHello, адресного differential
  на форму нет.
- **`quicsnap_reseal.c` (2):** `reseal_one`, `d2k_qsnap_recid` — E:
  `quic_snapshot.rs:79 r2k_quic_snapshot_reseal`,
  `quic.rs:338 r2k_quic_initial_reseal_for_dcid`; форма/длина
  сохраняются, тесты snapshot + reseal.
- **`quicwire.c` (28):** E — `salt_for`, `label_key/iv/hp`, varint read/
  len/write, `long_type_v1/wire`, long header без token, `d2k_qw_hdr_parse`,
  `d2k_qw_pn_decode`, `initial_secret`, `keys_from_secret`, `nonce_of`,
  `d2k_qw_seal/open`, `d2k_qw_retry_verify`: RFC 9001/9369, corrupted
  Initial/Retry, split-тесты. **P:** `d2k_qw_varint_write_w` (Rust не
  поддерживает принудительную ширину), `d2k_qw_long_hdr_token(_w)`
  (0-RTT/Retry-сборка не портирована), `d2k_qw_pn_len` (Rust фиксирует
  pn_len=4), `d2k_qw_ranges_*` (пересборка делегирована quinn).
  **N:** `d2k_qw_retry_build` — серверный Retry, клиенту не нужен.
- **`quic.c` (21):** E — `rd16`, `read_varint`, `parse_initial_header`,
  `d2k_quic_is_initial` (строже C: проверяет AEAD),
  `decrypt_initial`, `collect_crypto_frames`, `skip_u8/u16_vec`,
  `find_sni`, `find_client_hello_sni`, `crypto_stream_of`,
  `d2k_quic_client_hello/dgrams_hello/hello_name/sni`,
  `put_split_frame`, `d2k_quic_initial_split_crypto`: RFC-тесты,
  `r2o-quic-hello-differential.sh`, split v1/v2. **P:**
  `d2k_quic_hello_incomplete` (Rust собирает до `crypto_end`, отдельного
  предиката нет), `d2k_quic_assembly_init/feed/complete` (batch-API
  `..._from_datagrams` вместо инкрементального состояния).
- **`ipfrag.c` (8):** все E — `d2k_ipfrag_shape/cuts`, `wr16`, `sum16`,
  `fold`, `d2k_udpfrag_build_ex/build`, `d2k_udpfrag6_build_ex`:
  `wire.rs:299 build_udp_fragments_with_capacity`, differential
  `d2o_ipfrag_builder_matches_r2o_on_ipv4_ipv6_shapes`
  (C-оракул `tests/d2o_ipfrag_oracle.c`).
- **`stun.c` (5):** все E — `rd16/rd32`, `d2k_stun_request`,
  `parse_xor_mapped`, `d2k_stun_parse_response`:
  `r2k-core/src/stun.rs`, RFC 5769 + C-векторы Discovery
  (`tests/stun.rs`).
- **`quichello.c` (13):** E — `select_probe_profile`, `split_point`,
  `put_crypto`, `prepare`, `seal_one`, `probe_initial_sized`,
  `d2k_quic_probe_initial`, `d2k_quic_hello_rename`,
  `d2k_quic_hello_recid`: профиль/rename/reseal/build, RFC/тесты
  `quic.rs`, `quic_snapshot.rs`. **P:** `d2k_quic_probe_initial_longer`
  (Rust-обёртка всегда 1200), `d2k_quic_prepare_target` (композиция в
  `quic_replay.rs`, fallback-порядок не тестирован),
  `d2k_quic_hello_ask` (v2/clear-fixed-bit не вынесены),
  `d2k_quic_hello_split` (две датаграммы; `initial_split_crypto` даёт
  один пакет).
- **Вывод:** 83 функции; 63 E, 19 P, 1 N. Основные пробелы —
  quinn-замены ranges/pn_len, 0-RTT/Retry-сборка, длинный Initial,
  двухдатаграммный split и form-снимок.

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
| `d2k_http_lower` | 9-11 | 3 | ASCII lower | `fetch.rs:2910 r2o_fetch_ascii_contains` (`eq_ignore_ascii_case`) | **E*** | static-хелпер; владелец `r2o_fetch_http_outcome` покрыт тестами `fetch.rs:3486-3524` (регистр в фразе/портале). |
| `d2k_http_equal` | 12-16 | 5 | регистронезависимое сравнение n байт | `fetch.rs:2910-2914 r2o_fetch_ascii_contains`, `:2934-2938 eq_ignore_ascii_case` | **E*** | static-хелпер; те же тесты: `Access Blocked By RKN`, `WARNING.RT.RU`. |
| `d2k_http_hostchar` | 17-21 | 5 | символ host для границ в теле | `fetch.rs:2941-2943 r2o_fetch_http_host_char` | **E*** | static-хелпер; границы портала проверены `eais.rkn.gov.ru` vs `xnot-eais.rkn.gov.ru` (`fetch.rs:3508-3522`). |
| `d2k_http_portal` | 22-26 | 5 | список 6 порталов по индексу | `fetch.rs:2873-2908` и `:2916-2932` (те же 6 хостов в том же порядке) | **E*** | static-таблица; порядок и имена совпадают, используются тестами `warning.rt.ru`/`eais.rkn.gov.ru`. |
| `d2k_http_location_portal` | 27-52 | 26 | host портала из Location: схемы, userinfo, числовой порт, хвостовая точка, 6 имён | `fetch.rs:2873-2908 r2o_fetch_portal_location` | **E** | Построчный порт; тест `fetch.rs:3490-3500`: `https://user@WARNING.RT.RU.:443/blocked` → Blocked, `https://warning.rt.ru.evil.example/` → Neutral, `/login` → Positive. |
| `d2k_http_reply_classify` | 55-86 | 32 | HTTP 451/2xx/3xx/4xx → outcome+evidence | `fetch.rs:2836-2871 r2o_fetch_http_outcome` | **E** | Тесты `fetch.rs:3486-3524`: 451→LegalDenial; 302 портал/evil/relative; 403 фраза/портал; граница `total>len` (15 neutral, 16 blocked); non-identity neutral; `xnot-eais` neutral. Формулы и границы совпадают. |

## core/include/d2k_ip6frag_send.h (9 функций)

Отправка IPv6-пакетов с фрагментацией через AF_PACKET: netlink route/neigh, MTU, MAC, SO_MARK, кеш 1 с. В R2O есть `r2o-datapath/src/raw.rs` (`RawSocket`: AF_INET/AF_INET6 IPPROTO_RAW, SO_MARK, route/MTU, IPv4/IPv6 UDP-фрагментация), но он в датапате, а не в контроллере; ручной neighbor-резолв заменён ядром.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_ip6frag_sender_init` | 34-36 | 3 | сброс sender, fd=-1 | `raw.rs:46-93 RawSocket::open` (RAII) | **P*** | Отдельной init нет; контейнер и владение fd заменены `OwnedFd`. |
| `d2k_ip6frag_sender_close` | 37-40 | 4 | закрыть fd | `RawSocket` Drop | **P*** | RAII; отдельного close нет. |
| `d2k_f6_now` | 41-45 | 5 | монотонное время, мс | `std::time::Instant` | **P*** | `CLOCK_MONOTONIC` в мс → `Instant`; единицы пересчитываются. |
| `d2k_f6_attr` | 46-55 | 10 | rtattr в netlink-запрос с NLMSG_ALIGN/RTA_ALIGN | `r2o_route.rs:679-700` (сборка запросов) | **P** | Отдельного attr-хелпера нет; выравнивание/границы проверяются в сборщике. |
| `d2k_f6_query` | 56-72 | 17 | AF_NETLINK/NETLINK_ROUTE, SO_RCVTIMEO 200 мс, проверка `nl_pid==0` | `r2o_route.rs` netlink-сокет | **P** | API и таймауты иные; контроллерного вызова нет. |
| `d2k_f6_route` | 73-106 | 34 | RTM_GETROUTE IPv6 (src/dst/mark) → ifindex/gateway | `r2o_route.rs:691 r2o_route_lookup_request`, `:774 parse_lookup` | **P** | Парсер запроса/ответа есть, но это route-mark lookup, а не полный IPv6 src/dst/mark-запрос; контроллерный вызов отсутствует. |
| `d2k_f6_neighbor` | 107-154 | 48 | RTM_GETNEIGH dump → MAC шлюза, NUD_* и NDA_DST/LLADDR | нет функции; резолв делегирован ядру | **P** | Осознанная замена: R2O шлёт через `IPPROTO_RAW`, ядро само резолвит neighbor; ручной AF_PACKET/MAC-путь не портирован. Это не N, потому что функциональность отправки закрыта. |
| `d2k_ip6frag_prepare` | 155-195 | 41 | маршрут/MTU/MAC, AF_PACKET SOCK_DGRAM, SO_MARK, кеш 1 с, MTU≥1280 | `raw.rs:484 r2o_route_mtu`, `:622 ipv6_udp_fragment`, `wire.rs:294 build_udp_fragments` | **P** | Функциональность в датапате: IPv6-фрагменты строятся `build_udp_fragments`/`ipv6_udp_fragment` и шлются `IPPROTO_RAW`. **Не портированы:** AF_PACKET-путь, ручной neighbor/MAC, кеш `fd/mark/src/dst` 1 с, проверка `MTU≥1280` в том же месте; **`IP_NODEFRAG` отсутствует во всём R2O** (grep пуст). |
| `d2k_ip6frag_send` | 196-204 | 9 | sendto с EINTR-повтором, точная длина, сброс кеша при ошибке | `raw.rs:147-219 RawSocket::send_packet`/`send_packet_inner` | **P** | EINTR-повтор есть (`raw.rs:207`), точная длина проверяется, EMSGSIZE понижает route-MTU (`:208-217`), `MSG_DONTWAIT` и `ENOBUFS` учитываются. Отличия: C — блокирующий AF_PACKET `sendto`, R2O — неблокирующий `IPPROTO_RAW`; C сбрасывает кеш при ошибке, R2O понижает `maxlen`. |

### Углублённая сверка d2k_ip6frag_send.h (9)

- **C-путь:** `AF_PACKET/SOCK_DGRAM/ETH_P_IPV6` + ручной
  `RTM_GETROUTE` (src/dst/mark, `dst_len=src_len=128`) и
  `RTM_GETNEIGH` (dump, `NUD_REACHABLE|STALE|DELAY|PROBE|PERMANENT`,
  `NDA_DST`/`NDA_LLADDR`), кеш `fd/mark/src/dst` на 1 с, проверка
  MTU≥1280, `SO_MARK`, EINTR-повтор и точная длина.
- **R2O-путь:** `RawSocket` `AF_INET6/IPPROTO_RAW` + `IPV6_HDRINCL`
  (`raw.rs:75-80`), `SO_MARK`, `r2o_route_mtu` (`:484`), IPv6-
  фрагменты `ipv6_udp_fragment` (`:622`) и `build_udp_fragments`
  (`wire.rs:294`), отправка `send_packet_inner` (`:147-219`):
  EINTR-повтор, `MSG_DONTWAIT`, EMSGSIZE понижает route-MTU,
  `ENOBUFS` — busy.
- **Подтверждённые пробелы:** ручной neighbor/MAC и AF_PACKET-путь
  не портированы; `IP_NODEFRAG` отсутствует во всём R2O (grep
  пуст); контроллерного API `udp_raw_*` нет — датапат закрывает
  отправку через `IPPROTO_RAW`. Кеш 1 с и проверка MTU≥1280
  разнесены иначе. Отдельного C/Rust differential для IPv6-
  фрагментного отправителя нет, поэтому статусы P.

## core/include/d2k_quicprobe.h (9 функций)

Inline-решения QUIC-зонда: суд этапа данных, stall-детектор с PING, бюджет датаграмм. Порт: `r2k-core/src/quic.rs:31 r2k_quic_data_judge`, `r2o-controller/src/r2o_quic_http3.rs:543 R2oQuicHttp3Budget`, `:600 R2oQuicHttp3Stall`, `quic_replay.rs:417 r2o_quic_trial_data_verdict`. Дифференциалы: `test-quic-short-control-differential.sh`, `test-quic-budget-init-differential.sh`, `d2o_quic_http3_differential.c` в `r2o-diagnostics-differential.sh`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_quic_arm_data_judge` | 454-461 | 8 | handshake/status/bytes/complete → NO_HANDSHAKE/CUT/PASS | `quic.rs:31-58 r2k_quic_data_judge` (соответствует `judge3`) | **P** | **Расхождение:** простой C-judge: `!handshake→NO_HANDSHAKE`; `status<=0 или 451→CUT`; `complete или bytes>=32768→PASS`; иначе CUT. Rust `r2k_quic_data_judge` — это `judge3`: при `status==0` без `headers_too_long` он возвращает `NotRun`, а не `CUT`. В production `verify.c:2127` проверяется только `== PASS`, поэтому pass/fail там совпадает; C-тест `test_quic_arm_data.c:319` ждёт CUT для `(1,0,3000,1)`, differential с Rust дал бы NotRun. |
| `d2k_quic_arm_data_judge_limited` | 466-470 | 5 | NOT_RUN при переполнении заголовков, иначе простой judge | `quic.rs:31-58 r2k_quic_data_judge` | **P** | Заявленный пробел «headers_too_long-ветка не выделена» **неверен**: Rust содержит `status==0 && headers_too_long → NotRun` (`quic.rs:43-45`). Реальное отличие — `status==0` **без** `headers_too_long`: C возвращает `CUT`, Rust — `NotRun`. `judge_limited` используется только C-тестами (`test_quic_arm_data.c:326-332`), production идёт через `judge3`. |
| `d2k_qstall_init` | 523-535 | 13 | stall: RTO=max(3×RTT,1000), отметки прогресса | `r2o_quic_http3.rs:600-620 R2oQuicHttp3Stall::r2o_initialize` | **E** | Совпадает: `rto=max(3*rtt,1s)`, `last_progress_at=now`, `probe_at=None`, `wire_at_probe=wire`, `probe_packet_number=None`, `unanswered=0`. Тесты `r2o_quic_ping_ack_сверяется_с_номером_пакета`, `...при_одновременном_росте_потока`, `...различает_обрыв_и_одностороннюю_передачу` (`r2o_quic_http3.rs:1435-1490`). |
| `d2k_qstall_sent` | 540-543 | 4 | запомнить PN отправленного PING | `R2oQuicHttp3Stall::r2o_sent` (`:622-625`) | **E** | C `probe_pn/probe_pn_set`; Rust `probe_packet_number=Some`, `probes_sent++`. Те же тесты: PN 41/42 и ACK 40/41/42. |
| `d2k_qstall_step` | 545-584 | 40 | GOING/PROBE/STALLED/ONEWAY по прогрессу/ACK/RTO | `r2o_quic_http3.rs:645-686 R2oQuicHttp3Stall::r2o_step` | **E** | Построчно: рост progress → reset/GOING; PING после RTO; `acked>=probe` закрывает вопрос; второе неподтверждение → `wire_seen!=wire_at_probe ? ONEWAY : STALLED`. Rust добавляет `probes_sent/probes_acked`. Тесты `:1435-1490` покрывают PN-ACK, одновременный рост и оба исхода. Отличие порядка: Rust `r2o_capture_ack` до проверки progress, C — после; влияет только на `probes_acked` при одновременном событии. |
| `d2k_qbudget_init` | 616-620 | 5 | need=2×budget (25 по умолчанию) | `r2o_quic_http3.rs:548 r2o_quic_http3_budget_datagrams`, `R2oQuicHttp3Budget::r2o_initialize` | E | `test-quic-budget-init-differential.sh` (0/1/25/u32 max) |
| `d2k_qbudget_ok` | 626-631 | 6 | бюджет набран, прогресс растёт, не stall | `R2oQuicHttp3Budget` | E | `d2o_quic_http3_differential.c` + full-stage differential |
| `d2k_qbudget_grew` | 637-639 | 3 | упрощённая проверка роста | `R2oQuicHttp3Budget` (grew) | E | тот же differential |
| `d2k_quic_arm_data_judge3` | 641-652 | 12 | расширенный суд: complete/budget/stalled/need_complete/headers | `quic_replay.rs:417 r2o_quic_trial_data_verdict`, `r2k_quic_data_judge` | E | `d2o_quic_http3_differential.c` (judge3) + full-stage |

## core/include/d2k_arm.h (1 функция)

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_arm_segment` | 78-83 | 6 | размер сегмента ARM с учётом send_cap | `main.rs:6292-6305` `r2o_discovery_measured_split_plan` | **E** | Формула совпадает: `send_cap==0 → 1400`; `send_cap<=72 → 0`; иначе `min(send_cap-72,1400)`. `scripts/r2o-measured-split-differential.sh` сравнивает C/Rust для `send_cap` 0/1492/1280/100/72, split 0/1/1024 и verdict prefix/whole; C-сторона — `d2k_tcp_split_plan`/`d2k_arm_segment`. |

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

## Углублённая сверка: httpsearch (66) и httpsprobe (22)

- **`httpsearch.c`, E (22):** `d2k_hs_judge`, `hs_path_ok`,
  `d2k_hs_probe_run`, `d2k_hs_candidate_count/key`, `poison_key_spec`,
  `known_key`, `d2k_hs_candidate_text`, `stable_id`,
  `d2k_httpsearch_measured_poison`, `d2k_hs_plan_poisons`,
  `revoke_owned`, `all_failed`, `install`, `d2k_httpsearch_install_ack`,
  `trial_executed`, `d2k_httpsearch_cut/portal/ack/applied/result/save`
  — подтверждены `scripts/r2o-http-search-differential.sh`,
  `tests/http_search.rs` и C-фикстурами (judge/baseline/no-executed/
  applied/rollback/queue). Список кандидатов, точные тексты и
  FNV-id совпадают.
- **`httpsearch.c`, P:** `mono_ms`, `d2k_hs_answer_name`, `hs_read`
  (тайминги/первый байт/префикс не сопоставлены побайтово), `fresh_id`
  (нет fallback-ветки), `say`, `host_ok`, `rec_find/get` (HashMap вместо
  C-массива, лимиты `D2K_HS_RECORD_MAX_BYTES` не сопоставлены),
  `same_program` (TLV-сравнение иное), `d2k_httpsearch_new/free/busy/
  plan_of`, `d2k_httpsearch_diagnostic_counts/diagnostics`,
  `diagnostic_end/finish/open_job`, `confirmed`, `judge_trial`,
  `next_candidate`, `add_cand/build_cands/build_fallback`, `start/
  start_next`, `live_owner`, `d2k_httpsearch_bound_failure/control/tick/
  push_all/load`, `runner_*`. Причины: состояние переписано на задачи,
  часть переходов/таймеров не имеет C/Rust differential.
- **`httpsearch.c`, N:** `remember_live_failure`, `failed_live`,
  `d2k_httpsearch_test_add_failures`, `d2k_httpsearch_test_add_records`.
  **Ключевой пробел:** `HttpSearchRecord` (`main.rs:4468-4472`) хранит
  только `cut/repeat_path/repro_gap`; полей `failures/addr/binding/
  execution/request_ms`, лимитов `D2K_HS_FAILURE_*` и счётчиков нет.
  `HttpLiveFailures` строится из `failed_http_programs` (выключенные
  привязки каталога), а не из живых отказов. Поэтому
  `d2k_httpsearch_diagnostic_counts` P: `http_failure_bytes` жёстко 0
  (`main.rs:16762`), `failure_limit_hits/record_limit_hits/
  alloc_failures` остаются 0 (`diagnostics.rs:474-481`).
- **`httpsprobe.c`, E:** `d2k_https_classify/upgrade/ttl/state_name`,
  `host_ok`, `cache_find/put`, `d2k_httpsprobe_state`, `save`, `load`
  — `test-controller-httpsprobe-differential.sh` (состояния, TTL,
  capacity 130, bad-host, non-utf8, duplicates, upgrade-состояния).
- **`httpsprobe.c`, P:** `mono_ms`, `https_connect`, `https_tls`,
  `first_flight`, `d2k_https_probe_real`, `worker`,
  `d2k_httpsprobe_new/free/wake_fd/portal/done`. Live-дифференциала
  connect/TLS/lost нет; Rust использует канал/поток вместо pipe/fd,
  `d2k_httpsprobe_done` отдаёт пачку иначе.
- **`httpsprobe.c`, N:** `d2k_httpsprobe_lost` — счётчика потерянных
  результатов нет. C инкрементирует `lost` только при переполнении
  `done[]`; R2O `https_probe.rs:179` использует ограниченный
  `SyncSender` и блокирующий `send`, то есть при переполнении воркер
  блокируется, а не дропает; при закрытом канале результат теряется без
  счётчика.
- **Вывод:** HTTP-search — 22 E, 40 P, 4 N; основной пробел — живые
  отказы/диагностика. HTTPS-probe — 10 E, 11 P, 1 N; основной пробел —
  `lost` и live-тайминги.

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

## Глубокая сверка QUIC ask/questions (по `deep-core-verify.md`)

- **`qp_open_fresh` (637–697) ↔ `r2o_quic_http3_udp_socket_fresh`
  (`:71-125`):** C свежий порт, `SO_MARK` best-effort, 16 попыток,
  окно 480 с; Rust те же 4096/480 с/16 попыток. **Нет** параметра
  `src_port`/bind (вопрос низкого порта невозможен), C держит
  отвергнутые fd до конца, Rust закрывает после успеха. Отдельного
  differential нет. P.
- **`qp_send_one` (716–789) ↔ `QuicReplayProbe` (`quic_replay.rs:647`):**
  C умеет prefix/junk, `prefix_ttl`, `prefix_copies`, `src_port`,
  `split`, `longer`, `crypto_split`; Rust перезапечатывает снимок и
  шлёт датаграммы подряд, этих режимов нет. `ECONNREFUSED` на send в
  Rust попадает в `err`, в C — в `refused`. P.
- **`qp_recv_ttl` (937–997): N.** Во всём `crates/` нет `recvmsg`,
  `IP_RECVTTL`, `IPV6_HOPLIMIT`; `R2oQuicHttp3Result` и
  `R2oQuicRawAskResult` не содержат TTL/hoplimit. TTL-плечо и
  residual TTL не измеряются.
- **`qp_send_fragmented` (1004–1040) ↔ `build_udp_fragments`
  (`wire.rs:294`):** C шлёт IP-фрагменты из контроллера, проверяет
  форму 1..4, connected rx и fresh-port; Rust только формирует
  директивы `ipfrag`, фрагменты строит/шлёт датапат
  (`engine.rs:1753`). Raw-отправки из контроллера нет. P.
- **`quic_ask_core` (1064–1403) ↔ `r2o_quic_ask_donor_parallel`
  (`:901`):** параллельная отправка, poll/recv, pass/fail/err/refused,
  RTT и marked в целом повторены. **Пробелы:** нет отказа при
  `repeats > D2K_QUIC_MAX_ADDRS`; нет TTL/prefix/fragment/longer/
  split/fresh_sni; neutral control собирается заранее тремя снимками
  (`:139`), а не новой CH на каждый повтор; `ECONNREFUSED` на send —
  `err`, не `refused`; нет `ttl_in_out`. P.
- **`d2k_quic_data_stage` (1591–1829) ↔
  `r2o_quic_http3_measure...` (`:847`):** сильный дифференциал
  `r2o_http3_full_data_stage_matches_d2o...` (`tests:1444`) покрывает
  complete/no-growth/refusal/slow/drop/close, 451, stall/one-way,
  Content-Length, oversized headers. **Но:** `app_bytes` для oversized
  headers документирован как разрыв (`tests:2137-2141`), `reason`
  тексты не сверяются, `head_full` не выносится,
  `datagrams_before` сбрасывается после первого запроса (`:1053`), а
  C считает tx/rx от начала stage; h3 crate сам создаёт control-потоки,
  C явно шлёт SETTINGS и ждёт 400 мс. P.
- **`budget_left` (1984–1999) / `d2k_quic_budget_ms` (2096–2105):**
  C `limit_ms==0` — всегда исчерпан, иначе `elapsed<=limit`;
  `budget_ms = budget_s*1000` либо
  `wait_ms + 35*(dyn_wait + 60 мс)` (`QP_RUN_DYN_POLLS=2+9+18+6`).
  Rust — остаток 10-минутного task lifetime с yield и per-phase
  timeouts; `limit_ms/start` и точная формула не портированы.
  `arm_budget_spent` отсутствует. P.
- **`qp_questions_step` (2118–2269):** C задаёт 6 вопросов: мусор,
  два кадра CRYPTO, две датаграммы, погашенный fixed bit, низкий
  исходный порт, удлинение. Rust покрывает junk (`Clearance`), кадры
  (`SplitCrypto`), длину (`UdpLength`), фрагменты; **нет**
  двухдатаграммного split, clear-fixed-bit и low-source-port; нет
  `qprops/qtrace/probes`, счётчиков budget/addr/unbuilt и текста
  «вопросы(N): взяли …». P.
- **`classify_run` (2337–2918) ↔ `r2o_run_quic_discovery_trial`
  (`main.rs:20499`):** Rust покрывает base/VN, data-stage, strategy
  arms, fallback, fragment control/forms. **Пробелы:** нет
  `arm->data_cut` (`data_cut=2` запрещает alternative path; есть
  только `stall_cut`), `base_seed/run_seeded`, env
  `d2k_quic_allow_local`, итогового `d2k_vres` с verdict/reason/
  qtrace; не все opaque/residual/address ветви. P.
- **`d2k_quic_props_findings` (2275–2324) и `prop_word`
  (`quicarms.c:244-246`): N.** Тексты «приветствие, разложенное на два
  кадра…», «две датаграммы…», «вторая версия…», «погашенный fixed
  bit…», «низкий порт…», «фальшивый Initial…» и «прошло/не прошло/
  ответа нет» не портированы. Имена `r2o_quic_blob_name` их не
  заменяют.
