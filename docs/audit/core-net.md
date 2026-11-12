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

**Прочитано построчно: 19/19 функций, 609 строк C (1–609).**

| C-функция | строки | размер | назначение | R2O-аналог | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `rd16` | 51-53 | 3 | big-endian u16 из буфера | `hello.rs:186 hello_u16` | E | C читает без проверки границ (вызывающие проверяют); Rust `hello_u16` делает `checked_add(2)`+`get` и возвращает `Option`. На всех путях `parse_hello`/`locate_sni` чтение идёт после проверки длины, поэтому результат совпадает. Дифф `test-controller-clienthello-differential.sh`. |
| `rd24` | 54-56 | 3 | big-endian u24 | `hello.rs:192 hello_u24` | E | То же: Rust `hello_u24` с проверкой `checked_add(3)`/`get`; C полагается на вызывающего. Владелец `parse_hello_layout`; тот же дифф. |
| `wr16` | 57-60 | 4 | запись big-endian u16 без проверки границ | `hello.rs:534-547 write_len(width=2)` | **P** | C пишет в уже проверенный буфер и молча усекает `uint16_t`; Rust `write_len` отвергает `value>u16::MAX` (`hello.rs:535-542`). Для длин, которые получаются из валидного ClientHello и `delta`, значения всегда в диапазоне, поэтому наблюдаемый результат совпадает. Используется `splice_sni`/`rename_sni`. |
| `wr24` | 61-65 | 5 | запись big-endian u24 | `hello.rs:534-547 write_len(width=3)` | **P** | Rust проверяет `value>0xffffff`; C пишет младшие 24 бита без проверки. Для валидного шаблона/`delta` эквивалентно; при переполнении C испортил бы длину, Rust вернул бы `None`. |
| `skip_u8_vec` | 69-79 | 11 | пропуск TLS-вектора с 1-байтовой длиной | `hello.rs:198 hello_skip_u8_vec` | E | C: `*off+1>end` → -1, затем `*off+1+n>end` → -1, иначе `*off += 1+n`. Rust: `bytes.get(offset)?` + `checked_add` двух шагов + `next<=end` → `Option<usize>`. Те же границы; владелец `parse_hello_layout`, дифф ClientHello. |
| `skip_u16_vec` | 80-90 | 11 | пропуск TLS-вектора с 2-байтовой длиной | `hello.rs:204 hello_skip_u16_vec` | E | C: `*off+2>end`, `n=rd16`, `*off+2+n>end`; Rust: `hello_u16` + `checked_add(2)` + `next<=end`. Эквивалентно; тот же владелец и дифф. |
| `parse_hello` | 128-272 | 145 | разбор записи ClientHello: длины, SNI-координаты, supported_versions, усечение расширений | `r2o-controller/src/hello.rs:213 parse_hello_layout` | E | Ветви сверены построчно: `n<3`/`b[1]!=0x03`/`n<5`/`b[0]!=0x16`; `claimed=5+rec_len`, `end=min(claimed,avail)`; `hs_len`, отказ `off+hs_len>claimed`; `complete=hs_end<=avail`; `+34`; три вектора; `parsed=1`; блок расширений с `exts_truncated`; цикл `p+4<=exts_end`, обрыв на `edata+elen>exts_end`; SNI-лист и `supported_versions`; `p=edata+elen`. Rust не хранит `rec_len_off`/`hs_len_off` в `HelloLayout` — они фиксированы (3 и 6) в `SniLayout` (`hello.rs:15-17,116-117`), для выходов `shape/sni/ech` это не влияет. Дифф `test-controller-clienthello-differential.sh` (24+ кейса). |
| `d2k_hello_complete` | 274-281 | 8 | ровно одна полная запись+рукопожатие без хвоста | `hello.rs:344 hello_complete` | E | C: `n<9`; `5+rd16(3)==n`; `5+4+rd24(6)==n`; затем `parsed && complete && !exts_truncated`. Rust `hello_complete` проверяет те же два точных равенства через `hello_u16`/`hello_u24` и те же три поля. Дифф ClientHello; unit `trailing_bytes_keep_shape_and_sni_but_not_complete`. |
| `d2k_hello_shape` | 283-306 | 24 | MODERN/LEGACY/UNKNOWN по supported_versions | `hello.rs:366 hello_shape` | E | C: `!parsed → UNKNOWN`; `exts_truncated && !have_tls13 → UNKNOWN`; иначе `have_tls13 ? MODERN : LEGACY`. Rust ветвит теми же условиями в том же порядке. Дифф ClientHello + unit `shape_distinguishes_modern_and_legacy_profiles`, `duplicate_supported_versions_are_modern_for_shape`, `truncated_extensions_*`. |
| `d2k_hello_sni` | 308-320 | 13 | координаты имени SNI | `hello.rs:383 hello_sni_bounds` | E | C дополнительно требует ненулевые `off`/`len` (API-параметры), затем `parsed && have_sni`; Rust возвращает `Option<(offset,len)>` при `parsed && have_sni`. Для непустого имени результаты совпадают. Дифф ClientHello (sni-кейсы), unit `shape_distinguishes...`. |
| `d2k_hello_ech_offer` | 322-347 | 26 | валидация ECH-предложения и config_id | `hello.rs:391 hello_ech_offer` | E | C: `d2k_hello_complete` → -1; `!have_exts` → 0; цикл с `end-p<4`/`elen>end-p-4` → -1; тип `0xfe0d`: повтор/`elen<10`/`e[0]!=0`/`enc_len>elen-10`/`payload_len==0 \|\| payload_len!=elen-10-enc_len` → -1; `id=e[5]`; возврат 0/1. Rust `HelloEchOffer::{Incomplete,Absent,Present}` повторяет все проверки и порядок. Дифф ClientHello (ech-duplicate/bad-type/enc-over/payload-mismatch), unit `ech_offer_follows_outer_body_layout`. |
| `d2k_hello_alpn` | 349-375 | 27 | требует `d2k_hello_complete`; ищет extension 0x0010; проверяет list_len==elen-2, непустые имена; копирует **сырой** список; 1/0/-1 | `r2o_tls.rs:121-197 r2o_tls_client_hello_non_http_alpn` | **P** | **Подтверждённые расхождения:** (1) C копирует сырой ALPN-список и отдельно вызывает `d2k_alpn_is_http`; Rust сразу отбрасывает HTTP-протоколы и возвращает только non-HTTP (`None` при любом HTTP). (2) Rust отвергает ECH (`0xfe0d → None`), C ECH не проверяет. (3) Rust требует `extensions_end == end`, C допускает `exts_len` меньше остатка handshake. (4) Rust `Some([])` для ClientHello без ALPN; C `0` и `len=0`. (5) Пустой ALPN-список: C при `elen==2` возвращает 1 и `len=0`; Rust `protocols.is_empty() → None` (`r2o_tls.rs:189-191`). Ошибочная форма: C `-1`, Rust `None`. Покрыто косвенно `tests/d2o_verify_differential.rs:990`. |
| `d2k_alpn_is_http` | 377-387 | 11 | список имён: `http/1.1`, `http/1.0`, `h2`, границы `q+1+l<=len` | `r2o_tls.rs:180-185` (фильтр внутри) | **P** | C отдельный предикат; Rust сравнивает имена с теми же тремя HTTP-протоколами внутри `r2o_tls_client_hello_non_http_alpn` и сразу возвращает `None`. Для валидного списка эквивалентно; отдельного предиката/теста в Rust нет. |
| `splice_sni` | 409-452 | 44 | заменить SNI, обновить 6 длин: name/list/ext/exts/hs24/rec | `hello.rs:439-480 rename_sni`, `:549-585 client_hello_from_profile` | **P** | C: `parse_hello` → требуются `parsed && complete && have_sni`; `new_total=tmpl_len-name_len+name_len2`; `>cap` → -1; три `memmove`; `delta`; обновляются ровно 6 полей (name/list/ext/[exts]/hs24/rec). Rust: `locate_sni_for_record` (точная запись или handshake-префикс), `checked_sub/add`, шесть полей через `checked_add_signed`+`write_len`, затем повторная проверка `locate_sni_for_record` и точного имени. **Отличия:** C принимает «хвост» внутри рукопожатия после расширений (`parse_hello` не требует `exts_end==hs_end`), Rust `locate_sni` требует `extensions_end==record_end`; C молча усекает переполнение `wr16`, Rust отвергает; C не перепроверяет результат. Для валидных профилей эквивалентно; точного differential на rename нет (`raw_probe.rs:625` использует). |
| `hex_nibble` | 462-473 | 12 | hex-цифра → значение, иначе -1 | `hello.rs:512-513 decode_profile` (`to_digit(16)`) | **P** | C helper для чистого hex (`0-9a-fA-F`, иначе -1); Rust `to_digit(16)` в `decode_profile`, недопустимый символ → `None`. Отдельной функции нет; на встроенных профилях эквивалентно. |
| `hex_decode` | 480-498 | 19 | чётная длина, `n<=cap`, hex → байты; -1 при ошибке | `hello.rs:501-517 decode_profile` | **P** | C: нечётная длина/`n>cap`/невалидный nibble → -1, комментарии и пробелы не допускает. Rust: режет каждую строку по `#`, удаляет ASCII-пробелы, проверяет чётность и `<=4096`, затем `to_digit(16)` → `None` при ошибке. Для сгенерированных C-профилей и `include_str!`-профилей R2O байты совпадают; API `Vec`/`Option` вместо кода. |
| `d2k_hello_rename` | 500-535 | 36 | обернуть CH в TLS-запись, `splice_sni`, вернуть тело; `n>0xffff` или `n+5>4096` → -1 | `hello.rs:439 rename_sni`, `:482 locate_sni_for_record` | **P** | C принимает **тело** ClientHello, оборачивает в запись `16 03 01`, вызывает `splice_sni` и возвращает тело; проверяет `n<=0xffff`, `n+5<=4096`, непустое имя. Rust `rename_sni` принимает запись, проверяет `name` (непустое, без NUL), `bytes.len()<=4096`, обновляет те же 6 длин и валидирует результат; `locate_sni_for_record` для записи длиннее рукопожатия разбирает префикс и сохраняет хвост. Для полного CH с записью результат эквивалентен; unit/differential на `rename` нет. |
| `d2k_hello_without_sni` | 537-576 | 40 | требует complete/!truncated/have_exts/have_sni; удаляет server_name, обновляет ext/hs/rec | `r2k-core/src/quic.rs:1113 r2k_quic_client_hello_rename_sni(..., None)` | **P** | C принимает **тело** CH, оборачивает в запись, требует `parsed && complete && !exts_truncated && have_exts && have_sni`, проверяет `sni_ext_off+ext_len` против записи/расширений/handshake и удаляет расширение, обновляя `exts_len`, `hs_len`, `rec_len`, затем возвращает тело. Rust `r2k_quic_client_hello_rename_sni(..., None)` принимает тело CH (`bytes[0]==1`, длина handshake точная), удаляет `extension_start..extension_end`, обновляет `extensions_len` и `handshake_len`; без SNI возвращает копию. Для тела результат совпадает, но **TLS-обёртки записи и вызова из TLS-пути нет** (функция в модуле QUIC, используется только bridge-clone fixture). P. |
| `d2k_hello_from_profile` | 578-609 | 32 | modern/legacy профиль → `splice_sni`; UNKNOWN → -1 | `hello.rs:549-598 client_hello_from_profile` + `legacy/modern_client_hello` | **E** | C: `sni/out/out_len` не NULL, имя непустое; modern/legacy decode, `tmpl_len!=0`, `splice_sni`. Rust: имя непустое/без NUL/`<=u16::MAX`; `decode_profile`; `locate_sni`; `new_len<=4096`; шесть длин; валидация результата. C-профили modern/legacy и R2O `include_str!` дают те же байты (unit `shape_distinguishes_modern_and_legacy_profiles`, тесты профилей); Rust дополнительно имеет профиль `r2o_rx_fake`, которого в C нет. E. |

## core/tls12.c (26 функций)

C-реализация минимального TLS 1.2 клиента (ECDHE+AES128-GCM, X25519/P-256) для зондов/измерений. В R2O построчного порта нет: стек заменён `rustls` с ограничением cipher suites и KX-групп (`r2o-controller/src/r2o_tls.rs:53`, ветка `tls12`). Дифференциал: `scripts/r2o-tls-verify-differential.sh` → `tests/d2o_verify_differential.rs` (в т.ч. `donor_and_r2o_reject_short_tls12_server_finished` с C-фикстурой `tls12`).

**Прочитано построчно: 26/26 функций, 800 строк C (1–800).** Сверено с `r2o_tls.rs` (488 строк) и `fetch.rs:2386-2483`; проверены cipher suites, kx-группы, ALPN, `verify_finished`, счётчики байт/оборванных записей и тексты ошибок.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `tls12_dispose` | 98-100 | 3 | освободить сессию и снять учёт diagnostic memory | `r2o_tls.rs:53` (rustls, RAII) | P | владелец `d2k_tls12_connect`; отдельной функции нет, diag-учёт аллокатора не портирован |
| `say` | 215-224 | 10 | `vsnprintf` ошибки в `err/cap` | `format!`/`io::Error` в `r2o_quic_http3.rs`/`quic_replay.rs` | **P** | C пишет текст в переданный буфер, молча выходит при `!err||cap==0`; Rust возвращает `io::Error`/`String`, вызывающий логирует. Контракт «назвать причину» тот же, тексты/владение иные. |
| `now_ms` | 226-236 | 11 | `CLOCK_MONOTONIC`, fallback `gettimeofday`, мс | `std::time::Instant`/`Duration` | **P** | C сначала `clock_gettime(CLOCK_MONOTONIC)`, иначе `gettimeofday`; Rust `Instant` монотонен и не имеет fallback. Единицы/точность пересчитываются, отдельной функции нет. |
| `put16` | 116-116 | 1 | big-endian u16 | `u16::to_be_bytes` | P | хелпер записи заголовков |
| `get16` | 117-117 | 1 | big-endian u16 | `u16::from_be_bytes` | P | хелпер чтения заголовков |
| `read_exact` | 119-153 | 35 | дочитать n байт с дедлайном, учёт `rx_wire_bytes`/`rx_record_missing`, обработка EINTR/EOF | `fetch.rs:2464-2473 R2oTlsTcpStream::read`, `:2386-2437 R2oTlsRecordTracker` | P | В R2O нет отдельного `read_exact`: rustls `complete_io` + `set_read_timeout(remaining)` в цикле до абсолютного `deadline` (`fetch.rs:251-265`). Байты считает `R2oTlsTcpStream::read` (`fetch.rs:2464-2473`), границы записей — `R2oTlsRecordTracker` (`:2406-2436`). **Отличия:** C опрашивает `poll` квантами ≤1000 мс и повторяет `EINTR`/`EAGAIN`; Rust полагается на `SO_RCVTIMEO` и `complete_io`; тексты ошибок иные; `rx_record_missing` в C — остаток байт (`uint32`), в Rust — `bool` «запись оборвана». |
| `write_all` | 155-171 | 17 | дослать буфер с MSG_NOSIGNAL | `R2oTlsTcpStream::write` (`fetch.rs:2475-2482`) + rustls `Stream` | P | Rust `TcpStream::write` не ставит `MSG_NOSIGNAL` явно (в Linux SIGPIPE подавляется через `MSG_NOSIGNAL` только в std при необходимости); EINTR-ветка C не воспроизведена. Функционально запись/досыл эквивалентны. |
| `prf` | 183-212 | 30 | TLS 1.2 PRF (HMAC-SHA256, P_hash) | rustls (внутренний TLS1.2 PRF) | P | собственной функции нет; KAT C (`test_tls12.c`) в Rust не перенесён |
| `d2k_tls12_prf_for_test` | 214-218 | 5 | тестовый экспорт PRF | нет | N | используется только `test_tls12.c:44,58`; Rust-аналога и векторов нет |
| `tr_add` | 220-225 | 6 | накопить транскрипт рукопожатия | rustls (транскрипт внутри) | P | хелпер стека; собственная функция отсутствует |
| `nonce_of` | 228-233 | 6 | nonce = salt(4)+seq(8) для GCM | rustls/ring AEAD nonce | P | хелпер record-layer |
| `aad_of` | 235-242 | 8 | AAD записи TLS 1.2 (seq/type/version/len) | rustls/ring AEAD AAD | P | хелпер record-layer |
| `send_plain` | 246-256 | 11 | отправить открытую запись | rustls `write_tls` | P | собственной функции нет |
| `send_sealed` | 258-282 | 25 | зашифровать и отправить запись (explicit nonce, seq++) | rustls `write_tls` | P | cipher suite/группы совпадают с C, но формат записи проверяется только косвенно |
| `read_record` | 287-345 | 59 | 5-байтный заголовок; `HTTP/` → отдельная ошибка; `rlen==0` или `>REC_MAX` → отказ; CCS без тела; открытая запись копируется; зашифрованная: nonce=salt+explicit, AAD seq/type/ver, AES-GCM, seq++ | rustls `read_tls` + `fetch.rs:2386-2437 R2oTlsRecordTracker` | **P** | **Подтверждённое расхождение:** C распознаёт открытый `HTTP/` в первых 5 байтах и возвращает «не TLS: открытый HTTP-ответ». В R2O поиск `HTTP/` в TLS-пути отсутствует (`grep` по `crates/` не находит такой проверки в `fetch.rs`/`r2o_tls.rs`); rustls вернёт `InvalidMessage`/`DecryptError`. `rlen==0/>18432`, CCS и AEAD-ошибки делегированы rustls с иными текстами. Счётчик байт — `R2oTlsTcpStream::read` (`fetch.rs:2464-2473`), оборванная запись — `R2oTlsRecordTracker::body_is_missing` (`:2434-2436`). |
| `hs_next` | 355-407 | 53 | собрать handshake-сообщения из записей, CCS/alert | rustls handshake driver | P | собственная state-machine отсутствует |
| `ch12_build` | 415-485 | 71 | ClientHello: version 3,3, random, пустой session_id, 2 шифра ECDHE_*_AES128_GCM_SHA256, группы X25519/0x0017/0x0018, EC formats, 4 sigalg, padding ext 21 до `want_wire` | rustls ClientHello + `r2o_client_hello_wire_len` (`r2o_tls.rs:53-115`, `fetch.rs:157 wire_len`) | **P** | **Совпадает:** два cipher suite в том же порядке ECDSA→RSA (`r2o_tls.rs:80-84`), группы X25519→SECP256R1→SECP384R1 (`:92-97`). **Расхождения:** (1) C **не шлёт ALPN**, `r2o_tls_client_connection` всегда ставит `http/1.1` (`r2o_tls.rs:59`), но путь `_with_alpn` (`:63-68`, `fetch.rs:244`) может передать снятый ALPN; базовый TLS12-путь расходится; (2) C объявляет P-384, но `tls12_finish` его не реализует, rustls `SECP384R1` принимает; (3) sigalgs C — 4 значения, у rustls шире; (4) padding C — расширение 21 нулями, rustls — `r2o_client_hello_wire_len`. Отдельного tls12-дифференциала длины CH нет. |
| `d2k_tls12_connect` | 492-522 | 31 | создать сессию, собрать/отправить CH, пройти handshake | `r2o_tls.rs:53 r2o_tls_client_connection(tls12=true)` | P | В R2O `versions=[TLS12]`, cipher suites и kx-группы совпадают; `R2oD2oServerCertVerifier.verify_finished=false` (`r2o_tls.rs:76-79,45-47`) — как C, который считает доказательством расшифровку Finished. Ветки ошибок C (группа/шифр/клиентский сертификат) в rustls иные. `donor_and_r2o_reject_short_tls12_server_finished`, `tests/fetch.rs` TLS12-сервер. |
| `d2k_tls12_resume` | 532-551 | 20 | продолжить handshake по сохранённому полёту сервера (downgrade из tls13.c) | rustls (автосогласование версии в одном соединении) | P | Отдельного resume нет; rustls сам выбирает TLS12 из общего ClientHello (`versions=[TLS13,TLS12]`, `r2o_tls.rs:70-74`). C-путь `d2k_tls12_resume` с внешним `srv` не воспроизведён как API; поведение downgrade покрыто только косвенно. |
| `tls12_finish` | 556-748 | 193 | ServerHello/Certificate/SKE/Done, ECDH X25519/P-256, PRF/ключи, CKE/CCS/Finished; отказ на P-384 SKE и клиентском сертификате | rustls handshake (TLS12) | **P** | Порт не построчный. **Подтверждено:** rustls TLS12 принимает `SECP384R1` (`r2o_tls.rs:92-97`), а C объявляет его, но отвергает SKE (`tls12.c:610-616`) — расхождение; C отвергает клиентский сертификат, rustls с `with_no_client_auth` ответит иначе; C не проверяет подпись сервера, rustls с `verify_tls12_signature→assertion` тоже. `donor_and_r2o_reject_short_tls12_server_finished` покрывает только короткий Finished. |
| `d2k_tls12_write` | 750-754 | 5 | отправить application data | `fetch.rs` rustls `Stream::write_all` | P | Эквивалент зависимости; C шлёт `REC_APPDATA` через `send_sealed`, rustls — `writer().write_all`. |
| `d2k_tls12_read` | 756-793 | 38 | прочитать app data, обработать alert/буферизацию | `fetch.rs:2464` + rustls `Stream::read` | P | Эквивалент зависимости; C `close_notify` (`alert[1]==0`) → 0, rustls возвращает `UnexpectedEof`/`Ok(0)` в зависимости от настроек; точная семантика не сопоставлена. |
| `d2k_tls12_peer_name` | 795-795 | 1 | результат проверки имени сертификата | `response.rs:389 https_certificate_name_matches`, `fetch.rs` peer-name | P | C заполняет `peer_name` при `HS_CERTIFICATE` через `d2k_t13_cert_name_ok12`; R2O проверяет DER отдельно (`response.rs:389`, `:687`) и в fetch-результате. Дифференциал `donor_and_r2o_tls_results_match_for_matching_and_mismatched_certificate_names`. |
| `d2k_tls12_free` | 797-797 | 1 | освободить сессию | RAII `Drop` | P | Владелец `d2k_tls12_connect`; отдельной функции нет. |
| `d2k_tls12_rx_wire_bytes` | 799-799 | 1 | счётчик принятых байт | `fetch.rs:1308,1333 rx_tls_wire_bytes` | P | Поле результата, не функция; считается в `R2oTlsTcpStream::read` (`fetch.rs:2464-2473`) и сверяется в volume-дифференциалах (`fetch.rs:3778,3861`). |
| `d2k_tls12_rx_record_missing` | 800-800 | 1 | сколько байт записи не дочитано (`uint32`) | `fetch.rs:2459-2461 r2o_record_missing` → `bool` | P | **Подтверждённое расхождение типа:** C возвращает число недостающих байт (`rx_record_missing`), Rust — `bool` (`body_is_missing`, `fetch.rs:2434-2436`), в результат кладётся `bool` (`fetch.rs:1334`). Для решения «обрыв записи» достаточно, для диагностики точного числа нет. |

## core/tls13.c (23 функции)

C-реализация TLS 1.3 клиента (X25519, HKDF-SHA256, AES-128-GCM) с веткой ECH и downgrade на TLS 1.2. R2O заменяет стек на `rustls`; собственная сборка ClientHello для повторов/позднего RX — `r2o_tls.rs:340 r2o_tls13_client_hello`, ECH — `r2o_tls.rs:274/305` + `ech.rs`. Дифференциалы: `scripts/r2o-tls-verify-differential.sh`, `scripts/r2o-ech-rx-ladder-differential.sh`, `tests/r2o_tls.rs`.

**Прочитано построчно: 23/23 функций, 613 строк C (1–613).** Сверено с `r2o_tls.rs:53-116,274-302`, `fetch.rs:947-1005` и тестами `tests/r2o_tls.rs`, `tests/d2o_verify_differential.rs`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `tls_dispose` | 83-85 | 3 | освободить сессию TLS1.3 и снять diag-учёт | `r2o_tls.rs` (rustls, RAII) | P | владелец `tls_connect_internal`; отдельной функции нет |
| `say` | 215-224 | 10 | `vsnprintf` ошибки в `err/cap` | `format!`/`io::Error` в `r2o_quic_http3.rs`/`quic_replay.rs` | **P** | C пишет текст в переданный буфер, молча выходит при `!err||cap==0`; Rust возвращает `io::Error`/`String`, вызывающий логирует. Контракт «назвать причину» тот же, тексты/владение иные. |
| `now_ms` | 226-236 | 11 | `CLOCK_MONOTONIC`, fallback `gettimeofday`, мс | `std::time::Instant`/`Duration` | **P** | C сначала `clock_gettime(CLOCK_MONOTONIC)`, иначе `gettimeofday`; Rust `Instant` монотонен и не имеет fallback. Единицы/точность пересчитываются, отдельной функции нет. |
| `read_exact` | 102-136 | 35 | дочитать n байт с дедлайном и учётом `rx_wire_bytes`/`rx_record_missing` | `fetch.rs:2464-2473 R2oTlsTcpStream::read`, `:2386-2437 R2oTlsRecordTracker` | P | C: `poll` квантами ≤1000 мс, повтор `EINTR`/`EAGAIN`, `rx_wire_bytes += r`, `rx_record_missing = n-got` для тела записи. Rust: `set_deadline` + `complete_io` в цикле (`fetch.rs:963-985`), байты считает `R2oTlsTcpStream::read`, оборванную запись — `R2oTlsRecordTracker::body_is_missing` (`bool`). Различаются кванты, EINTR-семантика, тексты и тип счётчика `uint32`→`bool`. |
| `write_all` | 138-154 | 17 | дослать буфер с MSG_NOSIGNAL | `R2oTlsTcpStream::write` (`fetch.rs:2475-2482`) + rustls `Stream` | P | C использует `MSG_NOSIGNAL` и повторяет `EINTR`/`EAGAIN`; Rust пишет через `TcpStream::write` и `complete_io`, отдельной EINTR-ветки нет. Функционально запись эквивалентна. |
| `put16` | 160-160 | 1 | big-endian u16 | `u16::to_be_bytes` | P | хелпер |
| `get16` | 161-161 | 1 | big-endian u16 | `u16::from_be_bytes` | P | хелпер |
| `nonce_of` | 165-170 | 6 | nonce = iv XOR seq | rustls/ring AEAD nonce | P | хелпер record-layer |
| `read_record` | 175-234 | 60 | 5-байтный заголовок; `HTTP/` → ошибка; `rlen==0/>REC_MAX` → отказ; CCS без тела; **до ключей** открытая запись копируется, **после ключей** открытый не-APPDATA тоже копируется (206-212); APPDATA: nonce=iv^seq, GCM, снятие нулевой набивки, внутренний тип | rustls `read_tls` + `fetch.rs:2386-2437 R2oTlsRecordTracker` | **P** | **Подтверждённое расхождение:** C распознаёт открытый `HTTP/` в первых 5 байтах отдельной ошибкой. В R2O поиск `HTTP/` в TLS-пути отсутствует (`grep` по `crates/` не находит его в `fetch.rs`/`r2o_tls.rs`), rustls вернёт `InvalidMessage`/`DecryptError`. C после ключей принимает открытую запись типа Handshake/Alert (`!encrypted \|\| hdr[0]!=REC_APPDATA`), rustls такой поток отвергает по RFC 8446. Внутренний тип/padding/AEAD обрабатывает rustls с иными текстами; оборванную запись фиксирует `R2oTlsRecordTracker`. |
| `write_record` | 236-258 | 23 | зашифровать app data с внутренним типом и тегом | rustls `write_tls` | P | формат записи C не сравнивается с rustls побайтно |
| `traffic_keys` | 260-263 | 4 | HKDF-Expand-Label key/iv | rustls (key schedule) | P | собственной функции нет |
| `tls_connect_internal` | 265-523 | 259 | session_id 32, ALPN http/1.1 или клиентский список, padding до `want_wire-5`, `offer_tls12 = !ech`, CH/ECH, ServerHello, downgrade TLS1.2, X25519, HKDF-расписание, серверный полёт до Finished, cert-name из транскрипта, CCS+Finished, app keys | `r2o_tls.rs:53-116 r2o_tls_client_connection`, `:274-302 r2o_tls_ech_client_connection`, `fetch.rs:947-1005` | **P** | **Совпадает:** TLS1.3+TLS1.2 без ECH, только TLS1.3 с ECH (`r2o_tls.rs:70-74`), ECH `verify_finished=true` (`:283`), обычный путь `verify_finished=false` (`:78`), ALPN http/1.1 по умолчанию (`:59`), сертификат не проверяется (`verify_server_cert→assertion`). **Отличия:** C сам собирает CH, шлёт пустой CCS перед Finished, ведёт транскрипт и HKDF-расписание; rustls делает это внутри. C при ServerHello 0x0303 вызывает `d2k_tls12_resume` с уже прочитанным `sh`, rustls автосогласует TLS1.2 в том же соединении. Ветки ошибок C (ECH not accepted, Finished mismatch, малая точка X25519) заменены rustls и не сравнивались. |
| `d2k_tls_connect` | 525-529 | 5 | TLS1.3 без ECH, `client_alpn=0` → ALPN `http/1.1`, `offer_tls12=1` | `r2o_tls.rs:53 r2o_tls_client_connection`, `fetch.rs:955` | **P** | Rust предлагает TLS1.3+TLS1.2 (`r2o_tls.rs:73`) и `http/1.1`; C-профиль расширений уже (4 sigalg, padding ext 21, session_id 32). End-to-end покрыт TLS-дифференциалом; побайтового CH нет. |
| `d2k_tls_connect_alpn` | 531-536 | 6 | TLS1.3 с явным списком ALPN (`client_alpn=1`) | `r2o_tls.rs:63-115 r2o_tls_client_connection_with_alpn`, `fetch.rs:244` | **E** | Unit `tests/r2o_tls.rs:101 клиентское_рукопожатие_предлагает_http11_alpn`, `:115 клиентское_рукопожатие_предлагает_наборы_донора`; Rust подставляет переданный `alpn_protocols` в `config.alpn_protocols` (`r2o_tls.rs:110`). |
| `d2k_tls_connect_ech` | 538-546 | 9 | ECH: origin + config обязательны, ALPN `http/1.1`, только TLS1.3, `verify_finished=true` | `r2o_tls.rs:274-302 r2o_tls_ech_client_connection` | **P** | Rust: только TLS1.3 (`with_ech`), cipher TLS13_AES_128_GCM_SHA256, группы X25519/SECP256R1, ALPN http/1.1, `verify_finished=true`. C требует origin/config; живой ECH-путь не сверялся, replay покрыт `donor_and_r2o_require_server_hello_when_replaying_captured_ech`. |
| `d2k_tls_ech_accepted` | 548-548 | 1 | флаг `t->ech_accepted` | `fetch.rs:987-993 connection.ech_status()==Accepted` | **P** | C ставит флаг после `d2k_t13_ech_accepted`; Rust при ECH требует `EchStatus::Accepted` и иначе ошибка (`fetch.rs:987-992`), затем `ech_accepted=Some(true)` (`:993`). C-оракул для флага не подключён. |
| `d2k_tls_write` | 550-560 | 11 | запись app data частями ≤16 КиБ, делегирование TLS1.2 | `fetch.rs:1007 StreamOwned` + rustls `Stream::write_all` | P | C режет на 16384 и шлёт `write_record`; rustls `Writer::write_all` сам режет по пределу записи. При `t->v12` C делегирует `d2k_tls12_write`; в R2O версия одна — rustls-соединение. Эквивалент зависимости. |
| `d2k_tls_read` | 562-601 | 40 | чтение app data, CCS/alert/handshake, буферизация, делегирование TLS1.2 | `fetch.rs:1007` + rustls `Stream::read` | P | C пропускает CCS/Handshake, `close_notify` (`alert[1]==0`) → 0, остальные alert → -1, буферизует остаток; rustls `Stream::read` возвращает `Ok(0)` на close_notify и ошибку на прочих alert. Тексты/точная семантика не сопоставлены. |
| `d2k_tls_peer_name` | 603-603 | 1 | результат проверки имени сертификата: 1/0/-1 | `fetch.rs:1000-1005 peer_name_ok`, `response.rs:389 https_certificate_name_matches` | **E** | C `d2k_t13_cert_name_ok` из Certificate транскрипта → `peer_name`; Rust берёт первый `peer_certificates()` и `https_certificate_name_matches` → `Option<bool>`. Дифференциал `d2o_verify_differential.rs:719 donor_and_r2o_tls_results_match_for_matching_and_mismatched_certificate_names`. |
| `d2k_tls_free` | 605-608 | 4 | освободить TLS1.3/вложенный TLS1.2 | RAII `Drop` | P | Отдельной функции нет; вложенный `v12` в R2O отсутствует (одно rustls-соединение). |
| `d2k_tls_rx_wire_bytes` | 610-610 | 1 | суммарные принятые байты (обе версии) | `fetch.rs:1308,1333 rx_tls_wire_bytes`, `:2464-2473` | P | Поле результата; считается `R2oTlsTcpStream::read`, сверяется в volume-тестах (`fetch.rs:3778,3861`). C суммирует TLS1.3 + вложенный TLS1.2. |
| `d2k_tls_rx_record_missing` | 611-611 | 1 | недобор байт записи (обе версии) | `fetch.rs:2459-2461 r2o_record_missing` → `bool` | P | **Тип расходится:** C — `uint32` байт, Rust — `bool` (`body_is_missing`), в результат кладётся `bool` (`fetch.rs:1334`). Решение «обрыв записи» эквивалентно, точного числа нет. |
| `d2k_tls_version` | 613-613 | 1 | 0x0304/0x0303/0 | `fetch.rs:995-999 protocol_version → "1.3"/"1.2"` | **E** | Rust `ProtocolVersion::TLSv1_3→"1.3"`, `TLSv1_2→"1.2"`, иначе `None`; тесты `d2o_verify_differential.rs:755,862,909,955` проверяют `Some("1.3")`, `:1426` — по метке. |

## core/tls13core.c (24 функции)

Ядро TLS 1.3/ECH: DER-разбор SAN, сборка ClientHello, расписание ключей, разбор ServerHello, HPKE для ECH. Часть перенесена почти построчно: `response.rs` (SAN), `r2o_tls.rs:340 r2o_tls13_client_hello`, `ech.rs`. Дифференциалы: `tests/response.rs::d2o_shared_tls_response_vectors_match`, `tests/r2o_tls.rs`, `scripts/r2o-ech-rx-ladder-differential.sh`.

**Прочитано построчно: 24/24 функций, 701 строка C (1–701).** Сверено с `response.rs:382-538` (DER/SAN), `r2o_tls.rs:340-475` (сборка CH), `ech.rs:364-480` (разбор ECHConfigList/имени).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `put16` | 16-16 | 1 | big-endian u16 | `r2o_tls.rs:486 push_u16` | E | хелпер сборщика CH; владелец `d2k_t13_ch_build` → `r2o_tls13_client_hello`, unit `tests/r2o_tls.rs` |
| `get16` | 17-17 | 1 | big-endian u16 | `u16::from_be_bytes` | E | хелпер разбора ServerHello/сертификата; владельцы покрыты дифференциалами |
| `d2k_t13_random` | 21-27 | 7 | 32 случайных байта из /dev/urandom | `ring`/`getrandom` (через rustls, `ech.rs`) | P | прямого API нет; источник энтропии заменён зависимостью |
| `der_len` | 53-62 | 10 | длина DER-объекта: short form `<0x80`; long form `n&0x7f` 1..4; `n==0`/`avail<1+n` → 0 | `response.rs:485-500 https_der_length` | E | C и Rust одинаково: `first<0x80 → (first,1)`; `n=first&0x7f`, `n==0\|\|n>4\|\|len<n+1 → (0,0)`; значение big-endian. C возвращает 0 при ошибке и пишет `*hdr`, Rust — `(0,0)`. Differential `tests/response.rs:479 d2o_shared_tls_response_vectors_match`. |
| `ascii_lower` | 64-64 | 1 | ASCII lower | `response.rs:508-514 lower_ascii` (вложенная) | E | C: `'A'..='Z' → +32`; Rust `is_ascii_uppercase() → + (b'a'-b'A')`. Побайтово эквивалентно; входит в SAN-сравнение. |
| `name_matches` | 73-96 | 24 | сравнение DNS-имени: wildcard только `*.` в первой метке, иначе точное сравнение без регистра | `response.rs:507-538 https_dns_name_bytes_match` | E | C: `plen>2 && pat[0]=='*' && pat[1]=='.'` → отбрасывает первую метку host, `rlen==plen-2`, сравнение без регистра; иначе `plen==hlen` и побайтовое сравнение. Rust `https_dns_name_bytes_match` делает то же (`starts_with(b"*.")`, `dot==0`, суффикс, `lower_ascii`). Differential `d2o_shared_tls_response_vectors_match`, `d2o_verify_differential` (mismatch/invalid UTF-8/zero-length IP). |
| `cert_name_ok` | 106-154 | 49 | поиск subjectAltName 2.5.29.17 по байтам, optional critical, OCTET STRING, GeneralNames SEQUENCE, dNSName 0x82/iPAddress 0x87, wildcard | `response.rs:389-483 https_certificate_name_matches` | E | Ветви сверены: OID `06 03 55 1d 11`; optional `01 01 xx` → +3; требование `0x04`; DER-длина; `0x30` GeneralNames; цикл по GeneralNames; `0x82` dNSName + `name_matches` при не-IP хосте; `0x87` iPAddress + точное сравнение; `(saw_dns\|\|saw_ip) ? false : None`. Rust повторяет те же шаги и границы (`https_der_length`, `https_dns_name_bytes_match`). Отличие API: C `-1/0/1`, Rust `None/Some(false)/Some(true)`. Differential `tests/response.rs:479`, `d2o_verify_differential.rs:719`. |
| `d2k_t13_cert_name_ok12` | 166-175 | 10 | SAN из Certificate TLS1.2: 3-байтовая длина списка, 3-байтовая длина первого серта | `response.rs:389 https_certificate_name_matches` | E | C разбирает TLS1.2-обёртку (`list≥3`, `o+list≤len`, `clen>0`, `o+clen≤len`) и передаёт DER в `cert_name_ok`. Rust получает листовой DER от rustls (`peer_certificates()[0]`) и проверяет тем же парсером; TLS1.2-путь сверяется `donor_and_r2o_tls_results_match_...`. |
| `d2k_t13_cert_name_ok` | 177-189 | 13 | SAN из Certificate TLS1.3: context length + 3-байтовая длина списка + первый серт | `response.rs:389 https_certificate_name_matches` | E | C: `ctx=body[0]`, `o=1+ctx`, `o+3≤len`, `list`, `clen`, DER. Rust получает листовой DER от rustls; framing делает rustls. Тот же SAN-парсер; TLS1.3 differential. |
| `d2k_t13_ch_build` | 197-357 | 161 | CH: session_id≤32 (байты random), cipher_suites 0x1301[+0xc02b+0xc02f], SNI, ec_formats, groups X25519[+P-256], 9 sigalg, supported_versions [1.3(+1.2)], ALPN wire/str, psk_dhe_ke, extra, key_share X25519, padding 0x0015 | `r2o_tls.rs:340-475 r2o_tls13_client_hello` | **E** | **Побайтовый порт:** `[1,0,0,0]`+0x0303+random+session_id; `offer_tls12` → cipher `0x1301,0xc02b,0xc02f`, иначе `0x1301`; SNI `name.len()<256`; `0x000b` `[1,0]`; `0x000a` `[1d,17]` или `[1d]`; `0x000d` те же 9 sigalg (0403/0503/0603/0804/0805/0806/0401/0501/0601); `0x002b` те же версии; ALPN wire/str с теми же лимитами 256/255; `0x002d [1,1]`; extra; `0x0033` X25519 32; padding `0x0015`. Rust дополнительно ограничивает `pad_to/extra` 4096 и проверяет NUL в SNI. Unit `tests/r2o_tls.rs:183` (padding), `:212` (session_id), `:101/115` (ALPN). |
| `d2k_t13_derive_secret` | 361-366 | 6 | Derive-Secret(Transcript-Hash) | rustls key schedule | P | C: `SHA256(msgs)` + `hkdf_expand_label_ctx(secret,label,th,32,out,32)`. Собственной функции в R2O нет — ключи считает rustls; C-векторов/KAT в Rust нет. |
| `d2k_t13_schedule_hs` | 368-381 | 14 | early→handshake secret, c/s hs traffic | rustls key schedule | P | C: `HKDF-Extract(0,0)` → `derived` → `HKDF-Extract(derived,shared)` → `c hs traffic`/`s hs traffic`. Rust — внутри rustls; отдельного выхода `hs` нет. |
| `d2k_t13_schedule_ap` | 383-394 | 12 | master secret, c/s ap traffic | rustls key schedule | P | C: `derived2=Derive-Secret(hs,"derived","")`, `master=HKDF-Extract(derived2,0)`, `c/s ap traffic`. Rust — внутри rustls. |
| `d2k_t13_finished_mac` | 396-403 | 8 | finished_key + HMAC(transcript) | rustls | P | C: `hkdf_expand_label(secret,"finished")`, `SHA256(tr)`, `HMAC`. Rust — внутри rustls; C-векторов в Rust нет. |
| `d2k_t13_sh_version` | 407-426 | 20 | версия из ServerHello.supported_versions (downgrade-детект): legacy 0x0303, расширение 0x002b len=2 | rustls (version negotiation) | P | C разбирает `legacy_version`, session_id, cipher/compression, расширения и возвращает supported_versions или legacy. Rust выбирает версию внутри rustls; отдельной функции/downgrade-сверки нет. |
| `d2k_t13_sh_parse` | 428-475 | 48 | разбор ServerHello: session_id, cipher==0x1301, расширения, key_share 0x001d len=32 | `r2o_tls.rs:200-250 r2o_tls_replay_client_hello` (только критерий ServerHello), rustls (полный разбор) | P | C находит `peer_key`; Rust `r2o_tls_replay_client_hello` читает 6–7 байт и проверяет `b[0]==22,b[1]==3,b[5]==2` (это критерий донора, не разбор SH). Полный разбор SH и проверка cipher/key_share — внутри rustls; C-оракула на `d2k_t13_sh_parse` нет. |
| `d2k_t13_flight_next` | 479-490 | 12 | итератор handshake-сообщений: 4-байтный заголовок, длина 24 бита, обрыв → 0 | rustls (внутренний обход) | P | Отдельной публичной функции нет; C-итератор используется в `tls13.c` для Finished/Certificate. Rust получает сообщения от rustls. |
| `ech_host_ok` | 492-508 | 17 | публичное имя ECH: непустое, ≤253, метки 1..63, первый/последний символ не `.`/`-`, только alnum/`-` | `ech.rs:464-480 r2o_ech_public_name` | **P** | Логика эквивалентна: Rust `name.len()<=253`, `is_ascii`, split('.') → непустая метка ≤63, не начинается/заканчивается `-`, только `is_ascii_alphanumeric() \|\| '-'`. C дополнительно проверяет `p[0]!='.'`/`p[n-1]!='.'` (Rust это ловит пустой первой/последней меткой). C-тестов/дифференциала на границы нет; unit Rust на `r2o_ech_public_name` не найден. |
| `d2k_ech_config_parse` | 510-567 | 58 | ECHConfigList: outer length, version 0xfe0d, config_id, KEM 0x20, key_len 32, suites 0x0001/0x0001, max_name, public_name (`ech_host_ok`), extensions + mandatory unknown; первый валидный | `ech.rs:364-462 r2o_ech_select_config`, `:158 resolve_ech_config` | **P** | Ветви сверены и совпадают: outer length `== len-2`; цикл по конфигурациям; версия `0xfe0d`; `config_end=+4+len`; `config_id`; KEM `0x20`; `key_len=32`; suites `len%4==0` и `[0,1,0,1]`; `max_name`; `name_len`+`r2o_ech_public_name`; extensions length `== end-cursor`; mandatory bit `0x8000`; выбор первой валидной с `end-start<=512`. **Отличие представления:** C хранит `wire` = ECHConfig (4-байтный заголовок version/length + тело) без внешней 2-байтной длины; Rust хранит `config_list` = внешняя 2-байтная длина + ECHConfig, как требует `rustls::client::EchConfig::new` (`ech.rs:151-155`). HPKE-info в обоих использует сам ECHConfig. C/Rust differential на границы разбора не заявлен. |
| `hpke_extract` | 570-581 | 12 | HPKE-v1 labeled Extract: `HPKE-v1` + suite + label + ikm → HMAC | `hpke` crate (`ech.rs:63-144 R2oEchHpke`) | **P** | C вручную собирает `HPKE-v1‖suite‖label‖ikm` и вызывает `d2k_hkdf_extract`; Rust отдаёт HPKE crate (`setup_sender/setup_receiver`). C-векторов HPKE в Rust нет. |
| `hpke_expand` | 583-596 | 14 | HPKE-v1 labeled Expand: 2-байтная длина + `HPKE-v1` + suite + label + info, один HMAC-блок, out≤32 | `hpke` crate | **P** | C ограничивает `out_len<=32` и собирает `b[n]=1` (один блок); Rust — внутри crate. Собственной функции/векторов нет. |
| `ech_hpke` | 598-619 | 22 | X25519 base/shared, context=enc‖pk, info=`tls ech\0`‖config, HPKE extract/expand key/base_nonce, suite `HPKE(0x20,0x0001,0x0001)` | `ech.rs:63-144` через `hpke` | **P** | C: `d2k_x25519_base`/`d2k_x25519`, `eae_prk`/`shared_secret`/`psk_id_hash`/`info_hash`/`secret`/`key`/`base_nonce`. Rust: `hpke::setup_sender::<AesGcm128,HkdfSha256,X25519HkdfSha256>`; `suite()` объявляет `DHKEM_X25519_HKDF_SHA256`/`HKDF_SHA256`/`AES_128_GCM` (`ech.rs:135-143`). Байтового differential нет. |
| `d2k_t13_ech_build` | 621-682 | 62 | inner CH с ECH-расширением, outer CH с public_name, HPKE enc/config_id, AES-GCM шифрование inner, padding | `r2o_tls.rs:274-306 r2o_tls_ech_client_hello` (rustls) | **P** | Rust строит ECH через rustls `EchMode::Enable`, а не повторяет байтовую раскладку C (inner/outer, offset `39+sid`, `42+plain+16`, `maximum_name_length`). ECH-дифференциал проверяет RX-лестницу/повтор, не байты CH; C-оракул на `d2k_t13_ech_build` не подключён. |
| `d2k_t13_ech_accepted` | 684-701 | 18 | accept_confirmation: SHA-256(inner + ServerHello с обнулёнными 8 байтами), HKDF `ech accept confirmation`, сравнение 8 байт | `fetch.rs:987-993 connection.ech_status()==Accepted` | **P** | C вручную считает HKDF и сравнивает `sh[30..38]`; Rust проверяет статус rustls `EchStatus::Accepted` и иначе возвращает ошибку. C-оракул на accept_confirmation не подключён; дифференциал ECH-RX проверяет исход, не эту функцию. |

## core/verify.c (74 функции)

Проверочный зонд D2O: TCP/TLS 1.2/1.3 + HTTP/1.x, бюджет keep-alive, Discord Gateway WebSocket, QUIC/HTTP/3. В R2O основной преемник — `r2o-controller/src/fetch.rs` (страницы, бюджеты, Gateway), `r2k-core/src/http_response.rs` (HTTP-framing), `r2o_quic_http3.rs` (QUIC/H3), `ech.rs`. Дифференциалы: `scripts/r2o-tls-verify-differential.sh` (C `verify.o` как оракул), `scripts/test-http-chunk-framing-differential.sh`, `scripts/r2o-http-search-differential.sh`.

**Прочитано построчно: 74/74 функций, 2156 строк C (1–2156).** Сверено с `ech.rs:158-340` (DNS/HTTPS RR), `http_response.rs:1-389` (HTTP-framing), `fetch.rs:331-376,1080-1225,2650-2737` (replay, тело, бюджет).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `verify_now_ms` | 52-56 | 5 | монотонное время, мс | `std::time::Instant` | P | инфраструктурный хелпер |
| `dns16` | 58-58 | 1 | big-endian u16 DNS | `u16::from_be_bytes` | P | хелпер DNS-резолва ECH |
| `ech_dns_name` | 62-88 | 27 | разбор DNS-имени с компрессией, нижний регистр, лимит 253 | `ech.rs:482 r2o_ech_dns_name` | E | построчный порт; DNS-кейсы ECH-резолва в `tests`/`donor` (см. `ech.rs` unit) |
| `d2k_ech_resolve` | 90-184 | 95 | резолв HTTPS RR (type 65) через `/etc/resolv.conf`, UDP/53, SO_MARK, 1500 мс; проверка заголовка/вопроса/ответов ≤64/параметров; выбор ECHConfig | `ech.rs:158-233 resolve_ech_config` → `:164 r2o_ech_system_resolver`, `:182 r2o_ech_query_resolver`, `:269 r2o_ech_parse_https_reply`, `:364 r2o_ech_select_config` | **P** | **Исправление 2026-11-12:** прежняя запись «Rust через системный resolver/HTTPS-запрос» неверна. Rust читает тот же `/etc/resolv.conf`, берёт первый `nameserver`, шлёт UDP/53 с `SO_MARK` (если mark≠0), таймаут 1500 мс, проверяет id/QR/rcode/qdcount, вопрос name/type 65/class 1, answers ≤64, владельца/тип/класс, SvcPriority>0, target, строго возрастающие ключи, port 443, key 5 → `r2o_ech_select_config` (та же логика, что `d2k_ech_config_parse`). **Отличия:** C при отсутствии/нечитаемости `/etc/resolv.conf` использует 127.0.0.1, Rust возвращает ошибку; Rust срезает конечную точку и требует ASCII, C понижает регистр и отвергает недопустимые байты метки; C хранит ECHConfig без внешней 2-байтной длины, Rust `config_list` — с ней (требование `rustls::client::EchConfig::new`). C/Rust differential на DNS-разбор не заявлен. |
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
| `body_line` | 352-375 | 24 | CRLF-строка chunked/трейлера, максимум 127 байт; переполнение помечает `local_limit` | `http_response.rs:226-271 feed_line_byte` (`LINE_CAPACITY=128`) | **P** | **Подтверждённые отличия:** (1) C при строке >127 ставит `s->local_limit=1` и текст «chunked: строка длиннее…»; Rust помечает парсер `invalid`, а `fetch.rs:1171-1173` выставляет `local_limit` только для переполнения **заголовков** (`!headers_complete && headers.len()>=65536`), поэтому переполнение chunk-строки даёт `local_limit=false`. (2) Rust `feed_line_byte` разрешает произвольные байты в chunk-extension (после `;`) и trailers (`:230-233`), C проверяет только CR/LF и длину, но не NUL/control; в строке размера Rust дополнительно отвергает NUL/control (`invalid_line_byte`). Обрамление CRLF/LF/пустой размер совпадает; дифференциал привязан к D2O `a63d9641`, для `a378` не перезапускался. |
| `read_http_body` | 380-445 | 66 | 204/304 без тела; Content-Length; chunked с trailer; иначе до EOF; `body_expected` | `http_response.rs:55-271`, `fetch.rs:1206-1209` | **P** | Обрамление совпадает (204/304, CL, chunked, close, overflow, trailer; Rust `finish_headers` `head_only \|\| 204|304 → complete`). **Подтверждённое расхождение `body_expected`:** C для chunked и close-delimited выставляет `body_expected = body_bytes`; Rust `fixed_body_remaining()` даёт `Some` только для Content-Length, `r2o_body_expected_at_eof` (`fetch.rs:1107-1109,1189-1191`) — только остаток fixed body; для chunked/close `body_expected=None` → в `R2oVolumeObservation` 0. |
| `read_status_buf` | 457-697 | 241 | статус HTTP/1.0-1.1 100-599, NUL/управляющие, cf-challenge, CL/TE/CE/Connection/Location, 1xx, 101, тело, `http_reply` | `http_response.rs:160-321` + `fetch.rs:1084-1235` | **P** | **Совпадает:** заголовки 64 КиБ, NUL/управляющие, статус-строка, 1xx (сброс и ожидание следующего), CL/TE, CE, cf-challenge, 451, resource-scan. **Подтверждённые отличия:** (1) C при `framing_valid=false` (дубликат/не-chunked TE, **дубликат Location**, CL+TE) **не читает тело**; Rust `parse_headers` (`http_response.rs:281-319`) отвергает не-chunked TE/дубликат TE/CL+TE, но **Location не разбирает**, поэтому дубликат Location не делает ответ invalid, и тело дочитывается; (2) C `101` возвращает код 0, Rust сохраняет `status=101` при `invalid` (`http_response.rs:200-204`); (3) C Location ограничен `location_cap` и при переполнении остаётся пустым, Rust `header_value(...).map(String::from_utf8_lossy)` без предела (`fetch.rs:1214-1216`); (4) C `conn_close` учитывает HTTP/1.0 без keep-alive и тело без CL/chunked, Rust `r2o_http_connection_closes` — только явный `Connection: close` (`fetch.rs:2632-2648`). |
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
| `budget_tcp` | 1146-1213 | 68 | need=budget*2; проверка пакетов/conn_close/роста; повтор точного `req`; `budget_requests`; молчание→CUT, закрытие/битый ответ→NOT_APPLICABLE | `fetch.rs:2650-2737 r2o_measure_http_packet_budget` | **P** | **Подтверждённые расхождения:** (1) Rust на повторе собирает `build_request(&options.name,&options.path,encoding)` (`fetch.rs:2686`), а не повторяет фактически отправленный запрос (у C после redirect — `req`); (2) общий `deadline` (`:2674,2698`) вместо сброса `deadline_ms` на каждый повтор; (3) нет `budget_requests` и `fd_peer_spoke`; закрытие/EOF сразу дают `NotApplicable` (`:2669-2670,2728-2729`), таймаут — `Cut` (`:2700,2723`), тогда как C различает молчание, закрытие и битый ответ; (4) `connection_close` Rust обновляет через `eof \|\| r2o_http_connection_closes` (`:2731`), у C — `conn_close` из `read_status_buf`. Отдельного C/Rust differential бюджета нет. |
| `fd_peer_spoke` | 1217-1222 | 6 | `poll` с `POLLIN`, `POLLHUP`, `POLLERR`, таймаут 0 после неудачного чтения | нет | **P** | **Подтверждённый пробел:** в Rust budget-цикле после ошибки чтения peer не опрашивается; EOF/ошибка сразу дают `NotApplicable`, таймаут — `Cut`. C различает «сервер закрыл» и «коробка молчит». |
| `fd_packets` | 1223-1223 | 1 | `d2k_verify_packets_hook(fd)` | `fetch.rs:2650` `packet_counter(&stream.sock.socket)` | **P*** | C подменяемый hook; Rust замыкание `impl FnMut(&TcpStream)->Option<u32>`, в production — `r2o_tcp_counters`. |
| `request_complete_page` | 1238-1245 | 8 | `request_page_budget(..., io=NULL, budget=0)` | `fetch.rs:804 r2o_fetch_with_encoding` | **P** | C-обёртка без бюджета; Rust отдельного режима нет — бюджет опционален (`packet_budget: Option<u32>`). End-to-end differential покрывает обычный GET. |
| `request_page_budget` | 1247-1343 | 97 | GET с редиректами (3), gzip/identity, Gateway-ветка, бюджет | `fetch.rs:863-1363`, `:2650` | **P** | Differential `donor_and_r2o_send_the_same_default_verification_request` проверяет только байты `GET /`. **Подтверждённые расхождения:** (1) C передаёт в `budget_tcp` фактически отправленный `req` (`verify.c:1315,1329`), Rust на повторе строит `build_request` из `options.path` (`fetch.rs:2686`); (2) C сбрасывает `deadline_ms` на каждый повтор, Rust — общий `deadline`; (3) C следует same-origin redirect при `body_framing_valid` без `body_complete` (`verify.c:1297`), Rust требует `complete` (`fetch.rs:1251`); (4) C-классификация CUT/NotApplicable и `budget_requests` не воспроизведены; (5) Gateway-ветка C выбирается по `initial_path==NULL && host=="gateway.discord.gg"`, Rust — по `options.gateway`/цели (`fetch.rs:1050+`). |
| `verify_contact` | 1349-1363 | 15 | при mark: bind family, `d2k_mark_hook`, затем contact с `g_verify_tcp_timestamps` | `fetch.rs:3017 connect_target`, `:3029 connect_marked` | **P** | mark ставится до connect, family 4/6 поддержаны. **Подтверждённое расхождение:** C передаёт `g_verify_tcp_timestamps` (thread-local профиль) в contact; Rust `connect_target/marked` профиль TCP timestamps не принимает. |
| `d2k_props_contact_on_family_tcp_profile` | 1360-1361 | 2 | ложное срабатывание парсера: хвост вызова внутри `verify_contact`, не определение | `fetch.rs:3017 connect_target` (владелец `verify_contact`) | **P*** | Это **не функция**: строки 1360-1361 — продолжение `return d2k_props_contact_on_family_tcp_profile(...)` внутри `verify_contact` (`verify.c:1349-1363`). Реальная функция — `compose.c:638-753`, уже учтена в `core-state.md` как P. Отдельного Rust-аналога строка не требует; статус P*, чтобы не терять строку реестра. |
| `verify_probe13_internal` | 1365-1442 | 78 | path-check, Host-контроль, family, contact с mark/TS-профилем, TLS1.3/ECH, name_ok, page+budget, rx-байты, data_packets; **сокет остаётся открытым** | `fetch.rs:863-1363`, `:3017 connect_target`, `:200-222 FetchResult` | **P** | Совпадают path/имя, TLS/ECH, name_ok, page, бюджет, rx-байты/пакеты, `local_refusal`. **Подтверждённые расхождения:** (1) C после зонда освобождает TLS-сессию, но **не закрывает fd** — «иначе FIN потеряет ячейку потока в датапате» (`verify.c:1437-1440`); Rust `FetchResult` не содержит fd (`fetch.rs:200-222`), `TcpStream` закрывается при выходе из fetch; (2) C передаёт `g_verify_tcp_timestamps` в contact, Rust TCP-профиль не принимает; (3) C валидирует Host только как байты >32/≠127, Rust `FetchOptions::validate` дополнительно отвергает `/ \\ @ [ ]` и проверяет `ServerName`. `r2o-tls-verify-differential.sh` покрывает уровень/TLS/name_ok/complete/байты, не fd. |
| `verify_probe13_on` | 1444-1449 | 6 | обёртка TLS1.3 без ECH (`ech=NULL`) | `fetch.rs:844 r2o_fetch_with_phase_timeout` | **E** | C-обёртка пути NULL; Rust `r2o_fetch_with_phase_timeout` → TLS1.3/TLS1.2 без ECH. `r2o-tls-verify-differential.sh`. |
| `ech_http_denial` | 1451-1460 | 10 | status 429 и level не DENIED/BLOCKPAGE → CHALLENGE, reason «не усиливать отказ» | `main.rs:14518-14535 r2o_ech_witness_transport_proof`, `:27000+` unit | **E** | Rust принимает ECH-witness при `status==429 && !Blocked && !LegalDenial` (или cf-challenge), `complete`, TLS/ECH/name_ok. Unit `ECH witness 429 rate limits must match the donor challenge classification`. |
| `d2k_verify_probe_ech_on` | 1462-1476 | 15 | требует config+origin; probe13 encoding 0 + ECH; затем `ech_http_denial` | `fetch.rs:738-760 r2o_fetch_ech_connected_stream` | **P** | Rust требует `EchConfig`, делает Identity-запрос, при `ech_status()!=Accepted` возвращает ошибку, `ech_accepted=Some(true)`; 429-классификация — в witness-слое. C вызывает probe13 с encoding 0 и отдельно `ech_http_denial`. Живой ECH-зонд C/Rust differential не покрыт. |
| `d2k_verify_probe_ech_origin_on` | 1478-1492 | 15 | `d2k_ech_resolve(origin,dns_mark)`, точное `outer_name == config.public_name`, затем probe с mark только при `use_fd<0` | `ech.rs:158-220 resolve_ech_config`, `:150 r2o_ech_tls_config`, `main.rs:14490+` | **P** | Rust резолвит HTTPS RR через `/etc/resolv.conf` + UDP/53 с SO_MARK и строит `R2oEchConfig{public_name,origin_name,config_list}`; **сверка `outer_name == public_name` в `r2o_ech_tls_config` не выполняется** — её делает вызывающий discovery. DNS-путь/точное сравнение C/Rust differential не покрыты. |
| `d2k_verify_replay_on` | 1499-1562 | 64 | contact с TS-профилем, poll/recv 16 байт, ServerHello `16 03 ?? 02` → HANDSHAKE+replay_proof, alert, иное/тишина | `fetch.rs:331-376 r2o_verify_tls_replayed_client_hello`, `r2o_tls.rs:199-250 r2o_tls_replay_client_hello` | **P** | Rust повторяет сохранённый ClientHello: `write_all`, затем читает до 7 байт, пока `have<7 && !(have>=6 && response[0]==22)`, критерий `have>=6 && response[0]==22 && response[1]==3 && response[5]==2`; возвращает `handshake_verified=proof`, `tls=None`, reason. C дополнительно распознаёт alert (7 байт, тип 21) и формирует отдельные reason для «не ServerHello»/«тишина»; Rust сводит к `proof=false`. **Отличия:** C передаёт `g_verify_tcp_timestamps` в contact (`verify.c:1512-1514`) и оставляет fd открытым; Rust TCP TS-профиль не принимает, `TcpStream` закрывается при выходе (`fetch.rs:331-376`). Байтовый критерий ServerHello совпадает; differential `donor_and_r2o_require_server_hello_when_replaying_captured_ech`, `...absolute_deadline_to_replayed_client_hello`. |
| `d2k_verify_probe_on` | 1564-1568 | 5 | probe13 encoding=2, path NULL | `fetch.rs:844 r2o_fetch_with_phase_timeout` | **E** | `donor_and_r2o_send_the_same_default_verification_request`. |
| `d2k_verify_probe_alpn_on` | 1578-1625 | 48 | TLS-проба с ALPN клиента, без прикладного уровня | `fetch.rs:225-330 r2o_verify_tls_connected_stream_with_alpn` | **E** | Rust завершает handshake, возвращает TLS/name_ok/handshake_verified и reason «приложение не измерялось»; differential `donor_and_r2o_preserve_captured_mqtt_and_absent_alpn`. |
| `verify_probe12_internal` | 1636-1701 | 66 | полный зонд TLS1.2 (contact, handshake, page, бюджет) | `fetch.rs` с `tls12=true` | **P** | `donor_and_r2o_reject_short_tls12_server_finished` + `r2o-tls-verify-differential.sh` покрывают TLS1.2-handshake/отказ. **Подтверждённые отличия:** C передаёт `g_verify_tcp_timestamps` в contact и оставляет fd открытым после `d2k_tls12_free` (`verify.c:1660-1699`); Rust TCP TS-профиль не принимает, `TcpStream` закрывается при выходе из fetch. |
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

**Прочитано построчно: 2/2 функции, 127 строк C (1–127).**

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `replay_now_ms` | 23-27 | 5 | монотонное время, мс | `std::time::Instant` | **P*** | static-хелпер; C `CLOCK_MONOTONIC` в мс, Rust `Instant` с `Duration` — монотонность та же, единицы пересчитываются. |
| `d2k_verify_quic_replay_on` | 29-127 | 99 | parse→recid(reseal)→parse, family по `:`, port 443, connect/getsockname, отправить **все** датаграммы, poll/recv 1600 до 3000 мс, `d2k_quic_verify_bound`, HANDSHAKE/replay_proof | `quic_replay.rs:649-790 QuicReplayProbe::{prepare,prepare_fresh,from_socket,run,r2o_run_inner}`, `quic_snapshot.rs:79 r2k_quic_snapshot_reseal`, `:116 r2k_quic_snapshot_verify_bound_response` | **P** | **Совпадает:** reseal всех датаграмм под один DCID (`from_socket:679-690`), отправка всех датаграмм с проверкой полной отправки (`r2o_run_inner:752-761`), проверка bound-ответа Initial/Retry (`:778`), `handshake_confirmed`, `foreign_responses` (`:783`). **Подтверждённые отличия:** (1) C reseal'ит один раз за вызов; Rust `r2o_run_inner` **перезапечатывает заново на каждый `run`** (`:731-749`), т.е. новый DCID на повторный запуск; (2) C `deadline_ms` без верхнего предела (default 3000), Rust default-константа и обрезка до 10 с (`:763-767`); (3) C при ошибке parse/reseal закрывает переданный `use_fd`, Rust владеет `UdpSocket` и закрывает его Drop, но `try_clone_socket` позволяет передать сокет HTTP/3; (4) C `static __thread fresh[D2K_SHAPE_MAX]`, Rust `Vec`; (5) C `inet_pton`+`connect`, Rust `SocketAddr` с проверкой `port!=0/ip!=unspecified` (`:650-677`). C/Rust differential именно для verify-quic-replay нет. |

## core/httpsprobe.c (22 функции)

Асинхронный HTTPS-зонд (TCP 443 → first flight → TLS1.3/1.2) и кэш состояний `d2k-https`. В R2O: `r2o-controller/src/https_probe.rs` (воркер, кэш, save/load), `response.rs` (классификация и TLS-проба). Дифференциал: `scripts/test-controller-httpsprobe-differential.sh` (C `httpsprobe.o` против `examples/tg_cl13_httpsprobe_trace.rs`, кэш/состояния/загрузка).

**Прочитано построчно: 22/22 функций, 564 строки C (1–564).**

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_https_classify` | 32-40 | 9 | REFUSED→CLOSED; не CONNECTED→UNCONFIRMED; !server_tls→TLS_BLOCKED; !tls_ok→UNCONFIRMED; peer 1→SERVED, 0→OTHER_NAME, иначе UNCONFIRMED | `response.rs:90-107 classify_https_probe` | **E** | Построчно совпадает; differential httpsprobe + unit `classify_matches_d2o_https_state_machine`. |
| `d2k_https_upgrade` | 42-44 | 3 | SERVED/TLS_BLOCKED | `response.rs:149 should_redirect` | **E** | Совпадает; differential httpsprobe. |
| `d2k_https_ttl` | 46-55 | 10 | SERVED 6ч, TLS_BLOCKED 1ч, CLOSED/OTHER_NAME 30м, UNCONFIRMED 2м, иначе 0 | `response.rs:140-147 ttl_seconds` | **E** | Значения совпадают: 21600/3600/1800/1800/120; Rust `Served | TlsBlocked` и остальные ветви те же. differential httpsprobe. |
| `d2k_https_state_name` | 57-67 | 11 | served/closed/other-name/unconfirmed/probing/tls-blocked/unknown | `response.rs:117-138 stored_name/from_stored_name` | **E** | Для сохраняемых состояний имена совпадают; `probing`/`unknown` C печатает, но `save` их пропускает; Rust `from_stored_name` их отвергает. differential httpsprobe. |
| `mono_ms` | 37-41 | 5 | монотонное время, мс, `CLOCK_MONOTONIC` | `std::time::Instant`/`Duration` (`http_search.rs:314`, `main.rs:22901+`) | **P** | C возвращает целые мс от `CLOCK_MONOTONIC` (`httpsearch.c:37-41`); Rust использует `Instant` и `Duration`/`as_micros`/`as_millis`. Монотонность и единицы пересчитываются, отдельной функции-обёртки нет. |
| `https_connect` | 77-145 | 69 | socket, SO_MARK только при `mark!=0`, fcntl nonblock, connect+poll 1500, восстановление flags; refused на ECONNREFUSED/EHOSTUNREACH/ENETUNREACH, иначе NO_ANSWER | `response.rs:289-310 probe_socket`, `:254-287 connect_until`, `:540-570 https_socket` | **P** | **Подтверждённые отличия:** (1) C порт из глобального `d2k_https_probe_port` (по умолчанию 443, тесты меняют), Rust всегда `address.port()`; (2) C не ставит SO_MARK при `mark==0`, Rust в `probe_https_state` берёт `expected_mark=mark.unwrap_or(BYPASS_MARK)` (`:610`), `probe_socket` ставит его (`:307`), `https_socket` **проверяет** через `get_socket_mark` (`:546-548`); при `None` уходит `0x2d`; (3) C при ошибке SO_MARK → NO_ANSWER, Rust → Unconfirmed; (4) C восстанавливает исходные flags, Rust `set_nonblocking(false)` + TCP_NODELAY (`:566`). Коды refused/unreachable совпадают: C `REFUSED`, Rust `HttpsProbeState::Closed` (`:553-563`). Live-дифференциала с refused/EINTR нет. |
| `https_tls` | 148-165 | 18 | TLS1.3 или TLS1.2 отдельными стеками, peer_name из сертификата | `response.rs:373-380 https_connection`, `:606-692 probe_https_state` | **P** | C явно делает **два** соединения: TLS1.3, затем TLS1.2; Rust один rustls-connection с `with_protocol_versions(&[TLS13, TLS12])` и ручной проверкой имени. Итоговые состояния совпадают, но число CH/порядок попыток иной. Live-путь покрыт `tests/response.rs`, не C-оракулом. |
| `first_flight` | 836-892 | 57 | DCID/SCID/priv/random 8/8/32/32, X25519 pub, Initial key client+server, TP, CH (SNI IP→NULL, session_id 0, ALPN h3, extra TP, pad_to), transcript, CRYPTO frame | `quic.rs:261-335 r2k_quic_initial_build` + `quic_replay.rs:98-136` | **P** | **C-ветви проверены:** `dcid_len=scid_len=8`, random, `initial_scid`/`odcid`, X25519 base, `d2k_qw_initial_secret` client/server + keys, `tp_build`, CH opts (SNI NULL для IP, `session_id_len=0`, ALPN `h3`, `extra=tp`, `pad_to`), transcript=CH, `crypto_frame(0)`. **Rust:** `r2k_quic_initial_build` принимает готовый CH (обычно донорский профиль) и строит v1 Initial; сборки CH из SNI+TP+ALPN и `d2k_qc_first_initial`-API нет, data-stage идёт через rustls/quinn. |
| `d2k_https_probe_real` | 203-243 | 41 | connect 1500; first flight; TLS1.3→1.2 в общем deadline 2500; при повторном отказе connect → NO_ANSWER; classify | `response.rs:606-692 probe_https_state` | **P** | **Совпадает:** таймауты 1500/2500/2000, first flight, TLS-проверка, состояния. **Отличия:** C два отдельных TLS-соединения (1.3 и 1.2) и склейка причин; Rust одно rustls-соединение; C при `ff<0` → UNCONFIRMED, Rust при неудаче CH → TLS_BLOCKED; C mark=0 отключает метку, Rust None→0x2d. C/Rust differential live-пробы нет. |
| `host_ok` | 452-466 | 15 | host 1..253, только LDH и `.`, последняя метка не полностью цифровая | `DiscoveryTarget`/`normalize` (`main.rs:16028,16204`), `valid_dns_host` (`httpup.rs:390`) | **P** | C отдельный предикат: длина 1..253, `[A-Za-z0-9.-]`, последняя метка содержит нецифровой символ (`httpsearch.c:452-466`). Rust отдельного предиката с тем же контрактом не найдено: `DiscoveryTarget`/`normalize` нормализуют имя, `valid_dns_host` проверяет метки/дефисы иначе (в частности, требует ≥2 метки и запрещает ведущий дефис). Для обычных доменов совпадает; односложные/цифровые/краевые формы могут расходиться. |
| `cache_find` | 285-290 | 6 | линейный поиск без регистра | `https_probe.rs:94-100 cache_find` | **E** | Совпадает (`eq_ignore_ascii_case`); differential httpsprobe. |
| `cache_put` | 292-312 | 21 | обновить/вставить; пустой слот, затем самый старый stamp, **пропуская активный PROBING**; если нет — слот 0 | `https_probe.rs:279-318 insert_cache` | **E** | Rust не хранит PROBING в кэше (отдельный `pending`), поэтому пропуск активного зонда эквивалентен; жертва — min stamp. differential httpsprobe (capacity 130, duplicates). |
| `worker` | 314-349 | 36 | очередь job → probe → UNKNOWN/PROBING→UNCONFIRMED, ttl, done[17] + wake; при полном done `lost++` | `https_probe.rs:146-187` worker thread, `:132 sync_channel(16)` | **P** | **Подтверждённые отличия:** (1) C при полном `done` **отбрасывает** результат и инкрементит `lost`; Rust использует `sync_channel(16)` и **блокирующий `send`** (`:179-181`), поэтому при неразобранных результатах воркер встаёт, счётчика потерь нет; (2) C отдельно хранит PROBING в кэше, Rust — `pending`; (3) C worker не завершается по idle, Rust выходит через 10 с (`HTTPS_PROBE_IDLE`, `:164-168`) и перезапускается при submit. |
| `d2k_httpsprobe_new` | 351-375 | 25 | calloc, mutex/cond, pipe nonblock, pthread; ошибка pipe/потока → free/NULL | `https_probe.rs:131-188 new/r2o_ensure_worker` | **P** | Rust лениво создаёт поток и каналы; `new` не может вернуть NULL, при ошибке spawn `submit` вернёт false. C требует pipe+поток сразу. |
| `d2k_httpsprobe_free` | 377-391 | 15 | stop+broadcast+join, close pipe, destroy, free | `https_probe.rs:463-470 Drop` | **P** | **Подтверждённое отличие/риск:** C останавливает воркер флагом `stop`, будит cond и join-ит; результаты лежат в массиве `done[17]`, переполнение обрабатывается `lost++`. Rust `Drop` сначала `jobs.take()`, затем `thread.join()`, но `results: Receiver` остаётся живым до конца Drop; если очередь `sync_channel(16)` полна и воркер заблокирован в `result_sender.send`, join может не завершиться. В C такой блокировки нет. Pipe/fd-пробуждения в Rust нет. |
| `d2k_httpsprobe_wake_fd` | 393-395 | 3 | fd пробуждения для poll | нет (Rust — канал/`try_result`) | **P*** | Механизм заменён; fd-контракт не нужен. |
| `d2k_httpsprobe_portal` | 397-428 | 32 | проверка host/family/addr; cached upgrade + !answered → resend_ttl rc=2; иначе при месте в очереди job, PROBING на 10 с, rc=1; иначе 0 | `https_probe.rs:189-235 submit`, `main.rs:18992-19045` | **P** | **Совпадает:** host/family, дедуп pending/кэш, очередь 16, отказ при полной очереди. **Отличия:** C возвращает rc=2 и TTL для cached upgrade, Rust отдельно `cached_state`+`verified_names`; C ставит PROBING-запись, Rust `pending`; C `answered` проверяется внутри, Rust — в `target_from_portal`. C/Rust differential очереди нет. |
| `d2k_httpsprobe_done` | 430-449 | 20 | забрать до cap результатов, cache_put с полным ttl, memmove, повторный wake | `https_probe.rs:236-250 try_result`, `main.rs:17032-17035`, C-потребитель `d2kc.c:324-355` | **P** | **Подтверждённое расхождение:** C `http_probe_done` для каждого результата вызывает `d2k_https_upgrade`; только для SERVED/TLS_BLOCKED шлёт `SET_HTTPS(host, ttl_s)` (`d2kc.c:343`), иначе `http_search_portal` (`:344`). Rust `try_result` кладёт в кэш полный `state.ttl_seconds()`, но в `HttpsProbeResult.ttl_seconds` для не-upgrade состояний пишет **0** (`https_probe.rs:172-176`), а `main.rs:17033` **безусловно** шлёт `SET_HTTPS(host, ttl_seconds)` — для closed/other-name/unconfirmed это TTL=0, т.е. удаление имени. C в этих состояниях `SET_HTTPS` не шлёт. Rust отдаёт по одному, C — пачкой до cap; `lost` отсутствует. |
| `d2k_httpsprobe_state` | 451-458 | 8 | cached state, если не истёк, иначе UNKNOWN | `https_probe.rs:226-231 cached_state` | **E** | Rust возвращает `Option`, C — UNKNOWN; differential httpsprobe + unit `cached_state_and_pending_lookup_follow_host_and_expiry`. |
| `d2k_httpsprobe_lost` | 460-466 | 7 | счётчик потерянных результатов | нет | **N** | В `https_probe.rs` счётчика нет; Rust-воркер блокируется на полном канале вместо потери. |
| `d2k_httpsprobe_save` | 476-505 | 30 | `d2k-https 2 <wall_s>`, все не-PROBING и не истёкшие, tmp+fflush+fsync+rename | `https_probe.rs:399-460 save_cache` | **E** | Формат строк тот же: `d2k-https 2 {wall_now}`, по записи `{state} {wall_now+ttl} {host}`, пропуск `ttl==0`/PROBING (Rust PROBING в кэше не хранит). Атомарность: C `path.tmp` + `fflush`+`fsync`+`fclose`+`rename`; Rust уникальный `.new.{pid}.{nonce}` + `sync_all` + `rename` + fsync каталога. differential httpsprobe + round-trip unit. |
| `d2k_httpsprobe_load` | 507-564 | 58 | v1/v2, откат при `written>wall_s`, strict `%lld`, TTL-кламп, upgrade→push | `https_probe.rs:320-386 load_cache`, `:388-397 load_verified` | **E** | Ветви сверены: v1 (`d2k-https 1`) / v2 (`d2k-https 2 <written>`); `written>wall_now` → пусто; строго три поля, `state_name` из `stored[]`, `expires>wall_now`, `ttl=min(expires-wall_now, state.ttl_seconds())`; невалидные строки пропускаются. C дополнительно заполняет `push` для upgrade-состояний; Rust `load_verified` фильтрует `should_redirect()`. differential httpsprobe (16+ кейсов). |

## core/httpup_logic.c (15 функций)

Логика HTTP-upgrade/порталов: безопасный разбор запроса, распознавание провайдерского портала, ответ 307. Перенесена почти построчно в `crates/r2k-core/src/httpup.rs` и используется контроллером/датапасом. Векторы — `crates/r2k-core/tests/httpup.rs`; косвенно участвует в `scripts/r2o-http-search-differential.sh` (линкуется `httpup_logic.o`).

**Прочитано построчно: 15/15 функций, 277 строк C (1–277).**

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `ascii_alnum` | 16-19 | 4 | ASCII-буква/цифра | `r2k-core/src/httpup.rs:390 valid_dns_host` (встроено `is_ascii_alphanumeric`) | **E*** | Хелпер; владелец `dns_host` → `valid_dns_host`, тесты `httpup.rs:78,108`. |
| `dns_host` | 21-35 | 15 | 1..253, без ведущей/хвостовой точки, метки 1..63, LDH, без ведущего/хвостового `-` | `httpup.rs:390-410 valid_dns_host`, `:350-357 valid_http_name_host` | **P** | Сам `valid_dns_host` совпадает с C. **Подтверждённое расхождение:** `parse_plan_request` вызывает `valid_http_name_host`, который дополнительно отвергает **последнюю метку из одних цифр** (`127`, `1.2.3.4`); C `dns_host` такие имена принимает. `tests/httpup.rs:108 rejects_ambiguous...`. |
| `host_equal` | 37-44 | 8 | снять по одной хвостовой точке, сравнить без регистра, непустые | `httpup.rs:468-472 same_host` | **E** | Совпадает; `tests/httpup.rs:78,69`. |
| `known_portal_host` | 46-51 | 6 | 6 известных порталов | `httpup.rs:492-502 known_portal_host` | **E** | Список и `same_host` совпадают; `tests/httpup.rs:78`. |
| `find_crlf` | 53-58 | 6 | первый CRLF до `end` | `httpup.rs:382-388 find_crlf` | **E*** | Rust `windows(2)` + `checked_add`; эквивалентно; владелец `parse_request`, тесты `:11,108`. |
| `parse_request` | 60-130 | 71 | GET/HEAD, HTTP/1.0/1.1, origin-target без control/`#`, один Host, CL только `0`, запрет TE, порт только `:80`, финальный CRLFCRLF | `httpup.rs:220-229 parse_request`, `:231-344 parse_plan_request` | **P** | **Совпадает:** GET/HEAD (через `parse_request`), HTTP/1.0/1.1, target `/…` без `<=0x20/0x7f/#`, один Host (<256), хвостовая точка, `:80`, финальный CRLFCRLF, `Content-Length==0`. **Подтверждённые расхождения:** (1) Rust `parse_plan_request` ставит `boundary_known=false` при control-байте в строке заголовка, отсутствии `:` или невалидном HTTP-token имени; C неизвестные/битые заголовки игнорирует и control-байты не проверяет. (2) Rust ставит `boundary_known=false` на **`Upgrade`** и `Transfer-Encoding` (`:309-313`); C `Transfer-Encoding` отвергает, а `Upgrade` игнорирует — GET с `Upgrade: websocket` C примет, Rust (для `request_safe`/portal) отвергнет. (3) Rust `valid_http_name_host` отвергает all-digit last label (`127`, `1.2.3.4`), C `dns_host` принимает. (4) `parse_plan_request` Rust принимает произвольный uppercase-метод и `Content-Length>0` для выбора плана; `parse_request` их отвергает, как C. `tests/httpup.rs:11,108`. |
| `d2k_httpup_request_safe` | 132-135 | 4 | предикат безопасного запроса | `httpup.rs:164-166 request_safe` | **P** | Тонкая обёртка; наследует более строгий `parse_request` Rust. `tests/httpup.rs:11`. |
| `build_redirect` | 137-149 | 13 | `HTTP/1.1 307`, `Location: https://host+target`, `Cache-Control: no-store`, `Connection: close`, `Content-Length: 0`, `X-D2K-HTTP-Upgrade: <reason>` | `httpup.rs:504-516 build_redirect` | **P** | **Осознанное брендинговое отличие:** C пишет `X-D2K-HTTP-Upgrade: <reason>`, Rust — `X-R2O-HTTP-Upgrade: provider-portal`; по требованию проекта имена `d2k`/`d2o` не используются в рабочем коде R2O. В C оба производственных вызова (`portal_response`, `redirect_https`) передают `reason="provider-portal"`, поэтому отличие сводится к имени заголовка. Остальные строки/порядок/CRLF/пределы host<256 и target<2048 совпадают. Тест `builds_the_exact_https_redirect...`; differential `test-controller-h3-httpup-differential.sh` нормализует product-заголовок и проходит (49 кейсов). |
| `portal_marker` | 151-170 | 20 | 8 маркеров по меткам хоста | `httpup.rs:474-490 portal_marker` | **E** | Список/разбиение/регистр совпадают; `tests/httpup.rs:78`. |
| `redirect_location_host` | 172-190 | 19 | http/https, authority до `/ ? # :`, `dns_host` | `httpup.rs:452-466 parse_location_host` | **E** | Совпадает; `tests/httpup.rs:69`. |
| `portal_answer` | 193-225 | 33 | HTTP/1.x 301/302/303/307/308, ровно один Location, другой host, known/marker | `httpup.rs:411-450 portal_host` | **E** | Статус/дубликат Location/`same_host`/known+marker совпадают; C дополнительно требует `line_end==p` (пустая строка), Rust останавливается на пустой строке. `tests/httpup.rs:49,57`. |
| `d2k_httpup_portal_response` | 227-238 | 12 | parse_request + portal_answer → 307 provider-portal | `httpup.rs:191-199 portal_response` | **P** | Логика совпадает, но наследует брендинговое отличие `build_redirect` (`X-D2K`/`X-R2O`) и более строгий `parse_request` (control-байты/HTTP-token/all-digit label), из-за которого часть запросов C проходит, а Rust отвергает. `tests/httpup.rs:49`; differential PASS на общих кейсах. |
| `d2k_httpup_request_target` | 240-251 | 12 | host и origin-target | `httpup.rs:169-173 request_target` | **P** | Совпадает для валидного запроса; наследует строгий разбор Rust (битые заголовки/all-digit host). `tests/httpup.rs:31`. |
| `d2k_httpup_portal_location` | 253-262 | 10 | host портала из upstream | `httpup.rs:201-206 portal_location` | **E** | Логика `portal_host`+known/marker совпадает; `tests/httpup.rs:69`. |
| `d2k_httpup_redirect_https` | 264-277 | 14 | готовый 307 по host/target, только `target[0]=='/'`, пределы 255/2047 | `httpup.rs:208-217 redirect_https` | **P** | **Подтверждённые отличия:** (1) Rust `valid_dns_host(host)` и запрет `<=0x20/0x7f/#` в target; C проверяет только длины и первый `/`; (2) заголовок `X-R2O` вместо `X-D2K`. `tests/httpup.rs:126`. |

## core/httpsearch.c (66 функций)

Поиск HTTP-обхода: база → свои планы → split/checksum/продукт → fallback, с подтверждением APPLIED и живой привязкой. В R2O: `r2o-controller/src/http_search.rs` (judge, кандидаты, id, чтение ответа) и `main.rs` (`HttpSearchRecordCache:4464`, `run_http_search_task:22901`, `begin_http_search:19542`, `http_baseline_failure_action:22853`). Дифференциалы: `scripts/r2o-http-search-differential.sh` (набор C-фикстур `d2o_http_*_differential.c` против Rust-тестов), `tests/http_search.rs`.

**Прочитано построчно: 66/66 функций, 1593 строки C (1–1593).** Строки в таблице — реестровые/CSV; фактические строки C в `a378` на **+2** больше (сдвиг extractor, см. `deep-core-verify.md`). Например, `d2k_httpsearch_save` фактически 1446–1473, `d2k_httpsearch_load` — 1475–1514, `d2k_hs_candidate_text` — 296–326.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `mono_ms` | 37-41 | 5 | монотонное время, мс, `CLOCK_MONOTONIC` | `std::time::Instant`/`Duration` (`http_search.rs:314`, `main.rs:22901+`) | **P** | C возвращает целые мс от `CLOCK_MONOTONIC` (`httpsearch.c:37-41`); Rust использует `Instant` и `Duration`/`as_micros`/`as_millis`. Монотонность и единицы пересчитываются, отдельной функции-обёртки нет. |
| `d2k_hs_answer_name` | 43-57 | 15 | русские имена 10 исходов + default «нет» | `http_search.rs:17-24 enum Answer` (6 вариантов); тексты — в `main.rs` | **P** | **Подтверждённое отличие состава:** C различает `REAL/INJECTED/EARLY/GARBAGE/SILENT/RESET/CLOSED/CONNECT_FAIL/DECOY/CUT` и default (`httpsearch.c:43-57`); Rust `Answer` содержит только `Injected/Early/Garbage/Decoy/Real/Cut` (`http_search.rs:17-24`), а `Silent/Reset/Closed/ConnectFail` выражены ошибками ввода-вывода. Тексты C в Rust дословно не перенесены: логи используют собственные строки (`main.rs:22974,23127`). Диагностика. |
| `d2k_hs_judge` | 61-95 | 35 | классификация HTTP-ответа: garbage/injected/decoy/early/real | `http_search.rs:850-882 judge` | **E** | **Совпадает построчно:** `<12`/`HTTP/1.0|1.1`/код `1..5`+2 цифры/наличие CRLFCRLF → Garbage; `portal_location` → Injected; 400/421 или `disk.rzd.ru` без регистра → Decoy; `rtt_us>0 && reply_us>=0 && 2*reply_us<rtt_us` → Early; иначе Real. Rust те же условия и порядок (`http_search.rs:850-882`), `i128` для переполнения. Differential `scripts/r2o-http-search-differential.sh` + `d2o_http_judge_differential`. |
| `hs_path_ok` | 99-107 | 7 | допустимый путь для повтора: `/`, не `//`, длина ≤1023, байты 33..126 без `? # \` | `http_search.rs:300-308 repeatable_path` | **E** | C: `path[0]=='/'`, `path[1]!='/'`, `n<1023`, `c>32 && c<127`, запрет `? # \`, `n>0` (`httpsearch.c:99-107`). Rust: `1..=1023`, первый `/`, второй не `/`, `(33..127)` без `? # \`. Тесты `tests/http_search.rs:243-259`, `main.rs:28365`. |
| `hs_read` | 110-130 | 21 | чтение сокета: poll до `wait_ms`, EINTR, время первого байта, префикс 4 КиБ | `http_search.rs:310-365 read_probe_response`, `:367-398 read_response_head` | **P** | C `poll`-цикл, `recv`, `first_us` от первого байта, `head[4096]` (с телом), `used` — длина префикса (`httpsearch.c:110-130`). Rust читает заголовок побайтно до CRLFCRLF с пределом 64 КиБ, затем тело по CL/chunked/until-close; `first_byte: Instant`, `reply_us` от него. **Отличия:** C хранит только 4 КиБ ответа, Rust — 64 КиБ заголовков; C `used` не равен полному числу байт; таймаут C в `hs_read`, Rust — через `Read`/`Instant`. Побайтового differential таймингов нет. |
| `d2k_hs_probe_run` | 132-246 | 115 | один зонд: connect, RTT, local identity, 2 GET, judge, keep-alive | `main.rs:23385-23440 run_http_baseline(_on_stream)`, `http_search.rs:310-365` | **P** | Rust `run_http_baseline_on_stream` делает ровно 2 запроса, на каждом `read_probe_response`, прерывается на не-Real, CUT при `!complete`, останавливается при `connection_close`; connect 6 с. **Подтверждённые различия:** (1) C переопределяет ответ в INJECTED при `D2K_HTTP_BLOCKED` (`httpsearch.c:232`), Rust тело не классифицирует; (2) C 101 проходит judge как Real и затем `!complete` → CUT, Rust `BodyMode::Empty` + `complete=true` (`http_search.rs:338-341,590-600`); (3) C неверный CL/TE → CUT (parse error + head), Rust `Err(InvalidData)` (`:335-337`); (4) C judge видит первые 4 КиБ тела, Rust — только заголовки; (5) C не имеет общего дедлайна `3*probe_ms`, Rust ограничен connect 6 с и таймаутами. C-фикстура baseline покрывает keep-alive. |
| `d2k_hs_candidate_count` | 253-253 | 1 | число встроенных кандидатов | `http_search.rs:627 candidate_keys` | **P** | **Расхождение:** C `CANDS[]` — 4 элемента `split, disorder, fake-badsum, fake-seqshift` (`httpsearch.c:250-254`); Rust — 5 в порядке `split, fake-badsum-whole, fake-badsum, disorder, fake-seqshift` (`http_search.rs:7-13`). `fake-badsum-whole` в C — отдельный вопрос `HQ_PRODUCT`, не элемент `CANDS`. Тест `tests/http_search.rs:196` закрепляет расширенный список Rust. |
| `d2k_hs_candidate_key` | 254-254 | 1 | ключ кандидата по индексу | `http_search.rs:627 candidate_keys` | **P** | Индексы 0..3 не совпадают с C: на индексе 1 Rust отдаёт `fake-badsum-whole`, у C — `disorder`. C-дифференциала публичного списка нет. |
| `poison_key_spec` | 258-287 | 30 | разбор `fake:`: ttl=1/badsum=2/seqshift=3, строго возрастающий порядок; ttl 1..255, seqshift ±2147483647 ≠0; ttl без badsum/seqshift запрещён | `http_search.rs:796-834 poison_key_spec` | **E** | **Совпадает:** `len>39` → отказ; `strtok("+")`/`split('+').filter(nonempty)`; ранги 1/2/3; повтор/порядок → отказ; ttl 1..255, seqshift ±2147483647 и ≠0; ttl без badsum/seqshift → отказ; пустой список → отказ. C `strtol` base 10 принимает ведущие пробелы и знак; Rust `parse_decimal` срезает ведущие ASCII-пробелы и парсит `i64` (`:836-839`), знак принимает; хвостовой мусор оба отвергают. Тест `tests/http_search.rs:268`. |
| `known_key` | 289-294 | 6 | предикат: `fake-badsum-whole`, CANDS или валидный `fake:`-spec | `http_search.rs:631-674 candidate_key_from_plan_text` | **P** | C — предикат над ключом; Rust восстанавливает ключ из полного текста плана (`r2o-plan 1 11`, id, точное совпадение `candidate_text`, затем эвристика split/poison). Набор ключей эквивалентен через roundtrip, но API/направление иные; тест `:210`. |
| `d2k_hs_candidate_text` | 296-324 | 29 | `d2k-plan 1 11`, id, `proto tcp http`, fake payload/poison/repeats, split, disorder+pace | `http_search.rs:686-717 candidate_text` | **P** | **Осознанное брендинговое отличие:** C `d2k-plan 1 11`, Rust `r2o-plan 1 11`; директивы (`payload 1`, `poison 1`, `fake … repeats=1`, `split sni_middle +0`, `order reverse`, `pace 12000`) совпадают. Rust-тесты `tests/http_search.rs:227,235,243,260` фиксируют R2O-заголовок; C-байтового differential нет. |
| `stable_id` | 327-332 | 6 | FNV-1a по префиксу `d2k-http:` и ключу, 16 байт | `http_search.rs:780-795 stable_id` | **P** | **Осознанное брендинговое отличие:** C хеширует `"d2k-http:"`, Rust — `"r2o-http:"`, id для ключа разные. FNV-1a/prime/порядок совпадают. Тест `derives_the_r2o_stable_id_for_a_candidate` (`tests/http_search.rs:279`) закрепляет R2O-id. |
| `fresh_id` | 334-352 | 19 | 16 случайных байт из `/dev/urandom`; fallback mono/counter LCG; `id[0]\|=1` | `main.rs:23529-23537 random_id` | **P** | **Совпадает:** 16 байт из `/dev/urandom`; нулевой id исключается установкой `id[0]=1`. **Отличия:** C читает циклом с EINTR и при сбое переходит на LCG от `mono_ms`/счётчика и **всегда** ставит `id[0]\|=1` (`httpsearch.c:334-352`); Rust `read_exact` без fallback (ошибка возвращается) и ставит `id[0]=1` только если все 16 байт нулевые. Ветка сбоя urandom различается. |
| `say` | 215-224 | 10 | `vsnprintf` ошибки в `err/cap` | `format!`/`io::Error` в `r2o_quic_http3.rs`/`quic_replay.rs` | **P** | C пишет текст в переданный буфер, молча выходит при `!err||cap==0`; Rust возвращает `io::Error`/`String`, вызывающий логирует. Контракт «назвать причину» тот же, тексты/владение иные. |
| `host_ok` | 452-466 | 15 | host 1..253, только LDH и `.`, последняя метка не полностью цифровая | `DiscoveryTarget`/`normalize` (`main.rs:16028,16204`), `valid_dns_host` (`httpup.rs:390`) | **P** | C отдельный предикат: длина 1..253, `[A-Za-z0-9.-]`, последняя метка содержит нецифровой символ (`httpsearch.c:452-466`). Rust отдельного предиката с тем же контрактом не найдено: `DiscoveryTarget`/`normalize` нормализуют имя, `valid_dns_host` проверяет метки/дефисы иначе (в частности, требует ≥2 метки и запрещает ведущий дефис). Для обычных доменов совпадает; односложные/цифровые/краевые формы могут расходиться. |
| `rec_find` | 468-475 | 8 | линейный поиск записи `family + host` без регистра | `main.rs:4464 HttpSearchRecordCache` (HashMap, ключ lower-case) | **P** | C `strcasecmp` по массиву записей; Rust `HashMap<(String,u8),…>` с ключом `(target.host.to_ascii_lowercase(), family)` (`main.rs:4475-4478,4491-4495`). Для нормализованного host эквивалентно; отдельной функции нет. |
| `rec_get` | 477-496 | 20 | создание записи с лимитом `D2K_HS_RECORD_MAX_BYTES`, удвоением и счётчиками отказов | `main.rs:4436-4453,4480-4496 HttpSearchRecordCache` | **P** | **Совпадают ёмкости:** 256 КиБ/1480 = 177 записей, очередь 32 КиБ/273 = 120, удвоение 16→…; тест `http_record_and_queue_caps_match_d2o_storage_limits` (`main.rs:25019`). **Отличие:** C ведёт `record_limit_hits`/`record_alloc_failures` (`httpsearch.c:482-491`); в Rust эти диагностические поля остаются 0 (`main.rs:16762` и ниже), счётчиков отказов нет. |
| `same_program` | 500-508 | 9 | эквивалентность планов: компиляция обоих текстов в TLV и сравнение | `http_search.rs:775-778 candidate_program`, `main.rs:4594-4634 failed_http_programs` | **P** | C компилирует `d2k_hs_candidate_text` обоих ключей в TLV и сравнивает байты; ошибка компиляции → -1 «неизвестно» (`httpsearch.c:502-509`). Rust `candidate_program` компилирует текст в program bytes (`http_search.rs:775-778`), `failed_http_programs` сравнивает `Vec<Vec<u8>>` через `contains` и при ошибке ставит `evidence_lost`. Результат для валидных ключей эквивалентен, отдельной функции `same_program` нет. |
| `failed_live` | 510-519 | 10 | поиск живого отказа по ключу/адресу, `same_program<0` → evidence_lost | нет | **N** | `HttpSearchRecord` (`main.rs:4468-4472`) содержит только `cut/repeat_path/repro_gap`; массива `failures` и полей addr/binding/execution/request_ms нет. `HttpLiveFailures` (`:4457-4460`) — только `programs`/`evidence_lost`; `failed_http_programs` (`:4594`) читает выключенные привязки каталога, а не живые отказы. |
| `remember_live_failure` | 520-550 | 31 | учёт живого отказа: addr/binding/execution/request_ms, лимиты байт | нет | **N** | C хранит `live_failure[]` на запись с адресом, binding, execution и request_ms, лимитами `D2K_HS_FAILURE_*` и счётчиками (`httpsearch.c:522-550`). В Rust этих полей/массивов нет; `HttpLiveFailures` строится из выключенных привязок каталога, а `r2o_catalog_mark_flow_unfit` ставит только `recheck_since`. |
| `d2k_httpsearch_test_add_failures` | 553-566 | 14 | тестовый хук добавления отказов | нет | **N** | Существует только под `D2K_HS_TESTING`; в Rust тестового API нет. |
| `d2k_httpsearch_test_add_records` | 567-576 | 10 | тестовый хук добавления записей | нет | **N** | Только под `D2K_HS_TESTING`; в Rust тестового API нет (ёмкость проверяется прямым заполнением кеша в `main.rs:25019`). |
| `d2k_httpsearch_measured_poison` | 579-606 | 28 | регистрация измеренной poison-спеки: канонический ключ, алиасы, дедуп, максимум 8 | `http_search.rs:719-772 measured_poison_keys`, `main.rs:4565-4591 measured_http_candidate_keys` | **P** | C: spec → ключ `fake:...`, алиасы `fake:badsum`→`fake-badsum`, `fake:seqshift=-66000`→`fake-seqshift`, `known_key`, дедуп, `measured[8]` (`httpsearch.c:581-608`). Rust `measured_poison_keys` возвращает канонические ключи из текста TLS-плана, `measured_http_candidate_keys` сортирует по `successes` и ограничивает 8; отдельного состояния `measured` нет. Тест `candidate_tests::measured_poison_requires_tls_and_an_actual_fake_reference`. |
| `d2k_hs_plan_poisons` | 608-642 | 35 | poison-спеки, на которые ссылается fake в TLS-плане | `http_search.rs:719-772 measured_poison_keys` | **P** | C возвращает **спеки** (`ttl=64 badsum`), затем вызывающий регистрирует их; Rust сразу возвращает канонические **ключи** (`fake:ttl=64+badsum`). Условия совпадают: только `proto tcp tls`, `poison N`, ссылка `poison=N` в строке `fake `. Тот же тест; представление/API различаются. |
| `d2k_httpsearch_new` | 644-650 | 7 | создать состояние поиска, `cur.fd=-1` | `main.rs:4464 HttpSearchRecordCache` + `HttpSearchWorker` | **P** | C единый объект `d2k_httpsearch` с записями, очередью и текущим состоянием; Rust состояние разнесено на `HttpSearchRecordCache`, канал задач `HttpSearchWorker` и локальные переменные задачи. |
| `drop_socket` | 652-657 | 6 | закрыть сокет через `ops.close_port` | RAII `TcpStream`/`OwnedFd` | **P** | C вызывает хук закрытия; Rust сокет закрывается `Drop` при выходе из `run_http_baseline`. Отдельной функции/хука нет, поведение эквивалентно. |
| `drop_probe` | 659-664 | 6 | снять пробный план датапата по host/family/sport | `main.rs` delete/revoke | **P** | C вызывает `ops.del_probe`; Rust удаляет временную привязку командами `DEL_NAME_PROBE`/`revoke_http_search_binding`. API и момент снятия иные. |
| `d2k_httpsearch_free` | 666-674 | 9 | снять активную пробу, закрыть сокет, освободить записи/очередь | RAII `Drop` | **P** | C вручную освобождает `failures`, `recs`, `q`; Rust владеющие `Vec`/`HashMap` освобождаются `Drop`. Для непустого состояния эквивалентно. |
| `d2k_httpsearch_busy` | 676-678 | 3 | есть ли активная задача (`phase != PH_IDLE`) | `main.rs:4689+ HttpSearchTask`, `HttpSearchWindow::active` | **P** | C одно поле `phase`; Rust активность выражена окном `http_search_started` (`main.rs:19557-19566`) и задачей в worker-канале. Семантика «занято» сохраняется, API иное. |
| `d2k_httpsearch_plan_of` | 680-683 | 4 | ключ подтверждённого плана host+family, не revoked | `HttpSearchRecordCache`/каталог | **P** | C возвращает `r->key`, если он есть и не revoked (`httpsearch.c:682-685`). Rust подтверждённый план ищется в каталоге (`catalog_has_http_search_owner`, `acknowledged_http_search_owner`), отдельной функции нет. |
| `d2k_httpsearch_diagnostic_counts` | 687-706 | 20 | счётчики записей/очереди/отказов/лимитов/байт | `main.rs:16748-16767`, `diagnostics.rs:449-481` | **P** | C заполняет `http_records/queued/failures/records_bytes/queue_bytes/failure_bytes`, четыре лимита, `failure_limit_hits/…/queue_alloc_failures/http_bytes` (`httpsearch.c:689-708`). Rust заполняет записи/очередь/их байты и лимиты; `http_failure_bytes` жёстко 0 (`main.rs:16762`), счётчики `http_failure_limit_hits` и др. остаются 0, `http_bytes` не включает failures. |
| `d2k_httpsearch_diagnostics` | 707-709 | 3 | подключить observer диагностики | `diagnostics.rs` observer | **P** | C сохраняет `fn/ctx`; Rust использует общий диагностический канал/события. API иное. |
| `diagnostic_end` | 710-721 | 12 | событие завершения: id/target/outcome/reason/elapsed/ip/path/kind | `main.rs:4864 r2o_http_search_diagnostic_event` | **P** | C заполняет `d2k_diag_event` полями `id,target,protocol=http,family,outcome,reason,elapsed_ms,queue_ms=-1,probe_units=-1,ip,path=httpsearch,kind=name` и сбрасывает id (`httpsearch.c:712-723`). Rust `r2o_http_search_diagnostic_event` формирует те же ключевые поля, тест `http_search_diagnostic_event_matches_d2o_http_defaults` (`main.rs:31376`). Полного C/Rust differential события/таймингов нет; P. |
| `finish` | 722-728 | 7 | завершить: diagnostic_end, drop_socket, PH_IDLE, start_next | `main.rs:19570 complete_http_search` + worker loop | **P** | C завершает диагностику, закрывает сокет, сбрасывает фазу и запускает следующую очередь. Rust завершает задачу, освобождает окно `complete_http_search` и берёт следующую задачу из канала. Жизненный цикл переписан на задачи. |
| `open_job` | 730-748 | 19 | открыть сокет через `ops.open_port`, заполнить job host/addr/family/path/cut | `main.rs:23385+ run_http_baseline`, `22853+` | **P** | C создаёт fd/местный порт хуком и копирует контекст в `d2k_hs_job`; Rust соединяется через `TcpStream::connect_timeout`/bound socket в `run_http_baseline`, контекст передаётся аргументами. Хуки портов заменены сокетами. |
| `revoke_owned` | 752-757 | 6 | условно снять привязку плана | `main.rs:21622 revoke_http_search_owner` | **E** | Условный отзыв по известной привязке; Rust `revoke_http_search_owner` + `revoke_http_search_binding`. Тест `http_owned_plan_rollback_matches_d2o` (`main.rs:24067`) и `http_bound_delete_wire_matches_donor`. |
| `all_failed` | 759-802 | 44 | исходы «не измерено/конфликт/нестабильно/не найден» | `main.rs` completion disposition | **E** | C различает `!judged` (inconclusive/no-executed-trial, план оставлен), live-conflict (revoke + inconclusive), `any_had_real` (inconclusive/unstable-response), иначе failed/no-server-response; ставит `no_before_ms` (`httpsearch.c:761-804`). Rust `HttpSearchDisposition`/`HttpSearchCompletion` повторяют эти исходы, тест `http_no_executed_trial_matches_d2o` (`main.rs:31402`) + C-фикстура. |
| `install` | 804-816 | 13 | поставить план датапату с новым токеном, сбросить старую привязку | `main.rs` install/set_plan | **E** | C `fresh_id(token)`, `ops.set_plan`, сохраняет `install_id/pending_plan_id`; при уже известном install_id очищает binding/installed_plan_id. Rust ставит план командой и ведёт `HttpAcknowledgedBinding::Pending`, тест `confirmed_http_candidate_is_durable_before_catalog_flush_interval`. |
| `d2k_httpsearch_install_ack` | 818-841 | 24 | ACK установки: токен, known binding kind=NAME/temporary=0/family/shape=HTTP | `main.rs:16099-16169 record_http_bound_binding_acknowledgement` | **E** | C по токену находит запись, при ok принимает только известную нетемпорарную NAME-привязку family/HTTP и запоминает `installed_plan_id`; иначе снимает. Rust `record_http_bound_binding_acknowledgement` те же условия (`main.rs:16128-16143`). Тест `http_owned_plan_rollback_matches_d2o`. |
| `confirmed` | 843-889 | 47 | подтверждённый кандидат: conflict/evidence_lost, install, запись rec | `http_search.rs:36 confirmed_applied`, `main.rs` | **P** | C проверяет `failed_live`/`evidence_lost`, при конфликте увеличивает `conflicts`, снимает кандидата и переходит дальше; иначе `candidate_text`+`install`, пишет key/seq/wall/no_before. Rust разделяет это между `advance_http_candidate`, `confirmed_applied` и записью каталога; полного differential на конфликты/seq нет. |
| `trial_executed` | 894-900 | 7 | APPLIED покрывает все отправленные запросы, порт/адрес совпали | `main.rs` `http_applied_collection...`, `http_search.rs:36-97 confirmed_applied` | **E** | C: `requests_sent>0 && <=2`, `complete_responses<=requests_sent`, `applied>=requests_sent`, `local_port==proof_sport`, `local_ip==proof_client`. Rust `confirmed_applied` требует те же поля (family/key/plan/trial/execution/binding/shape/temporary), тест `http_applied_collection_requires_each_unique_execution_within_donor_window` (`main.rs:33161`). |
| `judge_trial` | 902-953 | 52 | суд кандидата по REAL/CUT/INJECTED | `http_search.rs:850 judge` + `main.rs` worker | **P** | C: `trial_executed` → `!executed` пропуск; `REAL+2`/`INJECTED`/`CUT` → judged; REAL+2 → ok++, при `HS_CONFIRM` confirmed; CUT после Real — один диагностический повтор; иначе переход. Rust `advance_http_candidate` повторяет правила (тесты `main.rs:31287,31311,31327`), но решение/логика распределены по worker; полного differential на все переходы нет. |
| `next_candidate` | 955-1003 | 49 | переход к следующему кандидату/вопросу, запуск зонда | `main.rs:22901 run_http_search_task` | **P** | C обходит вопросы OWN→SPLIT→CHECKSUM→PRODUCT→FALLBACK, сбрасывает состояние кандидата, создаёт plan/trial ID, ставит пробный план и ждёт ACK. Rust worker перебирает `candidates` и ставит пробу через команды; порядок вопросов покрыт unit, переходы/дедлайны — нет. |
| `add_cand` | 1005-1010 | 6 | добавить кандидата без дублей, предел массива | `main.rs:4638 http_search_candidates` + Vec | **P** | C фиксированный `cands[24]` (`N_CANDS*4+8`) с дедупом; Rust `Vec<String>` с `contains`/push без фиксированного предела, набор формируется `http_search_candidates`/`saved_http_candidate_keys`. |
| `build_cands` | 1012-1039 | 28 | свои подтверждённые планы: свой ключ, затем другие по убыванию seq | `main.rs:4394-4433 saved_http_candidate_keys` | **P** | C сначала добавляет ключ своей записи, затем лучшие (`seq` максимален) подтверждённые ключи других записей (`httpsearch.c:1024-1038`). Rust `saved_http_candidate_keys` сортирует по `same_context`, затем `confirmed` (`main.rs:4423-4426`), а не по seq; набор/приоритет могут отличаться. |
| `build_fallback` | 1041-1052 | 12 | fallback: split, disorder + измеренные или fake-badsum/fake-seqshift | `main.rs:4638-4657 http_search_candidates` | **P** | C fallback: `split`, `disorder`, затем measured-ключи, иначе `fake-badsum`, `fake-seqshift` (`httpsearch.c:1043-1053`). Rust всегда замешивает 5 канонических ключей (включая `fake-badsum-whole`) и measured, при непустых measured пропускает `fake-seqshift` (`main.rs:4642-4656`). Состав/порядок отличаются. |
| `start` | 1054-1091 | 38 | старт поиска: контекст repeat_path/cut, job, база PH_BASE, дедлайн 3×probe | `main.rs:19542 begin_http_search`, `22901 run_http_search_task` | **P** | C копирует контекст, проверяет `repro_gap`, открывает job, запускает worker, ставит PH_BASE и `deadline=3*probe_ms`. Rust `begin_http_search` держит окно/cooldown, `run_http_search_task` сразу выполняет baseline с повторами; стадии/дедлайны иные. |
| `start_next` | 1093-1101 | 9 | взять следующую заявку из очереди `pend[]` | `main.rs` worker loop / канал | **P** | C очередь — массив `pend` с `memmove`; Rust очередь — канал задач `HttpSearchWorker` (`main.rs:6629+`), порядок и момент старта иные. |
| `live_owner` | 1103-1111 | 9 | найти запись-владельца живого запроса по plan/binding/execution/request_ms | `main.rs:16023 acknowledged_http_search_owner`, `acknowledged_http_binding_for` | **P** | C проверяет `key[0]`, не revoked, `binding_equal`, `install_id==0`, `installed_plan_id==plan_id`, execution>0, request_ms>0, host_ok/family (`httpsearch.c:1105-1113`). Rust ведёт `http_acknowledged_bindings` и проверяет последнюю подтверждённую генерацию; тест `http_live_owner_requires_the_latest_acknowledged_runtime_generation` (`main.rs:24635`). Полного совпадения полей (request_ms/addr) нет; P. |
| `d2k_httpsearch_bound_failure` | 1113-1131 | 19 | живой отказ под планом: remember, revoked, repro_gap, отзыв, перезапуск | `main.rs` failure handling | **P** | C записывает live failure, ставит revoked, сохраняет repeat_path при валидном path, снимает привязку, завершает текущий поиск и ставит портал. Rust обрабатывает live-отказ через каталог/`revoke_http_search_owner`, покрыто косвенно rollback-тестом; массива live failures нет (см. N `remember_live_failure`). |
| `d2k_httpsearch_control` | 1133-1163 | 31 | диспетчер APPLIED/ACK/HTTP_RESPONSE/PORTAL | `main.rs:19622 service_http_search_command` | **P** | C маршрутизирует APPLIED, ACK SET_NAME_BOUND, live HTTP_RESPONSE (code 1/2), CUT (code 4) и PORTAL/code 3 с проверкой transport/port/trial. Rust обрабатывает команды в `service_http_search_command` и события в цикле контроллера; разбиение и проверки иные. |
| `d2k_httpsearch_cut` | 1170-1188 | 19 | запомнить обрыв тела и путь повтора, запустить поиск | `main.rs` record cut | **E** | C: host/family/addr/host_ok/path_ok, не дублировать активный поиск, записать `cut=1`/`repeat_path`, `repro_gap=0`, вызвать portal. Rust `HttpSearchRecordCache::record_cut` + тест `r2o_http_cut_context_survives_a_later_portal` (`main.rs:33409`). |
| `d2k_httpsearch_portal` | 1190-1227 | 38 | старт или постановка в очередь по portal-событию, лимиты очереди | `main.rs:19583 enqueue_http_search` | **E** | C проверяет host/family/addr, активный/очередной тот же host, `repro_gap`, `no_before_ms`, лимит `D2K_HS_QUEUE_MAX_BYTES`, удвоение; Rust `enqueue_http_search` + окно/канал, тест `http_search_queue_matches_the_unbounded_donor_queue` (`main.rs:33706`). |
| `d2k_httpsearch_ack` | 1229-1260 | 32 | ACK пробного плана: отказ → пропуск, успех → запуск зонда | `main.rs` ack handling | **E** | C проверяет trial, при отказе сбрасывает кандидата, при успехе запускает worker с тем же fd/контекстом и ставит PH_RUN/дедлайн. Rust обрабатывает ACK пробы и запускает задачу; тест `http_owned_plan_rollback_matches_d2o`. |
| `d2k_httpsearch_applied` | 1262-1287 | 26 | сбор APPLIED: до 2 уникальных execution, binding/порт/клиент | `main.rs` applied collection | **E** | C требует temporary NAME binding family/HTTP, совпадение plan/trial, client/server по порту 80 и proof_sport, одинаковый binding/клиент, уникальные execution, максимум 2. Rust `confirmed_applied` те же проверки, тест `http_applied_collection_requires_each_unique_execution_within_donor_window` (`main.rs:33161`). |
| `d2k_httpsearch_result` | 1289-1395 | 107 | результат зонда: база/кандидат, повторы, PH_APPLIED | `main.rs:22853 http_baseline_failure_action`, `:23385 run_http_baseline` | **E** | Differential `d2o_response_state_differential_preserves_portal_and_partial_head_outcomes`, baseline test. C-ветви базовой тишины/повторов и кандидата покрыты Rust-тестами `http_baseline_replays_donor_keepalive_paths_on_one_stream`, `http_cut_baseline_replays_the_observed_path_for_both_requests`. |
| `d2k_httpsearch_tick` | 1397-1427 | 31 | таймауты ACK/APPLIED/BASE/RUN | `main.rs` deadline handling | **P** | C единый tick: ACK → пропуск кандидата, APPLIED → суд, BASE/RUN → local-abort/worker-timeout с закрытием сокета. Rust использует таймауты задач/каналов (`HttpSearchWorker`, `run_http_search_task`), отдельного tick нет; моменты/коды могут отличаться. |
| `d2k_httpsearch_push_all` | 1429-1442 | 14 | переустановить все сохранённые планы при старте | `main.rs` restore/install loop | **P** | C обходит записи, снимает revoked, ставит остальные `install`. Rust восстанавливает планы из каталога при загрузке/старте; покрыто durable-тестом частично, отдельной функции нет. |
| `d2k_httpsearch_save` | 1444-1471 | 28 | атомарная запись `d2k-http-plans 1`: `host family key wall`, `fflush/fsync/fclose/rename`, `unlink(tmp)` | `main.rs`/`catalog.rs` persist (JSON-каталог) | **P** | C пишет отдельный файл `d2k-http-plans 1` с точным форматом и атомарной заменой (`httpsearch.c:1446-1473`). Rust сохраняет каталог JSON, файла/формата `d2k-http-plans` нет. Durable-дифференциал `d2o_http_durable_differential.c` сравнивает только маркер `persisted_before_flush=yes`; тест `confirmed_http_candidate_is_durable_before_catalog_flush_interval` проверяет каталог. **Фактические строки a378 — 1446–1473; в таблице — реестровые 1444–1471 (сдвиг +2).** |
| `d2k_httpsearch_load` | 1473-1512 | 40 | разбор файла планов, known_key, install | `catalog.rs:391 load` (HTTP-планы) | **P** | C читает заголовок `d2k-http-plans 1`, `sscanf("%299s %u %47s %lld")`, проверяет family/host/key, ставит план (`httpsearch.c:1475-1514`). Rust загружает HTTP-планы из JSON-каталога; отдельного загрузчика `d2k-http-plans` с теми же правилами нет. **Фактические строки a378 — 1475–1514; в таблице — 1473–1512 (сдвиг +2).** |
| `runner_main` | 1525-1537 | 13 | поток одного зонда: probe_run, mutex, ready, wake pipe | `std::thread`/worker (`main.rs:6629 HttpSearchWorker`) | **P** | C pthread с mutex/ready/pipe; Rust worker-поток с каналом задач/результатов. Функционально один зонд на поток, структура иная. |
| `d2k_hs_runner_new` | 1539-1553 | 15 | создать runner: pipe, O_NONBLOCK, mutex | `std::thread` + `sync_channel` | **P** | C `pipe(2)` + `O_NONBLOCK` + mutex; Rust `HttpSearchWorker` с `std::thread` и каналами. API/ресурсы иные. |
| `d2k_hs_runner_free` | 1555-1562 | 8 | join, close pipe, destroy mutex, free | `JoinHandle`/`Drop` | **P** | C вручную join/close/destroy; Rust join в `Drop`/остановке worker, RAII. |
| `d2k_hs_runner_wake_fd` | 1564-1564 | 1 | fd пробуждения | нет (канал) | **P** | C отдаёт read-end pipe для poll; Rust использует канал/поток, fd-контракт не нужен. |
| `d2k_hs_runner_start` | 1566-1579 | 14 | запустить зонд, запрет параллельного, join предыдущего | `main.rs` worker | **P** | C под mutex проверяет `running`, join-ит предыдущий, копирует job и создаёт pthread; Rust worker берёт задачу из канала и выполняет последовательно. |
| `d2k_hs_runner_done` | 1581-1591 | 11 | забрать результат, drain pipe, join | `JoinHandle::join`/канал | **P** | C под mutex забирает `ready/res`, join-ит поток; Rust получает результат из канала и join-ит worker. |

## core/h3.c (9 функций)

Кодирование/разбор HTTP/3: control-поток, QPACK-подобные префиксные целые, HEADERS-запрос, статус из HEADERS (static index + Huffman). Порт: `crates/r2k-core/src/h3.rs` (построчный). Дифференциал: `scripts/test-controller-h3-httpup-differential.sh` (C `h3.c` против `examples/tg_cl14_h3_httpup_trace.rs`), плюс unit-тесты в `h3.rs`.

**Прочитано построчно: 9/9 функций, 280 строк C (1–280).** Сверено с `h3.rs` (465 строк): `control` 00 04 00; `prefix_max/prefix_int/prefix_int_read` (включая 8-битный префикс и `shift>56`); `request` (static 17/23/1, authority literal name 0, path literal name 1, лимиты 255/512); `huff_status` (5/6 бит, EOS-хвост, `rest>=8`); `static_status`/`name_is_status` (24–28, 63–71); `decode_section` (indexed, literal-name, literal-literal, post-base index/literal); `status` (пропуск неизвестных кадров, отказ на обрезанном). Дополнительно проверены `h3.rs:23 varint_write`/`:43 varint_read`, соответствующие `d2k_qw_varint_write/read` из `quicwire.c`; различий в алгоритмах/границах не найдено.

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

**Прочитано построчно: 28/28 функций, 571 строка C (1–571).** Сверено с `quic.rs` (1105 строк): `read_varint/write_varint`, `parse_initial_header`, `derive_initial_keys(_for_role)`, `expand_label`, `seal_initial/open_initial`, `packet_nonce`, `decode_packet_number`, `retry_integrity_valid`, `r2k_quic_initial_build`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `salt_for` | 41-43 | 3 | соль Initial для v1/v2 | `quic.rs:853-877 derive_initial_keys_for_role` | E | C: `version==V2 ? salt_v2 : salt_v1` (неизвестная версия → v1); Rust явно `V1 → SALT_V1`, `V2 → SALT_V2`, иначе `Invalid`. Для поддерживаемых v1/v2 совпадает; RFC 9001/9369 тесты. |
| `label_key` | 44-46 | 3 | HKDF-label key (v1/v2) | `quic.rs:861-874` (labels) + `:893 expand_label` | E | C `"quicv2 key"`/`"quic key"`; Rust те же байты в `derive_initial_keys_for_role`. |
| `label_iv` | 47-49 | 3 | HKDF-label iv | `quic.rs:861-874` + `:893 expand_label` | E | C `"quicv2 iv"`/`"quic iv"`; Rust те же. |
| `label_hp` | 50-52 | 3 | HKDF-label header protection | `quic.rs:861-874` + `:893 expand_label` | E | C `"quicv2 hp"`/`"quic hp"`; Rust те же. |
| `d2k_qw_varint_read` | 56-67 | 12 | QUIC varint read | `quic.rs:1057 read_varint` | E | RFC 9001 Initial разбирается тестом `splits_rfc_9001_initial...` |
| `d2k_qw_varint_len` | 69-75 | 7 | длина varint по значению | `quic.rs:1070 write_varint` (выбор ширины) | E | helper; владелец `d2k_qw_varint_write_w`, тест `создаёт_аутентифицированный_quic_initial...` |
| `d2k_qw_varint_write_w` | 77-105 | 29 | varint с заданной шириной: `w∈{1,2,4,8}`, проверка `v<=63/16383/1073741823/2^62-1`, `w=0` — автоширина | `quic.rs:1070-1083 write_varint` | **P** | Rust `write_varint` всегда выбирает ширину по значению (1/2/4/8) и не имеет параметра принудительной ширины; C `d2k_qw_long_hdr_token_w` передаёт `length_width` явно. Для автоширины (`w=0`) байты совпадают; принудительные формы C не воспроизведены. |
| `d2k_qw_varint_write` | 107-109 | 3 | varint с автошириной | `quic.rs:1070 write_varint` | E | RFC-тесты Initial/фреймов |
| `long_type_v1` | 119-127 | 9 | wire→v1 тип long header (v2 mapping) | `quic.rs` (v2-константы в `parse_initial_header`/build) | E | test `splits_rfc_9369_initial_with_v2_keys_and_labels` |
| `long_type_wire` | 132-140 | 9 | v1→wire тип (v2 mapping) | `quic.rs` (сборка Initial/Retry) | E | тот же v2-тест |
| `d2k_qw_long_hdr_token_w` | 142-174 | 33 | long header v1/v2, token только Initial, заданная ширина length | `quic.rs:261-335 r2k_quic_initial_build` (inline) | **P** | **Подтверждённые отличия:** Rust строит **только Initial v1** (`clear_header.push(0xc0)`, `QUIC_V1`), **без token** (`write_varint(0)`), `pn_len=4`, ширину length подбирает перебором `[1,2,4,8]` под `target_len` (`:308-330`); C принимает v1/v2, произвольный Initial-token и `length_width`. Для штатного Initial v1 без token результат совпадает; v2/0-RTT/Retry-сборки в Rust нет. |
| `d2k_qw_long_hdr_w` | 176-184 | 9 | обёртка long header без token | `quic.rs:261 r2k_quic_initial_build` | **P** | Для Initial v1 без token эквивалентно (RFC-тест `создаёт_аутентифицированный_quic_initial_из_clienthello`); v2 и прочие типы C-обёртка умеет, Rust — нет. |
| `d2k_qw_long_hdr_token` | 186-194 | 9 | long header с token, автоширина | `quic.rs` (только Initial без token) | **P** | 0-RTT/Retry-сборка и Initial-token в Rust не портированы. |
| `d2k_qw_long_hdr` | 196-202 | 7 | long header без token, автоширина | `quic.rs:261` | **P** | Только Initial v1; v2-сборка отсутствует. |
| `d2k_qw_hdr_parse` | 204-273 | 70 | generic long/short/Retry/Initial/0-RTT/Handshake, token, length, pn offset, sample | `quic.rs:796-847 parse_initial_header` (+ short header у quinn) | **P** | **Подтверждённое сужение:** Rust `parse_initial_header` принимает **только Initial** (`V1 raw_type 0`, `V2 raw_type 1`, иначе None), version 1/2, token varint, `length_claimed>=17 && <= len-cursor`, `pn_offset+20<=len`; short header, Retry, 0-RTT и Handshake разбирает quinn/`parse_long_header_ids`. C generic-парсер умеет все типы, включая короткий заголовок с заданной `dcid_len_short`. Для клиентского Initial v1/v2 эквивалентно; RFC-тесты Initial v1/v2. |
| `d2k_qw_pn_len` | 277-293 | 17 | RFC 9000 A.2: unacked, bits+1, 1..4 байта | нет (Rust `seal_initial` принимает pn_len; `initial_build` передаёт 4) | **P** | **Подтверждённое отличие:** C вычисляет минимальную длину PN по `largest_acked`; Rust `r2k_quic_initial_build` всегда передаёт **pn_len=4** (`quic.rs:333`), `reseal` сохраняет исходную длину. Функции расчёта нет; для первого Initial 4 байта валидны, байтовый паритет с C на других largest_acked не доказан. |
| `d2k_qw_pn_decode` | 295-313 | 19 | восстановление PN по largest | `quic.rs:1041-1055 decode_packet_number` | E | Один и тот же алгоритм RFC 9000 A.3: `window=1<<(8*pn_len)`, `half=window/2`, `expected=largest+1`, `candidate=(expected&!mask)|truncated`; два уточнения (`candidate+half<=expected && +window<2^62` → +window; `candidate>expected+half && >=window` → -window). Rust `open_initial` вызывает с `largest=0`; RFC-тест split Initial. |
| `d2k_qw_initial_secret` | 317-325 | 9 | Initial secret: HKDF-Extract(salt, DCID) + Expand-Label `server in`/`client in` | `quic.rs:849-891 derive_initial_keys(_for_role)` | E | C `d2k_hkdf_extract(salt,dcid)` → `hkdf_expand_label(initial, side==SERVER?"server in":"client in", 32)`. Rust `Hkdf::new(Some(salt),dcid)` → `expand_label(role)`; те же соль/метка/32 байта. RFC 9001/9369 тесты. |
| `d2k_qw_keys_from_secret` | 327-338 | 12 | key/iv/hp из secret | `quic.rs:882-889` (в `derive_initial_keys_for_role`) | E | C три `hkdf_expand_label` (key/iv/hp); Rust те же три `expand_label` и длины 16/12/16. RFC-тесты. |
| `nonce_of` | 344-349 | 6 | nonce = iv XOR pn (младшие 8 байт) | `quic.rs:1033-1039 packet_nonce` | E | Оба копируют 12-байтный IV и XOR-ят `out[11-i] ^= pn>>(8*i)` для i=0..7. RFC-тесты. |
| `d2k_qw_seal` | 351-394 | 44 | long/short header: AEAD seal (AAD=hdr+pn), tag за ct, HP-маска 0x0f/0x1f, sample pn+4 | `quic.rs:968-1020 seal_initial` | **P** | **Подтверждённые отличия:** Rust `seal_initial` — только длинный заголовок Initial (маска `0x0f`); C умеет short header (`0x1f`). Совпадают: `pn_len∈1..=4`, проверка `pn_len+plain+16 >= 20`, запись младших битов `pn_len-1`, AAD = заголовок+PN, тег сразу за ct, sample `hdr_len+4`, HP-маска. Для Initial v1/v2 байты совпадают (RFC-тест split Initial, длина/аутентичность); short-header сборка не портирована. |
| `d2k_qw_open` | 396-450 | 55 | long/short, HP, PN decode от `largest_pn`, AEAD open, проверка reserved | `quic.rs:908-966 open_initial` | **P** | **Подтверждённые отличия:** Rust `open_initial` — только Initial (long), `decode_packet_number(0,…)` жёстко с `largest_received=0`, а C принимает `largest_pn` и поддерживает short header. Совпадают: sample `pn_offset+4`, маска `0x0f` для long, PN из маскированных байт, AAD с восстановленным первым байтом/PN, AES-GCM open, проверка reserved `0x0c` после расшифровки. Для первого полёта/снимка результат совпадает; для short header и largest>0 паритет не доказан. Тест `refuses_when_authenticated_initial_is_modified`, split-тесты. |
| `d2k_qw_retry_verify` | 454-479 | 26 | проверка Retry integrity tag: pseudo=`odcid_len‖odcid‖retry[..-16]`, AES-128-GCM key/nonce v1/v2, constant-time compare 16 байт | `quic.rs:569-600 retry_integrity_valid` | E | C шифрует пустой plaintext с AAD=pseudo и получает тег, затем сравнивает побайтно; Rust проверяет тег через `Aes128Gcm::decrypt` (aead сверяет tag). Те же `RETRY_KEY/NONCE` v1/v2, тот же pseudo, лимиты `retry_len>=17`, `retry+1+odcid<=MAX_DATAGRAM`. Тест `quic.rs` (valid/corrupted retry). |
| `d2k_qw_retry_build` | 481-521 | 41 | собрать Retry (серверная роль) | нет | N | Rust только проверяет Retry; сборка не нужна клиентскому datapath |
| `d2k_qw_ranges_reset` | 525-527 | 3 | сброс набора диапазонов | нет (quinn reassembly) | P | пересборка делегирована quinn |
| `d2k_qw_ranges_add` | 529-558 | 30 | добавить/слить диапазон, fin | нет (quinn) | P | собственной реализации нет |
| `d2k_qw_ranges_bytes` | 560-564 | 5 | сумма покрытых байт | `r2o_quic_http3.rs` app-bytes счётчики (иной смысл) | P | диапазоны не портированы |
| `d2k_qw_ranges_complete` | 566-571 | 6 | завершён ли поток (fin покрыт) | quinn `RecvStream`/`finish` | P | функциональность зависимости, не функция |

## core/quic.c (21 функция)

Разбор QUIC Initial, извлечение ClientHello/SNI, инкрементальная сборка и split crypto-фрейма. Порт: `crates/r2k-core/src/quic.rs` (`parse_initial_header`, `open_initial`, `collect_initial_crypto_frames`, `initial_split_crypto`, `r2k_quic_initial_client_hello_from_datagrams`). Доказательства: RFC 9001/9369 unit-тесты, `tests/quic_snapshot.rs`, `scripts/r2o-quic-hello-differential.sh`.

**Прочитано построчно: 21/21 функций, 948 строк C (1–948).** Сверено с `quic.rs`: `parse_initial_header` (`:796-847`), `open_initial` (`:908-966`), `collect_initial_crypto_frames` (`:632-702`), `initial_client_hello_sni` (`:249-258`), `r2k_quic_initial_client_hello_from_datagrams` (`:374+`), `initial_split_crypto` (`:167-244`), `skip_u8/u16_vector` (`:1321-1353`).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `rd16` | 97-99 | 3 | big-endian u16 | `u16::from_be_bytes` | E | хелпер; владельцы покрыты RFC-тестами |
| `read_varint` | 110-125 | 16 | QUIC varint | `quic.rs:1057 read_varint` | E | RFC-тесты Initial |
| `parse_initial_header` | 149-180 | 32 | long header только Initial v1/v2; `n<=1500`, `d2k_qw_hdr_parse`, long, version V1/V2, type Initial | `quic.rs:796-847 parse_initial_header` | E | C вызывает общий `d2k_qw_hdr_parse`, затем требует `long_hdr`, version `V1|V2`, type `INITIAL`. Rust: `len>=7`, long, version `V1|V2`, raw type `0/1`, token varint, `length_claimed>=17 && <= len-cursor`, `pn_offset+20<=len`; лимит `MAX_DATAGRAM`. Для Initial v1/v2 эквивалентно; тест `splits_rfc_9001_initial_without_changing_datagram_length`, v2-тест. |
| `d2k_quic_is_initial` | 182-185 | 4 | предикат: только структура long header Initial v1/v2, без ключей/AEAD | `quic.rs:107-127 is_authenticated_initial` | **P** | **Подтверждённое расхождение:** C возвращает 1 для структурно корректного Initial **с любым шифртекстом/битым тегом**; Rust `is_authenticated_initial` выводит ключи, снимает HP и проверяет AEAD (`open_initial` + `plain.is_empty()`), поэтому такой пакет даёт 0. Тест `refuses_when_authenticated_initial_is_modified` закрепляет более строгий контракт Rust. |
| `decrypt_initial` | 191-216 | 26 | вывести client Initial keys и открыть пакет (`largest_pn=0`) | `quic.rs:908-966 open_initial` | E | C: `d2k_qw_initial_secret(version, DCID, CLIENT)` → `d2k_qw_keys_from_secret` → `d2k_qw_open(..., largest_pn=0)`; Rust `open_initial` выводит client keys из DCID, снимает HP, `decode_packet_number(0,…)`, AES-GCM open, проверяет reserved. RFC-тесты split/SNI. |
| `collect_crypto_frames` | 239-416 | 178 | разбор PADDING/PING/ACK(0x02/0x03)/CRYPTO(0x06)/CONNECTION_CLOSE(0x1c), сборка потока по смещениям; неизвестный/битый кадр → стоп; `max_end` для CRYPTO за буфером | `quic.rs:632-718 collect_initial_crypto_frames` + `skip_initial_ack` | E | Ветви совпадают: PADDING пропускается серией, PING +1, ACK/ACK_ECN читает 4 varint + `range_count` пар (+3 ECN), CRYPTO пишет байты по `offset` в `stream`/`seen` без перезаписи, 0x1c читает err/frame/reason и пропускает reason, иное → break. **Отличие:** C ведёт `max_end` (дальний конец CRYPTO, включая не влезшие в буфер) для `d2k_quic_assembly_complete`; Rust `max_end` не возвращает, а инкрементальная сборка не портирована. RFC-тест `opened_frames`/`crypto_stream`. |
| `skip_u8_vec` | 434-444 | 11 | пропуск TLS-вектора u8: границы `off+1<=len`, `off+1+n<=len` | `quic.rs:1321-1336 skip_u8_vector` | E | Rust: `bytes.get(offset)`, `checked_add(1+len)`, `next<=end`. Те же границы; владелец `find_client_hello_sni`, RFC-тест SNI. |
| `skip_u16_vec` | 446-456 | 11 | пропуск TLS-вектора u16 | `quic.rs:1338-1353 skip_u16_vector` | E | C: `off+2<=len`, `n=rd16`, `off+2+n<=len`; Rust: `read_u16` + `checked_add(2+len)` + `next<=end`. Эквивалентно. |
| `find_sni` | 458-501 | 44 | поиск server_name в расширениях CH: цикл по расширениям, проверка `off+elen<=exts_end`, список имён, `nt==0`, `nlen>0` | `quic.rs:1107-1160 find_client_hello_sni` (внутри) | E | C и Rust одинаково проверяют полный заголовок расширения, границы списка/имени, пустое имя → ошибка; Rust возвращает `Option`, C -1/0. RFC-тест `extracts_sni_from_authenticated_v1_and_v2_initials`. |
| `find_client_hello_sni` | 503-544 | 42 | разбор CH до расширений и SNI: `stream[0]==1`, claimed/avail, version+random, session/ciphers/compression, exts_len, exts_end | `quic.rs:1107-1160 find_client_hello_sni` | E | Ветви совпадают: `filled<4`, тип 0x01, 3-байтная длина, `end=min(claimed,avail)`, `+34`, три вектора, `exts_len`, `off+exts_len<=claimed`, `exts_end=min(off+exts_len,avail)`; Rust дополнительно возвращает `Result` для различения «нет имени»/«бито». Тот же RFC-тест. |
| `crypto_stream_of` | 552-565 | 14 | Initial → CRYPTO-поток | `quic.rs:721 open_initial` + `collect_initial_crypto_frames` | E | RFC-тест `opened_frames` |
| `d2k_quic_client_hello` | 567-589 | 23 | полный ClientHello из одного Initial | `quic.rs:374 r2k_quic_initial_client_hello_from_datagrams` (1 датаграмма) | E | RFC-тест SNI/CH |
| `d2k_quic_dgrams_hello` | 607-657 | 51 | ClientHello из нескольких Initial: один полёт — одна версия и один DCID; поток 8192, полный CH по claimed | `quic.rs:374-437 r2k_quic_initial_client_hello_from_datagrams` | E | C требует одинаковые `version`/`dcid_len`/`DCID` у всех датаграмм, складывает CRYPTO в `stream[8192]`/`seen`, затем проверяет `stream[0]==1` и `whole=4+claimed <= filled && <= cap`. Rust batch-функция делает то же (проверка версии/DCID, сборка, `find_client_hello_sni`, полный CH); тест `fragmented_initials` + `r2o-quic-hello-differential.sh`. |
| `d2k_quic_hello_name` | 661-670 | 10 | SNI из уже собранного ClientHello | `quic.rs:249-258 initial_client_hello_sni` (из opened stream) | E | C `find_client_hello_sni` по полному CH; Rust `initial_client_hello_sni` делает то же через `find_client_hello_sni`. RFC-тест SNI. |
| `d2k_quic_hello_incomplete` | 672-685 | 14 | обрезан ли ClientHello в CRYPTO-потоке (`4+claimed > filled`) | нет прямого | P | Rust batch-функция возвращает `None` при неполном CH, но отдельного предиката «обрезан, но валиден» нет. |
| `d2k_quic_sni` | 687-706 | 20 | SNI из Initial (одна датаграмма) | `quic.rs:249 initial_client_hello_sni`, `:606-623 r2k_quic_initial_sni_result_from_datagrams` | E | C собирает CRYPTO одной датаграммы и ищет SNI; Rust `initial_client_hello_sni`/`..._sni_result_from_datagrams` делают то же, различая «нет имени»/«бито». RFC-тест SNI v1/v2. |
| `d2k_quic_assembly_init` | 708-710 | 3 | сброс инкрементальной сборки | нет (batch-API) | P | Пошагового состояния `d2k_quic_assembly` в Rust нет; batch-функция начинает с чистых буферов. |
| `d2k_quic_assembly_feed` | 712-778 | 67 | добавить датаграмму: при смене version/DCID — новая генерация, `d2k_qw_open` с largest_pn, сбор CRYPTO, вернуть SNI | нет (batch `..._from_datagrams`) | P | Инкрементальный API, `largest_pn`, `crypto_end`, смена поколения по DCID не портированы; batch-функция обрабатывает весь набор сразу. |
| `d2k_quic_assembly_complete` | 780-797 | 18 | полностью ли собрано рукопожатие: 4 байта заголовка, `stream[0]==1`, `crypto_end>=total`, без дыр в буфере | нет | P | Проверка полноты есть внутри batch-функции (полный CH по claimed), отдельного предиката с `crypto_end` нет. |
| `put_split_frame` | 824-839 | 16 | записать CRYPTO-фрейм: 0x06, varint offset, varint len, данные | `quic.rs:1085-1105 append_crypto_frame` | E | C пишет 0x06 + `d2k_qw_varint_write(off)` + `write(len)` + данные, проверяя cap; Rust `append_crypto_frame` делает то же с `checked_add` и truncate при ошибке. Владелец `d2k_quic_initial_split_crypto`, RFC-тест split. |
| `d2k_quic_initial_split_crypto` | 841-948 | 108 | разрезать CRYPTO по середине SNI (хвост первым), пересобрать Initial теми же ключами/PN/длиной, сохранить хвост датаграммы | `quic.rs:167-244 initial_split_crypto` | E | Ветви совпадают: `d2k_qw_hdr_parse` → Initial v1/v2 → `open` → `pn_len` → кадры CRYPTO (PADDING/PING допустимы), `stream`/SNI, `mid=sni_off+sni_len/2`, кадр, содержащий mid, tail-first, остальные кадры, PING/PADDING до прежней длины, `clear_header[0]&=0xf0`, `seal` с тем же PN/длиной, копия хвоста `n>packet_len`. Rust дополнительно проверяет `length_claimed`/`length_width` после seal. Тест `splits_rfc_9001_initial_without_changing_datagram_length`, v2-тест. |

## core/quichello.c (13 функций)

Сборка QUIC Initial из профиля ClientHello: выбор профиля, переименование/удаление SNI, варианты probing (v2, split, longer, clear fixed bit), recid. R2O: `r2k-core/src/quic.rs:261 r2k_quic_initial_build`, `:1113 r2k_quic_client_hello_rename_sni`, `:338 r2k_quic_initial_reseal_for_dcid`; профиль — `r2o-controller/src/quic_replay.rs:98 r2o_quic_profile_snapshot`. Тесты: `quic.rs` (RFC 9001/9369, rename/reseal), `tests/quic_snapshot.rs`.

**Прочитано построчно: 13/13 функций, 548 строк C (1–548).** Сверено с `quic_replay.rs:97-136 r2o_quic_profile_snapshot`, `quic.rs:167-244 initial_split_crypto`, `:261-335 r2k_quic_initial_build`, `:338-371 r2k_quic_initial_reseal_for_dcid`, `:1085-1105 append_crypto_frame`, `:1113-1160 rename_sni`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `select_probe_profile` | 34-45 | 12 | копия профиля + MIPS-замена cipher list по `[0,6]` на `[0x1303,0x1301,0x1302]` | `quic_replay.rs:98-135 r2o_quic_profile_snapshot` | **E** | Rust: профиль 275 байт, MIPS-ветка `get(39..41)==[0,6]` → те же три cipher suite, random/SCID/key_share обновляются. Эквивалентно. |
| `split_point` | 69-77 | 9 | первый SNI начиная с i=1 → `i+m/2`, иначе `n/2` | `quic.rs:167-196 initial_split_crypto` | **P** | Rust ищет SNI в собранном ClientHello, `middle=sni_offset+sni_len/2`, затем кадр, содержащий middle; при отсутствии имени — `NoNameInDatagram`. C при отсутствии имени режет **`n/2`** (вопрос про пересборку кадров всё равно задаётся), Rust в этом случае отказывает. При найденном имени формулы совпадают; тест split покрывает только именованный случай. |
| `put_crypto` | 80-95 | 16 | CRYPTO: 0x06, offset varint, len varint, data | `quic.rs:1085-1105 append_crypto_frame` | **E** | Та же раскладка/проверки; используется split. |
| `prepare` | 124-175 | 52 | разобрать Initial, извлечь CH, IP→удалить SNI иначе rename, DCID 8..20 (иначе 8), SCID из снимка, ver = V2 или версия снимка, ключи | `quic.rs:261-335 r2k_quic_initial_build` + `:1113-1160 r2k_quic_client_hello_rename_sni` | **P** | **Подтверждённые отличия:** Rust `r2k_quic_initial_build` всегда **QUIC v1** (`0xc0`, `QUIC_V1`), генерирует **DCID ровно 8 байт**, берёт **SCID = source_connection_id** от вызывающего (а не из снимка), `pn_len=4`, нет `want_v2`. C сохраняет версию/длину DCID (8..20, иначе 8)/SCID снимка, умеет V2 и `d2k_hello_without_sni` для IP. Композиция в `r2o_quic_profile_snapshot` покрывает только v1/8/профиль; `r2k_quic_initial_reseal_for_dcid` сохраняет форму, но не переименовывает SNI. |
| `seal_one` | 183-228 | 46 | итеративная добивка PADDING до want, long header v1/v2, опционально погасить fixed bit до seal | `quic.rs:261-335` (`target_len` + `seal_initial`) | **P** | **Подтверждённые отличия:** Rust подбирает ширину length перебором `[1,2,4,8]` под `target_len`, всегда v1, `pn_len=4`, fixed bit не гасит; C умеет v1/v2, `pn_len=0 → d2k_qw_pn_len(pn,-1)`, `clear_fixed` гасит бит **до** AEAD. Для `want=1200`, v1, fixed=1 результат эквивалентен (тест 1200). |
| `probe_initial_sized` | 235-274 | 40 | профиль + X25519 + random/SCID + rename (IP→без SNI) + CRYPTO + seal ровно want | `quic_replay.rs:97-136 r2o_quic_profile_snapshot` | **E** | Rust: `R2O_QUIC_PROFILE_HELLO` 275 байт, MIPS-замена cipher list, random 32, SCID 8, X25519 `pub_key`, `server_name.filter(not IPv4)`, `rename_sni`, `initial_build(...,1200)`, snapshot pack. C те же шаги для want=1200 v1 (профиль, random, SCID, X25519 base, IP→`without_sni`, иначе rename, CRYPTO, seal ровно want). Длина/SNI проверяются; тест `initial.len()==1200`. |
| `d2k_quic_probe_initial` | 276-279 | 4 | обёртка want=1200 | `r2o_quic_profile_snapshot` | **E** | Test `initial.len() == 1200`. |
| `d2k_quic_probe_initial_longer` | 281-285 | 5 | обёртка want=1300 (questions.go:237) | `quic.rs:261 r2k_quic_initial_build` (target_len=1200) | **P** | **Подтверждённое отличие:** Rust-владелец всегда вызывает `initial_build(..., 1200)`; вариант 1300 не портирован и не тестируется. |
| `d2k_quic_prepare_target` | 287-310 | 24 | отказ на QSN, попытка rename снятого Initial, иначе профиль 1200 | `r2k_quic_client_hello_rename_sni` + `r2k_quic_initial_build` | **P** | Композиция есть в `quic_replay.rs` (снимок QSN, профиль), отдельной функции с тем же fallback-порядком нет; QSN-отказ/порядок не тестированы. |
| `d2k_quic_hello_rename` | 312-321 | 10 | отказ на QSN, `hello_ask(PLAIN)` → prepare+rename внутри Initial | `quic.rs:1113-1160 r2k_quic_client_hello_rename_sni` | **P** | **Отличие уровня API:** C принимает готовый Initial и пересобирает его; Rust принимает **ClientHello** и возвращает CH. Пересборка Initial — отдельно `initial_build`/`reseal`; прямой C-функции «Initial→Initial rename» нет. Тесты rename/без SNI/повтор. |
| `d2k_quic_hello_ask` | 330-391 | 62 | PLAIN/V2/SPLIT/longer/clear-fixed: `prepare`, один CRYPTO или два (tail первым), `want=max(n,1200)`/1300, `seal_one` с `clear_fixed` | `quic.rs:167-244 initial_split_crypto`, `:261-335 r2k_quic_initial_build` | **P** | C после `prepare` (v1/v2, DCID/SCID снимка, rename/without_sni) собирает тело: split — два CRYPTO `cut..` затем `0..cut`; иначе один CRYPTO. `want=(n>1200?n:1200)`, для LONGER ровно 1300, `seal_one` гасит fixed bit для CLEAR_FIXED_BIT до AEAD. Rust умеет split одного пакета (только по SNI, иначе `NoNameInDatagram`) и v1 build 1200; **v2, longer=1300, clear-fixed-bit** не вынесены. |
| `d2k_quic_hello_split` | 412-455 | 44 | два Initial с одним DCID: tail (PN=1) и head (PN=0), каждый ≥1200, tail первым | нет прямого | **P** | Двухдатаграммного варианта в Rust нет; `initial_split_crypto` даёт один пакет. C `prepare`, `split_point`, tail с PN=1, head с PN=0, оба `seal_one(...,INITIAL_MIN)`; общий DCID на пару. |
| `d2k_quic_hello_recid` | 457-548 | 92 | QSN-отказ, Initial v1/v2, `packet_len==n`, свежий DCID той же длины, SCID из снимка, pn_len из Length, fixed bit из снимка, reseal с той же длиной | `quic.rs:338-371 r2k_quic_initial_reseal_for_dcid` | **E** | C: `d2k_qsnap_is` → -1; parse Initial; version V1/V2; `packet_len==n` (без коалесценции); open старыми ключами; новый DCID той же длины; SCID из снимка; `pn_len=length_claimed-plain_len-16`; long header с `length_width` снимка; `pkt[0]=(pkt[0]&~0x40)|(in[0]&0x40)`; seal; `made==pn_offset+length_claimed==n`. Rust: те же проверки (`packet_len==input.len()`, `new_dcid.len()==dcid_len`), open/новые ключи, `clear_header[0]=input[0]&0xf0` (fixed bit сохранён, младшие 4 обнулены), seal с тем же PN/`pn_len`, проверка `length_claimed/width`. Tests reseal/`quic_snapshot.rs:30`. |

## core/quicsnap.c (6 функций)

Упаковка нескольких QUIC Initial в снимок `QSN` (для повторного использования/пересылки). Порт: `crates/r2k-core/src/quic_snapshot.rs` (`pack`, `parse`, `reseal`, `verify_bound_response`); тесты `r2k-core/tests/quic_snapshot.rs`.

**Прочитано построчно: 6/6 функций, 104 строки C (1–104).** Сверено с `quic_snapshot.rs` (124 строки): `r2k_quic_snapshot_pack` (`:23-47`), `r2k_quic_snapshot_parse` (`:50-76`), `R2kQuicSnapshot::datagrams` (`:17-19`), `quic.rs:374-407`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_qsnap_is` | 13-15 | 3 | проверка магии `QSN` при `n>=4` | `quic_snapshot.rs:50-56 r2k_quic_snapshot_parse` (magic) | E | C: `p && n>=4 && p[0..3]=="QSN"`; Rust: `len>=4 && len<=6144 && input[..3]=="QSN"`. Для валидного снимка эквивалентно; Rust дополнительно ограничивает общий размер. `tests/quic_snapshot.rs` round-trip. |
| `d2k_qsnap_parse` | 17-47 | 31 | разбор: count 1..4, 2-байтные длины, 1..1500, точное потребление | `quic_snapshot.rs:50-76 r2k_quic_snapshot_parse` | E | Ветви совпадают: magic, `count 1..=4`, каждая длина BE u16, `1..=MAX_PACKET`, `off+len<=n`, финальный `off==n`, датаграммы — срезы. Rust дополнительно `input.len()<=6144`; C-снимок из `pack` (≤4×1502+4) заведомо меньше. `tests/quic_snapshot.rs:30` (pack→parse). |
| `d2k_qsnap_pack` | 49-73 | 25 | упаковать 1..4 датаграмм: `QSN`, count, 2-байтные длины, данные | `quic_snapshot.rs:23-47 r2k_quic_snapshot_pack` | E | C: `n 1..4`, каждая непустая `len<=1500`, `need=4+Σ(2+len)`, `need<=cap`; Rust: те же проверки + `total<=6144`, иначе None. Формат байтов совпадает (`QSN`, count, BE u16 len, data); тест round-trip + лимиты. |
| `d2k_qsnap_client_hello` | 75-80 | 6 | ClientHello из всех Initial снимка | `quic.rs:374-407 r2k_quic_initial_client_hello_from_datagrams` | E | C `d2k_quic_dgrams_hello(s->dg,s->len,s->n,...)`; Rust batch-функция с теми же проверками версии/DCID, сборкой CRYPTO и полным CH по claimed. Тест `fragmented_initials`, `r2o-quic-hello-differential.sh`. |
| `d2k_qsnap_sni` | 82-89 | 8 | SNI из снимка: собрать CH (8192), `d2k_quic_hello_name` | `quic.rs:249-258 initial_client_hello_sni`, `r2k_quic_snapshot_parse` | E | C собирает CH и ищет SNI; Rust `initial_client_hello_sni`/`r2k_quic_initial_sni_result_from_datagrams` делают то же. RFC-тесты SNI + snapshot round-trip. |
| `d2k_qsnap_form` | 91-104 | 14 | форма shaping: `n`, `dgram_len` первой, `ch_len` из CH; лимит u16 | `quic_snapshot.rs:17-19 R2kQuicSnapshot::datagrams`, `quic.rs` ClientHello | P | Отдельной структуры `form` в R2O нет: `n` и длины датаграмм выводятся из `datagrams()`, `ch_len` — из собранного ClientHello. C дополнительно отказывает при `len[0]>0xffff`/`chl>0xffff`; адресного differential на форму нет. |

## core/quicsnap_reseal.c (2 функции)

Перешифровка снимка `QSN` под новый DCID. Порт: `r2k-core/src/quic_snapshot.rs:79 r2k_quic_snapshot_reseal`, `quic.rs:338 r2k_quic_initial_reseal_for_dcid`.

**Прочитано построчно: 2/2 функции, 134 строки C (1–134).** Сверено с `quic_snapshot.rs:79-113 r2k_quic_snapshot_reseal`, `quic.rs:338-371 r2k_quic_initial_reseal_for_dcid`, `:409-417 r2k_quic_initial_flight_id`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `reseal_one` | 24-73 | 50 | открыть Initial старым ключом, собрать с новым DCID/ключами, сохранить SCID/token/fixed bit/PN/длину | `quic.rs:338-371 r2k_quic_initial_reseal_for_dcid` | E | Ветви совпадают: parse Initial, `packet_len==n`, open старыми ключами, `pn_len=length_claimed-plain_len-16` (1..4), заголовок с новым DCID и тем же SCID/token/`length_width`, `pkt[0]&~0x40 | in[0]&0x40`, seal новыми ключами, `made==n`. Rust `clear_header[0]=input[0]&0xf0` сохраняет fixed bit и обнуляет младшие 4; seal с тем же PN/`pn_len`; проверка `length_claimed/width`. Tests `quic.rs:1398-1420`, `quic_snapshot.rs:30`. |
| `d2k_qsnap_recid` | 75-134 | 60 | новый DCID для всех Initial снимка: длина из первого (8..20, иначе 8), один DCID на пачку, все датаграммы той же версии/DCID, reseal+pack | `quic_snapshot.rs:79-113 r2k_quic_snapshot_reseal` | **P** | **Совпадает:** разбор снимка, первый Initial, version V1/V2, старые ключи из первого DCID, новый DCID одной длины на все, проверка version/DCID каждой датаграммы, reseal каждой, упаковка. **Отличия:** (1) C при `first.dcid_len` 0..7 берёт новый DCID длиной **8**, Rust `old_dcid.len()<8 → None`; (2) C не проверяет, что новый DCID отличается от старого, Rust делает до 4 попыток и требует уникальности; (3) Rust `r2k_quic_initial_flight_id` требует **аутентифицированный** Initial (`is_authenticated_initial`), C — структурный, но `reseal_one` всё равно открывает старым ключом и падает на битом теге. Для снимков с DCID 8..20 и валидным тегом эквивалентно; тест `tests/quic_snapshot.rs`, контроллер `quic_replay.rs:679`. |

## core/quicprobe.c (56 функций)

Низкоуровневый QUIC-зонд: пул адресов, разбор/проверка Initial и Retry, параллельные ask-циклы, arm-стратегии, вопросы свойств, этап данных HTTP/3 и классификатор `classify_run`. В R2O: `r2o-controller/src/quic_replay.rs` (пул, фильтр, кандидаты, ask), `r2k-core/src/quic.rs` (verify/data judge/wait), `r2o_quic_http3.rs` (этап данных), `main.rs:20496 r2o_run_quic_discovery_trial`. Дифференциалы: `test-controller-quic-pool-differential.sh`, `test-quic-budget-init-differential.sh`, `test-quic-app-bytes-differential.sh`, `test-quic-http3-full-stage-differential.sh`, `test-quic-short-control-differential.sh`, `d2o_quic_base_differential.c`.

**Прочитано построчно: 56/56 функций, 2936 строк C (1–2936).** Сверено с `quic_replay.rs` (пул/ask/кандидаты/base/VN), `quic.rs` (verify/PN/Initial/data judge/wait), `r2o_quic_http3.rs` (этап данных), `main.rs:20496 r2o_run_quic_discovery_trial`. Подтверждённые отличия: `qp_recv_ttl` — N (в `crates/` нет `IP_RECVTTL`/`IPV6_HOPLIMIT`); `d2k_quic_props_findings` — N (текстовых выводов нет); `qp_send_one`/`qp_send_fragmented`/`qp_arm_first_send` — P (plan-send `d2k_udp_plan_send`: prefix/copies/TTL/split/fragment заменён прямым `send`/`QuicReplayProbe`); `d2k_quic_budget_ms` — P (Rust бюджет в пакетах/дедлайнах); `qp_questions_step` — P (C: 6 вопросов junk/frames/datagrams/bit/lowport/length, version2 снят; Rust-набор иной); `classify_run` — P (async trial). Совпадают: пул/дедуп, varint/Initial, donor-response/VN/Retry, bound-проверка, `qp_dyn_wait`, `qp_pinned_or_next`, neutral SNI, base-дифференциал.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `qp_addr_parse` | 173-179 | 7 | IPv4/IPv6 из текста, запрет `%`, 16-байтный выход | `std::net::IpAddr`/`SocketAddr` в `quic_replay.rs:23-53,56-75` | **P** | C `memcpy`-буфер: `inet_pton(AF_INET)` затем `AF_INET6`, отказ при `%` и пустом/битом тексте, family 4/6. Rust разбирает `SocketAddr`/`IpAddr` через `std`; зона `%` не тестировалась, отдельной функции с тем же буферным контрактом нет. Для обычных литералов эквивалентно. |
| `resolve_family` | 181-208 | 28 | getaddrinfo в пул адресов семьи, до `cap`, `inet_ntop` | `quic_replay.rs:56-75 r2o_quic_address_pool` (резолв снаружи) | **E** | C `getaddrinfo(sni,NULL,{family,SOCK_DGRAM})`, обход `ai_next`, `inet_ntop`; Rust получает уже разрешённые `SocketAddr`, фильтрует ту же семью и дедуплицирует (`:61-73`). Pool differential (v4/v6/дубли) `r2o_quic_residual_control_and_address_pool_match_d2o` (`quic_replay.rs:1147`). |
| `resolve_real` | 209-211 | 3 | resolve только IPv4 | `quic_replay.rs:56-75` + резолвер контроллера | **E** | C-обёртка `resolve_family(sni, AF_INET, ...)`; Rust резолвит адрес цели до пула, pool differential проверяет IPv4-путь и дедуп. |
| `d2k_quic_build_pool` | 254-295 | 42 | цель + DNS-адреса семьи, дедуп по 16 байтам, первый адрес гарантирован | `quic_replay.rs:56-75 r2o_quic_address_pool` | **E** | **Совпадает:** первый адрес — `ip` как есть, затем same-family адреса резолвера, дедуп по IP, порт берётся из primary (Rust `SocketAddr::new(address.ip(), primary.port())`), предел `D2K_QUIC_MAX_ADDRS`/`R2O_QUIC_MAX_ADDRS=8`. C дополнительно проверяет `strlen(ip)<ADDR_LEN`, `memchr` и зажимает `n_extra`; Rust работает с типизированными адресами. Тест `r2o_quic_residual_control_and_address_pool_match_d2o` (`quic_replay.rs:1147`) + pool differential. |
| `qp_varint` | 320-335 | 16 | QUIC varint: width 1/2/4/8, проверка `avail`, сборка BE | `quic.rs:1057 read_varint` | **E** | C `w=1<<(p[0]>>6)`, `avail<w` → -1, значение из младших 6 бит + BE-байты; Rust `read_varint` те же ширины/границы. RFC-тесты Initial (`r2k-core`/`tests/quic_budget.rs`). |
| `qp_parse_hdr` | 337-405 | 69 | разбор Initial: version/DCID/SCID/token/length/pn, проверки границ и 16-байтного сэмпла | `quic.rs:796 parse_initial_header` | **E** | C сначала `d2k_quic_is_initial`, затем version 1/2, длины DCID/SCID, varint token/length, `pn_offset`, `length<=n-pn`, `pn+4+16<=n`; Rust `parse_initial_header` те же поля/границы (RFC 9001 §5.4.2). RFC 9001/9369 тесты. |
| `qp_dcid_of` | 411-420 | 10 | версия и координаты DCID из Initial | `quic.rs:796 parse_initial_header` (поля) | **E** | C-обёртка над `qp_parse_hdr`; Rust использует поля `InitialHeader`/`r2k_quic_initial_flight_id`. Покрыто verify-тестами `quic.rs`. |
| `qp_donor_unauth_reply` | 456-490 | 35 | распознать VN/Retry/чужой Initial по критерию донора без AEAD | `quic.rs:441 r2k_quic_donor_response_matches` | **E** | **Совпадает:** длина ≥7, длинный заголовок (`p[0]&0x80`), разбор version/DCID/SCID, version 0 → VN, тип Retry (`0x03` v1, `0x00` v2) при совпадении версии → Retry, тип Initial (`0x00` v1, `0x01` v2) и та же версия → 0 (нужен AEAD), иначе -1. Rust `r2k_quic_donor_response_matches` те же условия; base differential/unit `quic.rs` (VN/Retry/corrupted). |
| `qp_verify_server_response` | 494-544 | 51 | ответ сервера: donor-критерий + AEAD серверными ключами из нашего DCID | `quic.rs:422 r2k_quic_initial_verify_donor_response` | **E** | C: `qp_donor_unauth_reply` → 1/0/-1, затем `qp_parse_hdr`, версия, `d2k_qw_initial_secret` (server)/`keys_from_secret`, `d2k_qw_open`, любой расшифрованный Initial; Rust `r2k_quic_initial_verify_donor_response` тот же порядок/ключи. Unit `quic.rs` (valid/wrong CID/corrupted) + base differential. |
| `qp_build_vn_trigger` | 574-615 | 42 | 1200-байтовый GREASE-Initial: 0xC0, версия 0x1a2a3a4a, случайные DCID/SCID 8, токен 0, нули | `quic_replay.rs:159-175 r2o_quic_build_vn_probe` | **E** | **Совпадает:** 1200 байт, `0xC0`, `0x1a2a3a4a`, DCID 8 + SCID 8 из CSPRNG, `token=0`, нули до 1200. Rust тест `r2o_quic_version_negotiation_probe_matches_d2o_wire_shape` (`quic_replay.rs:1248`) проверяет длину/поля/нули; C/Rust differential формы. |
| `nap_us` | 622-627 | 6 | nanosleep на микросекунды | `std::thread::sleep`/tokio в `main.rs` | **P** | C `nanosleep(us/1e6, us%1e6*1000)`; Rust паузы 60 мс заданы `R2O_QUIC_RESIDUAL_GAP`/tokio, отдельной функции нет. Семантика паузы та же. |
| `qp_open_fresh` | 637-697 | 61 | UDP-сокет: SO_MARK, опциональный bind src_port, connect, защита от свежего порта (`d2k_udp_port_claim`), удержание отвергнутых fd | `r2o_quic_http3.rs:71 r2o_quic_http3_udp_socket_fresh` | **P** | **Совпадает:** свежий UDP-сокет, best-effort SO_MARK, connect к цели, учёт метки. **Отличия:** C умеет `bind` на заданный `src_port` (вопрос lowport), перебирает до `D2K_UDP_FRESH_TRIES` через `d2k_udp_port_claim` и держит отвергнутые fd до конца серии; Rust `r2o_quic_http3_udp_socket_fresh` не принимает src_port и не имеет port-claim/удержания. Для обычных вопросов эквивалентно, lowport — P. |
| `qp_send_one` | 716-789 | 74 | открыть/пометить/подключить, IP_RECVTTL/HOPLIMIT, пачка, план prefix/split/longer, хвост прямым send, ECONNREFUSED → -2 | `quic_replay.rs:647-826 QuicReplayProbe` (`run`/`r2o_run_inner`) | **P** | **Подтверждённые отличия:** C для пачки `d2k_qsnap_parse` шлёт голову через `d2k_quic_question_plan`+`d2k_udp_plan_send` (prefix TTL/copies/split/longer), хвост — прямым `send`; Rust `QuicReplayProbe` перезапечатывает снимок и шлёт все датаграммы прямым `socket.send`, без plan-цепочки, TTL, copies/split/longer и без IP_RECVTTL/HOPLIMIT. `ECONNREFUSED` у C → -2; Rust `send` ошибку возвращает, `refused` считается в `r2o_quic_collect_donor_answers`. Обычный одиночный Initial эквивалентен. |
| `qp_head_of` | 806-813 | 8 | первая датаграмма пачки для проверки ответа | `quic_snapshot.rs:50 r2k_quic_snapshot_parse` | **E** | C `d2k_qsnap_is/parse` → `pk.dg[0]`; Rust `r2k_quic_snapshot_parse`/`datagrams()` даёт тот же первый Initial. Snapshot-тесты. |
| `qp_verify_aead` | 815-823 | 9 | проверить ответ по ключам клиентского Initial (голова пачки) | `quic.rs:422 r2k_quic_initial_verify_donor_response`, `quic_replay.rs:854-860` | **E** | C `qp_head_of` + `qp_dcid_of` + `qp_verify_server_response`; Rust donor-путь `r2k_quic_donor_response_matches` (VN/Retry/Initial) в `r2o_quic_collect_donor_answers`, строгий путь `r2k_quic_snapshot_verify_bound_response` в `QuicReplayProbe`. Тесты snapshot/verify + base differential. |
| `qp_verify_bound` | 835-878 | 44 | строгая привязка ответа: DCID ответа = наш SCID, Retry tag/SCID, VN не успех | `quic.rs:475 r2k_quic_initial_verify_bound_response` | **E** | C проверяет DCID/SCID нашего Initial, Retry: версия≠0, `rd==scid_len`, SCID≠наш DCID, непустой токен, `d2k_qw_retry_verify`; Initial — `qp_verify_server_response` + DCID ответа = наш SCID. Rust `r2k_quic_initial_verify_bound_response` те же условия; unit `quic.rs` (retry/corrupted/wrong CID). |
| `d2k_quic_verify_bound` | 880-882 | 3 | публичная обёртка `qp_verify_bound` | `quic.rs:475` | **E** | Тонкая обёртка; тот же unit `quic.rs`. |
| `d2k_quic_verify_response` | 890-892 | 3 | публичная обёртка AEAD-проверки | `quic.rs:422` | **E** | Тонкая обёртка; unit `quic.rs` + base differential. |
| `qp_verify_vn` | 898-903 | 6 | проверка ответа VN-зонда: donor-критерий с версией 1 и DCID из отправленного VN-триггера | `quic_replay.rs:967-1009 r2o_quic_ask_donor_version_negotiation`, `quic.rs:441` | **E*** | C берёт DCID из `msg.bytes+6` (VN-триггер) и версию V1, затем `qp_verify_server_response` (VN/Retry/Initial). Rust VN-путь использует `r2k_quic_donor_response_matches(1,&dcid,response)` с DCID из `r2o_quic_build_vn_probe`; тест `r2o_quic_version_negotiation_uses_donor_parallel_answers` (`quic_replay.rs:1280`) проверяет 3/3. Отдельного C/Rust differential именно `qp_verify_vn` нет. |
| `qp_recv_ttl` | 937-997 | 61 | recvmsg + IP_TTL/IP_RECVTTL/IPV6_HOPLIMIT, тестовый fault-hook | нет | **N** | В `crates/` нет `recvmsg`/`IP_RECVTTL`/`IPV6_HOPLIMIT` для QUIC-зонда; Rust `UdpSocket::recv` не возвращает TTL. Поле `server_ttl_in`/свойства TTL не заполняются. |
| `qp_send_fragmented` | 1004-1040 | 37 | отправка IP-фрагментами: форма 1..4, свежий сокет, план `ipfrag`, `d2k_udp_plan_send` | `r2k-core/src/wire.rs:294 build_udp_fragments`, `quic_replay.rs:490-503 fragment_candidates` | **P** | Rust умеет собирать IPv4/IPv6-фрагменты (`build_udp_fragments`, тесты `ipfrag.rs`) и строит кандидатов `ipfrag 1..4`, но контроллерный raw-отправитель фрагментов на провод отсутствует: `QuicReplayProbe`/`r2o_quic_ask_donor_parallel` шлют готовые датаграммы, а не фрагментированный план. C-ветка `!linux` → -1. |
| `qp_neutral_control_sni` | 1045-1058 | 14 | `z<10hex>.example.com` из 5 случайных байт | `quic_replay.rs:139-156 r2o_quic_neutral_control_snapshots` | **E** | **Совпадает:** 5 байт CSPRNG → 10 hex, префикс `z`, суффикс `.example.com`, 24-байтный буфер; Rust строит 3 таких имени на каждый контроль и snapshot. Тест `r2o_quic_donor_parallel_control_matches_d2o` (`quic_replay.rs:1338`) проверяет уникальные порты/3 ответа; `r2o_quic_neutral_control_snapshots` — формат. |
| `quic_ask_core` | 1064-1403 | 340 | repeats≤8; на попытку свежий DCID/снимок/пачка/VN/neutral/split; src_port-i; все send параллельно; poll до deadline; verify; RTT min, TTL; refused(-2)/err(-1) | `quic_replay.rs:901-964 r2o_quic_ask_donor_parallel` | **P** | **C-ветви проверены:** `repeats<=0 → 3`, `>8 → err=fail=repeats` без отправки; `wait=0 → floor`; на каждую попытку: VN-триггер, fresh_sni, neutral, split-пара, пачка или `d2k_quic_hello_recid`; `src_port-i`; отправка всех до poll; `POLLERR`→`SO_ERROR`; `ECONNREFUSED` → fail+refused, иное чтение → fail, `n==0` → fail; успех — `verify==0`; min RTT/первый TTL; `sent=repeats-not_sent`. **R2O-отличия:** donor parallel шлёт снимки прямым `send` (без src_port/TTL/prefix/copies/split/longer/plan), reseal на попытку, `refused` через tokio `ConnectionRefused`, RTT min, `sent/err/marked`; нет TTL и C-предела repeats в том же виде. Тест `r2o_quic_donor_parallel_control_matches_d2o`. |
| `quic_ask_ex` | 1405-1416 | 12 | обёртка core без crypto_split/longer | `quic_replay.rs:901 r2o_quic_ask_donor_parallel` | **P** | Тонкая обёртка; наследует отличия `quic_ask_core` (прямой send, нет TTL/plan-цепочки). |
| `quic_fragment` | 1418-1428 | 11 | ask с IP-фрагментацией по форме | `quic_replay.rs:490-503 r2o_quic_fragment_candidates` | **P** | Rust строит 5 кандидатов (control + формы 1..4) с директивами `ipfrag N`, но фактическая raw-отправка фрагментов в контроллере отсутствует (см. `qp_send_fragmented`). |
| `qp_progress` | 1432-1435 | 4 | hook прогресса только при `sent>0` | `main.rs` progress callback | **P** | C вызывает `d2k_quic_progress_hook(question,sent)`; Rust передаёт прогресс через discovery/CLI callback. Отдельного hook с тем же контрактом нет; тексты/момент иные. |
| `quic_ask_arm` | 1437-1477 | 41 | ask по arm-вопросу: neutral control/fragment/split | `quic_replay.rs:647 QuicReplayProbe`, `:449-503 candidates` | **P** | C собирает вопрос по `d2k_quic_arm_question` (control/addr/sni/frag/copies/ttl/split/longer), для control строит neutral; Rust arm-вопросы выражены кандидатами `discovery_candidates`/`fragment_candidates` и прямым probe; композиция/метки иные. |
| `qp_arm_first_send` | 1500-1508 | 8 | первый send Initial через план, вернуть local_port | `quic_replay.rs:647` | **P** | C использует `d2k_udp_plan_send` для первого пакета и `getsockname`; Rust `QuicReplayProbe` шлёт снимок напрямую, local_endpoint известен из сокета. Plan-send отсутствует. |
| `qp_now_ms` | 1510-1514 | 5 | монотонное время, мс | `std::time::Instant` | **P** | C `CLOCK_MONOTONIC` → мс; Rust `Instant`/`Duration` в HTTP/3/дедлайнах. Отдельной функции нет, единицы пересчитываются. |
| `quic_arm_data` | 1516-1584 | 69 | этап данных по arm: connect, h3, SETTINGS/GET, judge | `quic_replay.rs:417 r2o_quic_trial_data_verdict`, `r2o_quic_http3.rs:822 measure_with_wire_len` | **P** | C создаёт `d2k_qc`, вызывает `d2k_quic_data_stage`, возвращает `d2k_quic_arm_data` с verdict/reason/app_bytes/packets/requests/oneway. Rust `r2o_quic_http3_measure_with_wire_len` + `r2o_quic_trial_data_verdict`; композиция иная, stage differential покрывает основные исходы. |
| `d2k_quic_data_stage` | 1591-1829 | 239 | SETTINGS/control, GET stream 0, HEADERS 64 КиБ, 451, app-байты, PING-stall (RTO 3×RTT≥1с), бюджет 2× датаграмм, judge3, reason | `r2o_quic_http3.rs:822-1200 measure_with_wire_len` | **P** | **C-ветви проверены:** control `d2k_h3_control`; ошибка запроса → NOT_RUN; `malloc(D2K_VERIFY_HEADER_LIMIT)`+diag; `d2k_qstall_init(rtt, app_progress, rx_wire)`; `limit=max(4*step,4*RTO)`; повтор запроса только при `complete && status` на `sid+4`, сброс bytes/status/head_len; PING при `D2K_QSTALL_PROBE` с запоминанием PN; `451` → break; `judge3(1,status,bytes,complete,stalled,need_complete,head_full,budget)`. **R2O-отличия:** quinn/h3-клиент сам держит control stream, явной паузы 400 мс нет; бюджет/повторы через `R2oQuicHttp3Budget`/`Stall`; reason-тексты и judge3 не сверены побайтно. Stage-дифференциал `test-quic-http3-full-stage-differential.sh`. |
| `quic_ask` | 1832-1839 | 8 | базовый ask AEAD | `quic_replay.rs:901 r2o_quic_ask_donor_parallel` | **P** | Обёртка `quic_ask_ex`; наследует отличия прямого send/без TTL. |
| `qp_ask_vn` | 1855-1862 | 8 | ask VN: пустой msg, repeats 3, verify VN | `quic_replay.rs:967-1009 r2o_quic_ask_donor_version_negotiation` | **P** | C вызывает `quic_ask_ex` с `qp_verify_vn`, VN-триггер строится на каждую попытку, `D2K_QUIC_REPEATS`; Rust отдельная функция: 3 свежих VN-триггера, donor-сбор ответов, `sent/pass/refused/err/marked`. Тест `r2o_quic_version_negotiation_uses_donor_parallel_answers` (`quic_replay.rs:1280`). Побайтового C/Rust differential нет. |
| `quic_ask_ttl` | 1869-1875 | 6 | ask с prefix TTL | `quic_replay.rs:901` | **P** | C передаёт `prefix_ttl` в `quic_ask_ex` → `qp_send_one` ставит IP_TTL перед приманкой и восстанавливает; Rust `QuicReplayProbe` TTL не трогает, plan-send отсутствует. |
| `quic_ask_copies` | 1886-1893 | 7 | ask с числом копий приманки | `quic_replay.rs:901`, `:506-554` | **P** | C `prefix_copies` уходит в plan-send; Rust copies выражены директивой `fake ... repeats=N` в кандидатах fallback, но прямой ask копии не шлёт. |
| `quic_ask_srcport` | 1898-1904 | 6 | ask с исходным портом | `r2o_quic_http3.rs:71` + probe | **P** | C `src_port-i` и bind; Rust fresh-socket API не принимает src_port. Вопрос lowport не задаётся. |
| `quic_ask_split` | 1909-1915 | 6 | ask парой датаграмм с разрезом ClientHello | `quic.rs:167 initial_split_crypto` | **P** | Rust умеет `r2k_quic_initial_split_crypto`/`quicsplit`, но ask-режим пары на каждую попытку не вынесен; `QuicReplayProbe` шлёт снапшот как есть. |
| `quic_ask_longer` | 1924-1930 | 7 | ask с удлинённым Initial (udplen=100) | `quic_replay.rs:481-485` (`udplen 100`) | **P** | Rust добавляет кандидата `UdpLength` с директивой `udplen 100`, но прямой ask `100` не параметризован; `QuicReplayProbe` шлёт исходный снимок. |
| `quic_ask_frames` | 1931-1937 | 7 | ask с двумя CRYPTO-фреймами | `quic.rs:167 initial_split_crypto` | **P** | Rust `quicsplit 1` — кандидат стратегии; ask-режим `crypto_split` в параллельном пробе не вынесен. |
| `quic_ask_control` | 1942-1950 | 9 | ask нейтрального контроля | `quic_replay.rs:139-156 neutral snapshots` | **P** | C `neutral_control=1` → на каждую попытку fresh neutral SNI/Initial; Rust `r2o_quic_neutral_control_snapshots` строит 3 снимка, `r2o_quic_ask_donor_parallel` шлёт их; hook/цикл иной. |
| `reason_set` | 1957-1962 | 6 | записать reason через `vsnprintf` | `classify.rs`/`main.rs` reason string | **P** | C форматирует в `r->reason`; Rust собирает `String`/`format!`, тексты и лимиты иные. |
| `reason_append` | 1964-1973 | 10 | дописать reason с проверкой остатка | `classify.rs:1248 append_reason` | **P** | C `strlen`+`vsnprintf` в хвост; Rust `append_reason` дописывает в строку. Тексты/разделители не сверяются. |
| `budget_left` | 1984-1999 | 16 | остаток бюджета по `CLOCK_MONOTONIC`; `limit==0` → всегда 0 | `r2o_quic_http3.rs:548-580 R2oQuicHttp3Budget` | **P** | C бюджет в мс от `start`, `elapsed<=limit`, явный ноль; Rust бюджет в пакетах/дедлайнах, формула и единицы иные. |
| `qp_pinned_or_next` | 2018-2027 | 10 | без residual — pool[0]; иначе следующий адрес или NULL | `quic_replay.rs:78-90 r2o_quic_next_question_address` | **E** | **Совпадает:** `!residual` → primary, `next>=pool.len()` → None, иначе `pool[next]` с `next++`. Тест `r2o_quic_residual_control_and_address_pool_match_d2o` (`quic_replay.rs:1147`) проверяет pinned/fresh/unasked. |
| `qp_dyn_wait` | 2088-2093 | 6 | `clamp(3×RTT, floor, ceil)` | `quic.rs:66 r2k_quic_dynamic_wait_ms` | **E** | **Совпадает:** `rtt>ceil ? ceil : 3*rtt`, затем пол/потолок. Rust `r2k_quic_dynamic_wait_ms` та же формула; тесты `tests/quic_budget.rs:15`. |
| `d2k_quic_budget_ms` | 2096-2104 | 10 | бюджет в мс: тестовое переопределение или `wait + QP_RUN_DYN_POLLS*(dyn_wait+60)` | нет прямого | **P** | Rust бюджеты HTTP/3 в пакетах/дедлайнах (`R2oQuicHttp3Budget`), формула `d2k_quic_budget_ms` не портирована. |
| `qp_outcome` | 2111-2116 | 6 | tally → UNKNOWN/YES/NO: `err>0` или частичный pass → UNKNOWN; 3/3 → YES; иначе NO | `quic_replay.rs:276 r2o_quic_direct_action`, `:332 filter_round_decision` | **P** | C единогласие 3/3; Rust решения разделены: `r2o_quic_filter_round_decision` (Pass/No/Retry/Unknown) и `r2o_quic_direct_action`; маппинг иной, но исходы совпадают для 0/3/частичных. |
| `qp_questions_step` | 2118-2268 | 152 | 6 вопросов: мусор/кадры/датаграммы/бит/низкийпорт/длина; version2 снят; пропуск уже отвеченных; бюджет/адреса/не собралось; qtrace | `quic_replay.rs:449-503 r2o_quic_discovery_candidates` | **P** | **C-ветви проверены:** `qp_list` — junk (16 нулей), frames (SPLIT_CRYPTO), datagrams (SPLIT), bit (CLEAR_FIXED_BIT), lowport (SRCPORT `port-1`), length (LONGER); version2 не задаётся; пропуск `junk_asked`/`frames_asked`/`longer_asked` и уже известных; сначала сборка, потом адрес; `n_budget/n_addr/n_unbuilt/n_strategy`; `qp_outcome`; qtrace. **R2O-отличия:** набор `Clearance/SplitCrypto/UdpLength/TtlStrategy` иной по составу/порядку, lowport/longer в том же виде нет, бюджет в пакетах. |
| `d2k_quic_props_findings` | 2275-2323 | 50 | текстовые выводы по split_crypto/split_datagrams/version2/clear_fixed_bit/low_source_port | нет | **N** | В R2O текстовых `finding`-строк нет; свойства живут в `R2oQuicDiscoveryCandidate`/результатах, но аналогичного массива сообщений и `d2k_quic_props.cap`-контракта нет. |
| `arm_budget_left` | 2326-2326 | 1 | адаптер `budget_left` для arm-контекста | `quic_replay.rs` budget callbacks | **P** | C передаёт function pointer `can_ask`; Rust использует замыкание/дедлайн, отдельной функции нет. |
| `arm_budget_spent` | 2329-2332 | 4 | увеличить бюджет на потраченное arm-время (saturating) | нет | **P** | C `limit_ms += ms` с насыщением; Rust динамического бюджета arm нет, дедлайны фиксированы. |
| `classify_run` | 2337-2917 | 582 | шаг 0 контроль → 1 прямой Initial → 2 остаточный контроль → 3 VN/address → 4 arms/questions; base_only/seed; local-address; CLEAR/OPAQUE/NO_QUIC/ADDRESS/FLAKY | `main.rs:20496 r2o_run_quic_discovery_trial`, `quic_replay.rs:289 r2o_quic_base_result` | **P** | **C-ветви проверены:** вход ip/sni/trigger → FLAKY; private/local IP → LOCAL_ADDRESS; пул, `next_addr=1`; шаг 0 control/seed: refused → NO_QUIC, err==3 → FLAKY, pass==0 → VN, VN pass>0 → NO_QUIC, VN 0 → ADDRESS; pass>0 → dyn_wait/бюджет, шаг 1 direct/seed; base_only → CLEAR/INCONCLUSIVE; err>0 → FLAKY; 3/3 → data-cut arm (2 запроса+короткий контроль) или CLEAR/INCONCLUSIVE по метке; 0<pass<3 → FLAKY; шаг 2 nap 60 мс + residual control, `residual=pass==0`, OPAQUE, arms/questions, early exit `have_arm`; финальный marked. **R2O-отличия:** async trial/`r2o_quic_base_result`, бюджет в пакетах/дедлайнах, arms/questions через `discovery_candidates`; `d2o_quic_base_differential.c` и HTTP/3 stage покрывают не все ветви (`budget exhausted`, `data_cut 2`, короткий контроль). |
| `d2k_quic_classify` | 2920-2922 | 4 | публичный classify | `main.rs:20496` | **P** | Обёртка `classify_run`; наследует P. |
| `d2k_quic_base` | 2923-2926 | 4 | только базовый вопрос | `quic_replay.rs:289 r2o_quic_base_result` | **E** | C `classify_run(...,base_only=1,...)`; Rust `r2o_quic_base_result` + тест `r2o_quic_base_result_matches_d2o` (`quic_replay.rs:1041`) и `d2o_quic_base_differential.c`. |
| `d2k_quic_run_seeded` | 2928-2931 | 5 | classify с заранее снятым base seed | нет (seed-структуры нет) | **P** | C принимает `d2k_base_seed` и использует `ctl_pass/ctl_fail/...` вместо повторного опроса; Rust base-seed структуры/пути нет. |
| `d2k_quic_run` | 2933-2935 | 4 | публичный classify с arm | `main.rs:20496` | **P** | Обёртка `classify_run`; наследует P. |

## core/quicarms.c (8 функций)

Лестница arm-стратегий QUIC: перебор blob/копий/TTL/IP-фрагментации, затем стратегии clearance/split/longer/frag. R2O: `r2o-controller/src/quic_replay.rs` (`r2o_quic_discovery_candidates`, `r2o_quic_original_fallback_candidates`, `r2o_quic_strategy_attempt_decision`). Дифференциал `r2o-diagnostics-differential.sh` (C `quicarms.c` + `d2o_quic_base_differential.c`) покрывает профиль/verify/parallel/VN/base, но не всю лестницу.

**Прочитано построчно: 8/8 функций, 396 строк C (1–396).** Сверено с `quic_replay.rs:427-630` (`r2o_quic_discovery_candidates`, `original_fallback_candidates`, `blob_candidate`, `strategy_attempt_decision`).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_quic_original_blob` | 12-17 | 6 | 5 blob'ов: quic5, quic_google, quic_rutracker, fake_default_quic (620×0x40), 16 нулей; `index>=5 \|\| !len → NULL` | `quic_replay.rs:586-637 r2o_quic_blob_candidate/blob_name` | **E** | C: `quic_donor_blob_0/1/2`, `default_blob[620]={0x40}`, `zero_blob[16]`, имена `quic5/quic_google/quic_rutracker/fake_default_quic/0x000…`. Rust: `R2O_QUIC_ORIGINAL_BLOBS[0..4]`, `blob==4 → [0;16]`, имена `исходная приманка quic5/…`; размеры/содержимое 0–3 сверяются profile differential. |
| `ask_q` | 30-104 | 75 | yield/бюджет, выбор `pool[residual?next++:0]`, probe, trace, data-stage, measured/retry | `quic_replay.rs:368-416 strategy_attempt_decision`, `:647-790 QuicReplayProbe` | **P** | **C-ветви проверены:** yield hook → `paused_ms` в бюджет; `n_trace>=MAX` → incomplete; `can_ask==false` → not_measured=2; нет pool/адреса → not_measured=1; адрес `pool[residual?next++:0]`; probe; `sent/answered` в trace; `sent!=3 \|\| err>0` → incomplete/not_measured=3/retry; `measured=1`; `pass!=3` → retry при 1..2, иначе NO; control/no data → YES; data stage + spent; `data_note` с oneway; PASS→YES, NOT_RUN→incomplete/measured=0/retry. **R2O-отличия:** decision-функции без trace/`qp_budget`/`data_note`; probe-объект шлёт напрямую. |
| `ask_frag` | 112-121 | 10 | контроль фрагментов, затем формы 1..4 | `quic_replay.rs:490-517 r2o_quic_fragment_candidates` | **P** | Rust строит 5 кандидатов: control + 4 формы, те же директивы `ipfrag N`; **фактическая raw-отправка фрагментов в контроллере отсутствует** (см. `qp_send_fragmented`). |
| `ask` | 125-140 | 16 | собрать вопрос по blob/copies/ttl/frag/control + label | `quic_replay.rs:586-620 r2o_quic_blob_candidate` | **P** | Параметры/директивы совпадают (`payload 1`, `fake … repeats`, `poison ttl`, `quicsplit`, `udplen`, `ipfrag`); C-метки и тексты не портированы. |
| `d2k_quic_original_arms` | 142-219 | 78 | 5 singles → quic5/fake_default ×6/11 → adaptive fake_default×11+split → TTL 3/5/8/12 → frag | `quic_replay.rs:506-584 r2o_quic_original_fallback_candidates/_adaptive_split_candidate/_eligible` | **P** | **C-ветви проверены:** singles `b=0..4`, `b==4` пропускается при `benign_answered`; первый passing → selected; пары `candidates={0,3} × repeats={6,11}`; adaptive split только при `split_failed && !no_split && candidate==3 && copies==11 && last.answered>0 && ((answered<3 && !not_measured) \|\| data==CUT \|\| data==NO_HANDSHAKE)`; TTL `{3,5,8,12}` с blob 0/copies 2, TTL3 пропускается при `ttl_pair_answered`; frag при `!frag_answered`; selected → kind TTL/COPIES, frag→FRAG, `!marked`→FLAKY. **Rust:** те же списки/условия в `original_fallback_candidates`; adaptive split вынесен отдельным кандидатом с `r2o_quic_adaptive_split_eligible` (эквивалентное условие), порядок в списке иной. |
| `strategy_ask` | 227-242 | 16 | до 2 попыток, `asked` по not_measured 1/2, YES/NO/UNKNOWN | `quic_replay.rs:331-366 filter_round_decision`, `:368-416 strategy_attempt_decision` | **P** | Логика retry/NO/UNKNOWN совпадает: measured==repeats, answered 0→NO, 1..2→retry, attempt>1→Unknown. C отдельно ведёт `asked`; Rust — вызывающий. |
| `prop_word` | 244-246 | 3 | «прошло/не прошло/ответа нет» | нет | **N** | Только текст причины; Rust-строки формируются иначе. |
| `d2k_quic_strategy_arms` | 248-396 | 149 | TTL-lifetime (quic5×2 TTL3) → clearance benign → split CRYPTO → longer 100 → frag → original fallback; слияние trace | `quic_replay.rs:448-487 r2o_quic_discovery_candidates`, `:506-584` fallback/adaptive, `:368-416` decision | **P** | **C-ветви проверены:** TTL-вопрос только при `need_complete && budget_pk` (blob0/copies2/ttl3); YES → `TTL_LIFETIME`; иначе benign (16 нулей/copies1) → YES `CLEARANCE`; иначе split (если `!no_split`) → YES `SPLIT`; иначе `udplen=100` → YES `LENGTH`; если `clearance==NO && (split==NO \|\| no_split)` → `ask_frag`, форма → `FRAG`; иначе `d2k_quic_original_arms` с `benign_answered/frag_answered/ttl_pair_answered/split_failed`, слияние trace и `strategy=LADDER/FAKE_SPLIT`; `!marked`→FLAKY. **R2O:** `discovery_candidates` даёт плоский список TTL→Clearance→Split→UdpLength, `fragment_candidates` и `original_fallback_candidates` отдельно, решение — `strategy_attempt_decision`; полная лестница differential не покрыта. |

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

**Прочитано построчно: 36/36 функций, 1490 строк C (1–1490).** Сверено с `r2o_quic_http3.rs:217-234` (`R2oQuicHttp3Result`), `:889-916` (`ClientConfig::builder().with_root_certificates(roots)` → `QuicClientConfig` → `quinn::ClientConfig`), `quic_replay.rs` (`QuicReplayProbe`), `quic.rs:261-335` (`initial_build`). Критические отличия: C `tp_build` объявляет idle 30000, max_udp 1452, max_data 1 МиБ, stream window 256 КиБ, streams 16/16, CID limit 2, `initial_source_connection_id`; в `r2o_quic_http3.rs`/`quic_replay.rs` **нет `TransportConfig`** (grep), поэтому действуют умолчания quinn. C `d2k_qc_connect` **не проверяет цепочку/подпись** сертификата (только имя через `d2k_t13_cert_name_ok`), Rust `with_root_certificates(roots)`/webpki рвёт handshake при mismatch. C `first_flight` собирает CH из SNI+TP+ALPN h3 собственным `d2k_t13_ch_build`, Rust data-stage использует CH rustls. Остальные функции — P, заменены quinn/rustls; `crypto_frame` — E, `d2k_qc_peer_name` — N (в `R2oQuicHttp3Result` нет `name_ok`/`peer_name`).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `qc_dispose` | 209-211 | 3 | освободить `d2k_qc`, снять diag-учёт памяти | `quinn::Connection`/`Drop` | **P** | C `d2k_diag_memory_release(..., sizeof *c, ...)` + `free`; Rust соединение и буферы освобождаются `Drop`/RAII. Отдельной функции и diag-учёта размера `d2k_qc` нет. |
| `say` | 215-224 | 10 | `vsnprintf` ошибки в `err/cap` | `format!`/`io::Error` в `r2o_quic_http3.rs`/`quic_replay.rs` | **P** | C пишет текст в переданный буфер, молча выходит при `!err||cap==0`; Rust возвращает `io::Error`/`String`, вызывающий логирует. Контракт «назвать причину» тот же, тексты/владение иные. |
| `now_ms` | 226-236 | 11 | `CLOCK_MONOTONIC`, fallback `gettimeofday`, мс | `std::time::Instant`/`Duration` | **P** | C сначала `clock_gettime(CLOCK_MONOTONIC)`, иначе `gettimeofday`; Rust `Instant` монотонен и не имеет fallback. Единицы/точность пересчитываются, отдельной функции нет. |
| `crypto_put` | 243-251 | 9 | кусок CRYPTO по offset: обрезка по `CRYPTO_BUF`, карта `seen`, `high` | quinn/rustls CRYPTO-поток | **P** | C принимает перекрытия/дыры, копирует до 16 КиБ, отмечает `seen`, двигает `high`; Rust пересборку CRYPTO ведёт rustls/quinn, собственной карты и предела 16 КиБ в коде нет. |
| `crypto_ready` | 254-258 | 5 | длина непрерывного префикса CRYPTO | quinn/rustls | **P** | C идёт по `seen` до первой дыры; Rust отдаёт готовые handshake-сообщения через rustls. Функционально эквивалентно, API иной. |
| `build_ack` | 265-274 | 10 | ACK: largest, delay=0, 0 диапазонов, first=0 (один пакет) | quinn ACK-генератор | **P** | C собирает ACK по одному диапазону (`FR_ACK`, largest, 0, 0, 0); quinn строит ACK по своим диапазонам/задержке. Для одного пакета байты совпадают, для нескольких — нет. |
| `seal_level` | 281-350 | 70 | запечатать пакет уровня: Initial/Handshake long header + token, APP short header; padding в тело; `d2k_qw_seal`; `next_pn++` | quinn packet builder/`r2k_quic_initial_build` | **P** | **C-ветви проверены:** нет ключей → error; APP: padding тела до `pn_len+blen>=4` (RFC 9001 §5.4.2), заголовок `0x40` + DCID; long: тип Initial/Handshake, предварительный `d2k_qw_long_hdr_token` для `pad_to`, padding внутри тела, повторная сборка заголовка, Retry-token для Initial; `d2k_qw_seal`, трассировка, инкремент PN. Rust Initial собирает `r2k_quic_initial_build` для 1200-байтного v1, остальные пакеты/PN/паддинг — quinn. Побайтового паритета long/short header нет. |
| `send_level` | 352-363 | 12 | запечатать и отправить датаграмму, `tx_dgrams++` | quinn `send_datagram` | **P** | C `seal_level` + `send`, ошибка → -1, счётчик `tx_dgrams`; Rust отправляет через quinn/`UdpSocket`, счётчики берёт из quinn stats (`r2o_quic_http3_datagrams`). |
| `tp_put_int` | 367-374 | 8 | TP: id varint, длина varint, значение varint | quinn `TransportConfig` (внутренние TP) | **P** | C вручную пишет три varint; Rust TP задаёт `quinn::TransportConfig`, кодирование внутри quinn. Собственной функции нет. |
| `tp_build` | 380-403 | 24 | TP: idle 30000, max_udp 1452, max_data 1 МиБ, bidi_local/remote/uni 256 КиБ, streams bidi/uni 16, CID limit 2, initial_source_connection_id; расширение 0x0039 | quinn defaults (своего `TransportConfig` в `r2o_quic_http3.rs`/`quic_replay.rs` нет) | **P** | **Подтверждённое расхождение:** C собирает ровно этот набор (`quicconn.c:383-396`) и вставляет как расширение `0x0039`; R2O не вызывает `quinn::TransportConfig`, поэтому действуют умолчания quinn (иные idle timeout/окна/лимиты потоков). Влияет на flow control, число потоков и бюджет data-stage. |
| `tp_server_parse` | 418-453 | 36 | разбор серверных TP: 0x04 max_data, 0x06/0x07 sdata, 0x08/0x09 streams; неизвестные по длине; значение только ровно-varint | quinn transport params | **P** | **C-ветви проверены:** цикл `id,len`, `len>n-i` → return, `d2k_qw_varint_read(p+i,len)` и `vw==len` — только тогда число; 0x04/0x06/0x07/0x08/0x09 заполняют `peer_*` и `*_set`; неизвестные пропускаются по `len`. Rust значения TP живут внутри quinn; C-поля `peer_streams/sdata/max_data` наружу не выставляются, сопоставление значений не сделано. |
| `tp_server_ee` | 460-473 | 14 | найти 0x0039 в EncryptedExtensions: общая длина, тип/длина расширений, границы | quinn/rustls | **P** | C разбирает `total`, `while end-p>=4`, `et/el`, `el>end-p` → return, 0x0039 → `tp_server_parse`; Rust EncryptedExtensions обрабатывает rustls/quinn, отдельного разбора 0x0039 в коде контроллера нет. |
| `frames_in` | 479-696 | 218 | кадры: PADDING/PING/ACK/ACK_ECN, CRYPTO, NEW_TOKEN, HANDSHAKE_DONE, NEW_CONN_ID+retire, MAX_DATA/MAX_STREAMS, RETIRE/DATA_BLOCKED/STREAMS_BLOCKED, MAX_STREAM_DATA/STREAM_DATA_BLOCKED/STOP_SENDING, RESET_STREAM, PATH_*, CONNECTION_CLOSE, STREAM (off/len/fin), flow credit/app_rx | quinn frame layer | **P** | **C-ветви проверены:** ACK/ACK_ECN читает largest/delay/cnt/first+диапазоны+ECN, обновляет `largest_acked`; CRYPTO `crypto_put`; NEW_TOKEN пропуск; HANDSHAKE_DONE; NEW_CONN_ID читает seq/retire_prior_to/CID+16-байтный токен, при `ret>0` меняет `dcid`; MAX_DATA/MAX_STREAMS только увеличивают; RETIRE/DATA_BLOCKED/STREAMS_BLOCKED читают один varint; MAX_STREAM_DATA/STREAM_DATA_BLOCKED/STOP_SENDING — два; RESET_STREAM — три; PATH_* — 8 байт; CONNECTION_CLOSE — код/тип/причина, `closed=1`, возврат -1; STREAM — sid/off/len/fin, кредит половины окна (`fc_stream_limit`/`fc_conn_limit`), `app_rx` для своего потока, прочие в `rx_other`. Rust всё это делает quinn; собственных полей/точной политики кредита нет. |
| `recv_dgram` | 702-815 | 114 | poll `wait_ms`, recv, RTT от `sent0`, разбор нескольких пакетов, выбор уровня, Retry, смена peer CID, open, ACK due, `rx_pkts`, frames | quinn datagram receive | **P** | **C-ветви проверены:** `poll` 0/-1/EINTR; `recv` ≤2048; `rx_wire_bytes/rx_dgrams`; первый RTT `now-sent0`; цикл по пакетам `d2k_qw_hdr_parse`; short→APP, Initial/Handshake/RETRY; Retry проверяет `retry_count==0`, `!peer_cid_fixed`, версию, DCID=наш SCID, непустой SCID/токен, SCID≠ODCID, `d2k_qw_retry_verify`, сохраняет DCID/токен и возвращает 2; пакет без ключей пропускается; `d2k_qw_open` с largest_rx; первый long header фиксирует peer SCID как DCID; `ack_due`, `rx_pkts++`, `frames_in`. Rust приём/уровни/Retry/PN — quinn; собственных `level`/`crypto_rx` нет. |
| `crypto_frame` | 820-829 | 10 | CRYPTO-кадр: тип, offset, length, байты | `quic.rs:1085 append_crypto_frame` | **E** | **Совпадает:** `FR_CRYPTO`, varint offset, varint len, проверка `o+n<=cap`, копия. Rust `append_crypto_frame` тот же формат; владелец `r2k_quic_initial_build`, RFC-тест Initial. |
| `first_flight` | 836-892 | 57 | DCID/SCID/priv/random 8/8/32/32, X25519 pub, Initial key client+server, TP, CH (SNI IP→NULL, session_id 0, ALPN h3, extra TP, pad_to), transcript, CRYPTO frame | `quic.rs:261-335 r2k_quic_initial_build` + `quic_replay.rs:98-136` | **P** | **C-ветви проверены:** `dcid_len=scid_len=8`, random, `initial_scid`/`odcid`, X25519 base, `d2k_qw_initial_secret` client/server + keys, `tp_build`, CH opts (SNI NULL для IP, `session_id_len=0`, ALPN `h3`, `extra=tp`, `pad_to`), transcript=CH, `crypto_frame(0)`. **Rust:** `r2k_quic_initial_build` принимает готовый CH (обычно донорский профиль) и строит v1 Initial; сборки CH из SNI+TP+ALPN и `d2k_qc_first_initial`-API нет, data-stage идёт через rustls/quinn. |
| `prepare_retry` | 898-926 | 29 | Retry: новый SCID 8, сброс уровней, Initial keys из DCID Retry, `peer_cid_fixed=0`, `retry_count=1` | quinn Retry | **P** | C проверяет `retry_pending`, `retry_count==0`, DCID; генерирует новый SCID, обнуляет `lv`, выводит Initial key client/server из DCID Retry, сбрасывает `peer_cid_fixed`, ставит `retry_count=1`; quinn обрабатывает Retry внутри, C-полей/API нет. |
| `d2k_qc_first_initial` | 928-954 | 27 | calloc `d2k_qc`, `first_flight` (CH+TP), seal Initial ровно 1200, отдать байты | `quic.rs:261-335 r2k_quic_initial_build` | **P** | **Подтверждённое расхождение:** C собирает CH из SNI+TP (`d2k_t13_ch_build`) и запечатывает ровно 1200; Rust `initial_build` принимает готовый CH (обычно профиль) и запечатывает 1200 v1. Сборки CH+TP и API `d2k_qc_first_initial` в R2O нет. |
| `d2k_qc_connect` | 966-1286 | 321 | сокет/марка/свежий порт, first_flight, multi-datagram form, first_send, Initial/Retry, ServerHello/EE/Cert/Finished, ACK, app keys, Finished; cert только по имени; PTO 333×2; классификация отказа | `quinn::Endpoint::connect`, `r2o_quic_http3.rs:889-916` | **P** | **C-ветви проверены:** `first_flight`; family по `:`; `use_fd` или свежий порт (`d2k_udp_port_claim`, удержание до 3); mark/connect; `getsockname`; multi-datagram form (CH режется на `form->n` CRYPTO-кадров, pn 0..n-1, общий DCID) или один Initial 1200; `first_send` перед первым Initial; deadline 5000; PTO 333 мс с удвоением до 3; Retry; ServerHello→handshake keys; EE→`tp_server_parse`; Certificate→`d2k_t13_cert_name_ok` (только имя); ACK на каждый уровень; Finished→app keys+свой Finished; отказ по `Initial.rx_pkts`/`Handshake.rx_pkts` (`:1269-1282`). **R2O-отличия:** rustls `with_root_certificates(roots)` → `QuicClientConfig` → `quinn::ClientConfig`; проверяется цепочка/имя webpki, handshake **рвётся** при mismatch; `TransportConfig` нет (quinn defaults); multi-datagram form/`first_send`-путь не портированы; отказ — текст quinn; `peer_name` нет. HTTP/3 stage-дифференциал сверяет исход, не handshake-байты. |
| `qc_no_sigpipe` | 956-964 | 9 | `SO_NOSIGPIPE` на macOS, иначе 0 | `MSG_NOSIGNAL`/std/quinn | **P** | C ставит `SO_NOSIGPIPE`, если есть, иначе no-op; Rust на Linux полагается на `MSG_NOSIGNAL`/std, quinn не выставляет SIGPIPE. Платформенный хелпер, отдельной функции нет. |
| `d2k_qc_peer_name` | 1430-1430 | 1 | результат проверки имени сертификата (`-1/0/1`) | нет (quinn/webpki) | **N** | C заполняет `peer_name` из `d2k_t13_cert_name_ok` и **продолжает** handshake при чужом имени; R2O `with_root_certificates(roots)`/webpki проверяет цепочку и имя и **рвёт** handshake при mismatch; в `R2oQuicHttp3Result` (`r2o_quic_http3.rs:217-234`) полей `name_ok`/`peer_name` нет. TCP-дифференциал `tls13` этот QUIC-путь не покрывает. |
| `d2k_qc_stream_send` | 1288-1375 | 88 | проверка peer streams/sdata/max_data; want_stream и сброс rx; STREAM len+fin; last_app для PTO 300 мс | quinn `SendStream` | **P** | **Совпадает:** запись STREAM len+fin, учёт stream_id, проверка лимитов. **C-ветви проверены:** для клиентских потоков `count=(sid>>2)+1`, `peer_streams[uni]`, `peer_sdata[uni]`; `peer_max_data`; двунаправленный `(sid&3)==0` → `want_stream`, сброс `rx_*`/`app_rx`; кадр `FR_STREAM_LO|0x02|fin`, sid/len/байты; `last_app` + `app_pto_ms=now+300`, `app_tries=0`. **Отличия:** quinn делает retransmit/flow control сам, отдельных полей результата нет. |
| `d2k_qc_stream_recv` | 1377-1423 | 47 | буфер rx_data, recv 50 мс, повтор last_app по PTO, ACK + MAX_DATA/MAX_STREAM_DATA при половине окна | quinn `RecvStream` | **P** | **Совпадает:** чтение потока, ACK, расширение кредита. **C-ветви проверены:** отдаёт из `rx_data` до `cap`; `until`; `recv_dgram` кусками ≤50 мс; при пустом `rx_len` повтор `last_app` (`app_tries<3`, `300<<tries`); ACK + `FR_MAX_DATA`/`FR_MAX_STREAM_DATA` при `credit_due`; сброс флагов после отправки. **Отличия:** quinn управляет окнами/retransmit сам; точные пороги half-window и `last_app` не сопоставлены. |
| `d2k_qc_app_progress` | 1425-1428 | 4 | `d2k_qw_ranges_bytes`/`ranges_complete` по диапазонам ответа | `r2o_quic_http3.rs:278 app_bytes_load` | **P** | C считает уникальные байты и FIN-покрытие по `d2k_qw_ranges`; Rust — счётчик app-байт counted-stream, `complete` из `recv_data`/trailers. Семантика «разные байты/целиком» различается. |
| `d2k_qc_rx_wire_bytes` | 1431-1431 | 1 | принятые байты | `r2o_quic_http3.rs:1280 wire_bytes` | **P** | C `rx_wire_bytes` считает байты `recv`; Rust `wire_bytes` берёт из quinn stats. Точка/момент учёта иные. |
| `d2k_qc_datagrams` | 1432-1435 | 4 | счётчики tx/rx датаграмм | `r2o_quic_http3.rs:1272 datagrams` | **P** | C `tx_dgrams/rx_dgrams`; Rust quinn stats. Счётчики функционально те же, API/точка учёта иные. |
| `d2k_qc_handshake_done` | 1436-1436 | 1 | завершён ли handshake | quinn `Connection` | **P** | C флаг `handshake_done` из кадра `HANDSHAKE_DONE`; Rust `R2oQuicHttp3Result.handshake_confirmed` из quinn. |
| `d2k_qc_rtt_ms` | 1437-1437 | 1 | RTT рукопожатия, мс | quinn `stats().rtt` | **P** | C измеряет первую датаграмму после первого Initial; quinn считает RTT по своей модели. |
| `d2k_qc_dgrams` | 1438-1441 | 4 | tx/rx датаграммы | `r2o_quic_http3.rs:1272` | **P** | То же, что `d2k_qc_datagrams`; C дублирует геттер. |
| `d2k_qc_outbound` | 1443-1452 | 10 | последний отправленный PN, largest_acked и признак ACK | quinn stats | **P** | C `next_pn-1`, `have_acked/largest_acked`; quinn stats дают sent/acked, отдельного API с теми же полями нет. |
| `d2k_qc_ping` | 1454-1458 | 5 | послать PING | quinn keep-alive/`ping` | **P** | C `FR_PING` через `send_level(APP)`; Rust HTTP/3 использует keep-alive/PING quinn, отдельной функции нет. |
| `d2k_qc_fd` | 1459-1459 | 1 | fd сокета | quinn (нет публичного fd) | **P** | C отдаёт fd; quinn не публикует дескриптор, доступ не нужен. |
| `d2k_qc_local` | 1461-1468 | 8 | локальный IPv4/порт (IPv4 только при family 4) | `quinn::Connection::local_ip` | **P** | C `local_addr/port`, для IPv6 `ip4` зануляется; quinn отдаёт `local_ip`, порт — из сокета/соединения. |
| `d2k_qc_local_addr` | 1470-1476 | 7 | локальный адрес 16, family, порт | `quinn::Connection::local_ip` | **P** | C копирует 16 байт/семейство/порт; Rust `local_ip` не даёт порт в том же API. |
| `d2k_qc_release` | 1478-1484 | 7 | отдать fd, не закрывая, освободить структуру | нет (fd не вынимается) | **P** | C `fd=c->fd; c->fd=-1; qc_dispose; return fd`; Rust сокет принадлежит quinn/`Drop`, отдельного «отдать fd» нет. |
| `d2k_qc_close` | 1486-1490 | 5 | закрыть fd и освободить | `quinn::Connection::close`/Drop | **P** | C `close(fd)` + `qc_dispose`; Rust закрывает quinn-соединение и сокет через RAII. |

## core/ipfrag.c (8 функций)

Сборка IPv4/IPv6 UDP-фрагментов по 4 формам (прямой/обратный порядок, 3 фрагмента с перекрытием), контрольные суммы. Порт: `crates/r2k-core/src/wire.rs:294 build_udp_fragments_with_capacity`, `:380 udp_fragment_cuts`. Дифференциал: `crates/r2k-core/tests/ipfrag.rs::d2o_ipfrag_builder_matches_r2o_on_ipv4_ipv6_shapes` (C-оракул `tests/d2o_ipfrag_oracle.c`).

**Прочитано построчно: 8/8 функций, 129 строк C (1–129).** Сверено с `wire.rs:294-420` (`build_udp_fragments_with_capacity`, `udp_fragment_cuts`): shape 1..4, `first=8/16`, `reverse=shape>1`, `three` при 3/4, `second=32/48`, перекрытия 8, выравнивание `&~7`, проверки `total>65515`/`total<=24`/`off3`; IPv4-заголовок 20 байт, ID/checksum, IPv6 48 байт, flow/tc/hop/id. C-оракул `tests/ipfrag.rs:239` сравнивает offsets/lengths и байты IPv4/IPv6 для shape 1..4.

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

**Прочитано построчно: 5/5 функций, 123 строки C (1–123).** Сверено с `stun.rs:1-172`: тип 0x0001/0x0101, `0x2112a442`, 12-байтный txid, XOR порта `^ (magic>>16)`, IPv4 `^ magic`, IPv6 ключ `magic‖txid`, обход атрибутов с padding 4 и отказ на длине за границей — совпадают. **Отличие API:** C `d2k_stun_request` сам генерирует txid (`d2k_t13_random`, отказ при ошибке); Rust `binding_request(txid)` принимает готовый `[u8;12]` — генерация и обработка ошибки у вызывающего. Для валидного txid байты запроса/ответа совпадают. Rust дополнительно имеет `is_binding_request`/`is_binding_response_for`/Discord-сигнатуры, которых в `stun.c` нет.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `rd16` | 19-21 | 3 | big-endian u16 | `stun.rs:161 read_u16` | E | хелпер; владелец `d2k_stun_parse_response`, тесты stun |
| `rd32` | 23-25 | 3 | big-endian u32 | `stun.rs:168 read_u32` | E | хелпер; тесты stun |
| `d2k_stun_request` | 27-45 | 19 | Binding request: type 0x0001, magic, random txid | `stun.rs:18 binding_request` | **P** | **Отличие владения txid:** C генерирует 12 байт внутри через `d2k_t13_random` и возвращает 0 при ошибке; Rust принимает готовый `[u8;12]` от вызывающего. Для валидного txid байты запроса совпадают; тест `parses_rfc5769...`/`recognizes_only...` проверяет разбор, не генерацию. |
| `parse_xor_mapped` | 52-83 | 32 | XOR-MAPPED IPv4/IPv6 (port ^ magic>>16, IP ^ key) | `stun.rs:133 parse_xor_mapped` | E | test `parses_rfc5769_xor_mapped_v4_and_v6_addresses` |
| `d2k_stun_parse_response` | 85-123 | 39 | проверка типа/magic/txid, обход атрибутов с padding | `stun.rs:28 parse_binding_response` | E | tests `rejects_foreign_and_malformed...`, `...exact_transaction_id` |

## core/voice.c (14 функций)

Голосовой зонд Discord: цели из nf_conntrack, STUN-опрос с приманками, вердикты clear/blocked/no_udp/flaky/unmeasured. В R2O: `r2o-controller/src/voice_targets.rs` (разбор целей) и `voice_measure.rs` (`r2o_measure_voice`, `r2o_ask_voice`, `r2o_evaluate_voice`, `r2o_search_voice_arms`). Тесты: unit `voice_measure.rs` (15+ сценариев), `test-voice-list-differential.sh`, Discord voice differentials.

**Прочитано построчно: 14/14 функций, 671 строка C (1–671).** Сверено с `voice_targets.rs:1-171` (поле/парсер/порты/сортировка) и `voice_measure.rs:141-267,352-597` (`r2o_measure_voice`, `r2o_evaluate_voice`, `r2o_voice_observation`, `r2o_search_voice_arms`, `r2o_resolve_voice_control`, `r2o_ask_voice_with_arm`). Константы совпадают: `REPEATS=3` (`R2O_VOICE_REPEATS`), `MAX_REPEATS=8`, `SILENT_AFTER=4`, контроль `stun.cloudflare.com:3478`, 3 blob'а × копии `1/6`. **Отличия:** `voice_resolve` C `strtoul` без проверки хвоста (Rust `rsplit_once`+strict `u16`+первый IPv4), `d2k_voice_targets` C `strtoul/strtol` также без хвоста (Rust `parse::<u16>/<i32>` strict, `saturating_add`), `voice_blob_load` C читает файлы/`D2K_FAKE_DIR` (Rust compile-time profiles, `active_discord_udp=None`), `send_one` C plan-send vs Rust raw engine, `voice_ask_real` N. Остальные ветви/вердикты совпадают с unit-тестами.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `is_voice_port` | 42-47 | 6 | входит ли порт в голосовые диапазоны: 50000-50099, 1400, 3478-3481, 5349, 19294-19344 | `voice_targets.rs:161-167 r2o_is_voice_port` | E | Ровно те же диапазоны; тест `voice_targets.rs:182` (границы/50100/tcp/private) + `test-voice-list-differential.sh`. |
| `field_val` | 65-82 | 18 | найти `name=value` на границе слова (начало строки или пробел), значение до space/nl/tab, C-предел 64 байта | `voice_targets.rs:131-148 r2o_field` | E | C: `strstr`, `p==line || p[-1]==' '`, `p[nl]=='='`, конец по ` `,`\n`,`\t`, `len>=64 → NULL`. Rust: `find`, та же граница, конец по `char::is_whitespace`, предела 64 нет (строка ≤2047). Для полей conntrack короче 64 байт совпадает; тесты `:182,199` + `test-voice-list-differential.sh`. |
| `d2k_voice_targets` | 84-167 | 84 | разбор nf_conntrack: udp, публичный dst, voice-порт, агрегация, сортировка | `voice_targets.rs:17 r2o_parse_voice_targets`, `:26 r2o_read_voice_targets` | **P** | `test-voice-list-differential.sh` + 7 unit-тестов парсера проверяют валидные строки. **Подтверждённое отличие:** C `dport/sport/packets` разбирает `strtoul/strtol` без проверки хвоста (принимает `50000abc`, `+50000`, ведущие пробелы); Rust `parse::<u16>()`/`parse::<i32>()` строгий. C `packets` приводит к `int` с возможным переполнением, Rust `saturating_add`. Для нормального conntrack результат совпадает. |
| `send_one` | 173-203 | 31 | UDP-сокет, mark, STUN 20 байт; с приманкой — `d2k_voice_arm_plan` + `d2k_udp_plan_send`, иначе send | `voice_measure.rs:608-780 r2o_ask_voice_with_arm` | **P** | **Подтверждённое отличие:** C отправляет приманку через **plan-send** (`d2k_voice_arm_plan`/`d2k_udp_plan_send`) на обычном UDP-сокете; Rust собирает raw-пакеты через `r2o_datapath::engine::decide` + `RawSocket::send_packet`. Байты/копии могут совпадать, но путь отправки и отметка иные. Тесты `отправляет_копии_приманки...`, `соединённый_udp_оракул...`. |
| `ms_since` | 205-209 | 5 | мс с момента | `Instant::elapsed` | P | хелпер |
| `voice_ask` | 214-297 | 84 | параллельные STUN-запросы, poll, RTT, tally | `voice_measure.rs:608 r2o_ask_voice_with_arm`, `:600 r2o_ask_voice` | E | tests `три_ответа...`, `частичный_ответ...`, `местная_ошибка...`, `voice_poll_interruption...` |
| `voice_resolve` | 299-321 | 23 | последнее `:`, host<256, `strtoul` порта (без проверки хвоста), getaddrinfo AF_INET, первый адрес | `voice_measure.rs:581-599 r2o_resolve_voice_control` | **P** | **Подтверждённое отличие:** C `strtoul(colon+1,NULL,10)` принимает `123abc`, `+123`, ведущие пробелы и молча берёт префикс; Rust `parse::<u16>()` строгий, отвергает хвост/0/пустой host. Для валидного `host:port` результат совпадает; `voice_resolve` также не проверяет, что `colon` — последний (берёт `strrchr`). |
| `voice_blob_load` | 323-340 | 18 | dir → `D2K_FAKE_DIR` → `/opt/d2k/files/fake`, чтение cap, отказ на лишний байт/ошибку/`got<16` | `voice_measure.rs:485 r2o_search_voice_arms` (compile-time profiles) | **P** | C читает файлы во время замера и требует `got>=16`; Rust `R2O_VOICE_ARM_PROFILES` — встроенные `Option<&[u8]>` (3 профиля), файлового пути/`D2K_FAKE_DIR`/проверки «лишний байт» нет. Набор профилей/копий (1,6) совпадает. |
| `voice_alive` | 349-360 | 12 | состояние потока: answers/silent/young/unseen | `voice_measure.rs:553 r2o_voice_observation` | E | tests `ответный_флаг...`, `молодой_поток...`, `ответы_на_живом_потоке...` |
| `voice_ask_real` | 365-365 | 1 | вернуть указатель на voice_ask | нет (прямой вызов) | N | C-API function pointer не нужен/не портирован |
| `voice_ask_arms` | 371-399 | 29 | перебор 3 blob'ов × 1/6 копий | `voice_measure.rs:485 r2o_search_voice_arms` | E | test `непринятая_приманка_не_меняет_вердикт...` |
| `say_reason` | 403-408 | 6 | записать reason | `voice_measure.rs` reason string | P | текст не сверяется |
| `add_reason` | 410-417 | 8 | дописать reason | `voice_measure.rs` reason string | P | текст не сверяется |
| `d2k_voice_run` | 434-671 | 238 | полный вердикт: control resolve → targets → выбор потока (исключая контроль) → discovery → alive (answers/young/silent) → direct STUN → control → arms/no_udp/blocked, либо unseen → direct → clear/flaky/no_oracle | `voice_measure.rs:141-248 r2o_measure_voice`, `:352-483 r2o_evaluate_voice`, `:553-579 observation`, `:485-515 search_arms` | E | **C-ветви проверены:** `ctl_resolved`; выбор flow по `o.ip/o.port` и `flow_port_a/b` (forward/reverse), исключение IP контроля; нет flow → `NO_CALL`; discovery; `alive`: `ANSWERS→CLEAR`, `SILENT→direct STUN` (3/3 CLEAR, 1-2 FLAKY, err UNMEASURED), `YOUNG→UNMEASURED`; контрол: local err/unasked/`NO_UDP`/`BLOCKED`+arms; `UNSEEN→direct` (3/3 CLEAR, 1-2 FLAKY, 0 `NO_ORACLE`); `marked`. **Rust:** `r2o_measure_voice` (control/targets/select/discovery/observation) + `r2o_evaluate_voice` (те же ветви, ask через `r2o_ask_voice_with_arm`); 15+ unit-тестов вердиктов; CLI-дифференциала нет. |

## core/voice_discovery.c (7 функций)

Discord IP Discovery обход: разбор/сборка 20-байтового STUN-префикса в тексте плана, 3 обмена Discovery, поиск границы обрыва, подтверждение префиксом. В R2O: `r2o-controller/src/voice_discovery.rs` (`r2o_voice_discovery_prefix_from_plan_text`, `r2o_voice_arm_plan_text`, `r2o_search_discovery_endpoint`, `r2o_evaluate_r2o_discovery`). Дифференциалы: `r2o-discord-discovery-differential.sh`, `test-discord-voice-discovery-arm-differential.sh`.

**Прочитано построчно: 7/7 функций, 159 строк C (1–159).** Сверено с `voice_discovery.rs:3` (`R2O_DISCOVERY_EXCHANGES=25`), `:8-37` (arm-plan/prefix), `:475-515` (probe/search), `:566-668` (25 обменов, prefix через `engine::decide`+`RawSocket`, проверка `is_discord_ip_discovery_response`), `:728-800` (`evaluate_r2o_discovery`).

| C-функция | строки | размер | назначение | R2O-аналог (file:line/символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `nibble` | 16-21 | 6 | hex-цифра | `plan_text.rs:668 hex_nibble` | E | Хелпер; владелец `d2k_voice_discovery_prefix`, тесты плана. |
| `d2k_voice_discovery_prefix` | 22-39 | 18 | ровно `d2k-plan 1 1\nid <32hex>\nproto udp voice\npayload 1 <40hex>\npoison 1\nfake…\norder forward\npace 15000\n`; проверка 8-байтного STUN-заголовка | `voice_discovery.rs:26-37 r2o_voice_discovery_prefix_from_plan_text` | **P** | **Подтверждённое отличие формата:** C принимает только точный `d2k-plan` с фиксированной длиной/id/хвостом и проверяет байты `00 01 00 00 21 12 a4 42`; Rust компилирует **любой** `r2o-plan` (`compile_text`+`Plan::parse`), требует ровно один payload 20 байт, `is_binding_request`, затем сравнивает с пересобранным `r2o_voice_arm_plan` (id подменяется). C-текст `d2k-plan` Rust-парсером не принимается, и наоборот. Unit/Discovery-дифференциал. |
| `d2k_discovery_response` | 41-48 | 8 | 74 байта: `[0,2,0,70]`, SSRC, `p[72]\|p[73]`, NUL-терминированный IPv4 в p+8..72 | `r2k-core/src/stun.rs:89-107 is_discord_ip_discovery_response` | E | C и Rust одинаково проверяют длину/тип/SSRC/ненулевой порт/наличие NUL и `parse::<Ipv4Addr>`; тест `stun.rs:112`. |
| `milliseconds` | 49-53 | 5 | монотонное время | `Instant` | P | Хелпер. |
| `discovery_probe` | 54-99 | 46 | 25 обменов: свежий 12-байтный txid/SSRC, первый с prefix, poll/recv 3 с, проверка SSRC, стоп на первом неответе | `voice_discovery.rs:505-668 r2o_probe_discovery_endpoint` | **P** | **Совпадает:** 25 обменов, свежий txid/SSRC на каждый, `[0,1,0,70]`, первый запрос с STUN-prefix, ожидание 3 с, проверка `is_discord_ip_discovery_response`, стоп при отсутствии ответа. **Отличие:** C первый запрос с prefix отправляет через `d2k_voice_arm_plan`/`d2k_udp_plan_send` на том же UDP-сокете; Rust — `engine::decide`+`RawSocket::send_packet` (две посылки, пауза `delay_us`), обычные — UDP-сокетом. `r2o-discord-discovery-differential.sh`. |
| `local_failure` | 102-109 | 8 | `probes += sent`, `!marked→marked=0`; ошибка/непомеченный → UNMEASURED | `voice_discovery.rs:475-481 r2o_probe_shape_is_valid`, `:728-746 evaluate` | P | Ветка есть в `evaluate_r2o_discovery` (`local_error||!marked → Unmeasured`); отдельной функции нет. |
| `d2k_voice_discovery_search` | 110-159 | 50 | known prefix → 1 проба; 3 direct-пробы (0 ответов → continue, 25 → clear, cutoff, несовпадение → flaky); 3 prefix-пробы (25 → blocked+arm) | `voice_discovery.rs:484-501 r2o_search_discovery_endpoint`, `:728-800 evaluate_r2o_discovery` | E | C и Rust: known prefix (25 → Clear), direct 0 → Continue, 25 → Clear, cutoff, 3 повтора с `sent==cutoff+1` иначе Flaky, 3 prefix-пробы по 25 → Blocked+prefix. Дифференциалы Discovery + arm. |

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

**Прочитано построчно: 12/12 функций, 266 строк C (1–266).** Подтверждённые отличия: C печатает `d2k-plan`, Rust — `r2o-plan`/структурный Plan; `d2k_quic_delay_plan` (`d2k-plan 1 6 … delay 15000`) **не имеет продюсера** в R2O (есть только разбор/применение и тестовая фикстура); `d2k_quic_arm_plan`/`compose_plan`/`question_plan` разложены на `discovery_candidates` + `plan::apply`, побайтового differential текста нет. Voice-план (`payload/fake/order/pace 15000`) совпадает и покрыт `test-controller-udpplan-differential.sh`.

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

**Прочитано построчно: 8/8 функций, 190 строк C (1–190).** **Подтверждённые отличия:** C `udp_raw_prepare` на Linux **требует `IP_NODEFRAG`** и без него отказывает; в `r2o-datapath/src/raw.rs` есть только `IP_HDRINCL`/`IPV6_HDRINCL`/`SO_MARK`, `IP_NODEFRAG` отсутствует. C `d2k_udp_plan_send` читает TTL/hoplimit, собирает пачку, шлёт фрагменты raw, восстанавливает TTL и возвращает -2 на ECONNREFUSED; контроллерного API в R2O нет — проводное поведение разнесено по `plan::apply`/`wire::build_udp_fragments`/`raw.rs`, без get/set/restore TTL и без батча.

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

**Прочитано построчно: 19/19 функций, 732 строки C (1–732).** Сверено с `r2o_volume.rs` (286 строк: partial/pair/repeat/evidence), `fetch.rs:1397-1796` (RX-пробы и фолбэк), `:1799-1958` (TX-лестница), `:2531-2601` (X-Pad, HEAD, drain), `:3017-3126` (`connect_target`/`connect_marked`), `main.rs:3197-3220` (композиция TX+RX). Константы совпадают: `D2K_VOL_STEPS=10`/`R2O_VOLUME_TX_STEPS=10`, `CHUNK=4000`, `MIN_KB=12`, `CHUNK_DELAY=50 мс`, connect/handshake 8000 мс, RTT-таймаут `clamp(3×RTT,1500,12000)`. `fill_pad` — тот же алфавит 62 символа и fallback `i*31+7` (E). `d2k_volume_rx_evidence` — E, построчный порт с тестами. **Отличия:** `d2k_vol_verdict_name` — «цель»/«мишень»; `connect_bounded`/`drain_head_*` — C byte-loop/TCP_NODELAY/restore vs Rust `connect_target`/HTTP-парсер; `resource_retry_path` не вынесен; `measure_response_volume`/`probe_response_volume`/`d2k_volume_probe_path` покрыты e2e, не все ветки (third probe/resource retry/short-preserve) имеют C/Rust differential.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `rx_wire_partial` | 58-64 | 7 | partial-обрыв внутри TLS-записи: HANDSHAKE, name_ok, status=0, !replay, !local_limit, TLS 0x0303/0x0304, `rx_tls_record_missing`, wire≥12 КиБ | `r2o_volume.rs:136-145 r2o_volume_rx_wire_partial` | **E** | Условия совпадают поле в поле: `stage==Handshake`, `name_valid`, `status==0`, `!replay_proof`, `!local_limit`, `negotiated_tls ∈ {0x0303,0x0304}`, `rx_tls_record_missing`, `rx_tls_wire_bytes >= R2O_VOLUME_MIN_BYTES`. C `uint32` недобора → Rust `bool`; для предиката эквивалентно. Тесты `tests/r2o_volume.rs` (wire-partial кейсы). |
| `d2k_volume_rx_partial` | 66-72 | 7 | partial = wire-partial или 2xx identity-тело: incomplete, framing valid, ровно один из CL/chunked, body≥12 КиБ, CL>bytes | `r2o_volume.rs:68-77 r2o_volume_rx_partial` | **E** | C и Rust повторяют одну формулу: `wire_partial || (2xx && !complete && encoding==Identity && framing_valid && has_length != chunked && body_bytes>=12 КиБ && (!has_length || expected>bytes))`. Тесты `tests/r2o_volume.rs:49+`. |
| `d2k_volume_rx_pair_agrees` | 78-83 | 6 | обе partial, один домен; wire — совпадение версии TLS, body — совпадение CL/chunked | `r2o_volume.rs:80-97 r2o_volume_rx_pair_agrees` | **E** | Ветви совпадают: обе partial; если wire-домен различается → отказ; в wire-домене `negotiated_tls` равны; в body-домене `body_has_length` и `body_chunked` равны. Тесты `tests/r2o_volume.rs:49,63,96`. |
| `d2k_volume_rx_needs_repeat` | 103-109 | 7 | a partial, b — полный 2xx framing-valid ≥12 КиБ | `r2o_volume.rs:112-122 r2o_volume_rx_needs_repeat` | **E** | C: `!partial(a) || partial(b) → 0`, затем b 2xx, complete, framing valid, bytes≥12 КиБ. Rust те же четыре условия через `partial(a) && !partial(b)`. Тесты `tests/r2o_volume.rs`. |
| `d2k_volume_rx_evidence` | 111-213 | 103 | wire-evidence (два partial + меньший завершённый gzip) или body-evidence (два identity-обрыва + gzip; байтовый/пакетный бюджет), reason | `r2o_volume.rs:125-274 r2o_volume_rx_evidence` (`:147-188 wire`, `:190-274 body`) | **E** | Ветви сверены. Wire: оба wire-partial, одна версия TLS, gzip Application/name_ok/!local_limit/2xx/complete/framing/Gzip/body>0/wire>0/!missing/wire меньше обоих, разброс ≤4 КиБ; `cut_kb=mid/1024`, `cut_packets=min`. Body: оба 2xx identity incomplete framing-valid ≥12 КиБ, одинаковые CL/chunked, ровно один framing-вид, CL>bytes, разброс ≤4 КиБ; gzip 2xx framing-valid Gzip body>0; при незавершённом gzip — все пакеты>0 и разброс ≤3; reason-строки дословно те же. Тесты `tests/r2o_volume.rs:50,75,80,91`. |
| `d2k_vol_verdict_name` | 215-222 | 8 | русское имя вердикта: CUT/PASSED/SHORT, иначе UNREACHABLE | `fetch.rs:486-493 R2oFetchVolumeTxVerdict::r2o_label` | **P** | `Cut`/`Passed`/`Short` совпадают дословно; C default — «мишень не ответила», Rust `Unreachable` — «цель не ответила». Отдельной функции с C-семантикой и теста имени нет. |
| `now_ms` | 226-236 | 11 | `CLOCK_MONOTONIC`, fallback `gettimeofday`, мс | `std::time::Instant`/`Duration` | **P** | C сначала `clock_gettime(CLOCK_MONOTONIC)`, иначе `gettimeofday`; Rust `Instant` монотонен и не имеет fallback. Единицы/точность пересчитываются, отдельной функции нет. |
| `nap_ms` | 230-235 | 6 | sleep мс | `std::thread::sleep` | P | Хелпер; те же паузы 500/50 мс заданы константами `R2O_VOLUME_RX_PROBE_GAP`/`R2O_VOLUME_TX_CHUNK_GAP`. |
| `clamp_ms` | 237-241 | 5 | clamp `int64` в `[lo,hi]` | `Ord::clamp` | P | Хелпер; R2O `saturating_mul(3).clamp(1500,12000)` (`fetch.rs:1942-1945`). |
| `fill_pad` | 247-257 | 11 | 4000 байт из `/dev/urandom`, алфавит `A-Za-z0-9`, fallback `i*31+7` | `fetch.rs:2545-2560 r2o_volume_padding` | **E** | Посимвольно совпадает: тот же алфавит 62 символа, тот же fallback `(index as u8)*31+7`, тот же размер `R2O_VOLUME_TX_CHUNK_BYTES=4000`; тест X-Pad (`fetch.rs:4428-4435`). C читает `fgetc` по байту, Rust — `read_exact`. |
| `connect_bounded` | 259-322 | 64 | IPv4/IPv6, TCP_NODELAY, SO_NOSIGPIPE (где есть), SO_MARK при mark≠0, nonblock connect+poll 8000, SO_ERROR, восстановление flags | `fetch.rs:3017-3126 connect_target/connect_marked` | **P** | **Совпадает:** IPv4/IPv6 через `SocketAddr`, `effective_mark` игнорирует 0, SO_MARK, TCP_NODELAY, nonblock connect, poll до 8 с, SO_ERROR, возврат в блокирующий режим. **Отличия:** C ставит `SO_NOSIGPIPE` (где есть) и восстанавливает **исходные** `fcntl` flags; Rust создаёт `SOCK_NONBLOCK|SOCK_CLOEXEC`, затем `set_nonblocking(false)`, а `SO_NOSIGPIPE` не ставит. Ошибка метки у C — текст и `-1`, у Rust — `ConnectTargetError::local_refusal`. В unmarked-ветке `TcpStream::connect_timeout` TCP_NODELAY ставится позже в TX-лестнице (`fetch.rs:1826`). |
| `drain_head_tls` | 325-349 | 25 | побайтово до пустой строки через TLS, дедлайн wait_ms, буфер строки 4096 | `fetch.rs:2562-2601 r2o_drain_head_response` + `HttpResponseParser::new(true)` | **P** | C читает по 1 байту через TLS и считает пустой строкой `\n` при `n==0` или `\r\n`; `line[4096]` только для подсчёта, переполнение молча не сохраняется. Rust кормит `HttpResponseParser` блоками 4096 и требует валидную HTTP-строку/заголовки; на мусоре C может вернуть успех, Rust — `InvalidData`. Для корректного HEAD результат тот же. |
| `drain_head_plain` | 351-375 | 25 | то же для открытого TCP: poll+recv по 1 байту, дедлайн | `fetch.rs:2562-2601` тот же парсер | **P** | C `poll(POLLIN)`+`recv` по байту; Rust — `read` блоками через `HttpResponseParser`. Пустая строка и дедлайн те же по смыслу; C не валидирует статус/заголовки и не имеет лимита строки, Rust валидирует и имеет лимит 64 КиБ заголовков. |
| `resource_retry_path` | 393-406 | 14 | первый resource с host==SNI без регистра, `d2k_resource_path_ok`, путь ≠ текущего, длина < cap | `fetch.rs:1608-1615` (выбор в RX), `:1539-1545` (fallback path) | **P** | Предикат совпадает: `host.eq_ignore_ascii_case(name)`, `r2o_resource_path_ok`, `path != options.path`. C дополнительно отсекает `strlen(path)>=cap` (фиксированный буфер), Rust хранит `String`. C вызывает выбор внутри `measure_response_volume` и возвращает 1; Rust — в `r2o_fetch_measure_rx_volume_with_roots_and_phase_timeout`/fallback. Адресного differential на выбор нет. |
| `rx_probe` | 411-427 | 17 | probe 6 с; повтор, если (status=0 или ранний 2xx <12 КиБ) и HANDSHAKE/name_ok/TLS 0x0303 или 0x0304/!local_limit/!partial; пауза 500 мс | `fetch.rs:1447-1474 r2o_fetch_rx_probe`, `:1493-1503 needs_repeat` | **P** | R2O: 6 с (`R2O_D2O_VOLUME_RX_TIMEOUT`), те же условия `status==0 || early_success`, `name_valid`, TLS-версия, `!local_limit`, `!rx_partial`, пауза 500 мс. **Отличия:** C дополнительно требует `level==HANDSHAKE`; Rust не проверяет `stage` (для `status==0` стадия и так Handshake, для раннего 2xx — Application, т.е. ветвь C недостижима). C `early` = 2xx && !complete && body<12 КиБ, Rust то же. C при ошибке probe возвращает нулевую структуру, Rust возвращает `Err`. |
| `measure_response_volume` | 440-552 | 113 | identity-1; 2xx complete → direct_complete+resources; partial → identity-2; при расхождении — identity-3; gzip; evidence; при полном <12 КиБ — resource-retry; `measured_path` | `fetch.rs:1644-1796 r2o_fetch_measure_rx_volume_once`, `:1592-1642` retry | **P** | **Совпадает:** identity-1/2/3, порог 12 КиБ, gzip, evidence, `measured_path` при evidence, паузы 500 мс. **Отличия:** (1) C `rx_tls_unavailable = level==TRANSPORT && status==0`; Rust выставляет его только если ошибка начинается с «TLS-рукопожатие не завершилось:» (`:1666`), поэтому отказ TCP даёт `rx_tls_unavailable=false`; (2) C копирует `resources` только для complete 2xx не-Blocked/Legal, Rust хранит `first` и ищет resource позже; (3) C `rx_short` при `status>0 && complete && body<12 КиБ`, Rust `short_bytes` — то же, но reason-тексты иные; (4) C считает `rx_unmeasured` по `level==HANDSHAKE` и `!direct`, Rust — `needs_repeat && !direct && !rx_tls_unavailable` (без stage); (5) C возвращает 1 при найденном retry-пути, Rust возвращает структуру, повтор делает внешняя функция. E2E-дифференциал покрывает rx-volume, не все ветки third/retry. |
| `probe_response_volume` | 558-593 | 36 | один повтор по resource-path: сохранить `rx_short_bytes`, очистить short/unmeasured, 500 мс, повторить; если повтор `tls_unavailable`/`unmeasured` — восстановить short | `fetch.rs:1592-1642` (retry внутри RX), `:1509-1557` (внешний fallback) | **P** | **Подтверждённое расхождение:** C восстанавливает `rx_short` при `(rx_tls_unavailable || rx_unmeasured) && !rx_cut && !rx_short` (`volume.c:578-583`); Rust — только при `r2o_retry.rx_tls_unavailable && evidence.is_none() && short_bytes.is_none()` (`fetch.rs:1622-1630`), без `rx_unmeasured`. C-повтор берёт путь из `resources` первого ответа и вызывает `measure_response_volume(..., NULL, 0)`; Rust — `r2o_fetch_measure_rx_volume_once` с clone options. Reason-префикс «повтор по …» есть в обоих. |
| `d2k_volume_probe_path` | 595-727 | 133 | connect 8 с; TLS1.3/1.2 8 с; 10×HEAD: шаг 0 без X-Pad, шаги 1..9 X-Pad 4000; read-timeout=clamp(3×RTT,1500,12000); gap 50 мс; ошибка шага: i=0 UNREACHABLE, ≥12 КиБ CUT, иначе SHORT; полный проход PASSED; после (не plain) — RX | `fetch.rs:1799-1958 r2o_fetch_measure_tx_volume`, `main.rs:3197-3220 r2o_discovery_measure_volume` | **P** | **Совпадает:** 8 с connect/8 с handshake, 10 шагов, X-Pad с шага 1, 4000 байт, 50 мс, `at_kb=i*4000/1024`, порог 12 КиБ, read-timeout `clamp(3×RTT,1500,12000)`, PASSED=40 КиБ. **Отличия:** (1) C `plain` — отдельный аргумент; Rust `plain` только `options.port==80`; (2) C `host = sni || ip`, Rust `options.name` (validate требует непустое имя); (3) C хранит `rtt_ms`, Rust — `elapsed` всего замера; (4) C на ошибке TLS/запроса/шага всё равно вызывает `probe_response_volume`, Rust TX-функция RX не вызывает — композиция в `main.rs:3204-3218` запускает RX отдельно, кроме port 80 и «нет TCP к»; (5) C ведёт TLS byte-loop, Rust rustls+парсер; reason-тексты иные. Единого C/Rust differential на все ветки нет. |
| `d2k_volume_probe` | 729-732 | 4 | обёртка `probe_path(..., path=NULL)` | `fetch.rs:1799` + `main.rs:3197` | **P** | C `path=NULL` отключает выбор retry-пути и `measured_path`; в R2O `options.path` всегда задан (по умолчанию `/`), поэтому эквивалента «без пути» нет. Обёртка как отдельная функция отсутствует. |

## core/include/d2k_http_reply.h (6 функций)

Inline-классификация HTTP-ответа: 451/2xx/3xx-портал, тело с маркерами РКН/порталов. Порт: `r2o-controller/src/fetch.rs:2836 r2o_fetch_http_outcome`, `:2873 r2o_fetch_portal_location`, `:2916 r2o_fetch_body_has_portal`, `:2906 r2o_fetch_ascii_contains`. Отдельного differential на эту функцию не найдено; используется в page/verify-дифференциалах.

**Прочитано построчно: 6/6 функций, 87 строк C (1–87).** Сверено с `fetch.rs:2836-2943` (`r2o_fetch_http_outcome`, `r2o_fetch_portal_location`, `r2o_fetch_ascii_contains`, `r2o_fetch_body_has_portal`, `r2o_fetch_http_host_char`) и тестами `fetch.rs:3486-3526`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_http_lower` | 9-11 | 3 | ASCII lower: только `A-Z → +32`, остальные без изменений | `fetch.rs:2910-2914 r2o_fetch_ascii_contains` (`eq_ignore_ascii_case`), `:2941-2943 is_ascii_alphanumeric` | **E*** | static-хелпер; отдельной функции нет. `eq_ignore_ascii_case` в Rust сворачивает обе стороны по ASCII, C — только haystack; все C-вызовы передают нижний регистр, поэтому результат совпадает. Тесты `fetch.rs:3486-3524` (`Access Blocked By RKN`, `WARNING.RT.RU`). |
| `d2k_http_equal` | 12-16 | 5 | регистронезависимое сравнение n байт: lower(`p[i]`) vs `word[i]` без lower | `fetch.rs:2910-2914`, `:2929 eq_ignore_ascii_case` | **E*** | C не приводит `word` к нижнему регистру; все production-вызовы передают `http://`, `https://`, имена порталов и `access blocked by rkn` в нижнем регистре — эквивалентно. При верхнем регистре в `word` C вернул бы 0, Rust совпал бы; такого вызова нет. Тесты те же. |
| `d2k_http_hostchar` | 17-21 | 5 | lower, затем `a-z`, `0-9`, `_`, `.`, `-` | `fetch.rs:2941-2943 r2o_fetch_http_host_char` | **E*** | Rust `is_ascii_alphanumeric() || matches!(_ . -)`; `is_ascii_alphanumeric` включает `A-Z`, что после C-lower эквивалентно. Границы проверены `eais.rkn.gov.ru` vs `xnot-eais.rkn.gov.ru` (`fetch.rs:3508-3522`). |
| `d2k_http_portal` | 22-26 | 5 | список 6 порталов по индексу: eais, lawfilter, blackhole, warning.rt, warn.beeline, deny.megafon | `fetch.rs:2898-2905` и `:2917-2924` (два inline-массива, тот же порядок) | **E*** | C-функция возвращает `hosts[i]` без проверки `i<6`; все циклы C идут `i<6`. Rust не имеет доступа по индексу, но оба потребителя (`r2o_fetch_portal_location`, `r2o_fetch_body_has_portal`) содержат те же 6 имён в том же порядке. Тесты `warning.rt.ru`/`eais.rkn.gov.ru`. |
| `d2k_http_location_portal` | 27-52 | 26 | host портала из Location: `http://`/`https://`/`//`, конец по `/ ? #` и `<=0x20`, последний `@`, числовой порт, хвостовая точка, 6 имён без регистра | `fetch.rs:2873-2908 r2o_fetch_portal_location` | **E** | Ветви совпадают: те же три префикса, конец authority по `/ ? #` или `byte<=0x20` (NUL тоже), `rposition('@')`, последняя `:` с непустыми цифрами, `strip_suffix('.')`, точное сравнение с 6 именами `eq_ignore_ascii_case`. Тест `fetch.rs:3490-3502`: `https://user@WARNING.RT.RU.:443/blocked` → Blocked, `https://warning.rt.ru.evil.example/` → Neutral, `/login` → Positive. |
| `d2k_http_reply_classify` | 55-86 | 32 | HTTP 451→LegalDenial; 2xx/304→Positive; 301/302/303/307/308→Blocked(портал)/Positive(относительный `/x`)/Neutral; 4xx/5xx identity→Blocked по фразе или порталу в теле; иначе Neutral | `fetch.rs:2836-2871 r2o_fetch_http_outcome` | **P** | **Исходы совпадают, теряется `evidence`.** C возвращает `{outcome, evidence}`: `"HTTP 451"`, имя портала или `"access blocked by rkn"`; `verify.c:1286` копирует его в `r->http_evidence`, `:1292` — в reason «HTTP отказ: …». Rust возвращает только enum, строки-доказательства нет; `http_evidence` в `R2oFetch...` отсутствует. Сами ветви идентичны: тесты `fetch.rs:3486-3526` (451, 302 портал/evil/relative, 403 фраза/портал, граница `total>len` 15/16, non-identity, `xnot-eais`). |

## core/include/d2k_ip6frag_send.h (9 функций)

Отправка IPv6-пакетов с фрагментацией через AF_PACKET: netlink route/neigh, MTU, MAC, SO_MARK, кеш 1 с. В R2O есть `r2o-datapath/src/raw.rs` (`RawSocket`: AF_INET/AF_INET6 IPPROTO_RAW, SO_MARK, route/MTU, IPv4/IPv6 UDP-фрагментация), но он в датапате, а не в контроллере; ручной neighbor-резолв заменён ядром.

**Прочитано построчно: 9/9 функций, 206 строк C (1–206).** Сверено с `raw.rs:34-224` (`RawSocket`), `:270-357` (maxlen/MTU), `:484-550` (`r2o_route_mtu`), `:559-651` (разбор пакетов/фрагментов), `r2o_route.rs:679-803` (netlink-запрос/разбор), `r2k-core/src/wire.rs:294-420` (`build_udp_fragments`). `AF_PACKET` в production R2O отсутствует (только тест `raw6_differential.rs`), `IP_NODEFRAG`/`IPV6_NODEFRAG` — grep пуст.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_ip6frag_sender_init` | 34-36 | 3 | `memset` sender, `fd=-1` | `raw.rs:48-93 RawSocket::open` (RAII) | **P*** | Отдельной init/reset нет: `RawSocket` создаётся только `open`, fd принадлежит `OwnedFd`, поля `family/mark/maxlen/egress_mtu/route_mtu_cache` инициализируются конструктором. |
| `d2k_ip6frag_sender_close` | 37-40 | 4 | `close(fd)`, повторный init | `OwnedFd` Drop | **P*** | RAII: `RawSocket` не имеет `close`, дескриптор закрывается `Drop`; повторного использования структуры после close в R2O нет. |
| `d2k_f6_now` | 41-45 | 5 | `CLOCK_MONOTONIC` в мс, 0 при ошибке | `std::time::Instant` | **P*** | C возвращает 0 при сбое `clock_gettime`; Rust `Instant` не ошибается, единицы пересчитываются. Хелпер. |
| `d2k_f6_attr` | 46-55 | 10 | rtattr: `NLMSG_ALIGN`, `RTA_LENGTH`, проверка `at+RTA_ALIGN<=cap`, запись и обновление `nlmsg_len` | `r2o_route.rs:691-707 r2o_route_lookup_request` | **P** | C — общий хелпер с проверкой ёмкости и `EMSGSIZE`; Rust вручную собирает **один** `RTA_DST` с фиксированными NLA-заголовком/выравниванием, без generic-хелпера и без `RTA_SRC`/`RTA_MARK`. |
| `d2k_f6_query` | 56-72 | 17 | AF_NETLINK/SOCK_RAW/NETLINK_ROUTE, `SO_RCVTIMEO` 200 мс, sendto/recvfrom, `nl_pid==0`, восстановление errno | `r2o_route.rs:283-371` (`r2o_open_watch`, `r2o_drain_watch`) | **P** | R2O держит постоянный watch-сокет для правил/маршрута по умолчанию (`r2o_open_watch`), а не открывает сокет на каждый запрос; таймауты/цикл чтения иные. Контроллерного вызова `d2k_f6_query`-аналога нет. |
| `d2k_f6_route` | 73-106 | 34 | RTM_GETROUTE IPv6: `RTA_DST`+`RTA_SRC`+`RTA_MARK`, `dst_len=src_len=128`; NLMSG_ERROR, RTM_NEWROUTE, `RTN_UNICAST` или `RTN_LOCAL`, `RTA_OIF`, `RTA_GATEWAY`; иначе ENETUNREACH | `r2o_route.rs:691-708 r2o_route_lookup_request`, `:774-803 r2o_route_parse_lookup` | **P** | **Подтверждённые отличия:** Rust-запрос содержит только `RTA_DST` (`:700-706`) и `dst_len=probe.len()*8`, без `RTA_SRC`/`RTA_MARK`/`src_len=128`; разбор принимает только `RTN_UNICAST` (без `RTN_LOCAL`), извлекает `RTA_OIF`/`RTA_MULTIPATH`, но **не `RTA_GATEWAY`**. C-путь нужен AF_PACKET/MAC; R2O-путь — только ifindex для MTU/egress. |
| `d2k_f6_neighbor` | 107-154 | 48 | RTM_GETNEIGH dump: AF_INET6/ifindex, NUD_REACHABLE/STALE/DELAY/PROBE/PERMANENT, `NDA_DST`+`NDA_LLADDR`, 64 батча/200 мс, EHOSTUNREACH | нет функции; резолв делегирован ядру | **P** | Осознанная замена: R2O шлёт через `IPPROTO_RAW`, ядро само резолвит neighbor; `r2o_route_mtu` использует UDP-connect/`IP_MTU` (`raw.rs:484-550`). Ручной `RTM_GETNEIGH`/MAC и AF_PACKET-путь не портированы; это не N, потому что отправка закрыта ядром. |
| `d2k_ip6frag_prepare` | 155-195 | 41 | проверка IPv6+Fragment header и точной длины; кеш 1 с по `fd/mark/src/dst`; `d2k_f6_route`; AF_PACKET/SOCK_DGRAM/ETH_P_IPV6; SO_MARK; if_up/MTU/MTU≥1280; HWADDR; neighbor для Ether !NOARP; иначе loopback/pointopoint/noarp; сохранение src/dst/mark/expires | `raw.rs:48-93 RawSocket::open`, `:484-550 r2o_route_mtu`, `:622-651 ipv6_udp_fragment`, `r2k-core/src/wire.rs:294-324 build_udp_fragments` | **P** | **Подтверждённые отличия:** (1) R2O `RawSocket` — `AF_INET/AF_INET6` + `IPPROTO_RAW` + `IP_HDRINCL`/`IPV6_HDRINCL`, **не AF_PACKET**; (2) нет ручного neighbor/MAC, `sockaddr_ll`, `SIOCGIFHWADDR`; (3) нет sender-кеша `fd/mark/src/dst` на 1 с — есть кеш route-MTU 16 записей (`raw.rs:359-371`); (4) MTU берётся из `r2o_pick_maxlen`/`r2o_select_egress_mtu` с полом 576 (`R2O_RAW_MTU_FLOOR`), проверки `MTU>=1280` в prepare нет; (5) `IP_NODEFRAG`/`IPV6_NODEFRAG` отсутствуют, поэтому AF_INET6/LOCAL_OUT может дефрагментировать IPv6-фрагменты — AF_PACKET-путь это исключал. Фрагменты строит `build_udp_fragments`, валидирует `ipv6_udp_fragment`. |
| `d2k_ip6frag_send` | 196-204 | 9 | prepare; блокирующий `sendto` AF_PACKET sockaddr_ll; EINTR-повтор; точная длина; при ошибке `expires=0`, при короткой отправке `EIO` | `raw.rs:147-223 RawSocket::send_packet/send_packet_inner` | **P** | **Совпадает:** EINTR-повтор (`:207`), проверка точной длины (`:198-204`). **Отличия:** C — блокирующий AF_PACKET `sendto`, R2O — `sendto(MSG_DONTWAIT)` на `IPPROTO_RAW`; при `EAGAIN/ENOBUFS` C ждёт, R2O возвращает ошибку и учитывает `busy`; C сбрасывает кеш при любой ошибке, R2O при `EMSGSIZE` понижает route-MTU/maxlen (`:208-219`), а не сбрасывает кеш. |

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

**Прочитано построчно: 9/9 inline-функций, 930 строк заголовка C (1–930).** Сверено с `r2k-core/src/quic.rs:31-63 r2k_quic_data_judge`, `r2o_quic_http3.rs:543-687` (`R2oQuicHttp3Budget`, `R2oQuicHttp3Stall`), `:1003-1195,1284-1322` (вызовы budget/stall), `quic_replay.rs:417-430 r2o_quic_trial_data_verdict`, `:433-445 r2o_quic_short_control_data_verdict`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_quic_arm_data_judge` | 454-461 | 8 | handshake/status/bytes/complete → NO_HANDSHAKE/CUT/PASS | `quic.rs:31-63 r2k_quic_data_judge` (это `judge3`) | **P** | **Подтверждённое расхождение:** C: `!handshake→NO_HANDSHAKE`; `status<=0 или 451→CUT`; `complete или bytes>=32768→PASS`; иначе CUT. Rust — 8-аргументный `judge3`; при простых значениях (`stalled=false, need_complete=false, headers_too_long=false, budget_ok=false`) он даёт `status==0` → `NotRun`, `status>0` без complete и bytes<32768 → `NotRun`. C-тесты `test_quic_arm_data.c:319` (`1,0,3000,1→CUT`) и `:321` (`1,0,32768,0→CUT`) с Rust дали бы `NotRun`. Production `quicprobe.c:1577` вызывает `judge(0,0,0,0)` (NoHandshake) и `verify.c:2127` проверяет только `==PASS`, поэтому pass/fail там совпадает; контракт функции — нет. |
| `d2k_quic_arm_data_judge_limited` | 466-470 | 5 | `handshake && status<=0 && headers_too_long→NOT_RUN`, иначе простой judge | `quic.rs:31-63 r2k_quic_data_judge` | **P** | Rust `judge3` содержит `status==0 && headers_too_long→NotRun` (`:56-58`), но: (1) при `status==0` **без** `headers_too_long` C даёт `CUT`, Rust — `NotRun`; (2) при `status>0`, неполном ответе и bytes<32768 C даёт `CUT`, Rust — `NotRun`. C-тест `test_quic_arm_data.c:328` (`1,0,3000,0,0→CUT`) расходится. Функция используется только C-тестами (`:326-332`), production идёт через простой judge/judge3. |
| `d2k_qstall_init` | 523-535 | 13 | stall: RTO=max(3×RTT,1000), отметки прогресса | `r2o_quic_http3.rs:600-615 R2oQuicHttp3Stall::r2o_initialize` | **E** | Совпадает: `rto=max(3*rtt,1s)`, `last_progress_at=now`, `probe_at=None`, `wire_at_probe=wire`, `probe_packet_number=None`, `unanswered=0`; C `prog_seen/wire_seen` = Rust `progress_seen/wire_seen`. Rust добавляет только счётчики `probes_sent/probes_acked`. Тесты `r2o_quic_http3.rs:1435-1518` (PN-ACK, одновременный рост, STALLED/ONEWAY). |
| `d2k_qstall_sent` | 540-543 | 4 | запомнить PN отправленного PING | `r2o_quic_http3.rs:617-620 R2oQuicHttp3Stall::r2o_sent` | **E** | C `probe_pn=pn; probe_pn_set=1`; Rust `probe_packet_number=Some(pn); probes_sent+=1`. Номер и признак «PING ушёл» эквивалентны; тесты `:1437-1455`. |
| `d2k_qstall_step` | 545-584 | 40 | GOING/PROBE/STALLED/ONEWAY по прогрессу/ACK/RTO | `r2o_quic_http3.rs:622-686 R2oQuicHttp3Stall::{r2o_capture_ack,r2o_step}` | **E** | Ветви совпадают: обновление `wire_seen`; рост progress → reset/GOING; при `probe_at=None` и `now-last_prog>=rto` → PROBE с `wire_at_probe`; `acked>=probe_pn` закрывает вопрос; после RTO без PN → повторный PROBE; `unanswered>=2` → `wire_seen!=wire_at_probe ? ONEWAY : STALLED`. **Отличие порядка:** Rust вызывает `r2o_capture_ack` до проверки progress, C — после; при одновременном ACK+росте Rust увеличит `probes_acked`, C просто сбросит `probe_pn_set`. Действие в обоих случаях GOING; влияет только на счётчик. Тесты `:1435-1518`. |
| `d2k_qbudget_init` | 616-620 | 5 | need=2×budget, 0→25 | `r2o_quic_http3.rs:548-563 r2o_quic_http3_budget_datagrams/R2oQuicHttp3Budget::r2o_initialize` | **E** | C `need = 2u*(budget_pk?budget_pk:25)` в `unsigned` (переполнение по модулю 2³²); Rust `packets.wrapping_mul(2)` возвращает `u32`, затем `u64::from` — для `u32::MAX` оба дают `4294967294`. `prog_mark=0/marked=0` ↔ `progress_mark=None`. `test-quic-budget-init-differential.sh` (0/1/25/u32 max). |
| `d2k_qbudget_ok` | 626-631 | 6 | `pkts>=need`, отметить `prog`, затем `status>0 && prog>mark && now-last_prog<rto` | `r2o_quic_http3.rs:565-584 R2oQuicHttp3Budget::{r2o_mark,r2o_step}` | **E** | C и Rust: при `pkts>=need` отметка ставится один раз (`prog_mark`/`progress_mark.get_or_insert`); затем `status>0 && progress>mark && now.saturating_duration_since(last_progress)<rto`. `d2o_quic_http3_differential.c` + full-stage. |
| `d2k_qbudget_grew` | 637-639 | 3 | `ok(..., now=0, last_prog=0, rto=1)` — без проверки свежести, только `pkts>=need && status>0 && prog>mark` | нет отдельной функции; `R2oQuicHttp3Budget::r2o_mark` + ручная проверка | **P** | **Подтверждённый пробел:** C `grew` всегда считает свежесть истинной (`0-0<1`) и возвращает `status>0 && prog>prog_mark`; используется production-вызовом `verify.c:1871` для короткого контроля. В R2O `r2o_mark` только ставит отметку и ничего не возвращает, а `r2o_step` требует `now/last_progress/rto` и проверяет свежесть. Отдельного `grew`-режима нет; `r2o_quic_short_control_data_verdict` (`quic_replay.rs:433-445`) берёт готовый `budget_passed` из основного этапа, а не повторяет C-правило. |
| `d2k_quic_arm_data_judge3` | 641-652 | 12 | judge3: handshake/451/complete/budget/stalled/headers/need_complete/bytes | `quic.rs:31-63 r2k_quic_data_judge`, `quic_replay.rs:417-430 r2o_quic_trial_data_verdict` | **E** | Порядок и условия совпадают: `!handshake→NoHandshake`; `451→Cut`; `status>0 && complete→Pass`; `status>0 && budget_ok && !stalled→Pass`; `stalled→Cut`; `status==0 && headers_too_long→NotRun`; `!need_complete && status>0 && bytes>=32768→Pass`; иначе `NotRun`. C `status<=0` ↔ Rust `status==0` (Rust `u16`, отрицательных нет). `d2o_quic_http3_differential.c` (judge3) + full-stage. |

## core/include/d2k_arm.h (1 функция)

**Прочитано построчно: 1/1 функция, 91 строка C (1–91).** Сверено с `main.rs:6292-6317 r2o_discovery_measured_split_plan` и `scripts/r2o-measured-split-differential.sh` (донор закреплён на `a378e230…`).

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_arm_segment` | 78-83 | 6 | размер сегмента ARM: `send_cap==0 → 1400`; `send_cap<=72 → 0`; иначе `min(send_cap-72,1400)` | `main.rs:6307-6312` (`segment`, внутри `r2o_discovery_measured_split_plan`) | **E** | Формула эквивалентна: `send_cap==0 → 1400`, иначе `send_cap.saturating_sub(72).min(1400)`; при `send_cap<=72` получается 0, и план не строится (`(segment > 0).then(...)`), как C возвращает 0. `scripts/r2o-measured-split-differential.sh` сравнивает C/Rust для `send_cap` 0/1492/1280/100/72, split 0/1/1024 и verdict prefix/whole; C-сторона — `d2k_tcp_split_plan`/`d2k_arm_segment`. |

## Углублённая сверка: udpplan.c и udpruntime.c (20 функций)

**Прочитано построчно: 20/20 функций, 456 строк C (`udpplan.c` 1–266, `udpruntime.c` 1–190).** Сверены: сборщики quicsplit/ipfrag/udplen/fake/ttl/copies/voice/«нет воздействия», проверки arm/props, `d2k_udp_plan_build` (TLV → apply → >1 payload/IPID_ZERO/фрагменты/ORIG_PASS), raw-sink `AF_INET/SOCK_RAW/IPPROTO_RAW` + `IP_HDRINCL`/`IP_NODEFRAG`/`SO_MARK`, IPv6-frag sender, TTL/hoplimit get/set/restore, `ECONNREFUSED → -2`.

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

**Прочитано построчно: 12/12 N-функций; тела прочитаны по указанным строкам, отсутствие аналогов в `crates/` подтверждено поиском.**

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
- **`d2k_quic_props_findings` (`quicprobe.c` 2275–2324):** текстовые
  выводы по split/2 datagrams/v2/fixed bit/port для журнала
  (`sched.c:11506`). В R2O есть имена кандидатов (`quic_replay.rs:628`),
  но нет функции выводов. N — диагностический текст.
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
- **`remember_live_failure` (`httpsearch.c` 522–552):** C хранит
  addr/binding/execution/request_ms и лимиты байт. `HttpSearchRecord`
  (`main.rs:4468-4472`) содержит только `cut/repeat_path/repro_gap`;
  `HttpLiveFailures` (`main.rs:4457-4460`) — только `programs/evidence_lost`
  и строится из `failed_http_programs` (`main.rs:4594-4634`, каталожные
  привязки), а не из живых отказов. N — HTTP-search state.

Raw-UDP (`udp_raw_*`, `d2k_udp_plan_send`) после проверки — **P**:
`IP_HDRINCL`/`IPV6_HDRINCL`/`SO_MARK` есть (`raw.rs:75,77,80`), но
`IP_NODEFRAG` отсутствует, mark обязателен, socket TTL get/set/restore
и `ECONNREFUSED → -2` не портированы. `d2k_vol_verdict_name` — P:
`r2o_label` содержит те же состояния, отличается только «цель»/«мишень».

## Классификация N (12 функций)

**Прочитано построчно: 12/12 N-функций; классификация причин сверена с телами и R2O-структурами.**

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
