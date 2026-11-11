# Пофункциональный аудит паритета D2O → R2O

## Зачем этот файл

Это рабочий реестр **каждой production-функции C-кода D2O** и её состояния в R2O.
Он дополняет `functional-parity-matrix.md`: матрица отвечает за пользовательские
контракты, а здесь фиксируется, что именно из исходников D2O перенесено,
что перенесено частично и что не найдено.

## Закреплённые источники

- D2O (oracle): `/mnt/e/d2o-a378w`, SHA `a378e230947ebfd011439e1cac0f1e994d883aae`.
- R2O: `E:/r2o`, HEAD `d7b5a87971f689760ea3d061e246b54a7ae02f76` на момент среза.
- Реестр функций: `E:/r2o-tooling/audit/c-functions-a378.json` (1982 функции,
  51 328 строк тела).
- Черновая карта имён: `E:/r2o-tooling/audit/function-map-a378.json`.

## Как получен реестр

```text
python3 scripts/audit/extract_c_functions.py /mnt/e/d2o-a378w \
  /mnt/e/r2o-tooling/audit/c-functions-a378.json
python3 scripts/audit/map_functions.py \
  /mnt/e/r2o-tooling/audit/c-functions-a378.json \
  /mnt/e/r2o-tooling/audit/function-map-a378.json
python3 scripts/audit/make_slices.py
```

Сканер маскирует комментарии, строки и preprocessor-директивы, затем на
верхнем уровне ищет определения `... имя(...) {`, находит парную закрывающую
скобку и сохраняет `file`, `line`, `end_line`, `lines`, `static`, `signature` и
SHA-256 тела. В реестр входят только `core`, `datapath` и `detect`; тестовые
файлы, `planlab.c`, `ctlprobe.c`, `probe_mtproto.c`, `relay-*`, отдельный
`panel` и Telegram-донор `src/` исключены (для Telegram источником является
z2kOW, а не C11 D2O).

Повторный запуск на том же дереве даёт тот же результат:

```text
functions=1982 files=96 out=/tmp/audit-recheck.json
recheck 1982 1982 equal True
```

## Статусы

| Код | Значение | Что требуется для доказательства |
|---|---|---|
| **E** | Эквивалентно перенесено | Назван Rust-аналог и существующий differential/целевой тест, либо полный набор ветвей подтверждён тестом |
| **P** | Перенесено частично | Rust-реализация есть, но конкретные ветви/состояния/ошибки не доказаны; пробел назван |
| **N** | Не перенесено | Поиск по `crates/` не нашёл реализации; функция не является тестовым/диагностическим инструментом |
| **?** | Не установлено | Недостаточно данных в этом проходе; нельзя честно поставить E/P/N |

Статус `P` не означает «сломано»; он означает «код есть, доказательство неполное».
Статус `E` без ссылки на тест/дифференциал не ставится.

## Границы

- Аудит проверяет **поведение и состояние**, а не только совпадение имён.
- Static-хелпер может наследовать статус владеющей публичной функции, но в
  примечании обязателен владелец и указание, что именно проверено.
- Relay-enroll/relay-gate — отдельные VPS-сервисы, вне router-runtime.
- `panel` D2O — отдельный C-сервис; панель R2O написана заново, поэтому
  пофункциональный перенос C-панели не является целью этого реестра.
- Telegram: реализация взята из z2kOW; C11 `telegram/src` не является oracle
  для переноса (см. AGENTS.md).
- Отсутствие функции в R2O не всегда означает дефект: часть helper'ов
  реализована идиоматично/inlined. Это фиксируется в колонке «R2O-аналог».

## Сводка реестра

| Модуль | Функций | Строк тела | Файлов |
|---|---:|---:|---:|
| core | 1240 | 33 209 | 52 |
| datapath | 583 | 13 640 | 35 |
| detect | 159 | 4 479 | 9 |
| **Итого** | **1982** | **51 328** | **96** |

Точные суммы по файлам и группам — в отчётах ниже. Итоговые counts E/P/N/?
считаются сборщиком `scripts/audit/render_audit.py` из таблиц групп.

### Текущий прогресс (2026-11-11)

Проверены четыре группы из пяти, **1290 из 1982** функций:

| Группа | Функций | E | P | N | ? |
|---|---:|---:|---:|---:|---:|
| core-net | 548 | 220 | 311 | 16 | 1 |
| datapath-core | 400 | 120 | 270 | 10 | 0 |
| datapath-plan | 183 | 108 | 69 | 5 | 1 |
| detect | 159 | 49 | 98 | 12 | 0 |
| **Итого проверено** | **1290** | **497** | **748** | **43** | **2** |
| core-state (в работе) | 692 | — | — | — | — |

Это не оценка паритета: 748 P означают «код есть, доказательство ветвей
неполное», 44 N — в основном диагностические/CLI-функции и несколько реальных
расхождений (`SET_HTTPS` TTL, `ARM_SHAPE` UDP, `wire_udp` IPID_ZERO,
`udpruntime` raw UDP, `tls12/tls13` record-layer).


## Отчёты групп

| Группа | Функций | Отчёт | Состояние |
|---|---:|---|---|
| core-net: TLS/HTTP/ECH/QUIC/voice/verify | 548 | `docs/audit/core-net.md` | готовится |
| core-state: catalog/sched/diagnostics/link/… | 692 | `docs/audit/core-state.md` | готовится |
| datapath-core: d2kd/session/hold/udp/nfq/… | 400 | `docs/audit/datapath-core.md` | готовится |
| datapath-plan: plans/ctl/raw/route/… | 183 | `docs/audit/datapath-plan.md` | готовится |
| detect: trigger/poison/raw/classify/response | 159 | `docs/audit/detect.md` | готовится |

## Уже подтверждённые differential-контракты (контекст, не заменяет аудит)

Эти прогоны подтверждают поведение R2O на уровне модулей; в таблицах групп они
используются как доказательство только там, где функция действительно покрыта.

- ClientHello/TLS 1.2/1.3/ECH: 56 кейсов, PASS.
- TLS verify: 16/16, PASS.
- ECH RX ladder, layered RX: PASS.
- QUIC: hello/local/stop/STUN-watch, app-bytes, budget-init, short-control — PASS.
- HTTP/3 full-stage: 18/18, PASS.
- Classifier full tree/white decoy, fallback, raw profiles/connect/split — PASS.
- Живые: RuTracker 157/157 изображений, Rutor 786/786, YouTube video
  `readyState=4`, Discord `READY`, голос `RTC_CONNECTED` и RTP 26–37 мс.

## Как читать таблицы

Каждая строка — одна C-функция. Колонка «строки» — диапазон `line..end_line`
в закреплённом дереве D2O. «Размер» — число строк тела. «Назначение» —
краткое описание по телу, а не по имени. «R2O-аналог» — конкретный файл и
строка/символ; «нет» означает, что аналог не найден. «Доказательство/пробел» —
тест, дифференциал или конкретная непроверенная ветвь.

> Важно: наличие строки в таблице не является доказательством паритета.
> Доказательством является статус E с тестом либо P с явно названным пробелом.

## Итог по группам

| Группа | Функций | E | P | N | ? |
|---|---:|---:|---:|---:|---:|
| core-net | 548 | 220 | 311 | 16 | 1 |
| core-state (в работе: 332/692) | — | — | — | — | — |
| datapath-core | 400 | 120 | 270 | 10 | 0 |
| datapath-plan | 183 | 108 | 69 | 5 | 1 |
| detect | 159 | 49 | 98 | 12 | 0 |
| **Итого** | **1290** | **497** | **748** | **43** | **2** |


---

# Точечная сверка сложных функций (предварительно)

Этот файл — независимая проверка функций, у которых нет прямого совпадения по
имени. Полные таблицы групп находятся в `docs/audit/core-*.md`,
`datapath-*.md`, `detect.md`; здесь зафиксированы конкретные находки, чтобы
итоговый отчёт не опирался только на автоматическую карту имён.

| C-функция | Строки D2O | R2O-аналог | Статус | Что проверено / пробел |
|---|---:|---|---|---|
| `core/meas.c::d2k_meas` | 269–300 (32) | `r2o-controller/src/classify.rs::Tally` (992), цикл `measure` (1111), `unproven` (1225), `with_mark_status` (628) | **P** | Повтор серии, `pass/fail/errors/unproven`, AND-семантика метки и отказ при unmarked перенесены. Differential `test-classifier-*` покрывает классификатор, но отдельного C/Rust-теста именно на AND-метку серии нет. |
| `detect/response.c::d2k_resp_handshake12` | 123–209 (87) | `r2o-controller/src/response.rs::handshake` (1050), `count_handshakes` (1148), `scan12` (1248) | **P** | Legacy ClientHello без supported_versions, 65 536-байтовый предел, `ServerHelloDone`/fatal alert и подсчёт рукопожатий есть. Нужен отдельный C/Rust differential на граничный буфер и таймаут; в общем classifier-дифференциале эта функция не адресуется по имени. |
| `core/quicsnap_reseal.c::d2k_qsnap_recid` | 75–134 (60) | `r2k-core/src/quic_snapshot.rs::r2k_quic_snapshot_reseal` (79) | **E** | Перезапечатывание всех датаграмм одним новым DCID, проверка версии/старого DCID и отказ при коротком DCID. Покрыто `crates/r2k-core/tests/quic_snapshot.rs` и QUIC snapshot differential. |
| `datapath/ctlsrv.c::d2k_ctlsrv_pump` | 511–694 (184) | `r2o-datapath/src/main.rs` — журнал/события (1162, 1393 `control.send_event`), `flow_journal.rs` | **P** | События HELLO/SUSPECT/APPLIED/REFUSED и курсор `seen` перенесены в журнал/control. Нет отдельного differential на все виды событий и на потерю/переполнение журнала в этом цикле. |
| `core/crypto.c::d2k_aes128_ecb` | 167–171 (5) | QUIC header protection через `quinn-proto`/`ring`; `r2o-datapath/src/r2o_quic.rs` | **E** | Используется только для QUIC header protection (`quicwire.c:388,404`). R2O использует проверенную библиотеку; 18/18 HTTP/3 full-stage и QUIC differential проходят. Отдельного вектора AES-ECB в R2O нет, но поведение покрыто QUIC-тестами. |
| `core/x25519.c::d2k_x25519` / `d2k_x25519_base` | 119–168 (50) | `ring`/`x25519-dalek` в QUIC и ECH; `r2o-controller/src/ech.rs` HPKE (9, 22) | **E** | Секрет X25519 для QUIC initial и ECH HPKE. Покрыто QUIC full-stage, ECH-тестами и `test-ech`. |
| `core/p256.c::d2k_p256_keypair` / `d2k_p256_ecdh` | 282–316 (35) | `ring` SECP256R1 в `r2o_tls.rs` (95, 101, 288) | **N** | В production C вызовов `d2k_p256_*` не найдено — только `test_p256.c`; TLS-путь использует `ring`. Функция не является router-runtime контрактом R2O. |
| `core/httpsprobe.c::d2k_httpsprobe_done` | 430–449 (20) | `r2o-controller/src/https_probe.rs`, `response.rs::HttpsProbeState` (75) | **P** | Состояние/завершение HTTPS-пробы и кэш состояний есть; отдельного differential на `done`/persist нет. |
| `datapath/routemark.c::d2k_routemark_describe` | 327–343 (17) | `r2o-datapath/src/r2o_route.rs` (`r2o_route_mark`, 175), `netlink.rs` | **N** | Маршрутная метка/ifindex и выбор egress есть, но функции диагностического описания `describe` в R2O нет; на packet path это не влияет. |
| `core/quicconn.c::d2k_qc_dgrams` / `d2k_qc_ping` | 1438–1458 (8) | `r2o-controller/src/r2o_quic_http3.rs`, `quic_replay.rs` | **P** | Обмен датаграммами и ping/ack покрыты HTTP/3 full-stage 18/18; отдельных функций с теми же именами нет, поэтому построчная сверка ветвей не выполнена. |
| `core/quicsnap.c::d2k_qsnap_form` | 91–105 (15) | `r2k-core/src/quic_snapshot.rs::r2k_quic_snapshot_parse` (50), `R2kQuicSnapshot::datagrams` (17) | **P** | Форма снимка (n, длина датаграммы, ClientHello) восстанавливается из `quic_snapshot`; отдельного differential именно на `form` нет. |
| `datapath/nl.c::d2k_nl_errno` | 163–180 (18) | `r2o-datapath/src/netlink.rs::kernel_error` (183) | **E** | Разбор `NLMSG_ERROR` с отрицательным errno совпадает по коду; netlink-тесты и `test-nfq-*` покрывают ошибочные ответы. |
| `datapath/nl.c::d2k_nl_cfg_cmd` | 254–275 (22) | `r2o-datapath/src/netlink.rs::config_command` (219), `config_params` (234) | **E** | Заголовок `nfgenmsg`, `NLM_F_ACK`, атрибут `NFQA_CFG_CMD` и `F_FAIL_OPEN/GSO` перенесены; netns-тесты queue bind. |
| `datapath/http80.c::d2k_http80_delivered` | 267–281 (15) | `r2o-datapath/src/hold.rs::mark_http_response_answered` (239), `delivered` (276) | **P** | Учёт доставленных байт и `answered` есть; отдельного C/Rust differential на «ответ пришёл без портала» нет. |
| `datapath/http80.c::d2k_http80_swap` | 527–545 (19) | `r2o-datapath/src/main.rs` (`response_delivered`, 2086–2123), `hold.rs` | **P** | Замена ответа и отправка RST/verdict-payload реализованы в main/hold; построчная сверка состояний `ST_SWAP/ST_ANSWERED` не выполнена. |

## Вывод по точечной сверке

- Прямых «дыр» в критическом packet path не видно: QUIC/ECH/TLS-крипто
  закрыто библиотеками R2O и существующими differential-тестами.
- Основные пробелы — не отсутствие кода, а отсутствие **адресных**
  C/Rust-тестов на отдельные функции: `d2k_meas` (AND-метка серии),
  `d2k_resp_handshake12` (граница 65 536/таймаут), `d2k_ctlsrv_pump`
  (полный набор событий), `httpsprobe_done` (persist/state), `routemark_describe`.
- `d2k_p256_*` в production C не вызывается; это тестовый/резервный код,
  поэтому его отсутствие в R2O не является функциональным пробелом.

## Подтверждённые расхождения из отчёта datapath-plan

Проверено по исходникам, не только по словам агента:

- **`SET_HTTPS` TTL.** C `datapath/ctlsrv.c:446` обрезает TTL до
  `D2K_HTTPS_TTL_MAX_S`; R2O `control.rs:1070` возвращает `ACK_BAD_ARGS` при
  `ttl > MAX_HTTPS_TTL_SECONDS`. Это реальное расхождение поведения, статус P.
- **`ARM_SHAPE` транспорт.** C `datapath/ctlsrv.c:329` принимает транспорт 6 и
  17; R2O `control.rs:2002` отвергает всё, кроме 6. Для UDP/QUIC-снимков это
  может быть функциональным пробелом, статус P.
- **`d2k_plantab_shape_misses`.** В R2O поле `shape_misses` объявлено и
  читается, но не инкрементируется ни в одной ветви (`control.rs:92,166,193`);
  счётчик всегда 0. Это диагностическое расхождение, статус N.
- **`d2k_plantab_has_ech_target`.** Отдельного предиката нет; R2O собирает
  неполный ClientHello общим `capture.rs`/`engine.rs`. Поведение может быть
  покрыто, но адресного differential нет — статус `?`, не N.
- **`MAX_EMISSIONS = 26`.** Это не функциональный пробел: D2O тоже ограничивает
  выдачу 26 посылками в `datapath/session.c:2517` (`D2K_RESULT_MAX`). R2O
  отказывает раньше, в `Plan::apply`; наблюдаемый отказ совпадает, различаются
  слой и текст ошибки.


---

# Группа `core-net`

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
| `E` | 220 |
| `P` | 311 |
| `N` | 16 |
| `?` | 1 |

Доли: `E` — 40,15%, `P` — 56,75%, `N` — 2,92%, `?` — 0,18%.

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
| `read_exact` | 119-153 | 35 | дочитать n байт с дедлайном, учёт `rx_wire_bytes`/`rx_record_missing`, обработка EINTR/EOF | `fetch.rs:2464 R2oTlsTcpStream::read` + `R2oTlsRecordTracker` | P | эквивалент через `Read`+таймауты сокета; отдельная функция и точная семантика `rx_record_missing` не сопоставлены дифференциалом |
| `write_all` | 155-171 | 17 | дослать буфер с MSG_NOSIGNAL | `fetch.rs` запись через rustls `Stream` | P | эквивалент std/rustls; EINTR-ветка не воспроизведена |
| `prf` | 183-212 | 30 | TLS 1.2 PRF (HMAC-SHA256, P_hash) | rustls (внутренний TLS1.2 PRF) | P | собственной функции нет; KAT C (`test_tls12.c`) в Rust не перенесён |
| `d2k_tls12_prf_for_test` | 214-218 | 5 | тестовый экспорт PRF | нет | N | используется только `test_tls12.c:44,58`; Rust-аналога и векторов нет |
| `tr_add` | 220-225 | 6 | накопить транскрипт рукопожатия | rustls (транскрипт внутри) | P | хелпер стека; собственная функция отсутствует |
| `nonce_of` | 228-233 | 6 | nonce = salt(4)+seq(8) для GCM | rustls/ring AEAD nonce | P | хелпер record-layer |
| `aad_of` | 235-242 | 8 | AAD записи TLS 1.2 (seq/type/version/len) | rustls/ring AEAD AAD | P | хелпер record-layer |
| `send_plain` | 246-256 | 11 | отправить открытую запись | rustls `write_tls` | P | собственной функции нет |
| `send_sealed` | 258-282 | 25 | зашифровать и отправить запись (explicit nonce, seq++) | rustls `write_tls` | P | cipher suite/группы совпадают с C, но формат записи проверяется только косвенно |
| `read_record` | 287-345 | 59 | прочитать запись, распознать открытый HTTP/CCS/alert, расшифровать | rustls `read_tls` + `R2oTlsRecordTracker` | P | ключевая ветка «открытый HTTP вместо TLS» покрыта `fetch.rs`; побайтового differential нет |
| `hs_next` | 355-407 | 53 | собрать handshake-сообщения из записей, CCS/alert | rustls handshake driver | P | собственная state-machine отсутствует |
| `ch12_build` | 415-485 | 71 | собрать TLS1.2 ClientHello (2 шифра, X25519/P-256, padding до `want_wire`) | rustls ClientHello + `r2o_client_hello_wire_len` (`r2o_tls.rs:53`, `fetch.rs:157 wire_len`) | P | длина CH сверяется дифференциалом `donor_and_r2o_candidate_probes_keep_the_client_hello_wire_length` (tls13-pad), для tls12 отдельного кейса нет; набор расширений rustls шире C |
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
| `read_exact` | 102-136 | 35 | дочитать n байт с дедлайном и учётом `rx_wire_bytes`/`rx_record_missing` | `fetch.rs:2464 R2oTlsTcpStream::read` | P | эквивалент через `Read`; точная семантика счётчиков не сопоставлена |
| `write_all` | 138-154 | 17 | дослать буфер с MSG_NOSIGNAL | `fetch.rs` rustls `Stream::write_all` | P | эквивалент std |
| `put16` | 160-160 | 1 | big-endian u16 | `u16::to_be_bytes` | P | хелпер |
| `get16` | 161-161 | 1 | big-endian u16 | `u16::from_be_bytes` | P | хелпер |
| `nonce_of` | 165-170 | 6 | nonce = iv XOR seq | rustls/ring AEAD nonce | P | хелпер record-layer |
| `read_record` | 175-234 | 60 | чтение записи, CCS/alert, снятие padding, расшифровка, внутренний тип | rustls `read_tls` + `R2oTlsRecordTracker` | P | ключевая ветка «открытый HTTP вместо TLS» перенесена; побайтового differential нет |
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
| `remember_live_failure` | 520-550 | 31 | учёт живого отказа с лимитами байт | `main.rs` HttpSearchRecord | P | лимиты/флаги потерь не сопоставлены |
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
| `first_flight` | 836-892 | 57 | первый полёт: Initial + CRYPTO ClientHello | `r2k-core/src/quic.rs:261 r2k_quic_initial_build` | E | test `создаёт_аутентифицированный_quic_initial...` |
| `prepare_retry` | 898-926 | 29 | обработать Retry: новый DCID/token | quinn | P | заменено зависимостью; retry-проверка есть в `quic.rs:569` |
| `d2k_qc_first_initial` | 928-954 | 27 | публичная сборка первого Initial | `quic.rs:261 r2k_quic_initial_build` | E | RFC/unit-тесты Initial |
| `qc_no_sigpipe` | 956-964 | 9 | SO_NOSIGPIPE | `MSG_NOSIGNAL`/std | P | платформенный хелпер |
| `d2k_qc_connect` | 966-1286 | 321 | полный QUIC handshake клиента, early data, 1-RTT | `quinn::Endpoint::connect` (`r2o_quic_http3.rs`) | P | заменено quinn; end-to-end сверяется HTTP/3 stage-дифференциалом, не handshake-байтами |
| `d2k_qc_stream_send` | 1288-1375 | 88 | отправить STREAM с контролем окна | quinn `SendStream` | P | заменено зависимостью |
| `d2k_qc_stream_recv` | 1377-1423 | 47 | принять STREAM, вернуть stream_id/данные | quinn `RecvStream` | P | заменено зависимостью |
| `d2k_qc_app_progress` | 1425-1428 | 4 | прогресс app-байт/complete | `r2o_quic_http3.rs:278 app_bytes_load` | P | счётчики counted-stream, семантика иная |
| `d2k_qc_peer_name` | 1430-1430 | 1 | результат проверки имени сертификата | `fetch.rs peer_name_ok`, `response.rs:389` | E | differential `donor_and_r2o_tls_results_match_for_matching_and_mismatched_certificate_names` |
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
| `d2k_quic_delay_plan` | 205-217 | 13 | план `delay 500000` | `r2o_quic_deny.rs:203 r2o_delay` | P | директива есть, полный текст/проверки не сверены |
| `d2k_voice_arm_plan` | 219-239 | 21 | текст voice-плана с приманкой и copies | `voice_measure.rs:269 r2o_measured_voice_arm_plan_text` | E | unit `measured_voice_arm_plan_preserves_payload_copy_count_and_voice_shape` |
| `d2k_voice_plan` | 241-243 | 3 | voice-план с D2K_VOICE_DECOY_REPEATS | `voice_discovery.rs:8 r2o_voice_arm_plan_text` | E | используется `main.rs:17239`, тесты плана Discovery |
| `d2k_quic_question_plan` | 247-266 | 20 | текст плана по вопросу (udplen/split/frag/ttl/blob) | `quic_replay.rs` candidates + `r2k-core/src/plan.rs` | P | разбор вопроса в структуру есть, эмиттер текста отсутствует |

## core/udpruntime.c (8 функций)

Сборка UDP-пакета/пачки из текста плана и отправка плана с контроллера: обычным sendto для нефрагментированных, raw IP_HDRINCL/IP_NODEFRAG — для IP-фрагментов. В R2O план применяется в датапате (`r2k-core/src/plan/apply.rs`), а контроллер шлёт QUIC-датаграммы напрямую (`quic_replay.rs`) без UDP-plan runtime.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `udp_next_fragment_id` | 22-30 | 9 | потокобезопасный IP id (random seed, инкремент) | `wire.rs` (случайный id) | P | глобального счётчика нет; id выбирается случайно на сборку |
| `d2k_udp_batch_free` | 32-32 | 1 | освободить буфер пачки | RAII `Vec` | P | отдельной функции нет |
| `d2k_udp_plan_build` | 33-93 | 61 | текст → TLV → план → emissions → IPv4/IPv6 пакеты/фрагменты | `r2k-core/src/plan/apply.rs` (apply emissions) | P | применение плана есть; сборка байтовой пачки из контроллера отсутствует |
| `udp_raw_init` | 101-106 | 6 | инициализация raw-sink (IPv6 frag sender) | нет | N | raw UDP sink с IP_NODEFRAG в контроллере не найден |
| `udp_raw_close` | 107-112 | 6 | закрыть raw-sink | нет | N | то же |
| `udp_raw_prepare` | 113-130 | 18 | подготовить raw-сокет/IPv6 frag route | нет | N | то же; `raw_probe.rs` — TCP, не UDP-план |
| `udp_raw_send` | 131-139 | 9 | sendto raw IPv4/IPv6 | нет | N | то же |
| `d2k_udp_plan_send` | 147-190 | 44 | отправить план с сокета: TTL/hoplimit, задержки, фрагменты, восстановление TTL | нет (QUIC-датаграммы шлются напрямую) | N | UDP-plan runtime в контроллере отсутствует; датапат применяет план к проходящим пакетам |

## core/volume.c (19 функций)

Измерение объёма ответа: лестница HEAD с растущим X-Pad, повторные identity-пробы, gzip-контроль, evidence обрыва по объёму/пакетам. R2O: `r2o-controller/src/r2o_volume.rs` (почти построчный порт evidence), `fetch.rs` (`r2o_fetch_measure_rx_volume*`, `r2o_fetch_rx_probe`, `r2o_fetch_measure_tx_volume`). Тесты: `crates/r2o-controller/tests/r2o_volume.rs`, `d2o_verify_differential.rs` (rx-volume), `fetch.rs` unit.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `rx_wire_partial` | 58-64 | 7 | partial-обрыв внутри TLS-записи | `r2o_volume.rs:136 r2o_volume_rx_wire_partial` | E | `tests/r2o_volume.rs` (wire partial кейсы) |
| `d2k_volume_rx_partial` | 66-72 | 7 | partial по TLS-записи или телу | `r2o_volume.rs:68 r2o_volume_rx_partial` | E | `tests/r2o_volume.rs:49+` |
| `d2k_volume_rx_pair_agrees` | 78-83 | 6 | согласованы ли две partial-пробы | `r2o_volume.rs:80 r2o_volume_rx_pair_agrees` | E | `tests/r2o_volume.rs:49,63,96` |
| `d2k_volume_rx_needs_repeat` | 103-109 | 7 | нужна ли третья проба | `r2o_volume.rs:112 r2o_volume_rx_needs_repeat` | E | `tests/r2o_volume.rs` |
| `d2k_volume_rx_evidence` | 111-213 | 103 | evidence: wire/body cut, slack, пакетный бюджет, reason | `r2o_volume.rs:125 r2o_volume_rx_evidence` | E | `tests/r2o_volume.rs:50,75,80,91` |
| `d2k_vol_verdict_name` | 215-222 | 8 | русское имя вердикта | нет | N | текст не портирован |
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
- `udpruntime.c` — raw UDP-отправка планов из контроллера (`IP_HDRINCL`/`IP_NODEFRAG`) не портирована; в R2O план применяет датапат, а контроллер шлёт QUIC-датаграммы напрямую.
- `udpplan.c` — QUIC-план в R2O представлен структурой и `directives`, а не полным текстом `d2k-plan`; побайтового differential текста нет.
- `volume.c` — evidence-функции покрыты unit-тестами, но лестница HEAD/повторов и resource-retry сверяются только косвенно.
- Диагностические тексты (`props_findings`, `verdict_name`, `prop_word`, `reason`-форматы) в Rust не воспроизведены дословно — это `N`/`P`, не влияющие на сетевой datapath, но влияющие на CLI/лог-паритет.

## Классификация N (16 функций)

Не все N означают пропущенный обход. Разбивка по влиянию:

| Причина | Функции | Влияние на packet path |
|---|---|---|
| Тестовые хуки/экспорт | `d2k_tls12_prf_for_test`, `d2k_httpsearch_test_add_failures`, `d2k_httpsearch_test_add_records` | нет: существуют только под тестовой сборкой D2O |
| Диагностика/тексты/счётчики | `d2k_verify_tcp_timestamps_get`, `d2k_httpsprobe_lost`, `d2k_quic_props_findings`, `prop_word`, `d2k_vol_verdict_name` | нет: CLI/лог-паритет, не сеть |
| Серверная роль / C-API | `d2k_qw_retry_build`, `voice_ask_real` | нет: клиентский datapath не строит Retry и не отдаёт function pointer |
| Архитектурный raw-UDP/TTL | `udp_raw_init`, `udp_raw_close`, `udp_raw_prepare`, `udp_raw_send`, `d2k_udp_plan_send`, `qp_recv_ttl` | **есть риск**: R2O шлёт QUIC-датаграммы обычным UDP-сокетом, raw IP_NODEFRAG/TTL-приём не портированы; нужен differential на фрагменты/TTL |

Таким образом, реальных архитектурных пробелов в core-net — **6**, а не 16;
остальные 10 — тестовые, диагностические или серверные функции.

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


---

# Группа `datapath-core`

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


---

# Группа `datapath-plan`

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
| E | 108 |
| P | 69 |
| N | 5 |
| ? | 1 |
| **Всего** | **183** |

По файлам:

| Файл | Функций | E | P | N | ? |
|---|---:|---:|---:|---:|---:|
| datapath/plans.c | 75 | 37 | 36 | 1 | 1 |
| datapath/routemark.c | 23 | 19 | 3 | 1 | 0 |
| datapath/plan_parse.c | 17 | 14 | 3 | 0 | 0 |
| datapath/raw.c | 17 | 8 | 9 | 0 | 0 |
| datapath/plan_apply.c | 15 | 14 | 1 | 0 | 0 |
| datapath/ctl.c | 14 | 8 | 3 | 3 | 0 |
| datapath/ctlsrv.c | 12 | 6 | 6 | 0 | 0 |
| datapath/routemark_nl.c | 8 | 2 | 6 | 0 | 0 |
| datapath/include/d2k_plans.h | 2 | 0 | 2 | 0 | 0 |

---

## 1. datapath/ctl.c — 14 функций

Транспорт управляющего сокета: открытие, один пир, кольцо исходящих кадров, разбор кадров.
R2O-аналог — `crates/r2o-datapath/src/control.rs` (`ControlServer`), плюс цикл в
`crates/r2o-datapath/src/main.rs` (вызывает `poll()` напрямую, без epoll-регистрации fd).

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
| d2k_ctl_event | 217-255 | 39 | положить кадр целиком или потерять и посчитать | `control.rs:1913` `send_event`, `:2164` `enqueue` | E | `control_server_counts_each_event_without_connected_peer_as_dropped_like_d2o` (control.rs:2434); `try_send_event_...outbox...` (control.rs:2552) — переполнение. |
| d2k_ctl_poll | 257-313 | 57 | прочитать, разобрать кадры, рвать на невозможной длине | `control.rs:1883` `poll`, `:2110` `read_peer`, `:2138` `take_complete_frames` | E | Reconnect-тест читает `EVENT_PROTOCOL`; границы `FRAME_MAX` проверяются в `take_complete_frames`. |
| d2k_ctl_dropped | 315-315 | 1 | счётчик потерянных кадров | `control.rs:1983` `dropped_events` | E | `control_server_counts_each_event_without_connected_peer...` (control.rs:2434) сверяет счётчик. |
| d2k_ctl_sent | 316-316 | 1 | счётчик поставленных в кольцо кадров | — | N | Счётчика `sent` в R2O нет; есть только `dropped_events`. |

Итог по файлу: E 8, P 3, N 3. Пробелы: нет доступа к fd (listen/peer), нет счётчика
отправленных кадров, hook разрыва реализован в цикле, а не в объекте.

---

## 2. datapath/ctlsrv.c — 12 функций

Смысл команд и событий управляющего протокола. R2O: `NamePlans::handle` +
`ControlServer` (`crates/r2o-datapath/src/control.rs`), кодеки — `crates/r2k-core/src/control.rs`,
журнал событий — `flow_journal.rs` и `main.rs`.

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
| read_probe_flow | 169-187 | 19 | static: разобрать flow адресного опыта, отвергнуть неканонический IPv4 | `control.rs:1695` `r2o_udp_addr_probe_flow_key` + `r2k-core/control.rs:1701` `valid_udp_addr_probe_flow` | P | Код есть, тестов SET/DEL/FIND адресного опыта (COMMAND_*_ADDR_PROBE) в дереве не найдено. |
| d2k_ctlsrv_command | 189-509 | 321 | диспетчер команд, разбор тел, ACK, установка в таблицу | `control.rs:260` `NamePlans::handle`; `main.rs:68` `handle_control_command` (stall budgets); `control.rs:1988` `arm_client_shape` | P | Покрыты SET_NAME/BOUND/PROBE/ADDR/SUFFIX/BYPASS/DEL_*/HTTPS/ARM_SHAPE (control.rs:2633-3896). Пробелы: C `SET_HTTPS` обрезает TTL до максимума, R2O отвергает (`ACK_BAD_ARGS`) — control.rs:1070; `arm_client_shape` отвергает транспорт 17 (control.rs:2002), C принимает 6/17; адресные опыты не тестированы. |
| d2k_ctlsrv_pump | 511-694 | 184 | выгрузить новые записи журнала в события с раскладкой по типам | `main.rs:2728` `send_journal_updates`, `:2709` `send_journal_snapshot`; `flow_journal.rs:202` `to_event_frame` | P | `flow_journal` round-trip тесты и `d2o_control_frames_match_donor_wire_decoding` (tests/control.rs:47). Пробелы: v22-трансляция `EVENT_LEGACY_CLIENT_TCP` шлёт пустые TCP-опции (r2k-core/control.rs:1212-1215), C шлёт реальные; набор видов журнала уже C (нет отдельного CLIENT_TCP в v48). |
| d2k_ctlsrv_http80_event | 697-731 | 35 | событие HTTP-портала/ответа с измерениями | `control.rs:3136` `send_http_portal_event`, `:3148` `send_http_response_event`; `r2k-core/control.rs:852` `HttpResponseEvent::event_body` | P | `decodes_r2o_http_response_context_and_measurements` (tests/control.rs:977), `control_decoder_accepts_http_portal_response_events` (tests/capture_shape.rs:150). Отличие: R2O кодирует `code 1..4` и всегда несёт хвост status/body/request_no; C для портала без ответа хвост не шлёт. |

Итог по файлу: E 6, P 6, N 0. Пробелы: TTL HTTPS (обрезка vs отказ), ARM_SHAPE для
UDP, пустые TCP-опции в v22 CLIENT_TCP, адресные опыты без тестов, формат HTTP-события.

---

## 3. datapath/include/d2k_plans.h — 2 функции

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| d2k_binding_known | 98-102 | 5 | static inline: identity известна (generation, kind, epoch) | `r2k-core/control.rs:315` `BindingContext::is_known` + покомпонентные проверки в `control.rs:1446-1461` | P | `conditional_http_delete_preserves_replacements_and_removes_only_its_binding` (control.rs:3587). Отличие: R2O `is_known` не проверяет `kind`; `kind==1` проверяется отдельно в `delete_name_bound`. |
| d2k_binding_equal | 103-108 | 6 | static inline: совпадение generation/kind/family/shape/temporary/epoch | `control.rs:1468-1475` (epoch, generation, transport, shape через ключ) | P | Тот же тест. Отдельной функции сравнения нет: `family` берётся из ключа, `kind` проверяется как `==1`, `temporary` — как `false`. |

Итог: E 0, P 2, N 0. Обе функции — inline-предикаты identity; поведение распределено по
`delete_name_bound` и `binding_for_plan`.

---

## 4. datapath/plan_apply.c — 15 функций

Компиляция проверенного плана в список посылок. R2O: `crates/r2k-core/src/plan/apply.rs`
(`impl Plan`, `Actions`, `Emission`).

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
| d2k_plan_apply | 343-873 | 531 | превратить план+пакет в посылки, судьбу оригинала и причину отказа | `plan/apply.rs:155` `Plan::apply` | P | 17 тестов tests/apply.rs покрывают split/fake/overlay/order/pace/settle/delay/udplen/qsplit/qdeny/oob/metric. Пробелы: `MAX_EMISSIONS = 26` (apply.rs:9) против 65536 в C (`plan_apply.c:830`) — R2O отвергает раньше; однако D2O на выдаче в session тоже ограничивает 26 (`D2K_RESULT_MAX`, session.c:2517), поэтому наблюдаемый отказ совпадает, различаются слой и текст ошибки. В OOB-ветви `suffix.wire_profile` остаётся 0 (apply.rs:280-291), тогда как C проставляет профиль всем посылкам на `finalize`. |
| d2k_actions_cancel | 891-921 | 31 | правила отмены недосланного исполнения | `plan/apply.rs:104` `Actions::cancel` | E | `cancellation_drops_only_after_payload_bytes_were_emitted` (tests/apply.rs). |
| d2k_actions_free | 923-931 | 9 | освободить посылки | `plan/apply.rs:61` `Emission` + `Actions` (RAII) | E | Освобождение автоматическое; отдельных ошибок/утечек нет по типам. |

Итог по файлу: E 14, P 1, N 0. Главные отличия — место отказа при >26 посылках (D2O тоже
отказывает в session, но позже) и потеря `wire_profile` в OOB-суффиксе.
у OOB-суффикса.

---

## 5. datapath/plan_parse.c — 17 функций

Разбор канонического плана. R2O: `crates/r2k-core/src/plan.rs` (`Plan::parse`, `scan`,
`check_references`), поля `Plan`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| rd16 | 23-25 | 3 | static: u16 BE | `plan.rs:892` `read_u16` | E | `rejects_bad_header_lengths_records_and_unknown_versions` (tests/plan.rs). |
| rd32 | 27-30 | 4 | static: u32 BE | `plan.rs:902` `read_u32` | E | Тот же тест. |
| fail | 32-36 | 5 | static: записать текст ошибки | `plan.rs:67` `PlanError::new` | P | Тексты R2O другие; проверяется только факт отказа, не текст. |
| scan | 45-220 | 176 | первый проход: счётчики, проверки типов/длин/minexec | `plan.rs:687` `scan` | E | `rejects_bad_header_lengths_records_and_unknown_versions`, `rejects_dangling_references_and_invalid_operation_combinations` (tests/plan.rs). |
| check_refs | 224-325 | 102 | второй проход: ссылки, сочетания операций, порядок, одиночное перекрытие | `plan.rs:499` `check_references` | E | `rejects_dangling_references_and_invalid_operation_combinations` (tests/plan.rs). |
| d2k_find_payload | 327-334 | 8 | найти приманку по id | `plan.rs` — `self.payloads.iter().find(...)` (apply.rs:611, :1287 и др.) | E | `parses_payload_fake_and_cross_references` (tests/plan.rs). |
| d2k_find_poison | 336-343 | 8 | найти порчу по id | `plan.rs` — `self.poisons.iter().find(...)` (apply.rs:624, :744) | E | Тот же тест. |
| d2k_plan_load | 345-566 | 222 | полная загрузка: заголовок, scan, записи, check_refs, транспорт | `plan.rs:190` `Plan::parse`, `:167` `parse_wire` | E | 7 тестов tests/plan.rs, включая legacy `D2KP` (`parses_legacy_d2kp_container_with_identical_body`). Отличия: magic `R2OP` (legacy `D2KP` только через `parse_wire`), повторный `autottl` в R2O — ошибка (`plan.rs:307`), в C — «последний побеждает» (plan_parse.c:482). |
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

## 6. datapath/plans.c — 75 функций

Таблица планов по целям: ключи имя/адрес/суффикс, LRU-вытеснение, точные пробы, поиск на
пакетном пути. R2O-аналог — `NamePlans` в `crates/r2o-datapath/src/control.rs`
(`HashMap`-ключи вместо уплотнённого массива, `Cell<u64>`-часы вместо `last_used_ns`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| bind_context | 94-102 | 9 | static: присвоить плану identity (owner, generation, kind/family/shape/temporary) | `control.rs:1592` `next_generation`, `:878-887`/`:915-924` вставка | P | Identity выдаётся при вставке в каждую таблицу; отдельной функции нет. Проверяется через `binding_for_plan` в тестах APPLIED. |
| d2k_plantab_new | 104-130 | 27 | создать таблицу на cap записей и 16-байтовый epoch | `control.rs:146` `NamePlans::with_capacity` | E | `exact_name_addr_probe_tables_share_lru_capacity` (control.rs:2633). |
| d2k_plantab_free | 132-149 | 18 | освободить планы и массивы | `Drop` (`HashMap<String, InstalledPlan>`) | E | Владение типами; утечек нет по построению. |
| name_eq | 154-167 | 14 | static: сравнение имён без учёта регистра (ASCII) | `control.rs:2233` `canonical_name` (lowercase) + `String`-равенство | P | Регистронезависимость подтверждена для HTTPS-имён (`EXAMPLE.TEST`, control.rs:3167); теста на план, поставленный в верхнем регистре и найденный в нижнем, нет. |
| shape_transport | 169-175 | 7 | static: форма→транспорт (QUIC 17, TLS 6, иначе 0) | нет функции; совместимость в `control.rs:859-868`, `:955-960`, `:1597-1603` | P | Правила размазаны по трём `match`; отдельного предиката нет. |
| area_name_valid | 177-191 | 15 | static: валидация DNS-суффикса (метки, дефисы, 253) | `control.rs:2233` `canonical_name` | P | R2O строже: требует ≥2 метки и хотя бы одну нецифровую; C допускает односложное имя. Тест `исключение_снимает_suffix...` (control.rs:3075). |
| suffix_member | 193-197 | 5 | static: имя входит в суффикс по границе метки | `control.rs:1605` `domain_suffix_member` | E | `исключение_снимает_suffix_только_для_точного_имени...` (control.rs:3075): `other.googlevideo.com` получает план, `failed...` — нет. |
| area_exact | 199-207 | 9 | static: найти запись площади по (имя, транспорт, форма, family) | ключ `SuffixPlanKey`/`DomainBypassKey` (control.rs:64-78, HashSet/HashMap) | E | Тест control.rs:3075 (установка/поиск/удаление). |
| area_set | 209-226 | 18 | static: поставить план суффикса с проверкой формы/транспорта/family | `control.rs:928` `set_suffix` (и `:988` `set_domain_bypass`) | P | Тест control.rs:3075. Отличие: C принимает любой транспорт, равный `shape_transport(shape)`; R2O ограничивает набор форм TCP 1/2/6/8-13 и QUIC 3. |
| d2k_plantab_set_suffix_family | 228-237 | 10 | поставить план изученного суффикса | `control.rs:928` `set_suffix` | E | `исключение_снимает_suffix...` (control.rs:3075). |
| d2k_plantab_set_bypass_family | 239-244 | 6 | поставить исключение семейства (bypass) | `control.rs:988` `set_domain_bypass` | E | Тот же тест: bypass подавляет суффикс, затем снимается. |
| area_del | 246-253 | 8 | static: снять запись площади с уплотнением | `control.rs:1021` `delete_domain_area` | E | Тот же тест (DEL_BYPASS/DEL_SUFFIX). |
| d2k_plantab_del_suffix_family | 255-258 | 4 | снять суффикс | `control.rs:1021` `delete_domain_area(body, true)` | E | Тот же тест. |
| d2k_plantab_del_bypass_family | 260-263 | 4 | снять исключение | `control.rs:1021` `delete_domain_area(body, false)` | E | Тот же тест. |
| area_bypassed | 265-273 | 9 | static: имя исключено для (family, shape) | `control.rs:1557` `name_is_bypassed` | E | Тот же тест. |
| area_match | 275-284 | 10 | static: самый длинный подходящий суффикс | `control.rs:1569` `find_in_domain` (`max_by_key(len)`) | P | Тест покрывает один суффикс; выбор самого длинного из нескольких не проверен. |
| d2k_plantab_revision | 286-286 | 1 | ревизия таблицы | `control.rs:586` `revision` | E | `conditional_http_delete...` (control.rs:3587) сверяет `revision` до/после. |
| d2k_plantab_has_ech_target | 288-314 | 27 | есть ли ECH-привязка имени/адреса (для удержания фрагментов ECH) | — | ? | Прямого предиката с таким именем нет. R2O собирает неполный ClientHello общим путём `capture.rs`/`engine.rs` (не только при наличии ECH-привязки), поэтому поведение «фрагменты ECH удерживаются» может быть покрыто, но адресного differential на это правило нет. Нужен тест: ECH-привязка есть → обрывок удерживается; привязки нет → не удерживается. |
| d2k_plantab_stream_candidate | 316-319 | 4 | префильтр: есть ли потоковый план по имени/адресу | `control.rs:612` `has_tls_candidate(family)` | P | R2O префильтр только по family, без имени/адреса/sport; используется в `main.rs:1699`. |
| d2k_plantab_stream_candidate_family | 321-325 | 5 | то же с family | `control.rs:612` `has_tls_candidate` | P | То же: нет учёта имени и порта; тестов на точность префильтра нет. |
| d2k_plantab_stream_candidate_target | 327-350 | 24 | то же по (имя, адрес, sport, family), включая суффиксы | `control.rs:612` `has_tls_candidate` | P | Отличие: R2O не различает sport и конкретную цель; суффиксы учитываются, но без имени. |
| find_name_skip | 357-367 | 11 | static: запись имени без порта; опционально мимо HTTP | `control.rs:1493` `find` по `NamePlanKey{host,family,shape}` | P | HTTP-запись в R2O — отдельный shape-ключ, поэтому «пропустить HTTP» не нужно; но и «любая форма» одним поиском не выражается. |
| find_name | 369-371 | 3 | static: запись имени без порта | `control.rs:1493` `find` | E | Выбор по имени в `tls_probe_plan...`/`http_probe_plan...` (control.rs:3489, 3637). |
| find_name_shape_port | 385-395 | 11 | static: запись ровно (имя, форма, порт, family) | `control.rs:1493` `find` + `probes: NameProbeKey` | E | `tls_probe_plan_matches_only_its_source_port_and_reports_temporary_applied` (control.rs:3637). |
| find_name_port | 401-412 | 12 | static: портовая запись имени при неизвестной форме | `control.rs:548-571` — поиск probe по `(host, family, shape)` и bridge-shape | E | `tls_probe_plan...` (control.rs:3637): проба находится по своему порту. |
| d2k_plantab_http_candidate | 414-422 | 9 | префильтр HTTP: запись формы HTTP с точным портом и proto HTTP | `control.rs:624` `has_http_candidate(family)` | P | R2O проверяет только shape-ключ, без `proto==HTTP` и без sport; вызывается в `main.rs:1701`. |
| d2k_plantab_find_http | 424-431 | 8 | план для HTTP-запроса: проба своего порта, иначе постоянная | `control.rs:495-509` (`select` + `NameProbeKey` для порта 80) | E | `http_probe_plan_matches_only_its_source_port_and_acknowledges_trial_id` (control.rs:3489). |
| find_addr_shape | 439-450 | 12 | static: адресная запись ровно (адрес, family, форма) | `control.rs:1504` `find_addr` | E | `discord_voice_class_plan_matches_only_discord_voice_requests` (control.rs:3186), `удаление_адреса...` (control.rs:2793). |
| find_addr | 452-454 | 3 | static: любая форма адреса (для снятия/учёта промаха) | `control.rs:1504` `find_addr` (с ECH-fallback) | E | Те же тесты; снятие адреса в control.rs:2793. |
| modern_shape_for_ech | 465-469 | 5 | static: ECH-форма → соответствующая MODERN-форма | `control.rs:534-539` `fallback_shape` в `select` | E | `tls_план_работает_для_sni_с_ech_...` (control.rs:2823). |
| scan_name | 471-486 | 16 | static: один проход — shaped/modern/grandfather/any по имени | `control.rs:572-581` — цепочка `find` с fallback-формами | P | Порядок предпочтения сохранён, но R2O делает отдельные HashMap-поиски, а не один проход; ветка `h.any` (запись есть, формы нет) выражена иначе. |
| scan_addr | 488-502 | 15 | static: один проход по адресу | `control.rs:1522` `find_addr_fallback` | P | Учтён ECH-fallback и bypass; счётчик промахов по форме не ведётся (см. `shape_misses`). |
| oldest | 518-529 | 12 | static: самая старая запись (LRU) | `control.rs:211` `exact_victim` | E | `name_plan_table_evicts_lru_and_delete_releases_a_slot` (control.rs:2663). |
| take_free_or_evict | 541-569 | 29 | static: свободный слот или вытеснение LRU с уплотнением | `control.rs:234` `make_room_exact` | E | `exact_name_addr_probe_tables_share_lru_capacity` (control.rs:2633): общая ёмкость имя+адрес+проба. |
| d2k_plantab_set_name_shaped | 571-574 | 4 | поставить план имени с формой | `control.rs:832` `set_name` (shape — часть ключа) | E | `условие_..._tls_форма` (control.rs:2844) и shape-тесты. |
| d2k_plantab_set_name_probe | 576-580 | 4 | поставить пробный план имени на один порт | `control.rs:1092` `set_name_probe` | E | `http_probe_plan...` (control.rs:3489), `tls_probe_plan...` (control.rs:3637). |
| probe_transport | 584-588 | 5 | static: транспорт пробы (из плана, иначе по форме) | `control.rs:1129` (`plan.transport != 6`), `:859-868` | P | Вывод транспорта из формы без плана в R2O не нужен: проба всегда TCP/proto 1/HTTP. |
| d2k_plantab_set_name_family | 590-667 | 78 | основная установка имени: ключ (имя, форма, порт, family), замена пробы того же порта, grandfather-правило | `control.rs:832` `set_name`, `:1092` `set_name_probe` | P | Тесты shape/probe/bound (control.rs:2700-3896). Отличия: C при `sport` снимает прежнюю пробу того же (имя, family, порт, транспорт) — R2O `retain` по (host, family, port) без транспорта; C хранит `SHAPE_ANY` и grandfather в общем массиве — R2O различает их ключом. |
| d2k_plantab_set_name | 672-676 | 5 | legacy: поставить имя как grandfather | `control.rs:832` `set_name` (контроллер шлёт форму явно) | P | Legacy-входа без формы нет; совместимость обеспечивает shape=GRANDFATHER в ключе. |
| d2k_plantab_set_addr | 678-681 | 4 | legacy: адрес как grandfather | `control.rs:891` `set_addr` (форма обязательна) | P | C legacy-вход только для тестов датапата; командой сокета не используется. В R2O такого входа нет. |
| d2k_plantab_set_addr_family | 686-690 | 5 | legacy: адрес без формы → grandfather | `control.rs:891` `set_addr` | P | То же: форма обязательна (`valid_addr_shape`), grandfather по сокету не принимается — совпадает с C `ctlsrv`. |
| d2k_plantab_set_addr_shaped | 692-721 | 30 | адресная привязка ровно (адрес, family, форма) | `control.rs:891` `set_addr` | E | `удаление_адреса_разделяет_формы...` (control.rs:2793): две формы одного IP, удаление одной. |
| drop | 728-741 | 14 | static: снять запись, сохранив уплотнение | `HashMap::remove` (control.rs:1408, 1473, 1489) | E | `name_plan_table_evicts_lru_and_delete_releases_a_slot` (control.rs:2663). |
| d2k_plantab_del_name | 743-745 | 3 | legacy: снять ВСЕ записи имени (v4) | `control.rs:1389` `delete_name` (одна форма) | P | Семантика разная: C legacy снимает все формы, R2O — только точный ключ (как v9 `DEL_NAME`). Широкого удаления в R2O нет. |
| d2k_plantab_del_name_family | 747-765 | 19 | снять все формы имени в family | `control.rs:1389` `delete_name` | P | То же: удаляется один shape-ключ, а не все формы. |
| d2k_plantab_del_name_shaped | 773-790 | 18 | снять постоянную запись (имя, транспорт, форма, family), пробы не трогать | `control.rs:1389` `delete_name` | E | `conditional_http_delete_preserves_replacements_and_removes_only_its_binding` (control.rs:3587). |
| d2k_plantab_del_name_bound | 792-806 | 15 | условное снятие по identity (generation/epoch/kind) | `control.rs:1416` `delete_name_bound` | E | Тот же тест: замена с другой identity не удаляется. |
| d2k_plantab_del_name_probe | 808-811 | 4 | снять пробную запись по порту | `control.rs:1362` `delete_name_probe` | E | `http_probe_plan...` (control.rs:3489) снимает пробу. |
| d2k_plantab_del_name_probe_family | 813-828 | 16 | то же с family | `control.rs:1362` `delete_name_probe` | E | Тот же тест. |
| d2k_plantab_del_addr | 830-832 | 3 | legacy: снять адрес целиком (все формы) | `control.rs:1479` `delete_addr` (одна форма) | P | Семантика разная: широкого удаления адреса в R2O нет (v7 шлёт форму). |
| d2k_plantab_del_addr_family | 837-842 | 6 | снять все формы адреса | `control.rs:1479` `delete_addr` | P | То же: одна форма. |
| d2k_plantab_del_addr_shaped | 844-848 | 5 | снять ровно форму адреса | `control.rs:1479` `delete_addr` | E | `удаление_адреса_разделяет_формы...` (control.rs:2793). |
| trial_id_valid | 850-855 | 6 | static: trial id не весь нулевой | inline `iter().all(\|b\| *b == 0)` (control.rs:1198, 1277, 1329) | P | Три копии вместо функции; тестов на нулевой id не найдено. |
| probe_flow_valid | 860-874 | 15 | static: валидность flow опыта (UDP, dst port, family, ненулевые адреса) | `r2k-core/control.rs:1701` `valid_udp_addr_probe_flow` | P | R2O требует family 4/6 (C допускает 0) и ненулевой src-порт (C — wildcard 0 для голоса вынесен в отдельную таблицу). Тестов нет. |
| probe_flow_equal | 876-887 | 12 | static: равенство flow | ключ `[u8; KEY_LEN]` в `HashMap` (control.rs:88) | P | Равенство по ключу тривиально, но адресные опыты не тестированы. |
| probe_drop | 889-895 | 7 | static: снять запись опыта | `HashMap::remove`/`retain` (control.rs:607, 1291) | E | `clearing_disconnected_http_probes_keeps_the_permanent_plan` (control.rs:3703) — очистка проб. |
| d2k_plantab_clear_probes | 897-910 | 14 | снять пробные записи и QUIC-запреты | `control.rs:600` `clear_probes` | E | Тот же тест. Отличие: R2O чистит `probes`, `voice_addr_probes`, `addr_probes`, но не записи с `qdeny` в основной таблице. |
| d2k_plantab_set_addr_probe | 912-961 | 50 | временный план на точный flow с trial id и lease | `control.rs:1260` `set_addr_probe` | P | Реализация есть (lease, trial, отказ при чужой generation), но ни одного теста COMMAND_SET_ADDR_PROBE не найдено. |
| d2k_plantab_del_addr_probe | 963-976 | 14 | снять ровно (flow, generation) | `control.rs:1318` `delete_addr_probe` | P | Тестов нет. |
| find_probe | 978-1006 | 29 | static: поиск опыта, ленивое истечение, wildcard-порт только для голоса | `control.rs:804` `addr_probe_binding_at_hook`, `:764` `voice_address_binding` | P | Голосовая часть покрыта (`временная_voice_запись...`, control.rs:3239), адресная — нет. |
| d2k_plantab_find_addr_probe | 1008-1012 | 5 | поиск точного адресного опыта | `control.rs:804` `addr_probe_binding_at_hook` | P | Тестов нет; поиск дополнительно требует authenticated Initial и клиентского направления. |
| d2k_plantab_find_voice_probe | 1014-1018 | 5 | поиск голосового опыта (wildcard клиентского порта) | `control.rs:764` `voice_address_binding` | E | `временная_voice_запись_соответствует_только_с_заданным_и_целым_адресом` (control.rs:3239), `stun_...` (3278). Ключ R2O не содержит клиентского порта — wildcard выражен структурно. |
| d2k_plantab_probe_count | 1020-1022 | 3 | число адресных опытов | `control.rs:186` `r2o_probe_count` | P | Считает только неистёкшие `addr_probes`; тестов нет. |
| shape_fits | 1044-1052 | 9 | static: подходит ли форма записи наблюдению (три исхода + ECH-перенос) | `control.rs:534-539, 572-581` — цепочка exact/bridge/fallback/grandfather | P | Логика расщеплена на цепочку поисков; отдельного предиката нет. ECH-перенос и grandfather покрыты тестами (control.rs:2823). |
| shape_is_udp | 1054-1056 | 3 | static: QUIC/VOICE | `matches!(shape, SHAPE_QUIC \| SHAPE_VOICE)` в разных местах (control.rs:1404 и др.) | P | Отдельной функции нет; правило кросс-транспортного перехода C (UDP-наблюдение не блокируется TCP-записью) в R2O заменено общим fallback на адрес. |
| d2k_plantab_shape_misses | 1058-1060 | 3 | счётчик «нашли, но форма не подошла» | `control.rs:193` `r2o_shape_misses` | N | Поле `shape_misses` объявлено и читается, но **нигде не инкрементируется** (grep по `shape_misses` — только объявление/инициализация/геттер) → всегда 0. |
| d2k_plantab_find | 1062-1066 | 5 | поиск плана по имени, затем адресу | `control.rs:410` `select` | P | R2O `select` разбирает пакет и сам извлекает SNI/HTTP/QUIC; порядок «имя → суффикс → адрес» сохранён, но набор ветвей другой (см. `find_target`). |
| d2k_plantab_find_sport | 1068-1072 | 5 | поиск с местным портом потока | `control.rs:410` `select` (`tcp.source_port` для проб) | P | Порт учитывается только для проб; отдельного входа с sport нет. |
| d2k_plantab_find_family | 1074-1079 | 6 | поиск с family | `control.rs:410` `select` (`view.family`) | P | Family берётся из пакета; отдельного входа нет. |
| d2k_plantab_find_target | 1081-1236 | 156 | ядро поиска: точный порт → своя форма → grandfather → суффикс → адрес; счёт промахов по форме | `control.rs:419` `select_with_quic_host_at_hook` | P | Тесты: TLS/ECH/QUIC/HTTP/voice/probe (control.rs:2823-3896). Отличия: (1) счётчик промахов не ведётся; (2) R2O добавляет TCP-контекст 8–13 и bridge-shape (control.rs:529-539); (3) кросс-транспортный переход UDP↔TCP в C отдельной ветвью (`goto check_addr`), в R2O — общим fallback; (4) ECH-fallback на адрес в R2O отсутствует. |
| d2k_plantab_count | 1238-1240 | 3 | число занятых записей | `control.rs:178` `r2o_plan_count` | E | `exact_name_addr_probe_tables_share_lru_capacity` (control.rs:2633) и eviction-тест сверяют counts. |
| d2k_plantab_capacity | 1242-1244 | 3 | ёмкость таблицы | `control.rs:182` `r2o_plan_capacity` | E | `name_plan_table_evicts_lru...` (control.rs:2663) сверяет capacity. |
| d2k_plantab_binding | 1246-1257 | 12 | identity установленного плана (generation/kind/family/shape/temporary/epoch) | `control.rs:380` `http_name_binding_context`, `:690` `binding_for_plan` | E | `bound_http_set_returns_its_trial_id_and_installed_binding` (control.rs:2700); APPLIED-фикстуры D2O (tests/control.rs:47). |
| d2k_plantab_set_name_trial | 1259-1267 | 9 | поставить пробный план с trial id | `control.rs:1092` `set_name_probe` (trial_id) | E | `http_probe_plan_matches_only_its_source_port_and_acknowledges_trial_id` (control.rs:3489). |
| d2k_plantab_trial | 1268-1273 | 6 | trial id установленного временного плана | `control.rs:690` `binding_for_plan` (`PlanBinding.trial_id`) | E | `tls_probe_plan...reports_temporary_applied` (control.rs:3637), voice-тесты (control.rs:3239). |

Итог по файлу: E 37, P 36, N 1, ? 1. Ключевые пробелы: счётчик промахов по форме мёртв;
нет ECH-удержания; адресные опыты без тестов; префильтры кандидатов грубее C; legacy-удаления
«все формы» отсутствуют; поиск ядра отличается набором ветвей.

---

## 7. datapath/raw.c — 17 функций

Сырой сокет: пределы длины, MTU маршрута, отправка без ожидания. R2O:
`crates/r2o-datapath/src/raw.rs` (`RawSocket`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| if_mtu | 64-81 | 18 | static: MTU интерфейса через `SIOCGIFMTU` | `raw.rs:301` `r2o_interface_mtu` (sysfs `/sys/class/net/<if>/mtu`) | P | Механизм другой (sysfs), ioctl-путь не проверен; теста на чтение MTU реального интерфейса нет. |
| pick_maxlen | 92-116 | 25 | static: предел по named iface или наименьшему MTU поднятых (без loopback) | `raw.rs:270` `r2o_pick_maxlen` | P | `общий_предел_берёт_наименьший...` (raw.rs:836) тестирует выбор через инъекцию; сам обход sysfs и fallback 1500 против `D2K_RAW_MTU_FALLBACK` не сверены. |
| route_mtu | 140-176 | 37 | static: MTU маршрута к адресу (UDP connect + `IP_MTU`/`IPV6_MTU`) | `raw.rs:484` `r2o_route_mtu` | P | Код тождествен по смыслу, но требует root/kernel; теста нет. |
| say | 181-191 | 11 | static: текст ошибки с сохранением errno | `io::Error` + `eprintln!` | P | Формат другой; errno сохраняет `io::Error`. |
| d2k_raw_open | 193-256 | 64 | открыть IPv4 raw, `IP_HDRINCL`, `SO_MARK`, вычислить maxlen | `raw.rs:48` `RawSocket::open` | P | Отличия: R2O требует ненулевой mark (C допускает 0), один объект — одно семейство (C держит IPv4+IPv6 вместе), нет ленивого fragment-сокета. Тестов open на живой системе нет. |
| d2k_raw_close | 258-269 | 12 | закрыть fd/фрагментный сокет | `Drop for RawSocket` (`OwnedFd`) | E | Владение типами; утечек нет по построению. |
| d2k_raw_limits | 271-273 | 3 | маска ограничений способа отправки (`CANT_IPID\|CANT_IPSUM`) | нет API; `engine.rs:2091` отвергает `POISON_IPID_ZERO` | P | `CANT_IPSUM` в R2O не выражен (суммы считает wire); маска как интерфейс отсутствует. |
| d2k_raw_maxlen | 275-279 | 5 | предел посылки, никогда не 0 | `raw.rs:96` `maxlen` | E | `предел_маршрута_учитывает_объявленный_интерфейс...` (raw.rs:820). |
| d2k_raw_adopt_egress | 281-303 | 23 | принять наименьший MTU выходных ifindex (если предел не объявлен) | `raw.rs:106` `r2o_adopt_egress` | E | `общий_предел_берёт_наименьший...` (raw.rs:836): фильтр `< FLOOR`, дубли, `None`. |
| blend | 306-309 | 4 | static: маршрут против общего предела при объявленном iface | `raw.rs:351` `r2o_effective_route_maxlen` | E | `предел_маршрута_учитывает_объявленный_интерфейс_и_запасной_mtu` (raw.rs:820). |
| d2k_raw_route_maxlen | 311-313 | 3 | MTU маршрута для dst[4] | `raw.rs:119` `packet_route_maxlen` | P | Вход — пакет, а не 4 байта; IPv6-путь и fallback на общий предел не сверены. |
| d2k_raw_route_maxlen_family | 315-339 | 25 | кэш из 16 маршрутов, порог 1280/576, запись кольцом | `raw.rs:136` `r2o_route_maxlen`, `:367` `R2oRouteMtuCache` | E | `кэш_mtu_сохраняет_только_полезные_маршруты_и_ограничен` (raw.rs:786); порог и вытеснение. |
| d2k_raw_prepare | 341-404 | 64 | ленивая подготовка IPv6/fragment-сокета, проверка длин и контекста фрагмента | `raw.rs:559` `outgoing_packet` (+`:591`/`:622` фрагменты) | P | R2O не открывает отдельный fragment-сокет с `IP_NODEFRAG` и не создаёт IPv6-сокет лениво (семейство задано при старте); валидация фрагментов есть (`raw_sender_accepts_only_well_formed...`, raw.rs:874). |
| d2k_raw_send | 406-512 | 107 | `sendto(MSG_DONTWAIT)`, EINTR-повтор, EMSGSIZE → снизить предел | `raw.rs:147` `send_packet`, `:155` `send_packet_inner` | P | Логика EMSGSIZE/кэша и busy есть (raw.rs:208-219, `record_send_outcome`), но реальная отправка в тестах не выполнялась (нужен root). Тесты покрывают статистику и разбор. |
| d2k_raw_sent | 514-516 | 3 | счётчик успешных посылок | `raw.rs:100` `send_stats().sent` | E | `raw_send_stats_count_success_and_busy_errors_like_d2o` (raw.rs:231). |
| d2k_raw_errors | 518-520 | 3 | счётчик ошибок | `raw.rs:100` `send_stats().errors` | E | Тот же тест. |
| d2k_raw_busy | 522-524 | 3 | счётчик EAGAIN/ENOBUFS | `raw.rs:100` `send_stats().busy` | E | Тот же тест. |

Итог по файлу: E 8, P 9, N 0. Главные отличия: один сокет на семейство, обязательный
mark, нет `IP_NODEFRAG`, нет ленивого открытия, нет маски ограничений.

---

## 8. datapath/routemark.c — 23 функции

Сопоставление fwmark/выходных интерфейсов и политика Keenetic. R2O:
`crates/r2o-datapath/src/r2o_route.rs` (`R2oRouteGate`, `R2oRoutePolicy`, парсеры).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| rd16h | 27-27 | 1 | static: u16 host order | `u16::from_ne_bytes` (r2o_route.rs:838 и др.) | E | `r2o_разбор_правил_учитывает_маску...` (r2o_route.rs:1109). |
| rd32h | 28-28 | 1 | static: u32 host order | `u32::from_ne_bytes` | E | Те же тесты разбора. |
| wr16h | 29-29 | 1 | static: записать u16 host order | `to_ne_bytes` (r2o_route.rs:683) | E | `r2o_запросы_содержат_семейство...` (r2o_route.rs:1086). |
| wr32h | 30-30 | 1 | static: записать u32 host order | `to_ne_bytes` (r2o_route.rs:685) | E | Тот же тест. |
| d2k_routemark_init | 32-34 | 3 | обнулить состояние | `impl Default for R2oRouteGate` (r2o_route.rs:108) | E | Все тесты создают `R2oRouteGate::default()`. |
| d2k_routemark_request | 36-46 | 11 | собрать `RTM_GETRULE` dump-запрос | `r2o_route.rs:679` `r2o_route_rule_request` | E | `r2o_запросы_содержат_семейство_последовательность_и_адрес_поиска` (r2o_route.rs:1086). |
| nl_error | 49-51 | 3 | static: errno из тела `NLMSG_ERROR` | `r2o_route.rs:863` `r2o_kernel_error` | E | `r2o_ошибки_и_повреждённые_сообщения...` (r2o_route.rs:1161). |
| d2k_routemark_parse | 53-95 | 43 | разобрать дамп правил: fwmark/fwmask, invert, mask=0 | `r2o_route.rs:711` `r2o_route_parse_rules` | E | `r2o_разбор_правил_учитывает_маску_инверсию_и_завершение_дампа` (r2o_route.rs:1109). |
| d2k_routemark_lookup_request | 103-120 | 18 | собрать одиночный `RTM_GETROUTE` к probe-адресу | `r2o_route.rs:691` `r2o_route_lookup_request` | E | `r2o_запросы_содержат...` (r2o_route.rs:1086). |
| add_oif | 122-128 | 7 | static: добавить ifindex без дублей и нуля | `r2o_route.rs:950` `r2o_route_add_ifindex` | E | `r2o_разбор_маршрута_собирает_основной_и_multipath...` (r2o_route.rs:1137). |
| route_oifs | 132-152 | 21 | static: обойти RTA_OIF и RTA_MULTIPATH | `r2o_route.rs:876` `r2o_route_attributes`, `:913` `r2o_route_parse_multipath` | E | Тот же тест: OIF+multipath+нулевой hop. |
| d2k_routemark_lookup_parse | 154-173 | 20 | разобрать ответ маршрута, не-unicast → 2 | `r2o_route.rs:774` `r2o_route_parse_lookup` | E | Тот же тест + `r2o_ошибки_...` (r2o_route.rs:1161). |
| d2k_routemark_watch_relevant | 175-190 | 16 | нужно ли обновление по уведомлению | `r2o_route.rs:806` `r2o_route_watch_relevant` | E | `r2o_уведомления_обновляют_состояние...` (r2o_route.rs:1189). |
| d2k_routemark_clear_oifs | 192-199 | 8 | сбросить список устройств (маршрут без устройства) | `r2o_route.rs:131` `r2o_set_default_ifindices(family, None/Some(vec![]))` | P | В R2O нет флага `oifs_read`; `None` = неизвестно, `Some(empty)` = известно «нет устройств». Соответствие не проверено тестом на реальном маршруте без OIF. |
| d2k_routemark_set_oifs | 201-213 | 13 | сохранить список устройств с признаком чтения | `r2o_route.rs:131` `r2o_set_default_ifindices` | E | `r2o_устройства_по_умолчанию_включают_multipath...` (r2o_route.rs:1053), `r2o_выходные_интерфейсы...` (r2o_route.rs:1074). |
| d2k_routemark_set | 215-227 | 13 | заменить набор селекторов, вернуть изменение | `r2o_route.rs:119` `r2o_set_rules` | P | R2O не возвращает признак изменения и не хранит `rules_read*` в объекте (выражено `Option<Vec<...>>`); влияние на `revision`/удержания не проверено. |
| d2k_routemark_merge | 229-267 | 39 | объединить v4/v6, сохранить прежнее семейство при ошибке | `r2o_route.rs:372` `r2o_refresh` (обновляет только успешное семейство) | P | Логика сохранения прежнего набора есть; `found`/`truncated` в статусе не перенесены (нет `d2k_routemark_status`). |
| d2k_routemark_set_policy | 269-275 | 7 | включить политику (none/mark/mask) | `r2o_route.rs:170` `r2o_set_policy(Some/None)` + `R2oRoutePolicy::new` | E | `r2o_политика_отделяет_чужие_потоки...` (r2o_route.rs:1008). |
| policy_match | 277-280 | 4 | static: метка подходит политике | `r2o_route.rs:93` `R2oRoutePolicy::r2o_matches` | E | Тот же тест. |
| d2k_routemark_routed | 282-296 | 15 | уведена ли метка чужим ip rule (fail closed) | `r2o_route.rs:175` `r2o_mark_is_routed` | E | `r2o_метки_fwmark_учитывают_маску_семейство_и_неизвестные_правила` (r2o_route.rs:979). |
| d2k_routemark_client | 298-302 | 5 | метка клиента, кроме probe/own | `r2o_route.rs:201` `r2o_route_mark` (первые ветви) | E | `r2o_политика_...` (r2o_route.rs:1008): свои метки 0x2d/0x2e не считаются клиентскими. |
| d2k_routemark_gate | 304-325 | 22 | политика Keenetic + клиентская метка + проверка outdev | `r2o_route.rs:201` `r2o_route_mark` | E | `r2o_политика_...` (r2o_route.rs:1008) и `r2o_устройства_по_умолчанию...` (r2o_route.rs:1053). |
| d2k_routemark_describe | 327-343 | 17 | текст «0xmark/0xmask v4, ...» для логов | — | N | Функции/строки описания набора правил в R2O нет. |

Итог по файлу: E 19, P 3, N 1. Пробелы: статус merge (`found/truncated`), признак
изменения набора правил, отсутствие текстового описания.

---

## 9. datapath/routemark_nl.c — 8 функций

Rtnetlink: дампы правил, одиночный поиск маршрута, подписка на изменения. R2O:
`R2oRouteMonitor` в `crates/r2o-datapath/src/r2o_route.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| parse_rules | 18-21 | 4 | static: адаптер сигнатуры под `d2k_routemark_parse` | `r2o_route.rs:402` замыкание `r2o_route_parse_rules` | E | `r2o_разбор_правил...` (r2o_route.rs:1109). |
| dump | 27-59 | 33 | static: отправить запрос и читать до DONE, EAFNOSUPPORT = пусто | `r2o_route.rs:448` `r2o_receive_request` + `:398`/`:425` | P | Цикл 4096 и EINTR есть; обработка `-EAFNOSUPPORT/-EOPNOTSUPP` для правил только для IPv6 (r2o_route.rs:406), для IPv4 — ошибка; C трактует пустым для обоих. |
| dump_rules | 61-67 | 7 | static: дамп правил family | `r2o_route.rs:398` `r2o_dump_rules` | P | Предел 32 правила (R2O_ROUTE_RULE_CAPACITY) против D2K_ROUTEMARK_MAX; тест на переполнение не найден. |
| lookup_route | 72-110 | 39 | static: один `RTM_GETROUTE`, коды 0/2/3 | `r2o_route.rs:425` `r2o_lookup_default` | P | Коды C (2 = маршрут без устройства, 3 = нет маршрута) сведены к `R2oRouteLookup`; соответствие проверено только парсером, не живым ядром. |
| dump_socket | 115-128 | 14 | static: netlink-сокет с `SO_RCVTIMEO` 200 мс | `r2o_route.rs:455-493` (socket + SO_RCVTIMEO в `r2o_receive_request`) | E | `r2o_монитор_читает_правила_и_маршрут_текущего_ядра` (r2o_route.rs:1240) проходит при доступном rtnetlink. |
| d2k_routemark_load | 130-177 | 48 | загрузить правила v4/v6 + маршруты, каждую часть независимо | `r2o_route.rs:372` `r2o_refresh` | P | Независимость семейств есть; C пересоздаёт сокет после ошибки части, R2O создаёт новый сокет на каждый запрос; `routes4_ok/routes6_ok` наружу не отдаются. |
| d2k_routemark_watch_open | 179-209 | 31 | подписка на 4 группы (IPv4 обязательны) | `r2o_route.rs:283` `r2o_open_watch` | P | `r2o_монитор_читает_правила...` (r2o_route.rs:1240) вызывает `r2o_open_watch`, но результат намеренно не проверяется (`let _watch_opened = ...is_ok()`); обязательность IPv4-групп тестом не подтверждена. |
| d2k_routemark_watch_drain | 211-228 | 18 | ограниченный слив уведомлений, ENOBUFS → обновить | `r2o_route.rs:334` `r2o_drain_watch` | P | R2O: 256 чтений, ENOBUFS → `changed=true`, EAGAIN → выход; C при достижении предела возвращает 1. Поведение на границе не тестировано. |

Итог по файлу: E 2, P 6, N 0. Пробелы: обработка `EAFNOSUPPORT` для IPv4-правил, лимит
правил, внешние коды `load`, обязательность IPv4-групп подписки.

---

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
   реализован в цикле; `SET_HTTPS` отвергает TTL > max вместо обрезки; ARM_SHAPE не
   обслуживает UDP; v22 CLIENT_TCP идёт с пустыми TCP-опциями.
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


---

# Группа `detect`

# Аудит паритета: detect — измеритель DPI (D2O C → R2O Rust)

Дата: 2026-11-11. Проход только по исходникам: код не менялся, роутер не затрагивался.

## Baseline

- D2O (oracle): `E:\d2o-a378w`, SHA `a378e230947ebfd011439e1cac0f1e994d883aae`.
- R2O: `E:\r2o`, HEAD `9272eafa7992e88dff99cd25056e93157008a3d5` (ветка `main`).
  Ссылки на строки даны по рабочему дереву; в нём возможны незакоммиченные правки других сессий.
- Срез: E:\r2o-tooling\audit\slice-detect.csv — **159 функций** из 9 файлов:
  `detect/raw.c` (62), `detect/classify.c` (36), `detect/bridge.c` (17), `detect/poison.c` (12),
  `detect/trigger.c` (9), `detect/main.c` (8), `detect/props.c` (7), `detect/response.c` (7),
  `detect/include/d2k_detect.h` (1).
- Метод: прочитано тело каждой функции `line..end_line`; Rust-аналоги искались по всему
  `crates/`, а не только по кандидатам CSV; проверялись ветви, коды ошибок, таймауты,
  отмена и побочные эффекты.

> Ограничение этого прохода: `git` и `cargo` в среде отсутствуют, тесты **не запускались**.
> Статус E означает «Rust-реализация совпадает по разобранным ветвям и в дереве есть
> профильный юнит-тест или C/Rust-дифференциал, названный в колонке доказательства».
> Факт успешного прогона теста здесь не заявляется; production- и аппаратные сценарии
> (реальный DPI, OpenWrt/musl, mipsel) не проверялись.

## Статусы

- **E** — эквивалент: есть Rust-реализация, разобранные ветви совпадают, есть профильный тест/дифференциал.
- **P** — реализовано, но не все ветви/края доказаны, либо форма реализации иная (часть поведения перенесена).
- **N** — реализации нет.
- **?** — не установлено.

Static-хелперы наследуют статус владельца; в колонке R2O у них указано место, куда логика встроена.
Размер — тело функции в байтах UTF-8 по срезу.

## Сводка

| Статус | Кол-во |
|---|---:|
| E | 49 |
| P | 98 |
| N | 12 |
| ? | 0 |
| **Всего** | **159** |

Доли: E — 30.8 % (49/159); E или P — 92.5 % (147/159); N — 7.5 % (12/159).
P не считается доказанным паритетом: это покрытие без полного доказательства ветвей.

По файлам:

| Файл | Функций | E | P | N |
|---|---:|---:|---:|---:|
| detect/bridge.c | 17 | 2 | 13 | 2 |
| detect/classify.c | 36 | 16 | 18 | 2 |
| detect/main.c | 8 | 0 | 8 | 0 |
| detect/poison.c | 12 | 8 | 4 | 0 |
| detect/props.c | 7 | 0 | 7 | 0 |
| detect/raw.c | 62 | 13 | 42 | 7 |
| detect/response.c | 7 | 7 | 0 | 0 |
| detect/trigger.c | 9 | 3 | 5 | 1 |
| detect/include/d2k_detect.h | 1 | 0 | 1 | 0 |
| **Всего** | **159** | **49** | **98** | **12** |

---

## 1. detect/bridge.c — 17 функций

Мост между планировщиком d2k и перенесённым измерителем: вход из `d2k_hello`, запуск дерева,
перевод вердикта и находки в `d2k_vres`, прогресс и вопросы свойств. В R2O этот слой не выделен:
его роль играет discovery-конвейер `main.rs` (вызов классификатора, seed базового вопроса,
гейты `r2o_discovery_split_gate`/`search_owned`) плюс `classify.rs`. Поэтому здесь много P:
поведение есть, но не одним символом с тем же контрактом. Дифференциалы есть для клона приманки,
фильтра невыразимых находок и гейта socket-only split (`scripts/r2o-measured-split-differential.sh`,
`scripts/r2o-bridge-clone-decoy-differential.sh`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_detect_stop_all` | 45-45 | 50 | липкий общий флаг остановки службы | — | N | глобального stop-all нет: отмена только через AtomicBool задачи |
| `stop_asked` | 50-55 | 156 | две причины броска: флаг задачи и службы | classify.rs:1041 stopped, raw_probe.rs:641 is_cancelled | P | один AtomicBool вместо двух источников; общего флага службы нет |
| `plannable_hit` | 76-93 | 540 | фильтр находок: невыразимое планом не обрывает перебор | raw_probe.rs:1122 executable_poison_hit, classify.rs:1252 append_reason | E | tests/classify.rs:599 accepted_but_unplannable_poison_keeps_opaque_verdict_and_search_ownership; scripts/r2o-measured-split-differential.sh |
| `map_verdict` | 95-112 | 953 | перевод D2K_DV_* в D2K_V_* | classify.rs:894 Verdict, :1657 ветка Poisonable | P | единое перечисление; отдельного второго enum и таблицы соответствия нет |
| `bridge_input` | 116-255 | 8964 | сборка входа измерителя из d2k_hello | main.rs:15396-15466 discovery adapter, raw_probe.rs:602 select_bridge_decoy | P | клон-приманка дифференцирован (raw_probe.rs:2235), адаптер целиком не покрыт |
| `progress_seen` | 261-273 | 653 | ход вопросов планировщику | main.rs:10573 closure + update_probe_progress | P | подавление seeded-whole не реализовано, счётчики seed печатаются повторно |
| `trace_questions` | 284-309 | 1043 | qtrace вопросов свойств в d2k_vres | — | N | qtrace-аналога нет; наблюдения остаются в ClassifyResult.trace |
| `retry_base_timeout` | 314-316 | 139 | распознать наш dial timeout для seed | classify.rs:1244 is_dial_timeout_text | E | tests/classify.rs:796 only_our_connect_deadline_gets_one_doubled_retry_and_stays_flaky |
| `sched_tcp` | 320-463 | 8837 | полный прогон, вердикт и плечо планировщику | main.rs:15396 discovery pipeline, 6229-6256 гейты | P | notes/qtrace/owns_search перенесены частично, единого символа нет |
| `d2k_detect_sched_tcp` | 466-474 | 446 | крючок планировщика без white | main.rs:15396 | P | отдельного крючка нет, один путь discovery |
| `d2k_detect_sched_tcp_white` | 478-485 | 468 | крючок с ECH-приманкой | main.rs:15460 white + 15396 | P | приманка есть, отдельного символа нет |
| `d2k_detect_sched_tcp_seeded` | 488-497 | 545 | крючок с seed базового вопроса | classify.rs:1842 run_base + main.rs:10634 seed | P | seed перенесён, отдельного крючка нет |
| `d2k_detect_sched_tcp_seeded_white` | 503-511 | 573 | seed и white одновременно | classify.rs:1842 + main.rs:15460/15396 | P | оба входа есть, отдельного крючка нет |
| `base_seen` | 531-535 | 160 | отметка, что базовый вопрос задан | classify.rs:1842 run_base_with_backend_progress | P | run_base спрашивает только базу, колбэка отметки нет |
| `base_stop` | 537-541 | 136 | останов после базового вопроса | classify.rs:1842 | P | останов структурный, отдельного cancel-колбэка нет |
| `d2k_detect_sched_tcp_ack` | 548-573 | 889 | перепроверка мёртвого адреса | response.rs:898 probe_neutral_ack, classify.rs:1588 | P | тест tests/classify.rs:679; отдельного hook-символа с probes нет |
| `d2k_detect_sched_tcp_base` | 575-641 | 3012 | отдельный базовый вопрос с вердиктом | classify.rs:1842 run_base_with_backend_progress | P | BaseProbe{seed,blocked,probes}; вердикт и причина не возвращаются |

## 2. detect/classify.c — 36 функций

Ядро дерева: триггер, опции, трасса, measure, самопроверка сырого слоя, перебор и итоговый вердикт.
Сильные места R2O: `measure`, `split_offsets`, `trigger_accepts`, нейтральный ACK и кэш самопроверки
покрыты тестами и C/Rust-дифференциалами. Слабые: нет `notes`/`covers_tls12`, нет trace о непринятом
правиле RST, текст причины при отказе сырого слоя и счёт probes ответного направления отличаются,
`note_gap_loss` отсутствует вовсе.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_verdict_name` | 57-72 | 604 | имя вердикта дерева | classify.rs:907 Verdict::as_str | E | прямой switch; tests/classify.rs:1025 проверяет clear/inconclusive |
| `d2k_resp_name` | 74-82 | 255 | имя вердикта ответного направления | classify_json.rs:103-109, main.rs:1278-1283 | P | английские имена разнесены по двум местам, теста имён нет |
| `d2k_now_ms` | 86-91 | 188 | монотонное время в мс | Instant (classify.rs:1307, 1937) | P | инъекции d2k_clock_offset_ms нет |
| `d2k_sleep_ms` | 96-105 | 194 | пауза между сегментами | thread::sleep (raw_probe.rs:1238, response.rs:856) | P | отдельного символа нет, семантика nanosleep совпадает |
| `d2k_trigger_accepts` | 109-124 | 903 | критерий прохода по типу accept | classify.rs:543 trigger_accepts | E | tests/classify.rs:833 trigger_acceptance_matches_the_donor_rules |
| `d2k_trigger_sni` | 126-134 | 236 | извлечь SNI из имени триггера | classify.rs:1461 strip_prefix("tls:") | P | inline strip_prefix; прямого теста нет, ответная ветка CLI-теста может не дойти |
| `d2k_detect_stopped` | 136-139 | 92 | проверка отмены | classify.rs:1041 stopped, raw_probe.rs:641 is_cancelled | E | tests/classify.rs:818 и cancellation_after_* в classify.rs:2596+ |
| `d2k_opts_defaults` | 141-162 | 815 | умолчания повторов, сроков и метки | classify.rs:860 Default, 1888 configured_options | P | метка по умолчанию 0x2d вместо 0x40000000 (datapath-detect-audit.md, п. 14) |
| `d2k_opts_acceptable` | 164-170 | 153 | фильтр приемлемости находки | raw_probe.rs:1122 executable_poison_hit | P | общего колбэка accept нет; в CLI R2O фильтр плана включён всегда, в C CLI accept не задан |
| `d2k_opts_skipped` | 172-181 | 206 | пропуск гипотезы по имени | classify.rs:885 poison_selected | P | --only/--skip сведены в одну функцию, профильного теста нет |
| `d2k_trace_add` | 183-204 | 1018 | добавить наблюдение в трассу | classify.rs:1048 add_observation | E | tests/classify.rs:384 classifier_reports_each_question_and_probe_as_it_runs |
| `obs_done` | 210-215 | 133 | объявить наблюдение наружу | classify.rs:1235 progress callback | E | tests/classify.rs:384; колбэк вызывается в measure |
| `d2k_note` | 217-227 | 264 | добавить оговорку к результату | classify.rs:1248 append_reason | P | поля notes нет, текст уходит в reason |
| `note_gap_loss` | 238-247 | 504 | предупреждение о потере паузы между копиями | — | N | такой оговорки в R2O нет |
| `d2k_split_offsets` | 253-287 | 915 | точки разреза в диапазоны | classify.rs:28 split_offsets | E | tests/classify.rs:337, :349, :361 |
| `dial_marked_mode` | 292-364 | 2591 | помеченное TCP-соединение | response.rs:723 dial_probe_target, :289 probe_socket | P | ветка require_mark и различение отказа SO_MARK отсутствуют |
| `d2k_dial_deadline_err` | 368-374 | 183 | признак нашего срока соединения | classify.rs:1244 is_dial_timeout_text, :575 ProbeError | E | tests/classify.rs:796 |
| `dial_marked` | 376-380 | 217 | обёртка соединения без require_mark | response.rs:723 dial_probe_target | P | отдельной обёртки нет, поведение то же |
| `once_probe` | 385-492 | 4437 | один зонд: запись триггера и ожидание ответа | response.rs:776 probe_trigger, :891 raw_split_enabled, raw_probe.rs:1140 probe_tcp_split | E | tests/classify.rs:957; response.rs:1476/1512 split/cancel; differentials meas_eintr |
| `unacked_bytes` | 499-518 | 388 | байты в очереди отправки | response.rs:953/963 unacked_bytes | E | TIOCOUTQ/SO_NWRITE; tests/classify.rs:990 |
| `d2k_probe_data_ack` | 520-586 | 2519 | подтверждение нейтрального байта | response.rs:898 probe_neutral_ack | E | tests/classify.rs:990 live_neutral_ack_confirms_delivery_even_when_control_is_silent |
| `measure` | 608-710 | 4054 | повторы одного зонда и запись наблюдения | classify.rs:1076 measure | E | tests/classify.rs:535, :694, :732; seeded/progress |
| `bind_decoy` | 717-728 | 279 | привязать приманку и длину перекрытия | raw_probe.rs:203-231, :1047, classify_measured.rs:106 | P | привязка разнесена по местам, профильного теста нет |
| `answered_by_props` | 732-739 | 215 | не повторять гипотезу, уже отвеченную свойствами | raw_probe.rs:474 answered + same_hypothesis | P | логика есть, теста нет |
| `fam_ix` | 766-766 | 65 | индекс семейства для кэша selftest | raw_probe.rs:702/719 inline | P | отдельного хелпера нет |
| `self_ix` | 769-771 | 100 | индекс кэша (семейство, метка времени) | raw_probe.rs:719 raw_selftest_index | E | raw_probe.rs:2348 raw_syn_profile_matches_the_d2o_fixture (RAW_SELFTEST_KEY) |
| `selftest_cached_age` | 774-789 | 445 | возраст кэша самопроверки | raw_probe.rs:685 raw_selftest_age | P | TTL 600 с совпадает, теста возраста нет |
| `selftest_store` | 791-799 | 282 | записать исход самопроверки в кэш | raw_probe.rs:735 store_raw_selftest | E | raw_probe.rs:2348 (RAW_SELFTEST_INVALIDATION) |
| `d2k_raw_note_rc` | 801-823 | 1035 | счётчики и серия ошибок сырого слоя | raw_probe.rs:701 note_raw_probe | E | raw_probe.rs:701 + локальные raw_ok/raw_errors (:99-100); raw_probe.rs:2348 (RAW_SELFTEST_INVALIDATION) |
| `raw_selftest` | 827-854 | 943 | самопроверка сырого слоя | raw_probe.rs:120-186 | P | цикл встроен в sweep, отдельного теста цикла нет |
| `raw_doubted` | 860-863 | 141 | пора перепроверить кэш | raw_probe.rs:669 should_recheck | E | self-тест raw_probe.rs:2513 raw_selftest_recheck_requires_a_cached_check_and_zero_successes |
| `raw_recheck` | 867-880 | 544 | немедленная перепроверка слоя | raw_probe.rs:746 raw_recheck | E | raw_probe.rs:2513 + R2O_RAW_RECHECK_C_OUTPUT |
| `sweep_poisons` | 887-1076 | 8251 | перебор: свойства, сборка, список гипотез | raw_probe.rs:78 sweep_poisons | P | нет trace о непринятом RST-правиле, иной текст selftest, compose без контроля |
| `cross_check_tls12` | 1084-1092 | 367 | проверка покрытия TLS 1.2 | — | N | C-заглушка не перенесена, поля covers_tls12 нет |
| `d2k_classify_run` | 1095-1476 | 22179 | дерево зондов и вердикт | classify.rs:1298 run_with_backend_progress | P | нет notes/covers_tls12, иной счёт probes ответного направления |
| `d2k_send_nosig` | 1481-1494 | 309 | запись без SIGPIPE | libc::send MSG_NOSIGNAL (response.rs:815/1100) | P | ветки SO_NOSIGPIPE для macOS нет |

## 3. detect/main.c — 8 функций

CLI `d2k-detect` и форматы вывода. R2O использует другой интерфейс (`r2o-controller --classify HOST PORT`),
поэтому соответствие функциональное, а не построчное. В JSON R2O нет массива `notes` и поля `covers_tls12`,
порядок ключей и форма `response` иные; в человеческом отчёте нет блока свойств коробки и оговорок.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `usage` | 19-49 | 3084 | справка CLI | main.rs:1721-1739 help | P | форма CLI иная (--classify вместо подкоманды), текст другой |
| `print_json_str` | 51-65 | 338 | экранирование JSON-строки | serde_json (classify_json.rs:71) | P | наследует print_json, прямого теста нет |
| `print_tri` | 67-73 | 181 | необязательное трёхзначное поле | classify_json.rs:4 insert_tri_state | P | наследует print_json |
| `print_json` | 75-187 | 4176 | JSON-отчёт | classify_json.rs:18 result_json_value | P | нет notes и covers_tls12; порядок ключей иной (serde_json сортирует), тексты причин иные |
| `print_progress` | 193-199 | 271 | прогресс зондов в stderr | main.rs:1187 report_progress | P | без столбца err, печатаются только завершённые наблюдения |
| `tri_word` | 201-205 | 156 | слово для трёхзначного свойства | main.rs:811 r2o_tri_state | P | теста нет |
| `print_human` | 207-275 | 3700 | человеческий отчёт | main.rs:1254-1302 | P | нет блока свойств, notes и имени/длины триггера |
| `main` | 277-450 | 8186 | CLI классификатора | main.rs:1104-1306, 1555/1586 | P | флаг --classify вместо подкоманды, часть флагов и умолчаний иная |

## 4. detect/poison.c — 12 функций

Каталог гипотез и перевод находки в строку стратегии/язык плана. Порядок и состав 85 гипотез совпадают
и закреплены тестом. `poison_has_fake` и `arm_from_poison` не знают осей `autottl`/`tcp_ts_up`,
которые есть в C-структуре; на текущем каталоге это не проявляется, но функция не эквивалентна для
произвольного `d2k_poison`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_poison_supports_family` | 17-22 | 290 | допустимость гипотезы для семейства | classify.rs:389 poison_supports_family | E | tests/classify.rs:861 (проверка ipid на IPv6) |
| `d2k_poison_has_fake` | 24-40 | 1239 | несёт ли гипотеза фальшивку | classify.rs:382 poison_has_fake | P | не учитывает autottl (datapath-detect-audit.md, п. 13), тест покрывает badsum/ts |
| `add` | 47-60 | 335 | добавить гипотезу в список | classify.rs:215 add_poison | E | tests/classify.rs:861 порядок и 85 записей |
| `d2k_poison_same` | 62-70 | 300 | сравнение гипотез без имени | classify.rs:200 same_hypothesis | P | C сравнивает memcmp с указателем decoy, Rust — поля |
| `already_listed` | 73-82 | 248 | отсев уже перечисленной гипотезы | classify.rs:327-330 | E | tests/classify.rs:861 все 85 уникальны |
| `init_poisons` | 84-180 | 5674 | полный список гипотез в порядке стоимости | classify.rs:223 build_poisons | E | tests/classify.rs:861 |
| `d2k_poisons` | 182-189 | 284 | неизменяемый список гипотез | classify.rs:377 poisons | E | tests/classify.rs:861 |
| `d2k_note_props_hit` | 194-208 | 540 | свойства по проходу гипотезы | classify.rs:173 note_props_hit | E | tests/classify.rs:907 poison_outcomes_update_only_properties_they_prove |
| `d2k_note_props_miss` | 216-223 | 242 | свойства по промаху гипотезы | classify.rs:189 note_props_miss | E | tests/classify.rs:907 |
| `d2k_strategy_for_poison` | 226-398 | 7211 | строка стратегии nfqws2 | classify.rs:394 strategy_for_poison | E | tests/classify.rs:879; raw emission differential |
| `d2k_strategy_for` | 401-404 | 144 | стратегия разреза unknown | classify.rs:1933 strategy_for | P | теста строки нет |
| `d2k_arm_from_poison` | 413-475 | 4050 | перевод гипотезы в язык плана | classify_measured.rs:30 plan_text_for_poison, :50 measured_plan_text, r2k-core plan.rs | P | дифференцированы split и badsum, не все поля и отказы |

## 5. detect/props.c — 7 функций

Вопросы о свойствах и сборка кандидатов из вектора. В R2O цикл вопросов и `compose_from_props`
встроены в `raw_probe::sweep_poisons`; отдельного дифференциала на весь список вопросов нет,
покрыт только составной ECH-вопрос и перепроверка самопроверки. Расхождение: при `control = None`
C всё равно выдаёт кандидат «всё сразу», R2O его не выдаёт.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `prop_probes` | 49-196 | 9436 | 12 вопросов о свойствах | raw_probe.rs:840 property_probes | P | состав совпадает, полного differential списка нет |
| `apply_set` | 198-257 | 2251 | запись ответа вопроса в вектор | raw_probe.rs:1005 apply_property | P | тест покрывает только white-ts |
| `d2k_run_properties` | 261-265 | 216 | обёртка вопросов для IPv4 | raw_probe.rs:85-87 (семейство из адреса) | P | отдельной обёртки нет: семейство всегда берётся из адреса цели |
| `d2k_run_properties_family` | 267-416 | 9648 | цикл вопросов о свойствах | raw_probe.rs:189-345 | P | логика встроена в sweep, не выделена |
| `tri_no` | 418-418 | 60 | проверка «нет» | inline == TriState::False | P | хелпер заменён сравнением |
| `tri_yes` | 419-419 | 59 | проверка «да» | inline == TriState::True | P | хелпер заменён сравнением |
| `d2k_compose_from_props` | 426-498 | 3144 | сборка кандидатов из вектора свойств | raw_probe.rs:1047 compose_from_props | P | при control=None C выдаёт «всё сразу», R2O не выдаёт |

## 6. detect/raw.c — 62 функции

Сырой слой: свой TCP, правило подавления RST, сборка пакетов и исполнение измеренного плана.
Сильная часть — пакетные строители, SYN-профиль и исполнение плана: есть C/Rust-дифференциалы
(`r2o-raw-emission-cancel-differential.sh`, `r2o-raw-profile-differential.sh`). Слабая — уборка
брошенных правил: R2O не разбирает строки iptables, чистит только собственный тег `r2o-rst`,
не знает legacy-формы без комментария и не проверяет диапазон портов 30000..54999.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `parse_long_exact` | 63-77 | 397 | точный разбор числа из строки правила | inline str::parse (raw_probe.rs:1788/1800) | P | без проверки начала/конца и диапазона |
| `d2k_parse_rst_rule` | 79-118 | 1719 | разбор строки правила подавления RST | — | N | разбора строк iptables в R2O нет |
| `d2k_parse_stale_rst_rule` | 121-124 | 110 | прежний вход разбора правила | — | N | нет |
| `pid_alive` | 128-132 | 149 | жив ли владелец правила | raw_probe.rs:1791 libc::kill | P | inline, EPERM считается живым |
| `d2k_rst_rule_stale` | 137-143 | 216 | брошенное ли правило по владельцу | — | N | нет классификации по владельцу |
| `d2k_raw_supported` | 164-164 | 41 | есть ли сырой слой | raw_probe.rs:63 raw_supported | P | фактическая проба сокета вместо константы 1 |
| `raw_rule_system` | 224-255 | 1285 | команда правила со сроком | raw_probe.rs:1285 run_command | P | без kill группы процессов, только ребёнок |
| `d2k_raw_rst_fail_count` | 262-262 | 74 | отказы вставки правила (поток) | raw_probe.rs:54 rst_rule_failure_count | E | raw_probe.rs:2770 rst_rule_failure_counts_are_per_worker_thread |
| `d2k_raw_dial_count` | 263-263 | 62 | число сырых соединений (поток) | raw_probe.rs:58 raw_dial_count | P | теста счётчика нет |
| `seed_init` | 265-269 | 153 | инициализация ГСЧ и порта | raw_probe.rs:1419 random_u32, :1439 OnceLock | P | getrandom вместо srandom |
| `seed_once` | 271-274 | 74 | однократная инициализация | raw_probe.rs:1439 OnceLock | P | OnceLock |
| `next_source_port` | 283-292 | 252 | исходный порт сырого зонда | raw_probe.rs:1441 next_source_port | P | диапазон 30000..54999 совпадает, теста нет |
| `rst_nft` | 313-317 | 108 | режим nftables | raw_probe.rs:1496 r2o_rst_uses_nft | P | переменная R2O_FW вместо D2K_FW |
| `sweep_stale_rst_rules` | 319-348 | 992 | уборка брошенных правил | raw_probe.rs:1749 sweep_stale_iptables | P | только тег r2o-rst, без legacy-формы и диапазона портов |
| `rst_rule_cmd_form` | 382-400 | 1165 | команда вставки/снятия правила | raw_probe.rs:1561 nft_args, :1586 iptables_args | P | тег r2o-rst и таблица r2o_rst вместо d2k |
| `rst_rule_cmd` | 402-405 | 113 | команда правила с текущей формой | raw_probe.rs:1561/1586 | P | отдельной функции нет |
| `rc_exit1` | 407-410 | 91 | код «правила нет» | inline status.code()==Some(1) | P | inline |
| `rst_delete_once` | 416-422 | 188 | снять правило, проверив -C | raw_probe.rs:1638 rst_delete_once_locked | P | есть nft-тест, iptables -D/-C не покрыт |
| `rst_abandon` | 424-434 | 651 | сообщить об отказе от повторов | raw_probe.rs:1690-1718 RST_ABANDON_REPORTED | P | текст и точка вызова иные |
| `register_atexit` | 437-437 | 63 | регистрация выхода | raw_probe.rs:1739 register_rst_cleanup | P | libc::atexit |
| `rst_remember` | 440-450 | 335 | запомнить неснятое правило | raw_probe.rs:1681-1693 rst_release | P | предел 64 совпадает |
| `retry_pending_releases` | 454-468 | 498 | повтор отложенных снятий | raw_probe.rs:1697 retry_pending_rst_releases_locked | P | логика совпадает, теста нет |
| `rst_release_locked` | 471-476 | 140 | снять сразу дважды или запомнить | raw_probe.rs:1675 rst_release | P | логика совпадает |
| `d2k_raw_flush_pending` | 481-486 | 166 | снять отложенное перед прогоном | raw_probe.rs:1745 flush_pending_rst_releases | P | теста нет |
| `d2k_raw_pending_count` | 488-495 | 169 | число отложенных снятий | — | N | геттера нет |
| `raw_atexit` | 497-504 | 381 | снятие при выходе | raw_probe.rs:1735 rst_cleanup_at_exit | P | без trylock (мьютекс блокирующий) |
| `rst_key_of` | 506-515 | 232 | ключ кортежа правила | поля RstRule (raw_probe.rs:1478-1485) | P | структура собирается на месте |
| `suppress_kernel_rst` | 517-545 | 1469 | подавление ядерного RST | raw_probe.rs:1501 RstRule::install, :1613 RstGuard::install | P | нет снятия правила после таймаута команды |
| `release_kernel_rst` | 547-553 | 190 | снять подавление | raw_probe.rs:1630 Drop for RstGuard | P | через Drop |
| `local_addr_for` | 556-596 | 1254 | свой адрес к цели | raw_probe.rs:1463 local_address_for | P | UDP connect, как в C |
| `rd16` | 598-598 | 81 | чтение big-endian u16 | u16::from_be_bytes (raw_probe.rs:2107/2140) | E | владелец build_ip_tcp; raw_probe.rs:2550 differential |
| `rd32` | 600-604 | 154 | чтение big-endian u32 | u32::from_be_bytes (raw_probe.rs:2148) | E | владелец build_ip_tcp |
| `wr16` | 606-606 | 89 | запись big-endian u16 | r2k-core wire.rs:552 write_u16, build_control_packet:1405 | E | владелец build_ip_tcp |
| `wr32` | 608-612 | 152 | запись big-endian u32 | r2k-core wire.rs:556 write_u32, build_control_packet:1407 | E | владелец build_ip_tcp |
| `checksum` | 614-628 | 342 | контрольная сумма IP | raw_probe.rs:1308 internet_checksum, wire.rs:534 sum16 | E | raw_probe.rs:2870 builds_an_ipv4_syn_with_valid_ip_and_tcp_checksums |
| `tcp_checksum` | 630-648 | 723 | контрольная сумма TCP | raw_probe.rs:1328 tcp_checksum | E | raw_probe.rs:2870/2896 |
| `build_ipv4_tcp` | 652-736 | 2739 | сборка IPv4/TCP пакета | raw_probe.rs:1350 build_control_packet, wire.rs:18 build_tcp_packet | E | raw_probe.rs:2550 measured_tcp_split_wire_packets_match_donor |
| `tcp_checksum_family` | 738-747 | 447 | контрольная сумма TCP для IPv4/IPv6 | raw_probe.rs:1328 (псевдозаголовок IPv6), wire.rs:516 pseudo_sum | E | raw_probe.rs:2896 builds_an_ipv6_syn_with_valid_tcp_checksum |
| `build_ip_tcp` | 750-771 | 1183 | сборка IP/TCP любого семейства | raw_probe.rs:1350 (IPv4/IPv6) | E | raw_probe.rs:2550/2896 |
| `raw_sendto` | 773-791 | 629 | отправка собранного пакета | raw_probe.rs:2002 send_ip_packet | P | сокетного теста нет |
| `d2k_raw_set_segment_max` | 814-814 | 89 | потолок сегмента под датапат | — | N | фиксированные 1400 (classify_measured.rs:12), сеттера нет |
| `raw_send` | 830-858 | 847 | запись нагрузки на провод | raw_probe.rs:1213 (план), :1195 (syn_data) | P | плановый путь E, syn_data шлётся одним пакетом вместо нарезки |
| `raw_send_syn` | 864-896 | 1552 | SYN с профилем опций клиента | raw_probe.rs:723 raw_syn_options, :1953 SYN | E | scripts/r2o-raw-profile-differential.sh, RAW_SYN_PROFILE |
| `raw_recv` | 900-949 | 1970 | приём и фильтрация сегмента | raw_probe.rs:2041 receive_segment | P | фильтрация строже (длины, фрагменты, локальный адрес) |
| `raw_read_payload` | 952-988 | 1590 | ожидание данных с якорем seq | raw_probe.rs:2156 read_payload | P | якорь реализован, профильного теста нет |
| `raw_close` | 990-1006 | 336 | закрыть сокеты и снять правило | Drop RawConn/RstGuard | P | через Drop |
| `raw_handshake` | 1008-1089 | 3623 | своё рукопожатие с RTO и эхом метки | raw_probe.rs:1941-1999 | P | RTO/эхо есть, теста ретрансмита SYN нет |
| `raw_dial` | 1092-1180 | 4262 | поднять сырое соединение | raw_probe.rs:1841 RawConn::connect | P | полного сетевого теста нет |
| `d2k_raw_probe_handshake_as` | 1187-1197 | 465 | самопроверка рукопожатия | RawConn::connect (raw_probe.rs:136) | P | используется в selftest, отдельного теста нет |
| `raw_send_plan` | 1209-1262 | 2910 | исполнить измеренный план | raw_probe.rs:1213-1259, :1267 emit_plan_packets, r2k-core plan.rs:190 Plan::parse | E | scripts/r2o-raw-emission-cancel-differential.sh; raw_probe.rs:2550/2819 |
| `d2k_raw_probe_poison_family` | 1272-1321 | 1828 | один зонд отравления | raw_probe.rs:1174 raw_probe_once | P | плановая часть покрыта, сетевой путь нет |
| `d2k_raw_supported` | 1328-1328 | 41 | stub вне Linux | classify.rs:751-754 cfg(not(linux)) | P | возвращает false через cfg |
| `d2k_raw_set_segment_max` | 1329-1329 | 57 | stub вне Linux | — | N | сеттера нет и в Linux-ветке |
| `d2k_raw_rst_fail_count` | 1330-1330 | 56 | stub вне Linux | raw_probe.rs:54 | E | тот же счётчик, что в Linux-ветке; raw_probe.rs:2770 |
| `d2k_raw_dial_count` | 1331-1331 | 52 | stub вне Linux | raw_probe.rs:58 | P | thread-local счётчик |
| `d2k_raw_flush_pending` | 1332-1332 | 35 | stub вне Linux | raw_probe.rs:1745 | P | функция есть |
| `d2k_raw_pending_count` | 1333-1333 | 48 | stub вне Linux | — | N | геттера нет |
| `d2k_raw_probe_poison_family` | 1335-1343 | 513 | stub вне Linux | classify.rs:764-772 cfg(not(linux)) | P | sweep возвращает None |
| `d2k_raw_probe_handshake_as` | 1345-1353 | 464 | stub вне Linux | classify.rs:746-754 cfg(not(linux)) | P | сырой слой отключён |
| `d2k_raw_probe_handshake` | 1357-1361 | 256 | обёртка IPv4 | raw_probe.rs:1174 | P | отдельного символа нет |
| `d2k_raw_probe_handshake_family` | 1364-1370 | 371 | рукопожатие с профилем метки | raw_probe.rs:1174/1841 | P | offer_ts всегда передаёт вызывающий |
| `d2k_raw_probe_poison` | 1372-1377 | 305 | обёртка IPv4 | raw_probe.rs:1174 | P | отдельного символа нет |

## 7. detect/response.c — 7 функций

Ответное направление TLS 1.2. Самый закрытый файл среза: разбор потока записей, рукопожатие,
счёт серии, нейтральное имя и решение покрыты юнит-тестами и общими C-векторами
(`tests/fixtures/d2o/tls-response-vectors.tsv`, `d2o_response_fixture.c`, EINTR-дифференциал).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `resp_timeout` | 64-70 | 160 | потолок одного рукопожатия 3 с | response.rs:164 response_timeout | E | tests/response.rs:649 full probe |
| `d2k_resp_scan12` | 83-118 | 996 | поиск ServerHelloDone/алерта в потоке | response.rs:1248 scan12 | E | tests/response.rs:122/138/479 (13 векторов) |
| `d2k_resp_handshake12` | 123-207 | 2623 | рукопожатие TLS 1.2 до ServerHelloDone | response.rs:1050 handshake | E | tests/response.rs:649, :555 |
| `count_handshakes` | 215-228 | 403 | счёт рукопожатий серии | response.rs:1148 count_handshakes | E | tests/response.rs:649 |
| `d2k_neutral_sni` | 233-269 | 1252 | случайное нейтральное имя | response.rs:1172 neutral_sni | E | tests/response.rs:203 loopback same-address control |
| `d2k_resp_decide` | 274-304 | 1957 | вердикт по счётчикам | response.rs:1304 decide | E | tests/response.rs:421, :479 |
| `d2k_probe_response` | 310-324 | 806 | проверка ответного направления | response.rs:1207 probe_response | E | tests/response.rs:649, :780 |

## 8. detect/trigger.c — 9 функций

Чем меряем: ClientHello из снятого профиля, произвольный hex, контроль, приманка и вопрос о метке
времени клиента. Байты приветствий совпадают с C побайтно (тесты `tests/hello.rs`). Контроль и
разбор TCP-опций клиента в R2O перенесены не как отдельные функции: контроль собран в CLI,
признак метки передаётся булевым `client_tcp_has_timestamps`, переопределения нет.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_trigger_tls` | 21-50 | 1378 | ClientHello из снятого профиля с SNI | classify.rs:87 Trigger::tls, :96 Trigger::tls13, hello.rs:549 | E | tests/hello.rs:42 legacy и :50 modern byte-for-byte, :62 fake, tests/classify.rs:946; смещения SNI пересчитываются hello::sni_bounds |
| `hexval` | 52-58 | 203 | значение hex-цифры | trigger.rs:11 inline | E | tests/trigger.rs:41 |
| `d2k_trigger_raw_hex` | 67-108 | 1322 | триггер из hex-строки | classify.rs:77 Trigger::raw_hex, trigger.rs:4 parse_raw_hex | E | tests/trigger.rs:41-58 |
| `d2k_trigger_control` | 118-128 | 376 | заведомо безобидный контроль | main.rs:1555 classify_control_trigger | P | только на уровне CLI; имя и accept совпали |
| `d2k_opts_decoy` | 130-136 | 153 | приманка: decoy или контроль | raw_probe.rs:602 select_bridge_decoy | P | отдельного opt.decoy нет, fallback на контроль есть |
| `d2k_trigger_host_ts_override` | 156-156 | 66 | переопределение «стек предлагает метку» | — | N | сеттера нет |
| `host_offers_ts` | 158-178 | 638 | читает tcp_timestamps один раз | raw_probe.rs:673 raw_offer_timestamps | P | OnceLock, без override |
| `d2k_trigger_offers_ts` | 180-199 | 615 | предлагает ли клиент метку времени | raw_probe.rs:673/731 | P | передаётся bool из снятого профиля, байты опций не разбираются |
| `d2k_trigger_allows_poison` | 201-207 | 165 | совместима ли гипотеза с профилем клиента | raw_probe.rs:731 raw_profile_allows, :967 fallback | P | та же логика в иной форме |

## 9. detect/include/d2k_detect.h — 1 функция

Единственная функция заголовка — правило большинства для вопросов о свойствах.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_prop_majority` | 490-493 | 108 | большинство повторов | raw_probe.rs:665 majority | P | формула совпадает, отдельного теста нет; владелец — цикл свойств (P) |

---

## Главные пробелы (N)

12 строк среза соответствуют 10 отсутствующим функциям: пары Linux/#else в `raw.c` дают дубли
у `pending_count` и `set_segment_max`.

1. `d2k_detect_stop_all` — нет общего липкого флага остановки службы; отмена только по задаче.
2. `trace_questions` — нет `qtrace`-аналога: ответы вопросов остаются в `ClassifyResult.trace` и не уходят планировщику как отдельный журнал.
3. `note_gap_loss` — нет оговорки о том, что найденный приём опирался на паузу между копиями.
4. `cross_check_tls12` и поле `covers_tls12` — не перенесены (в C это честная заглушка).
5. `d2k_parse_rst_rule`, `d2k_parse_stale_rst_rule`, `d2k_rst_rule_stale` — R2O не разбирает строки iptables и не снимает чужие/legacy-правила по владельцу.
6. `d2k_raw_pending_count` (обе ветки) — геттера отложенных снятий нет.
7. `d2k_raw_set_segment_max` (обе ветки) — потолок сегмента не настраивается: в плане жёстко 1400 (`classify_measured.rs:12`).
8. `d2k_trigger_host_ts_override` — нет переопределения «стек предлагает метку времени».

## Ключевые частичные пробелы (P)

- `sweep_poisons`/`d2k_classify_run`: нет `notes`, нет trace «правило подавления RST не встало», иной текст причины при отказе самопроверки, счёт probes ответного направления берётся из фактических попыток, а не `2 × repeats`.
- `d2k_compose_from_props`: при отсутствии контроля C выдаёт кандидат «всё сразу», R2O — нет.
- `raw_send`: `syndata` в R2O уходит одним пакетом, в C — нарезается по `seg_max`.
- `d2k_poison_has_fake`/`d2k_arm_from_poison`: не выражены оси `autottl` и `tcp_ts_up`.
- `d2k_trigger_offers_ts`: R2O получает булев признак из снятого профиля, а не разбирает байты TCP-опций триггера; произвольный набор опций не переносится.
- `main.c` целиком: интерфейс, человеческий отчёт и JSON расходятся по форме (см. таблицу).

## Проверки, выполненные в этой сессии

Агент-аудитор тесты не запускал. Дополнительно координатор прогнал на закреплённом
D2O `a378e230` и текущем R2O следующие differential-сценарии, которые покрывают
ядро `classify`/`trigger`/`response`/`raw`:

```text
test-classifier-white-decoy-differential.sh          PASS
test-classifier-full-tree-control-differential.sh    PASS
r2o-raw-profile-differential.sh                      PASS
r2o-fallback-differential.sh                         PASS
r2o-raw-connect-fallback-differential.sh             18/18 PASS
r2o-raw-split-support-differential.sh                PASS
test-controller-clienthello-differential.sh          56 кейсов PASS
r2o-tls-verify-differential.sh                       16/16 PASS
```

Эти прогоны подтверждают группу в целом, но не каждый E-ряд: если в колонке
доказательства назван другой тест, он помечен как «тест есть, прогон не
заявлен». Для строк, где E держится только на существовании теста, это
ограничение сохраняется.

## Уточнения к N-списку

- `cross_check_tls12` в C — честная заглушка (`detect/classify.c:1084`), поля
  `covers_tls12` в R2O нет; это не функциональный пробел обхода.
- `d2k_raw_pending_count` — только диагностический геттер отложенных снятий;
  на packet path не влияет.
- `d2k_raw_set_segment_max` — production-вызовов в D2O нет (grep по `detect/`,
  `files/`, `scripts/`), значение по умолчанию 1400 совпадает с R2O
  (`classify_measured.rs:12`). N относится к тестовому/CLI-сеттеру, а не к
  поведению живого датапата.
- `d2k_trigger_host_ts_override` — CLI/тестовое переопределение; в production
  вызовов нет, но для воспроизведения тестов D2O его отсутствие важно.
- `d2k_detect_stop_all` — глобальный липкий флаг; R2O отменяет задачу через
  `AtomicBool` (`classify.rs:603,1041`). Для одиночного CLI-прогона поведение
  эквивалентно, для «остановить все классификаторы» — нет.



## Ограничения проверки

- Тесты и дифференциалы в этом проходе не запускались: в среде нет `git`, `cargo`, компилятора C. Ссылки в колонке доказательства — на файлы и имена тестов, а не на результат прогона. Координатор дополнительно прогнал групповые differentials, перечисленные выше; это не отменяет ограничение для отдельных E-рядов.
- Не проверялись: реальный DPI-бокс, OpenWrt/musl и mipsel-сборка, поведение при нехватке прав на raw-сокет, гонки нескольких классификаторов на одном роутере, тайминги на живом канале.
- Пункты E по static-хелперам наследуют владельца: отдельного теста на сам хелпер может не быть.

## Итог

- Полностью подтверждено разбором и наличием профильного теста/дифференциала (E): **49 из 159 (30.8 %)**.
- Покрыто реализацией, но без полного доказательства ветвей (P): **98 из 159**.
- Не перенесено (N): **12 из 159 (7.5 %)**, но часть N — диагностические
  геттеры/CLI-сеттеры (`d2k_raw_pending_count`, `d2k_raw_set_segment_max`,
  `cross_check_tls12`), а не packet-path обход.
- Не установлено (?): **0**.
- Для паритета среза остаётся закрыть 12 N и доказать ветви у 98 P; один только факт наличия теста в дереве не заменяет прогон.
