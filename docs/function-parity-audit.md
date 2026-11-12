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

Проверены все пять групп, **1982 из 1982** функций:

| Группа | Функций | E | P | N | ? |
|---|---:|---:|---:|---:|---:|
| core-net | 548 | 226 | 308 | 13 | 1 |
| core-state | 692 | 127 | 564 | 1 | 0 |
| datapath-core | 400 | 120 | 269 | 11 | 0 |
| datapath-plan | 183 | 105 | 72 | 5 | 1 |
| detect | 159 | 49 | 100 | 10 | 0 |
| **Итого** | **1982** | **627** | **1313** | **40** | **2** |

Это не оценка паритета: 1313 P означают «код есть, доказательство ветвей
неполное», 40 N — в основном диагностические/CLI-функции и несколько реальных
расхождений (`SET_HTTPS` TTL, `ARM_SHAPE` UDP, `wire_udp` IPID_ZERO,
`udpruntime` raw UDP, `tls12/tls13` record-layer).

Статусы пересчитаны строго по колонке «статус»: описание вида «N цифр подряд»
больше не считается статусом, экранированные `\|` не сдвигают колонки.


## Итог и подтверждённые расхождения (2026-11-11)

Покрытие реестра: **1982/1982** функций. Статусы: **E 603 / P 1335 /
N 42 / ? 2**. Это не 100 % паритет: E требует целевого теста/дифференциала,
P означает неполное доказательство ветвей, N — отсутствие реализации.

| # | Область | D2O | R2O | Подтверждение |
|---|---|---|---|---|
| 1 | `SET_HTTPS` TTL | обрезает до **7 суток** (`d2k_ctl.h:231`, `ctlsrv.c:446`) | отвергает `> 6 часов` (`control.rs:64,1070,1781`) | `deep-detect-plan.md`, `deep-datapath-core.md` |
| 2 | `ARM_SHAPE` | принимает transport 6 и 17 (`ctlsrv.c:329`) | только 6 (`control.rs:2002`) | `deep-datapath-core.md` |
| 3 | `wire_udp` IPv4 | `POISON_IPID_ZERO` разрешён, ID=0 (`wire_udp.c:75,136`); TOS из пакета | любой poison отвергнут (`wire.rs:213`), TOS иной | C/Rust harness 4 poison-кейса |
| 4 | raw UDP/TTL | `IP_HDRINCL`+`IP_NODEFRAG`+TTL get/set/restore, `qp_recv_ttl` | `IP_NODEFRAG` отсутствует, TTL не принимается; датапат raw без controller API | `deep-core-net.md` |
| 5 | production classify | donor-семантика C | discovery: `full_detect_semantics=false`, `confirm_clear=true` (`classify.rs:869-870`, `main.rs:15380-15391`), дифференциалы идут с `true` | `deep-detect-plan.md` |
| 6 | `d2k_compose_from_props` | при `control=None` всегда «всё сразу» (`props.c:477-486`) | кандидат не выдаётся (`raw_probe.rs:1094-1096`) | `deep-detect-plan.md` |
| 7 | `d2k_raw_set_segment_max` | production `d2kc.c:575,789` ставит `d2k_arm_segment(send_maxlen)` | measured-план жёстко 1400 (`classify_measured.rs:12,143`) | `deep-detect-plan.md` |
| 8 | HTTP80 capacity | 128 потоков **с вытеснением** (`http80.h:40-41`, `http80.c:217-236`) | 1024 потока **без вытеснения** (`hold.rs:20,1080-1084`) | `deep-datapath-core.md` |
| 9 | ENOBUFS | TCP hold flush all, UDP — только истёкшие (`d2kd.c:1590`) | дренирует **все** UDP hold/deferred (`main.rs:1312-1335`) | `deep-datapath-core.md` |
| 10 | TCP options shape | `shape_opts[4][40]` полный набор (`session.c:142,2258,2982`) | `ClientShapeEvent` только ClientHello + bool TS (`control.rs:421-433`) | `deep-datapath-core.md` |
| 11 | HTTP live failures | `failures/addr/binding/execution/request_ms` (`httpsearch.c:520-550`) | `HttpSearchRecord` только cut/repeat_path/repro_gap (`main.rs:4468-4472`); счётчики диагностики 0 | `deep-core-net.md` |
| 12 | QUIC cert-name | `qc_peer_name` возвращает `name_ok`, handshake продолжается (`quicconn.c:1430,1195-1197`) | `R2oQuicHttp3Result` без `name_ok`; webpki рвёт handshake (`r2o_quic_http3.rs:890`) | `deep-core-net.md` |
| 13 | TLS 1.2 | CH без ALPN, P-384 объявлен/отвергнут, открытый HTTP — отдельная ошибка | ALPN `http/1.1`, P-384 разрешён, открытый HTTP — общий rustls error; `rx_record_missing` только bool | `deep-core-net.md` |
| 14 | ctl output ring | 64 КиБ (`ctl.c:21`) | 128 КиБ (`control.rs:28`) | `datapath-plan.md` |
| 15 | raw mark | допускает `mark=0` (`raw.c:193`) | требует ненулевой mark (`raw.rs:55-59`) | `datapath-plan.md` |
| 16 | Binding | `tcp_profile` хранится, `family` default 4 (`catalog.c:834-890`) | `Binding` без `tcp_profile`, `family` default 0 (`catalog.rs:165-181`) | `core-state.md` |
| 17 | plan identity | FNV-1a `plan-%08x` в TLV (`compose.c:218-240`) | trial-id 16 байт (`discovery.rs:1450`) | `core-state.md` |
| 18 | P-256 | production TLS1.2 ECDHE (`tls12.c:650-655`) | `ring`; прямых C/Rust-векторов нет | `core-state.md` |
| 19 | HTTP-search `probe_run` | 403 с телом РКН → `INJECTED`; 101/битый CL/TE → CUT; `head` включает тело | Rust не классифицирует тело, 101 → `Empty`, битый CL/TE → `InvalidData`; judge видит только заголовки | `deep-core-verify.md` |
| 20 | HTTP-search кандидаты | `CANDS[]`: split, disorder, fake-badsum, fake-seqshift (4) | 5 кандидатов, включая `fake-badsum-whole`, другой порядок | `deep-core-verify.md` |
| 21 | HTTP-search save | файл `d2k-http-plans 1`, `fflush/fsync/rename` | JSON-каталог, отдельного файла/формата нет | `deep-core-verify.md` |
| 22 | verify page budget | бюджетный повтор шлёт фактический `req`, дедлайн сбрасывается | повтор строит запрос из `options.path`, общий deadline; redirect только при `complete` | `deep-core-verify.md` |
| 23 | detect mark | `D2K_BYPASS_MARK=0x40000000` (`detect/include/d2k_detect.h:34`) | `BYPASS_MARK=0x2d` (`raw_probe.rs:23`, `response.rs:71`) | `detect.md` |
| 24 | raw-hex accept | первый байт `0x16` → `accept_serverhello` (`verdict.c:33-35,126-129`) | `Trigger::raw_hex` всегда `Accept::Any` (`classify.rs:77-83`) | `core-state.md` |
| 25 | endpoint role | `server_is_low` по эфемерному диапазону ≥32768 для любого порта (`sched.c:1798-1805`) | `DiscoveryTarget::from_event` только 443, `from_http_portal` только 80 (`discovery.rs:355-460`) | `core-state.md` |
| 26 | HTTPS probe non-upgrade | `http_probe_done`: SET_HTTPS только для `SERVED`/`TLS_BLOCKED`, иначе `http_search_portal` (`d2kc.c:331-344`) | `main.rs:17033` шлёт `SET_HTTPS(host, ttl_seconds)` для любого результата; у не-upgrade `ttl_seconds=0` (`https_probe.rs:170-178`), HTTP-поиск только через `pending_http_searches` | `core-net.md` |
| 27 | HTTPS first flight | донорский `modern` ClientHello из `d2k_hello_from_profile` (`httpsprobe.c:171-177`) | rustls-сгенерированный ClientHello (`response.rs:572-605`) | `core-net.md` |
| 28 | HTTPS result loss | `done[17]`; при переполнении `lost++`, результат отбрасывается (`httpsprobe.c:337-340`) | `sync_channel(16)` + блокирующий `send`, счётчика `lost` нет (`https_probe.rs:132,181-183`) | `core-net.md` |
| 29 | HTTP-upgrade 307 | `X-D2K-HTTP-Upgrade: provider-portal` (`httpup_logic.c:145`) | `X-R2O-HTTP-Upgrade: provider-portal` (`httpup.rs:513`), закреплено тестом | `core-net.md` |
| 30 | HTTP-search plan identity | `d2k-plan 1 11` + FNV-префикс `d2k-http:` (`httpsearch.c:300,330-333`) | `r2o-plan 1 11` + префикс `r2o-http:` (`http_search.rs:686,784`) | `core-net.md` |
| 31 | QUIC is_initial | только структура заголовка, без AEAD (`quic.c:182-185`) | `is_authenticated_initial` требует успешного open/AEAD (`quic.rs:107-127`) | `core-net.md` |
| 32 | QUIC Initial build | v1/v2, DCID 8..20, SCID из снимка, longer=1300, clear-fixed, two-datagram split (`quichello.c:124-455`) | `initial_build` только v1, DCID 8, SCID = аргумент, всегда 1200, без clear-fixed/two-datagram (`quic.rs:261-336`, `quic_replay.rs:98-135`) | `core-net.md` |
| 33 | QUIC data-stage transport | TP idle 30000/max_udp 1452/max_data 1 МиБ/stream 256 КиБ/16+16, CH из SNI+TP+ALPN h3, сертификат только по имени (`quicconn.c:380-403,836-892,1195-1197`) | quinn defaults без `TransportConfig`, CH rustls, webpki-цепочка рвёт handshake (`r2o_quic_http3.rs:889-916`) | `core-net.md` |

### Остаточные P (не доказано, не значит «сломано»)

- `rustls`/`quinn` record layer, HRR/key update/resumption, ACK/loss/Retry/
  transport params — end-to-end исходы есть, построчного паритета нет.
- `sched.c` (282) — полная матрица состояний и редкие комбинации
  ECH+volume/addr+voice/QUIC-deny не доказаны.
- HTTP-search — переходы/таймеры задач, live failures, диагностические
  счётчики; HTTPS-probe — live-тайминги и `lost`.
- datapath — сложные ветви session/hold/capture, `nfq` ENOBUFS, HTTP80
  capacity; detect — bridge/CLI, autottl/tsup, handshake12.
- core-state — CLI-флаги/вывод, PSL/catalog-парсер, crypto HKDF-границы,
  voice-blob, volume resource-retry.
- `?` (2): `d2k_plantab_has_ech_target` (предиката нет, поведение может
  покрываться общим hold) и ложное срабатывание парсера
  `d2k_props_contact_on_family_tcp_profile`.

## Следующий этап: исправление подтверждённых расхождений

После завершения аудита (все 1982 функции получили строку и глубокую сверку)
перехожу к фиксу. Приоритет:

1. **Packet-path/безопасность:** `wire_udp` IPID_ZERO/TOS; raw UDP/TTL
   (`IP_NODEFRAG`, `qp_recv_ttl`); `ARM_SHAPE` transport 17; `SET_HTTPS`
   7 суток vs 6 часов; `plan_apply` OOB `wire_profile` и qsplit `delay_us`;
   `raw_set_segment_max`; полный `shape_opts`; HTTP80 capacity 128/1024;
   ENOBUFS-дренаж только истёкших.
2. **Данные/каталог:** `Binding.tcp_profile`; default `family=4`; FNV
   `plan-%08x`; HTTP live failures/счётчики; QUIC `name_ok`; TLS 1.2
   ALPN/P-384/открытый HTTP/`rx_record_missing`.
3. **Диагностика/CLI:** `--log/--health-file/--duration/--sched-slots`;
   группы `print_stats`; N-функции (`count_reason`, `offline_self_check`,
   NAT/session-агрегаты, RST-парсеры).
4. **Остаточные P:** record layer/HRR/key update/resumption, полная матрица
   `sched`, HTTP-search transitions, TLS/QUIC live-тайминги.

Правила фикса: каждый пункт — с тестом/дифференциалом; C-реализацию не
удалять до подтверждения эквивалентности; после фикса пересчитать матрицу.

## Отчёты групп

| Группа | Функций | Отчёт | Состояние |
|---|---:|---|---|
| core-net: TLS/HTTP/ECH/QUIC/voice/verify | 548 | `docs/audit/core-net.md` | готов |
| core-state: catalog/sched/diagnostics/link/… | 692 | `docs/audit/core-state.md` | готов |
| datapath-core: d2kd/session/hold/udp/nfq/… | 400 | `docs/audit/datapath-core.md` | готов |
| datapath-plan: plans/ctl/raw/route/… | 183 | `docs/audit/datapath-plan.md` | готов |
| detect: trigger/poison/raw/classify/response | 159 | `docs/audit/detect.md` | готов |

Глубокая повторная проверка: `deep-core-net.md`, `deep-core-verify.md`,
`deep-datapath-core.md`, `deep-detect-plan.md`. `deep-core-verify.md`
интегрирован в `core-net.md` (E→P: `request_page_budget`,
`d2k_hs_probe_run`, `d2k_hs_candidate_count/key`, `d2k_httpsearch_save`).
Линии `httpsearch.c` в реестре/CSV местами сдвинуты на +2 относительно
фактического файла a378; в `deep-core-verify.md` указаны фактические.

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
| core-net | 548 | 195 | 339 | 13 | 1 |
| core-state | 692 | 135 | 554 | 3 | 0 |
| datapath-core | 400 | 122 | 267 | 11 | 0 |
| datapath-plan | 183 | 102 | 75 | 5 | 1 |
| detect | 159 | 49 | 100 | 10 | 0 |
| **Итого** | **1982** | **603** | **1335** | **42** | **2** |


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
| `core/p256.c::d2k_p256_keypair` / `d2k_p256_ecdh` | 282–316 (35) | `ring` SECP256R1 в `r2o_tls.rs` (95, 101, 288) | **P** | **Исправлено:** это production-путь TLS 1.2 ECDHE — `core/tls12.c:650-655` вызывает `d2k_p256_keypair` и `d2k_p256_ecdh`, если сервер выбрал secp256r1. R2O делегирует генерацию/ECDH `ring`, проверка точки на кривой — внутри `ring`; прямых C/Rust-векторов P-256 и явной retry-политики 16 попыток нет. |
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
- `d2k_p256_*` **вызывается в production**: `core/tls12.c:655` использует
  `d2k_p256_keypair`/`d2k_p256_ecdh` для ECDHE, если сервер выбрал secp256r1.
  R2O закрывает это `ring`, но прямых C/Rust-векторов P-256 нет — статус P,
  не N.

## Подтверждённые расхождения из отчёта datapath-plan

Проверено по исходникам, не только по словам агента:

- **`SET_HTTPS` TTL.** C `datapath/ctlsrv.c:446` обрезает TTL до
  `D2K_HTTPS_TTL_MAX_S` = **7 суток** (`d2k_ctl.h:231`); R2O
  `control.rs:1070,1781` возвращает `ACK_BAD_ARGS` при
  `ttl > MAX_HTTPS_TTL_SECONDS` = **6 часов**. Это реальное расхождение
  поведения, статус P.
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

**Построчная сверка a378:** все 9 функций сверены с `h3.rs`; различий в алгоритмах/границах не найдено. Совпадают: `control` 00 04 00; `prefix_max/prefix_int/prefix_int_read` (включая 8-битный префикс и `shift>56`); `request` (static 17/23/1, authority literal name 0, path literal name 1, лимиты 255/512); `huff_status` (5/6 бит, EOS-хвост); `static_status`/`name_is_status` (24–28, 63–71); `decode_section` (indexed, literal-name, literal-literal, post-base index/literal); `status` (пропуск неизвестных кадров, отказ на обрезанном).

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
| `d2k_qw_long_hdr_token_w` | 142-174 | 33 | long header v1/v2, token только Initial, заданная ширина length | `quic.rs:261-336 r2k_quic_initial_build` (inline) | **P** | **Подтверждённые отличия:** Rust строит **только Initial v1** (`0xc0`, `QUIC_V1`), **без token** (пишет token_len=0) и подбирает ширину length перебором `1/2/4/8` под `target_len`; C принимает v1/v2, произвольный Initial-token и `length_width`. Для штатного Initial v1 без token результат совпадает; v2/0-RTT/Retry-сборки в Rust нет. |
| `d2k_qw_long_hdr_w` | 176-184 | 9 | обёртка long header без token | `quic.rs:261 r2k_quic_initial_build` | **P** | Для Initial v1 без token эквивалентно (RFC-тест `создаёт_аутентифицированный_quic_initial_из_clienthello`); v2 и прочие типы C-обёртка умеет, Rust — нет. |
| `d2k_qw_long_hdr_token` | 186-194 | 9 | long header с token, автоширина | `quic.rs` (только Initial без token) | **P** | 0-RTT/Retry-сборка и Initial-token в Rust не портированы. |
| `d2k_qw_long_hdr` | 196-202 | 7 | long header без token, автоширина | `quic.rs:261` | **P** | Только Initial v1; v2-сборка отсутствует. |
| `d2k_qw_hdr_parse` | 204-273 | 70 | generic long/short/Retry/Initial/0-RTT/Handshake, token, length, pn offset, sample | `quic.rs:796-848 parse_initial_header` (+ short header у quinn) | **P** | **Подтверждённое сужение:** Rust `parse_initial_header` принимает **только Initial** (v1 raw_type 0, v2 raw_type 1), проверяет token/length/pn+20; short header, Retry, 0-RTT и Handshake разбирает quinn/иной код. C generic-парсер умеет все типы. Для клиентского Initial v1/v2 эквивалентно; RFC-тесты Initial v1/v2. |
| `d2k_qw_pn_len` | 277-293 | 17 | RFC 9000 A.2: unacked, bits+1, 1..4 байта | нет (Rust `seal_initial` принимает pn_len; `initial_build` передаёт 4) | **P** | **Подтверждённое отличие:** C вычисляет минимальную длину PN по `largest_acked`; Rust `r2k_quic_initial_build` всегда передаёт **pn_len=4**, `reseal` сохраняет исходную длину. Функции расчёта нет; для первого Initial 4 байта валидны, байтовый паритет с C на других largest_acked не доказан. |
| `d2k_qw_pn_decode` | 295-313 | 19 | восстановление PN по largest | `quic.rs:1041 decode_packet_number` | E | используется в RFC-тесте split Initial |
| `d2k_qw_initial_secret` | 317-325 | 9 | Initial secret (client/server in) | `quic.rs:849 derive_initial_keys` | E | RFC 9001/9369 тесты |
| `d2k_qw_keys_from_secret` | 327-338 | 12 | key/iv/hp из secret | `quic.rs:853 derive_initial_keys_for_role` | E | RFC-тесты |
| `nonce_of` | 344-349 | 6 | nonce = iv XOR pn | `quic.rs:1033 packet_nonce` | E | helper; RFC-тесты |
| `d2k_qw_seal` | 351-394 | 44 | long/short header: AEAD seal (AAD=hdr+pn), tag за ct, HP-маска 0x0f/0x1f, sample pn+4 | `quic.rs:968-1021 seal_initial` | **P** | **Подтверждённые отличия:** Rust `seal_initial` поддерживает только **long header** (маска 0x0f) и Initial; C умеет short header (0x1f). Для Initial v1/v2 байты совпадают (RFC-тест split Initial, длина/аутентичность). Проверка `pn_len+plain+16 >= 20` та же. |
| `d2k_qw_open` | 396-450 | 55 | long/short, HP, PN decode от `largest_pn`, AEAD open, проверка reserved | `quic.rs:908-967 open_initial` | **P** | **Подтверждённые отличия:** Rust `open_initial` — только Initial (long), `decode_packet_number(0, …)` жёстко с largest_received=0, а C принимает `largest_pn` и поддерживает short header. Для первого полёта/снимка результат совпадает; для последующих пакетов с largest>0 паритет не доказан. Тест `refuses_when_authenticated_initial_is_modified`, split-тесты. |
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
| `d2k_quic_is_initial` | 182-185 | 4 | предикат: только структура long header Initial v1/v2, без ключей/AEAD | `quic.rs:107-127 is_authenticated_initial` | **P** | **Подтверждённое расхождение:** C возвращает 1 для структурно корректного Initial **с любым шифртекстом/битым тегом**; Rust `is_authenticated_initial` выводит ключи, снимает HP и проверяет AEAD, поэтому такой пакет даёт 0. Тест `refuses_when_authenticated_initial_is_modified` закрепляет более строгий контракт Rust. |
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
| `select_probe_profile` | 34-45 | 12 | копия профиля + MIPS-замена cipher list по `[0,6]` на `[0x1303,0x1301,0x1302]` | `quic_replay.rs:98-135 r2o_quic_profile_snapshot` | **E** | Rust: профиль 275 байт, MIPS-ветка `get(39..41)==[0,6]` → те же три cipher suite, random/SCID/key_share обновляются. Эквивалентно. |
| `split_point` | 69-77 | 9 | первый SNI начиная с i=1 → `i+m/2`, иначе `n/2` | `quic.rs:167-196 initial_split_crypto` | **E** | Rust ищет SNI в собранном ClientHello, `middle=sni_offset+sni_len/2`, затем кадр, содержащий middle; при отсутствии — `NoNameInDatagram`. C fallback `n/2` относится к другому сценарию (нет имени), Rust в этом случае отказывает. Тест split. |
| `put_crypto` | 80-95 | 16 | CRYPTO: 0x06, offset varint, len varint, data | `quic.rs:1085-1105 append_crypto_frame` | **E** | Та же раскладка/проверки; используется split. |
| `prepare` | 124-175 | 52 | разобрать Initial, извлечь CH, IP→удалить SNI иначе rename, DCID 8..20 (иначе 8), SCID из снимка, ver = V2 или версия снимка, ключи | `quic.rs:261-336 r2k_quic_initial_build` + `:1113 r2k_quic_client_hello_rename_sni` | **P** | **Подтверждённые отличия:** Rust `initial_build` всегда **QUIC v1**, генерирует **DCID ровно 8 байт**, берёт **SCID = source_connection_id** от вызывающего (а не из снимка) и не имеет `want_v2`. C сохраняет версию/длину DCID (8..20)/SCID снимка и умеет V2. Композиция rename+build в `r2o_quic_profile_snapshot` покрывает только v1/8/профиль. |
| `seal_one` | 183-228 | 46 | итеративная добивка PADDING до want, long header, опционально погасить fixed bit до seal | `quic.rs:261-336` (`target_len` + `seal_initial`) | **P** | **Подтверждённые отличия:** Rust подбирает ширину length под `target_len` и всегда v1, fixed bit не гасит; C умеет v1/v2 и `clear_fixed`. Для `want=1200`, v1, fixed=1 результат эквивалентен (тест 1200). |
| `probe_initial_sized` | 235-274 | 40 | профиль + X25519 + random/SCID + rename (IP→без SNI) + CRYPTO + seal ровно want | `quic_replay.rs:98-135 r2o_quic_profile_snapshot` | **E** | Rust делает те же шаги для want=1200 v1: профиль 275, random 32, SCID 8, X25519 pub, IP→`rename_sni(None)`, иначе rename, `initial_build(1200)`. Длина/SNI проверяются. |
| `d2k_quic_probe_initial` | 276-279 | 4 | обёртка want=1200 | `r2o_quic_profile_snapshot` | **E** | Test `initial.len() == 1200`. |
| `d2k_quic_probe_initial_longer` | 281-285 | 5 | обёртка want=1300 (questions.go:237) | `quic.rs:261 r2k_quic_initial_build` (target_len=1200) | **P** | **Подтверждённое отличие:** Rust-владелец всегда вызывает `initial_build(..., 1200)`; вариант 1300 не портирован и не тестируется. |
| `d2k_quic_prepare_target` | 287-310 | 24 | отказ на QSN, попытка rename снятого Initial, иначе профиль 1200 | `r2k_quic_client_hello_rename_sni` + `r2k_quic_initial_build` | **P** | Композиция есть в `quic_replay.rs` (снимок QSN, профиль), отдельной функции с тем же fallback-порядком нет; QSN-отказ/порядок не тестированы. |
| `d2k_quic_hello_rename` | 312-321 | 10 | отказ на QSN, `hello_ask(PLAIN)` → prepare+rename внутри Initial | `quic.rs:1113-1160 r2k_quic_client_hello_rename_sni` | **P** | **Отличие уровня API:** C принимает готовый Initial и пересобирает его; Rust принимает **ClientHello** и возвращает CH. Пересборка Initial — отдельно `initial_build`/`reseal`; прямой C-функции «Initial→Initial rename» нет. Тесты rename/без SNI/повтор. |
| `d2k_quic_hello_ask` | 330-391 | 62 | PLAIN/V2/SPLIT/longer/clear-fixed; split — два CRYPTO в одном пакете, tail первым | `quic.rs:167 initial_split_crypto`, `:261 initial_build` | **P** | **Подтверждённые отличия:** Rust умеет split одного пакета и v1 build; **v2, longer=1300, clear-fixed-bit** не вынесены. C split режет по `split_point` (SNI или n/2), Rust — только по SNI и иначе отказ. |
| `d2k_quic_hello_split` | 412-455 | 44 | два Initial с одним DCID: tail (PN=1) и head (PN=0), каждый ≥1200 | нет прямого | **P** | Двухдатаграммного варианта в Rust нет; `initial_split_crypto` даёт один пакет. |
| `d2k_quic_hello_recid` | 457-548 | 92 | QSN-отказ, Initial v1/v2, свежий DCID той же длины, SCID из снимка, pn_len из Length, fixed bit из снимка, reseal с той же длиной | `quic.rs:338-372 r2k_quic_initial_reseal_for_dcid` | **E** | Rust: parse Initial, open старыми ключами, reseal новым DCID, `clear_header[0]=input[0]&0xf0` (fixed bit сохранён), новые ключи, проверка длины/length_width. Tests reseal/`quic_snapshot.rs:30`. |

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

**Построчная сверка a378 (все 56 функций):** C прочитан целиком. Подтверждённые отличия: `qp_recv_ttl` — N (Rust не читает TTL/hoplimit); `d2k_quic_props_findings` — N (текстовые выводы не портированы); `qp_send_one`/`qp_send_fragmented`/`qp_arm_first_send` — P, потому что plan-send (`d2k_udp_plan_send`: prefix/copies/TTL/split/fragment) заменён прямым `send`/`QuicReplayProbe`; `d2k_quic_budget_ms` — P (Rust бюджет в пакетах, формула мс не портирована); `qp_questions_step` — P (C задаёт 6 вопросов: junk, frames, split-datagrams, clear-fixed, low-port, longer; version2 снят, Rust-набор кандидатов иной); `classify_run` — P (async-переписывание). Совпадают: пул/дедуп, varint/Initial, donor-response/VN/Retry, bound-проверка, `qp_dyn_wait`, `qp_pinned_or_next`, neutral SNI, base-дифференциал.

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
| `quic_ask_core` | 1064-1403 | 340 | repeats≤8; на повтор свежий DCID (recid снимка/пачки, VN-триггер, neutral, split-пара); src_port-i; все send параллельно, poll, verify, RTT min, TTL первого, pass/fail/refused/err | `quic_replay.rs:901-1010 r2o_quic_ask_donor_parallel` | **P** | **Совпадает:** параллельная отправка, reseal/новый DCID на повтор (`from_socket`), pass/refused/err, min RTT, timeout 1500 по умолчанию. **Отличия:** Rust не принимает `src_port`, `prefix_ttl/copies`, `split/longer` и не читает TTL (`qp_recv_ttl`); plan-send (`d2k_udp_plan_send`) заменён прямым send. C-предел repeats и точные счётчики `sent/refused` не сверены differential. |
| `quic_ask_ex` | 1405-1416 | 12 | обёртка core без crypto_split/longer | `quic_replay.rs:901` | **P** | Тонкая обёртка; наследует отличия `quic_ask_core`. |
| `quic_fragment` | 1418-1428 | 11 | ask с IP-фрагментацией | `quic_replay.rs:490 r2o_quic_fragment_candidates` | P | кандидаты есть, отправка фрагментами — нет |
| `qp_progress` | 1432-1435 | 4 | hook прогресса | `main.rs` progress callback | P | hook не портирован |
| `quic_ask_arm` | 1437-1477 | 41 | ask по arm-вопросу (fragment/split/neutral) | `quic_replay.rs:647 QuicReplayProbe` | P | arm-цикл в Rust иной |
| `qp_arm_first_send` | 1500-1508 | 8 | первый send Initial через план, local_port | `quic_replay.rs:647` | P | plan-send отсутствует |
| `qp_now_ms` | 1510-1514 | 5 | монотонное время | `Instant` | P | хелпер |
| `quic_arm_data` | 1516-1584 | 69 | этап данных по arm: connect, h3, суд | `quic_replay.rs:417 r2o_quic_trial_data_verdict`, `r2o_quic_http3` | P | композиция иная; verdict покрыт differential |
| `d2k_quic_data_stage` | 1591-1829 | 239 | SETTINGS control, пауза 400 мс, GET stream 0, HEADERS 64 КиБ, 451, app-байты, PING-stall (RTO 3×RTT≥1 с), бюджет 2× датаграмм с новыми потоками sid+4, judge3 | `r2o_quic_http3.rs:702-1200 measure_with_wire_len` | **P** | **Совпадает:** SETTINGS/control, GET, статус/451, app-байты, stall (PING/OneWay), бюджет 2×, полный ответ на новый поток. **Отличия:** Rust `h3_client` сам создаёт control stream и не имеет явной паузы 400 мс; бюджет/повторы выражены через `R2oQuicHttp3Budget`/`Stall`; reason-тексты и `judge3` не сверены. Stage-дифференциал `test-quic-http3-full-stage-differential.sh`. |
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
| `qp_questions_step` | 2117-2268 | 152 | ровно 6 вопросов в порядке: junk, frames (SPLIT_CRYPTO), datagrams (SPLIT), bit (CLEAR_FIXED_BIT), lowport (SRCPORT), length (LONGER); version2 снят; каждый на `qp_pinned_or_next`, бюджет | `quic_replay.rs:449-520 r2o_quic_discovery_candidates` | **P** | **Подтверждённые отличия:** C-таблица `qp_list` содержит 6 вопросов и **не задаёт version2** (комментарий 57); Rust-набор кандидатов (`Clearance/SplitCrypto/UdpLength/TtlStrategy`) имеет другой состав/порядок и не содержит low-port/longer в том же виде. Бюджет C в мс, Rust — в пакетах/дедлайнах. |
| `d2k_quic_props_findings` | 2274-2323 | 50 | текстовые выводы по свойствам (split/2 datagrams/v2/fixed bit/port/fake) | нет | N | тексты и выводы не портированы |
| `arm_budget_left` | 2325-2325 | 1 | предикат остатка бюджета для arm | `quic_replay.rs` budget | P | тривиальный адаптер, отдельной функции нет |
| `arm_budget_spent` | 2328-2331 | 4 | увеличить бюджет на потраченное время | нет | P | динамического бюджета arm нет |
| `classify_run` | 2336-2917 | 582 | шаги 0 base control → 1 direct trigger → 2 residual control → 3 VN/address → 4 arms/questions; base_only/seed; budget ms; local-address; CLEAR/OPAQUE/NO_QUIC/ADDRESS/FLAKY | `main.rs:20496 r2o_run_quic_discovery_trial`, `quic_replay.rs:289 r2o_quic_base_result` | **P** | **Совпадает:** base/direct/residual, VN при полной тишине, address при VN 0, `NO_QUIC` при refused, local-address, base-only/seed. **Отличия:** Rust разложен на async trial/`r2o_quic_base_result`, бюджет в пакетах/дедлайнах, arms/questions идут через `discovery_candidates`; `d2o_quic_base_differential.c` и HTTP/3 stage покрывают не все ветви (в частности `budget exhausted`, `data_cut 2`, короткий контроль). |
| `d2k_quic_classify` | 2919-2922 | 4 | публичный classify | `main.rs:20496` | P | обёртка |
| `d2k_quic_base` | 2923-2926 | 4 | только базовый вопрос | `quic_replay.rs:289 r2o_quic_base_result` | E | `d2o_quic_base_differential.c` + unit |
| `d2k_quic_run_seeded` | 2927-2931 | 5 | classify с заранее снятым base seed | нет (seed-структуры нет) | P | base seed не портирован |
| `d2k_quic_run` | 2932-2935 | 4 | публичный classify с arm | `main.rs:20496` | P | обёртка |

## core/quicarms.c (8 функций)

Лестница arm-стратегий QUIC: перебор blob/копий/TTL/IP-фрагментации, затем стратегии clearance/split/longer/frag. R2O: `r2o-controller/src/quic_replay.rs` (`r2o_quic_discovery_candidates`, `r2o_quic_original_fallback_candidates`, `r2o_quic_strategy_attempt_decision`). Дифференциал `r2o-diagnostics-differential.sh` (C `quicarms.c` + `d2o_quic_base_differential.c`) покрывает профиль/verify/parallel/VN/base, но не всю лестницу.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_quic_original_blob` | 12-17 | 6 | 5 blob'ов: quic5, quic_google, quic_rutracker, fake_default_quic (620×0x40), 16 нулей | `quic_replay.rs:586-630 r2o_quic_blob_candidate/blob_name` | **E** | Rust: 4 файла `R2O_QUIC_ORIGINAL_BLOBS` + `blob==4` → `[0;16]`, имена те же (`quic5`/`google`/`rutracker`/`fake_default`/`безобидная`). `quic_default.bin` соответствует 620×0x40 (profile differential). |
| `ask_q` | 30-104 | 75 | yield/бюджет, выбор `pool[residual?next++:0]`, probe, trace, data-stage, measured/retry | `quic_replay.rs:368-416 strategy_attempt_decision`, `:647 QuicReplayProbe` | **P** | **Совпадает:** выбор адреса, `sent==REPEATS && err==0` как measured, 0/3→NO, 1–2/3→retry, NOT_RUN→retry, data PASS→YES. **Отличия:** C ведёт `trace[]`/`not_measured`/`data_note` и бюджет в мс; Rust возвращает только decision, трассы и `qp_budget` нет. |
| `ask_frag` | 112-121 | 10 | контроль фрагментов, затем формы 1..4 | `quic_replay.rs:490-517 r2o_quic_fragment_candidates` | **P** | Rust строит 5 кандидатов: control + 4 формы, те же директивы `ipfrag N`; **фактическая raw-отправка фрагментов в контроллере отсутствует** (см. `qp_send_fragmented`). |
| `ask` | 125-140 | 16 | собрать вопрос по blob/copies/ttl/frag/control + label | `quic_replay.rs:586-620 r2o_quic_blob_candidate` | **P** | Параметры/директивы совпадают (`payload 1`, `fake … repeats`, `poison ttl`, `quicsplit`, `udplen`, `ipfrag`); C-метки и тексты не портированы. |
| `d2k_quic_original_arms` | 142-219 | 78 | 5 singles → quic5/fake_default ×6/11 → fake_default×11+split по измеренному контрасту → TTL 3/5/8/12 → frag | `quic_replay.rs:506-556 r2o_quic_original_fallback_candidates`, `:558-570 adaptive_split_candidate` | **P** | **Совпадает:** 5 singles (blob 4 пропускается при `benign_answered`), пары 0/3 ×6/11, TTL 3/5/8/12 (3 пропускается), frag при `!fragment_questions_used`. **Отличие:** C запускает fake-split внутри цикла 2×2 только при измеренном частичном ответе/CUT/NO_HANDSHAKE; Rust выносит его отдельным `AdaptiveSplit` + `adaptive_split_eligible` (эквивалентное условие, иной порядок в списке). |
| `strategy_ask` | 227-242 | 16 | до 2 попыток, `asked` по not_measured 1/2, YES/NO/UNKNOWN | `quic_replay.rs:331-366 filter_round_decision`, `:368-416 strategy_attempt_decision` | **P** | Логика retry/NO/UNKNOWN совпадает: measured==repeats, answered 0→NO, 1..2→retry, attempt>1→Unknown. C отдельно ведёт `asked`; Rust — вызывающий. |
| `prop_word` | 244-246 | 3 | «прошло/не прошло/ответа нет» | нет | **N** | Только текст причины; Rust-строки формируются иначе. |
| `d2k_quic_strategy_arms` | 248-396 | 149 | TTL-lifetime (quic5×2 TTL3) → clearance benign → split CRYPTO → longer 100 → frag → original fallback; слияние trace | `quic_replay.rs:427-490 r2o_quic_discovery_candidates`, `:506+` fallback | **P** | **Совпадает:** TTL только при `need_complete && budget` и stalled baseline; clearance→split→udplen; при обоих NO — frag; иначе original. **Отличия:** C-порядок TTL→clearance→split→longer→frag→original и слияние трасс; Rust возвращает плоский список кандидатов, решение по данным — `strategy_attempt_decision`. Полная лестница differential не покрыта. |

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

**Построчная сверка a378 (все 36 функций):** C прочитан целиком. Критические отличия: C `tp_build` объявляет idle 30000, max_udp 1452, max_data 1 МиБ, stream window 256 КиБ, streams 16/16, CID limit 2, `initial_source_connection_id`; в `r2o_quic_http3.rs`/`quic_replay.rs` **нет `TransportConfig`**, поэтому действуют умолчания quinn. C `d2k_qc_connect` **не проверяет цепочку/подпись** сертификата (только имя через `d2k_t13_cert_name_ok`), Rust `with_root_certificates`/webpki рвёт handshake при mismatch. C `first_flight` собирает CH из SNI+TP+ALPN h3 собственным `d2k_t13_ch_build`, Rust data-stage использует CH rustls. Остальные функции — P, заменены quinn/rustls; `crypto_frame` — E, `d2k_qc_peer_name` — N (в результате quinn нет name_ok).

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
| `tp_build` | 380-403 | 24 | idle 30000, max_udp 1452, max_data 1 МиБ, bidi/uni stream 256 КиБ, max_streams 16/16, active_cid_limit 2, initial_source_connection_id | quinn defaults (своего `TransportConfig` в `r2o_quic_http3.rs`/`quic_replay.rs` нет) | **P** | **Подтверждённое расхождение:** C объявляет конкретные TP (`quicconn.c:383-396`); R2O не настраивает `quinn::TransportConfig`, поэтому действуют умолчания quinn (иные idle timeout/окна/лимиты потоков). Влияет на flow control, число потоков и бюджет data-stage. `tp_server_parse` при этом читает пределы сервера, но собственные TP не совпадают с C. |
| `tp_server_parse` | 418-453 | 36 | разбор серверных 0x04/0x06/0x07/0x08/0x09, неизвестные по длине | quinn transport params | **P** | Функциональность внутри quinn; C-поля `peer_streams/sdata/max_data` не выставляются в R2O-коде. Значения quinn не сопоставлены. |
| `tp_server_ee` | 460-473 | 14 | TP из EncryptedExtensions | quinn/rustls | P | заменено зависимостью |
| `frames_in` | 479-696 | 218 | разбор кадров: PADDING/ACK/CRYPTO/STREAM/MAX_*/NEW_CONNECTION_ID/PING/CLOSE | quinn | P | заменено зависимостью |
| `recv_dgram` | 702-815 | 114 | приём датаграммы, определение уровня, открытие | quinn | P | заменено зависимостью |
| `crypto_frame` | 820-829 | 10 | CRYPTO-кадр для первого полёта | `quic.rs:1085 append_crypto_frame` | E | хелпер; владелец `d2k_qc_first_initial`, RFC-тест |
| `first_flight` | 836-892 | 57 | random DCID/SCID/priv/random, X25519 pub, Initial keys client+server, CH через `d2k_t13_ch_build`: SNI (IP→NULL), `session_id_len=0`, ALPN h3, `extra=tp_build`, `pad_to`; transcript; CRYPTO frame | `r2k-core/src/quic.rs:261-336 r2k_quic_initial_build` + профиль/rustls | **P** | **Подтверждённое расхождение:** C строит **свежий** ClientHello из SNI+TP+ALPN (`quicconn.c:866-889`), Rust raw-путь берёт донорский/снятый профиль без TP (`r2o_quic_profile_snapshot`), а data-stage — CH rustls/quinn. Построчной сборки CH из SNI+TP в R2O нет. |
| `prepare_retry` | 898-926 | 29 | обработать Retry: новый DCID/token | quinn | P | заменено зависимостью; retry-проверка есть в `quic.rs:569` |
| `d2k_qc_first_initial` | 928-954 | 27 | аллоцирует `d2k_qc`, `first_flight` (CH+TP), seal Initial ровно 1200, отдаёт байты | `quic.rs:261-336 r2k_quic_initial_build` | **P** | **Подтверждённое расхождение:** C собирает CH из SNI+TP и запечатывает 1200; Rust `initial_build` принимает **готовый CH** (обычно профиль) и запечатывает 1200 v1. Сборки CH+TP нет; `d2k_qc_first_initial` как API отсутствует. |
| `qc_no_sigpipe` | 956-964 | 9 | SO_NOSIGPIPE | `MSG_NOSIGNAL`/std | P | платформенный хелпер |
| `d2k_qc_connect` | 966-1286 | 321 | сокет/марка/свежий порт, first_flight, multi-datagram form, Initial/Retry, ServerHello/EE/Cert/Finished, ACK, app keys, Finished; cert только по имени; PTO 333 мс; классификация отказа по Initial/Handshake | `quinn::Endpoint::connect`, `r2o_quic_http3.rs:889-916` | **P** | **Подтверждённые расхождения:** (1) C **не проверяет цепочку/подпись** сертификата — только `d2k_t13_cert_name_ok` (`:1195-1197`); Rust `with_root_certificates(roots)` + webpki рвёт handshake при mismatch; (2) C TP (`tp_build`) не портирован — quinn defaults; (3) C multi-datagram form режет transcript на `form.n` Initial; Rust data-stage использует quinn без этой формы; (4) C классифицирует отказ по числу Initial/Handshake (`:1269-1282`), quinn даёт свой текст; (5) C `peer_name` — отдельный флаг, Rust — нет. HTTP/3 stage-дифференциал сверяет исход, не handshake-байты. |
| `d2k_qc_stream_send` | 1288-1375 | 88 | проверка peer streams/sdata/max_data, want_stream, сброс rx, STREAM len+fin, last_app для PTO 300 мс | quinn `SendStream` | **P** | **Совпадает:** запись STREAM len+fin, учёт stream_id, проверка лимитов. **Отличия:** C сам проверяет `peer_streams/sdata/max_data` и хранит `last_app` для повтора (300 мс, 3 раза); quinn делает retransmit/flow control внутри, отдельных полей результата нет. |
| `d2k_qc_stream_recv` | 1377-1423 | 47 | буфер rx_data, recv 50 мс, повтор last_app по PTO, ACK + MAX_DATA/MAX_STREAM_DATA при половине окна | quinn `RecvStream` | **P** | **Совпадает:** чтение потока и ACK. **Отличия:** C вручную расширяет кредит (`fc_stream_limit/conn_limit`, credit_due) и повторяет последнюю посылку; quinn управляет окнами/retransmit сам. Точные пороги half-window не сопоставлены. |
| `d2k_qc_app_progress` | 1425-1428 | 4 | `ranges_bytes`/`ranges_complete` по диапазонам ответа | `r2o_quic_http3.rs:278 app_bytes_load` | **P** | C считает уникальные байты и FIN-покрытие по `d2k_qw_ranges`; Rust — счётчик app-байт counted-stream, `complete` из `recv_data`/trailers. Семантика «разные байты/целиком» различается. |
| `d2k_qc_peer_name` | 1430-1430 | 1 | результат проверки имени сертификата (`-1/0/1`) | нет (quinn/webpki) | **N** | **Подтверждённое расхождение:** C возвращает `name_ok` и **продолжает** handshake при чужом имени; R2O `with_root_certificates`/webpki проверяет цепочку и имя и **рвёт** handshake при mismatch; поля `name_ok` в `R2oQuicHttp3Result` нет. TCP-дифференциал `"tls13"` этот QUIC-путь не покрывает. |
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

**Построчная сверка a378:** все 8 функций прочитаны; различий в shape/cuts/выравнивании/перекрытиях/checksum/UDP6-заголовке не найдено. C-оракул сравнивает offsets/lengths и байты IPv4/IPv6 для shape 1..4.

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

**Построчная сверка a378:** все 5 функций прочитаны; тип 0x0001/0x0101, magic, 12-байтный txid, XOR порта/адреса, IPv6-ключ magic+txid, обход атрибутов с padding 4 и отказ на длине за границей совпадают. Различий не найдено.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `rd16` | 19-21 | 3 | big-endian u16 | `stun.rs:161 read_u16` | E | хелпер; владелец `d2k_stun_parse_response`, тесты stun |
| `rd32` | 23-25 | 3 | big-endian u32 | `stun.rs:168 read_u32` | E | хелпер; тесты stun |
| `d2k_stun_request` | 27-45 | 19 | Binding request: type 0x0001, magic, random txid | `stun.rs:18 binding_request` | E | test `parses_rfc5769...`, `recognizes_only...` |
| `parse_xor_mapped` | 52-83 | 32 | XOR-MAPPED IPv4/IPv6 (port ^ magic>>16, IP ^ key) | `stun.rs:133 parse_xor_mapped` | E | test `parses_rfc5769_xor_mapped_v4_and_v6_addresses` |
| `d2k_stun_parse_response` | 85-123 | 39 | проверка типа/magic/txid, обход атрибутов с padding | `stun.rs:28 parse_binding_response` | E | tests `rejects_foreign_and_malformed...`, `...exact_transaction_id` |

## core/voice.c (14 функций)

Голосовой зонд Discord: цели из nf_conntrack, STUN-опрос с приманками, вердикты clear/blocked/no_udp/flaky/unmeasured. В R2O: `r2o-controller/src/voice_targets.rs` (разбор целей) и `voice_measure.rs` (`r2o_measure_voice`, `r2o_ask_voice`, `r2o_evaluate_voice`, `r2o_search_voice_arms`). Тесты: unit `voice_measure.rs` (15+ сценариев), `test-voice-list-differential.sh`, Discord voice differentials.

**Построчная сверка a378:** все 14 функций прочитаны. Константы совпадают: `REPEATS=3`, `MAX_REPEATS=8`, `SILENT_AFTER=4`, контроль `stun.cloudflare.com:3478`, 3 blob'а × копии `1/6`. **Отличия:** `voice_resolve` C `strtoul` без проверки хвоста (Rust strict), `voice_blob_load` C читает файлы/`D2K_FAKE_DIR` (Rust compile-time profiles), `send_one`/`discovery_probe` C plan-send vs Rust raw engine, `voice_ask_real` N. Остальные ветви/вердикты совпадают с unit-тестами.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `is_voice_port` | 42-47 | 6 | входит ли порт в голосовые диапазоны | `voice_targets.rs:161 r2o_is_voice_port` | E | test `voice_targets.rs:231 принимает_только_границы_голосовых_диапазонов` |
| `field_val` | 65-82 | 18 | выделить `name=value` из строки conntrack | `voice_targets.rs:131 r2o_field` | E | tests `voice_targets.rs:182,199` + `test-voice-list-differential.sh` |
| `d2k_voice_targets` | 84-167 | 84 | разбор nf_conntrack: udp, публичный dst, voice-порт, агрегация, сортировка | `voice_targets.rs:17 r2o_parse_voice_targets`, `:26 r2o_read_voice_targets` | E | `test-voice-list-differential.sh` + 7 unit-тестов парсера |
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
| `d2k_voice_run` | 434-671 | 238 | полный вердикт: выбор потока, discovery, alive, direct STUN, контроль, arms | `voice_measure.rs:141 r2o_measure_voice`, `:352 r2o_evaluate_voice` | E | 15+ unit-тестов вердиктов; CLI-дифференциала нет (см. `r2o-fetch`/ask) |

## core/voice_discovery.c (7 функций)

Discord IP Discovery обход: разбор/сборка 20-байтового STUN-префикса в тексте плана, 3 обмена Discovery, поиск границы обрыва, подтверждение префиксом. В R2O: `r2o-controller/src/voice_discovery.rs` (`r2o_voice_discovery_prefix_from_plan_text`, `r2o_voice_arm_plan_text`, `r2o_search_discovery_endpoint`, `r2o_evaluate_r2o_discovery`). Дифференциалы: `r2o-discord-discovery-differential.sh`, `test-discord-voice-discovery-arm-differential.sh`.

| C-функция | строки | размер | назначение | R2O-аналог (file:line, символ) или "нет" | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `nibble` | 16-21 | 6 | hex-цифра | `plan_text.rs:668 hex_nibble` | E | хелпер; владелец `d2k_voice_discovery_prefix`, тесты плана |
| `d2k_voice_discovery_prefix` | 22-39 | 18 | ровно `d2k-plan 1 1\nid <32hex>\nproto udp voice\npayload 1 <40hex>\npoison 1\nfake…\norder forward\npace 15000\n`; проверка 8-байтного STUN-заголовка | `voice_discovery.rs:26-37 r2o_voice_discovery_prefix_from_plan_text` | **P** | **Подтверждённое отличие формата:** C принимает только точный `d2k-plan` с фиксированной длиной/id/хвостом и проверяет байты `00 01 00 00 21 12 a4 42`; Rust компилирует **любой** `r2o-plan` (`compile_text`+`Plan::parse`), требует один payload 20 байт, `is_binding_request`, затем сравнивает с пересобранным `r2o_voice_arm_plan` (id подменяется). C-текст `d2k-plan` Rust-парсером не принимается, и наоборот. Unit/Discovery-дифференциал. |
| `d2k_discovery_response` | 41-48 | 8 | валидация 74-байтового Discovery-ответа (SSRC, IP, порт) | `voice_discovery.rs:728 evaluate_r2o_discovery` (внутри), `r2k-core/tests/stun.rs:102` | E | `tests/stun.rs:112 r2o_discovery_принимает_ответ...` |
| `milliseconds` | 49-53 | 5 | монотонное время | `Instant` | P | хелпер |
| `discovery_probe` | 54-99 | 46 | 25 обменов Discovery: свежий SSRC, первый с prefix через `d2k_voice_arm_plan`/`d2k_udp_plan_send`, poll/recv 3 с, проверка SSRC | `voice_discovery.rs:505-710 r2o_probe_discovery_endpoint` | **P** | **Совпадает:** 25 обменов (`D2K_DISCOVERY_EXCHANGES=25`/`R2O_DISCOVERY_EXCHANGES=25`), свежий SSRC, первый запрос с STUN-префиксом, 74-байтный ответ, ожидание 3 с. **Отличие:** C отправляет prefix через `d2k_udp_plan_send`, Rust — raw engine + `RawSocket`; C использует один UDP-сокет, Rust raw-сокет только для кандидата. `r2o-discord-discovery-differential.sh`. |
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

**Построчная сверка a378:** все 12 функций прочитаны. Подтверждённые отличия: C печатает `d2k-plan`, Rust — `r2o-plan`/структурный Plan; `d2k_quic_delay_plan` (`d2k-plan 1 6 … delay 15000`) **не имеет продюсера** в R2O (есть только разбор/применение и тестовая фикстура); `d2k_quic_arm_plan`/`compose_plan`/`question_plan` разложены на `discovery_candidates` + `plan::apply`, побайтового differential текста нет. Voice-план (`payload/fake/order/pace 15000`) совпадает и покрыт `test-controller-udpplan-differential.sh`.

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

**Построчная сверка a378:** все 8 функций прочитаны. **Подтверждённые отличия:** C `udp_raw_prepare` на Linux **требует `IP_NODEFRAG`** и без него отказывает; в `r2o-datapath/src/raw.rs` есть только `IP_HDRINCL`/`IPV6_HDRINCL`/`SO_MARK`, `IP_NODEFRAG` отсутствует. C `d2k_udp_plan_send` читает TTL/hoplimit, собирает пачку, шлёт фрагменты raw, восстанавливает TTL и возвращает -2 на ECONNREFUSED; контроллерного API в R2O нет — проводное поведение разнесено по `plan::apply`/`wire::build_udp_fragments`/`raw.rs`, без get/set/restore TTL и без батча.

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

**Построчная сверка a378:** все 19 функций прочитаны. Константы совпадают: `D2K_VOL_STEPS=10`/`R2O_VOLUME_TX_STEPS=10`, `CHUNK=4000`, `MIN_KB=12`, `CHUNK_DELAY=50 мс`, connect/handshake 8000 мс, RTT-таймаут `clamp(3×RTT,1500,12000)`. `fill_pad` — тот же алфавит 62 символа и fallback `i*31+7` (E). `d2k_volume_rx_evidence` — E, построчный порт с тестами. **Отличия:** `d2k_vol_verdict_name` — «цель»/«мишень»; `connect_bounded`/`drain_head_*` — C byte-loop/TCP_NODELAY/restore vs Rust `connect_target`/HTTP-парсер; `resource_retry_path` не вынесен; `measure_response_volume`/`probe_response_volume`/`d2k_volume_probe_path` покрыты e2e, не все ветки (third probe/resource retry/short-preserve) имеют C/Rust differential.

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
| `fill_pad` | 247-257 | 11 | 4000 байт из `/dev/urandom`, алфавит `A-Za-z0-9`, fallback `i*31+7` | `fetch.rs:2545-2560 r2o_volume_padding` | **E** | Посимвольно совпадает: тот же алфавит, тот же fallback, тот же размер `R2O_VOLUME_TX_CHUNK_BYTES=4000`; тест X-Pad (`fetch.rs:4428-4435`). |
| `connect_bounded` | 259-322 | 64 | IPv4/IPv6, TCP_NODELAY, SO_NOSIGPIPE (где есть), SO_MARK при mark≠0, nonblock connect+poll 8000, SO_ERROR, восстановление flags | `fetch.rs:3017 connect_target`, `:3029 connect_marked`, `:2975 set_deadline` | **P** | **Совпадает:** mark, таймаут, nonblock connect, SO_ERROR. **Отличия:** C явно ставит TCP_NODELAY и восстанавливает исходные flags; Rust `connect_target`/`set_deadline` ставит read/write timeouts, TCP_NODELAY ставится в TLS-пути (`set_nodelay`), не в connect; C возвращает -1 с текстом, Rust — `ConnectTargetError` с `local_refusal`. |
| `drain_head_tls` | 325-349 | 25 | побайтово до пустой строки через TLS, дедлайн wait_ms | `fetch.rs` `HttpResponseParser::new(true)` | **P** | C читает по 1 байту и ищет `\n`/`\r\n`; Rust кормит парсер блоками (`head_only=true`). Для корректного HEAD результат тот же; таймауты/ошибки и лимит строки 4096 различаются. |
| `drain_head_plain` | 351-375 | 25 | то же для открытого TCP, poll+recv по 1 байту | `fetch.rs` тот же парсер | **P** | C poll+recv по байту, Rust — парсер; семантика пустой строки та же, тексты/дедлайн иные. |
| `resource_retry_path` | 393-406 | 14 | первый resource того же host (без регистра), `path_ok`, не равный текущему, в буфер | `fetch.rs:1366 r2o_fetch_resource_scan_allowed` + redirect | **P** | C выбирает путь из `a.resources` по host/`d2k_resource_path_ok`; Rust resource-scan строит `r2o_resources`, но отдельной функции «другой путь для повтора» нет — выбор/повтор реализован в fetch-композиции. C/Rust differential на этот выбор нет. |
| `rx_probe` | 411-427 | 17 | одна rx-проба с повтором при раннем обрыве | `fetch.rs:1447 r2o_fetch_rx_probe` | E | `d2o_verify_differential.rs` rx-volume тесты |
| `measure_response_volume` | 440-552 | 113 | identity-1; при partial — identity-2, при расхождении identity-3; gzip; evidence; resource-retry при завершённом ответе <12 КБ; `rx_unmeasured`/`rx_short`/`measured_path` | `fetch.rs:1430+ r2o_fetch_measure_rx_volume_with_fallback_path_and_timeouts` | **P** | **Совпадает:** identity-1/2, третий прогон только при `rx_needs_repeat`, gzip для evidence, порог 12 КБ, resource-retry. **Отличия:** C сам решает `rx_unmeasured`/`rx_short` и копирует `resources`/`measured_path`; Rust возвращает `R2oFetchVolumeRxResult`, композиция и reason-тексты иные. E2E-дифференциал `d2o_verify_differential.rs` покрывает rx-volume, но не все ветки third/resource-retry. |
| `probe_response_volume` | 558-593 | 36 | один повтор по resource-path; сохранить `rx_short`/`rx_short_bytes`, если повтор не дошёл до TLS | `fetch.rs:1509+ r2o_fetch_measure_rx_volume_with_fallback_path...` | **P** | C сбрасывает short/unmeasured перед повтором и восстанавливает short, если повтор `rx_tls_unavailable`/`rx_unmeasured`; Rust fallback-path делает один повтор, но поля/условие сохранения `rx_short` не сопоставлены. |
| `d2k_volume_probe_path` | 595-727 | 133 | connect 8 с, TLS1.3/1.2 8 с, 10×HEAD: шаг 0 без X-Pad, шаги 1..9 X-Pad 4000; read-timeout=clamp(3×RTT,1500,12000); gap 50 мс; CUT при ≥12 КБ, SHORT иначе, UNREACHABLE на шаге 0; затем rx-volume | `fetch.rs:1916-1954` tx ladder + `:1430+` rx | **P** | **Совпадает:** 10 шагов, 4000-байтный X-Pad со второго запроса, 50 мс, порог 12 КБ, RTT-clamp. **Отличия:** C сам ведёт TLS1.3/1.2 и byte-loop заголовков; Rust использует rustls + `HttpResponseParser`, а rx-volume вызывается отдельно; C при ошибке TLS/запроса всё равно запускает `probe_response_volume`, R2O-композиция иная. Точные ветки не покрыты единым C/Rust differential. |
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


---

# Группа `core-state`

# Аудит паритета D2O (C) → R2O (Rust): core/catalog…sched

Дата аудита: 2026-11-11. D2O-оракул: `a378e230947ebfd011439e1cac0f1e994d883aae`. R2O: `74a5795f379f50d9bb7d132acfaab0f5fcf3e8f7` (HEAD на момент начала работы — `d7b5a879…`; владельцы `main.rs`, `discovery.rs`, `classify.rs`, `control.rs` и остальные перечисленные Rust-файлы между этими коммитами не менялись). Срез: `slice-core-state.csv`, **692 функции** в 23 файлах.

Аудит выполнен только по исходникам: тела C-функций прочитаны целиком, Rust-аналоги найдены поиском по крейтам `r2o-controller` и `r2k-core`, проверены существующие тесты и дифференциалы в дереве. **Ни один тест в этом аудите не запускался**; поэтому статус `E` означает «есть эквивалентная реализация и готовое доказательство в дереве (C/Rust differential или C-фикстура)», а не «тест только что прошёл». Где прямого доказательства нет, стоит `P`/`?`.

Покрытие по статусам: **E = 126** (67 прямых + 59 static-хелперов), **P = 565** (263 + 302 static-хелперов), **N = 1**, **? = 0**. `E*`/`P*` — static-хелпер, наследующий статус владельца; отдельного контракта у него нет.

Важное ограничение методики: `end_line` в срезе для части функций обрезан эвристикой (например, `refuse_is_permanent`: 298–309 вместо 301–312, `d2k_fallback_arms`: 1498–1500 вместо 1500). В таблицах ниже строки и размер пересчитаны по фактическому телу (совпадение фигурных скобок с игнорированием комментариев/строк); поэтому они могут отличаться от колонок `line/end_line` среза на несколько строк. Каждая из 692 строк среза присутствует ровно один раз.

Легенда: `E` — эквивалент + differential/тест; `P` — реализация есть, но не все ветви/ошибки/таймеры/формат доказаны (пробел указан); `N` — реализации нет; `?` — не установлено. `P*`/`E*` — static-хелпер, статус владельца. В колонке R2O для `sched.c` часто указана подсистема/ветвь, а не единственная функция: у планировщика соответствие идёт на уровне состояний и обработчиков, точная карта — в разделе «`sched.c`: карта подсистем → Rust».

## Сводка по файлам

| Файл | Функций | E | P | N | ? | Основной Rust-владелец |
|---|---:|---:|---:|---:|---:|---|
| `core/catalog.c` | 60 | 3 | 57 | 0 | 0 | `catalog.rs` (serde_json вместо ручного парсера) |
| `core/compose.c` | 53 | 18 | 35 | 0 | 0 | `compose_d2o.rs`, `r2o_fallback.rs`, `ask.rs`, `classify_measured.rs` |
| `core/crypto.c` | 28 | 26 | 2 | 0 | 0 | крейты `aes`, `aes-gcm`, `sha2`, `hkdf`, `hmac`; `quic.rs` |
| `core/d2kask.c` | 24 | 0 | 24 | 0 | 0 | `ask.rs`, `main.rs::run_r2o_ask` |
| `core/d2kc.c` | 28 | 1 | 27 | 0 | 0 | `main.rs::serve_catalog`, `ControlClient`, `diagnostics.rs` |
| `core/d2kfetch.c` | 6 | 0 | 6 | 0 | 0 | `bin/r2o-fetch.rs`, `fetch.rs` |
| `core/d2kvoice.c` | 4 | 0 | 4 | 0 | 0 | `voice_measure.rs`, `voice_targets.rs`, `main.rs` |
| `core/diagnostics.c` | 41 | 0 | 41 | 0 | 0 | `diagnostics.rs` |
| `core/domain.c` | 4 | 0 | 4 | 0 | 0 | `domain.rs` + crate `psl` |
| `core/groups.c` | 14 | 0 | 14 | 0 | 0 | `groups.rs` |
| `core/link.c` | 43 | 2 | 41 | 0 | 0 | `r2k-core/control.rs` (decode/encode), `main.rs::ControlClient` |
| `core/match.c` | 3 | 0 | 3 | 0 | 0 | `catalog.rs` (`is_compatible_with`, `match_fingerprint`) |
| `core/meas.c` | 13 | 0 | 12 | 1 | 0 | `response.rs`, `raw_probe.rs`, `classify.rs`, `r2o_quic_http3.rs` |
| `core/measured.c` | 11 | 3 | 8 | 0 | 0 | `classify_measured.rs`, `r2o_rx_volume.rs` |
| `core/net4.c` | 4 | 3 | 1 | 0 | 0 | `std::net`, `quic_replay.rs`, `discovery.rs` |
| `core/p256.c` | 22 | 0 | 22 | 0 | 0 | `hpke`/`ring` (P-256 в rustls) |
| `core/plantlv.c` | 20 | 20 | 0 | 0 | 0 | `plan_text.rs` |
| `core/props.c` | 5 | 0 | 5 | 0 | 0 | `quic_replay.rs`, `r2o_quic_http3.rs` |
| `core/sched.c` | 282 | 48 | 234 | 0 | 0 | `main.rs` (R2oDiscoverySearches/Queue/Life), `discovery.rs`, `r2o_resource_limit.rs`, `r2o_fallback.rs`, `voice_*` |
| `core/verdict.c` | 7 | 0 | 7 | 0 | 0 | `classify.rs` (иное API; C-путь в d2kc мёртв) |
| `core/x25519.c` | 11 | 0 | 11 | 0 | 0 | `hpke`/`x25519-dalek` (X25519) |
| `core/include/d2k_link.h` | 3 | 3 | 0 | 0 | 0 | `r2k-core/control.rs` |
| `core/include/d2k_resource.h` | 6 | 0 | 6 | 0 | 0 | `r2o_resource.rs` |
| **Итого** | **692** | **127** | **564** | **1** | **0** | |

## Ключевые пробелы (P/N)

1. **`sched.c` (282 функции, 234 P, включая 132 static-хелпера)**: планировщик не является построчным портом. `R2oDiscoverySearches`/`R2oDiscoveryQueue`/`R2oDiscoveryWorkerLife` в `main.rs` покрывают cooldown, dead-address, очередь, own-first, ECH, voice и sync, но полная матрица состояний `T_ASKING→T_PROPS_*→T_PLANNING→T_TRIAL_SETTLE→T_VERIFY*→T_WATCHING` и редкие комбинации (ECH+volume, addr+voice, QUIC deny recheck) не доказаны.
2. **CLI `d2kask`/`d2kfetch`/`d2kvoice`/`d2kc`**: наборы флагов и stdout/exit расходятся; дифференциалы покрывают отдельные сценарии, а не полный CLI-контракт. У `d2kc` отсутствуют `--measure-mark`, `--log`, `--health-file`, `--https-cache=`, `--release-id`, `--self-check`; `--serve` имеет другую форму.
3. **Крипто-примитивы P-256/X25519** заменены `ring`/`hpke`/`dalek`; AES/SHA/HMAC/HKDF/GCM имеют C/Rust differential, но P-256/X25519 прямых C-векторов в дереве нет.
4. **`diagnostics.c`**: реализованы memory tracking, madvise и report.json, но C/Rust differential сравнивает только часть полей; полный формат отчёта, RSS-аномалии и smaps-ветви подтверждены unit-тестами, не C-оракулом.
5. **`catalog.c`**: ручной JSON-парсер заменён `serde_json`; загрузка/сохранение/atomic покрыты differential, но внутренние ветви парсера (экранирование, суррогатные пары/null, глубина) проверяются Rust-тестами, а не побайтовым C/Rust diff.
6. **`meas.c`/`measured.c`**: дифференциалы покрывают send/recv EINTR, timeout, часть RX-лестницы и measured-plan; полный набор accept/connect/raw-ветвей и все 5 вариантов RX-volume не сравнивались.
7. **`d2k_udp_port_forget_all` — единственный `N`**: в R2O реестр свежих UDP-портов не сбрасывается (static Mutex), сброс используется только тестами.

## `sched.c`: карта подсистем → Rust

Построчного соответствия «C-функция → Rust-функция» у планировщика нет; ниже — фактическое распределение ветвей, по которому выставлены статусы 282 строк.

| Ветвь C | Конкретные C-функции | Rust-владелец |
|---|---|---|
| Приём подозрения, фильтры, cooldown, dead address | `on_suspect`, `cooldown_*`, `dead_*`, `same_flow/remember/recall` | `main.rs::ControlClient::r2o_queue_tcp_suspect` (20090), `R2oDiscoveryQueue::queue_after_fresh_suspect` (13534), `R2oDiscoveryCooldownRing` (8509), `r2o_discovery_failure_backoff` (14284), `r2o_discovery_late_trigger` (7357) |
| Очередь, admission, worker permits, QUIC yield | `launch_or_queue`, `queued_*`, `quic_yield_tick`, `measure_*` | `main.rs::R2oDiscoveryQueue` (7883), `R2oDiscoveryWorkerLife` (9218), `r2o_resource_limit::R2oMeasurementGate` (445)/`R2oAdaptiveLimit` (144) |
| Состояния задачи и тайм-ауты | `d2k_sched_tick` (T_ASKING/T_PROPS_*/T_PLANNING/T_TRIAL_SETTLE/T_VERIFY*/T_WATCHING/T_VOICE_*) | `main.rs::R2oDiscoverySearches` (7971)/`R2oDiscoverySearch` (7985), `ControlClient` event loop, `apply_discovery_outcome` (21856), `r2o_queue_tcp_suspect` (20090) |
| Свойства коробки | `prop_send_next`, `prop_finish`, `d2k_props_ask_traced` | `ask.rs::question_plan/record_question_passed`, `main.rs::run_r2o_ask` |
| Кандидаты и подтверждение | `install_next`, `verify_confirm`, `partial_finish`, `budget_cut_reject`, `own_first_*`, `known_plans` | `main.rs::r2o_run_discovery_candidate_trial` (5717), `r2o_confirm_discovery_outcome` (5347), `install_http_candidate` (21781), `r2o_install_quic_candidate` (21506), `apply_discovery_outcome` (21856); `discovery.rs::{known_plans (274), own_first_plans (158), add_measured_binding (928)}` |
| Отказы и APPLIED | `on_applied`, `on_refused`, `on_refused_unfit`, `exec_refusal`, `local_refusal_verdict` | `main.rs::ControlClient::observe_applied` (15716), `observe_refused` (15752), `remember_applied_event` (20292), `r2o_ask_applied_matches` (22313); `control.rs::decode_applied/decode_refused` |
| ECH | `ech_*`, `start_search`, `worker_run_body` ECH-ветви | `main.rs::r2o_discovery_ech_config` (14394), `r2o_discovery_first_ech_witness` (14494), `r2o_discovery_ech_grease_fallback` (15311); `discovery.rs::r2o_ech_witness_candidates` (486) |
| QUIC | `fill_hellos` (QUIC), `quic_*`, `on_shape` QUIC, `worker_run_body` QUIC | `main.rs` QUIC worker/`r2o_quic_discovery_probe_path` (3136), `r2o_quic_http3.rs` (свежие порты 108), `quic_replay.rs` |
| Voice | `voice_start`, `voice_finish_measure`, `voice_confirm`, `voice_trial_send`, `voice_pending_dispatch` | `voice_discovery.rs::r2o_search_discovery_endpoint` (484)/`r2o_probe_discovery_endpoint` (505)/`evaluate_r2o_discovery` (728); `voice_measure.rs::r2o_measure_voice_for_flow` (250); `voice_targets.rs::r2o_parse_voice_targets` (17) |
| Синхронизация каталога и областей | `d2k_sched_sync*`, `area_*`, `desired_area`, `sync_areas` | `main.rs::R2oCatalogPersistence` (2097), `CatalogSyncCursor` (3887), `catalog_area_action` (3905), `catalog_area_store` (4004), `observe_area_ack` (4256), `expire_area_ack` (4305) |
| Live.json и диагностика | `d2k_sched_write_live`, `write_live_groups`, `d2k_sched_diagnostic_*`, `search_report` | `live.rs::snapshot` (63)/`write_snapshot` (199), `main.rs::r2o_live_searches` (12404)/`r2o_live_status` (12466), `diagnostics.rs::Recorder` |
| Ресурсы | `cpu_*`, `mem*`, `ct_*`, `res_sample`, `measure_limit_update` | `r2o_resource_limit.rs::{R2oAdaptiveLimit (144), R2oMeasurementGate (445), r2o_scheduler_tick (480)}` |

## Детальные таблицы

### `core/catalog.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `set_err` | 55–61 | 7 | записать текст ошибки | Result<_, CatalogError> | **P*** | static-хелпер |
| `jpeek` | 79–87 | 9 | пропустить пробелы и вернуть следующий символ | serde_json::Deserializer | **P*** | static-хелпер ручного JSON-парсера |
| `jeat` | 92–104 | 13 | ожидать конкретный символ JSON | serde_json | **P*** | static-хелпер |
| `jeat_null_if_present` | 110–117 | 8 | распознать null | Option<T> | **P*** | static-хелпер |
| `floor_div` | 148–153 | 6 | деление с округлением вниз | div_euclid | **P*** | static-хелпер |
| `days_from_civil` | 156–163 | 8 | дни от гражданской даты (алгоритм Ховарда Хиннанта) | time crate | **P*** | static-хелпер |
| `civil_from_days` | 166–178 | 13 | гражданская дата из числа дней | time crate | **P*** | static-хелпер |
| `format_rfc3339` | 185–195 | 11 | epoch в RFC3339 UTC | time::format_description | **E*** | static-хелпер; persist differential сравнивает поля added/confirmed |
| `jparse_raw_int` | 207–239 | 33 | строгий целый JSON без float/exponent, до 18 цифр | serde_json + validate | **P*** | static-хелпер; R2O отвергает float через типы/validate |
| `jparse_i32` | 241–250 | 10 | int32 из JSON | serde_json i32 | **P*** | static-хелпер |
| `jparse_u8` | 252–261 | 10 | u8 0..255 из JSON | serde_json u8 + validate | **P*** | static-хелпер |
| `jparse_u16` | 263–272 | 10 | u16 0..65535 из JSON | serde_json u16 | **P*** | static-хелпер |
| `jparse_bool_i` | 274–284 | 11 | true/false в int | serde_json bool | **P*** | static-хелпер |
| `jparse_string_dyn` | 305–402 | 98 | разбор JSON-строки с escape/\u и запретом NUL/суррогатов | serde_json String + validate | **P*** | static-хелпер; serde_json допускает суррогатные пары, R2O проверяет NUL отдельно |
| `jparse_string_fixed` | 408–422 | 15 | строка в фиксированный буфер | String + validate_string | **P*** | static-хелпер |
| `read_fixed_digits` | 428–445 | 18 | N цифр подряд | time crate | **P*** | static-хелпер |
| `eat_lit` | 447–454 | 8 | ожидать литерал времени | time crate | **P*** | static-хелпер |
| `jparse_rfc3339` | 462–500 | 39 | строгий RFC3339 с дробной частью и диапазонами | catalog::parse_timestamp | **P*** | static-хелпер; unit accepts_old_catalogs/rejects_trailing |
| `jskip_value` | 545–611 | 67 | пропуск произвольного JSON-значения с ограничением глубины 24 | serde_json + check_json_depth | **P*** | static-хелпер; unit rejects_excessive_nesting |
| `parse_object` | 629–655 | 27 | обход JSON-объекта с обработчиком ключей | serde_json derive | **P*** | static-хелпер |
| `grow` | 667–678 | 12 | рост динамического массива вдвое | Vec::push | **P*** | static-хелпер |
| `parse_array` | 692–717 | 26 | разбор JSON-массива в C-массив с null=>пусто | serde_json Vec | **P*** | static-хелпер |
| `handle_signal_key` | 723–742 | 20 | поля signal: kind/ttl/ttl_delta/tos/ipid/volume/seen/packets | catalog::Signal serde | **P** | unit round_trips_known_measurement_context |
| `parse_signal` | 743–746 | 4 | разобрать signal | catalog::Signal | **P*** | static-хелпер |
| `handle_fp_key` | 756–788 | 33 | поля fingerprint: method/signals до 8 | catalog::Fingerprint | **P** | unit rejects ... ninth_signal |
| `parse_fp` | 789–792 | 4 | разобрать fingerprint | catalog::Fingerprint | **P*** | static-хелпер |
| `handle_plan_key` | 798–816 | 19 | поля plan: id/proto/text/added/successes/enabled | catalog::Plan serde | **P** | unit round_trips_known_measurement_context |
| `parse_plan` | 817–820 | 4 | разобрать plan | catalog::Plan | **P*** | static-хелпер |
| `elem_plan` | 821–823 | 3 | элемент массива plans | Vec<Plan> | **P*** | static-хелпер |
| `handle_binding_key` | 834–885 | 52 | поля binding: kind/target/plan_id/level/confirmed/successes/enabled/transport/family/shape/tcp_profile/verified_by/input/probe_path/ech_origin/recheck_since/budget | catalog::Binding serde + validate | **P** | C `family` принимает только 4/6 (`catalog.c:852-859`), `tcp_profile` — только 0/1/2 (`:862-869`), затем пишет все поля. Rust `Binding` (`catalog.rs:166-198`) **не имеет `tcp_profile`**: serde молча игнорирует ключ, при save поле теряется. `family` в `Binding` есть, но без C-валидации 4/6 в `validate`. Для старых каталогов shape 1/2 + tcp_profile 1/2 теряется измеренный TS-профиль; R2O выводит его из shape только для 8–13. |
| `parse_binding` | 886–890 | 5 | `memset`, `out->family=4`, затем `parse_object` | `catalog.rs:166-198` `Binding` | **P** | C явно ставит `family=4` до разбора (`catalog.c:887-888`) и валидирует 4/6 при наличии. Rust `#[derive(Default)]` + `#[serde(default)]` даёт family=0; `serialize_family` пишет 0 как 4 **только при сохранении**, `validate` не нормализует. Старый каталог без `family` в памяти получает 0; поведение потребителей family=0 отличается от C. |
| `elem_binding` | 891–893 | 3 | элемент массива bindings | Vec<Binding> | **P*** | static-хелпер |
| `d2k_cat_shape_fits` | 905–912 | 8 | совместимость форм: 0 подходит любой, иначе **только равенство** | `group_shape_fits` (`live.rs:284`, `main.rs:3023`) | **P** | **Подтверждённое расхождение:** C `stored==0 || got==0 ? 1 : stored==got`; Rust дополнительно принимает `saved==SHAPE_MODERN && observed==SHAPE_ECH_TCP` (`1` vs `6`). C-вызовы `sched.c:3522/5088/7858` такую пару отвергают, Rust — нет. Используется для сопоставления binding/наблюдения. |
| `handle_box_key` | 918–939 | 22 | поля box: id/created/updated/fingerprint/plans/bindings | catalog::BoxRecord serde | **P** | unit round_trips |
| `parse_box` | 940–943 | 4 | разобрать box | catalog::BoxRecord | **P*** | static-хелпер |
| `elem_box` | 944–946 | 3 | элемент массива boxes | Vec<BoxRecord> | **P*** | static-хелпер |
| `handle_domain_observation` | 953–970 | 18 | поля domain observation: name/plan_id/key/evidence/at | catalog::DomainObservation serde | **P** | unit groups/catalog |
| `parse_domain_observations` | 972–989 | 18 | массив наблюдений до 256 | Vec<DomainObservation> | **P** | unit groups |
| `handle_net_whitelist_key` | 991–999 | 9 | поля network_whitelist: name/searched/tx_only/confirmed_utc | catalog::NetworkWhitelist | **P** | unit catalog |
| `handle_catalog_key` | 1001–1027 | 27 | корневые ключи: `boxes`, `domain_observations`, `domain_groups_frozen`, `domain_groups_disabled`, `domain_groups_disabled_at`, `network_whitelist`; `schema`/`updated`/`domain_groups` пропускаются | `CatalogInput` (`catalog.rs:1226-1239`) → `Catalog.domain_state` (`:364-381`), `CatalogOutput` (`:1240+`) | **E** | C разбирает те же top-level поля; `domain_observations` ≤256, frozen/disabled/disabled_at, network_whitelist. Rust `CatalogInput` читает их, `schema != 1` отвергает, неизвестные ключи игнорирует, конвертирует в `DomainState`; `CatalogOutput` пишет обратно. Есть `skips_unknown_fields`, persist differential и `validate` лимитов. |
| `parse_catalog_obj` | 1028–1034 | 7 | `memset`, `parse_object` с глубиной 1 | `Catalog::parse` (`catalog.rs:344-389`) | **P** | C стартует глубину с 1; Rust `check_json_depth` (64) + serde_json. Разбор верхнего объекта эквивалентен; отдельного кода функции нет. |
| `prune_unavailable_domain_groups` | 1036–1053 | 18 | после restore удалить группу, если нет **enabled** плана с тем же `plan_id` и proto (`transport 17` → `quic`, иначе `tls`) | `DomainState::restore` (`groups.rs:15`) → `rebuild` | **P** | **Подтверждённое расхождение:** C после `d2k_group_restore` проходит по группам и удаляет те, чей план отключён/отсутствует в каталоге (`catalog.c:1036-1053`). Rust `restore`/`rebuild` работают только с `DomainState` и не видят `boxes`, поэтому группа, выведенная из наблюдения, остаётся даже при отключённом/удалённом плане. Unit `derived_domain_groups_are_ignored` покрывает недоверие сохранённым `domain_groups`, но не prune по плану. |
| `free_box` | 1062–1070 | 9 | освободить планы/привязки коробки | Drop | **P*** | static-хелпер |
| `d2k_catalog_free` | 1072–1082 | 11 | освободить каталог | Drop | **P*** | static-хелпер |
| `d2k_catalog_memory_bytes` | 1084–1097 | 14 | память каталога: `n_boxes*sizeof`, планы/привязки, `strlen(text)+1`, `sizeof(groups)` | `catalog_bytes` = длина `to_json_at()` (`main.rs:16768`) | **P** | **Расхождение метрики:** C считает **in-memory** размер структур и текстов; Rust — длину **сериализованного JSON**. Числа систематически разные (JSON включает ключи/форматирование, но не capacity Vec). Для диагностического поля `catalog_bytes` смысл меняется; C/Rust differential на объём нет. |
| `read_whole_file` | 1103–1143 | 41 | прочитать файл целиком | std::fs::read | **P*** | static-хелпер |
| `d2k_catalog_load` | 1145–1191 | 47 | загрузка каталога: JSON, domain observations, prune, запрет мусора после объекта | catalog::Catalog::load | **E** | r2o-catalog-persist-differential.sh + tests/catalog.rs (старые каталоги, null, trailing garbage) |
| `write_json_string` | 1198–1218 | 21 | JSON-строка с escape | serde_json | **P*** | static-хелпер |
| `wr_indent` | 1220–1222 | 3 | отступ 2 пробела | serde_json::to_string_pretty | **P*** | static-хелпер |
| `write_json_array` | 1230–1240 | 11 | массив с отступами | serde_json | **P*** | static-хелпер |
| `write_signal_elem` | 1242–1257 | 16 | JSON signal, packets только при nonzero | catalog::Signal serde | **P** | persist differential сравнивает каталог частично |
| `write_fp` | 1259–1266 | 8 | JSON fingerprint | catalog::Fingerprint serde | **P** | то же |
| `write_plan_elem` | 1268–1280 | 13 | JSON plan с RFC3339 added | catalog::Plan serde | **P** | то же |
| `write_binding_elem` | 1282–1332 | 51 | JSON binding: kind/target/plan_id/level/confirmed/successes/enabled/transport/family/shape/**tcp_profile**/verified_by/input/probe_path/ech_origin/recheck_since/budget; family 0→4 | catalog::Binding serde | **P** | C всегда пишет `tcp_profile` (`catalog.c:1307`) и `family ? family : 4` (`:1300`). Rust `Binding` не имеет `tcp_profile`, поэтому ключ исчезает при save; `serialize_family` даёт 4 для 0, это совпадает. Полный побайтовый формат save не сравнивался (persist differential — save_atomic), статус P. |
| `write_box_elem` | 1334–1351 | 18 | JSON box с fingerprint/plans/bindings | catalog::BoxRecord serde | **P** | то же |
| `write_domain_key` | 1353–1358 | 6 | JSON-поля ключа области | GroupKey serde | **P*** | static-хелпер |
| `write_domain_observation` | 1359–1366 | 8 | JSON наблюдения области | DomainObservation serde | **P*** | static-хелпер |
| `write_domain_group` | 1367–1372 | 6 | JSON производной группы | DomainGroup serde | **P*** | static-хелпер |
| `d2k_catalog_save` | 1374–1442 | 69 | сохранение каталога schema=1 с flush/fsync | catalog::Catalog::to_json_at | **P** | persist differential проверяет save_atomic; отдельная сверка полного формата save не заявлена |
| `d2k_catalog_save_atomic` | 1445–1477 | 33 | сохранение в .new, rename и fsync каталога | catalog::Catalog::save_atomic | **E** | r2o-catalog-persist-differential.sh (включая конкурентное внешнее обновление) |

### `core/compose.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_net_whitelist_count` | 107–109 | 3 | число имён встроенного белого списка TCP 16-20 | r2o_rx_volume::r2o_rx_volume_name_count | **P*** | static-таблица; список и порядок покрыты unit r2o_rx_volume |
| `d2k_net_whitelist_name` | 110–112 | 3 | имя белого списка по индексу | r2o_rx_volume::r2o_rx_volume_name | **P*** | static-хелпер |
| `wr16be` | 150–150 | 1 | запись big-endian u16 | push_u16 | **P*** | static-хелпер TLV |
| `rd16be` | 151–151 | 1 | чтение big-endian u16 | read_u16 | **P*** | static-хелпер TLV |
| `wr32be` | 152–155 | 4 | запись big-endian u32 | push_u32 | **P*** | static-хелпер TLV |
| `tlv_rec` | 162–174 | 13 | TLV-запись с проверкой вместимости | plan_text::push_record | **P*** | static-хелпер; используется только TLV-тест-билдерами, прямого differential нет |
| `tlv_header` | 186–198 | 13 | заголовок D2KP и записи id/proto | plan_text::header | **P*** | static-хелпер; используется только TLV-тест-билдерами |
| `plan_tlv_stamp_ident` | 218–240 | 23 | FNV-1a идентификатор плана и запись в REC_ID | discovery.rs::plan_text_for_trial (1450) | **P** | идентификатор плана и FNV-1a проверяются plan/fallback differentials; запись именно в TLV REC_ID прямого C/Rust diff не имеет |
| `overlap_plan_tlv` | 258–270 | 13 | TLV-план перекрытия слева | compose_d2o overlap_plan_text + plan_text::compile_text | **P** | TLV-вариант используется только C-тестом test_plantlv; Rust собирает текст и компилирует, прямого TLV-differential нет |
| `reorder_plan_tlv` | 277–290 | 14 | TLV-план обратного порядка | compose_d2o reorder_plan_text + plan_text::compile_text | **P** | TLV-вариант используется только C-тестом; прямого TLV-differential нет |
| `badsum_fake_plan_tlv` | 296–316 | 21 | TLV-план badsum + fake с повторами/gap | compose_d2o badsum_fake_plan_text + plan_text::compile_text | **P** | TLV-вариант используется только C-тестом; текст покрыт compose differential, TLV — нет |
| `checksum_plan_tlv` | 322–326 | 5 | TLV-план проверки контрольной суммы | compose_d2o checksum + plan_text::compile_text | **P** | TLV-вариант используется только C-тестом; прямого TLV-differential нет |
| `to_hex` | 331–338 | 8 | байты в hex | hex-хелпер | **E*** | static-хелпер |
| `ev_matches_flow` | 351–366 | 16 | сравнение события с потоком в обе стороны | main.rs flow match helpers | **P** | перенесено; direct unit/diff на C-функцию нет |
| `wait_for_event3` | 397–421 | 25 | ожидание одного из трёх типов событий с code/filter/flow и дедлайном | main.rs ask event loop | **P** | реализовано в run_r2o_ask; C/Rust differential нет |
| `wait_for_event` | 423–429 | 7 | ожидание одного типа события | main.rs ask event loop | **P** | обёртка; см. wait_for_event3 |
| `props_bind_any` | 494–524 | 31 | socket/bind/getsockname локального TCP/UDP-порта, IPv6 `IPV6_V6ONLY=1`, ошибка при `out_fd==NULL` | `main.rs:22501-22611 BoundTcpProbe::open` | **P** | Rust: socket, nonblock+CLOEXEC, `SO_MARK=0x2d` (C bind не метит), bind/getsockname, отказ при нулевом порту. **Отличия:** Rust **не ставит `IPV6_V6ONLY`**; C закрывает fd и возвращает -1 при `out_fd==NULL`; Rust всегда владеет `OwnedFd`. Для IPv4/обычного IPv6 bind эквивалентно. |
| `d2k_props_bind` | 526–528 | 3 | bind IPv4 TCP | `BoundTcpProbe::open(4, ..)` | **P*** | Тонкая обёртка family=4. |
| `d2k_props_bind_family` | 530–532 | 3 | bind TCP family 4/6 | `BoundTcpProbe::open` | **P*** | family 4/6; наследует отсутствие `IPV6_V6ONLY`. |
| `d2k_props_bind_udp` | 534–536 | 3 | bind IPv4 UDP | нет прямого аналога | **P*** | UDP-bind для ask-вопросов не используется (вопросы TCP); отдельного Rust-хелпера нет. |
| `d2k_props_bind_udp_family` | 538–540 | 3 | bind UDP family 4/6 | нет прямого аналога | **P*** | То же; C-обёртка над `props_bind_any(SOCK_DGRAM)`. |
| `d2k_props_contact` | 542–545 | 4 | TCP-обращение к цели IPv4 с отправкой приветствия | CLI `run_r2o_ask` (`main.rs:493+`, `BoundTcpProbe`) | **P** | Реализовано только в CLI-опросе; production-discovery R2O этим путём вопросы не задаёт. C/Rust differential контакта нет. |
| `d2k_props_contact_on` | 547–551 | 5 | то же с готовым fd | `BoundTcpProbe` (fd внутри) | **P*** | C принимает `use_fd`; Rust владеет сокетом с момента open, отдельного «готового fd» нет. |
| `d2k_props_contact_on_family` | 553–558 | 6 | то же для family 4/6 | `BoundTcpProbe::connect` | **P*** | family 4/6; наследует отсутствие tcp-профиля. |
| `tcp_timestamps_read` | 567–578 | 12 | прочитать `/proc/sys/net/ipv4/tcp_timestamps`, допустить '0'..'2' | `raw_probe.rs:676` (только для host_offers_ts) | **P** | Rust читает тот же файл, но **не для connect-профиля**: helper'а `tcp_timestamps_read/write` вокруг connect нет. Для `host_offers_ts` чтение и дефолт 1 совпадают. |
| `tcp_timestamps_write` | 580–588 | 9 | записать tcp_timestamps | нет | **N** | Во всём `crates/` нет записи в `/proc/sys/net/ipv4/tcp_timestamps`; временное переключение sysctl не портировано. |
| `connect_with_tcp_profile` | 591–636 | 46 | под мьютексом прочитать/переключить tcp_timestamps, connect, восстановить; -2 при сбое профиля | нет | **N** | Rust не меняет sysctl и не имеет кодов -2/восстановления; `BoundTcpProbe::connect` делает обычный неблокирующий connect. Профиль TCP-опций задаётся только параметром `client_tcp_has_timestamps` для уже снятого приветствия, а не настройкой ядра. |
| `d2k_props_contact_on_family_tcp_profile` | 638–753 | 116 | полный TCP-contact: опции, nonblock connect, локальные адрес/порт, отправка hello, опциональный tcp-профиль | `main.rs:22501+ BoundTcpProbe`, `run_r2o_ask` | **P** | Перенесены socket/TCP_NODELAY/таймауты/неблокирующий connect/getsockname/отправка, но **параметр `tcp_timestamps` и sysctl-переключение отсутствуют**; C возвращает -3 при сбое профиля, Rust такого кода не имеет. `SO_NOSIGPIPE`-ветки macOS нет (Rust использует `MSG_NOSIGNAL`). |
| `build_fake_body` | 786–796 | 11 | тело fake: decoy-префикс + заполнитель 0f, длина `2*truth` | classify_measured.rs `fake_len=n*2`, `append_measured_payload` | **E** | C `want=truth_len*2`, `memset(0f)`, decoy копируется в голову с обрезкой до want; Rust `fake_len = n.saturating_mul(2)`, `append_measured_payload(..., fake_len, decoy)` даёт те же байты (decoy/0f). Покрыто `tests/measured_plan.rs`. |
| `d2k_props_question_plan` | 798–841 | 44 | TLV-план вопроса 0..4: overlap/reorder/checksum/protocol/duplicates | ask.rs:432 `question_plan` → `plan_text_for_poison` | **P** | Порядок вопросов и эффекты совпадают: q0 `0f`+seqovl, q1 split payload_start+1/sni_middle/reverse/pace 12000, q2 `0f`×`2*truth`, q3 decoy-hello (control, обрезка до `2*truth`)+badsum, q4 `0f`×`2*truth`+repeats 2/gap 20 мс. **Отличия формата:** C — TLV с id 1 для payload, Rust — текст `r2o-plan` с payload 2 у overlap; id плана C считает FNV-1a (`plan-%08x`), Rust принимает случайный `plan_id` от вызывающего. C/Rust differential планов вопросов нет; unit `question_order_and_plan_parameters` проверяет параметры, не байты. |
| `d2k_props_question_passed` | 845–864 | 20 | ответ вопроса → d2k_props: overlap/reorder/checksum=NO, protocol→parses=YES+checksum=NO, duplicates=YES | ask.rs:492 `record_question_passed` | **E** | Ветви совпадают посимвольно; Rust-тест `protocol_parse_requires_control_and_success_updates_only_its_proven_fields` проверяет protocol и запись только по проходу. |
| `question_retire` | 874–879 | 6 | снять пробный план: DEL_NAME_PROBE с transport 6, имя/shape/sport/family | `client.delete_name_probe(&sni, shape, family, source_port)` (`main.rs:528+`) | **P*** | Кадр DEL_NAME_PROBE тот же (см. link.c); C игнорирует ошибку снятия, Rust возвращает ошибку и в части ветвей прерывает опрос. |
| `d2k_props_ask` | 881–884 | 4 | опрос свойств без трассировки | `run_r2o_ask` (`main.rs:332`), `ask::question_plan` | **P** | Обёртка существует только в CLI; в discovery C-опрос заменён raw-пробами (см. `prop_send_next`). |
| `step_rc` | 889–898 | 10 | записать `rc`/`err` шага трассы | `r2o_print_ask_trace`/`AskStep` (`main.rs`) | **P*** | C пишет в массив `d2k_props_step`; Rust печатает строку трассы, структуры шага нет. |
| `d2k_props_ask_traced` | 900–1191 | 292 | 5 вопросов по очереди: bind порт, SET_NAME_PROBE, ACK, contact, EXCHANGE/APPLIED/REFUSED, остановка на первом прошедшем | main.rs:332-780 `run_r2o_ask` + ask.rs | **P** | **Совпадает:** 5 вопросов в одном порядке, bind до установки плана, SET_NAME_PROBE, ожидание ACK, contact, ожидание APPLIED+ServerHello, снятие непрошедшего вопроса, остановка на первом прошедшем. **Отличия:** (1) C id плана — FNV-1a TLV, Rust — случайный `plan_id`/`trial_id` (header, п. 17); (2) C не сверяет trial_id в ACK, Rust отвергает чужой trial; (3) C считает проход по `applied && server_hello` (exchange подразумевается hello), Rust требует ещё `exchange_seen`; (4) C при ошибке снятия плана игнорирует её, Rust возвращает ошибку и может прервать опрос; (5) CLI differential не сравнивает stdout, отдельные ветви NO_ACK/UNSENT/APPLIED покрыты unit. |
| `append_fmt` | 1203–1213 | 11 | дописать форматированный текст | String::push_str | **E*** | static-хелпер |
| `emit_header_proto` | 1221–1227 | 7 | заголовок d2k-plan/id/proto | compose_d2o::header | **E*** | static-хелпер; compose differential |
| `emit_header` | 1229–1231 | 3 | заголовок tcp tls | compose_d2o::header | **E*** | static-хелпер |
| `append_hex` | 1233–1239 | 7 | дописать hex | compose_d2o::hex | **E*** | static-хелпер |
| `overlap_plan_text` | 1245–1256 | 12 | текстовый план перекрытия слева | compose_d2o overlap_plan_text | **E** | d2o_compose_differential.c |
| `reorder_plan_text` | 1271–1279 | 9 | текстовый план обратного порядка с pace | compose_d2o reorder_plan_text | **E** | d2o_compose_differential.c |
| `badsum_fake_plan_text` | 1288–1305 | 18 | текстовый badsum+fake план | compose_d2o badsum_fake_plan_text | **E** | d2o_compose_differential.c |
| `checksum_plan_text` | 1312–1316 | 5 | текстовый план checksum (64 байта 0f) | compose_d2o checksum | **E** | d2o_compose_differential.c |
| `build_decoy_hello` | 1346–1351 | 6 | ClientHello приманки modern/legacy по decoy-имени | compose_d2o::decoy_hello | **E** | compose differential |
| `parse_protocol_plan_text` | 1356–1361 | 6 | план вопроса protocol (badsum + decoy hello) | compose_d2o parse_protocol_plan_text | **E** | d2o_compose_differential.c |
| `duplicates_plan_text` | 1367–1372 | 6 | план вопроса duplicates (2 повтора, gap 20 мс) | compose_d2o duplicates_plan_text | **E** | d2o_compose_differential.c |
| `body_room` | 1384–1388 | 5 | запас тела под заголовки 120 байт | compose_d2o D2K_HEAD_ROOM | **E*** | static-хелпер |
| `everything_plan_text` | 1397–1426 | 30 | запасной «всё сразу» план при отсутствии свойств | compose_d2o everything_plan_text | **E** | d2o_compose_differential.c |
| `d2k_fallback_arms` | 1499–1501 | 3 | число запасных arm-ов донора | r2o_fallback::total | **E** | r2o-fallback-differential.sh |
| `fb_arm_at` | 1504–1540 | 37 | arm по индексу: head/fake/ttl/seqovl/dup | r2o_fallback::arm | **E** | r2o-fallback-differential.sh |
| `d2k_fallback_plan` | 1543–1550 | 8 | текст запасного плана по индексу | r2o_fallback::plan | **E** | r2o-fallback-differential.sh + unit fallback_plans_match_donor |
| `d2k_arm_plan` | 1552–1751 | 200 | общий текст плана из arm: disorder_pos, oob, seqovl/seqovl_hello, fake (badsum/ttl/tcpts/ipidzero/seq_out), between, repeats/gap, pace | `r2o_fallback::plan` (`:168`) для 49 fallback-arm; `classify_measured::plan_text_for_poison` для измеренных arm | **P** | C одна функция на оба входа. Rust разделён: `r2o_fallback::plan` жёстко берёт decoy `"disk.rzd.ru"` (совпадает с production `SCHED_DECOY`), `disorder_pos` печатает как `+2` (в fallback-списке только 2), не умеет `tcpts`/`ipidzero`; `plan_text_for_poison` умеет `tcpts`/`ipidzero`/`seqshift`/`split_pos` и произвольный `disorder_pos`. `r2o-fallback-differential.sh` покрывает 49 arm × 5 send_cap; произвольные сочетания arm и общий `d2k_arm_plan` одним differential не покрыты. |
| `d2k_compose` | 1763–1799 | 37 | набор планов из вектора свойств: overlap, reorder, duplicates, checksum (если parse≠YES), protocol, fallback «всё сразу» | `compose_d2o::compose_plan_texts` (`:101`), production `ask::compose_plan_texts` (`:305`) | **E** | `d2o_compose_differential.c` + unit `compose_d2o`. Порядок и условия ветвей совпадают. `compose_d2o` — чистый побайтный порт `d2k-plan 1 1`; production `ask::compose_plan_texts` печатает `r2o-plan 1 10` (формат runtime R2O) с теми же эффектами; текст сравнивается через compose-дифференциал именно для `compose_d2o`. |

### `core/crypto.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `xtime` | 33–36 | 4 | умножение байта на x в GF(2^8) для AES | crate aes (внутренняя таблица) | **E*** | static-хелпер AES; результат покрыт test-core-crypto-differential.sh, отдельной функции нет |
| `d2k_aes_sbox_byte` | 70–72 | 3 | доступ к таблице S-box AES | crate aes | **E*** | static-таблица; AES-128 ECB сверяется дифференциалом crypto |
| `aes128_key_expand` | 80–110 | 31 | раскрытие ключа AES-128 в 11 раундовых ключей | crate aes::Aes128 | **E*** | static-хелпер; покрыт AES-128 ECB вектором |
| `sub_bytes` | 112–116 | 5 | раунд SubBytes AES | crate aes | **E*** | static-хелпер AES |
| `shift_rows` | 121–129 | 9 | раунд ShiftRows AES | crate aes | **E*** | static-хелпер AES |
| `mix_columns` | 131–140 | 10 | раунд MixColumns AES | crate aes | **E*** | static-хелпер AES |
| `add_round_key` | 142–146 | 5 | XOR состояния с раундовым ключом | crate aes | **E*** | static-хелпер AES |
| `aes128_encrypt_block` | 151–165 | 15 | шифрование одного 16-байтного блока AES-128 | crate aes::BlockEncrypt | **E*** | static-хелпер; ECB-вектор FIPS-197 совпадает |
| `d2k_aes128_ecb` | 167–171 | 5 | AES-128 ECB одного блока (публичный API) | crates/r2k-core/src/quic.rs:1023 Aes128 | **E** | test-core-crypto-differential.sh: case aes128-ecb |
| `rotr32` | 175–177 | 3 | циклический сдвиг 32-битного слова для SHA-256 | crate sha2 | **E*** | static-хелпер SHA-256 |
| `sha256_compress` | 201–228 | 28 | компрессия блока SHA-256 | crate sha2 | **E*** | static-хелпер; SHA-256 покрыт дифференциалом |
| `sha256_init` | 230–238 | 9 | инициализация контекста SHA-256 | crate sha2::Sha256 | **E*** | static-хелпер SHA-256 |
| `sha256_update` | 242–265 | 24 | накопление данных SHA-256 | crate sha2::Digest::update | **E*** | static-хелпер SHA-256 |
| `sha256_final` | 267–290 | 24 | дополнение и финализация SHA-256 | crate sha2::Digest::finalize | **E*** | static-хелпер SHA-256 |
| `d2k_sha256` | 292–297 | 6 | SHA-256 буфера | crate sha2::Sha256 | **E** | test-core-crypto-differential.sh: sha256-abc, sha256-100 |
| `d2k_hmac_sha256` | 301–327 | 27 | HMAC-SHA-256 с ключом любой длины | crate hmac::Hmac<Sha256> | **E** | test-core-crypto-differential.sh: hmac-key-message, hmac-long |
| `d2k_hkdf_extract` | 331–339 | 9 | HKDF-Extract (HMAC с солью) | crate hkdf::Hkdf::<Sha256>::extract | **E** | test-core-crypto-differential.sh: hkdf-extract |
| `d2k_hkdf_expand_label` | 350–353 | 4 | обёртка `..._ctx(..., ctx=NULL, 0)` | `quic.rs:893-907 expand_label` + `hkdf` | **P** | **Подтверждённое расхождение границ:** C `D2K_HKDF_LABEL_MAX=58` (`d2k_crypto.h:88`) отвергает label >58; Rust `u8::try_from(6 + label.len())` допускает до 249 (255-6), затем `hkdf.expand`. Для production-меток (`client in`, `quic key`, …) совпадает; differential `hkdf-client-in`/`hkdf-quic-key` границы не проверяет. |
| `d2k_hkdf_expand_label_ctx` | 355–427 | 73 | HkdfLabel: out_len BE16, full_label, ctx_len, ctx; label ≤58, ctx ≤32 | `quic.rs:893` (ctx всегда пуст) + `m6_crypto_trace.rs:24-36` | **P** | **Подтверждённые расхождения:** (1) C отвергает `label_len>58`, Rust `expand_label` — только `6+len>255`; (2) C принимает контекст до 32 байт и кодирует его, production-Rust `expand_label` **всегда пишет ctx_len=0** и параметра контекста не имеет; m6-пример принимает context, но `context.len() as u8` без проверки >255. Дифференциал `hkdf-derived-ctx` сравнивает только фиксированный 32-байтный контекст на C-стороне/примере. |
| `gf128_h_table` | 449–461 | 13 | таблица умножения на H в GF(2^128) для GHASH | crate aes-gcm (GHASH) | **E*** | static-хелпер GCM |
| `gf128_mul_fast` | 463–474 | 12 | умножение в GF(2^128) по таблице | crate aes-gcm | **E*** | static-хелпер GCM |
| `ghash` | 479–535 | 57 | GHASH по AAD и шифротексту | crate aes-gcm | **E*** | static-хелпер; тег GCM сверяется дифференциалом |
| `d2k_ghash_for_test` | 538–541 | 4 | экспорт GHASH для C-тестов | crate aes-gcm (нет публичного API) | **E*** | тест-хук; отдельного Rust API нет, GHASH покрыт тегом GCM |
| `inc32` | 547–554 | 8 | инкремент младших 32 бит счётчика GCM | crate aes-gcm | **E*** | static-хелпер GCM |
| `gctr` | 560–578 | 19 | GCTR-режим AES-128 для GCM | crate aes-gcm | **E*** | static-хелпер GCM |
| `consttime_eq16` | 584–590 | 7 | сравнение 16 байт за постоянное время | crate aes-gcm (тег) | **E*** | static-хелпер; проверка тега покрыта bad-tag case |
| `d2k_aes128_gcm_encrypt` | 596–625 | 30 | AES-128-GCM шифрование с AAD и тегом | crate aes_gcm::Aes128Gcm | **E** | test-core-crypto-differential.sh: gcm-ciphertext/gcm-tag |
| `d2k_aes128_gcm_decrypt` | 627–671 | 45 | AES-128-GCM расшифрование и проверка тега | crate aes_gcm::Aes128Gcm | **E** | test-core-crypto-differential.sh: gcm-opened и gcm-bad-tag (rc=-1) |

### `core/d2kask.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `need_value` | 120–128 | 9 | проверка наличия значения флага | ask::parse_ask_options | **P*** | static-хелпер CLI |
| `parse_flag_u16` | 134–149 | 16 | u16 >0 с верхней границей | ask::parse_positive_port | **P*** | static-хелпер |
| `parse_flag_u32` | 157–172 | 16 | u32: `strtoul` base 0 (0x hex, ведущий 0 — восьмеричное, иначе десятичное), минус запрещён | `ask.rs:190-206 parse_mark` | **P*** | **Оба принимают 0x/восьмеричное/десятичное.** Отличия: C `strtoul` допускает ведущие пробелы и `+`; Rust `parse_mark` их отвергает. Переполнение: C `ERANGE`, Rust `u32` range. |
| `parse_flag_ms` | 179–194 | 16 | положительное десятичное мс, `strtol`, ≤LONG_MAX | `ask.rs:179-188 parse_positive_ms` | **P*** | Оба >0. C `strtol` принимает `+`/пробелы и ограничен LONG_MAX; Rust `u64::parse` строже и вмещает больше, затем `Duration::from_millis`. |
| `parse_args` | 202–301 | 100 | разбор CLI: флаги, обязательные, hello/control-взаимоисключения | `ask.rs:44-160 parse_ask_options` | **P** | Набор флагов совпадает. **Отличия:** C при повторе флага берёт последний, Rust `one()` отвергает повтор; C хранит `--ip` строкой и разбирает позже, Rust парсит `IpAddr` сразу; коды/тексты ошибок разные. |
| `hex_nibble` | 315–320 | 6 | значение hex-цифры | ask::decode_hex | **P*** | static-хелпер |
| `save_hex` | 329–349 | 21 | заголовок `# снимок {what}, имя {sni}, N байт — снят d2kask…`, 32 байта/строку | `main.rs:783-808 save_ask_snapshot` | **P** | Формат hex/32 байта/строку совпадает; в заголовке Rust пишет «снят r2o-controller», C — «снят d2kask». Ошибка записи в обоих не прерывает опрос. |
| `read_hex_file` | 361–414 | 54 | комментарии `#` после пробелов, hex/пробелы, нечёт/пусто/`>cap` → отказ | `ask.rs:209-260 read_hex_file/decode_hex` | **P** | Логика совпадает: комментарии, hex, нечётные цифры, пустой файл, cap 2048. **Отличие:** C читает фиксированными строками по 8200 байт; комментарий длиннее буфера будет разрезан и вторая часть даст «недопустимый символ», Rust пропускает строку целиком. Unit `ask.rs`; C/Rust differential нет. |
| `wait_shape` | 424–455 | 32 | ожидание D2K_EV_SHAPE до дедлайна | main.rs run_r2o_ask: wait_shape branch | **P** | логика таймаута перенесена; differential не найден |
| `pval_str` | 462–468 | 7 | текст pval: да/нет/не измерено | main.rs run_r2o_ask output | **P*** | static-хелпер формата |
| `print_header` | 470–476 | 7 | заголовок отчёта d2kask | main.rs run_r2o_ask output | **P*** | static-хелпер формата |
| `print_snapshot` | 482–502 | 21 | печать снимка, SNI и вида приветствия | main.rs run_r2o_ask output | **P*** | static-хелпер формата |
| `pos_decided` | 519–528 | 10 | решён ли вопрос свойств | ask::DpiProps/AskQuestion | **P*** | static-хелпер |
| `pos_value` | 530–539 | 10 | значение вопроса свойств | ask::DpiProps | **P*** | static-хелпер |
| `step_rc_str` | 547–561 | 15 | текст кода шага опроса | main.rs ask step output | **P*** | static-хелпер |
| `ack_code_str` | 565–573 | 9 | текст кода ACK | main.rs r2o_ask_ack_reason | **P*** | static-хелпер |
| `print_seen_types` | 579–594 | 16 | печать встреченных TLS-типов | main.rs r2o_ask_print_seen_types | **P*** | static-хелпер |
| `print_step` | 597–624 | 28 | печать шага: план, обмен, причина | main.rs run_r2o_ask output | **P*** | static-хелпер формата |
| `print_question` | 632–674 | 43 | печать вопроса и его ответа | main.rs run_r2o_ask output | **P*** | static-хелпер формата |
| `all_unknown` | 676–682 | 7 | все пять свойств не измерены | ask::DpiProps::all_unknown | **P*** | static-хелпер |
| `print_not_asked_at_all` | 684–696 | 13 | печать отказа от всех вопросов | main.rs run_r2o_ask output | **P*** | static-хелпер формата |
| `print_vector` | 698–705 | 8 | печать итогового вектора свойств | main.rs run_r2o_ask output | **P*** | static-хелпер формата |
| `print_plans` | 707–725 | 19 | печать планов d2k_compose | main.rs run_r2o_ask output | **P*** | static-хелпер формата |
| `main` | 736–913 | 178 | CLI d2kask: снимок триггера/control, d2k_props_ask_traced, d2k_compose, exit 0/2 | main.rs r2o_ask_command/run_r2o_ask + ask.rs | **P** | есть unit/ask и r2o-ask-differential.sh без сравнения stdout; C при нечисловом --ip/битом hello доходит до «ни один вопрос не задан» и exit 0, Rust возвращает 1/2 |

### `core/d2kc.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `on_signal` | 111–111 | 1 | SIGINT/SIGTERM выставляют stop_asked | main.rs signal handler | **P*** | static-хелпер; Rust использует atomic/cancel |
| `now_ms` | 113–117 | 5 | монотонное время в мс | std::time::Instant | **P*** | static-хелпер |
| `save_atomic` | 122–125 | 4 | атомарное сохранение каталога | catalog::Catalog::save_atomic | **E** | r2o-catalog-persist-differential.sh |
| `self_mem` | 136–148 | 13 | RSS/HWM/VmData/Threads из /proc/self/status | diagnostics::process_memory | **P** | реализовано; формат/точки чтения отличаются, отдельного C/Rust differential нет |
| `sched_say` | 150–157 | 8 | журнал планировщика с локальным временем | main.rs log callback | **P*** | static-хелпер |
| `http_search_portal` | 168–174 | 7 | класс 3 (портал) → `d2k_httpsearch_portal`: пропуск при `!g_hs`, family 0, UNKNOWN/PROBING, `d2k_https_upgrade(st)` | `r2o_http_search_https_action` (`main.rs:4729-4750`) | **P** | C передаёт портал только для известного не-upgrade состояния; Rust решает `Queue/Suppress/Wait` по `response_code==3`, `live_bound_failure`, `HttpsProbeState::should_redirect()` и `probe_pending`. Наборы условий различаются: Rust откладывает/подавляет при pending, C при PROBING просто выходит. |
| `hs_open_port` | 176–208 | 33 | socket family, опциональный `SO_MARK=g_probe_mark`, bind, getsockname | `BoundTcpProbe::open` (`main.rs:22507-22611`) | **P** | C: socket, mark только если `g_probe_mark!=0`, bind/getsockname, без nonblock/CLOEXEC. Rust: mark `unwrap_or(0x2d)` (0 отключает), nonblock+CLOEXEC, отказ при нулевом порту. При `Some(0)` марка не ставится, как и в C при `g_probe_mark==0`; Rust шире по проверкам. |
| `hs_close_port` | 210–210 | 1 | `close(fd)` | `OwnedFd`/Drop (`BoundTcpProbe`) | **P*** | C закрывает явно; Rust владеет fd и закрывает при drop. |
| `hs_hex` | 212–219 | 8 | `d2k_plan_text_to_hex` в буфер 8192, ошибка в stderr | `compile_text` + `r2o_plan_records_for_wire` | **P** | C печатает ошибку и возвращает -1; Rust возвращает `String`-ошибку, текст и стадия иные. Компиляция плана покрыта plan_text/дифференциалами. |
| `hs_set_probe` | 221–233 | 13 | SET_NAME_PROBE trial: `SHAPE_HTTP`, sport, family | `encode_set_name_probe(&host, wire_shape, family, port, ..)` (`main.rs:5545`) | **P** | C всегда `D2K_LINK_SHAPE_HTTP`; Rust `wire_shape = r2o_plan_wire_shape(target.shape, has_timestamp)` — для HTTP-цели ожидается 7, но функция не жёстко фиксирует HTTP. Кодирование покрыто control tests. |
| `hs_del_probe` | 235–244 | 10 | DEL_NAME_PROBE с `SHAPE_HTTP` | `delete_name_probe(&host, shape, family, port)` (`main.rs:19799`) | **P** | Кадр тот же для shape 7; Rust принимает shape из задачи. |
| `hs_set_plan` | 246–257 | 12 | SET_NAME_BOUND с `SHAPE_HTTP`, token | `encode_set_name_bound` (`main.rs:21813`) | **P** | `encode_set_name_bound` сам требует `SHAPE_HTTP` и ненулевой trial — совпадает с C-вызовом; C дополнительно не проверяет plan records, Rust проверяет (см. link.c). |
| `hs_del_plan` | 259–269 | 11 | проверка `binding->family == family` и `d2k_binding_known`, затем DEL_NAME_BOUND | `send_http_owned_delete` (`main.rs:21608`) | **P** | **Расхождение:** C отвергает binding с чужим `family`; Rust `encode_delete_name_bound(host, 6, binding)` проверяет известность/kind/temporary, но **не сверяет `binding.family` с целевым family**. Для каталога с family 6 и target family 4 команда уйдёт, C-датапат её отвергнет позже. |
| `hs_start` | 271–274 | 4 | `d2k_hs_runner_start` | `HttpSearchTask`/worker (`main.rs:4689+`) | **P** | C отдельный runner; Rust задача в общем планировщике. Жизненный цикл покрыт http-search differential частично. |
| `hs_changed` | 277–284 | 8 | сохранить `http-plans.txt` через `d2k_httpsearch_save` | каталог JSON (`R2oCatalogPersistence`) | **P** | **Расхождение (header, п. 21):** C пишет отдельный файл формата `d2k-http-plans 1`; в Rust grep `http-plans` пуст — подтверждённые HTTP-кандидаты живут в каталоге JSON. Момент сохранения (по изменению) и формат не совпадают. |
| `http_portal` | 288–308 | 21 | `d2k_httpsprobe_portal` → rc 0: http_search_portal, rc 1: лог «проверяю HTTPS», rc 2: SET_HTTPS с ttl | `r2o_http_search_https_action` (`main.rs:4729`), `encode_set_https` (`:16610`, `:17033`) | **P** | C rc 0/1/2 — три исхода одной функцией; Rust разносит решение по `HttpSearchHttpsAction` (`Queue/Suppress/Wait`) и отдельно отправляет `encode_set_https`. Условия `probe_pending`/`live_bound_failure`/`should_redirect` в C выражены иначе. |
| `http_push` | 310–315 | 6 | `d2k_link_set_https(host, ttl)` + stderr при ошибке | `encode_set_https` (`main.rs:16610`, `:17033`) | **P** | Кодирование покрыто control tests; TTL-политика R2O (6 ч) уже расходится с C (7 суток) — header, п. 1. |
| `http_save` | 317–322 | 6 | `d2k_httpsprobe_save(path, now, wall)` + stderr | `https_probe.save_cache(path, wall_now, Instant::now())` (`main.rs:17080`) | **P** | Формат/атомарность кэша C и Rust не сравнивались; вызов сохранения есть. |
| `http_probe_done` | 324–355 | 32 | drain до 8 результатов, лог, `http_push`/`http_search_portal`, save при total, лог роста `lost` | `https_probe` drain (`main.rs:17033+`), `save_cache` | **P** | Поток «up → SET_HTTPS, иначе → HTTP-поиск» перенесён; **счётчика `d2k_httpsprobe_lost` в Rust нет** (core-net, N), поэтому лог потерь и повторная проверка имён отсутствуют. |
| `hs_say` | 357–357 | 1 | журнал HTTP-поиска через `sched_say` | `main.rs` log callback | **P*** | static-хелпер. |
| `poison_cmp` | 365–367 | 3 | сортировка `poison_seen` по `succ` убыванию | `sort_by_key(Reverse(successes))` (`main.rs:4587`) | **P*** | C `qsort` по разности, Rust `Reverse`; при равных successes порядок C не стабилен, Rust stable sort сохраняет порядок каталога. |
| `hs_measured_poisons` | 368–392 | 25 | каталог → до 8 poison-спеков на план, всего 64, сортировка по successes, `d2k_httpsearch_measured_poison` | `measured_http_candidate_keys` (`main.rs:4565-4597`) + `measured_poison_keys` (`http_search.rs:719`) | **P** | **Отличия:** C ограничивает 8 спеков на план и 64 всего, передаёт **сырой** spec; Rust извлекает poison-ids из текста, маппит в ключи (`fake-badsum`, `fake-seqshift`, `fake:{spec}`), дедуплицирует и берёт максимум **8**. C-фильтр `text contains "\nproto tcp tls\n"`, Rust — `plan.proto=="tls"` + строка `proto tcp tls`. Сортировка по successes в обоих. |
| `usage` | 394–404 | 11 | справка: `--control/--catalog/--live/--log/--https-cache/--mark/--measure-mark/--health-file/--version` | `main.rs:1721 print_help`, `--serve` | **P** | C-набор флагов и умолчаний (`--mark 0x2e` в тексте, фактически 0x2d; `--measure-mark` по умолчанию = mark) шире `--serve СОКЕТ КАТАЛОГ [--discover] [--mark N]`; `--live/--log/--health-file/--https-cache/--measure-mark/--release-id/--self-check` отсутствуют или имеют другую форму. |
| `offline_self_check` | 406–411 | 6 | `D2K_CTL_PROTO_VERSION == D2K_RUNTIME_WIRE` и SHA-256(`abc`) == `ba78…15ad` | `--version` (`main.rs`), crypto tests | **P** | C вызывается через `d2k_runtime_offline(argc, argv, "d2kc", offline_self_check)` (флаг `--self-check`). В `r2o-controller` grep `self-check/offline` пуст: флага нет; wire-версия проверяется при handshake, SHA-256 — только crypto-дифференциалом. Отдельного offline-входа нет. |
| `diagnostic_event` | 415–417 | 3 | `d2k_diag_record` события планировщика/HTTP | `Recorder::record` (`diagnostics.rs`) | **P** | Колбэк перенесён; состав полей события и точки вызова проверяются частично differential/unit. |
| `diagnostic_limit` | 418–420 | 3 | `d2k_diag_record_limit` смены лимита | `Recorder::record_limit` | **P** | То же; C передаёт `mono` и `d2k_diag_counts`, Rust — `Counts`. |
| `diagnostic_tick` | 421–468 | 48 | раз в 1 с проверка `D2K_DIAG_DIR`, раз в 60 с sample+`report.json` через `report.new` + rename, madvise reset, memory enable | `Recorder::tick/write_report` (`:790`, `:1179`) | **P** | Жизненный цикл (включение/выключение, 60 с, временный файл) перенесён; unit `diagnostic_tick_lifecycle_matches_d2o`. C дополнительно сбрасывает madvise и включает memory-сэмплер при создании; C/Rust differential сравнивает только часть JSON. |
| `main` | 470–931 | 462 | главный цикл d2kc: CLI, каталог, greeting, link, sched, https/httpsearch, hooks, sync, poll, save/live/report, health, graceful stop, exit 1 при потере link | `serve_catalog` + `ControlClient` + `R2oCatalogPersistence` + `diagnostics` (`main.rs`) | **P** | Перенесены каталог/link/sched/https/httpsearch/poll/sync/save/live/report/health/graceful stop. **CLI-непаритет:** нет `--measure-mark`, `--log`, `--health-file` (Rust health пишется иначе), `--https-cache=`, `--release-id`, `--self-check`, периодической сводки событий; `--serve` позиционный. Отдельного C/Rust differential `main` нет. |

### `core/d2kfetch.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `json_string` | 41–62 | 22 | JSON-строка: `"`/`\\`, control → `\\u%04x`, валидный UTF-8 как есть, иначе `\\u%04x` | serde_json::to_string | **P*** | C сам валидирует UTF-8 (overlong/surrogate/>0x10ffff) и печатает `\u00xx`; Rust строки всегда валидны, serde_json экранирует control иначе (`\u001f` и т.п.). Для ASCII эквивалентно. |
| `vol_verdict_code` | 64–72 | 9 | `unreachable/cut/passed/short/unknown` | `bin/r2o-fetch.rs:227` match `R2oFetchVolumeTxVerdict` | **P** | Строки совпадают; CLI-differential не проверяет. |
| `usage` | 74–102 | 29 | флаги `--name/--ip/--port/--path/--wire/--snapshot[=ms]/--ladder/--mark/--quic/--tls12/--deadline/--json/--version` | `r2o-fetch` print_help | **P** | Набор флагов расширен (`--quic-budget`, `--control`); текст/форма справки отличаются. |
| `resolve_first` | 104–114 | 11 | `getaddrinfo(AF_UNSPEC,SOCK_STREAM)`, первый адрес, `getnameinfo(NI_NUMERICHOST)` | `std::net::ToSocketAddrs` | **P** | C берёт первый результат getaddrinfo (порядок ОС), Rust — первый из `ToSocketAddrs`; семейство/порядок могут отличаться. `r2o-fetch-cli-differential.sh` проверяет только localhost. |
| `snapshot_wire` | 117–155 | 39 | link open (NULL sock), ARM_SHAPE transport 6, ожидание `D2K_EV_SHAPE` transport 6 до `wait_ms`, `shape_len` | `fetch::r2o_fetch_snapshot_wire_len`, CLI snapshot tests | **P** | C ARM_SHAPE передаёт transport 6; Rust-снимок использует ARM_SHAPE/ожидание SHAPE, но C/Rust differential снимка не заявлен; известное расхождение ARM_SHAPE transport 17 (header, п. 2) сюда не входит (C тоже 6). |
| `main` | 157–356 | 200 | CLI: name/ip/port/path/wire/snapshot/ladder/quic/tls12/deadline/mark/json/version; atoi/atol без проверки; port 443, deadline 15000, snapshot 60000 | `r2o-fetch` bin + `fetch.rs` | **P** | **Подтверждённые отличия:** C `atoi/atol` молча даёт 0/мусор, Rust парсит строго; C level не выдаёт 5/6, Rust выводит `name_ok` из TLS, `location` всегда строка; `r2o-fetch-cli-differential.sh` сравнивает только DNS-fail и QUIC-refusal. |

### `core/d2kvoice.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `usage` | 22–37 | 16 | флаги `--addr/--control/--conntrack/--wait/--mark/--list/--discovery` | `main.rs` `r2o_voice_check_command` help | **P** | Флаги те же, текст/форма командной строки отличается; CLI-дифференциала нет. |
| `split_hostport` | 39–48 | 10 | последнее `:`, host<64, port 1..65535 | `main.rs` `r2o_voice_check_command` parse | **P*** | C `strtoul` не проверяет хвост (`1:2x` → порт 2); Rust строгий parse. IPv6-литерал C всё равно отвергает `d2k_ip4_parse`. |
| `verdict_word` | 50–61 | 12 | русские тексты CLEAR/BLOCKED/NO_UDP/NO_CALL/FLAKY/NO_ORACLE/UNMEASURED | `voice_measure::r2o_format_voice_measurement` | **P** | Строки совпадают; формат всего вывода не сравнивался. |
| `main` | 63–135 | 73 | CLI: list-only (targets по conntrack), voice_run, печать разговора/вердикта/зондов/предупреждения/приёма, exit 0 для CLEAR иначе 1 | `main.rs` `r2o_voice_check_command`/`r2o_voice_list_command` + `voice_measure`/`voice_targets` | **P** | **Подтверждённые отличия:** C `--wait 0` передаёт 0, `d2k_voice_run` подставляет default 3000; Rust `0` остаётся 0. C `--list` принимает любые флаги, Rust `--voice-list` — только `--conntrack`. C `atoi/strtoul` без проверки; Rust строгий parse. Блок «Приём» зависит от `discovery_verified`/BLOCKED. |

### `core/diagnostics.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `copy` | 98–104 | 7 | копия в `cap`, обрезка до `cap-1`, откат с continuation-байта UTF-8 | diagnostics::truncate_utf8 (`:1313`) | **P*** | C `while(n && (s[n]&0xc0)==0x80)n--` — отступает только если `cap-1` попал внутрь символа; Rust `is_char_boundary` — тот же результат. Пределы полей задаёт вызывающий. |
| `js` | 105–130 | 26 | JSON-строка: `"`/`\\`, `\\n`, control→`?`, валидный UTF-8 как есть, иначе `\\ufffd` | serde_json + `d2o_event_text` (`:1324`) | **P*** | C сам валидирует UTF-8 (overlong/surrogate/>0x10ffff) и печатает `\ufffd`; Rust строки всегда валидны, `d2o_event_text` режет по NUL и control→`?`. Для валидных строк вывод эквивалентен; raw-байты C вне UTF-8 Rust не получает. |
| `number` | 131–131 | 1 | `<0` → `null`, иначе число | serde_json `Value` | **P*** | C отрицательные даёт `null`; Rust использует `Option`/`null`, для счётчиков `u64`. |
| `d2k_diag_new` | 132–132 | 1 | создать диагностическийリング | diagnostics::Recorder::new | **P*** | static-хелпер жизненного цикла |
| `d2k_diag_free` | 133–133 | 1 | освободить диагностику | Drop | **P*** | static-хелпер |
| `d2k_diag_bytes` | 134–134 | 1 | размер диагностической структуры | size_of::<Recorder> | **P*** | static-хелпер |
| `d2k_diag_event_count` | 135–135 | 1 | число событий в кольце | Recorder events.len() | **P*** | static-хелпер |
| `d2k_diag_sample_count` | 136–136 | 1 | число сэмплов | Recorder samples | **P*** | static-хелпер |
| `d2k_diag_memory_history_count` | 137–137 | 1 | число записей истории памяти | Recorder memory_history | **P*** | static-хелпер |
| `d2k_diag_memory_enable` | 138–138 | 1 | включить учёт аллокаций | diagnostics::memory_enable | **P** | unit recorder_toggles_memory_tracking; C/Rust дифференциала нет |
| `d2k_diag_memory_active` | 139–139 | 1 | включён ли учёт аллокаций | diagnostics::memory_active | **P*** | static-хелпер |
| `atomic_read` | 140–140 | 1 | атомарное чтение счётчика | AtomicU32::load | **P*** | static-хелпер |
| `atomic_peak` | 141–144 | 4 | CAS-обновление пика | AtomicU32::fetch_max | **P*** | static-хелпер |
| `d2k_diag_memory_acquire` | 145–151 | 7 | учесть выделение сайта | diagnostics::memory_acquire | **P** | unit memory_tracking_and_madvise_json_match_d2o_shape |
| `d2k_diag_memory_release` | 152–156 | 5 | учесть освобождение сайта | diagnostics::memory_release | **P** | тот же unit |
| `d2k_diag_memory_alloc_failure` | 157–160 | 4 | учесть отказ аллокатора | diagnostics::memory_alloc_failure | **P** | тот же unit |
| `d2k_diag_memory_snapshot` | 161–169 | 9 | снимок сайтов памяти | diagnostics::memory_snapshot | **P** | unit |
| `d2k_diag_memory_counts` | 170–179 | 10 | суммарные tracked tcp/tls/quic bytes | diagnostics::tracked_memory_bytes | **P** | unit |
| `d2k_diag_set_madvise` | 180–180 | 1 | сохранить статистику madvise | Recorder::set_madvise | **P** | unit memory_tracking_and_madvise_json_match_d2o_shape |
| `record_anomaly` | 181–187 | 7 | записать аномалию в кольцо (12 слотов) | Recorder::record_anomaly | **P*** | static-хелпер |
| `d2k_diag_record_write_error` | 188–191 | 4 | записать ошибку записи отчёта | Recorder::record_write_error | **P** | unit records_only_while_enabled |
| `d2k_diag_record` | 192–201 | 10 | записать событие в кольцо 64: id/at/family/trigger/elapsed/queue/units/target/ip/path/kind/shape/protocol/outcome/reason; пределы target 255, protocol 15, outcome 31, **reason 255**, ip 47, path 15, kind 7 | Recorder::record (`:754`) | **P** | **Подтверждённое расхождение:** C `reason[256]` → `copy` режет до **255** байт; Rust явно задаёт `("reason", 1024)` (`diagnostics.rs:768`). Остальные пределы совпадают. Rust сам добавляет `id`, если его нет, и всегда перезаписывает `at`; C берёт id/at из структуры. C не проверяет `enabled` (это делает вызывающий), Rust `record` выходит при `!enabled` — эквивалентно при штатном включении. |
| `d2k_diag_record_limit` | 202–212 | 11 | записать переход лимита (32) | Recorder::record_limit | **P** | unit/differential частично |
| `value` | 213–217 | 5 | число после ключа в /proc | diagnostics::meminfo/read_number | **P*** | static-хелпер |
| `compact_kib` | 218–220 | 3 | сжать KiB в i32 или -1 | diagnostics compact | **P*** | static-хелпер |
| `compact_bytes_kib` | 221–221 | 1 | байты в KiB с округлением вверх или -1 | diagnostics compact | **P*** | static-хелпер |
| `compact_bytes` | 222–222 | 1 | байты в i32 или -1 | diagnostics compact | **P*** | static-хелпер |
| `compact_count` | 223–223 | 1 | счётчик в u8 с насыщением | diagnostics compact | **P*** | static-хелпер |
| `proc_pid_dir_present` | 225–229 | 5 | существует ли /proc/<pid> как каталог | diagnostics::process_detail | **P*** | static-хелпер |
| `optional_proc_status` | 230–237 | 8 | различить unsupported/unavailable для smaps_rollup | diagnostics::read_smaps_rollup | **P*** | static-хелпер |
| `read_proc` | 238–259 | 22 | pid из pid-файла, comm, VmRSS/HWM/RssAnon/Threads/VmData/VmSwap | diagnostics::process_memory (`:1411`) | **P** | C требует **точного** `comm == names[i]` и читает только основной pid-файл; Rust принимает `name == spec.comm || name.starts_with(spec.comm)` (из-за усечения comm до 15 байт) и пробует `fallback_pidfile` (`r2o-controller4.pid` и т.п.). Поля status читаются теми же ключами; unit `process_memory_follows_pidfiles_and_restarts`, C-oracle нет. |
| `read_detail` | 260–304 | 45 | stat starttime, VmSize/Data/Stk/Swap, fd_count, smaps_rollup | diagnostics::process_detail | **P** | unit first_process_detail_survives_process_exit |
| `read_status` | 305–309 | 5 | код статуса smaps_rollup в строку | diagnostics::read_status | **P*** | static-хелпер |
| `write_detail` | 310–328 | 19 | JSON memory_detail процесса | diagnostics memory_details | **P** | unit/differential частично |
| `write_limit_reason` | 329–343 | 15 | JSON limit_reason по counts | diagnostics::limit_reason_values | **P** | unit diagnostics_id_and_counts_match_d2o |
| `write_limit_reason_state` | 344–356 | 13 | JSON limit_reason по flags/mask | diagnostics::limit_reason_values | **P** | unit |
| `write_memory_tracking` | 357–369 | 13 | JSON memory_tracking (сайты, coverage) | diagnostics::memory_tracking_json | **P** | unit memory_tracking_and_madvise_json_match_d2o_shape |
| `write_madvise` | 370–381 | 12 | JSON madvise (success/fail/errno-гистограмма) | diagnostics::madvise_json | **P** | unit |
| `write_anomalies` | 382–394 | 13 | JSON аномалий и счётчиков перезаписи | Recorder::write_report | **P** | unit records_only_while_enabled |
| `d2k_diag_sample` | 395–468 | 74 | раз в 60 с: meminfo, conntrack, процессы, first/latest detail, память-история 1440, детектор RSS-роста | `Recorder::tick` (`:790`) + `process_memory`/`process_detail` | **P** | **Подтверждённые расхождения в `memory_history`:** (1) C пишет фактические `rollup_status`, `rollup_errno` и `rollup[5]` первичного процесса; Rust жёстко кладёт `0`, `null`, `null` — поля `smaps_rollup_status_code`/`errno`/`kib` в истории всегда пустые. (2) C `compact_kib` даёт `-1` (JSON `null`) для недоступного RSS/VmData/VmSwap/RssAnon; Rust `unwrap_or(0)` даёт **0**. Остальное совпадает: интервал 60 с, окно 10 точек, `rising>=7`, `span>=9 мин`, `rss_delta>=1024`, `accounted<rss/4`, cooldown 30 мин, epoch при смене pid/start_ticks. Unit `d2o_periodic_rss_sample_matches_c`, `first_process_detail_survives_process_exit`. |
| `d2k_diag_write` | 469–605 | 137 | report.json schema=1: controller_pid/release/ring_bytes/capacities/overwritten, http_storage_limits, memory_tracking, madvise, anomalies, events, limit_transitions, memory_history, samples, memory_details | `Recorder::write_report` (`:1179`) + serde_json | **P** | Поля и константы совпадают: schema 1, capacities 64/32/120/1440/60 с, overwritten, memory_tracking, madvise, anomalies, events, limits, samples, memory_details, `smaps_status:not-read`. **Отличия:** C пишет `http_storage_limits` только при `d->ns>0`, Rust — всегда; C выводит `reason_source` из `protocol=="http"` (`terminal-code`/`last-classifier-context`), Rust берёт поле из события и не добавляет его сам. `r2o-diagnostics-differential.sh` сравнивает ring_bytes/event/snapshots/http_records; остальные поля — unit, не C/Rust diff. |

### `core/domain.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_domain_normalize` | 6–29 | 24 | одна хвостовая точка, длина 1..253, lower-case, LDH, метка ≤63, без ведущего/хвостового `-`, хотя бы одна нецифра | domain::normalize (`domain.rs:8`) | **P** | **Подтверждённое расхождение:** C **не требует ≥2 меток** — `localhost`, `a-b` проходят (если есть нецифра); Rust `labels < 2` отвергает. Остальное совпадает: одна точка, длина, lower-case, LDH, ≤63, дефисы, запрет чисто числового имени. Unit `tests/domain.rs`; C/Rust differential нет. |
| `rule_exists` | 31–40 | 10 | бинарный поиск правила в сгенерированном `d2k_psl_blob` | `psl` crate (`psl::suffix`) | **P*** | Таблица заменена crate `psl`; версия/состав PSL и бинарный поиск C напрямую не сравнивались. |
| `d2k_domain_base` | 42–64 | 23 | регистрируемый домен: longest rule, exception (`!`), wildcard (`*.`), неизвестный TLD → отказ | domain::registrable_domain (`:62`) | **P** | C явно перебирает суффиксы, считает `exception/longest/wildcard` и требует `count>suffix_count`; Rust `psl::suffix` + `is_known()` + `psl::domain`. Алгоритм PSL тот же, но таблица/версия и точные исключения C/Rust не сравнивались; unit private wildcard/exception. |
| `d2k_domain_member` | 66–72 | 7 | normalize(name)+normalize(suffix)+base(suffix), затем совпадение по границе метки | domain::is_member (`:74`) | **P** | C требует успешный `d2k_domain_base(suffix)`; Rust — `registrable_domain(suffix).is_some()`. Сравнение `name==suffix || prefix.ends_with('.')` эквивалентно. Отличие наследует `normalize` (односложные имена). Unit `tests/domain.rs`. |

### `core/groups.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_group_key_make` | 9–17 | 9 | ключ области: transport/family/shape/path/ech_origin; path/origin короче полей, иначе -1 | `catalog::GroupKey` + `validate_key` (`groups.rs:424`) | **P** | C копирует в фиксированные буферы с проверкой `strlen >= sizeof`; Rust `String` + `validate_key`: transport 6/shape 1/2/6/8–13 или 17/3, family 4/6, path/origin ≤255 без NUL. Эквивалентно; C/Rust differential групп нет. |
| `d2k_group_key_same` | 19–23 | 5 | равенство transport/family/shape/path/ech_origin | `GroupKey: PartialEq` | **E** | C пять сравнений; Rust derived `PartialEq` по всем полям. `tests/groups.rs`. |
| `valid` | 24–36 | 13 | NUL-терминация, family 4/6, transport 6/shape 1/2/6/8–13 или 17/3, evidence ровно 1/2/4/8, BLOCKED/PLAN_FAILED требуют plan_id | `validate_key` + `canonical_evidence` (`:389`) | **P** | Транспорт/форма/семейство и требование plan_id совпадают. **R2O-расширение:** `OPERATOR_REJECT=32` и маски `BLOCKED|...`; C принимает только точные `1/2/4/8`. C-проверка NUL через `memchr`; Rust `contains(&0)`. |
| `member` | 38–41 | 4 | суффикс по границе метки: `name==suffix` или `name[-len-1]=='.'` | `groups::member` (`:443`) | **E** | Формула совпадает посимвольно; `tests/groups.rs`. |
| `votes` | 45–60 | 16 | живые/устаревшие голоса: DIRECT_CLEAR без исключения → 0; BLOCKED&same plan&name!=suffix; итог `live>=2 && live>stale && live+stale>=3` | `groups::votes` (`:484`) + `latest_vote` (`:514`) | **P** | Формула и условия совпадают; C обновляет `*latest` внутри `votes`, Rust считает `latest_vote` отдельным проходом. C-oracle нет, unit `tests/groups.rs`. |
| `failures` | 61–71 | 11 | число PLAN_FAILED для суффикса/ключа/плана | `groups::failures` (`:531`) | **P*** | Три условия (`PLAN_FAILED`, key, plan_id, member) совпадают; unit `tests/groups.rs`. |
| `add_group` | 72–102 | 31 | замена/выбор по failures, count, at, plan_id; запрет покрытой группы; frozen при 64 | `groups::add_group` (`:544`) | **P** | Выбор совпадает: меньше failures, затем больше count, затем свежее at, затем лексикографически меньший plan_id; удаление покрытых групп и `frozen` при 64 — те же. Unit `tests/groups.rs`; C/Rust differential нет. |
| `rebuild` | 103–120 | 18 | из BLOCKED-наблюдений: base, перебор суффиксов от длинного к короткому, последний с голосами | `groups::rebuild` (`:326`) | **P** | C требует `d2k_domain_base`, идёт от первого суффикса к короткому и перезаписывает `best` при `count!=0` (побеждает самый короткий с голосами); Rust `registrable_domain` + `labels[start..]`, та же перезапись. Наследует разницу PSL/`normalize`; unit `tests/groups.rs`. |
| `cover` | 122–132 | 11 | самый длинный покрывающий суффикс для ключа; disabled/overflow → NULL | `groups::covering_group` (`:450`) | **P*** | C `disabled || n_groups>MAX` → NULL; Rust то же, `max_by_key(len)`. Unit `tests/groups.rs`. |
| `d2k_group_learn` | 133–245 | 113 | приём: normalize/base, admitted_clear, слот по plan_id/any/replace, frozen/capacity, disabled-reenable, reclaim oldest, замена, OR PLAN_FAILED, очистка дублей, rebuild | `groups::learn` (`:65`) | **P** | Основная логика совпадает построчно: slot/any/replace, changed/frozen, reclaim exact INCONCLUSIVE→BLOCKED→first, disabled_at=max, PLAN_FAILED OR, admitted exception, очистка без PLAN_FAILED, rebuild. **Отличия:** (1) Rust `OPERATOR_REJECT` — ранний `Ok(false)` и отдельная маска, C такого бита не знает; (2) при disabled C удаляет только `evidence==BLOCKED`, Rust — любой `evidence & BLOCKED` (шире); (3) C не делает rebuild при вставке INCONCLUSIVE, Rust делает (набор групп не меняется). Unit `tests/groups.rs`. |
| `d2k_group_restore` | 246–273 | 28 | канонизация масок, normalize/base, at≥0, дубликаты (same plan или нет PLAN_FAILED), rebuild | `groups::restore` (`:15`) + `canonical_evidence` (`:389`) | **P** | Канонизация совпадает: снять INCONCLUSIVE, ADMITTED_EXCEPTION требует DIRECT_CLEAR, BLOCKED снимает DIRECT_CLEAR|PLAN_FAILED, DIRECT_CLEAR+PLAN_FAILED→PLAN_FAILED; дубликаты — то же условие. **R2O-расширение:** OPERATOR_REJECT (база BLOCKED|PLAN_FAILED|5). |
| `d2k_group_match` | 274–293 | 20 | нормализация, disabled/overflow, longest suffix, исключение DIRECT_CLEAR или PLAN_FAILED того же плана | `groups::match_domain` (`:358`) | **P** | Формула и выбор longest совпадают; **Rust дополнительно исключает `OPERATOR_REJECT`**. C/Rust differential нет, unit `tests/groups.rs`. |
| `d2k_group_forget` | 294–310 | 17 | удалить PLAN_FAILED имени/транспорта/семейства, rebuild при удалении | `groups::forget_failures` (`:271`) | **E** | C и Rust: normalize, фильтр name/transport/family/PLAN_FAILED, swap_remove, rebuild при dropped>0, возврат числа. Unit `tests/groups.rs`. |
| `d2k_group_expire` | 311–324 | 14 | удалить PLAN_FAILED с `at < now-max_age`, rebuild | `groups::expire_failures` (`:304`) | **E** | Условия `max_age<=0 || now<max_age` и `at < cutoff` совпадают; swap_remove/rebuild. Unit `tests/groups.rs`. |

### `core/link.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `execution_context` | 45–51 | 7 | разбор execution_id (8 байт BE) и binding для APPLIED/REFUSED | control::decode_applied/decode_refused + BindingContext | **E*** | static-хелпер декодера; d2o_control_differential |
| `say` | 56–64 | 9 | текст ошибки link | io::Error/Result | **P*** | static-хелпер |
| `wait_readable` | 70–86 | 17 | poll с повтором на EINTR | poll в ControlClient | **P*** | static-хелпер |
| `read_exact` | 92–106 | 15 | дочитать ровно N байт, EINTR повтор | Read::read_exact | **P*** | static-хелпер |
| `write_all` | 108–131 | 24 | дописать всё, MSG_NOSIGNAL | Write::write_all / send | **P*** | static-хелпер |
| `hex_nibble` | 133–138 | 6 | значение hex-цифры | plan_text::hex_nibble | **P*** | static-хелпер |
| `hex_decode` | 144–159 | 16 | hex в байты с проверкой | plan_text::decode_hex | **P*** | static-хелпер |
| `d2k_link_open` | 161–189 | 29 | AF_UNIX connect к управляющему сокету | ControlClient::connect | **P** | реализовано; C/Rust differential на ошибки connect нет |
| `d2k_link_close` | 191–195 | 5 | закрыть link | Drop | **P*** | static-хелпер |
| `d2k_link_peer_closed` | 197–221 | 25 | проверить POLLHUP/POLLERR без чтения | ControlClient peer-closed check | **P** | реализовано; differential нет |
| `d2k_link_next` | 223–522 | 300 | прочитать кадр 6+plen, разобрать ключ потока и все типы событий (HELLO/HTTP/SUSPECT/STATS/EXCHANGE/CLIENT_TCP/SHAPE/ACK/APPLIED/PROTO/REFUSED) | r2k_core::control::{read_frame,decode_*} | **E** | d2o_control_differential.c + tests/control.rs; декодирование APPLIED/REFUSED/ACK покрыто отдельно |
| `d2k_link_set_name` | 524–527 | 4 | SET_NAME без пробного порта | control::encode_set_name | **P** | точный кадр проверен tests/control.rs; C/Rust differential кодирования не найден |
| `d2k_link_set_name_probe` | 531–536 | 6 | SET_NAME_PROBE с local port | control::encode_set_name_probe | **P** | unit-тест; C/Rust differential кодирования не найден |
| `send_name_plan` | 538–630 | 93 | общий кодировщик name-команды: family 4/6, fd, имя 1..255, transport 6/17, hex plan, sport, trial, кадр | control::encode_set_name* | **P** | **Подтверждённое расхождение:** C **не проверяет `shape` вовсе** и кодирует любое значение `g_scratch[o++]=shape` (`link.c:591`); Rust `encode_set_name` отвергает форму вне `{1,2,3,4,5,6,7} ∪ {8..13}`. C также не проверяет совместимость плана с формой; Rust `valid_name_probe_plan_records`/`valid_domain_plan_records` проверяют transport/proto. Точные кадры валидных команд совпадают (tests/control.rs), C/Rust differential нет. |
| `d2k_link_set_name_family` | 632–637 | 6 | SET_NAME/SET_NAME_PROBE по family | control::encode_set_name | **P** | Тонкая обёртка выбирает команду по `sport_be`; наследует расхождение `send_name_plan` (C не проверяет shape). |
| `d2k_link_set_name_bound` | 639–643 | 5 | SET_NAME_BOUND с identity: только `token != NULL`, затем `send_name_plan` | control::encode_set_name_bound | **P** | **Подтверждённое расхождение:** C принимает любую `shape` и любой `token` (в т.ч. нулевой); Rust требует **`shape == SHAPE_HTTP`** и **ненулевой trial_id** (`control.rs:1399-1406`), иначе отказ. C-датапат (`ctlsrv.c`) может отвергнуть позже; стадия отказа иная. |
| `d2k_link_del_name_bound` | 645–657 | 13 | условное удаление name binding: имя/transport/known/kind NAME/!temporary | control::encode_delete_name_bound | **P** | Построчно совпадает: `family` не передаётся (C не проверяет), Rust `encode_delete_name_bound` проверяет transport 6/17, `binding.is_known()`, `kind==1`, `!temporary`. Тест `encodes_a_bounded_exact_name_binding_delete`; C/Rust diff нет. |
| `d2k_link_set_name_probe_trial` | 659–668 | 10 | SET_NAME_PROBE с trial_id: требует `sport_be != 0` | control::encode_set_name_probe | **P** | C проверяет только ненулевой порт; Rust дополнительно требует `valid_name_probe_plan_records(shape, plan)` и family 4/6, trial не проверяет. Для валидного плана кадр совпадает; набор отказов шире. |
| `area_context_valid` | 670–675 | 6 | допустимая комбинация transport/shape/family для области | control::valid_domain_area_context | **P*** | static-хелпер; формула сверена ниже (P). |
| `d2k_link_set_suffix_family` | 677–684 | 8 | SET_SUFFIX с планом | control::encode_set_suffix | **P** | **Подтверждённое расхождение:** C `send_name_plan(..., SET_SUFFIX)` проверяет только имя/family/transport/hex; Rust `encode_set_suffix` дополнительно проверяет shape (1/2/3/6 или 8–13), family и **`valid_domain_plan_records`** (transport/proto плана). C кодирует несовместимый план, Rust отвергает. |
| `d2k_link_set_https` | 686–705 | 20 | SET_HTTPS имя+ttl | `control.rs:1777-1790` `encode_set_https` | **P** | **Расхождение:** C-link проверяет только имя (1..253) и кодирует любой `u32 ttl`; обрезку до `D2K_HTTPS_TTL_MAX_S` = **7 суток** (`d2k_ctl.h:231`) делает датапат (`ctlsrv.c:446`). Rust-link отвергает `ttl > MAX_HTTPS_TTL_SECONDS` = **6 часов** ещё на кодировании. Наблюдаемый итог для сверх-6ч различается стадией (C: обрезка до 7 суток, R2O: отказ). Unit `encodes_the_exact_https_name_and_ttl` покрывает только допустимый TTL. |
| `d2k_link_set_stall_budgets` | 707–729 | 23 | SET_STALL_BUDGETS список бюджетов | control::encode_set_tcp_stall_budgets | **P** | unit бюджеты tcp/reset; C/Rust diff нет |
| `send_area_key` | 731–752 | 22 | общий кодировщик domain-area команд (name/key/area_id) | control::encode_domain_area_key | **P*** | static-хелпер |
| `d2k_link_del_suffix_family` | 754–757 | 4 | DEL_SUFFIX | control::encode_delete_suffix | **P** | кодировщик есть; C/Rust differential нет |
| `d2k_link_set_bypass_family` | 758–761 | 4 | SET_BYPASS | control::encode_set_bypass | **P** | кодировщик есть; differential нет |
| `d2k_link_del_bypass_family` | 762–765 | 4 | DEL_BYPASS | control::encode_delete_bypass | **P** | кодировщик есть; differential нет |
| `d2k_link_area_identified` | 767–777 | 11 | area-команда с identity/area_id | control::encode_set_suffix/encode_domain_area_key | **P** | unit area_ack_round_trips; C/Rust differential нет |
| `addr_shape_ok` | 783–787 | 5 | допустима форма 1/2/3(QUIC)/5(VOICE)/6(ECH_TCP)/**8–13** | control::valid_addr_shape | **P*** | **Подтверждённое расхождение:** C принимает контекстные TCP-формы `8..13` (`d2k_link.h:311-328`, `link.c:786`); Rust `valid_addr_shape` — только `{1,2,3,5,6}` (`control.rs:1462-1467`). `SET_ADDR`/`DEL_ADDR` с формой 8–13 C кодирует, Rust отвергает. |
| `d2k_link_set_addr` | 789–792 | 4 | SET_ADDR IPv4 | control::encode_set_addr | **P** | Тонкая обёртка family=4; наследует расхождение `addr_shape_ok`. |
| `d2k_link_set_addr_family` | 794–848 | 55 | SET_ADDR family 4/6: shape, hex, 16-байтный адрес, план без проверки совместимости | control::encode_set_addr | **P** | C проверяет `addr_shape_ok` (включая 8–13), кодирует `family + 16 байт + shape + hex`; Rust дополнительно вызывает `valid_addr_plan_records` (transport/proto плана) и не принимает 8–13. Для формы 1/2/3/5/6 и совместимого плана кадр совпадает. |
| `addr_probe_flow_bytes` | 852–866 | 15 | 38-байтный ключ UDP: family, src/dst, **src_port_be может быть 0**, dst_port≠0, transport 17 | control::udp_addr_probe_flow | **P*** | **Подтверждённое расхождение:** C явно допускает `src_port_be=0` — «голосовой опыт на любой клиентский порт» (`link.c:855`); Rust `udp_addr_probe_flow` требует `source.port() != 0` (`control.rs:1677`). `SET_ADDR_PROBE`/`DEL_ADDR_PROBE` voice с нулевым исходным портом C кодирует, Rust отвергает. |
| `d2k_link_set_addr_probe` | 868–875 | 8 | SET_ADDR_PROBE IPv4 | control::encode_set_addr_probe | **P** | Обёртка family=4; наследует расхождение `src_port=0` и проверку плана. |
| `d2k_link_set_addr_probe_family` | 877–909 | 33 | SET_ADDR_PROBE: fd/trial/lease≤MAX/flow/hex, trial≠0 | control::encode_set_addr_probe | **P** | C проверяет `trial_id`, `lease_ms 1..MAX`, transport 17, dst_port≠0; Rust дополнительно требует `source.port()!=0`, ненулевые/не-unspecified адреса и `valid_addr_plan_records(SHAPE_QUIC)`. C не проверяет план. Кадр при валидных входах совпадает. |
| `d2k_link_del_addr_probe` | 911–917 | 7 | DEL_ADDR_PROBE IPv4 | control::encode_delete_addr_probe | **P** | Обёртка family=4; наследует `src_port=0`. |
| `d2k_link_del_addr_probe_family` | 919–937 | 19 | DEL_ADDR_PROBE: flow + trial≠0 | control::encode_delete_addr_probe | **P** | C требует transport 17, dst_port≠0, trial≠0; Rust дополнительно `source.port()!=0`, ненулевые адреса, одинаковое семейство. Кадр при валидных входах совпадает. |
| `d2k_link_arm_shape` | 939–942 | 4 | ARM_SHAPE IPv4 | control::encode_arm_shape | **P** | unit arm_shape_roundtrip; C/Rust diff нет |
| `d2k_link_arm_shape_family` | 944–979 | 36 | ARM_SHAPE: имя, transport 6/17, family 4/6 | `control.rs:902-915` `encode_arm_shape` | **P** | Кодирование совпадает: C и Rust принимают transport 6/17, family 4/6, имя до 253/255. **Но** датапат R2O `arm_client_shape` (`control.rs:2002`) отвергает transport 17, а C `ctlsrv.c:329` принимает 6/17 — это уже зафиксированное расхождение конца пути, не link-кодера. |
| `d2k_link_del_name_family` | 981–1012 | 32 | DEL_NAME: fd, имя 1..255, family 4/6, transport 6/17, **shape != 0** (без сверки пары) | control::encode_delete_name | **P** | **Подтверждённое расхождение:** C принимает любую пару `transport`+`shape!=0` (например, 17 + shape 1); Rust `encode_delete_name` требует `transport==6 && shape ∈ {1,2,4,6,7,8..13}` или `transport==17 && shape ∈ {3,5}`. C шире, отказ переносится на датапат. Кадр для допустимой пары совпадает. |
| `d2k_link_del_name_probe` | 1014–1018 | 5 | DEL_NAME_PROBE IPv4 | control::encode_delete_name_probe | **P** | кодировщик есть; unit/дифференциала именно для DEL_NAME_PROBE не найдено |
| `d2k_link_del_name_probe_family` | 1020–1049 | 30 | DEL_NAME_PROBE: имя, shape, family 4/6, source port | `control.rs:1906-1926` `encode_delete_name_probe` | **P** | **Расхождение:** C-link не проверяет `shape` вовсе (только имя/порт/family), Rust требует `valid_tcp_probe_shape(shape)` и отвергает неизвестную форму. C-датапат всё равно отверг бы такую команду, но отказ происходит позже. Точный кадр C/Rust не сравнивался. |
| `d2k_link_del_addr` | 1051–1054 | 4 | DEL_ADDR IPv4 | control::encode_delete_addr | **P** | unit-тест; C/Rust diff нет |
| `d2k_link_del_addr_family` | 1056–1076 | 21 | DEL_ADDR family 4/6 | control::encode_delete_addr | **P** | unit-тест; C/Rust diff нет |
| `d2k_ev_outer_appdata` | 1079–1094 | 16 | есть ли в обмене TLS application data (бит 23) | r2k_core::control event seen_types | **P*** | static-хелпер; events tests |

### `core/match.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `same_evidence` | 38–73 | 36 | одна улика: kind volume/rx-volume/rx-volume-wire → `abs(volume delta)<=4`; иначе `abs(ttl delta)<=2` и tos/ipid точно; ttl_delta/seen не читаются | catalog.rs:1077-1090 `same_signal` | **P*** | Совпадает посимвольно: C `int`-вычитание и `abs`, Rust `i64::from().abs()`, `abs_diff`, `tos/ipid`; `VOLUME_SLACK=4`, `TTL_SLACK=2`. Unit `tests/catalog.rs`; отдельного boundary-теста на 4/5 и 2/3 нет. |
| `d2k_fp_same` | 75–125 | 51 | method, внешний обход b→a, все приметы того же рода в a, `kind_seen && !agreed → false`, хотя бы один общий род | catalog.rs:59-84 `Fingerprint::is_compatible_with` | **P** | Логика совпадает: направленный обход наблюдаемого, просмотр всех same-kind, break на первом согласии, `any_agreement`, `common>0`. Unit `tests/catalog.rs` (partial evidence, all same-kind signals); C/Rust differential нет. |
| `d2k_catalog_match` | 127–136 | 10 | первый индекс коробки с совместимым отпечатком, иначе -1 | catalog.rs:537-541 `match_fingerprint` | **E** | C возвращает `i`/`-1`; Rust `position` → `Option<usize>`. Unit `tests/catalog.rs`. |

### `core/meas.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `nap_us` | 52–55 | 4 | `nanosleep` на us (сек+нс) | `std::thread::sleep(Duration::from_micros)` (`raw_probe.rs:1238`, `response.rs:856`) | **P*** | C округляет в нс, Rust — Duration; фактическая пауза не измерялась/не сравнивалась. |
| `d2k_mark_real` | 61–70 | 10 | `setsockopt(SO_MARK, int mark)`, вне Linux -1 | `setsockopt(SO_MARK)` в `response.rs`/`raw_probe.rs` | **P*** | C `int m=(int)mark`; Rust `u32`→`c_int`, ошибка возвращается. Платформенная ветка та же; отдельного differential нет. |
| `d2k_accept_serverhello` | 87–94 | 8 | `len>=6 && b[0]==0x16 && b[1]==0x03 && b[5]==0x02` | `classify.rs:543-547` `trigger_accepts(Accept::ServerHello)` | **P** | Байтовое правило совпадает посимвольно. Целевого C/Rust differential нет; используется в `response.rs:882`/`raw_probe.rs:1264` и покрыто `response.rs:1442-1463`. |
| `d2k_accept_tls_record` | 96–99 | 4 | `len>=3` и `b[0]` равен `0x16` или `0x15`, и `b[1]==0x03` | `classify.rs:548-550` `trigger_accepts(Accept::TlsRecord)` | **P** | Совпадает; используется для белого ClientHello (`main.rs:34054`), отдельного C/Rust differential нет. |
| `d2k_accept_any` | 101–104 | 4 | `len>0` | `classify.rs:551` `trigger_accepts(Accept::Any)` | **P** | Совпадает: `!bytes.is_empty()`. Покрыто сокетными тестами `response.rs:1480-1528`, не C-оракулом. |
| `cuts_valid` | 109–116 | 8 | строго возрастающие `0<cut<len`; любой плохой разрез — отказ всего опыта | `classify.rs:28-56` `split_offsets`; `raw_probe.rs:1150` требует ровно один разрез | **P** | **Подтверждённое расхождение:** C отвергает весь опыт при `cut<=prev || cut>=len`; Rust `split_offsets` молча фильтрует `cut>0 && cut<len`, берёт первые 8, сортирует и дедуплицирует, строит диапазоны. Raw-путь R2O при `cuts.len()!=1` возвращает `Local("invalid cut")`, C штатно шлёт несколько разрезов. Нужен differential на несколько/невалидные разрезы. |
| `send_all` | 124–136 | 13 | доотправка буфера с учётом partial write; ошибка отправки — сбой опыта, не «молчание» цели | `response.rs:795-839` send-loop в `probe_trigger` | **P*** | partial write обрабатывается циклом, `EAGAIN` — через `poll_one(POLLOUT)`, `EINTR` возвращает `Transport("write: ...")`, как C `n<=0` возвращает `-1`. Отличие: C блокирующий сокет с `SO_SNDTIMEO`, R2O — неблокирующий с явным poll. `r2o-meas-differential.sh` покрывает send-timeout/EINTR. |
| `connect_bounded` | 142–173 | 32 | неблокирующий connect с poll и SO_ERROR | `response.rs:254-300` `connect_until` | **P** | Проверка `EINPROGRESS/EALREADY/EINTR`, poll по `POLLOUT`, затем `SO_ERROR` — совпадает. C после успеха возвращает блокирующий режим; R2O сокет остаётся неблокирующим (`probe_socket`, `SOCK_NONBLOCK`), а send/recv обходят `EAGAIN` через poll. Поведение эквивалентно, но отдельного differential на все errno-ветви нет. |
| `d2k_meas_once` | 175–267 | 93 | один TCP-замер: literal IPv4/IPv6, connect, разрезы, пауза, recv 512, accept | `response.rs:776-892` `probe_trigger`; `raw_probe.rs:1140` `probe_tcp_split` | **P** | **Расхождение пути:** C всегда шлёт разрезы обычным TCP-сокетом; R2O на Linux при непустых `cuts` уходит в raw-путь `probe_tcp_split` (только один разрез). C отвергает IPv6 zone-id (`%`), R2O резолвит host через `ToSocketAddrs` и фильтрует по семейству. `SO_MARK`, `TCP_NODELAY`, `SO_RCVTIMEO`, recv 512 и accept-фильтр перенесены. `r2o-meas-differential.sh` покрывает send/recv EINTR и таймауты, но не multi-cut и не IPv6 zone. |
| `d2k_meas` | 269–293 | 25 | серия повторов, `pass/fail/err/unproven`, метка серии — AND по всем дозвонам | `classify.rs:992-1000` `Tally`, `:1076-1240` `measure`, `:628-636` `with_mark_status` | **P** | Логика совпадает: `repeats<=0 -> 3`, `ERR` даёт `errors+1` и `fail+1`, `UNPROVEN` даёт `unproven+1` и `fail+1`, `unmarked` становится sticky. Тесты `classify.rs:2129-2171`, `2303-2361` проверяют unmarked/unproven. Отдельного C/Rust differential на серию нет. |
| `udp_now_ms` | 307–311 | 5 | монотонное время для реестра UDP-портов | `std::time::Instant` | **P*** | static-хелпер; монотонность обеспечена `Instant`, прямого сравнения с `CLOCK_MONOTONIC` нет. |
| `d2k_udp_port_claim` | 313–339 | 27 | недавно занятый локальный UDP-порт (анти-residual): кольцо 4096, возраст 480 с | `r2o_quic_http3.rs:16,19,127-147` `r2o_quic_port_was_recently_claimed` | **P** | C: `UDP_RECENT_CAP=4096` (`meas.c:300`), `D2K_UDP_RESIDUAL_MS=480000` (`d2k_meas.h:196`); R2O: `R2O_QUIC_RECENT_PORTS=4096`, `R2O_QUIC_RESIDUAL_PORT_AGE=480s`. API отличается (C принимает fd, R2O — port), но правило «недавно занят → отвергнуть и держать сокет» перенесено в цикл `r2o_quic_http3.rs:108-121`. Отдельного C/Rust differential нет. |
| `d2k_udp_port_forget_all` | 341–346 | 6 | сброс реестра недавних UDP-портов | нет прямого аналога | **N** | Подтверждено: единственный вызов в D2O — `core/test_quic_arm_data.c:440`; production-вызовов нет. В R2O реестр живёт в `static OnceLock<Mutex<...>>` (`r2o_quic_http3.rs:21`) и не сбрасывается. Это тестовый сброс, не packet-path контракт. |

### `core/measured.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `append_fmt` | 10–20 | 11 | дописать форматированный текст в буфер с проверкой места | String::push_str / write! | **P*** | static-хелпер |
| `append_hex` | 22–28 | 7 | дописать байты как hex | hex-хелпер в classify_measured | **P*** | static-хелпер |
| `d2k_white_decoy_hello` | 33–44 | 12 | собрать белое ClientHello с подменой SNI | `hello.rs:598` `r2o_rx_fake_client_hello` (профиль `profiles/r2o_rx_fake.hex`) | **E** | Прямая C-фикстура: `main.rs:34050-34061` сравнивает `r2o_discovery_white_trigger("hcaptcha.com").payload` с `tests/fixtures/r2o-rx-fake-hcaptcha-c.bin`; длинное имя покрыто C-фикстурой плана `r2o_rx_volume.rs:165-177`. |
| `template_plan` | 57–82 | 26 | tcp-template-v1: `d2k-plan 1 {13 при autottl, иначе 8}`, segment `d2k_arm_segment(send_cap)`, hello в payload, `poison 1 [badsum][tcpts][autottl=1,2-12]`, fake ×8, split | `r2o_rx_volume.rs:26-58` `r2o_rx_volume_plan_for_client` | **P** | C-фикстуры `r2o-rx-volume-hcaptcha-split2-c.txt`/`split5-c.txt` покрывают `tcpts` и точный текст; autottl-ветка — unit `r2o_rx_volume.rs:112-128`. **Отличия:** C `badsum`-ветка в RX-плане не имеет Rust-аналога (R2O всегда tcpts/autottl); Rust `R2O_RX_VOLUME_SEGMENT=1400` фиксирован, C `d2k_arm_segment(send_cap)` может быть меньше при узком канале. |
| `d2k_rx_volume_plan_named` | 84–88 | 5 | `..._client(..., client_has_ts=1)` | `r2o_rx_volume.rs:21-23` `r2o_rx_volume_plan` | **P** | Обёртка `for_client(..., true)` совпадает; C-фикстуры variant 0/4 и длинное имя, варианты 1/2/3 — unit `r2o_rx_volume.rs:94-110`. C проверяет `shape==MODERN`; Rust shape не принимает. |
| `d2k_rx_volume_plan_client` | 90–110 | 21 | variant 0..4 → split `{2,1,3,4,5}`, shape только MODERN, name→white hello, `client_has_ts` выбирает tcpts или autottl | `r2o_rx_volume.rs:26-58` `r2o_rx_volume_plan_for_client` | **P** | **Подтверждённое расхождение сигнатуры:** C отвергает `shape != D2K_SHAPE_MODERN` (`measured.c:96-98`), Rust shape не принимает и всегда строит modern-план. Остальное совпадает: split-таблица, проверка variant, имя через `r2o_rx_fake_client_hello`, `send_cap - hello >= 132`, minexec 8/13, `poison tcpts` или `autottl=1,2-12`, fake ×8, split/order. C-фикстуры только ts=1; autottl — unit. |
| `d2k_rx_volume_plan` | 114–117 | 4 | RX-volume план для hcaptcha.com | r2o_rx_volume::r2o_rx_volume_plan | **E** | та же C-фикстура варианта 0 |
| `measured_payload` | 121–138 | 18 | `payload-pad64 ID LEN 15 [base64(prefix)]`, префикс обрезается до LEN | `classify_measured.rs:381-399` `append_measured_payload`, `:401-425` `base64` | **P** | Формат и обрезка `prefix_len>len` совпадают; base64-таблица стандартная, паддинг `=` для 1/2 байт. C-фикстуры покрывают обычные payload, но не границы 1/2/3 байта и не пустой префикс; отдельного C/Rust differential нет. |
| `d2k_tcp_split_plan` | 140–151 | 12 | план split payload_start с gap и сегментом под `send_cap` | `main.rs:6292` `r2o_discovery_measured_split_plan` | **E** | `scripts/r2o-measured-split-differential.sh` компилирует `tests/d2o_measured_split_differential.c` с `core/measured.c` и сравнивает вывод с Rust для `send_cap` 0/1492/1280/100/72, split 0/1/1024, verdict prefix/whole. Тест `main.rs:28767` формирует тот же вывод; сегмент `send_cap-72 min 1400` совпадает с `d2k_arm_segment`. |
| `d2k_arm_plan_measured_cap` | 153–385 | 233 | сборка измеренного плана: split-only, template, disorder, oob, fake/between/seqovl, ttl/md5/tcpts/tsup/ipidzero/autottl, выбор minexec и segment | `classify_measured.rs:45-378` `measured_plan_text` | **P** | **Конкретные пробелы:** (1) `Poison` (`classify.rs:127-146`) не содержит `autottl` и `tcpts_up`, поэтому R2O не может собрать ветви `a->autottl` (C `measured.c:343-345`) и `a->tcpts_up` (`:349`); (2) `segment` жёстко 1400 (`classify_measured.rs:12,143`), тогда как C берёт `d2k_arm_segment(send_cap)` (`measured.c:170`, `d2k_arm.h:79-82`) — на `send_cap=1280` C даёт 1208; (3) C `minexec=13` при autottl, Rust — 5/12. Остальные ветви (split/oob/disorder/seqovl/md5/tcpts/ipidzero) перенесены; C-фикстуры покрывают обычные fake/split/oob, редкие — unit. |
| `d2k_arm_plan_measured` | 387–390 | 4 | обёртка `d2k_arm_plan_measured_cap(..., send_cap=0)` | `classify_measured.rs:30-37` `plan_text_for_poison(..., send_cap=0)` | **P** | Обёртка совпадает; все пробелы те же, что у `d2k_arm_plan_measured_cap`. |

### `core/net4.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_ip4_parse` | 7–30 | 24 | 4 октета по 1–3 цифры, 0..255, ровно точки/конец, старший байт вперёд | `Ipv4Addr::from_str` (`examples/m5_net4_trace.rs:15`) | **P** | **Подтверждённое расхождение:** C принимает ведущие нули (`010.0.0.1` → 10.0.0.1), Rust 1.98 — `Err(AddrParseError)`. Остальное совпадает: 1–3 цифры, ≤255, ровно 4 октета, конец строки. `test-core-net4-differential.sh` (пин a378) покрывает обычные/битые литералы, но не ведущие нули. |
| `d2k_ip4_text` | 32–38 | 7 | 4 байта → `%u.%u.%u.%u`, 0 при нехватке cap | `Ipv4Addr::Display` | **E** | `test-core-net4-differential.sh` сравнивает текст на валидных адресах; контракт `cap` не нужен Rust `Display`. |
| `d2k_ip4_private` | 40–51 | 12 | 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, 0.0.0.0 | `quic_replay.rs:24-33` `ipv4_is_local` | **E** | Диапазоны совпадают посимвольно: `a==10/127`, `172 && b∈16..=31`, `192.168`, `169.254`, `100 && b∈64..=127`, `is_unspecified`. `test-core-net4-differential.sh` + `r2o-quic-local-address-differential.sh`. |
| `d2k_ip6_private` | 53–64 | 12 | `::`/`::1`, fc00::/7, fe80::/10, ff00::/8, v4-mapped → ip4_private | `quic_replay.rs:37-51` IPv6-ветка | **E** | C: 15 нулевых байт + `ip[15]<=1`; `(ip[0]&0xfe)==0xfc`; `ip[0]==0xfe && (ip[1]&0xc0)==0x80`; `ip[0]==0xff`; `::ffff:` → ip4. Rust: `is_unspecified/is_loopback`, те же маски, mapped_v4. `test-core-net4-differential.sh`. |

### `core/p256.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `fe_copy` | 31–31 | 1 | копирование 8-словного элемента поля P-256 | hpke/ring (P-256) | **P*** | static-хелпер; своей арифметики в R2O нет |
| `ge` | 34–39 | 6 | сравнение элементов поля с модулем P | hpke/ring | **P*** | static-хелпер |
| `is_zero` | 41–45 | 5 | проверка нуля элемента поля | hpke/ring | **P*** | static-хелпер |
| `sub_raw` | 48–56 | 9 | вычитание 256-битных чисел с заимствованием | hpke/ring | **P*** | static-хелпер |
| `add_raw` | 59–67 | 9 | сложение 256-битных чисел с переносом | hpke/ring | **P*** | static-хелпер |
| `fe_add` | 69–74 | 6 | сложение по модулю P-256 | hpke/ring | **P*** | static-хелпер |
| `fe_sub` | 76–80 | 5 | вычитание по модулю P-256 | hpke/ring | **P*** | static-хелпер |
| `fe_mul` | 84–113 | 30 | умножение Монтгомери по модулю P-256 | hpke/ring | **P*** | static-хелпер |
| `fe_sqr` | 115–115 | 1 | возведение в квадрат по модулю P-256 | hpke/ring | **P*** | static-хелпер |
| `to_mont` | 124–124 | 1 | перевод в форму Монтгомери | hpke/ring | **P*** | static-хелпер |
| `from_mont` | 125–128 | 4 | обратный перевод из Монтгомери | hpke/ring | **P*** | static-хелпер |
| `fe_inv` | 131–141 | 11 | обращение элемента поля P-256 | hpke/ring | **P*** | static-хелпер |
| `fe_from_be` | 143–148 | 6 | разбор 32-байтного big-endian элемента поля | hpke/ring | **P*** | static-хелпер |
| `fe_to_be` | 150–156 | 7 | сериализация элемента поля big-endian | hpke/ring | **P*** | static-хелпер |
| `pt_double` | 161–190 | 30 | удвоение точки якобиевых координат P-256 | hpke/ring | **P*** | static-хелпер |
| `pt_add` | 192–232 | 41 | сложение точек P-256 в якобиевых координатах | hpke/ring | **P*** | static-хелпер |
| `pt_mul` | 235–246 | 12 | скалярное умножение точки P-256 | hpke/ring | **P*** | static-хелпер |
| `pt_affine` | 249–260 | 12 | перевод точки в аффинные координаты | hpke/ring | **P*** | static-хелпер |
| `scalar_ok` | 262–266 | 5 | проверка скаляра 0<k<N | hpke/ring | **P*** | static-хелпер |
| `d2k_p256_public` | 268–280 | 13 | `scalar_ok` (`0<k<N`), `pt_mul(G)`, аффинные координаты, `0x04` + X + Y | `rustls::crypto::ring::kx_group::SECP256R1` (`r2o_tls.rs:95,101,288`) | **P** | Production-путь TLS 1.2 подтверждён: C `core/tls12.c:650-655`, Rust rustls/ring `SECP256R1`. Отдельного публичного P-256 API в R2O нет; `d2k_p256_public` используется внутри `d2k_p256_keypair`. C/Rust-векторов публичного ключа нет. |
| `d2k_p256_keypair` | 282–289 | 8 | `d2k_t13_random` 32 байта, `scalar_ok`, до 16 попыток | `ring::agreement::EphemeralPrivateKey` (через rustls) | **P** | **Production:** `core/tls12.c:650-655` (ECDHE TLS 1.2). C явно повторяет генерацию до 16 раз при `k==0 || k>=N`; ring генерирует ключ внутри и его retry/отбраковка не сравнивались. C-векторов keypair нет. |
| `d2k_p256_ecdh` | 291–316 | 26 | `scalar_ok`, `peer[0]==0x04`, `x,y<P`, проверка `y²=x³-3x+b`, `pt_mul`, вывод X | `ring::agreement` (P256) через rustls | **P** | **Production:** `core/tls12.c:655`. C сам проверяет точку на кривой; ring тоже отвергает невалидную точку, но C/Rust-векторы ECDH и поведение при точке не на кривой не сравнивались. |

### `core/plantlv.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `b64_value` | 126–131 | 6 | декодирование символа base64 | plan_text::base64_decode | **E*** | static-хелпер; differential plantlv |
| `parse_base64` | 133–161 | 29 | строгий разбор base64 с проверкой паддинга | plan_text::base64_decode | **E*** | static-хелпер; plantlv differential |
| `say` | 163–169 | 7 | записать текст ошибки | Result<String, String> | **E*** | static-хелпер; текст ошибок не сравнивается |
| `hex_nib` | 171–176 | 6 | значение hex-цифры | plan_text::hex_nibble | **E*** | static-хелпер |
| `parse_hex` | 180–204 | 25 | разбор hex-строки в байты | plan_text::decode_hex | **E*** | static-хелпер; plantlv differential |
| `anchor_by_name` | 206–217 | 12 | имя якоря split/oob в номер | plan_text::anchor | **E*** | static-хелпер |
| `split_fields` | 221–233 | 13 | разбиение строки плана на поля | plan_text::split_whitespace | **E*** | static-хелпер |
| `parse_uint` | 237–245 | 9 | десятичное число с верхней границей | plan_text::number | **E*** | static-хелпер |
| `parse_int` | 248–256 | 9 | знаковое число в диапазоне | plan_text::number_signed | **E*** | static-хелпер |
| `kv_u32` | 259–263 | 5 | разбор key=value | plan_text::key_value | **E*** | static-хелпер |
| `str_u32` | 268–270 | 3 | u32 из строки | plan_text::number | **E*** | static-хелпер |
| `plan_free` | 272–275 | 4 | освобождение разобранного плана | Drop | **E*** | static-хелпер; управление памятью заменено RAII |
| `parse_text` | 277–685 | 409 | полный разбор текста d2k-plan/r2o-plan во внутреннюю структуру | plan_text::parse | **E** | scripts/test-controller-plantlv-differential.sh: принятие/отказ и точные TLV; строгие случаи сверены с plan_parse.c |
| `put` | 691–695 | 5 | запись байтов в TLV-буфер | plan_text::push_bytes | **E*** | static-хелпер; TLV сверяется дифференциалом |
| `put_u8` | 696–696 | 1 | TLV: один байт | plan_text::push_u8 | **E*** | static-хелпер |
| `put_u16` | 697–697 | 1 | TLV: big-endian u16 | plan_text::push_u16 | **E*** | static-хелпер |
| `put_u32` | 698–701 | 4 | TLV: big-endian u32 | plan_text::push_u32 | **E*** | static-хелпер |
| `put_rec` | 702–707 | 6 | TLV-запись тип/длина/значение | plan_text::push_record | **E*** | static-хелпер |
| `d2k_plan_text_to_tlv` | 709–845 | 137 | компиляция текста плана в TLV D2KP (записи id/proto/payload/poison/...) | plan_text::compile_text | **E** | plantlv differential сравнивает hex после нормализации магии D2KP/R2OP |
| `d2k_plan_text_to_hex` | 847–863 | 17 | компиляция плана в hex-строку | plan_text::compile_text + hex | **E** | используется link/CLI; покрыто plantlv differential |

### `core/props.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `original_probe` | 35–44 | 10 | hook исходного QUIC-замера: `sni = q->control ? NULL : target_sni`, затем `d2k_quic_ask_arm_hook(q,sni,port,wait,mark,sent)` | `r2o_quic_blob_candidate`/`r2o_quic_raw_ask` (`quic_replay.rs`), `r2o_quic_http3_get...` | **P** | **Прямого hook-аналога нет:** Rust строит кандидатов (`r2o_quic_discovery_candidates`, `r2o_quic_original_fallback_candidates`) и вызывает `r2o_quic_http3_*` с `server_name`, но отдельной пары probe/data-hook с `control ? NULL : target_sni` нет. QUIC differentials сравнивают результаты, не эту развилку. |
| `original_data` | 47–50 | 4 | hook данных: `d2k_quic_arm_data_hook(q,target_sni,path,port,wait,mark)` | `r2o_quic_http3_measure...` (`path`/`server_name`/timeouts) | **P** | C передаёт target SNI/path/port/wait/mark одной структурой; Rust принимает path/server_name параметрами в `r2o_quic_http3_get_with_wire_len`. Эквивалентность полей не доказана. |
| `wire_measure` | 52–78 | 27 | собрать `original_wire`, вытащить SNI из trigger, при неудаче и IPv4-литерале `pool[0]` → target_sni, подменить probe/data, скопировать `path`, `next`, `marked`, `probe_path` | `r2o_run_quic_discovery_trial`/`quic_replay` (arm-контекста нет) | **P** | **Подтверждённый пробел:** в Rust grep `target_sni`/`pool[0]` в QUIC-модулях пуст — fallback «literal IP без SNI → pool[0]» не найден; `probe_path` копируется в других местах (`r2o_quic_discovery_probe_path`), `next/marked` живут в `R2oQuicRawAskResult`/trial. Одноимённой обёртки нет. |
| `d2k_quic_original_measure` | 80–83 | 4 | запуск `d2k_quic_original_arms` через `wire_measure` | `r2o_quic_original_fallback_candidates` + trial runner | **P** | C-обёртка одной строкой; Rust список исходных кандидатов и исполнение разнесены. Результаты покрыты QUIC differentials, сама обёртка/`probe_path` — нет. |
| `d2k_quic_strategy_measure` | 88–91 | 4 | запуск `d2k_quic_strategy_arms` через `wire_measure` | `r2o_quic_discovery_candidates` + trial runner | **P** | C-обёртка; Rust список стратегий (`Clearance/SplitCrypto/UdpLength/TtlStrategy`) и исполнение разнесены. Покрыто `r2o-quic-*` differentials частично. |

### `core/sched.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `refuse_is_permanent` | 301–312 | 12 | отказ, который не лечится повтором (TOO_LONG/NOT_APPLIED/FLOW_UNFIT) | discovery.rs refusal classification / main.rs | **P** | правило перенесено; C/Rust differential на коды отказа частичный |
| `refuse_is_damage` | 320–322 | 3 | отказ DAMAGED — поток испорчен недоисполнением | discovery.rs refusal classification | **P*** | static-хелпер |
| `verify_default` | 388–413 | 26 | выбор зонда подтверждения по транспорту и форме (QUIC/TLS1.2/TLS1.3) | main.rs discovery verification dispatch | **P** | ветви подтверждения покрыты TLS/QUIC differentials, но сам диспетчер C/Rust не сравнивался |
| `bind_default` | 415–418 | 4 | bind TCP/UDP порта по транспорту | main.rs discovery bind | **P*** | static-хелпер |
| `verify_rx_default` | 420–427 | 8 | подтверждение identity/gzip при RX-обрыве | main.rs main.rs: RX identity verification branch / fetch identity | **P** | RX-identity проверки покрыты r2o-layered-rx/measured-split частично |
| `verify_rx_gzip_default` | 429–436 | 8 | подтверждение gzip-контроля RX | main.rs main.rs: RX identity verification branch_gzip | **P** | gzip-ветви покрыты measured-split differential частично |
| `mark_default` | 438–440 | 3 | SO_MARK через hook | setsockopt helper | **P*** | static-хелпер |
| `classify_unconfigured` | 451–463 | 13 | заглушка при неподключённом классификаторе: flaky + owns_search | classify::run (всегда подключён) | **P** | C-путь мёртв при сборке d2kc; Rust не имеет такого состояния |
| `voice_default` | 482–484 | 3 | голосовой замер по умолчанию | voice_measure::r2o_measure_voice_for_flow | **P** | покрыто Discord differential частично |
| `d2k_sched_cpu_parse` | 488–511 | 24 | разбор первой строки /proc/stat: busy/total, idle=iowait | r2o_resource_limit::r2o_parse_cpu_stat (48) | **E** | r2o-resource-limit-differential.sh |
| `cpu_read_proc` | 513–527 | 15 | чтение /proc/stat и числа онлайн-ядер | r2o_resource_limit::R2oResourceReading::r2o_read_proc (114) | **E** | r2o-resource-limit-differential.sh |
| `meminfo_field` | 531–549 | 19 | поле MemTotal/MemAvailable из /proc/meminfo | r2o_resource_limit::r2o_meminfo_field (87) | **E*** | static-хелпер; resource differential |
| `d2k_sched_meminfo_parse` | 551–560 | 10 | разбор MemTotal/MemAvailable и отказ при total=0 | r2o_resource_limit::r2o_parse_meminfo (98) | **E** | r2o-resource-limit-differential.sh |
| `mem_read_proc` | 562–570 | 9 | чтение /proc/meminfo | r2o_resource_limit::R2oResourceReading::r2o_read_proc (114) | **E** | resource differential |
| `read_u64_file` | 573–582 | 10 | u64 из файла /proc | r2o_resource_limit::r2o_read_counter (107) | **E*** | static-хелпер; resource differential |
| `ct_read_proc` | 584–589 | 6 | conntrack count/max из /proc | r2o_resource_limit::R2oResourceReading::r2o_read_proc (114) | **E** | resource differential |
| `client_alpn_nonhttp` | 1114–1137 | 24 | решить, можно ли подтверждать не-HTTP клиента его ALPN | main.rs r2o_discovery_client_alpn_verification_allowed | **P** | реализовано; ветви ECH/measure_path/volume проверены classifier differential частично |
| `fresh_trial_id` | 1139–1154 | 16 | 16 случайных ненулевых байт trial ID | getrandom/random id helper | **P** | криптостойкость/ненулевость проверены unit, C-oracle нет |
| `addr_probe_remove` | 1516–1535 | 20 | снять addr-probe привязку с датапата по сохранённой identity | main.rs voice/QUIC addr probe cleanup | **E** | test-discord-voice-confirm-delete-retry/shutdown-cleanup differentials |
| `question_retire` | 1557–1570 | 14 | снять план вопроса и закрыть bound fd | main.rs ask question retire | **P*** | static-хелпер |
| `candidate_retire` | 1572–1590 | 19 | снять пробный name/addr-план и закрыть probe fd | main.rs discovery trial cleanup | **P** | используется в scheduler/voice; отдельного differential нет |
| `trial_retire` | 1592–1595 | 4 | снять вопрос и кандидата | main.rs discovery trial cleanup | **P*** | static-хелпер |
| `say` | 1603–1611 | 9 | журнал планировщика | main.rs log callback | **P*** | static-хелпер |
| `say_quiet` | 1615–1632 | 18 | журнал с подавлением повторов по ключу (8 слотов, 5 мин) | main.rs quiet log | **P*** | static-хелпер |
| `d2k_sched_set_send_cap` | 1634–1637 | 4 | установить предел отправки датапата | main.rs discovery send_cap | **P*** | static-хелпер |
| `d2k_sched_set_say` | 1639–1643 | 5 | установить колбэк журнала | main.rs log callback | **P*** | static-хелпер |
| `verdict_name` | 1647–1662 | 16 | русские фразы для лога: «проходит как есть» … «имя разрешается в приватный адрес», default «неизвестный вердикт» | `classify.rs:907-922 Verdict::as_str` | **P** | **Подтверждённое расхождение:** C — русские человекочитаемые строки и набор из 11 вердиктов, включая `NO_QUIC`/`LOCAL_ADDRESS` и без `POISONABLE`; Rust `as_str` — английские машинные имена (`clear/prefix/whole_packet/opaque/inconclusive/address/poisonable/flaky/unreachable/response`) без `NO_QUIC`/`LOCAL_ADDRESS`. Это лог-текст/набор, не классификация. |
| `signal_of` | 1672–1694 | 23 | code 1/4→rst, 2→repeat, 3→silent, иначе `код-N`; ttl/ttl_delta/tos/ipid только для rst; seen=1 | `main.rs:3391-3420 r2o_discovery_suspect_signal` | **P** | Совпадает посимвольно: те же коды/строки, `is_rst`-гейт для полей, `seen=1`, `ttl_delta=ttl-ref_ttl`. Unit scheduler/classifier; C/Rust differential нет. |
| `is_rx_volume_kind` | 1699–1701 | 3 | `rx-volume` или `rx-volume-wire` | inline `matches!` в `main.rs:3438+` | **P*** | Rust не выделяет helper, но фильтры `volume`/`rx-volume`/`rx-volume-wire` совпадают. |
| `fp_add` | 1703–1730 | 28 | слить сигнал: volume-роды по `abs(Δvolume)<=4` + packets, остальные по `abs(Δttl)<=2`+tos+ipid; иначе добавить до 8 | `catalog.rs:112-150 Fingerprint::merge_observed` + `same_signal` (`:1077-1090`) | **P** | Пороги и слияние совпадают: `VOLUME_SLACK=4`, `TTL_SLACK=2`, tos/ipid, packets только для volume-родов, лимит 8. **Отличие:** Rust `merge_observed` при пустом отпечатке копирует `method`, при несовпадении method выходит; C `fp_add` method не трогает (это делает вызывающий). Unit catalog; C/Rust differential нет. |
| `volume_bucket` | 1746–1751 | 6 | `kb<=0→0`, иначе `floor(log2(kb))+1` | `main.rs:3430-3436 r2o_discovery_volume_bucket` | **P*** | C цикл `kb>>=1; b++` и Rust `32-leading_zeros` дают одно и то же для всех `i32>0`. |
| `is_volume_kind` | 1753–1755 | 3 | `volume`/`rx-volume`/`rx-volume-wire` | inline `matches!` (`main.rs:3438+`) | **P*** | Набор тот же. |
| `box_volume_bucket_agrees` | 1760–1772 | 13 | есть ли у коробки объёмная примета того же рода и той же корзины | `main.rs:3438-3510 r2o_discovery_volume_known_plans` (`same_bucket`) | **P** | C проверяет только совпадение kind+корзины; Rust сначала `fingerprint.is_compatible_with(observed)`, затем `same_bucket` по observed_buckets/box signals, затем сортирует планы по `same_bucket` и `successes`. Итоговый отбор планов шире, чем одна функция; C/Rust differential нет. |
| `server_is_low` | 1798–1805 | 8 | сервер: ровно один порт ≥32768 → другой конец; иначе меньший порт | `DiscoveryTarget::from_event` (`discovery.rs:355-395`), `from_http_portal` (`:416-460`) | **P** | **Подтверждённое расхождение:** C выводит роль по эфемерному диапазону (32768) для **любого** порта; Rust `from_event` принимает только пары с `443` (`(443,443)→None`, `(_,443)`/`(443,_)`), `from_http_portal` — только `80`. TLS/SNI на не-443 порту C обработает, Rust цель не создаст. |
| `client_ip_of` | 1807–1811 | 5 | IP клиента: противоположный серверу конец | endpoint из `DiscoveryTarget::from_event` | **P** | C берёт `high_ip`/`low_ip` по `server_is_low`; Rust формирует `endpoint` сервера из пары 443/80. Для 443/80 эквивалентно, для прочих портов — нет. |
| `server_of` | 1813–1822 | 10 | IP:port сервера в текст и порт | `endpoint`/`host` в `DiscoveryTarget` | **P** | C `inet_ntop` по выбранному концу; Rust строковый `endpoint` из `from_event`/`from_http_portal`. Тот же порт-гейт 443/80. |
| `same_flow` | 1824–1830 | 7 | transport/family/ports/low_ip/high_ip | полный 38-байтный ключ в `R2oRecentTcpNameCache` (`main.rs:7809-7847`) | **P*** | Rust ищет по полному `HelloEvent.key`, что включает transport/ports/адреса; эквивалентно для TCP. Отдельного `same_flow` нет. |
| `remember` | 1841–1862 | 22 | имя потока в кольцо **64** слота, ключ same_flow, `observed_ms` | `R2oRecentTcpNameCache::note` (`main.rs:7815-7847`) | **P** | **Подтверждённые отличия:** C `SCHED_SEEN=64`, ключ transport/family/ports/адреса, поле `observed_ms`; Rust `R2O_RECENT_TCP_NAME_CAPACITY=**512**`, полный 38-байтный ключ, `Instant`, и кэш используется прежде всего для `ech_witness_names`, а не общего recall. C/Rust differential нет. |
| `recall` | 1864–1869 | 6 | точное имя по same_flow | только `ech_witness_names` (`main.rs:7849-7880`) | **P** | **Пробел:** C `recall` возвращает имя по точному потоку; Rust `ech_witness_names` фильтрует по family/адресу и TTL и возвращает список имён для ECH-witness. Общего точного recall по flow нет. |
| `cooldown_find_endpoint` | 1871–1884 | 14 | `used && !challenge && transport/family/name/ip/port` | `R2oDiscoveryCooldownRing` (`main.rs:8509-8600`) | **P*** | C линейный поиск; Rust `Vec<Option<Entry>>` с типизированным ключом (name/transport/family/ip/port). Эквивалентно; differential `r2o-scheduler-cooldown`. |
| `cooldown_find_challenge` | 1886–1897 | 12 | `used && challenge && transport/family/name` | `R2oDiscoveryCooldownRing` (challenge-ключ) | **P*** | C линейный поиск; Rust ключ помечает challenge. Эквивалентно. |
| `dead_find` | 1899–1910 | 12 | ключ name/transport/family/addr | `R2oDeadAddressKey` + `R2oDeadAddressCache` (`main.rs:8305-8415`) | **P*** | Rust ключ `(host, transport, family, ip)`, слоты 128 (`R2O_DISCOVERY_COOLDOWN_CAPACITY`); C тот же набор полей. Эквивалентно. |
| `dead_step` | 1915–1935 | 21 | свободный/самый ранний слот, streak++ (≤255), delay 10/30/60 мин, until=now+delay | `R2oDeadAddressCache::step` (`main.rs:8370-8408`) | **E** | Совпадает: поиск по ключу → free → earliest expiry; `streak.saturating_add(1)`; `r2o_discovery_clear_retry_after` 10/30/60; `expires=now+retry`. `r2o-scheduler-dead-address-differential.sh`. |
| `dead_clear` | 1937–1940 | 4 | очистить запись ключа | `R2oDeadAddressCache::clear` (`main.rs:8414-8423`) | **E** | C `memset` найденной записи; Rust обнуляет все слоты с ключом (ключ уникален). `r2o-scheduler-dead-address-differential.sh`. |
| `is_late_volume_suspicion` | 1942–1946 | 5 | code ∈ {RST_AFTER_APP=5, FIN_RETRY=6, TCP_STALL=8} | `main.rs:7357-7359 r2o_discovery_late_trigger` | **P*** | Коды C (`d2k_journal.h:41,42,56`) и Rust `Some(5|6|8)` совпадают. |
| `cooldown_blocks` | 1948–1973 | 26 | проверить активный cooldown с учётом challenge/exhausted/late_rst_only/кода | main.rs R2oDiscoveryCooldownRing::blocks | **E** | r2o-scheduler-cooldown-differential.sh |
| `cooldown_clear_endpoint` | 1975–1980 | 6 | снять endpoint-cooldown | main.rs discovery cooldown clear | **E** | r2o-scheduler-cooldown-differential.sh |
| `cooldown_clear_nonchallenge` | 1982–1998 | 17 | снять не-challenge cooldown (опционально exhausted/ECH) | main.rs discovery cooldown clear_nonchallenge | **P** | используется в ECH/QUIC путях; отдельного differential нет |
| `clear_backoff_ms` | 2000–2004 | 5 | streak≤1 → **10 мин**, 2 → **30 мин**, иначе **60 мин** | `main.rs:14356-14362 r2o_discovery_clear_retry_after` + константы `:7332-7338` | **E** | **Исправлено:** C `SCHED_CLEAR_BACKOFF_1_MS=10 мин`, `_2_MS=30 мин`, `_MAX_MS=60 мин` (`sched.c:162-164`); Rust FIRST=10, SECOND=30, MAX=60 мин. `r2o-scheduler-cooldown-differential.sh`. |
| `cooldown_victim` | 2012–2027 | 16 | выбрать слот cooldown для вытеснения | main.rs cooldown ring eviction | **P*** | static-хелпер; ring тесты |
| `cooldown_record` | 2032–2097 | 66 | записать challenge/denied/exhausted/negative cooldown | main.rs R2oDiscoveryCooldownRing::record | **E** | r2o-scheduler-cooldown-differential.sh |
| `late_close_what` | 2100–2104 | 5 | текст причины позднего закрытия | main.rs discovery reason | **P*** | static-хелпер |
| `box_stall_budget` | 2114–2122 | 9 | бюджет пакетов коробки из rx-volume packets | main.rs discovery stall budget | **P** | unit/scheduler tests; C/Rust diff нет |
| `budget_listed` | 2124–2127 | 4 | есть ли бюджет в списке | main.rs discovery stall budget | **P*** | static-хелпер |
| `name_stall_budgets` | 2131–2148 | 18 | собрать бюджеты коробок, привязанных к имени | main.rs main.rs: discovery stall-budget branch | **P** | реализовано; differential нет |
| `tcp_stall_in_name_band` | 2153–2166 | 14 | отфильтровать TCP_STALL вне бюджета коробки (±slack) | main.rs discovery stall band | **P** | реализовано; C/Rust differential нет |
| `stall_budgets_push` | 2170–2191 | 22 | отправить SET_STALL_BUDGETS при изменении списка | main.rs discovery sync stall budgets | **P** | кодировщик покрыт control tests; отправка — unit |
| `task_of` | 2193–2202 | 10 | найти задачу по name/transport/family | main.rs R2oDiscoverySearches | **P*** | static-хелпер |
| `task_free_slot` | 2204–2209 | 6 | свободный слот задачи | main.rs discovery search slot | **P*** | static-хелпер |
| `task_watching_slot` | 2217–2222 | 6 | слот наблюдающей задачи для вытеснения | main.rs discovery watching slot | **P*** | static-хелпер |
| `tcp_hello_kind` | 2240–2243 | 4 | ECH-TCP или обычная форма ClientHello | main.rs/classify hello shape | **P*** | static-хелпер |
| `hello_fits_client` | 2245–2252 | 8 | совместимость снимка hello с формой клиента | main.rs discovery hello_fits_client | **P** | реализовано; differential нет |
| `quic_pack_ech` | 2256–2266 | 11 | есть ли ECH в QUIC-пачке (собрать ClientHello из Initial) | main.rs r2o_quic_snapshot_has_ech (4925) | **P** | покрыто QUIC ECH differential частично |
| `quic_named_find` | 2268–2274 | 7 | найти свежий QUIC-снимок имени (10 мин) | main.rs discovery quic_named ring | **P*** | static-хелпер |
| `client_offers_ts` | 2286–2301 | 16 | если опции неизвестны → `trigger_tcp_profile != NO_TS`; иначе разбор: 0→break, 1→skip, битая длина→0, 8/10→1 | `raw_probe.rs:673-682 raw_offer_timestamps` + `ClientShapeEvent.tcp_has_timestamp` | **P** | **Подтверждённое расхождение default:** C при неизвестных опциях берёт **профиль триггера** (`!= NO_TS`); Rust `raw_offer_timestamps(None)` читает `/proc/sys/net/ipv4/tcp_timestamps` (обычно 1). Если триггер измерен как NO_TS, а опции клиента не сняты, C даёт false, Rust — true. Разбор известных опций эквивалентен `PacketView::tcp_options_timestamp_profile`. |
| `client_tcp_profile` | 2303–2318 | 16 | !known/overflow→UNKNOWN; 0→NO_TS; 1→skip; битая→UNKNOWN; 8/10→TS; конец→NO_TS | `packet.rs:39-65 PacketView::tcp_options_timestamp_profile` | **P** | Алгоритм совпадает посимвольно (тест `timestamp_profile_matches_d2o_parser`). **Отличие представления:** `r2o_client_shape_from_legacy` сводит результат к `Option<bool>` (`== TS`), поэтому UNKNOWN превращается в `Some(false)`, а `ClientShapeEvent` не хранит профиль/сырые опции (header, п. 10). |
| `flowkey_same` | 2320–2325 | 6 | transport/family/ports/a_ip/b_ip | полный 38-байтный ключ (`control.rs`/`HelloEvent.key`) | **P*** | Rust сравнивает ключ целиком (включая proto/ports/адреса); эквивалентно для TCP. Отдельного helper нет. |
| `take_shape_opts` | 2328–2341 | 14 | при совпадении имени и flowkey скопировать `tcp_shape_opts[4][40]` и вычислить профиль | `r2o_client_shape_from_legacy` (`main.rs:9355-9390`) + `ClientShapeEvent` | **P** | **Подтверждённый пробел (header, п. 10):** C хранит **сырые TCP-опции** (4×40) в задаче и пересчитывает профиль; Rust уже на приёме события сводит опции к `Option<bool>` и сырые байты не хранит. `take_shape_opts` как отдельный шаг отсутствует; для последующей проверки/повторов доступен только bool. |
| `drop_client_opts` | 2342–2345 | 4 | сбросить `client_opts_known/len` | нет прямого аналога | **P*** | В Rust нет состояния сырых опций, сбрасывать нечего; bool приходит в событии и не переиспользуется как «опции задачи». |
| `fill_hellos` | 2347–2491 | 145 | подготовить trigger/control hello: QUIC снимок/PROFILE, ECH input, TCP снимок, cold profile, decoy | main.rs discovery fill_hellos + hello.rs | **P** | ветви снимка/ECH покрыты discovery/ECH differentials частично; cold profile и decoy — unit |
| `worker_arg_alloc` | 2519–2527 | 9 | выделить аргументы worker через mmap | Box/R2oDiscoveryWork | **P*** | static-хелпер; память покрыта worker-memory differential |
| `worker_arg_free` | 2529–2536 | 8 | освободить аргументы worker | Drop | **P*** | static-хелпер |
| `d2k_sched_ech_baseline_result` | 2538–2556 | 19 | вердикт по прямому ECH-witness: clear только при accepted+name_ok+application+body_complete | main.rs main.rs: ECH baseline outcome branch | **P** | ECH differentials покрывают часть; отдельного C/Rust diff нет |
| `worker_volume` | 2561–2629 | 69 | измерить объёмную лестницу TX/RX, повторить по alt-path при rx_short | main.rs r2o_discovery_measure_volume + fetch ladder | **P** | r2o-measured-split/volume differentials покрывают часть |
| `worker_volume_cut` | 2632–2664 | 33 | сформировать inconclusive-вердикт при доказанном обрыве объёма | main.rs r2o_discovery_volume_cut | **P** | unit/дифференциал объёма частичный |
| `seed_input_of` | 2667–2673 | 7 | FNV-1a seed по hello/ip/port/len | main.rs discovery seed_input | **P*** | static-хелпер |
| `d2k_sched_progress_note` | 2680–2695 | 16 | передать прогресс вопроса в task под мьютексом | main.rs discovery progress | **P*** | static-хелпер |
| `ask_settle` | 2700–2703 | 4 | зафиксировать минимум probe-счётчика | main.rs discovery ask settle | **P*** | static-хелпер |
| `sched_quic_yield` | 2707–2729 | 23 | уступить слот TCP во время QUIC-вопроса и измерить паузу | main.rs discovery quic yield | **P** | r2o-scheduler-concurrent-endpoint/queue differentials частично |
| `sched_quic_progress` | 2731–2733 | 3 | передать прогресс QUIC-вопроса | main.rs discovery progress | **P*** | static-хелпер |
| `sched_mono_ms` | 2735–2739 | 5 | монотонное время мс | std::time::Instant | **P*** | static-хелпер |
| `worker_run_body` | 2741–3253 | 513 | тело worker: VOICE/VERIFY/CONTACT/addr-recheck/ECH GREASE+real/baseline/own-first base/volume first+after+carried/QUIC arm/TCP white/seed/classify и фиксация результата | `main.rs:15311 r2o_discovery_ech_grease_fallback`, `:15322 r2o_discovery_ech_replay_required`, `:15274 r2o_classify_discovery_target_with_client_hello_and_ech`, `:15396 r2o_classify_discovery_target_with_client_hello_and_ech_progress`, `r2o_discovery_volume_*`, `r2o_measure_voice_for_flow`, `r2o_quic_*`, `fetch` | **P** | C-ветви: VOICE (2769-2787), VERIFY (2789-2901: `layered_rx`, verifier по `rx_phase`/`rx_cut`, budget/TS/QUIC-form, ECH replay/ALPN/path), CONTACT (2903-2921), addr-recheck (2934-2965), ECH GREASE/real (2966-3041), ECH baseline (3042-3058), `own_first==1` base (3059-3074), volume_first/after/carried (3077-3103, 3205-3239), QUIC arm (3109-3169), TCP white/seed (3170-3203), результат (3241-3252). Rust покрывает ветви отдельными функциями; **не сопоставлено:** точная матрица verifier'ов (`rx_phase`, `layered_rx`, `measure_path`, ALPN) и комбинации ECH+volume, addr+voice, QUIC deny recheck; C `volume_carried && CLEAR` (3228-3239) отдельной ветвью в Rust не найдена; `own_first==1` base hook не сверен. |
| `worker_run` | 3255–3270 | 16 | обёртка worker: executing, время последнего замера | main.rs discovery worker life | **P** | worker-permit/memory differentials |
| `quic_text_is_split` | 3276–3278 | 3 | план содержит quicsplit | main.rs discovery quic plan check | **P*** | static-хелпер |
| `quic_client_multi` | 3280–3286 | 7 | имя замечено как multi-datagram QUIC | main.rs discovery quic_multi ring | **P*** | static-хелпер |
| `quic_split_unfit` | 3293–3298 | 6 | разрез CRYPTO неприменим (multi-datagram/неполный Initial) | main.rs discovery quic_split_unfit | **P** | покрыто r2o-quic-* differentials частично |
| `task_budget` | 3306–3329 | 24 | бюджет пакетов: отпечаток цели → RX-cut → коробка → поле 04.10 | main.rs discovery task_budget | **P** | unit budget/scheduler; C/Rust diff нет |
| `note_worker_start_failure` | 3331–3337 | 7 | учесть локальную ошибку запуска worker | main.rs discovery local error | **P*** | static-хелпер |
| `start_worker` | 3339–3398 | 60 | создать pthread worker с 1 МБ стека, перенести hello/opts/caps | main.rs discovery worker spawn | **P** | worker-permit/memory differentials; spawn hook/стек не сравнивались |
| `join_worker` | 3405–3424 | 20 | остановить и join worker, учёт join failures | main.rs discovery worker join | **P** | worker-memory/permit differentials |
| `box_ensure` | 3430–3442 | 13 | найти/создать коробку по id | catalog::Catalog box upsert | **P*** | static-хелпер |
| `wall_s` | 3459–3461 | 3 | монотонное время в wall-clock секунды | main.rs discovery wall time | **P*** | static-хелпер |
| `bind_confirmed` | 3463–3568 | 106 | записать подтверждённую привязку/план/отпечаток, обновить successes/confirmed/budget | main.rs apply_discovery_outcome + catalog | **P** | ack-applied/catalog persist differentials покрывают основные ветви; редкие budget/input/ECH origin — unit |
| `fnv1a` | 3574–3581 | 8 | FNV-1a 64 | main.rs discovery fnv | **P*** | static-хелпер |
| `tried_add` | 3593–3596 | 4 | добавить hash плана в список испытанных (лимит) | main.rs discovery tried ring | **P*** | static-хелпер |
| `plan_ident` | 3598–3605 | 8 | plan-%08x и 16-байтный wire id | main.rs discovery plan id | **P*** | static-хелпер |
| `is_hex_digit` | 3607–3609 | 3 | hex-цифра | plan_text::is_hex_digit | **P*** | static-хелпер |
| `question_shape` | 3635–3640 | 6 | wire-shape вопроса: QUIC/форма hello/grandfather | main.rs discovery question shape | **P*** | static-хелпер |
| `probe_shape` | 3642–3672 | 31 | wire-shape зонда: ECH/QUIC/legacy/modern | main.rs discovery probe shape | **P*** | static-хелпер |
| `task_wire_shape` | 3674–3676 | 3 | wire-shape с TCP-профилем | r2k_core::control::r2k_link_shape_tcp_context | **P*** | static-хелпер |
| `binding_wire_shape` | 3678–3682 | 5 | wire-shape сохранённой привязки | main.rs discovery binding shape | **P*** | static-хелпер |
| `stamp_plan_id` | 3684–3704 | 21 | заменить id в тексте плана на wire id | discovery.rs::plan_text_for_trial (1450) | **E** | используется во всех plan differentials; unit |
| `prop_close` | 3727–3732 | 6 | закрыть fd вопроса | main.rs discovery prop_close | **P*** | static-хелпер |
| `contact_close` | 3738–3743 | 6 | закрыть fd contact | main.rs discovery contact_close | **P*** | static-хелпер |
| `ver_close` | 3749–3754 | 6 | закрыть verify-результат | main.rs discovery ver_close | **P*** | static-хелпер |
| `task_reset` | 3762–3811 | 50 | сброс задачи, закрытие fd, MADV_DONTNEED и учёт madvise | main.rs discovery task reset | **P** | madvise-поля покрыты diagnostics unit; C/Rust diff нет |
| `box_injects_rst` | 3834–3840 | 7 | коробка имеет сигнал rst | main.rs discovery box_injects_rst | **P*** | static-хелпер |
| `rst_guard_wanted` | 3842–3847 | 6 | нужен guard rst_alien для RST-триггеров | main.rs discovery rst_guard | **P*** | static-хелпер |
| `plan_arm_rst_guard` | 3853–3860 | 8 | добавить guard rst_alien в план | plan_text guard | **P*** | static-хелпер; classifier tests |
| `prop_send_next` | 3864–3970 | 107 | следующий вопрос свойств: план, bind, mark, SET_NAME, JOB_CONTACT | `ask::question_plan` + CLI `run_r2o_ask` (`main.rs:469`); discovery — `raw_probe::sweep_poisons` | **P** | **Расхождение слоя:** C вызывает это в production-discovery при `verdict==OPAQUE && transport==6 && !have_arm && !owns_search` (`sched.c:11462-11474`, `:12182-12200`) и ставит временный план через управляющий сокет; R2O discovery вопросов через control не задаёт — только raw-пробы (12 свойств, `raw_probe.rs:840`), а `question_plan`/`wait_for_ask_proof` есть лишь в CLI `--ask` (`main.rs:469,646`). На роутере без raw-сокета C всё равно получает вектор, R2O — нет. |
| `prop_finish` | 3974–3989 | 16 | завершить опрос свойств: снять последний план вопроса, закрыть fd, sync | CLI `run_r2o_ask`: `question_retire` (`main.rs:737`); в discovery аналога нет | **P*** | static-хелпер; в production-discovery R2O снимать нечего, потому что control-план вопроса не ставится. Снятие временного плана после raw-пробы не требуется. |
| `task_fail` | 3993–4030 | 38 | завершить задачу неудачей: join, report, cleanup, cooldown/rest | main.rs discovery task_fail | **P** | scheduler differentials покрывают основные ветви |
| `quic_deny_find` | 4032–4038 | 7 | найти QUIC-deny слот | main.rs discovery quic deny ring | **P*** | static-хелпер |
| `quic_deny_install` | 4040–4112 | 73 | поставить quicdeny-план, backoff и пометить привязки на recheck | main.rs discovery quic deny | **P** | есть QUIC-deny тесты; C/Rust differential частичный |
| `quic_deny_active` | 4114–4120 | 7 | активен ли запрет QUIC для имени/семейства | main.rs discovery quic deny | **P*** | static-хелпер |
| `quic_deny_recheck` | 4129–4153 | 25 | перепроверить QUIC своим запросом после истечения запрета | main.rs discovery quic deny recheck | **P** | реализовано; differential нет |
| `quic_deny_tick` | 4155–4181 | 27 | тик QUIC-запретов: recheck или снятие | main.rs discovery quic deny tick | **P** | differential нет |
| `task_done` | 4183–4191 | 9 | завершить задачу отменой: join, report, cleanup, free | main.rs discovery task done | **P** | queue/lifetime differentials частично |
| `rx_decoy_name` | 4195–4197 | 3 | имя приманки RX: network_whitelist.name или hcaptcha.com | main.rs discovery rx_decoy_name | **P*** | static-хелпер |
| `net_whitelist_undecided` | 4201–4203 | 3 | белое имя сети ещё не определено | main.rs discovery net whitelist state | **P*** | static-хелпер |
| `net_whitelist_needs_probe` | 4211–4214 | 4 | нужен подбор белого имени (не решено или rx_cut+tx_only) | main.rs discovery net whitelist probe | **P** | покрыто r2o-net-whitelist-probe-differential.sh |
| `sched_probe_cap` | 4220–4222 | 3 | предел зондов задачи (+ список белых имён) | main.rs discovery probe cap | **P*** | static-хелпер |
| `vol_cut_measured` | 4224–4226 | 3 | обрыв объёма измерен (TX или RX) | main.rs discovery volume cut | **P*** | static-хелпер |
| `vol_cut_kb` | 4227–4229 | 3 | KB обрыва: RX приоритетнее TX | main.rs discovery volume cut | **P*** | static-хелпер |
| `rx_ladder_pending` | 4233–4236 | 4 | есть неиспробованные варианты RX-лестницы/белых имён | main.rs discovery rx ladder | **P*** | static-хелпер |
| `next_rx_volume_plan` | 4242–4290 | 49 | следующий план RX-лестницы: белые имена или 5 вариантов decoy, дедуп по hash | main.rs discovery next_rx_volume_plan | **P** | r2o-measured-split/rx-volume differentials частично |
| `refill_from_fallback` | 4292–4368 | 77 | дозаполнить очередь кандидатов RX-лестницей и запасным перебором донора | main.rs discovery refill_from_fallback + r2o_fallback | **P** | r2o-fallback/rx-ladder differentials частично |
| `claim_early_refusal` | 4394–4410 | 17 | взять код раннего REFUSED, совпавшего с потоком зонда | main.rs discovery early refusal | **P*** | static-хелпер |
| `ack_reason_text` | 4412–4419 | 8 | текст причины ACK | main.rs r2o_ask_ack_reason (15770) | **P*** | static-хелпер |
| `candidate_trial_matches` | 4424–4431 | 8 | ACK относится к trial кандидата (name/addr) | main.rs discovery trial match | **P** | ack-applied differential частично |
| `exec_refusal` | 4437–4466 | 30 | обработать отказ исполнителя: late/non-late, вернуть probe-счётчик, взять следующего | main.rs discovery exec refusal | **P** | scheduler differentials частично |
| `ech_witness_transport_proof` | 4468–4474 | 7 | ECH-witness дал транспортное доказательство (challenge/CF) | main.rs discovery ech witness | **P** | ECH differentials частично |
| `ech_witness_rx_cut` | 4476–4483 | 8 | ECH-witness дал RX-cut (>=8 КБ, неполное тело) | main.rs discovery ech witness | **P** | ECH differentials частично |
| `local_refusal_verdict` | 4485–4537 | 53 | вердикт локального отказа: permanent/повтор/исчерпание | main.rs discovery local refusal | **P** | classifier/scheduler differentials частично |
| `install_next` | 4539–4750 | 212 | поставить следующего кандидата: trial id, guard, bind port, mark, SET_NAME_PROBE/SET_ADDR_PROBE, backoff QUIC | main.rs r2o_run_discovery_candidate_trial (5717) | **P** | крупная ветвистая функция; ack/queue/quic differentials покрывают часть |
| `binding_for` | 4760–4775 | 16 | найти name binding для имени/транспорта/семейства | main.rs discovery binding_for | **P*** | static-хелпер |
| `known_plans` | 4777–4831 | 55 | выбрать сохранённые планы совместимой коробки по отпечатку и success/volume | main.rs discovery known_plans | **E** | r2o-known-plans-differential.sh |
| `budget_rank` | 4866–4868 | 3 | ранг бюджета: passed > unchecked > cut | main.rs main.rs: apply_discovery_outcome budget-rank branch | **P*** | static-хелпер |
| `binding_beats` | 4869–4872 | 4 | сравнение привязок по budget/confirmed | main.rs discovery binding order | **P*** | static-хелпер |
| `bound_plan_here` | 4881–4901 | 21 | есть ли уже подтверждённый план для этой формы/профиля | main.rs discovery bound_plan_here | **P** | own-first/ack differentials частично |
| `own_rank_before` | 4906–4912 | 7 | порядок своих планов: lead, tier, successes, свежесть | main.rs discovery own plan rank | **P*** | static-хелпер |
| `own_first_plans` | 4914–5053 | 140 | собрать и упорядочить свои подтверждённые планы (fill=0/1/2) | main.rs discovery own_first_plans | **E** | r2o-own-first-differential.sh |
| `verdict_proves_block` | 5057–5060 | 4 | вердикт доказывает блокировку (prefix/whole/opaque) | classify verdict helper | **P*** | static-хелпер |
| `clear_measured_shape` | 5074–5080 | 7 | форма, под которой измерен clear | main.rs discovery clear shape | **P*** | static-хелпер |
| `clear_binding_matches` | 5082–5089 | 8 | привязка относится к цели и измеренной форме | main.rs discovery clear binding | **P*** | static-хелпер |
| `forget_clear_target_bindings` | 5123–5172 | 50 | прямой проход: пометить/удалить привязки цели после двух независимых clear | main.rs discovery forget_clear_target_bindings | **P** | own-first/scheduler differentials частично |
| `props_text` | 5178–5186 | 9 | текст вектора свойств | ask::DpiProps display | **P*** | static-хелпер |
| `probes_word` | 5191–5201 | 11 | склонение «опыт/опыта/опытов» | main.rs discovery plural | **P*** | static-хелпер |
| `verdict_to_plans` | 5209–5551 | 343 | по вердикту собрать кандидатов: early-return, ECH trial, QUIC arm, volume fingerprint + known plans, measured arm, RX-лестница, PREFIX/WHOLE split, owned fallback, compose | `main.rs:14573 r2o_ech_rx_ladder_candidate`, `:3438 r2o_discovery_volume_known_plans`, `:6292 r2o_discovery_measured_split_plan`, `r2o_fallback`/`own_first_plans`, `compose_d2o`/`compose_from_props`, `quic_replay.rs:427 r2o_quic_discovery_candidates` | **P** | C-порядок: (1) CLEAR/UNREACHABLE/ADDRESS/RESPONSE/NO_QUIC/LOCAL_ADDRESS → пусто (`:5224-5234`); (2) ECH trial — known plans witness (`:5242-5262`); (3) QUIC — один план из arm+qprops, `arm_hash/arm_path`, `stall_cut`, `quic_split_unfit` (`:5264-5386`); (4) volume signal + `known_plans` (`:5390-5422`); (5) measured arm первым (`:5429-5459`); (6) RX-лестница: room по `rx_cut`, `net_probing`, `plan_boxes`, `rx_volume_candidate_pending` (`:5465-5517`); (7) PREFIX/WHOLE split (`:5519-5528`); (8) `owned_fallback`/`refill_from_fallback` (`:5539-5544`); (9) `d2k_compose` (`:5547-5550`). Rust покрывает источники отдельными функциями; **не найдено:** `arm_hash/arm_path`-атрибуция, `stall_cut`, `net_probe_name`/`plan_boxes`-раскладка, `rx_volume_candidate_pending` как очередь; полного differential порядка нет. |
| `d2k_sched_new` | 5566–5610 | 45 | создать планировщик: defaults, wake-pipe, mutex/cond, QUIC hooks | main.rs R2oDiscoveryQueue (7883)/R2oDiscoverySearches (7971) constructors | **P** | process/serve tests; C/Rust diff нет |
| `d2k_sched_set_measure_mark` | 5612–5614 | 3 | установить метку измерений | main.rs discovery measure_mark | **P*** | static-хелпер |
| `json_str` | 5624–5632 | 9 | JSON-строка live.json | serde_json | **P*** | static-хелпер |
| `json_time` | 5634–5645 | 12 | RFC3339 или 0001-01-01 для live.json | main.rs r2o_live_timestamp | **P*** | static-хелпер |
| `level_name` | 5650–5659 | 10 | текст уровня привязки | main.rs live binding level_name | **P*** | static-хелпер |
| `signal_human` | 5663–5680 | 18 | человеческое описание сигнала | main.rs live signal human | **P*** | static-хелпер |
| `task_phase` | 5685–5705 | 21 | текст фазы поиска | main.rs r2o_live_searches phase | **P*** | static-хелпер |
| `live_binding_for` | 5707–5721 | 15 | найти активную привязку для live.json | main.rs r2o_live_status | **P*** | static-хелпер |
| `live_autopick_status` | 5723–5807 | 85 | причина autopick и остаток cooldown для live.json | main.rs r2o_live_status/autopick | **P** | panel live tests; C/Rust diff нет |
| `d2k_sched_diagnostics` | 5811–5813 | 3 | подключить observer событий диагностики | diagnostics Recorder hook | **P*** | static-хелпер |
| `d2k_sched_limit_diagnostics` | 5814–5816 | 3 | подключить observer смены лимита | diagnostics Recorder hook | **P*** | static-хелпер |
| `worker_type` | 5817–5825 | 9 | тип worker для диагностики | main.rs discovery worker type | **P*** | static-хелпер |
| `d2k_sched_diagnostic_counts` | 5826–5875 | 50 | собрать counts: boxes/bindings/plans/observations/active/queued/workers/task_states/... | main.rs diagnostics counts + r2o_resource_limit | **P** | diagnostics/scheduler differentials частично |
| `d2k_sched_diagnostic_madvise` | 5876–5876 | 1 | отдать статистику madvise | diagnostics::MadviseStats | **P** | unit memory_tracking_and_madvise_json_match_d2o_shape |
| `d2k_sched_diagnostic_madvise_reset` | 5877–5877 | 1 | сбросить статистику madvise | diagnostics madvise reset | **P*** | static-хелпер |
| `d2k_sched_write_live` | 5879–6049 | 171 | атомарно записать live.json: boxes/plans/bindings/groups/searches/measurements/autopick/targets | live.rs::snapshot (63)/write_snapshot (199) | **P** | panel live tests; полный C/Rust differential live.json не найден |
| `d2k_sched_free` | 6051–6072 | 22 | остановить задачи, снять addr-probe, join, закрыть pipe и освободить | main.rs worker shutdown | **P** | shutdown tests частично |
| `wake_loop` | 6077–6080 | 4 | разбудить poll планировщика | main.rs discovery wake | **P*** | static-хелпер |
| `d2k_sched_wake_fd` | 6082–6082 | 1 | fd для poll пробуждения | main.rs discovery wake fd | **P*** | static-хелпер |
| `d2k_sched_active` | 6084–6093 | 10 | число активных поисков (queued/shape/asking/planning/verify/watching) | main.rs r2o_live/searches active | **P** | live tests |
| `plan_by_id` | 6096–6103 | 8 | найти включённый план коробки по id | catalog plan lookup | **P*** | static-хелпер |
| `d2k_sched_sync` | 6112–6125 | 14 | начать полную синхронизацию каталога с датапатом | main.rs R2oCatalogPersistence sync | **E** | r2o-catalog-sync-differential.sh |
| `d2k_sched_sync_pending` | 6127–6129 | 3 | синхронизация ожидается/активна | main.rs catalog sync state | **P*** | static-хелпер |
| `addr_binding_shape` | 6144–6165 | 22 | однозначная wire-shape адресной привязки | main.rs discovery addr_binding_shape | **P** | catalog sync tests частично |
| `newer_name_binding` | 6171–6193 | 23 | есть ли более сильная привязка того же имени | main.rs discovery newer_name_binding | **P** | known/own-first differentials частично |
| `area_key_same` | 6195–6198 | 4 | равенство ключа установленной области | main.rs discovery area key | **P*** | static-хелпер |
| `area_find` | 6200–6204 | 5 | найти установленную область | main.rs discovery area find | **P*** | static-хелпер |
| `area_store` | 6206–6212 | 7 | сохранить область (до 320 слотов) | main.rs discovery area store | **P*** | static-хелпер |
| `area_retry_delay` | 6214–6221 | 8 | 15 с → 30 с → ... → 5 мин | main.rs discovery area retry | **E** | r2o-catalog-sync-differential.sh |
| `area_failure` | 6223–6237 | 15 | зафиксировать отказ области и retry_at/permanent | main.rs discovery area failure | **E** | r2o-catalog-sync-differential.sh |
| `area_ack_reason` | 6239–6246 | 8 | код ACK в причину области | main.rs discovery area ack reason | **P*** | static-хелпер |
| `area_reason_name` | 6248–6258 | 11 | имя причины области | main.rs discovery area reason | **P*** | static-хелпер |
| `area_retry_due` | 6260–6265 | 6 | есть область с наступившим retry | main.rs discovery area retry due | **E** | r2o-catalog-sync-differential.sh |
| `area_plan` | 6267–6273 | 7 | найти план области подходящего proto | main.rs discovery area plan | **P*** | static-хелпер |
| `own_exact_confirmed` | 6278–6293 | 16 | есть точная подтверждённая привязка имени/ключа | groups/catalog confirmed lookup | **P** | groups/catalog tests |
| `desired_area` | 6297–6332 | 36 | желаемая область из группы/исключения | main.rs discovery desired_area | **P** | catalog sync tests частично |
| `desired_has_key` | 6334–6341 | 8 | ключ ещё желаем каталогом | main.rs discovery desired_has_key | **P*** | static-хелпер |
| `write_live_groups` | 6347–6438 | 92 | JSON groups: install/exception state, active/possibly_active, evidence/exceptions | main.rs r2o_live_status groups | **P** | panel tests; C/Rust diff нет |
| `sync_area_send` | 6442–6518 | 77 | отправить SET/DEL_SUFFIX/BYPASS с identity и 5-с дедлайном ACK | main.rs ControlClient area commands | **E** | r2o-catalog-sync-differential.sh |
| `area_exceptions_ready` | 6520–6532 | 13 | все исключения группы подтверждены | main.rs discovery area exceptions | **P** | catalog sync tests частично |
| `area_exception_groups_suspended` | 6534–6551 | 18 | общие правила группы сняты перед исключением | main.rs discovery area suspension | **P** | catalog sync tests частично |
| `group_exception_status` | 6553–6586 | 34 | статус исключений группы (none/pending/retrying/rejected/active) | main.rs discovery group exception status | **P** | live/group tests частично |
| `sync_areas` | 6588–6642 | 55 | синхронизация областей: удаление нежелаемых, исключения раньше групп, ACK-таймаут 5 с | main.rs catalog_area_action (3905)/catalog_area_store (4004)/observe_area_ack (4256) | **E** | r2o-catalog-sync-differential.sh |
| `plan_text_max_emit` | 6648–6658 | 11 | максимальная длина плана после emit (для send_cap) | plan_text::compile + plan::max_emit | **P** | plan tests; C/Rust diff нет |
| `d2k_sched_sync_step` | 6660–6907 | 248 | порция до 8 привязок: skip recheck/weak/unshaped, guard RST, проверка send_cap, SET_NAME/ADDR, затем области | main.rs CatalogSyncCursor::send_step (3887/4205) | **E** | r2o-catalog-sync-differential.sh + catalog persist |
| `has_other_family_target_plan` | 6915–6935 | 21 | есть подтверждённый план той же цели другого семейства | main.rs discovery other family plan | **P** | family queue differential частично |
| `remember_resources` | 6939–6959 | 21 | запомнить публичные resource paths (8 слотов, 1 ч) | r2o_resource::R2oResourceCache::remember_hints | **P** | unit r2o_resource |
| `remember_measured_path` | 6969–6983 | 15 | запомнить доказанный measured_path | r2o_resource::remember_proven_path | **P** | unit r2o_resource |
| `public_resource_peer` | 6985–6993 | 9 | публичный адрес цели (не private/loopback/CGNAT) | r2o_resource/public peer check | **P*** | static-хелпер; net4 differential |
| `select_resource_path` | 6995–7048 | 54 | выбрать measure_path/alt: binding → proven → mention | main.rs discovery select_resource_path | **P** | unit r2o_resource; C/Rust diff нет |
| `ech_rr_known` | 7052–7059 | 8 | кэш HTTPS RR: known yes/no и public_name (10/60 мин) | main.rs discovery ech_rr | **P*** | static-хелпер ECH |
| `ech_rr_store` | 7061–7072 | 12 | сохранить результат HTTPS RR | main.rs discovery ech_rr | **P*** | static-хелпер |
| `ech_chal_has` | 7074–7079 | 6 | имя в 30-мин карантине ECH-witness | main.rs discovery ech_chal | **P*** | static-хелпер |
| `ech_chal_add` | 7081–7086 | 6 | добавить имя в карантин ECH-witness | main.rs discovery ech_chal | **P*** | static-хелпер |
| `ech_pick_witness` | 7088–7116 | 29 | выбрать ECH-witness с public_name == имя, с учётом real/allow_chal | main.rs discovery ech_pick_witness | **P** | ECH differentials частично |
| `ech_witness_untried` | 7118–7128 | 11 | есть неотвергнутый witness | main.rs discovery ech witness | **P*** | static-хелпер |
| `ech_witness_reject` | 7130–7136 | 7 | отвергнуть witness и поставить карантин | main.rs discovery ech witness | **P*** | static-хелпер |
| `ech_witness_add` | 7140–7150 | 11 | добавить кандидата-witness, если RR известен | main.rs discovery ech witness | **P*** | static-хелпер |
| `start_search` | 7152–7328 | 177 | старт поиска: fill_hellos, resource path, ECH witnesses, family recovery, base/own-first, JOB_CLASSIFY | main.rs discovery start_search | **P** | discovery/ECH/own-first differentials покрывают часть |
| `box_id_for` | 7332–7413 | 82 | id коробки по fp/тексту с солью при коллизии | main.rs discovery box_id_for | **P** | catalog tests частично |
| `voice_trial_send` | 7424–7444 | 21 | поставить измеренный voice arm как SET_ADDR_PROBE с lease | voice_discovery.rs::r2o_voice_arm_plan (20) + main.rs voice trial send | **E** | test-discord-voice-discovery-arm/lifecycle differentials |
| `voice_ip_fmt` | 7446–7449 | 4 | IPv4 в текст с fallback «?» | std::net::Ipv4Addr Display | **P*** | static-хелпер |
| `voice_ip_text` | 7450–7453 | 4 | статический буфер IPv4 | std::net::Ipv4Addr Display | **P*** | static-хелпер |
| `voice_ip_text2` | 7454–7457 | 4 | второй статический буфер IPv4 | std::net::Ipv4Addr Display | **P*** | static-хелпер |
| `voice_trial_owned` | 7461–7464 | 4 | voice trial принадлежит нам (name, identity, sport=0, dport!=0) | voice_discovery.rs::r2o_voice_binding_address_scoped (72) | **P*** | static-хелпер |
| `voice_trial_same_context` | 7469–7479 | 11 | событие относится к тому же voice endpoint/клиенту | voice_discovery.rs::r2o_voice_target_from_event (267) | **P** | voice differentials частично |
| `voice_start` | 7481–7510 | 30 | найти known discovery prefix и запустить JOB_VOICE | voice_discovery.rs::r2o_voice_discovery_prefix_from_plan_text (26) + main.rs R2oVoiceDiscoveryWorker (9801) | **E** | r2o-discord-discovery-differential.sh |
| `voice_finish_measure` | 7512–7609 | 98 | разобрать voice-замер: CLEAR/blocked, flow match, arm → план, SET_ADDR_PROBE, T_VOICE_TRIAL | voice_discovery.rs::evaluate_r2o_discovery (728) + main.rs R2oVoiceDiscoveryWorker (9801) | **P** | discord lifecycle differential частично |
| `quic_addr_start` | 7616–7624 | 9 | QUIC-поиск по адресу без SNI | main.rs discovery quic_addr_start | **P** | quic differentials частично |
| `measurements_in_flight` | 7628–7633 | 6 | число идущих замеров без parked QUIC | main.rs discovery in-flight | **P*** | static-хелпер; queue tests |
| `queued_measurements` | 7635–7641 | 7 | число задач в очереди + parked QUIC | main.rs discovery queued | **P*** | static-хелпер |
| `res_sample` | 7649–7686 | 38 | сэмпл CPU/памяти/conntrack, EWMA свободного CPU 1/10 с | r2o_resource_limit::r2o_scheduler_tick | **E** | r2o-resource-limit-differential.sh |
| `res_valid` | 7696–7696 | 1 | валидны и CPU, и память | r2o_resource_limit | **E*** | static-хелпер; resource differential |
| `cpu_free_pct` | 7698–7700 | 3 | свободный CPU в процентах | r2o_resource_limit::r2o_cpu_free_pct | **E*** | static-хелпер |
| `mem_reserve_kb` | 7702–7705 | 4 | резерв памяти: 20 % или 32 МБ | r2o_resource_limit::r2o_mem_reserve_kb | **E*** | static-хелпер |
| `mem_short` | 7707–7709 | 3 | память ниже резерва | r2o_resource_limit | **E*** | static-хелпер |
| `ct_short` | 7711–7715 | 5 | conntrack >= 60 % | r2o_resource_limit | **E*** | static-хелпер |
| `ct_pct` | 7717–7719 | 3 | процент conntrack | r2o_resource_limit | **E*** | static-хелпер |
| `meas_state` | 7721–7735 | 15 | состояние считается измеряющим | r2o_resource_limit | **E*** | static-хелпер |
| `measure_slots` | 7741–7748 | 8 | доступные слоты замера (free/queued/measuring, max 8) | r2o_resource_limit | **E*** | static-хелпер |
| `limiter_text` | 7750–7763 | 14 | текст причины лимита: процессор/память/conntrack/слоты | r2o_resource_limit::r2o_limiter_text | **P*** | static-хелпер |
| `measure_started` | 7767–7769 | 3 | запомнить grow_pending при упоре в лимит | r2o_resource_limit | **E*** | static-хелпер |
| `measure_limit_update` | 7771–7837 | 67 | AIMD-лимит: shrink вдвое, grow +1, маска limiter, диагностика | r2o_resource_limit::R2oAdaptiveLimit | **E** | r2o-resource-limit-differential.sh; start-gap 250 мс |
| `installed_family_ready` | 7842–7873 | 32 | семейство уже установлено и подтверждено после события | main.rs discovery installed_family_ready | **P** | family queue differential частично |
| `binding_covering` | 7876–7897 | 22 | подходящая привязка exact/modern/unshaped | main.rs discovery binding_covering | **P*** | static-хелпер |
| `watch_shape` | 7899–7903 | 5 | форма наблюдаемого hello с учётом ECH | main.rs discovery watch_shape | **P*** | static-хелпер |
| `queued_family_ready` | 7905–7908 | 4 | очередь можно снять: семейство установлено | main.rs discovery queue family ready | **P** | family queue differential частично |
| `family_recovery_eligible` | 7910–7913 | 4 | задача подходит для быстрого семейного восстановления | main.rs discovery family recovery | **P*** | static-хелпер |
| `group_path` | 7919–7921 | 3 | путь группы: «/» для UDP/пустого | main.rs discovery group_path | **P*** | static-хелпер |
| `family_recovery_start` | 7923–7997 | 75 | быстрый старт по собственным планам семейства без нового замера | main.rs discovery family recovery start | **P** | r2o-scheduler-family-queue-differential.sh частично |
| `launch_task` | 7999–8027 | 29 | запуск задачи: admission sequence, by_addr/voice/arm shape/start_search | main.rs discovery launch_task | **P** | queue/voice/QUIC differentials частично |
| `launch_or_queue` | 8029–8068 | 40 | запуск или постановка в ограниченную очередь с start-gap 250 мс | main.rs R2oDiscoveryQueue | **E** | r2o-queue-order/queue-full/worker-permit differentials |
| `voice_observe` | 8070–8084 | 15 | UDP-ответ voice без протокольного доказательства — не в каталог | main.rs voice observe | **P** | voice lifecycle differential частично |
| `voice_confirm` | 8090–8151 | 62 | подтвердить voice/stun привязку, снять trial, записать в каталог | main.rs confirm_r2o_voice_trial (16383) + voice_discovery.rs::r2o_save_confirmed_voice_binding (39) | **E** | r2o-discord-discovery-differential.sh + lifecycle |
| `voice_fail` | 8153–8158 | 6 | снять voice trial при молчании | main.rs voice fail | **P** | voice lifecycle differential частично |
| `is_voice_class` | 8160–8162 | 3 | UDP и имя @discord-voice | main.rs is_voice_class | **P*** | static-хелпер |
| `is_telegram_tunnel_domain` | 8167–8178 | 12 | домен telegram.org/поддомен — не мерить | main.rs discovery telegram tunnel | **P*** | static-хелпер |
| `on_suspect` | 8181–8592 | 412 | главный вход подозрения: cooldown/dead address/voice pending/clean handshake/binding/fp/task/queue; фильтры и запуск | main.rs ControlClient::r2o_queue_tcp_suspect (20090) + R2oDiscoveryQueue::queue_after_fresh_suspect (13534) | **E** | r2o-scheduler-differential.sh, cooldown, dead-address, queue-order, coalesce |
| `quic_own_initial` | 8607–8621 | 15 | взять свой QUIC Initial: snap или свежий снимок имени | main.rs discovery quic_own_initial | **P*** | static-хелпер |
| `remeasure_snapped` | 8623–8682 | 60 | перемерить снимком клиента: сброс состояния, смена hello, launch | main.rs discovery remeasure_snapped | **P** | snapshot/discovery differentials частично |
| `quic_note_multi` | 8690–8730 | 41 | запомнить multi-datagram QUIC и пометить split-привязки на recheck | main.rs discovery quic_note_multi | **P** | QUIC differentials частично |
| `on_shape` | 8732–9008 | 277 | снимок hello: сохранить TCP opts/ECH/QUIC, подменить вход задачи, перезапуск/наблюдение | main.rs discovery on_shape | **P** | ECH/QUIC/discovery differentials частично; вся матрица состояний не сравнивалась |
| `group_record` | 9013–9032 | 20 | записать наблюдение области (BLOCKED/CLEAR/PLAN_FAILED) | groups::learn + main.rs | **P** | groups tests; C/Rust differential нет |
| `record_shape` | 9035–9040 | 6 | форма для записи привязки | main.rs discovery record_shape | **P*** | static-хелпер |
| `budget_uncountable_note` | 9043–9050 | 8 | однократно сообщить, что бюджет потока не считается | main.rs discovery budget note | **P*** | static-хелпер |
| `budget_cut_reject` | 9072–9151 | 80 | отклонить кандидата при обрыве бюджета, сохранить лучший частичный | main.rs discovery budget_cut_reject | **P** | budget/layered-rx differentials частично |
| `say_question_trace` | 9159–9168 | 10 | напечатать трассу вопросов QUIC-замера | main.rs discovery qtrace log | **P*** | static-хелпер |
| `ladder_candidate_at` | 9175–9184 | 10 | план по индексу — кандидат RX-лестницы | main.rs discovery ladder_candidate | **P*** | static-хелпер |
| `ladder_candidate` | 9185–9187 | 3 | текущий кандидат — лестница | main.rs discovery ladder_candidate | **P*** | static-хелпер |
| `candidate_path` | 9189–9200 | 12 | источник кандидата: свой план/приём/RX/перебор/вывод | main.rs discovery candidate_path | **P*** | static-хелпер |
| `search_report` | 9207–9260 | 54 | итог поиска в журнал и diagnostics (id/target/protocol/outcome/path/probes/elapsed/queue) | main.rs r2o_discovery_diagnostic_event + search report | **P** | r2o-diagnostics-differential.sh проверяет event_json частично |
| `verify_confirm` | 9262–9653 | 392 | подтвердить кандидата: budget/лестница, bound-plan, ECH/QUIC replay, name_ok, split-unfit, unfit-список, bind_confirmed, группа, budget-mark, measure_path, by_addr, net-whitelist, report, T_WATCHING | `main.rs:5347 r2o_confirm_discovery_outcome`, `:21856 apply_discovery_outcome`, `:5321 r2o_family_recovery_decision`, `:21518 r2o_install_quic_candidate`, `:15322 r2o_discovery_ech_replay_required`, `:14628 r2o_discovery_volume_recovery` | **P** | Покрыто: полный HTTPS-ответ + APPLIED (`r2o_family_recovery_decision`), ECH accepted/peer_name/complete/application, Cloudflare/Blocked/LegalDenial, QUIC/ECH адресная привязка (`add_confirmed_quic_address_binding`), ECH replay (`r2o_discovery_ech_replay_required`), volume recovery. **Не найдено:** (1) pre-confirmation гейт по `unfit_seen` — FLOW_UNFIT обрабатывается только после события (`r2o_catalog_mark_flow_unfit`, main.rs:19097-19169), в подтверждении список не проверяется; (2) остановка других `T_ASKING` задач (`yield_to_own_plan`, sched.c:9622-9636) — в Rust не найдена; (3) `bd->budget` PASSED/UNCHECKED/CUT в `apply_discovery_outcome` не выставляется, хотя константы `R2O_D2K_CAT_BUDGET_*` есть; (4) `tcp_profile` отсутствует в `Binding` (подтверждено ранее), `verified_by`/`input` есть, `probe_path` сохраняется для QUIC. |
| `partial_finish` | 9668–9689 | 22 | взять лучший частичный обход и подтвердить его | main.rs discovery partial_finish | **P** | budget differential частично |
| `plan_id_is_ours` | 9691–9696 | 6 | plan_id события — наш ver_plan_id | main.rs discovery plan id check | **P*** | static-хелпер |
| `applied_trial_is_ours` | 9700–9705 | 6 | trial_id события — trial кандидата | main.rs discovery trial match | **P*** | static-хелпер |
| `applied_of_candidate` | 9708–9723 | 16 | APPLIED относится к кандидату: family/transport/plan/addr trial и endpoint | main.rs discovery applied match | **P** | ack-applied differential частично |
| `on_applied` | 9739–9857 | 119 | APPLIED: voice trial→watch, props early/applied, verify early, verify_wait ok | main.rs ControlClient::observe_applied (15716) + remember_applied_event (20292) | **E** | r2o-ack-applied-persist-differential.sh + ack sequence |
| `on_refused_foreign` | 9900–9939 | 40 | REFUSED чужого/постоянного отказа: unfit plan_id и unfit_names | main.rs discovery on_refused_foreign | **P** | scheduler differential частично |
| `on_refused_unfit` | 9960–10051 | 92 | REFUSED NOT_APPLIED/FLOW_UNFIT: помечить привязки на recheck и перемерить | main.rs discovery on_refused_unfit | **P** | classifier/scheduler differential частично |
| `on_refused` | 10053–10157 | 105 | маршрутизация REFUSED по состояниям задачи и групповым отказам | main.rs ControlClient::observe_refused (15752) | **E** | r2o-scheduler-differential.sh + classifier |
| `note_clean_handshake` | 10176–10199 | 24 | запомнить чистое рукопожатие имя+клиент (10 мин) | main.rs discovery clean handshake | **P** | discovery coalesce differential частично |
| `clean_handshake_recent` | 10202–10215 | 14 | недавнее чистое рукопожатие для этого клиента | main.rs discovery clean handshake | **P*** | static-хелпер |
| `on_exchange` | 10217–10323 | 107 | EXCHANGE: clean handshake, voice proof, props early/reply/pass, outer appdata наблюдение | main.rs discovery on_exchange | **P** | scheduler/voice differentials частично |
| `d2k_sched_event` | 10325–10457 | 133 | диспетчер событий датапата: HELLO/ACK/область/SUSPECT/STATS/SHAPE/CLIENT_TCP/APPLIED/REFUSED/EXCHANGE | main.rs ControlClient::watch_events + note_datapath_event | **E** | r2o-control-events/ack-applied/scheduler differentials |
| `own_first_continue` | 10465–10523 | 59 | после своих планов: сброс, seed, снимок клиента, полный замер | main.rs discovery own_first_continue | **P** | r2o-own-first-differential.sh частично |
| `rx_saved_bootstrap` | 10528–10572 | 45 | прямой RX-зонд не дошёл до TLS: проверить identity под сохранённым планом | main.rs discovery rx_saved_bootstrap | **P** | layered-rx differential частично |
| `layered_rx_result` | 10574–10652 | 79 | двухфазная RX-проверка identity/gzip и решение о остаточном обходе | main.rs discovery layered_rx_result | **E** | r2o-layered-rx-differential.sh |
| `queued_before` | 10658–10662 | 5 | порядок очереди: hot_event desc, queued_event asc, queued_ms asc | main.rs discovery queue order | **E*** | static-хелпер; r2o-queue-order-differential.sh |
| `quic_yield_tick` | 10666–10701 | 36 | park/resume QUIC-задач, уступая TCP, с переносом ожидания | main.rs discovery quic_yield_tick | **E** | r2o-scheduler-concurrent-endpoint/queue differentials |
| `queued_pick` | 10703–10726 | 24 | выбор следующей задачи: TCP при parked QUIC, family recovery приоритет, иначе порядок | main.rs discovery queue pick | **E** | r2o-queue-order/family-queue differentials |
| `queued_release` | 10728–10754 | 27 | запуск из очереди при наличии слота и соблюдении start-gap | main.rs discovery queue release | **E** | r2o-queue-order/worker-permit differentials |
| `voice_pending_dispatch` | 10756–10782 | 27 | запустить отложенное voice-подозрение после текущего trial/watch | main.rs voice pending dispatch | **P** | discord lifecycle differential частично |
| `d2k_sched_tick` | 10784–12364 | 1581 | главный тик: clock/admission, ресурсы, wake, QUIC yield/deny, группы, sync, все состояния задач (QUEUED/RESTING/lifetime/VOICE/ASKING/PROPS/VERIFY/TRIAL_SETTLE/PLANNING), очередь, voice, диагностика | `main.rs:7971 R2oDiscoverySearches`, `:12071` worker loop, `:12140` QUIC yield, `r2o_resource_limit`, `r2o_route`, `groups.rs`, `live.rs` | **P** | Блоки C: clock/report admission (10793-10807), `res_sample` (10809), wake drain (10812), `quic_yield_tick`/`quic_deny_tick` (10817-10818), group expiry 7 суток (10822-10830), sync/area retry (10831-10837), task loop (10840-12360). Rust: worker loop/queue/cooldown/dead/resource/route/voice, `r2o_quic_yield_waiting_for_tcp` (`:12140`), `groups.rs`; **не доказано:** полная матрица переходов и комбинации ECH+volume/addr+voice/QUIC-deny; `T_WATCHING` как фаза отсутствует; `yield_to_own_plan`/`shape_misses` не найдены. |

### `core/verdict.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `looks_like_tls` | 33–35 | 3 | `bytes[0] == 0x16` → ServerHello, иначе Any | `Trigger::accept` (`classify.rs:73-103`) | **P** | **Подтверждённое расхождение:** C выбирает accept **по первому байту** (raw-триггер с `0x16` получает ServerHello); Rust `Trigger::raw_hex` всегда ставит `Accept::Any`, `tls/tls13` — ServerHello. Для raw-hex `0x16` набор принимаемых ответов шире, чем у C. C-вердиктное дерево production-вызовов не имеет (только `core/test_verdict.c`), но контракт функции различается. |
| `reverse_note` | 53–62 | 10 | MODERN → "", LEGACY → «обратное направление не проверено», UNKNOWN → «вид не разобран…» | classify.rs reason | **P*** | C-тексты фиксированы; Rust формирует причину иначе, дословного сравнения нет. |
| `pause_note` | 74–80 | 7 | `gap_us==0` → «без пауз», иначе «с паузой N мкс»; буфер 96 | classify.rs reason | **P*** | C `snprintf` в 96 байт; Rust `String` без обрезки. Текст и границы не сравнивались. |
| `stop_requested` | 92–94 | 3 | `stop && *stop` (volatile sig_atomic) | `AtomicBool::load`/cancel (`classify.rs:1041`) | **P*** | C указатель может быть NULL; Rust `Option<&AtomicBool>`/cancel-флаг. Эквивалентно. |
| `classify_cancelled` | 96–102 | 7 | verdict=INCONCLUSIVE, `marked=(mark!=0)&&all_marked`, reason «профильный замер отменён…» | `finish_cancelled` (`classify.rs:1952`) | **P** | C текст и явный `marked`; Rust ставит Inconclusive и reason «замер брошен по требованию остановки на N-м зонде…», `finish` не выставляет `marked` в этой функции. C-путь не production (только test_verdict.c). |
| `d2k_classify_cancelable` | 104–334 | 231 | дерево: guard len<2 → FLAKY; база; `err==repeats` → UNREACHABLE; частичный pass → FLAKY; полный → confirm 2 → CLEAR/INCONCLUSIVE; иначе разрез 1 → PREFIX/FLAKY/контроль → OPAQUE/INCONCLUSIVE; метка по AND | `run_with_backend_progress` (`classify.rs:1298`) + `measure`/`finish` | **P** | Ветви и порядок совпадают, но production discovery использует `full_detect_semantics=false`, `confirm_clear=true` (`classify.rs:869-870`, `main.rs:15380-15391`): нет удвоенного dial-retry, иначе обрабатываются частичные transport-ошибки, control без `until_pass`, добавлен whole-confirm. Дифференциалы идут с `true` и этот путь не покрывают. |
| `d2k_classify` | 336–342 | 7 | обёртка `d2k_classify_cancelable(..., stop=NULL)` | `classify::run` (`:1929`) | **P** | C-обёртка без отмены; Rust `run` → `run_with_backend(TcpProbeBackend)`. C-путь production-вызовов не имеет. |

### `core/x25519.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `car25519` | 32–50 | 19 | перенос radix-16 поля 2^255-19, `o[0]+=38*c` на последней конечности | `hpke`/`ring` (внутренняя арифметика) | **P*** | C-арифметика TweetNaCl; Rust своей арифметики не имеет: ECH — `X25519HkdfSha256` (`ech.rs:9,128`), TLS/QUIC — `ring::kx_group::X25519` (`r2o_tls.rs:94,100,287`, `quic_replay.rs:125`). Совпадение результатов только через косвенные ECH/TLS differentials. |
| `sel25519` | 54–61 | 8 | константное переключение по маске | `hpke`/`ring` | **P*** | Отдельной функции нет; constant-time обеспечивает библиотека. |
| `pack25519` | 63–82 | 20 | упаковка 16 конечностей в 32 байта | `hpke`/`ring` | **P*** | То же; сериализация публичного ключа проверяется косвенно. |
| `unpack25519` | 84–89 | 6 | распаковка 32 байт, старший бит отбрасывается | `hpke`/`ring` | **P*** | RFC 7748 §5; библиотека делает то же, прямого вектора нет. |
| `A` | 91–91 | 1 | сложение элементов поля | `hpke`/`ring` | **P*** | static-хелпер. |
| `Z` | 92–92 | 1 | вычитание элементов поля | `hpke`/`ring` | **P*** | static-хелпер. |
| `M` | 94–104 | 11 | умножение 16×16 с редукцией `38*t[i+16]` | `hpke`/`ring` | **P*** | static-хелпер. |
| `S` | 106–106 | 1 | квадрат через `M` | `hpke`/`ring` | **P*** | static-хелпер. |
| `inv25519` | 109–117 | 9 | обращение через `p-2` (253..0, пропуск 4 и 2) | `hpke`/`ring` | **P*** | static-хелпер. |
| `d2k_x25519` | 119–168 | 50 | clamp `z[31]=(z[31] & 127)` с установкой бита 64, `z[0] &= 248`, Montgomery ladder 254..0, **отказ при нулевом результате** | `hpke X25519HkdfSha256` (`ech.rs:9,80-117`), `ring::agreement` X25519 (`r2o_tls.rs:94,100,287`) | **P** | **Подтверждённое расхождение политики:** C явно возвращает -1 при all-zero shared secret (малая точка); Rust полагается на `hpke`/`ring`. Прямых C/Rust-векторов X25519 и теста на low-order точку нет; ECH/TLS differentials косвенные. |
| `d2k_x25519_base` | 170–198 | 29 | clamp + ladder от базовой точки 9; нулевой результат не проверяется | `hpke`/`ring` public key | **P** | C не проверяет ноль (при clamp он невозможен); Rust `PublicKey` из hpke/ring. Отдельного differential с C нет. |

### `core/include/d2k_link.h`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_link_shape_tcp_profile` | 309–319 | 11 | 8/9/10 → NO_TS(1), 11/12/13 → TS(2), иначе UNKNOWN(0) | `control.rs:99-107` `r2k_link_shape_tcp_profile` | **E*** | C switch и Rust match совпадают; unit `tcp_shape_context_table_matches_d2o`. |
| `d2k_link_shape_tcp_base` | 321–331 | 11 | 8/11→1, 9/12→2, 10/13→6, иначе shape как есть | `control.rs:108-118` `r2k_link_shape_tcp_base` | **E*** | Точное совпадение; unit таблицы. |
| `d2k_link_shape_tcp_context` | 333–339 | 7 | профиль UNKNOWN → shape; 1/2/6 + TS/NO_TS → 8..13; иначе shape | `control.rs:119-147` `r2k_link_shape_tcp_context` | **E** | C и Rust: три базовые формы, TS→*_TS, NO_TS→*_NO_TS, прочие без изменений; unit `tcp_shape_context_table_matches_d2o` (таблица против C). |

### `core/include/d2k_resource.h`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_resource_word` | 27–35 | 9 | равная длина, ASCII lower-case `s[i]`, сравнение с `word[i]` | `r2o_resource.rs:407-413` `r2o_resource_word` | **P*** | Совпадает: длина + `eq_ignore_ascii_case` по байтам. Отдельного теста хелпера нет. |
| `d2k_resource_space` | 36–38 | 3 | `' '`, `\\t`, `\\r`, `\\n`, `\\f` | `r2o_resource.rs:415-417` `r2o_resource_space` | **P*** | Совпадает посимвольно. |
| `d2k_resource_path_ok` | 39–50 | 12 | непустой, <512, `/`, не `//`, без `/../` и `/./`, `[A-Za-z0-9/._-]`, кончается `.css` | `r2o_resource.rs:309-330` `r2o_resource_path_ok`/`path_bytes_ok` | **P** | Построчно совпадает; Rust `windows(4)`/`windows(3)` вместо `strstr`, `.css` — `eq_ignore_ascii_case`. Целевого C/Rust differential нет. |
| `d2k_resource_add` | 51–73 | 23 | https/`//`: путь, хост <256, без ведущей/хвостовой точки, LDH+`.`, lower-case, один ресурс на хост, максимум 2 | `r2o_resource.rs:255-305` `r2o_add_url`/`r2o_add_url_bytes` | **P*** | Построчно совпадает: strip_prefix, первый `/`, host/path checks, lower-case, dedupe по host, push. Rust дополнительно останавливает `feed` при 2 ресурсах (C — в `add`). |
| `d2k_resource_tag` | 74–113 | 40 | завершить тег: raw `/script`/`/style`, script/style/body, `link` с одним `href`/`rel=stylesheet`, href <1024 | `r2o_resource.rs:188-236` `r2o_finish_tag`, `:332-405` `r2o_link_stylesheet_href` | **P*** | Построчно совпадает, включая префикс `/script`/`/style` (case-sensitive), один `href`/`rel`, отказ при незакрытой кавычке и лимит 1024. |
| `d2k_resource_feed` | 114–159 | 46 | лимит 32768, сбор URL по байту `h`, теги/комментарии/кавычки, `>` завершает тег | `r2o_resource.rs:140-186` `R2oResourceScan::feed` | **P** | Построчно совпадает; **отличие:** Rust прерывает обход при `resources.len() >= 2`, C продолжает до 32768, а лишние ресурсы отбрасывает в `add`. Итоговый набор тот же, объём сканирования разный. Целевого C/Rust differential нет. |

## Углублённая сверка: domain/groups/match/net4/verdict/props (37 функций)

| C-функция | строки | R2O-аналог | статус | доказательство / пробел |
|---|---:|---|---|---|
| `d2k_domain_normalize` | 6–29 | `domain.rs:8-58` `normalize` | **P** | C принимает односоставное нечисловое имя (`localhost`), Rust требует ≥2 метки (`domain.rs:52-54`). Для `d2k_domain_base/member` это не проявляется (там нужен известный PSL-суффикс), но прямой контракт функции различается. |
| `rule_exists` (static) | 31–40 | `domain.rs:63-69` `psl::suffix/domain` | **P*** | C ищет правило в зашитом `psl_index.h`; Rust использует crate `psl`. Совпадение снимка PSL не доказано. |
| `d2k_domain_base` | 42–64 | `domain.rs:61-71` `registrable_domain` | **P** | Логика «longest rule, exception, wildcard, unknown TLD → отказ» соответствует `psl::domain` + `is_known()`. C/Rust differential на PSL-набор не найден. |
| `d2k_domain_member` | 66–72 | `domain.rs:74-86` `is_member` | **P** | C требует, чтобы `suffix` имел известный base; Rust делает то же через `registrable_domain(suffix).is_none()`. Зависит от совпадения PSL. |
| `d2k_group_key_make` | 9–17 | `catalog::GroupKey` + `validate_key` (`groups.rs:424`) | **P** | C копирует в фиксированные буферы с `strlen >= sizeof`; Rust `String` + `validate_key` (transport 6/shape 1/2/6/8–13 или 17/3, family 4/6, path/origin ≤255 без NUL). Эквивалентно; отдельного конструктора нет. |
| `d2k_group_key_same` | 19–23 | `PartialEq for GroupKey` | **E** | Пять полей, derived `PartialEq`; unit `tests/groups.rs`. |
| `valid` (static) | 24–36 | `validate_key` + `canonical_evidence` (`:389`) | **P** | Транспорт/форма/семейство и требование plan_id совпадают. **R2O-расширение:** `OPERATOR_REJECT=32` и маски `BLOCKED|...`; C принимает только точные evidence 1/2/4/8. |
| `member` (static) | 38–41 | `groups::member` (`:443`) | **E** | Формула `name==suffix` или `prefix.ends_with('.')` совпадает; unit. |
| `votes` (static) | 45–60 | `groups::votes` (`:484`) + `latest_vote` (`:514`) | **P** | Правило `live>=2 && live>stale && live+stale>=3`, stale при PLAN_FAILED/DIRECT_CLEAR, latest по `at` — совпадают; Rust считает latest отдельным проходом. C-oracle нет. |
| `failures` (static) | 61–71 | `groups::failures` (`:531`) | **P*** | План/ключ/суффикс/PLAN_FAILED совпадают; unit `tests/groups.rs`. |
| `add_group` (static) | 72–102 | `groups::add_group` (`:544`) | **P** | Выбор по failures→count→at→plan_id, удаление покрытых и `frozen` при 64 совпадают; unit. |
| `rebuild` (static) | 103–120 | `groups::rebuild` (`:326`) | **P** | C `d2k_domain_base` + суффиксы от длинного к короткому, последний `count!=0` побеждает; Rust `registrable_domain` + `labels[start..]`, та же перезапись. Наследует разницу PSL/`normalize`. |
| `cover` (static) | 122–132 | `groups::covering_group` (`:450`) | **P*** | disabled/overflow → None, иначе longest suffix по key; unit. |
| `d2k_group_learn` | 133–245 | `groups::learn` (`:65`) | **P** | Слот same-plan/any/replace, changed/frozen, reclaim exact INCONCLUSIVE→BLOCKED→first, disabled_at=max, PLAN_FAILED OR, admitted exception, очистка дублей, rebuild — совпадают. **Отличия:** (1) Rust `OPERATOR_REJECT` — ранний `Ok(false)`; C бита не знает; (2) при disabled C удаляет только `evidence==BLOCKED`, Rust — любой `evidence & BLOCKED` (шире); (3) C не делает rebuild при вставке INCONCLUSIVE, Rust делает (набор групп не меняется). |
| `d2k_group_restore` | 246–273 | `groups::restore` (`:15`) + `canonical_evidence` (`:389`) | **P** | Канонизация масок и проверка дублей совпадают. **R2O-расширение:** OPERATOR_REJECT (база BLOCKED/PLAN_FAILED/5). Отдельного C/Rust теста нет. |
| `d2k_group_match` | 274–293 | `groups::match_domain` (`:358`) | **P** | Исключения DIRECT_CLEAR/PLAN_FAILED того же плана и longest suffix совпадают; **Rust дополнительно исключает OPERATOR_REJECT**. |
| `d2k_group_forget` | 294–310 | `groups::forget_failures` (`:271`) | **E** | normalize, фильтр name/transport/family/PLAN_FAILED, swap_remove, rebuild, возврат числа — совпадают; unit. |
| `d2k_group_expire` | 311–324 | `groups::expire_failures` (`:304`) | **E** | `max_age<=0` или `now<max_age`, `at < now-max_age`, swap_remove/rebuild — совпадают; unit. |
| `same_evidence` (static) | 38–73 | `catalog.rs:1077-1090` `same_signal` | **P** | volume/rx-volume: `\|d\|<=4`; ttl: `\|d\|<=2`; tos/ipid точно — совпадает с C. Тестов/дифференциала именно на эту функцию нет. |
| `d2k_fp_same` | 75–125 | `catalog.rs:59-84` `Fingerprint::is_compatible_with` | **P** | Направленный обход b→a, все приметы одного рода, `kind_seen && !agreed → false`, `common>0` — совпадает. |
| `d2k_catalog_match` | 127–136 | `catalog.rs:537-541` `match_fingerprint` | **P** | Первый совместимый индекс; эквивалентно. |
| `d2k_ip4_parse` | 7–30 | `std::net::Ipv4Addr::from_str` (`examples/m5_net4_trace.rs:15`) | **P** | **Подтверждённое расхождение:** C принимает ведущие нули (`010.0.0.1` → 10.0.0.1), Rust 1.98 даёт `Err(AddrParseError(Ipv4))` (проверено `rustc`). `test-core-net4-differential.sh` покрывает только обычные/битые литералы, не ведущие нули. |
| `d2k_ip4_text` | 32–38 | `Ipv4Addr::Display` | **E** | `scripts/test-core-net4-differential.sh` сравнивает C `d2k_ip4_text` и Rust `Display` на валидных адресах. |
| `d2k_ip4_private` | 40–51 | `quic_replay.rs:23-46` `ipv4_is_local` | **E** | Differential покрывает 0/8? (C только `v==0`), 10/8, 127/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10 и public 8.8.8.8. Rust-диапазоны совпадают. |
| `d2k_ip6_private` | 53–64 | `quic_replay.rs:47-58` IPv6-ветка | **E** | Differential покрывает ::, ::1, fc00::, fe80::, ff02::, IPv4-mapped private/public, 2001:db8::1. |
| `looks_like_tls` (static) | 33–35 | `Trigger::accept` (`classify.rs:73-103`) | **P** | **Подтверждённое расхождение:** C выбирает accept по первому байту (`0x16` → ServerHello); Rust `Trigger::raw_hex` всегда `Accept::Any`, `tls/tls13` — ServerHello. Для raw-hex `0x16` Rust принимает любой непустой ответ, C — только ServerHello. C-дерево production-вызовов не имеет (только `test_verdict.c`). |
| `reverse_note` (static) | 53–62 | `classify.rs` reason-строки | **P** | C различает MODERN/LEGACY/UNKNOWN по `d2k_hello_shape`; Rust формирует оговорку по разобранной форме. Тексты не сравнивались побайтно. |
| `pause_note` (static) | 74–80 | `classify.rs` reason-строки | **P** | Формат «замерено без пауз/с паузой N мкс» перенесён; C-буфер 96 байт, Rust `String` без обрезки. |
| `stop_requested` (static) | 92–94 | `classify.rs` `stopped(options)` | **P** | Проверка atomic-флага отмены эквивалентна. |
| `classify_cancelled` (static) | 96–102 | `classify.rs` cancel-ветка | **P** | VERDICT=INCONCLUSIVE, marked=(mark!=0)&&all_marked, reason про снимок клиента — перенесено. |
| `d2k_classify_cancelable` | 104–334 | `classify.rs:1250-1900` | **P** | Дерево base→confirm→split1→control, CLEAR_CONFIRM_REPEATS=2, UNREACHABLE/FLAKY/CLEAR/PREFIX/OPAQUE/INCONCLUSIVE и AND-метка перенесены; тесты `classify.rs:2096-2444`. Отличия: R2O имеет ветку `neutral_ack` и режим `full_detect_semantics`; полного C/Rust differential дерева нет. |
| `d2k_classify` | 336–342 | `classify.rs` публичный `classify` | **P** | Обёртка с `stop=NULL`; эквивалентна. |
| `original_probe` (static) | 35–44 | `quic_replay.rs`/`r2o_quic_http3.rs` | **P** | Выбор SNI (`q->control` → NULL, иначе target_sni) и вызов wire-hook перенесены; отдельного differential нет. |
| `original_data` (static) | 47–50 | `quic_replay.rs` data-stage | **P** | Те же target_sni/path/port/wait/mark; построчно не сверялось. |
| `wire_measure` (static) | 52–78 | `quic_replay.rs`/`r2o_quic_http3.rs` | **P** | Копирование context, подмена probe/data, path и next/marked; C/Rust differential на все поля нет. |
| `d2k_quic_original_measure` | 80–83 | `quic_replay.rs` original arms | **P** | Обёртка над `wire_measure`; эквивалентна. |
| `d2k_quic_strategy_measure` | 88–91 | `quic_replay.rs` strategy arms | **P** | Обёртка над `wire_measure`; эквивалентна. |

## Углублённая сверка: CLI d2kfetch/d2kvoice/d2kask (34 функции)

| C-функция | строки | R2O-аналог | статус | доказательство / пробел |
|---|---:|---|---|---|
| `json_string` (static) | 41–62 | `r2o-fetch.rs` JSON-вывод | **P** | C вручную проверяет UTF-8, экранирует `"`/`\`, управляющие байты и невалидные последовательности как `\u00xx`; Rust формирует JSON через строковые шаблоны/serde. Побайтовое совпадение экранирования не проверено. |
| `vol_verdict_code` (static) | 64–72 | `r2o_volume`/`r2o-fetch` verdict | **P** | Коды `unreachable/cut/passed/short/unknown` перенесены; тексты и JSON-поля сверяются косвенно. |
| `usage` (static) | 74–102 | `r2o-fetch.rs:694-718` | **P** | Rust поддерживает `--name/--ip/--port/--path/--wire/--snapshot/--tls12/--deadline/--mark/--json/--version/--ladder/--quic`, добавляет `--control` и `--quic-budget`; текст помощи другой. |
| `resolve_first` (static) | 104–114 | `ToSocketAddrs`/`resolve` в `r2o-fetch.rs` | **P** | C берёт первый адрес `getaddrinfo`; Rust резолвит через std и фильтрует семейство. Порядок/выбор адреса может отличаться. |
| `snapshot_wire` (static) | 117–155 | `r2o-fetch.rs` snapshot-ветка | **P** | ARM_SHAPE(name,6), ожидание `EV_SHAPE` transport 6 и бюджет `wait_ms` перенесены; отдельного C/Rust differential на таймаут/чужое событие нет. |
| `main` | 157–356 | `crates/r2o-controller/src/bin/r2o-fetch.rs:11` | **P** | Флаги и режимы (ladder/quic/tls12/json/snapshot) есть; C `--snapshot` взводит ARM_SHAPE, Rust использует control-сокет. Коды выхода 0/1/2 и полный JSON-schema не сверялись. |
| `usage` (static) | 22–37 | `voice_measure.rs:100-135` | **P** | Rust разбирает `--addr/--control/--conntrack/--wait/--mark/--discovery`; `--list` обрабатывается отдельно в `main.rs:258`. Текст помощи другой. |
| `split_hostport` (static) | 39–48 | `voice_measure.rs:806-815` `SocketAddrV4` | **P** | C режет по последнему `:`, принимает только IPv4 через `d2k_ip4_parse`; Rust требует `IPv4:port`. Эквивалентно, но leading-zero IPv4 унаследует расхождение `net4`. |
| `verdict_word` (static) | 50–61 | `voice_measure.rs` verdict-тексты | **P** | Семь вердиктов CLEAR/BLOCKED/NO_UDP/NO_CALL/FLAKY/NO_ORACLE/UNMEASURED; тексты Rust отличаются. |
| `main` | 63–135 | `voice_measure.rs:95-135`, `main.rs:252-258` | **P** | `--list`, `--addr`, `--control`, `--conntrack`, `--wait`, `--mark`, `--discovery` есть; код выхода `CLEAR?0:1` и печать приёма не сверялись побайтно. |
| `need_value` (static) | 120–128 | `ask.rs:62-95` parser | **P** | Проверка «флаг без значения» есть; текст ошибки другой. |
| `parse_flag_u16` (static) | 134–149 | `ask.rs` `parse_port` | **P** | C: 1..65535, только base 10, отказ на `-`, хвост, ERANGE. Rust-парсер проверяет диапазон; точные тексты/ветви не сверялись. |
| `parse_flag_u32` (static) | 157–172 | `ask.rs` `parse_mark` | **P** | C: base 0, запрет `-`, ERANGE; Rust принимает `0x`/десятичное, диапазон u32. |
| `parse_flag_ms` (static) | 179–194 | `ask.rs` `parse_positive_ms` | **P** | C: положительное `long`, base 10; Rust `parse_positive_ms` — положительное; эквивалентно. |
| `parse_args` | 202–301 | `ask.rs:62-140` | **P** | Набор флагов и взаимоисключения (`--hello-hex`/`--arm-wait-ms`, `--control-hex`/`--control-sni`, `--control-sni` требует `--arm-wait-ms`) перенесены. R2O-парсер возвращает `Result`, тексты иных. |
| `hex_nibble` (static) | 315–320 | `ask.rs` hex-парсер | **P** | 0-9/a-f/A-F; эквивалентно. |
| `save_hex` (static) | 329–349 | `ask.rs` save snapshot | **P** | Формат `# комментарий` + hex по 32 байта; Rust сохраняет снимок, но точный формат/обработка ошибок записи не сверялись. |
| `read_hex_file` (static) | 361–414 | `ask.rs` hex reader | **P** | Комментарии `#`, пробелы, нечётное число цифр, пустой файл, cap 2048 — перенесены; точные тексты ошибок другие. |
| `wait_shape` (static) | 424–455 | `ask.rs` wait event | **P** | Бюджет по времени, пропуск чужих событий, отказ при `shape_len>cap` — перенесены; C/Rust differential на таймаут нет. |
| `pval_str` (static) | 462–468 | `ask.rs` `D2K_P_*` | **P** | «да/нет/не измерено»; тексты совпадают. |
| `print_header` (static) | 470–476 | `ask.rs` вывод | **P** | Печать цели/SNI/сокета/метки; формат Rust иной. |
| `print_snapshot` (static) | 482–502 | `ask.rs` вывод снимка | **P** | Печать длины, SNI и MODERN/LEGACY/UNKNOWN; формат Rust иной. |
| `pos_decided` (static) | 519–528 | `ask.rs`/`classify` props | **P** | Спецслучай checksum при `parses_l7=YES` перенесён; прямой unit есть, C/Rust diff нет. |
| `pos_value` (static) | 530–539 | `ask.rs` props | **P** | Отображение позиции в поле; эквивалентно. |
| `step_rc_str` (static) | 547–561 | `ask.rs` step rc | **P** | 10 кодов `D2K_STEP_*`; тексты Rust иные. |
| `ack_code_str` (static) | 565–573 | `ask.rs` ACK codes | **P** | OK/BAD_PLAN/BAD_ARGS/NO_ROOM; тексты иные. |
| `print_seen_types` (static) | 579–594 | `ask.rs` TLS record mask | **P** | Типы 20/21/22/23 и «ни одной»; формат иной. |
| `print_step` (static) | 597–624 | `ask.rs` step output | **P** | План/обмен/причина; формат Rust иной. |
| `print_question` (static) | 632–674 | `ask.rs` question output | **P** | Пять вопросов, «спрошен: нет/да», примечания checksum/parse; тексты Rust иные. |
| `all_unknown` (static) | 676–682 | `ask.rs` props vector | **P** | Все пять полей UNKNOWN; эквивалентно. |
| `print_not_asked_at_all` (static) | 684–696 | `ask.rs` output | **P** | Пять причин «не задан»; формат иной. |
| `print_vector` (static) | 698–705 | `ask.rs` output | **P** | Пять полей вектора; формат иной. |
| `print_plans` (static) | 707–725 | `ask.rs` plan output | **P** | До 8 планов, построчная печать; формат Rust иной. |
| `main` | 736–913 | `main.rs:315-332` `run_r2o_ask` | **P** | Последовательность parse→snapshot→props→compose→print перенесена; Rust-вывод и коды возврата (0/1/2) не сверялись побайтно. Отдельно: C `main` всегда возвращает 0 после успешного прогона, Rust возвращает код ошибки/успеха. |

## Углублённая сверка: plantlv.c (20 функций)

- **Декодеры и числовые хелперы:** `b64_value`, `parse_base64`, `hex_nib`,
  `parse_hex`, `anchor_by_name`, `split_fields`, `parse_uint`, `parse_int`,
  `kv_u32`, `str_u32` сверены с `plan_text.rs::base64_value/base64/hex_nibble/
  hex/anchor/number/kv_number`; правила паддинга base64, hex, шесть якорей,
  лимит 8 полей и запрет знака у `parse_uint` совпадают. `plan_free`
  заменён RAII (`Drop`/`Vec`).
- **`parse_text`:** набор директив, лимиты (payload/poison/split/fake 8,
  seqovl 4), проверки `payload-pad` (префикс не длиннее выхода),
  `payload-slice` (источник уже разобран), `oob` (ровно один байт),
  `fake` (`tlsmod` требует minexec≥8), `autottl/min-max` и финальные
  minexec-инварианты перенесены. **Нюанс:** C `sscanf("%d,%u-%u")`
  принимает хвостовой мусор (`autottl=1,2-12junk`), Rust строго отвергает.
  Это не дефект R2O: `scripts/fixtures/plantlv_stricter_cases.txt` и
  `test-controller-plantlv-differential.sh` фиксируют, что R2O строже
  ровно настолько, насколько строг `datapath/plan_parse.c` самого D2O;
  end-to-end исход (план не исполняется) совпадает, различается стадия
  отказа.
- **Сборщики TLV:** `put`, `put_u8`, `put_u16`, `put_u32`, `put_rec`,
  `d2k_plan_text_to_tlv`, `d2k_plan_text_to_hex` сверены с
  `plan_text.rs::push_u16/push_u32` и порядком записей: ID, PROTO,
  payload, poison+autottl, split, fake, seqovl, ORDER, PACE, INPUT,
  SETTLE, SEGMENT, INPUT_TLS, DELAY, WIRE, IPFRAG, UDPLEN, QSPLIT,
  QDENY, OOB, GUARD. `recOrder` пишется безусловно; `Plan::parse`
  повторно проверяет собранный TLV. `test-controller-plantlv-differential.sh`
  сравнивает C/Rust на двух фикстурах и отдельно проверяет stricter-случаи.
- **Вывод:** статусы E для 20 функций оставлены; единственное отличие —
  ранний отказ R2O на тексте, который C-компилятор пропускает, но
  `plan_parse.c` D2O всё равно отвергает.

## Углублённая сверка: link.c (43 функции)

- **Открытие/чтение кадра:** `d2k_link_open`, `d2k_link_close`,
  `d2k_link_peer_closed`, `wait_readable`, `read_exact`, `write_all`,
  `hex_nibble`, `hex_decode` сверены с `ControlClient`/`read_frame`/
  `write_frame`. `d2k_link_next` (300 строк) декодирует HELLO/HTTP/SUSPECT/
  STATS/EXCHANGE/CLIENT_TCP/SHAPE/ACK/APPLIED/PROTO/REFUSED; на него есть
  `d2o_control_differential.c` + `tests/control.rs` — статус E. Остальные
  хелперы P: C/Rust differential на ошибки connect/HUP нет.
- **Кодировщики name/area/addr:** `send_name_plan`, `send_area_key`,
  `d2k_link_set_name*`, `d2k_link_set_suffix/bypass`, `d2k_link_set_addr*`,
  `d2k_link_arm_shape*`, `d2k_link_del_*` собраны по тем же полям и порядку,
  что `control.rs::encode_*`; точные кадры валидных команд проверяются
  unit-тестами `tests/control.rs`, но C/Rust differential кодирования нет.
  Построчная сверка выявила систематическое отличие: **C-link почти не
  валидирует поля, которые проверяет Rust-кодировщик**. Отказ C переносится
  на датапат (`ctlsrv.c`), поэтому для валидных команд кадры совпадают, а
  для невалидных различается стадия и код ошибки.
- **Подтверждённые расхождения:**
  1. `SET_HTTPS`: C-link кодирует любой `u32 ttl` и оставляет обрезку
     датапату до **7 суток** (`d2k_ctl.h:231`); Rust `encode_set_https`
     отвергает `ttl > 6 часов`.
  2. `send_name_plan`: C не проверяет `shape` (`link.c:591` кодирует
     любой байт); Rust `encode_set_name` отвергает форму вне
     `{1,2,3,4,5,6,7} ∪ {8..13}`. C также не проверяет совместимость
     плана с формой, Rust проверяет `valid_name_probe_plan_records`.
  3. `SET_NAME_BOUND`: C требует только `token != NULL`; Rust
     `encode_set_name_bound` требует `shape == SHAPE_HTTP` и ненулевой
     trial_id (`control.rs:1399-1406`).
  4. `SET_SUFFIX`: C `send_name_plan` не проверяет план; Rust
     `encode_set_suffix` требует shape/family и
     `valid_domain_plan_records` (transport/proto плана).
  5. `addr_shape_ok`: C принимает контекстные TCP-формы **8–13**
     (`d2k_link.h:311-328`); Rust `valid_addr_shape` — только
     `{1,2,3,5,6}`. `SET_ADDR`/`DEL_ADDR` 8–13 C кодирует, Rust нет.
  6. `addr_probe_flow_bytes`: C допускает `src_port_be=0` для голосового
     опыта «на любой клиентский порт» (`link.c:855`); Rust
     `udp_addr_probe_flow` требует `source.port()!=0`.
  7. `DEL_NAME`: C принимает любую пару `transport`+`shape!=0`; Rust
     `encode_delete_name` требует конкретные пары (6 с 1/2/4/6/7/8–13,
     17 с 3/5).
  8. `DEL_NAME_PROBE`: C не проверяет `shape`; Rust требует
     `valid_tcp_probe_shape` и отвергает неизвестную форму раньше.
  9. `ARM_SHAPE`: кодировщики совпадают (transport 6/17), но датапат R2O
     `arm_client_shape` принимает только 6, тогда как C `ctlsrv.c:329` — 6/17.
- `d2k_ev_outer_appdata`: бит 23 (`application data`) в `seen_types`;
  перенесён в `control::decode_*`, отдельного differential нет.

## Углублённая сверка: diagnostics.c (41 функция)

- **Ёмкости колец совпадают:** C `EVENTS=64`, `LIMIT_EVENTS=32`, `SAMPLES=120`,
  `MEMORY_HISTORY=1440`, `ANOMALIES=8`, `GROWTH_POINTS=10`, `PROCESS_COUNT=3`;
  Rust `EVENT_CAPACITY=64`, `LIMIT_CAPACITY=32`, `SAMPLE_CAPACITY=120`,
  `MEMORY_HISTORY_CAPACITY=1440`, `ANOMALY_CAPACITY=8`, `GROWTH_CAPACITY=10`,
  `D2O_PROCESS_CAPACITY=3`. `MADVISE_ERRNO_SLOTS=4` и
  `MEMORY_SITE_COUNT=6` тоже совпадают.
- **`copy`/`js`:** C `copy` режет до `cap-1` и отступает на continuation-
  байт UTF-8, `js` сам валидирует UTF-8 (overlong/surrogate/>0x10ffff) и
  печатает `\ufffd`; Rust `truncate_utf8`/`d2o_event_text` работают с уже
  валидными `String`, control→`?`, NUL обрезается. Для валидных строк
  эквивалентно; невалидные байты Rust не получает. P*.
- **`read_proc`/`read_detail`/`d2k_diag_sample`:** C требует точного
  `comm == names[i]` (`d2kc`/`d2kd`/`d2kpanel`) и одного pid-файла; Rust
  принимает префикс comm (усечение до 15 байт) и fallback
  `*-controller4.pid` и т.п. Поля status, `stat` starttime, fd_count,
  `smaps_rollup` и 60-секундный интервал совпадают; unit
  `process_memory_follows_pidfiles_and_restarts`,
  `first_process_detail_survives_process_exit`,
  `d2o_periodic_rss_sample_matches_c`.
  **Подтверждённые расхождения истории памяти:** C пишет фактические
  `rollup_status/errno/rollup[5]`, Rust — `0/null/null`; C даёт `null`
  для недоступных RSS/VmData/VmSwap/RssAnon, Rust — `0` (`unwrap_or(0)`).
  P.
- **`d2k_diag_write`:** C вручную пишет `report.json` schema=1 с лимитом
  448 КиБ; Rust сериализует `Recorder::write_report` через serde_json с тем
  же `REPORT_MAX`. **Отличия:** C пишет `http_storage_limits` только при
  `ns>0`, Rust — всегда; C выводит `reason_source` из `protocol=="http"`,
  Rust берёт его из события. `r2o-diagnostics-differential.sh` сравнивает
  `ring_bytes/event/snapshots/http_records`; остальные поля — unit, не
  C-oracle. P.
- **`d2k_diag_record`/`record_limit`/`record_anomaly`/`write_anomalies`:**
  кольца и счётчики `event_total/limit_total/anomaly_total/write_failures`
  перенесены; `record_anomaly` пишет kind/code/rss_delta/accounted_delta/
  stage в кольцо 8. **Подтверждённое расхождение:** предел `reason` —
  255 байт в C (`reason[256]`) и **1024** в Rust (`diagnostics.rs:768`);
  остальные пределы совпадают. P, отдельного C/Rust differential на
  переполнение колец нет.

## Углублённая сверка: catalog.c (60 функций)

- **JSON-парсер:** `jpeek`, `jeat`, `jeat_null_if_present`, `jparse_raw_int`,
  `jparse_i32/u8/u16`, `jparse_bool_i`, `jparse_string_dyn/fixed`,
  `jparse_rfc3339`, `jskip_value`, `parse_object`, `parse_array`, `grow`,
  `read_fixed_digits`, `eat_lit`, `floor_div`, `days_from_civil`,
  `civil_from_days` заменены `serde_json` + `CatalogInput` + `validate`.
  Неизвестные ключи C пропускает через `jskip_value`, serde — через
  отсутствие `deny_unknown_fields`; null→пусто через `null_to_default`;
  глубина/размеры ограничены (`MAX_CATALOG_BYTES`, `check_json_depth`).
  `format_rfc3339` — E (persist differential).
- **`handle_signal_key`/`parse_signal`/`handle_fp_key`/`parse_fp`:**
  kind/ttl/ttl_delta/tos/ipid/volume/seen/packets и method/signals
  перенесены; лимит 8 сигналов проверяется в `validate`.
- **`handle_plan_key`/`parse_plan`/`elem_plan`:**
  id/proto/text/added/successes/enabled перенесены; `Plan` serde.
- **`handle_binding_key`/`parse_binding`/`elem_binding`:**
  kind/target/plan_id/level/confirmed/successes/enabled/transport/family/
  shape/verified_by/input/probe_path/ech_origin/recheck_since/budget
  перенесены. **Два пробела:** (1) C хранит и проверяет `tcp_profile`
  (0/1/2), в Rust `Binding` этого поля нет — значение теряется при
  load/save; (2) C по умолчанию ставит `family=4`, Rust `Binding::default`
  даёт 0, `serialize_family` пишет 0 как 4 только при сохранении, `validate`
  family не нормализует. Старый каталог без `family` загрузится с 0.
- **`handle_box_key`/`parse_box`/`elem_box`/`d2k_cat_shape_fits`:**
  boxes/fingerprint/plans/bindings перенесены (`BoxRecord` serde);
  **`d2k_cat_shape_fits` — подтверждённое расхождение:** C принимает
  только `stored==0 || got==0 || stored==got`, Rust `group_shape_fits`
  дополнительно принимает `saved==MODERN && observed==ECH_TCP`
  (`live.rs:284`, `main.rs:3023`).
- **`handle_domain_observation`/`parse_domain_observations`/
  `handle_net_whitelist_key`/`handle_catalog_key`/`parse_catalog_obj`:**
  domain_state/observations до 256, network_whitelist и top-level
  frozen/disabled/disabled_at перенесены (`catalog.rs`/`groups.rs`);
  unit `derived_domain_groups_are_ignored`.
  **`prune_unavailable_domain_groups` — подтверждённое расхождение:**
  C после restore удаляет группы без enabled-плана в каталоге; Rust
  `restore`/`rebuild` не видят `boxes` и такого prune не делают.
- **`read_whole_file`/`d2k_catalog_load`:** загрузка, schema=1, запрет
  мусора после объекта — E (`r2o-catalog-persist-differential.sh`,
  `tests/catalog.rs`).
- **`write_json_string`/`wr_indent`/`write_json_array`/`write_signal_elem`/
  `write_fp`/`write_plan_elem`/`write_binding_elem`/`write_box_elem`/
  `write_domain_key`/`write_domain_observation`/`write_domain_group`/
  `d2k_catalog_save`:** serde_json pretty с теми же полями; `packets`
  только при nonzero, `family` 0→4. Полный побайтовый формат save не
  сравнивался, persist differential проверяет save_atomic — P.
- **`d2k_catalog_save_atomic`:** `.new` + rename + fsync каталога — E
  (persist differential, включая конкурентное обновление).
- **`d2k_catalog_memory_bytes`/`free_box`/`d2k_catalog_free`:**
  освобождение — RAII; **`catalog_bytes` — расхождение метрики:** C
  считает in-memory размер структур + `strlen(text)+1`, Rust — длину
  `to_json_at()` (сериализованный JSON, `main.rs:16768`). Числа
  систематически разные; C/Rust differential на объём нет. P.

## Углублённая сверка: compose.c (53 функции)

- **Белый список и TLV-билдеры:** `d2k_net_whitelist_count/name`,
  `wr16be`, `rd16be`, `wr32be`, `tlv_rec`, `tlv_header`, `to_hex` сверены с
  `r2o_rx_volume`/`plan_text`; список 266 имён и порядок покрыты unit
  `r2o_rx_volume`, TLV-билдеры используются в C-тестах и прямого
  C/Rust differential не имеют (P/P*).
- **`plan_tlv_stamp_ident`:** C считает FNV-1a по байтам TLV с нулевым
  `REC_ID` и вписывает `plan-%08x` (12 байт + NUL) в запись ID. Rust
  `discovery.rs:1450 plan_text_for_trial` подставляет в текст переданный
  вызывающим 16-байтный trial-id; функции, повторяющей FNV-1a-штамп именно
  в TLV, нет. Это реальное различие идентичности плана/атрибуции APPLIED:
  статус P, нужен differential `plan_tlv_stamp_ident` ↔ R2O trial-id.
- **Сборка TLV-планов:** `overlap_plan_tlv`, `reorder_plan_tlv`,
  `badsum_fake_plan_tlv`, `checksum_plan_tlv` — только C-тестовые билдеры;
  Rust собирает текст и компилирует `plan_text::compile_text`. Прямого
  TLV-differential нет, статус P.
- **События/contact:** `ev_matches_flow`, `wait_for_event3`,
  `wait_for_event` — C-цикл по времени с фильтром типа/кода/ключа; Rust
  `wait_for_ask_proof(trial_id, plan_id, expected_key)` и
  `BoundTcpProbe`. `props_bind_any` ↔ `BoundTcpProbe::open`:
  socket/bind/getsockname и отказ при нулевом порту совпадают, но Rust
  **не ставит `IPV6_V6ONLY`** и не имеет ветви `out_fd==NULL`.
  `tcp_timestamps_write` и `connect_with_tcp_profile` — **N**: Rust
  нигде не пишет `/proc/sys/net/ipv4/tcp_timestamps`; `tcp_timestamps_read`
  используется только для `host_offers_ts` (`raw_probe.rs:676`), не для
  connect-профиля. `d2k_props_contact_on_family_tcp_profile` переносит
  socket/TCP_NODELAY/таймауты/неблокирующий connect/getsockname/send, но
  без параметра `tcp_timestamps`, кода -3 и восстановления sysctl; P.
- **Вопросы свойств:** `build_fake_body` — E (те же `2*truth` байт
  `0f`/decoy). `d2k_props_question_plan` — P: порядок и эффекты 5
  вопросов совпадают (overlap `0f`+seqovl, reorder split+reverse+pace,
  checksum `0f`×2n, protocol decoy+2n, duplicates 0f×2n+2/20 мс), но C
  собирает TLV и считает FNV-1a id, Rust — текст `r2o-plan` с payload 2
  у overlap и случайным `plan_id`. `d2k_props_question_passed` — E.
  `question_retire`/`step_rc` — P (кадр тот же, трасса и обработка
  ошибки снятия иные). `d2k_props_ask_traced` — P: C требует
  `applied && server_hello`, Rust — `applied && exchange_seen &&
  server_hello`; C не сверяет trial_id ACK, Rust отвергает чужой;
  C игнорирует ошибку снятия плана, Rust может прервать опрос.
- **Текстовые планы и fallback:** `append_fmt`, `emit_header*`,
  `append_hex`, `overlap_plan_text`, `reorder_plan_text`,
  `badsum_fake_plan_text`, `checksum_plan_text`, `build_decoy_hello`,
  `parse_protocol_plan_text`, `duplicates_plan_text`, `body_room`,
  `everything_plan_text`, `d2k_fallback_arms`, `fb_arm_at`,
  `d2k_fallback_plan`, `d2k_compose` — E по `d2o_compose_differential.c`,
  `r2o-fallback-differential.sh` и unit `fallback_plans_match_donor`.
  `d2k_arm_plan` (200 строк) — P: `r2o_fallback::arm_plan`/`classify_measured`
  покрывают 50 arm и 5 `send_cap`, но произвольные сочетания
  disorder/oob/seqovl/fake/ttl/tcpts/ipidzero не сравнивались.

## Углублённая сверка: d2kc.c (28 функций)

- **Сигналы/время/сохранение:** `on_signal`, `now_ms` — P* (atomic/Instant);
  `save_atomic` — E (`r2o-catalog-persist-differential.sh`).
- **Память/журнал:** `self_mem` читает `/proc/self/status` (RSS/HWM/VmData/
  Threads); Rust `diagnostics::process_memory` читает те же поля, но набор
  точек и формат различаются, C/Rust differential нет — P. `sched_say`/`hs_say`
  — P* (лог-колбэки).
- **HTTP-поиск:** `http_search_portal`/`http_portal` ↔
  `r2o_http_search_https_action` + `encode_set_https`; C различает
  rc 0/1/2 (портал/лог/SET_HTTPS), Rust — `Queue/Suppress/Wait`.
  `hs_open_port` ↔ `BoundTcpProbe::open`: C ставит `SO_MARK` только
  при `g_probe_mark!=0`, Rust — `unwrap_or(0x2d)` и nonblock+CLOEXEC.
  `hs_set_probe`/`hs_del_probe`/`hs_set_plan` кодируют те же кадры;
  C жёстко `SHAPE_HTTP`, Rust передаёт `wire_shape`.
  **`hs_del_plan` — подтверждённое расхождение:** C проверяет
  `binding->family == family`, Rust `encode_delete_name_bound(host,6,
  binding)` — нет. **`hs_changed` — подтверждённое расхождение:**
  C пишет отдельный `http-plans.txt` формата `d2k-http-plans 1`;
  в Rust grep `http-plans` пуст, кандидаты живут в JSON-каталоге.
  `hs_start`/`hs_hex`/`hs_close_port` — P.
- **HTTP-портал/HTTPS:** `http_push` ↔ `encode_set_https` (TTL уже
  расходится, header п. 1), `http_save` ↔ `save_cache`,
  `http_probe_done` ↔ drain+save. **Счётчик `d2k_httpsprobe_lost` в
  Rust отсутствует** (core-net, N), поэтому лог потерь не перенесён.
  `poison_cmp` — E/P* (qsort vs stable `Reverse`).
  **`hs_measured_poisons`:** C берёт до 8 спеков на план и 64 всего,
  сортирует по successes и передаёт сырой spec; Rust
  `measured_http_candidate_keys` извлекает poison-ids, маппит в
  `fake-badsum`/`fake-seqshift`/`fake:{spec}`, дедуплицирует, cap 8.
  P — форматы/лимиты разные.
- **CLI/самопроверка:** `usage` — P: `--serve` позиционный и не имеет
  `--measure-mark`, `--log`, `--health-file`, `--https-cache=`,
  `--release-id`; `offline_self_check` — P: `--self-check` в
  `r2o-controller` отсутствует, SHA-256(abc) покрыт только
  crypto-дифференциалом.
- **Диагностика:** `diagnostic_event/limit` ↔ `Recorder::record/
  record_limit`; `diagnostic_tick` ↔ `Recorder::tick/write_report`
  (1 с/60 с, tmp+rename), unit `diagnostic_tick_lifecycle_matches_d2o`;
  C/Rust differential сравнивает только часть JSON. P.
- **`main` (462 строки):** P. Каталог, greeting, link, sched,
  https/httpsearch, hooks, poll, sync, save/live/report, health,
  graceful stop и exit 1 перенесены в `serve_catalog`; полного
  CLI-паритета нет, `--serve` имеет другую форму.

## Углублённая сверка: sched.c (282 функции)

- **Карта состояний:** C `T_ASKING → T_PROPS_* → T_PLANNING →
  T_TRIAL_SETTLE → T_VERIFY* → T_WATCHING`, очередь, cooldown, dead-address,
  ECH-лестница и voice перенесены в `R2oDiscoverySearches`/
  `R2oDiscoveryQueue`/`R2oDiscoveryCooldownRing`/`R2oDeadAddressCache`/
  `R2oDiscoveryWorkerLife` (`main.rs:7971-9300`), `discovery.rs` и
  `voice_*`. Основные ветви покрыты `r2o-scheduler-differential.sh`,
  `r2o-scheduler-cooldown/dead-address/concurrent-endpoint`,
  `r2o-queue-order/coalesce`, `r2o-own-first`, `r2o-ech-rx-ladder`,
  `r2o-resource-limit`, `r2o-discord-*`; полной матрицы всех переходов и
  редких комбинаций (ECH+volume, addr+voice, QUIC deny recheck) нет.
- **`refuse_is_permanent` (301–309):** C считает постоянными `TOO_LONG`,
  `NOT_APPLIED`, `FLOW_UNIT` и использует это в 4487/9901/10113. Rust
  разложил это на `main.rs:19091-19095` (`TOO_LONG|NOT_APPLIED →
  record_client_unfit`) и отдельную ветку `FLOW_UNFIT → каталог/повторный
  замер` (`19097-19170`). Семантика постоянства сохранена, но единой
  функции/таблицы нет — P.
- **`refuse_is_damage` (320–322):** C `DAMAGED` используется при объяснении
  недосланного (`4522`), чтобы в журнале было «поток повреждён», а не
  «посылка не ушла». В Rust `flow_journal.rs` есть
  `R2O_JOURNAL_REFUSE_DAMAGED`/`PlanDamaged`/текст, но в главном цикле
  контроллера (`main.rs:19086-19175`) отдельной ветки `DAMAGED` нет — код
  только печатается. Статус P, нужна проверка журнальной ветки.
- **`verdict_to_plans` (5209–5551, 343 строки):** C собирает ECH trial,
  QUIC arm, known plans, measured arm, RX-лестницу, split, fallback и
  compose. Rust не имеет одной функции: это `discovery.rs::known_plans/
  own_first_plans`, `main.rs::r2o_discovery_volume_known_plans`,
  `r2o_fallback` и `compose_d2o`; differentials покрывают known/own-first/
  fallback/QUIC, но не все комбинации. P.
- **`on_suspect` (8181–8592):** E — `r2o-scheduler-differential.sh`,
  cooldown/dead-address/queue-order/coalesce, `ControlClient::
  r2o_queue_tcp_suspect` (`main.rs:20090`) + `R2oDiscoveryQueue::
  queue_after_fresh_suspect` (`13534`).
- **`verify_confirm` (9262–9653):** P — ECH/QUIC/форма/budget,
  `bind_confirmed`, группа, адресный план, сеть, live/report, T_WATCHING
  перенесены в `r2o_confirm_discovery_outcome` (`main.rs:5347`) +
  `apply_discovery_outcome` (`21856`); ack-applied/budget/ECH differentials
  покрывают часть, крупная функция целиком не сверена.
- **`worker_run_body` (2741–3253, 513 строк):** P — VOICE/VERIFY/CONTACT/
  addr-recheck/ECH/baseline/volume/classify и фиксация результата;
  ветви покрыты differentials, но не все комбинации ECH/volume/addr.
- **`d2k_sched_tick` (10784–12364, 1581 строка):** P — clock, ресурсы,
  wake, QUIC yield/deny, группы, sync, все состояния задач, очередь, voice,
  диагностика. `R2oDiscoverySearches`/`ControlClient`/`r2o_resource_limit`
  покрывают основные ветви; полная матрица состояний не доказана.
- **Остальные 274 функции:** статические хелперы (CPU/meminfo/conntrack,
  cooldown/dead, fingerprint, task slots, worker args, plan ident/stamp,
  close/reset) наследуют статус владельца; E/P выставлены по наличию
  differential/unit, без полного C/Rust построчного diff.

## Углублённая сверка: crypto.c / p256.c / x25519.c (61 функция)

- **AES-128/ECB:** `xtime`, `d2k_aes_sbox_byte`, `aes128_key_expand`,
  `sub_bytes`, `shift_rows`, `mix_columns`, `add_round_key`,
  `aes128_encrypt_block`, `d2k_aes128_ecb` заменены crate `aes`/`Aes128`;
  `scripts/test-core-crypto-differential.sh` сравнивает FIPS-197 вектор
  `aes128-ecb`. `d2k_aes128_ecb` production-используется для QUIC header
  protection (`quicwire.c:388,404`), R2O — `quic.rs`/quinn; E.
- **SHA-256/HMAC/HKDF:** `rotr32`, `sha256_compress/init/update/final`,
  `d2k_sha256`, `d2k_hmac_sha256`, `d2k_hkdf_extract` покрыты
  `sha2`/`hmac`/`hkdf` и differential-кейсами `sha256-abc`, `sha256-100`,
  `hmac-*`, `hkdf-extract`, `hkdf-client-in`, `hkdf-quic-key` — E.
  `d2k_hkdf_expand_label`/`_ctx` — P: границы `label>249`/`ctx>32` в
  Rust-обёртке не сравнивались.
- **AES-128-GCM:** `gf128_h_table`, `gf128_mul_fast`, `ghash`,
  `d2k_ghash_for_test`, `inc32`, `gctr`, `consttime_eq16`,
  `d2k_aes128_gcm_encrypt/decrypt` заменены `aes-gcm`; differential
  сравнивает `gcm-ciphertext`, `gcm-tag`, `gcm-opened`, `gcm-bad-tag` — E.
- **P-256:** `fe_*`, `pt_*`, `scalar_ok` — статические хелперы, своей
  арифметики в R2O нет (P*). **`d2k_p256_public`/`keypair`/`ecdh`
  production-используются:** `core/tls12.c:650-655` вызывает
  `d2k_p256_keypair`/`d2k_p256_ecdh` для ECDHE secp256r1. R2O делегирует
  `ring`; прямых C/Rust-векторов P-256, проверки точки не на кривой и
  retry-политики 16 попыток нет — P. Это не N.
- **X25519:** `car25519`, `sel25519`, `pack25519`, `unpack25519`, `A`,
  `Z`, `M`, `S`, `inv25519` — статические хелперы (P*);
  `d2k_x25519`/`d2k_x25519_base` production-используются в QUIC
  (`quicconn.c:851,1159`, `quichello.c:247`), TLS 1.2/1.3
  (`tls12.c:650`, `tls13.c:279,395`) и ECH/HPKE. R2O — `x25519-dalek`/
  `ring`/`hpke`; ECH/QUIC differentials косвенные, прямых C-векторов
  X25519 нет — P.
- **Вывод:** 26 AES/SHA/HMAC/HKDF/GCM функций — E (кроме двух
  HKDF-границ P), 22 P-256 и 11 X25519 — P; N в блоке нет.

## Карта состояний sched.c → Rust

C-машина состояний: `task_state` (`sched.c:596-635`), 15 значений. R2O не имеет
единого enum: состояние выражено очередью, фазой диагностики (`phase:
&'static str`), задачами воркера, каталогом и голосовыми контекстами.

| C-состояние | вход C | что означает | Rust-эквивалент | статус/пробел |
|---|---|---|---|---|
| `T_FREE` | `sched.c:597` | слот свободен | нет записи в `R2oDiscoverySearches.entries`/`task_slots` | P*: явного слота нет, память освобождает `HashMap` |
| `T_QUEUED` | `sched.c:8053` | подозрение сохранено, ждёт безопасного слота; поля `queued_ms/queued_event/hot_event/hot_count` (`:663-673`) | `R2oDiscoveryQueue` (`main.rs:7883`): `enqueue_with_planned` (`:9004`), `promote_with_planned` (`:9085`), `pop_with_tcp_preference_and_planned` (`:9155-9180`, ключ `(Reverse(hot_event), queued_event)`), `r2o_expire` (`:9060`) | P: порядок «горячие→FIFO» и TTL совпадают; C отдельно считает безопасный слот по `measurements_in_flight`, R2O — через `R2O_DISCOVERY_TASK_CAPACITY` и permit-гейт |
| `T_ASKING` | `sched.c:7287,7311` | сетевой оракул в потоке | `R2oDiscoverySearches::set_asking` (`main.rs:8112`), `searches.asking.contains` (`:9424`), фаза «распознаём поведение» | E/P: classifier differentials; отдельного состояния нет |
| `T_SHAPE_WAIT` | `sched.c:7157` | QUIC: снимок заказан, ждём `EV_SHAPE`; событие — `:8994-9008` | `R2oPendingQuicDiscovery` + `r2o_take_ready_quic_discovery` (`main.rs:9182-9216`), `queued_quic_snapshots` (`:12753`) | P: отдельного состояния нет; ожидание выражено очередью+permit, `T_SHAPE_WAIT` существует только для QUIC |
| `T_PROPS_CONTACT` | `sched.c:3962`, тик `:11530-11562` | план-вопрос отправлен, обращение к цели в потоке | `main.rs` discovery → `raw_probe::sweep_poisons`; control-путь `question_plan` только CLI (`main.rs:469`) | **P с пробелом:** C задаёт 5 вопросов через управляющий сокет при `OPAQUE && TCP && !have_arm && !owns_search` (`:11462-11474`, `:12182-12200`); R2O discovery делает только raw-пробы, control-опрос в production отсутствует |
| `T_PROPS_WAIT` | `sched.c:11562` | обращение состоялось, ждём обмен по своему потоку | обработчик `sched.c:10260-10300`; в Rust — `wait_for_ask_proof` (`main.rs:20194`), но только в CLI `--ask` | **P:** в discovery нет ожидания APPLIED на потоке вопроса; критерий «ServerHello + APPLIED» из C не воспроизведён в control-слое |
| `T_PLANNING` | `sched.c:4465,4503,9150,11526` | вектор собран, ставим планы | генерация кандидатов `main.rs:10892-11900` (`known_plans/own_first/compose`) | P: набор источников совпадает, единой `verdict_to_plans` нет |
| `T_TRIAL_SETTLE` | `sched.c:12345` | план записан, ждём принятия датапатом; предел `SCHED_TRIAL_SETTLE_MS=50` | `exchange_candidate_probe_with_settle` (`main.rs:22209`), `D2O_TRIAL_SETTLE_MS=50` (`:141`) | E/P: тест `d2o_missing_candidate_ack_expires_after_settle_window` |
| `T_VERIFY` | `sched.c:4534,12050` | кандидат стоит, зонд в потоке | `r2o_run_discovery_candidate_trial_with_retries` (`main.rs:5785`) | P: retry/bare-retry/arm-retry перенесены, полного differential нет |
| `T_VERIFY_WAIT` | `sched.c:11805,11975` | зонд вернулся, ждём APPLIED его потока; предел `SCHED_VERIFY_STEP_MS=5000` | сбор APPLIED `r2o_collect_controller_applied_events_until` (`main.rs:5661`), сверка `r2o_family_applied_flow_matches` (`:5705`), `wait_for_ask_proof` (`:20194`) | P: APPLIED сверяется по plan/trial/key, но отдельного состояния/таймаута 5 с нет |
| `T_WATCHING` | `sched.c:8144,9621` | подтверждено, смотрим живой трафик | привязка каталога + live-группы (`r2o_confirm_discovery_outcome`, `main.rs:5347`) | P: подтверждение/привязка есть, наблюдение живой цели — через `live.rs` |
| `T_RESTING` | `sched.c:4025` | неудача, цель отдыхает | `R2oDiscoveryCooldownRing` (`main.rs:8509`), `R2oDeadAddressCache` (`:8312`), `r2o_record_discovery_cooldown` (`:12608`) | E/P: cooldown differentials |
| `T_VOICE_MEASURE` | `sched.c:7502` | C voice/STUN замер в воркере | `R2oVoiceLatestQueue` (`main.rs:9552`), `r2o_measure_voice_for_flow`; правило «другие endpoint'ы отбрасываются» — `:9556` | P: очередь/дедуп/срок совпадают, C/Rust differential замера частичный |
| `T_VOICE_TRIAL` | `sched.c:7603` | временный arm на конкретной пятёрке, lease | `R2oVoiceTrialContext` (`main.rs:9735`), `install_r2o_voice_trial` (`:16264`), продление `:16318-16327` | P: lease/продление/снятие перенесены, точные коды NAK/истечения — unit |
| `T_VOICE_WATCH` | `sched.c:9784` | приём применился к разговору, ждём ответа/молчания | `r2o_take_silent_voice_trial` (`main.rs:10192`), `R2O_VOICE_PENDING_GRACE=120с` (`:9667`) | P: тишина/истечение есть, полного differential нет |

**Итог по карте:** переходы C в основном воспроизведены, но не одним автоматом:
`T_QUEUED/T_SHAPE_WAIT` → очередь и permit-гейт, `T_PROPS_*` → raw-пробы
(control-путь только в CLI), `T_PLANNING` → генераторы кандидатов,
`T_TRIAL_SETTLE/T_VERIFY*` → `exchange_candidate_probe_with_settle` +
сбор APPLIED, `T_RESTING` → cooldown-ring/dead-address, `T_VOICE_*` →
голосовые контексты. Полной матрицы «состояние × событие × таймаут» нет —
статус P для `d2k_sched_tick` остаётся обоснованным.

## Углублённая сверка: core/include/d2k_resource.h (6)

- **`d2k_resource_word`/`d2k_resource_space`:** сравнение слова без
  регистра и набор пробельных символов (` `, `\t`, `\r`, `\n`,
  `\x0c`) совпадают с `r2o_resource_word`/`r2o_resource_space`
  (`r2o_resource.rs:407-417`) построчно.
- **`d2k_resource_path_ok`:** непустой путь, `<512`, начинается с
  `/`, не `//`, без `/../` и `/./`, только
  `[A-Za-z0-9/._-]`, оканчивается `.css` — всё то же в
  `r2o_resource_path_ok`/`path_bytes_ok` (`:309-330`). Rust
  использует `windows(4)`/`windows(3)` вместо `strstr`; для
  корректных входов эквивалентно.
- **`d2k_resource_add`:** принимает только `https://` и `//`,
  путь проверяется `path_ok`, хост непустой `<256`, без ведущей и
  хвостовой точки, только LDH и `.`, lower-case, один ресурс на
  хост, максимум `D2K_RESOURCE_COUNT=2`. Rust
  `r2o_add_url`/`r2o_add_url_bytes` (`:255-305`) делает то же;
  дополнительно `feed` останавливается при достижении 2 ресурсов.
- **`d2k_resource_tag`:** raw-режимы `script`/`style`,
  `body → seen=32768`, `link` с одним `href` и одним
  `rel=stylesheet`, href `<1024`, отказ при незакрытой кавычке.
  Rust `r2o_finish_tag` + `r2o_link_stylesheet_href`
  (`:188-236,332-405`) повторяет это построчно.
- **`d2k_resource_feed`:** лимит 32768 байт, сбор URL по байту `h`,
  теги/комментарии/кавычки, `>` завершает тег; Rust
  `R2oResourceScan::feed` (`:140-186`) совпадает, плюс ранняя
  остановка по 2 ресурсам.
- **Ограничение:** тесты `r2o_resource.rs:594-662` покрывают
  `R2oResourceMemory` (кэш/пути/вытеснение), а не сам сканер;
  отдельного C/Rust differential сканера нет. Поэтому статусы
  P/P*, а не E, несмотря на построчное совпадение.

## Углублённая сверка sched.c: verify_confirm

C-функция `verify_confirm` (`sched.c:9262-9653`) — 392 строки и 16 гейтов.
Rust-подтверждение разложено на `r2o_family_recovery_decision` (`main.rs:5321`),
`r2o_confirm_discovery_outcome` (`:5347`), `apply_discovery_outcome`
(`:21856`), `r2o_install_quic_candidate` (`:21518`), ECH-replay (`:15322`),
volume-recovery (`:14628`) и каталог.

| C-гейт | строки | Rust | статус/пробел |
|---|---:|---|---|
| volume ladder budget | 9268–9285 | `r2o_discovery_volume_recovery` (`:14628`), `r2o_discovery_volume_ladder_decision` (`:3282`) | P: разные слои, полного differential нет |
| bound plan без PASSED-бюджета | 9286–9298 | прямого аналога не найдено | **подтверждённый пробел:** grep `bound_plan_id` по `crates/` пуст; C-гейт `own_first==2 && bound_plan_id==plan_id && budget!=PASSED → T_PLANNING` в Rust не найден. |
| QUIC ECH replay | 9299–9304 | `r2o_discovery_ech_replay_required` (`:15322`), `r2o_quic_data_proof_confirmed` | P: replay/APPLIED есть, уровня HANDSHAKE как отдельного условия нет |
| ECH accepted/name_ok/application | 9305–9318 | `r2o_family_recovery_decision` (`:5321-5341`) | P: `ech_accepted`/`peer_name_ok`/`complete`/`application_verified`; C-ветка `ech_replay` выражена иначе |
| name_ok=0 — только диагностика | 9330–9334 | не блокирует для не-ECH (`ech_accepted=None`) | эквивалентно |
| QUIC split unfit | 9335–9345 | `split_applicable`/`valid_quic_plan` при генерации кандидатов | P |
| `unfit_here` по plan_id | 9346–9365 | `r2o_catalog_mark_flow_unfit` (`main.rs:2951`, вызов `:19113`) | **подтверждённый пробел:** функция маркировки есть и вызывается после FLOW_UNFIT, но pre-confirm проверки `t->unfit_plan_id`/`ver_plan_id` в `r2o_confirm_discovery_outcome`/`apply_discovery_outcome` нет. Кандидат может подтвердиться, хотя тот же план уже не подошёл клиенту. |
| bind_confirmed: shape/input/verified_by/probe_path/tcp_profile | 9366–9427 | `add_measured_binding_with_fingerprint_in_box`, `add_confirmed_quic_address_binding` | P: `tcp_profile` в `Binding` отсутствует; `probe_path` для QUIC есть |
| group_record BLOCKED_CONFIRMED | 9431–9432 | `groups.rs`/каталог | P: прямого вызова из `apply_discovery_outcome` не найдено |
| budget mark PASSED/UNCHECKED/CUT | 9449–9474 | `Binding.budget` (`catalog.rs:195`), merge (`:931`), константы `R2O_D2K_CAT_BUDGET_*` (`main.rs:2440-2442`) | **подтверждённый пробел:** поле и merge есть, но production-присваивания `binding.budget` из подтверждения не найдено (grep `.budget =` — только тесты `main.rs:25821/25826`). C выставляет PASSED/UNCHECKED/CUT в `verify_confirm`. |
| measure_path | 9475–9488 | `probe_path` для QUIC; для name-binding не найден | P |
| by_addr permanent plan | 9489–9506 | `r2o_install_quic_candidate`/`add_confirmed_quic_address_binding` для QUIC/ECH | P: общий адресный путь не найден |
| net whitelist tx_only/searched | 9514–9536 | `r2o_discovery_record_network_whitelist` (`:2269`) | P |
| T_WATCHING | 9621 | live-группы/`live.rs`; фазы «смотрим живой трафик» нет | P |
| yield других T_ASKING | 9622–9636 | `yield_to_own_plan` в Rust не найден | **подтверждённый пробел:** grep `yield_to_own_plan`/`yield.*own` по `crates/` пуст; C прерывает чужие `T_ASKING` при появлении подтверждённого плана (`ot->stop=1`). |
| sync_pending | 9643 | очередь синхронизации каталога | P |
| remeasure snapshot после trial | 9648–9652 | `r2o_discovery_client_shape_trial`/`r2o_capture_client_shape` | P |

**Итог:** прямого аналога не найдено для четырёх гейтов (`bound plan`,
`unfit_here`, `budget mark`, `yield`); остальное — P из-за разного слоя или
отсутствия differential. Это не доказательство отсутствия поведения: часть
может быть закрыта каталогом/live-слоем, но в `apply_discovery_outcome` и
`r2o_confirm_discovery_outcome` соответствующих проверок нет.

## Углублённая сверка sched.c: verdict_to_plans

| C-ветвь | строки | Rust | статус/пробел |
|---|---:|---|---|
| early-return CLEAR/UNREACHABLE/ADDRESS/RESPONSE/NO_QUIC/LOCAL_ADDRESS | 5224–5234 | отсев вердиктов в `r2o_discovery_*` | P: набор вердиктов тот же, единой функции нет |
| ECH trial: known plans witness | 5242–5262 | `r2o_ech_rx_ladder_candidate` (`:14573`) | P: known-plan отбор и дедуп по тексту разнесены |
| QUIC: один план из arm+qprops | 5264–5386 | `r2o_quic_discovery_candidates` (`quic_replay.rs:427`), `r2o_quic_trial_data_verdict`, `stall_cut` (`main.rs:4898/4908/20509-21068`) | P: Rust строит список кандидатов, C — один план; **`stall_cut` в Rust есть** и выставляется в QUIC-путях; `arm_hash`/`arm_path` (FNV-атрибуция и «свойство»/«перебор») отсутствуют. |
| volume fingerprint + known plans | 5390–5422 | `r2o_discovery_volume_known_plans` (`:3438`) | P: сигнал `volume`/`rx-volume(-wire)` и повторный lookup есть, полного differential нет |
| measured arm первым | 5429–5459 | `r2o_discovery_measured_split_plan` (`:6292`), `classify_measured` | P: `send_cap`/unfit-ветка есть; `arm_path`-атрибуция иная |
| RX-лестница | 5465–5517 | `r2o_ech_rx_ladder_candidate_count`/`r2o_ech_rx_ladder_candidate` (`main.rs:14564/14573`), `r2o_rx_volume` | P: Rust-лестница с `network_probe`/`send_cap`/`rx_ladder_plan_found`/`measured_rx_cut` есть, но C-поля `plan_boxes`/`net_probe_name` и очередь `rx_volume_candidate_pending` не найдены; room по `rx_cut` выражен иначе. |
| PREFIX/WHOLE split | 5519–5528 | `r2o_discovery_measured_split_plan` | E/P: формула и differential `r2o-measured-split` покрывают split/gap/send_cap |
| owned fallback | 5539–5544 | `r2o_fallback`/`own_first_plans` | P: список и условие входа есть, порядок refill не сверен |
| `d2k_compose` | 5547–5550 | `compose_d2o::compose_plan_texts`/`compose_from_props` | P: состав и `send_cap` есть, полного C/Rust differential всех ветвей нет |

**Итог:** источники кандидатов перенесены; `stall_cut` в Rust есть.
Не найдены C-атрибуция `arm_hash`/`arm_path` (FNV-хеш и метка
«свойство»/«перебор») и поля RX-лестницы `plan_boxes`/`net_probe_name`/
`rx_volume_candidate_pending`. Полной матрицы «вердикт × источник ×
порядок» нет — P обоснован.

## Углублённая сверка sched.c: worker_run_body

| C-ветвь | строки | Rust | статус/пробел |
|---|---:|---|---|
| JOB_VOICE: `d2k_sched_voice_hook` | 2769–2787 | `voice_measure::r2o_measure_voice_for_flow`/`R2oVoiceOptions` | P: опции mark/discovery/known_prefix/flow передаются; полного differential нет |
| JOB_VERIFY: выбор verifier | 2789–2901 | `r2o_family_recovery_sibling_trial*`, `fetch` | P: C выбирает `rx_gzip`/`rx`/`ver`/`replay`/`alpn`/`path`/`quic_replay` по `rx_phase`, `layered_rx`, `rx_cut`, `measure_path`, ECH; в Rust это разнесено, полной матрицы нет |
| VERIFY: budget/TS/QUIC-form | 2816–2832 | `r2o_discovery_classify_options`, `fetch` | P: per-call настройки C заменены полями `FetchOptions`; сброс после вызова не нужен |
| JOB_CONTACT | 2903–2921 | `ask.rs`/`run_r2o_ask` | P: contact и reserved fd есть только в CLI-опросе; production-discovery вопросов не задаёт (см. `prop_send_next`) |
| addr-recheck | 2934–2965 | `response::probe_neutral_ack` | P: C rc>0→ack, rc==0→ADDRESS, rc<0→не подтверждён/не снят; Rust возвращает `ProbeOutcome`/`neutral_ack`, точные коды не сверены |
| ECH GREASE/real | 2966–3041 | `r2o_discovery_ech_grease_fallback` (`:15311`), `r2o_discovery_ech_replay_required` (`:15322`) | P: C различает real/GREASE по public_name и свидетелю, ставит `ech_grease`/`ech_replay`/`ech_regrade`; Rust-флаги/переходы иные |
| ECH baseline | 3042–3058 | `r2o_discovery_ech_config`/`witness`, `r2o_ech_rx_ladder` | P: C `ech_trial=1` при не-CLEAR baseline и уровне ≠CHALLENGE; отдельного `ech_trial` в Rust не найдено |
| `own_first==1` base | 3059–3074 | `r2o_discovery_base`/`classify` (не сверено) | P |
| volume_first | 3077–3103 | `r2o_discovery_volume_*`, `r2o_discovery_volume_recovery` (`:14628`) | P: условия `rx_volume_only`/`family_reuse` и INCONCLUSIVE-ветви не сопоставлены один-в-один |
| QUIC arm | 3109–3169 | `r2o_quic_*`, `r2o_quic_discovery_candidates` | P: C `arm.data_cut`/`budget_pk`/seeded/deny_recheck; Rust-поля и порядок иные |
| TCP white/seed | 3170–3203 | `r2o_rx_volume`/`hello`, `compose` | P: ECH-приманка даётся всегда, seeded/white hooks; Rust-путь есть, полного differential нет |
| volume_after | 3205–3227 | `r2o_discovery_volume_recovery_eligible` | P: C разрешает FLAKY при late-volume suspicion и не-dial-deadline; Rust-условия не сверены |
| volume_carried && CLEAR | 3228–3239 | `cached_volume_cut` (`:11025/11217/11354`) | P: C сохраняет доказанный обрыв при CLEAR; отдельной ветви в Rust не найдено |
| результат | 3241–3252 | `DiscoveryOutcome` | P: `res`, `ask_settle`, wake; Rust-поля и тайминги иные |

**Итог:** ветви перенесены, но матрица «verifier × вход × состояние» и
особые случаи (`volume_carried && CLEAR`, `ech_trial`, `own_first base`)
не доказаны. P обоснован.

## Углублённая сверка sched.c: d2k_sched_tick

| C-блок | строки | Rust | статус/пробел |
|---|---:|---|---|
| clock/report admission | 10793–10807 | `Instant`, `R2oDiscoverySearches.queued_at` | P: привязка монотонных часов к стенным и допуск отчётов разнесены |
| `res_sample`/`measure_limit_update` | 10809 | `r2o_resource_limit::R2oMeasurementGate` | P: снимок CPU/RSS/conntrack и лимит замеров иные |
| wake drain | 10812–10813 | цикл `DiscoveryWorker` на condvar/канале | P: самопайп заменён очередью/condvar |
| `quic_yield_tick`/`quic_deny_tick` | 10817–10818 | `r2o_quic_yield_waiting_for_tcp` (`:12140`), QUIC deny cache | P |
| group expiry 7 суток | 10822–10830 | `groups.rs::expire_failures` | P |
| sync/area retry | 10831–10837 | каталог/`R2oCatalogPersistence` | P |
| `T_QUEUED` expiry/family | 10844–10865 | `R2oDiscoveryQueue::pop/expire/promote` | E/P: queue differentials |
| `T_RESTING` | 10867–10869 | `R2oDiscoveryCooldownRing`/`R2oDeadAddressCache` | P: cooldown/dead differentials |
| lifetime: SHAPE_WAIT/WATCHING/own_first=2/voice/ASKING | 10872–10944 | `R2O_DISCOVERY_TASK_LIFETIME`, phase, voice trial retire | P: `T_WATCHING`-фазы нет; `own_first`-срок и voice-retire разнесены |
| `T_VOICE_MEASURE` | 10946–10955 | `R2oVoiceLatestQueue`, `r2o_measure_voice_for_flow` | P |
| `T_VOICE_WATCH` | 10957–10979 | `r2o_take_silent_voice_trial`, `R2O_VOICE_PENDING_GRACE` | P |
| `T_VOICE_TRIAL` | 10980–10992 | `R2oVoiceTrialContext`, `R2O_VOICE_TRIAL_RENEW_INTERVAL` | P |
| `T_ASKING` | 10994–12360 | `r2o_classify_discovery_target...`, `r2o_discovery_ech_*`, `r2o_discovery_volume_*`, `r2o_discovery_client_shape_trial` | P: yield/addr/ECH/base/family/resources/snap/rx_volume/classify разнесены; полной матрицы нет |
| `T_PROPS_CONTACT`/`T_PROPS_WAIT` | ~11530–11634 | raw-пробы discovery; control-опрос только CLI | **пробел слоя:** см. `prop_send_next` |
| `T_VERIFY`/`T_VERIFY_WAIT` | ~11636–12042 | `r2o_run_discovery_candidate_trial*`, сбор APPLIED | P |
| `T_TRIAL_SETTLE` | ~12044–12060 | `exchange_candidate_probe_with_settle` | E/P |
| `T_PLANNING` | ~12063–12345 | установка кандидата/проверка | P |
| `queued_release` | ~12360 | очередь | P |

**Итог:** тик разложен на Rust-структуры, но полной матрицы
«состояние × событие × таймаут» нет; `T_WATCHING`-фазы, `yield_to_own_plan`
и `shape_misses` в Rust не найдены. P обоснован.

## Проверка полноты

Строк среза: 692. Строк в таблицах: 692. E=127, P=564, N=1, ?=0; E+P+N+?=692. `E*`/`P*` учтены в E/P соответственно (static-хелперы).


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
| `usage` (static) | 834–861 | 28 | текст помощи CLI | `main.rs:2952 print_help` | **P** | **C:** `--health-file/--queue/--plan/--log/--control/--mark/--probe-mark/--only-mark/--udp-reverse-hook/--iface/--flows/--queue-len/--copy-range/--sched-slots/--journal/--idle/--stats/--duration/--no-fail-open/--mode`. **R2O:** те же основные, но **нет** `--log`, `--health-file`, `--duration`, `--sched-slots`; добавлены `--family`, `--check`, `--controller-only`, `--control-wire`, `--control-release-id`, `--rcvbuf`, `--both/--queue4/6/--control4/6`, `--r2o-flow-capacity`, `--r2o-udp-reverse-visible`. Текст и состав отличаются. |
| `arg_u32` (static) | 863–871 | 9 | строгий разбор u32 | `main.rs:2911 parse_value` | P | общий `FromStr`; граничные тесты не выделены |
| `port_of` (static) | 873–876 | 4 | big-endian u16 | `packet.rs`/`read_u16` (приватный) | P | тривиально; отдельного теста нет |
| `print_stats` (static) | 878–1030 | 153 | периодическая сводка (процесс, HTTP80, hold, пакеты, ICMP, план, потоки, приветствия, sched, payload, NFQ, NAT, routed, UDP marked, raw, follow, shape misses, plan count, причины) | `main.rs:629-773` десять `r2o_log_*` | **P** | R2O печатает: процесс, очередь, TCP/UDP-таблицы, sched, session (reply_hidden/hello/sni/rst/HTTP keep-alive), payload (без capture), capture, hold, raw, udp_follow. **Не печатает:** HTTP80-статистику, владение приветствием (`hold_owned/resent/resend_fail`), план `applied/done/emitted/deferred/damaged/stale_deferred/sent_lost` (эти счётчики в R2O — N), NAT `ok/miss/none/retry`, routed flows, `udp_marked_kept`, `shape_misses` (всегда 0), `plan_count/capacity`, гистограмму причин (`count_reason` — N). ICMP печатается отдельно `icmp_guard.r2o_stats_line()` (`main.rs:1158`). `test-datapath-stats-timer-differential.sh` есть. |
| `proto_name` (static) | 1039–1045 | 7 | имя протокола 6/17 | inline в `main.rs` | P | — |
| `jrn_kind` (static) | 1050–1066 | 17 | код журнала → текст | `flow_journal.rs:85 c_name`, `:100 russian_name` | P | `flow_journal.rs:1027 journal_note_texts_match_d2o` |
| `print_journal` (static) | 1070–1104 | 35 | печать журнала по записям | `main.rs:3006 format_journal_details` | P | формат отличается; D22 сверяет записи, не печать |
| `refuse_of_errno` (static) | 1114–1116 | 3 | errno → код REFUSE | `flow_journal.rs:16-23` константы + `main.rs` | P | маппинг SEND/TOO_LONG разнесён по вызывающим |
| `offline_self_check` (static) | 1118–1123 | 6 | `--offline-self-check` SHA-проверка | нет | N | опция отсутствует в `parse_options` |
| `main` | 1125–2415 | 1291 | CLI, сокеты, NFQUEUE-цикл, sweep, hold/release, stats | `main.rs:884 run` (и `parse_options` `:2754`) | **P** | Цикл и большинство ветвей есть: NFQUEUE, raw, sched, hold, HTTP80, ICMP, stats, signals, route/cap refresh. **Нет** `--log` (R2O пишет в stderr без freopen), `--health-file` (health-файл не пишется), `--duration` (нет остановки по времени), `--sched-slots` (ёмкость очереди отправки задаётся в коде `scheduler.rs`). C-проверки «apply требует plan или control», «apply требует mark≠0», «probe-mark≠mark» в R2O разнесены по `parse_options`/`run`; `--check` — R2O-расширение. |

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
  EMSGSIZE→TOO_LONG, иначе SEND; Rust константы + вызывающие, P.
- **HTTP80:** `http80_log` (717–728) — текст «вставка провайдера»;
  Rust событие `send_http_portal_event`, P. `http80_io_payload`/
  `http80_io_accept`/`http80_io_rst` (733–768) — ACCEPT с заменой,
  ACCEPT, raw RST; Rust `nfqueue.rs:317/310`, `raw.rs:147`, E/P.
  `http80_cut` (776–784) — событие обрыва; Rust
  `hold.rs:255`/`main.rs:3148`, P. `http80_step` (786–829) —
  DROP/REPLACE/swap; Rust `main.rs:2006/2093` + `hold.rs`, P + D17.
- **CLI/вывод:** `usage` (834–861) — см. строку: R2O не имеет
  `--log/--health-file/--duration/--sched-slots`, добавляет
  `--family/--check/--controller-only/--control-wire/--rcvbuf/
  --both`. `arg_u32` (863–871) — `strtoul(...,0)`; Rust
  `parse_value`, P. `port_of` (873–876) — BE u16; Rust `read_u16`,
  P. `print_stats` (878–1030) — см. строку: R2O не печатает HTTP80,
  hold ownership, план applied/done/damaged/stale/sent_lost, NAT,
  routed, udp_marked, shape_misses, plan count, гистограмму причин.
  `proto_name` (1039–1045) — tcp/udp/?; Rust inline, P.
  `jrn_kind` (1050–1066) — имена видов; Rust `c_name`/
  `russian_name`, P. `print_journal` (1070–1104) — печать журнала;
  Rust `format_journal_details`, P.
- **Самопроверка:** `offline_self_check` (1118–1123) — SHA-256("abc")
  и версия провода; Rust-опции `--offline-self-check` нет. **N.**
- **`main` (1125–2415):** CLI, план, raw, NFQUEUE, control, session,
  http80, sched, signals, цикл. Нет `--log`/`--health-file`/
  `--duration`/`--sched-slots`; health-файл не пишется, остановки по
  времени нет, лог не переоткрывается. Остальные ветви (apply
  требует plan/control, mark≠0, probe-mark≠mark, SO_TIMESTAMP,
  stats/idle/sched/hold/http80/routes/cap) перенесены — P.

**Итог:** 44 функции; N — `count_reason`, `offline_self_check`
(диагностика/CLI), остальные P/E с подтверждёнными пробелами
CLI-логирования, health-файла, duration и состава сводки.

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
| `name_same` (static) | 369–382 | 14 | сравнение имени без регистра: равная длина, ASCII A-Z→a-z | `httpup.rs:468 same_host` | **P** | C не трогает хвостовую точку и пустую строку; Rust `same_host` снимает одну хвостовую `.` и требует непустое левое имя. Для SNI/`last_name` это может дать разный результат на `example.com.`; тест `httpup` покрывает только HTTP-путь. |
| `rd16` (static) | 384–386 | 3 | big-endian u16 | `packet.rs:231 read_u16` | P | — |
| `refuse_coded` (static) | 402–413 | 12 | отказ плана в журнал; зонд молчит только при code=0 | `flow_journal.rs:684 record_plan_refused`, `main.rs:3737 send_refused_event` | P | D22 сверяет записи; условие «зонд+code 0» реализовано |
| `refuse` (static) | 415–418 | 4 | `refuse_coded(...,NONE,NULL)` | там же | P | — |
| `tcp_options_timestamp_profile` (static) | 422–433 | 12 | профиль опций: UNKNOWN/NO_TS/TS | `packet.rs:39 tcp_options_timestamp_profile` | E | unit-тесты packet/tcp на опции |
| `tcp_options_have_timestamp` (static) | 435–437 | 3 | есть ли TS-опция | `packet.rs:39` + сравнение | P | — |
| `plan_handed_off` (static) | 446–473 | 28 | applied/key/plan/trial, `orig_taken`, `sends_left=n_out+1`, `sends_failed/sends_done/udp_replan=0`, execution_id, binding | `engine.rs:588-603 r2o_begin_execution`, `main.rs:411 R2oTcpExecution`, `PendingApplied`, `TransmissionOutcome` | **P** | C ведёт счётчик посылок и `orig_taken` на потоке; Rust `r2o_begin_execution` ставит `execution_id`/`r2o_execution_pending`, `PendingApplied` хранит `payload_on_wire/original_spent/original_taken`, а `TransmissionOutcome.r2o_sends_done` — булев факт хотя бы одной отправки. Числовых `sends_left/sends_done` нет: ожидание всех emits делает `ScheduledQueue::has_pending(ticket)`. `udp_replan` функционально заменён сбросом `plan_applied` в `r2o_note_execution_failure` (`r2o_udp_sessions.rs:383-406`). P — нет per-send счётчиков и `sent_lost`. |
| `table_of` (static) | 477–479 | 3 | выбрать таблицу по proto | `TcpSessions`/`R2oUdpSessions` (разные типы) | P | — |
| `suspect_num` (static) | 486–503 | 18 | подозрение один раз на поток (`controller_probe`/`suspected`), `suspects++`, planned/client_shape в journal | `engine.rs` tcp_*_events, `r2o_quic.rs:478 sweep`, `flow_journal` | **P** | C дедуплицирует на потоке и пишет `D2K_JRN_SUSPECT` с planned/shape; Rust события `EVENT_R2O_TCP_*`/`flow_journal`; сводного `suspects++` нет (N), единой функции нет. |
| `suspect` (static) | 505–508 | 4 | `suspect_num(...,0)` | там же | P | — |
| `on_flow_expire` (static) | 521–530 | 10 | при истечении: `capture_forget` + `tcp_silence_observe` | `engine.rs:698-760 expire_with_silent` | **P** | Rust `expire_with_silent` вызывает замыкание `on_silent` перед удалением; capture забывается в `TcpSessions`. Эквивалентно по смыслу, callback заменён замыканием. |
| `rd32` (static) | 532–535 | 4 | big-endian u32 | `packet.rs:236 read_u32` | P | — |
| `is_discord_ip_discovery` (static) | 544–550 | 7 | строгая сигнатура 74 байта, нули 8..71 | `stun.rs:82 is_discord_ip_discovery_request` | P | end-to-end в `r2o_voice` тестах; unit в stun.rs нет |
| `is_discord_ip_discovery_response` (static) | 552–564 | 13 | ответ 0x0002, тот же SSRC, адрес/порт | `stun.rs:89 is_discord_ip_discovery_response` | P | `r2o_voice.rs` proof-тесты |
| `is_stun_binding` (static) | 569–578 | 10 | RFC 5389: cookie, длина, тип | `stun.rs:116 is_binding` | P | тестов в stun.rs нет; voice-тесты косвенные |
| `is_stun_request` (static) | 580–582 | 3 | Binding Request 0x0001 | `stun.rs:71 is_binding_request` | P | — |
| `is_stun_response_for` (static) | 584–588 | 5 | Binding Success + txid | `stun.rs:76 is_binding_response_for` | P | — |
| `d2k_session_nat_stats` | 650–656 | 7 | глобальные счётчики NAT ok/miss/none/retry | нет аналога (proc_nat не считает) | N | счётчики NAT в R2O не собираются |
| `plan_fits_transport` (static) | 672–676 | 5 | план объявлен для этого proto (0=любой) | `Plan.transport` проверка в `engine.rs`/`main.rs` | P | — |
| `flow_tracked` (static) | 678–777 | 100 | conntrack: 1-й пакет — не читать; SYN-ACK — считать доказанным; иначе до 3 попыток procfs; коды 0/1/-1 и nat_state | `proc_nat.rs:20 lookup`, `engine.rs` conntrack gate | **P** | C: `first_packet`/`saw_synack` исключения, `g_nat_ok/miss/none/retry`, `nat_state` 0/1/3. Rust lookup/три попытки/«нет таблицы» есть (`r2o-nat-proc-differential.sh`), но **`g_nat_*` счётчики не ведутся** (N), а `nat_state` заменён состоянием gate. P. |
| `handle_udp` (static) | 779–1569 | 791 | весь UDP-путь: направление, voice/QUIC, hold, NAT, план, сборка, ipfrag | `main.rs:1600-2600` (UDP), `r2o_udp_sessions.rs`, `r2o_quic.rs`, `r2o_voice.rs` | P | `r2o-udp-exchange-differential.sh`, `test-controller-udpplan-differential.sh`, voice/quic differentials; ветви ipfrag/NAT-fragment проверены частично |
| `note_tcp_hello` (static) | 1573–1580 | 8 | запомнить ACK приветствия, счётчик hello-потоков; зонд не считается | `engine.rs:1044/1049` `r2o_tcp_hello_flows`, `hello_ack` | **P** | C: `if (!controller_probe) tcp_hello_flows++`, `hello_ack=rd32(tcp+8)`, `hello_ack_valid=ack`. Rust: тот же инкремент под `!controller_probe`, `hello_ack=ack.then_some(tcp.acknowledgment)` — `Option` заменяет пару ack/valid. Тесты `engine.rs:2548`, `:2565`, `:2608` (счётчики и reply-hidden). C/Rust differential нет. |
| `routed_flow` (static) | 1593–1626 | 34 | клиент с меткой политики → без плана; `routed_flows++`/`routed_first`; новый SYN без метки снимает флаг | `r2o_route.rs:580-665 R2oRoutedFlows::r2o_skip_packet`, `:666-678 r2o_is_new_syn` | **P** | C ставит `fl->routed` и идёт ядром; Rust `r2o_skip_packet` вставляет key+reverse, при новом SYN удаляет оба, чистит по idle/ёмкости. Семантика совпадает; `routed_flows`/`routed_first` — счётчики сессии. `r2o-route-gate-differential.sh`. |
| `session_packet` (static) | 1628–2601 | 974 | TCP-путь: заголовки, направление, capture, TLS/HTTP, план, сборка | `engine.rs:1441 decide_with_session_mode` + `:1849 decide_tcp` | P | `test-datapath-default-mode-differential.sh`, tcp differentials; полный набор ветвей C не доказан |
| `d2k_session_packet` | 2603–2606 | 4 | публичный вход: `session_packet(observe_only=0, probe=0, mtu=0)` | `engine.rs:1403-1410 decide_with_session` → `decide_with_session_mode(false,0)` | **P** | Обёртка совпадает; вся логика — в `session_packet`/`decide_with_session_mode`. |
| `d2k_session_packet_mtu` | 2608–2613 | 6 | вход с `tcp_segment_cap` | `engine.rs:1421-1429 decide_with_session_mtu` | **P** | `tcp_segment_cap` передаётся в plan apply; `test-tcp-shape-context-differential.sh`. |
| `d2k_session_packet_probe` | 2615–2619 | 5 | вход зонда контроллера (`probe=1`) | `engine.rs:1412-1419 decide_with_session_probe` | **P** | `controller_probe` исключает поток из пользовательских наблюдений; `test-datapath-controller-probe-capture-differential.sh`. |
| `d2k_session_packet_probe_mtu` | 2621–2626 | 6 | зонд + `tcp_segment_cap` | `engine.rs:1431-1439 decide_with_session_probe_mtu` | **P** | Та же wrapping-семантика; отдельного differential нет. |
| `d2k_session_observe_tcp` | 2628–2631 | 4 | только наблюдение, без вердикта | `main.rs` observe-mode `decide_with_session` | P | — |
| `d2k_session_plan_revision` | 2633–2635 | 3 | сумма `s->plan_revision` и `d2k_plantab_revision(plans)` | `control.rs` `NamePlans.revision` | **P** | C складывает ревизию запасного плана и ревизию таблицы; Rust ведёт один счётчик `NamePlans.revision` на все изменения. Для обнаружения изменений эквивалентно, для точного числа — нет. |
| `d2k_session_stream_anchor` | 2637–2645 | 9 | якорь HTTP-потока или SYN+1: `d2k_hold_parse`, поток с `saw_syn`, `http_next` при `http_flow && http_conn`, иначе `syn_seq+1` | `hold.rs:969 remember_syn` (capture_anchor) | **P** | C сначала разбирает hold-заголовок и требует найденный TCP-поток с `saw_syn`; приоритет `http_next` выше `syn_seq+1`. Rust хранит `capture_anchor` в hold-слоте по SYN; отдельного API с тем же приоритетом и проверкой `saw_syn` нет. D6; нужен тест «HTTP-поток → http_next, иначе SYN+1». |
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
| `d2k_session_want_shape_family` | 2931–2960 | 30 | отдать last_hello или взвести ожидание по transport/family; копирует и полный набор TCP-опций | `main.rs` `r2o_capture_client_shape`/`arm_client_shape`; `control.rs:1988` | **P** | C хранит `last_hello/last_name/last_opts` на слот `(transport,family)`; Rust — `ClientShapeEvent`/`last_client_shapes`. **Пробел:** полный `shape_opts` не передаётся, только `tcp_has_timestamp` (см. `d2k_session_shape_tcp_options_family` — N). Повторный запрос после утери потока снимок не вернёт. |
| `d2k_session_shape` | 2962–2964 | 3 | снимок формы TCP | `capture.rs:170 tcp_hello_from_packet`, `r2o_quic.rs:180 capture_hello` | P | снимок берётся из capture/события, не из сессионного буфера |
| `d2k_session_shape_family` | 2966–2980 | 15 | снимок формы по transport/family | `capture.rs:170`, `r2o_quic.rs:180` (family в ключе потока), `control.rs` `ClientShapeEvent` | **P** | C отдаёт `shape[k]` и длину; Rust — ClientHello из `ClientShapeEvent`/кэша. Полный набор TCP-опций не хранится. |
| `d2k_session_shape_tcp_options_family` | 2982–2990 | 9 | опции TCP к снимку | `control.rs ClientShapeEvent.tcp_has_timestamp` (только bool) | **N** | C хранит `shape_opts[4][40]` и отдаёт полный набор TCP-опций; R2O `ClientShapeEvent` несёт ClientHello + только булев `tcp_has_timestamp`, а v22 `CLIENT_TCP` уходит с пустыми TCP options. Произвольные опции (MD5/порядок TS и др.) не передаются; D2O-контроллер получает `NO_TS` для TS-клиента. |
| `d2k_session_plans` | 2992–2994 | 3 | таблица планов | `control.rs` NamePlans | P | — |
| `d2k_session_plan_count` | 2996–2998 | 3 | число планов | `control.rs` NamePlans len | P | — |
| `d2k_session_plan_capacity` | 3000–3002 | 3 | ёмкость планов | `control.rs` MAX_* лимиты | P | — |
| `silence_deadline` (static) | 3018–3028 | 11 | срок молчания: 8×RTT, [1,5] с, без RTT 2 с | `engine.rs` `tcp_silence_event`/`fin_retry_window` | P | `r2o-tcp-silence` differential; формула воспроизведена |
| `tcp_silence_observe` (static) | 3034–3049 | 16 | SILENT: TTL-видимость, нет payload, повтор | `engine.rs:1330-1369` silence events | P | `test-tcp-silence-current-differential.sh` |
| `fin_retry_window` (static) | 3063–3067 | 5 | окно повтора FIN: `3×max(3×RTT, 1с)` = `max(9×RTT, 3с)` | `engine.rs:1389 fin_retry_window` | **E** | Формула совпадает: Rust `rtt*9`, минимум 3 с; `None` (RTT неизвестен) → 3 с, что соответствует C `rtt_ns=0`. Тест `engine.rs:3823` (истечение ограниченного окна FIN) и `:3568` (повтор FIN). |
| `fin_window_over` (static) | 3069–3073 | 5 | `pending_fin && now>=pending_fin_ns && now-pending_fin_ns >= fin_retry_window(f)` | `engine.rs:708-710 fin expiry` | **E** | Rust проверяет `pending_fin_at.is_some_and(|started| elapsed >= fin_retry_window(rtt))`; порядок и сравнение `>=` совпадают. Тест `engine.rs:3823`. |
| `sweep_one` (static) | 3084–3087 | 4 | обход TCP-потоков | `engine.rs:693 expire_with_silent` | P | — |
| `sweep_udp_one` (static) | 3112–3142 | 31 | SILENT по UDP: rev_seen/повтор PTO/срок | `r2o_quic.rs:478 sweep`, `main.rs` quic sweep | P | `r2o-quic-stun-watch-differential.sh` |
| `quic_watch` (static) | 3164–3169 | 6 | кандидат QUIC-stall | `r2o_quic.rs:503 r2o_quic_stall_candidates` | P | — |
| `flow_tuple` (static) | 3174–3187 | 14 | прямой кортеж для ctnetlink | `conntrack.rs:420 tuple_from_packet`, `:413 from_socket_addrs` | P | — |
| `ct_flow` (static) | 3197–3221 | 25 | QUIC stall по счётчикам conntrack | `r2o_quic.rs:527 update_r2o_quic_stall` | P | `r2o-quic-stun-watch-differential.sh`, `test-conntrack-retry-current-differential.sh` |
| `tcp_watch` (static) | 3257–3261 | 5 | TCP-stall: proto 6, `saw_hello`, `had_sni`, `rev_payload_after_hello>0`, не suspected/controller_probe/pending_fin/tcp_watch_off/routed | `engine.rs:788-815 tcp_stall_candidates` | **P** | Rust: `direction_known`, `!controller_probe`, `hello_has_sni`, `response_payload`, `!reverse_rst`, `guards==0`, `!stall_watch_off`, `!stall_reported`. **Отличия:** Rust не проверяет `pending_fin` и `routed`, но добавляет `reverse_rst`/`guards`/`stall_reported`. Таблица только TCP, proto 6 подразумевается. P — набор предикатов не совпадает. |
| `tcp_in_band` (static) | 3263–3269 | 7 | оценка в полосе любого бюджета: `est+3 >= b && est <= b+3` | `engine.rs:880-883` | **E** | Формула совпадает посимвольно (`saturating_add(3) >= budget && estimate <= budget+3`), `TCP_STALL_PACKET_SLACK=3`. Покрыто stall-тестами `engine.rs:2341`, `:2381`, `:2405` (бюджеты 15/35 и оценка пакетов). |
| `tcp_band_top` (static) | 3271–3277 | 7 | максимум бюджетов + `TCP_STALL_PACKET_SLACK=3`; пустой список → 3 | `engine.rs:850-855` | **P** | Rust: `max().unwrap_or(25) + 3`. Для непустого списка совпадает; при пустом C даёт `0+3`, Rust — `25+3`. На практике пустой список заменяется полевым 25 в `set_tcp_stall_budgets`, но отдельного boundary-теста нет. |
| `ct_tcp_flow` (static) | 3279–3328 | 50 | TCP stall: ESTABLISHED, 3 пакета, RTO, полоса | `engine.rs` conntrack stall detection | P | `test-tcp-stall*`/`r2o-tcp-silence`; полный differential не подтверждён |
| `d2k_session_set_stall_budgets` | 3330–3343 | 14 | до 8 ненулевых бюджетов, пусто → полевой 25 | `engine.rs:451-460 set_tcp_stall_budgets` | **E** | Точное совпадение: `>8` или любой `0` → отказ; пустой список → `[25]`; иначе копия. Тесты `engine.rs:2431-2434` (нулевой/9/пусто/25). |
| `d2k_session_stall_budgets` | 3345–3351 | 7 | чтение бюджетов (до cap) | `engine.rs:371/850` поле `tcp_stall_budgets` | **P** | Поле есть и используется (`:880`), отдельного getter с cap нет; эквивалентно для чтения. |
| `d2k_session_sweep` | 3353–3370 | 18 | `sweep_one` TCP + `sweep_udp_one`; при `ct_query` — обход uflows/flows через `ct_flow`/`ct_tcp_flow` | `main.rs` periodic sweep, `engine.rs`/`r2o_quic.rs`, `conntrack.rs` | **P** | C-счётчики `told` и порядок uflows→flows; Rust — периодический sweep и conntrack-запросы. Полного differential на все типы потоков нет. |
| `d2k_session_expire` | 3372–3395 | 24 | `remove_if(FIN)` + `track_expire(TCP, callback)` + `track_expire(UDP, NULL)` | `engine.rs:698-760 expire_with_silent`, `r2o_udp_sessions.rs:456 expire` | **P** | C FIN-окно и TCP-callback; Rust `expire_with_silent` + UDP expire. Эквивалентно по смыслу, тайминги/порядок не сверены. |
| `d2k_session_flows` | 3397–3399 | 3 | сумма `track_count(TCP)+track_count(UDP)` | `main.rs:668-679 r2o_log_flow_table_stats` | **P** | Rust считает `tcp_sessions.len()` + `udp_stats.flows`; сумма та же. |
| `d2k_session_send_pending` | 3401–3405 | 5 | `fl && execution_id==execution && sends_left && !sends_failed` | `engine.rs:614 r2o_send_pending` | **P** | Rust проверяет `execution_id != 0`, совпадение поколения, `r2o_execution_pending` и `!damaged`. `sends_left` заменён ожиданием `ScheduledQueue`, `sends_failed` — удалением `PendingApplied`; для проверяемых состояний эквивалентно. Тесты `engine.rs:4600`, `:4639` (истина → ложь после завершения/чужого поколения). Числового `sends_left` нет. |
| `d2k_session_sent` | 3407–3428 | 22 | учёт отправки: `sends_left--`, `sends_done++`, при нуле `done++` + PLAN_DONE; иначе `sent_lost++` | `engine.rs:627-653 r2o_mark_plan_done_for_execution`, `main.rs` `ScheduledQueue::has_pending` | **P** | C считает каждую из `n_out+1` посылок. Rust ждёт опустошения `ScheduledQueue` по ticket (все emits), оригинал отпускается `release_many` до этого; затем `r2o_mark_plan_done_for_execution` ставит `plan_done` при совпадении key/execution/pending/!damaged. Функционально многосборочность покрыта, но **числовых `sends_left/sends_done` и счётчика `sent_lost` нет**; устаревшее завершение просто игнорируется. P. |
| `d2k_session_exec_failed` | 3449–3501 | 53 | общий исход отказа: UNSENT один раз; UDP original-lost→`udp_replan`; damaged→`damaged_flows++`, `guards=0`, PLAN_DAMAGED один раз | `main.rs:411-430 r2o_finish_tcp_execution`, `:433-446 r2o_release_damaged_tcp_hold`, `:468 r2o_fail_pending_applied`; `engine.rs:672-690 r2o_mark_damaged_for_execution`; `r2o_udp_sessions.rs:383-406` | **P** | Совпадает: `r2o_mark_damaged_for_execution` ставит `damaged=true`, `pending=false`, **`guards=0`**; `r2o_finish_tcp_execution` выбирает done/damaged/failed по `payload_on_wire`/`original_spent`/`original_taken`. **Исправлено:** C при damaged тоже пишет **две** записи — PLAN_UNSENT (через `d2k_session_unsent`) и PLAN_DAMAGED; `record_execution_failure` делает то же. `udp_replan` функционально покрыт `plan_applied=false` в `r2o_note_execution_failure` при `lost`. Остаётся **нет счётчика `damaged_flows`** и числового `sends_done` (в Rust bool). `test-raw-emission-cancel-differential.sh`. |
| `d2k_session_guards` | 3503–3507 | 5 | guards потока | `engine.rs` `session.guards` | **P** | Поле есть; `r2o_mark_damaged_for_execution` обнуляет, как C. Отдельного getter нет. |
| `d2k_session_client_shape` | 3509–3513 | 5 | форма клиента потока | `engine.rs` `session.client_shape` | **P** | Поле есть; заполняется из ClientHello. Полный набор TCP-опций не хранится (см. форму — N). |
| `d2k_session_damaged` | 3515–3523 | 9 | пометить поток damaged при совпадении execution | `engine.rs:672-690 r2o_mark_damaged_for_execution` | **P** | C ставит только `damaged=1`; Rust дополнительно сбрасывает `r2o_execution_pending` и `guards=0`. Для флага эквивалентно, для guards — Rust сбрасывает раньше, чем C в `exec_failed`. |
| `d2k_session_unsent` | 3525–3539 | 15 | PLAN_UNSENT + `sends_left=0`/`sends_failed=1` | `main.rs:468 r2o_fail_pending_applied`, `r2o_datapath::flow_journal::record_execution_failure` | **P** | C пишет PLAN_UNSENT и обнуляет счётчики; Rust `sends_left/sends_failed` не имеет, UNSENT — часть `record_execution_failure` (PlanUnsent). Повторный UNSENT невозможен, потому что `r2o_fail_pending_applied` удаляет `PendingApplied`; это функциональный эквивалент `sends_failed=1`. D22. |
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
| `d2k_track_new_connection` | 231–257 | 27 | сброс полей при новом SYN; сохраняются key/in_use/first/last/init_low/dir_known/счётчики пакетов и байт, **sends_left/sends_failed/execution_id/binding/plan_id/trial_id** | `engine.rs:938` ветка new_connection (новый `TcpSession`, копируются только `metrics`) | **P** | **Подтверждённое расхождение:** C намеренно сохраняет `sends_left/sends_failed/execution_id` через границу нового SYN, чтобы позднее завершение старой посылки не приняли за новую. Rust создаёт новый `TcpSession` с `execution_id=0`, `r2o_execution_pending=false`; `PendingApplied`/tickets живут отдельно, поэтому поздний completion старого поколения будет отброшен (`r2o_send_pending` вернёт false), а не учтён. Нужен тест «новый SYN при незавершённой посылке». |
| `d2k_track_remove` | 259–267 | 9 | найти и удалить сдвигом | `engine.rs` `flows.remove` | **P** | C: `find` + `remove_at`; Rust: `HashMap::remove`. Функционально эквивалентно; отдельного теста на удаление середины кластера нет (в C это важно, в Rust — нет). |
| `d2k_track_walk` | 269–278 | 10 | обход всех занятых слотов в порядке таблицы | `flows.iter()` / `retain` (`engine.rs:698`) | **P** | C обходит слоты по возрастанию индекса; Rust — в неопределённом порядке `HashMap`. Если потребитель зависит от порядка (логи/диагностика), результат может отличаться; функциональные счётчики не зависят. |
| `d2k_track_expire` | 280–308 | 29 | истечение по idle: `now>=last && now-last>=idle`, callback **до** удаления, повторная проверка слота после сдвига | `engine.rs:698 expire_with_silent` | **P** | C защищается от `now<last` явно; Rust использует `saturating_duration_since`, что для `idle>0` даёт тот же отказ. Callback `on_silent` вызывается до `retain`-удаления. C удаляет по одному и перепроверяет слот; Rust делает одним `retain`. Итоговый набор удалённых и событий совпадает, порядок обхода иной. Тесты `engine.rs:3356`, `:3448`. |
| `d2k_track_remove_if` | 310–325 | 16 | удаление по предикату (FIN-окно), повторная проверка слота | `engine.rs:700 fin_expired в retain` | **P** | C: `while (used && gone()) remove_at`; Rust: `retain` с `fin_expired`. Набор удаляемых совпадает; C перепроверяет слот после сдвига, Rust — нет необходимости. Отдельного теста на несколько подряд идущих FIN нет. |
| `d2k_track_count` | 327–329 | 3 | число занятых записей | `engine.rs:429 len` | **E** | Прямой getter `flows.len()`; используется в тестах и статистике. |
| `d2k_track_capacity` | 331–333 | 3 | физическая ёмкость (степень 2) | `engine.rs:434 r2o_tcp_flow_capacity` | **E** | Прямой getter `flow_capacity.slots()`; тест `flow_capacity.rs:45` проверяет округление. |
| `d2k_track_refusals` | 335–337 | 3 | счётчик отказов вставки | `engine.rs:438 r2o_tcp_flow_refusals` | **P** | Прямой getter; инкремент в `track_packet_mode` при `len >= limit`. Есть `test-datapath-tcp-capacity-differential.sh`, но в этом проходе он не перезапускался; статус P. |

## capture.c (6 функций)

Сборка ClientHello/HTTP-заголовка по seq: TTL, generation, anchor, перекрытия,
конфликт → poison. R2O: `crates/r2o-datapath/src/capture.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `same` (static) | 4–6 | 3 | сравнение ключей | `TcpFlowKey` `Eq` (`capture.rs:14`) | E | используется во всех capture-тестах |
| `d2k_capture_forget` | 8–14 | 7 | сбросить слоты ключа | `capture.rs:650 forget` | E | `capture.rs:949` (требует forget/new generation) |
| `reject` (static) | 16–20 | 5 | state=2, rejected++ | `capture.rs:662 reject_result` | E | `capture.rs:949` conflicting overlap |
| `d2k_capture_feed_ready` | 22–107 | 86 | сборка по seq: TTL, generation, anchor, overlap, wrap, ready-callback | `capture.rs:514 feed_mode`, `:446 feed`, `:480 feed_http` | **P** | TLS-путь совпадает построчно: TTL (`now<started`/`now-started>=TTL` ↔ `checked_duration_since`), generation, проверка anchor (`(int32_t)offset >= 0`, `< CAPTURE_BYTES`, `len <= CAPTURE_BYTES-offset`), `delta`, overlap-conflict, `high`, `contiguous`, `reject/full/completed`. **Отличия:** (1) Rust требует совпадения `mode` и освобождает слот при смене TLS↔HTTP, C режима не знает; (2) C при отсутствии anchor требует `bytes[0]==22` для **любого** ready-callback, Rust — только для TLS, HTTP без anchor принимает; (3) Rust `http_ready` использует `request_host_range`, C `d2k_http_request`: Rust требует полностью закрытые заголовки (`find_crlf`), C может вернуть 1 при завершённой строке Host без пустой строки; Rust отвергает `#` и target ≥2048, C — нет; Rust отвергает полный 4096-байтный буфер без `\r\n\r\n`, C оставляет слот до TTL; (4) статистика Rust гейтится `visible`, C считает всегда (R2O-расширение для controller probe). Trace-тесты `capture.rs:989/1099` есть, но `test-datapath-capture-lifecycle-differential.sh` пинится на другой SHA. |
| `tls_ready` (static) | 109–118 | 10 | критерий целой TLS-записи (1 запись, длины) | `capture.rs:673 tls_ready` | **E** | Точное совпадение: `n>=2 && b[1]!=3`, `n>=6 && b[5]!=1`, `total=5+u16`, `9..=4096`, `high>total`, `hs+9==total`, `n==total`; тест `capture.rs:1209`. |
| `d2k_capture_feed` | 119–124 | 6 | feed с TLS-критерием `tls_ready` | `capture.rs:446 feed` | **E** | Тонкая TLS-обёртка: C `feed_ready(..., tls_ready)`, Rust `feed(..., CaptureMode::Tls, visible=true)`. Для пользовательского TLS-трафика `feed_ready` эквивалентен; общий HTTP-путь — P (см. выше). |

### capture.c: построчная сверка

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

## hold.c (12 функций)

Удержание TCP-сегментов до сборки приветствия/HTTP-заголовка: слоты, дедлайн,
ревизия плана, порядок оригиналов, ready-batch. R2O: `hold.rs`.

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

### hold.c: построчная сверка

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

## udp_hold.c (10 функций)

Ограниченное владение NFQUEUE ID для сборки QUIC ClientHello: слоты, дедлайн,
пачки, переполнение. R2O: `r2o_udp_hold.rs` (`R2oUdpHoldTable`).

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

### udp_hold.c: построчная сверка

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

## udp_path.c (7 функций)

Транзакция UDP-hold вокруг решения сессии и выпуск/повтор пачек.
R2O: `main.rs` (`r2o_release_udp_batch*`, `r2o_udp_handle_late_tail`),
`r2o_udp_sessions.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_udp_path_release` | 6–13 | 8 | закрыть session-hold и выпустить пачку `NF_ACCEPT` | `main.rs:153 r2o_release_udp_batch`, `:200 r2o_release_udp_batches` | **P** | C вызывает `d2k_session_udp_hold_end(&b->key)` и `d2k_udp_out_batch(..., NF_ACCEPT, 0, now, now, seq)`. Rust `r2o_release_udp_batch` отпускает голову/хвосты через `r2o_release_batch_with`, помечает follow и логирует ошибки, но **прямого `hold_end` нет**: `r2o_udp_sessions` не хранит `udp_hold_active`, а `r2o_begin_hold` ограничивает попытки через `hold_attempts/hello_seen/plan_applied`. P — разный жизненный цикл hold. |
| `d2k_udp_path_pre` | 15–33 | 19 | flush истёкших, `session_udp_hold_begin`, `hold_feed_marked`; при отказе feed — `hold_end` | `main.rs:1560-1635` flush/release + begin_hold + feed | **P** | C: flush с release-callback → `hold_begin` → `feed_marked`; при отказе feed вызывает `hold_end`. Rust: `r2o_flush(now)` + `r2o_release_udp_batches`, затем `r2o_begin_hold` и `r2o_feed`; `Held` без собранного ClientHello делает `continue` без отката, `Overflow` отпускает пачку, `Refused` ничего; `hold_end` отсутствует. Логика близка, но ветви rollback/held-без-hello различаются. |
| `d2k_udp_path_post` | 35–60 | 26 | `udp_hold_wait` → HELD/NORMAL; `udp_hold_ready` → take/replay → REPLAY, иначе LOST; `fed` → take/release → RECLAIMED | `main.rs:1600-2210` (late tail/replay/release) | **P** | C возвращает один из четырёх кодов и явно вызывает `hold_replay`/`hold_end`. Rust разносит это по веткам `PacketDecision`, `r2o_udp_handle_late_tail`, `r2o_mark_hold_replay_first` и `r2o_release_udp_batch`; отдельной функции с теми же четырьмя исходами нет. P — нужен differential на HELD/REPLAY/LOST/RECLAIMED. |
| `d2k_udp_path_read` | 62–67 | 6 | `rseq++`, `seq=rseq`, `now_ns` | `main.rs:1340` `udp_receive_seq` | **P** | C инкрементирует `rseq` без защиты от нуля; Rust `wrapping_add(1).max(1)` — при переполнении C даёт `seq=0`, Rust `1`. На практике 64-битный счётчик не переполняется; отличие зафиксировано. |
| `d2k_udp_path_expire` | 69–74 | 6 | `seq = read_follows ? rseq+1 : NONE`, flush по таймеру | `main.rs:1330-1345` flush + release + `follow.age` | **P** | C `D2K_UDP_SEQ_NONE` для отсутствия чтения; Rust `follow_receive_seq = received ? udp_receive_seq : 0`, затем `r2o_flush`/`r2o_release_udp_batches`/`r2o_age`. Семантика 0/NONE совпадает, но `max(1)` и порядок flush/release/age разнесены. |
| `d2k_udp_path_passed` | 76–88 | 13 | пассивный проход: IPv4, len≥20, `udp_opening`, neutral, follow_mark(0,seq) | `main.rs:108 r2o_udp_mark_plain_pass` | **P** | Rust дополнительно требует `view.protocol==17` и `fragment & 0x3fff == 0` через `PacketView`, C проверяет только `len>=20` и версию IPv4; C `d2k_udp_out_neutral` и Rust `r2o_udp_packet_is_neutral` учитывают route/probe mark. `follow_mark(...,0,seq)` ↔ `follow.r2o_mark(packet, now, None, receive_seq)`. P. |
| `d2k_udp_path_planned` | 90–97 | 8 | плановая посылка: те же проверки + follow_mark(at_ns,seq) | `main.rs:131 r2o_udp_mark_planned` | **P** | То же отличие proto/fragment; `at_ns` ↔ `Option<Instant> at`, `seq` ↔ `receive_seq`. Отдельного differential на planned-путь с `at` нет. |

### udp_path.c: построчная сверка

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

### udp_release.c: построчная сверка

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

## nfq.c (12 функций)

NFQUEUE: netlink bind/params с ACK, SO_RCVBUF(FORCE), recv ENOBUFS, вердикты.
R2O: `nfqueue.rs`, `netlink.rs`.

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

### nfq.c: построчная сверка

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
| `d2k_nl_packet` | 79–161 | 83 | атрибуты NFQA: hdr/payload/cap/ts/mark/oif | `netlink.rs:125 QueuePacket::parse` | **P** | Все поля совпадают: `PACKET_HDR` (id/hw_protocol/hook при vlen≥7), `PAYLOAD`, `CAP_LEN`, `SKB_INFO`, `MARK`, `TIMESTAMP` (sec/usec, границы), `IFINDEX_OUTDEV`. **Расхождение `truncated`:** C `out->truncated = cap_len > payload_len` даже при отсутствии `PAYLOAD` (`payload_len=0`), Rust `cap_len.zip(payload).is_some_and(cap>len)` — без `PAYLOAD` даёт `false`. Тесты `:371`, `:403` этот случай не покрывают. |
| `d2k_nl_errno` | 163–176 | 14 | знаковый errno из NLMSG_ERROR | `netlink.rs:183 kernel_error` | E | `:429 kernel_error_reads...` |
| `hdr_init` (static) | 181–197 | 17 | nlmsghdr+nfgenmsg | `netlink.rs:263 header` | E | `:332` |
| `put_attr` (static) | 200–216 | 17 | атрибут + zero padding | `netlink.rs:274 push_attr` | E | `:321` |
| `d2k_nl_verdict` | 218–234 | 17 | VERDICT | `netlink.rs:188 verdict` | E | `:304` |
| `d2k_nl_verdict_payload` | 236–252 | 17 | VERDICT+PAYLOAD | `netlink.rs:203 verdict_payload` | E | `:321` |
| `d2k_nl_cfg_cmd` | 254–273 | 20 | CONFIG BIND/UNBIND, ACK | `netlink.rs:219 config_command` | E | `:332` |
| `d2k_nl_cfg_params` | 275–309 | 35 | PARAMS/MAXLEN/FLAGS/MASK | `netlink.rs:234 config_params` | E | `:332` |

### nl.c: построчная сверка

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

## icmpguard.c (7 функций)

Отсечение ICMP time-exceeded на свои фальшивки с пониженным TTL.
R2O: `r2o_icmp_guard.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_icmpguard_init` | 6–8 | 3 | обнулить кольцо 256 | `Default for R2oIcmpGuard` (`:32`) | **E** | C `memset`, Rust `[Slot::default(); 256]` + счётчики 0. |
| `u16` (static) | 10 | 1 | big-endian u16 | `r2o_icmp_guard.rs:257 r2o_u16` | **E** | C `(p[0]<<8)|p[1]`; Rust `from_be_bytes` с проверкой границ через `get`. |
| `parse_ip` (static) | 21–47 | 27 | IP-заголовок цитаты: IPv4/IPv6, proto 6/17, отказ non-first fragment, `n>=hl+8` | `:204 r2o_parse_icmp_quote` | **P** | Построчно совпадает: family по версии; IPv4 `n>=20`, `hl=(p[0]&15)*4>=20`, `fragment & 0x1fff == 0`; IPv6 `n>=40`, `ip_id=0`; proto 6/17; `transport=get(hl..hl+8)`. Rust checked-арифметика (`checked_add`) вместо C `n<hl+8`. Unit-тестов в модуле нет; differential `test-icmp-guard-current-differential.sh` есть. |
| `d2k_icmpguard_note` | 49–69 | 21 | запомнить фальшивку: `ttl<orig_ttl`, ring 256, `at=now?now:1`, family/proto/ttl, src/dst, ports, l4word, ip_len, ip_id | `:56 r2o_note` | **P** | C для UDP копирует в `l4word` 2 байта (остаток занулён `memset`), Rust всегда копирует `transport[4..8]` (4 байта); `check` для UDP сравнивает только 2, поэтому на результат не влияет. `have_id = family==4 && ip_id!=0`, `at=max(now,1)`, ring 256 — совпадают. Differential `test-icmp-guard-current-differential.sh`. |
| `d2k_icmpguard_check` | 71–110 | 40 | ICMPv4 type 11/0, v6 type 3/0; `fragment & 0x3fff`, цитата family, 7 полей, `q.ttl<=s.ttl`, dropped++ | `:90 r2o_check`, `:175 r2o_icmp_quote_start` | **P** | C и Rust совпадают: IPv4 len/ihl/proto 1/`0x3fff`/type 11 code 0; IPv6 len 48/proto 58/type 3 code 0; `quote_start=hl+8/48`; `parse_ip` цитаты; family match; слоты 256, `at!=0`, `now>=at`, `now-at<=5с`, family/proto, src/dst (4/16), sport/dport, l4word (TCP 4/UDP 2), ip_len, `have_id/ip_id`, `q.ttl<=slot.ttl`; иначе dropped++. Отличие только в представлении (`memcmp` ↔ срезы). Unit-тестов в модуле нет; differential есть. |
| `d2k_icmpguard_dropped` | 112 | 1 | счётчик снятых | `:149 r2o_dropped` | **E** | Прямой getter; `u64` saturating/wrapping-add. |
| `d2k_icmpguard_noted` | 113 | 1 | счётчик запомненных | `:145 r2o_noted` | **E** | Прямой getter; `u64` saturating/wrapping-add. |

### icmpguard.c: построчная сверка

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

### http80.c: построчная сверка

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

## http_trace.c (1 функция)

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_http_trace` | 9–50 | 42 | строка `d2kd: HTTP execution host=... IPv4/6 [src]:cport -> [dst]:80 seq=... hook/mark/outdev/status/prepared/plan/execution/planned/raw_sent/queued/original/output_failed/reason` | нет: grep `HTTP execution` по R2O пуст | **N** | C: TCP/80, method заглавными + пробел, `d2k_http_request` иначе `host=<unparsed>`, `inet_ntop`, plan hex или `-`, status `OBSERVE/SKIPPED/FAILED/PENDING/COMPLETE`, seq/hook/mark/outdev, execution, planned/sent/queued, original `ACCEPT/DROP`, output_failed, reason; возвращает длину с усечением до `cap-1`. В R2O есть события портала/ответа и журнал, но **нет** этой текстовой строки; N подтверждён. |

## journal.c (14 функций)

Кольцо журнала наблюдений: kinds, коды suspect/refuse, очистка имени, plan/trial/
execution/binding, added/dropped. R2O: `flow_journal.rs`.

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

## nat.c (5 функций)

Внешний адрес/порт из `/proc/net/nf_conntrack`: разбор строк, «лучшая запись» по
TTL, отличие «нет таблицы» от «нет записи». R2O: `proc_nat.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `parse_ip4` (static) | 20–41 | 22 | строгий IPv4: 4 десятичных октета 0..255, ровно точки и NUL | `proc_nat.rs:145 parse_ipv4` | **P** | C принимает ведущие нули (`001`→1), отвергает пустой октет, `>255`, лишние символы/точки. Rust `split('.')`, все ASCII-цифры, `checked_mul/checked_add`, `<=255`, ровно 4 части — эквивалентно. Unit-теста на отказы нет; differential есть. |
| `field_after` (static) | 46–63 | 18 | найти `name=` на границе слова, вернуть значение до пробела/`\n`, сдвинуть `next` | `proc_nat.rs:122 field_after`, `:113 fields` | **P** | C `strstr` + проверка `p==s||p[-1]==' '` + `p[nl]=='='`, режет копию строки. Rust сначала токенизирует строку по ASCII-пробелам в `(key,value)`, затем ищет **точное** имя. Для нормальной строки эквивалентно; Rust строже к `src=` внутри значения другого поля. |
| `d2k_nat_outside` | 67–73 | 7 | IPv4-обёртка: family=4, src/dst как 4 байта | `:20 lookup` с tuple family=4 | **P** | C передаёт указатели на `uint32_t` и family 4; Rust `R2oConntrackTuple.family=4`, адреса 16-байтные с нулевым хвостом. Эквивалентно. |
| `parse_address` (static) | 75–82 | 8 | IPv4 через `parse_ip4`, IPv6 через `inet_pton`, out[16] занулён | `:134 parse_address` | **P** | C `memset(out,0,16)`, v6 `inet_pton(AF_INET6)`, v4 `parse_ip4` + 4 байта. Rust `Ipv6Addr::from_str` / `parse_ipv4`, 16-байтный массив. Оба не принимают `%zone`; unit-теста нет. |
| `d2k_nat_outside_family` | 84–194 | 111 | fopen; 1 — нет таблицы, -1 — нет записи, 0 — найдено; строки >1022 пропуск; direct/reverse tuple; best TTL (3-е число) | `:20 lookup` → `R2oProcNatLookup` | **E** | C `fopen` fail → 1, Rust `TableMissing`; пустая/без записи → -1/Missing; найдено → 0/Found. Совпадают: `fgets(1024)` + drain длинной строки ↔ `read_until` + `content_len>1022`; `strstr(tcp/udp)`; direct `src/dst/sport/dport`; reverse `dst/dport`; `third_number`; `ttl<=best` skip; memcmp адресов/портов. Тест `:220 отличает_отсутствие_таблицы...` + `r2o-nat-proc-differential.sh`; в этом проходе не перезапускались. |

### nat.c: построчная сверка

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

### ctq.c: построчная сверка

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

## sched.c (16 функций)

Двоичная куча отложенной отправки по (due, seq), владение NFQUEUE ID,
выбрасывание слишком длинной головы. R2O: `scheduler.rs` (отсортированный Vec +
flow-брони).

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

### sched.c: построчная сверка

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

## wire.c (9 функций)

Единственное место расчёта контрольных сумм TCP: TTL по измеренному пути,
опции, MD5, seq_shift, badsum, IPv4/IPv6. R2O: `r2k-core/src/wire.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `wr16` (static) | 23–26 | 4 | big-endian u16 | `wire.rs:552 write_u16` | E | golden-тесты wire.rs |
| `wr32` (static) | 28–33 | 6 | big-endian u32 | `:556 write_u32` | E | — |
| `rd16` (static) | 35–37 | 3 | big-endian u16 | `u16::from_be_bytes` в `:436` | P | — |
| `auto_ttl` (static) | 54–70 | 17 | TTL по rev_ttl: origin 64/128/255, delta, min/max, clamp 1..255; 0 если нельзя | `plan/apply.rs:764 poison_ttl` | **E** | Формула совпадает: первый `origin` из 64/128/255 ≥ rev_ttl, `hops=origin-rev_ttl`, `+delta`, `max`, `min`, `clamp(1,255)`. C при rev_ttl=0/нет origin возвращает 0, Rust `poison_ttl` — `poison.ttl`, далее `emission_ttl` даёт original/64; итог тот же. Тест `engine.rs:2120`. |
| `sum16` (static) | 73–82 | 10 | RFC1071 | `wire.rs:534 sum16` | **E** | Пословное сложение BE с нечётным хвостом; golden wire. |
| `fold` (static) | 84–89 | 6 | свёртка и инверсия | `:545 checksum_value` | **E** | Точное совпадение. |
| `pseudo_sum` (static) | 99–107 | 9 | IPv4 псевдозаголовок TCP | `:516 pseudo_sum` | **E** | C строит 12-байтный ph, Rust складывает src/dst+6+len; для IPv4 эквивалентно. |
| `d2k_wire_build` | 109–277 | 169 | сборка TCP: профили 0/DETECT/TEMPLATE, MD5, TS/TS-up, seq_shift, poison, суммы | `wire.rs:18 build_tcp_packet` | **P** | **Совпадает:** family 4/6, urgent, ipfrag/profile, MD5 только measured, native options ≤40/кратность 4, TS 8/10 уникальна, TS-back `-1000`, TS-up перенос 10 байт, IPv4 ID 0/random/native+1, measured DF=0/window=65535, IPv6 IPID_ZERO reject, MD5-байты 19/18/1/1, TS NOP/NOP/8/10, badsum measured `^0xbeef`/0x1234 vs legacy `~`/0xffff. **Отличия:** C берёт src/dst/ports/ack/window/ttl/ip_id/traffic_class/flow_label/options из `d2k_conn`, Rust — из входного `PacketView`/`TcpSegmentView`; C `measured` IP-ID — `random()%65535`, Rust — `getrandom()%u16::MAX` (разный источник); C допускает `family=0` как IPv4, Rust требует 4/6. 12 golden/дифференциалов покрывают шаблон/TS-up/badsum/measured/MD5/v6/capacity, но не равенство RNG и не conn-vs-input. |
| `d2k_wire_tcp_checksum_ok` | 279–306 | 28 | IPv4: версия/proto/ihl/total; IPv6: len≥60/proto 6/base-only; сверка суммы | `wire.rs:436 tcp_checksum_ok` | **P** | Для базовых IPv4/IPv6-пакетов формула та же (`pseudo_sum`+`sum16`+`fold==0`). C IPv6 смотрит только основной заголовок (`pkt[6]==6`, len≥60), Rust `PacketView` допускает цепочку padding-extension headers; C `total<ihl`/ihl<20 — аналогично. Различается набор принимаемых ext-header пакетов; тесты wire/http_replace покрывают базовые. |

### wire.c: построчная сверка

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

## wire_udp.c (5 функций)

Сборка UDP-датаграммы IPv4/IPv6; отказ неприменимым искажениям, обязательная
сумма (0→0xffff). R2O: `wire.rs::build_udp_packet`.

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

## addr.c (3 функции)

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_addr_parse` | 5–18 | 14 | IPv4/IPv6 литерал, отказ `%zone`, family 4/6 | `r2k-core/src/addr.rs:11 Address::parse` | **E** | C отвергает NULL и любой `%`, `inet_pton(AF_INET)` затем `AF_INET6`, family 4/6. Rust `IpAddr::parse` отвергает host/zone, те же семейства; `network.rs:6`, `:22` (включая `fe80::1%eth0`). Форматы ввода совпадают. |
| `d2k_addr_text` | 20–30 | 11 | `inet_ntop`, отказ при неизвестной family; `n>=cap`→0, иначе копия+`\0`, вернуть n | `addr.rs:49 Display` | **P** | C пишет в буфер `out/cap`, проверяет `n>=cap` и возвращает длину; Rust `Display`/`format!` не имеет буфера и не усекает, вызывающий сам выделяет строку. Текст IPv4/IPv6 совпадает, контракт «не влезло → 0» не портирован. |
| `d2k_addr_equal` | 32–36 | 5 | family совпадает, `memcmp` 4/16; неизвестная family → 0 | `addr.rs:5 PartialEq` | **E** | C сравнивает family+bytes, family 0/иная → 0; Rust derived `Eq` на `IpAddr` (V4/V6 — разные варианты). `network.rs:16`. |

### addr.c: построчная сверка

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

## tls.c (7 функций)

Разбор TLS ClientHello/ServerHello: границы claimed/avail, SNI, TLS1.3,
ECH, середина приветствия. R2O: `r2k-core/src/tls.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `rd16` (static) | 30–32 | 3 | big-endian u16 | `tls.rs:129 read_u16` | **E** | C `p[0]<<8|p[1]`; Rust `read_u16` с проверкой границ через `get`. |
| `skip_u8_vec` (static) | 36–46 | 11 | пропуск вектора с u8-длиной | `:141 skip_u8_vector` | **E** | C `off+1>len`/`off+1+n>len`; Rust `get`+`checked_add`, затем `next>end`. Эквивалентно; `:367`. |
| `skip_u16_vec` (static) | 48–58 | 11 | пропуск вектора с u16-длиной | `:158 skip_u16_vector` | **E** | C `rd16`+те же две проверки; Rust `read_u16`+checked. `:367`. |
| `has_ech_offer` (static) | 72–87 | 16 | структурно целый ECH 0xfe0d: type, n≥10, b[off]==0, enc≤n-10, payload>0 и ==n-10-enc | `:230 has_ech_offer` | **E** | C и Rust проверяют те же поля/границы; Rust checked-арифметика. Тест `:466`. |
| `has_tls13` (static) | 105–129 | 25 | supported_versions содержит 0x0304; если блок оборван — key_share | `:175 has_tls13` | **E** | C: `key_share` ставится до проверки длины, supported_versions с list_len и чётными версиями, иначе `truncated && key_share`; Rust тот же порядок и эвристика. `:411`, `:438`. |
| `find_sni` (static) | 131–177 | 47 | server_name→host_name; пустое/битое имя — отказ | `:274 find_sni` | **E** | C возвращает -1 при выходе extension/list/name за границы и при nlen==0; Rust `Option`/None с теми же проверками. `:445`, `:455`. |
| `d2k_tls_parse` | 179–361 | 183 | запись TLS, claimed/avail, ServerHello≥38, ClientHello, hello_middle, extensions, ECH/TLS1.3/SNI | `tls.rs:32 parse` | **E** | Построчно совпадает: `len<3`/`b[1]!=3`, `record_type`, `record_end` при полной записи, `record_type!=0x16`, `end=min(claimed,avail)`, ServerHello `sh_len>=38 && off+4+sh_len<=claimed`, ClientHello `hs_end<=claimed`, `hello_middle=off+hs_len/2` только при полном hello, 34 байта version/random, skip session/ciphers/compression, exts_len/claimed, `exts_truncated` при exts_end>hs_end, затем has_tls13/ECH/find_sni. Тесты `:367`-`:525`, `tls_parser` `:394`, fuzz-префиксы `:503`. |

### tls.c: построчная сверка

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

## include/*.h (14 inline-функций)

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---|---|---|---|---|
| `d2k_ctl_binding_write` (inline) | 86–90 | 5 | запись binding: BE u64 generation, kind/family/shape/temporary, 16-байтная epoch | `r2k-core/src/control.rs:330-347 AppliedEvent::event_body`, `:305 BindingContext`, `:2016/2051 encode_ack_with_binding` | **P** | Раскладка построчно совпадает (BE u64 + 4 байта + epoch). Roundtrip-тесты APPLIED/REFUSED/ACK (`:2528-2607`, `:2770+`, `:2168-2337`) проверяют кодирование/декодирование, но **C/Rust byte-differential отсутствует**; отдельного теста на все три места записи нет. |
| `d2k_ctl_binding_read` (inline) | 91–99 | 9 | чтение/валидация binding: n=28, kind≤4, family 0/4/6, shape≤MAX, temporary≤1 | `control.rs:2373 decode_applied`, `:2445 decode_refused`, `:3104 valid_binding` | **P** | Валидации совпадают: `kind<=4`, `family in {0,4,6}`, `shape<=SHAPE_ECH_TS`, temporary только 0/1. Тесты: REFUSED roundtrip/truncated (`:2528-2607`), APPLIED; ветки `kind=5`, `family=1`, `shape>MAX` отдельным тестом не покрыты. |
| `d2k_http_request_stream_init` (inline) | 19–21 | 3 | обнулить состояние, `start=next=seq`, `first=1` | `httpup.rs:64 R2oHttpRequestSequence::new` | **P** | Rust хранит только `first/next/checked/disabled`, без `start/head_len/end/length`; это другой уровень (трекер границ, не байтовый парсер). |
| `d2k_http_request_stream_line` (inline) | 22–30 | 9 | завершение строки: ровно один Host, конец ≤0x7fffffff, CL с цифрами | `httpup.rs:231 parse_plan_request`, `:219 parse_request`, `:382 find_crlf` | **P** | C завершает строку инкрементально и валидирует `hosts==1`, `length`, 10 цифр CL; Rust разбирает весь буфер и проверяет Host через `Option`, а `header_len/end_offset` вычисляет в конце. Промежуточного состояния строки нет. |
| `d2k_http_request_stream_feed` (inline) | 31–86 | 56 | потоковый разбор заголовка: CRLF, token, Host, CL, TE/Upgrade, end/past_end/invalid | `httpup.rs:116 observe_detailed`, `:73 candidate`, `:263-316 boundary_known` | **P** | **Расхождения:** C отвергает TE/Upgrade (`invalid`), Rust только `end_offset=None`; C отвергает управляющие байты и неверные имена полей, Rust помечает лишь `boundary_known=false` и продолжает; C ограничивает CL 10 цифрами, Rust — `usize`; C не валидирует DNS-значение Host, Rust требует `valid_dns_host`, снимает `:80` и точку. C игнорирует полностью старые байты, Rust — `candidate_state`; обе стороны считают `end<=0x7fffffff`. Отдельного C/Rust differential для потока нет. |
| `d2k_hr_decimal` (inline) | 21–29 | 9 | десятичное число с проверкой переполнения | `http_response.rs:360 parse_decimal` | **E** | Совпадает: пусто/нецифра → ошибка, `checked_mul/checked_add`; тест `rejects_malformed...` с `18446744073709551616` (`tests/http_response.rs:229`). |
| `d2k_hr_token` (inline) | 31–34 | 4 | допустимый token-байт RFC 7230 | `httpup.rs:346 is_http_token` | **E** | Набор символов совпадает; используется в `parse_plan_request` для имени заголовка запроса. В ответном парсере Rust этот предикат не применяется (см. `d2k_hr_field`). |
| `d2k_hr_field` (inline) | 35–42 | 8 | валидация поля: непустое имя, token, допустимые байты значения | `http_response.rs:281 parse_headers` | **P** | **Неполно:** Rust ищет `:` и разбирает известные поля, но не отвергает строку без `:`, не проверяет token-символы имени и управляющие байты значения; C делает всё это через `d2k_hr_field`. |
| `d2k_hr_extensions` (inline) | 43–70 | 28 | разбор chunk-extensions: `;token[=token/quoted]`, OWS, контрольные байты | `http_response.rs:372 parse_chunk_size` | **P** | **Неполно:** Rust отбрасывает всё после первого `;` и не валидирует extensions; C проверяет token, кавычки, escape и управляющие байты. Поэтому `1;\x01`, незакрытая кавычка и `1 ;x` дают разный исход. |
| `d2k_hr_headers` (inline) | 72–105 | 34 | разбор status-line и заголовков, CL/TE, interim, 101/204/304 | `http_response.rs:281 parse_headers`, `:321 parse_status_line` | **P** | **Расхождения:** C `head[8192]`, Rust 64 КиБ; C принимает status-line ровно 12 байт, Rust требует 13-й символ; C валидирует каждое поле и отвергает дубли Content-Length, Rust пропускает строки без `:` и разрешает одинаковые CL; C отвергает управляющие байты в заголовках, Rust после status-line их не проверяет. Логика interim/101/204/304/CL+TE совпадает. |
| `d2k_http_response_feed` (inline) | 107–160 | 54 | потоковый разбор ответа: header/fixed/chunk/trailer/close/fin | `http_response.rs:55 feed` | **P** | **Расхождения:** C при байтах после `complete` ставит `invalid`, Rust молча `break`; C `line[512]`, Rust 128; C валидирует trailer как поле и отвергает NUL, Rust принимает ведущий NUL как пустой trailer; C проверяет chunk-extensions, Rust игнорирует; C `head[8192]`, Rust 64 КиБ. Общая state-machine и `fin`-логика совпадают. |
| `d2k_packet_u16` (inline) | 20–22 | 3 | big-endian u16 | `packet.rs:231 read_u16` | E | Построчно совпадает; используется в `parse_ipv4/parse_ipv6` с bounds-check. |
| `d2k_packet_parse` (inline) | 24–70 | 47 | разбор IPv4/IPv6, fragment, extension headers, только Pad1/PadN, L4 minimum | `packet.rs:69 PacketView::parse`, `:152 parse_ipv4`, `:172 parse_ipv6`, `:203 has_only_padding_options` | E | IPv4: IHL/ total / fragment offset / ID / proto / TTL / TOS / адреса совпадают. IPv6: payload≠0, total=40+payload, TC/flow label, до 8 extension headers, Pad1/PadN; иные опции отвергаются. Тесты `r2k-core/tests/network.rs:36+`. |
| `d2k_key_equal` (inline) | 76–83 | 8 | равенство ключа: proto/ports/family/адреса; family 0 и 4 эквивалентны | `#[derive(Eq, PartialEq)]` (`capture.rs:13 TcpFlowKey`, `engine.rs:41`, `r2o_udp_hold.rs`, `session`) | **E** | Для ключей, созданных R2O, поля сравниваются все; family 4/6 представлена `Address`, legacy family 0 не используется. C-ветка `family==0` и `family==4` с `low_ip` эквивалентна Rust-ключу IPv4. Отдельного differential нет. |

### include/*.h (14 inline-функций)

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

- **`count_reason` (static, 165–186):** гистограмма причин отказа по
  указателю/строке, до 32 записей, печатается в итоговой сводке `d2kd`.
  R2O причины передаёт в `RefusedEvent`/журнал, но агрегированной таблицы
  и печати нет. N — диагностика, packet-path не меняет.
- **`offline_self_check` (static, 1118–1123):** `--offline-self-check`
  проверяет `D2K_CTL_PROTO_VERSION == D2K_RUNTIME_WIRE` и SHA-256("abc")
  по эталону. R2O SHA-256 покрыт `test-core-crypto-differential.sh`, но
  самой CLI-опции нет. N — CLI/self-check.
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

**Построчная сверка a378:** все 14 функций прочитаны. Кольцо `D2K_CTL_OUT_RING`,
кадр `HDR=6` (`plen` включает 2 байта типа, `plen>=2`), `D2K_CTL_FRAME_MAX`,
потеря кадра при нехватке места и `dropped++`, EAGAIN-дозапись, один пир,
`drop_peer` при ошибке чтения — совпадают с `control.rs` (`send_event`/`enqueue`/
`take_complete_frames`/`disconnect`). Отличия: R2O не отдаёт listen/peer fd,
не считает `sent`, hook разрыва вызывает цикл `main.rs`, а не объект; `open`
не удаляет чужой не-сокет и ставит 0600/backlog по умолчанию.

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
| read_probe_flow | 169-187 | 19 | static: разобрать flow адресного опыта, отвергнуть неканонический IPv4 | `control.rs:1695` `r2o_udp_addr_probe_flow_key` + `r2k-core/control.rs:1701` `valid_udp_addr_probe_flow` | **P** | **Расхождение:** C допускает `src_port=0` — голосовой опыт «любой клиентский порт» (`ctlsrv.c:302-304`), и не требует ненулевых адресов; Rust `valid_udp_addr_probe_flow` требует оба порта ≠0 и ненулевые адреса. R2O вынес голос в отдельную `SET_VOICE_ADDR_PROBE` (0x0095), которой в C нет: C-команды заканчиваются на 0x0093. Тестов SET/DEL/FIND адресного опыта в дереве нет. |
| d2k_ctlsrv_command | 189-509 | 321 | диспетчер команд, разбор тел, ACK, установка в таблицу | `control.rs:260` `NamePlans::handle`; `main.rs:68` `handle_control_command` (stall budgets); `control.rs:1988` `arm_client_shape` | **P** | Покрыты SET_NAME/BOUND/PROBE/ADDR/SUFFIX/BYPASS/DEL_*/HTTPS/ARM_SHAPE/STALL_BUDGETS (control.rs:2633-3896). **Подтверждённые расхождения:** (1) `SET_HTTPS`: C обрезает TTL до **7 суток** (`d2k_ctl.h:231`, `ctlsrv.c:446`), R2O отвергает `> 6 часов` (`control.rs:64,1070,1781`); (2) `ARM_SHAPE`: C принимает transport 6/17 (`ctlsrv.c:341`), R2O — только 6 (`control.rs:2002`); (3) `SET_ADDR_PROBE`: C допускает `src_port=0` для голоса (`ctlsrv.c:302-304`), R2O generic-проба требует оба порта ≠0, а голос вынесен в `SET_VOICE_ADDR_PROBE` 0x0095, отсутствующую в C; (4) `DEL_NAME_PROBE`: C не проверяет shape (`ctlsrv.c:422-437`), R2O проверяет; (5) адресные опыты не тестированы; (6) `SET_NAME`/`SET_SUFFIX`: C не проверяет `shape` (передаёт `b[1+len]` в plantab), Rust `encode_set_name`/`encode_set_suffix` отвергает неизвестные формы; (7) `DEL_NAME`: C принимает любую пару `transport` (6/17) + `shape != ANY`, Rust `encode_delete_name` — только 6 с 1/2/4/6/7/8..13 или 17 с 3/5. C `DEL_NAME_BOUND`/`DEL_ADDR_PROBE` идемпотентны и всегда ACK OK — R2O так же. |
| d2k_ctlsrv_pump | 511-694 | 184 | выгрузить новые записи журнала в события с раскладкой по типам | `main.rs:2728` `send_journal_updates`, `:2709` `send_journal_snapshot`; `flow_journal.rs:202` `to_event_frame` | **P** | C: `PLAN_APPLIED` не отдаётся вовсе (`ctlsrv.c:566-568`), `PLAN_DONE→APPLIED`, `REFUSED/UNSENT/DAMAGED→REFUSED`, `SHAPE→CLIENT_TCP+SHAPE`, `HELLO/SUSPECT/EXCHANGE` — своими типами. R2O `send_journal_updates` шлёт каждую запись как `EVENT_R2O_JOURNAL_ENTRY`, а dedicated-события (`EVENT_APPLIED/REFUSED/CLIENT_SHAPE/HELLO`) идут отдельными путями; контроллер декодирует journal entry только для печати (`main.rs:7148,17948`), доказательства — через dedicated. `PlanApplied` не становится `EVENT_APPLIED` ни там, ни там. Пробел v22: `EVENT_LEGACY_CLIENT_TCP` шлёт пустые TCP-опции (`r2k-core/control.rs:1212-1215`), C — реальные. |
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
| d2k_plan_apply | 343-873 | 531 | превратить план+пакет в посылки, судьбу оригинала и причину отказа | `plan/apply.rs:155` `Plan::apply` | P | 17 тестов tests/apply.rs покрывают split/fake/overlay/order/pace/settle/delay/udplen/qsplit/qdeny/oob/metric. Пробелы: `MAX_EMISSIONS = WIRE_BATCH_MAX = 26` (`plan.rs:10`, `apply.rs:9`) против 65536 в C (`plan_apply.c:830`) — R2O отвергает раньше; однако D2O на выдаче в session тоже ограничивает 26 (`D2K_RESULT_MAX`, session.c:2517), поэтому наблюдаемый отказ совпадает, различаются слой и текст ошибки. В OOB-ветви `suffix.wire_profile` остаётся 0: Rust ставит профиль только `first` и `urgent` (`apply.rs:284-285`), а `suffix` создан без него; C на `finalize` проставляет профиль **всем** посылкам (`plan_apply.c:812`). qsplit-ветвь обходит `delay_us`: Rust возвращает `Actions` в `apply.rs:203-260` до блоков pace/settle/delay (`:640-657`), тогда как C применяет `delay_us` после цикла кусков, включая qsplit (`plan_apply.c:803-809`). Лимит 26 — слой R2O: D2O `plan_apply.c` допускает до 65536, но `session.c:2517` всё равно отказывает при >26, поэтому наблюдаемый отказ совпадает. |
| d2k_actions_cancel | 891-921 | 31 | правила отмены недосланного исполнения | `plan/apply.rs:104` `Actions::cancel` | E | `cancellation_drops_only_after_payload_bytes_were_emitted` (tests/apply.rs). |
| d2k_actions_free | 923-931 | 9 | освободить посылки | `plan/apply.rs:61` `Emission` + `Actions` (RAII) | E | Освобождение автоматическое; отдельных ошибок/утечек нет по типам. |

Итог по файлу: E 14, P 1, N 0. Главные отличия — потеря `wire_profile` в OOB-суффиксе,
обход `delay_us` в qsplit и место отказа при >26 посылках (D2O тоже отказывает в session,
но позже).
у OOB-суффикса.

**Построчная сверка a378:** все 15 функций прочитаны. Подтверждены три расхождения
`d2k_plan_apply` (`plan_apply.c:343-873`) с `apply.rs:155-300/600-670`:
(1) OOB: C на `finalize` проставляет `wire_profile` всем посылкам (`:812`), Rust — только
`first` и `urgent`, `suffix` остаётся 0; (2) qsplit: Rust возвращает `Actions` до
`apply_timing`, поэтому `delay_us` не применяется, C применяет его после всех ветвей
(`:803-809`); (3) предел `MAX_EMISSIONS=26` в Rust против 65536 в C, но `session.c:2517`
всё равно отказывает >26, поэтому наблюдаемый отказ совпадает. Остальные helper'ы
(`anchor_offset`, `split_points`, `tls_ch_layout`, `fake_tls_bytes`, `emit_fake`,
`max_emit`, `cancel`) совпадают с тестами `tests/apply.rs`.

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
| d2k_plan_load | 345-566 | 222 | полная загрузка: заголовок, scan, записи, check_refs, транспорт | `plan.rs:190` `Plan::parse`, `:167` `parse_wire` | **P** | **Подтверждённое расхождение:** повторный `REC_AUTOTTL` для той же порчи C применяет «последний побеждает» (`plan_parse.c:473-486`), Rust `autottl.replace` отвергает повтор (`plan.rs:307`). Остальное совпадает: 7 тестов tests/plan.rs, legacy `D2KP` через `parse_wire`, magic `R2OP`. C/Rust differential на дубликат autottl нет. |
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
`plan.rs:687-845/499-685` по всем типам записей, длинам, minexec и сочетаниям; отличие —
повтор `AUTOTTL` (C last-wins, Rust отказ), поэтому `d2k_plan_load` переведён в P.
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

## 6. datapath/plans.c — 75 функций

Таблица планов по целям: ключи имя/адрес/суффикс, LRU-вытеснение, точные пробы, поиск на
пакетном пути. R2O-аналог — `NamePlans` в `crates/r2o-datapath/src/control.rs`
(`HashMap`-ключи вместо уплотнённого массива, `Cell<u64>`-часы вместо `last_used_ns`).

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
| d2k_plantab_has_ech_target | 288-314 | 27 | есть ли ECH-привязка имени/адреса для трёх ECH-форм, с учётом `only_sport` и BYPASS; затем суффиксы | — | **?** | Прямого предиката нет. C проверяет `ECH_TCP/ECH_NO_TS/ECH_TS`, точное имя/адрес, `only_sport==sport`, исключает BYPASS для не-точных записей и отдельно перебирает три ECH-суффикса (`plans.c:288-314`). R2O собирает неполный ClientHello общим путём `capture.rs`/`engine.rs`, без привязки к наличию ECH-target; адресного differential нет. Нужен тест «ECH-привязка есть → обрывок удерживается; нет → не удерживается». |
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

## 7. datapath/raw.c — 17 функций

Сырой сокет: пределы длины, MTU маршрута, отправка без ожидания. R2O:
`crates/r2o-datapath/src/raw.rs` (`RawSocket`).

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
| rd16h | 27-27 | 1 | static: u16 host order через `memcpy` | `u16::from_ne_bytes` (`r2o_route.rs:1098` и др.) | **E** | `r2o_разбор_правил_учитывает_маску_инверсию_и_завершение_дампа` (`r2o_route.rs:1109`). |
| rd32h | 28-28 | 1 | static: u32 host order | `u32::from_ne_bytes` (`:735`, `:747`) | **E** | Те же тесты разбора. |
| wr16h | 29-29 | 1 | static: записать u16 host order | `to_ne_bytes` (`:683`, `:696`) | **E** | `r2o_запросы_содержат_семейство_последовательность_и_адрес_поиска` (`:1086`). |
| wr32h | 30-30 | 1 | static: записать u32 host order | `to_ne_bytes` (`:685`, `:698`) | **E** | Тот же тест. |
| d2k_routemark_init | 32-34 | 3 | `memset` всего состояния, включая `rules_read*`/`policy_on` | `impl Default for R2oRouteGate` (`:107-116`) | **E** | Все тесты создают `R2oRouteGate::default()`; поля-`Option` дают «неизвестно». |
| d2k_routemark_request | 36-46 | 11 | `RTM_GETRULE`, `NLM_F_REQUEST/DUMP`, seq, family в `fib_rule_hdr[0]` | `r2o_route_rule_request` (`:679-690`) | **E** | Совпадает: длина 28, тип 34, flags 0x301, seq, family; тест `:1086`. |
| nl_error | 49-51 | 3 | `body_len>=4` → знаковый errno, иначе 0 | `r2o_kernel_error` (`:863-872`) | **P*** | **Отличие только в коротком теле:** C возвращает 0 и парсер даёт общую ошибку «ответ не разобран»; Rust возвращает `Malformed`. Оба отвергают дамп, но классификация разная; теста на `NLMSG_ERROR` короче 4 байт нет. |
| d2k_routemark_parse | 53-95 | 43 | обход `NEWRULE`: family[0], flags[8..12] invert, FWMARK/FWMASK (alen≥8), mask по умолчанию `0xffffffff` при ненулевой метке, `mask==0` пропуск, DONE→1 | `r2o_route_parse_rules` (`:711-766`) | **P** | **Совпадает:** FWMARK/FWMASK, `mark &= mask`, invert, `mask=0`, DONE, ошибка на хвосте ≥4. **Подтверждённые отличия:** (1) C принимает **любой** `family` и кладёт его в селектор, Rust — только 2/10, остальные пропускает; (2) C при `*n >= cap` всё равно увеличивает `*n` (переполнение видно вызывающему и обрезается в `merge`), Rust `r2o_dump_rules` при >32 правилах **возвращает ошибку** (`:437-443`); (3) `nl_error` на коротком теле. Тест `:1109`. |
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

## 9. datapath/routemark_nl.c — 8 функций

Rtnetlink: дампы правил, одиночный поиск маршрута, подписка на изменения. R2O:
`R2oRouteMonitor` в `crates/r2o-datapath/src/r2o_route.rs`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| parse_rules | 18-21 | 4 | static: адаптер сигнатуры под `d2k_routemark_parse` | замыкание в `r2o_dump_rules` (`r2o_route.rs:402-420`) | **E** | Тонкий адаптер; владелец `r2o_route_parse_rules`, тест `:1109`. |
| dump | 27-59 | 33 | static: `sendto`, до 4096 `recv`, EINTR, парсер до DONE; `-EAFNOSUPPORT/-EOPNOTSUPP` → пустой успех; иная ошибка ядра/разбор → -1 | `r2o_receive_request` (`:458-557`) + ветка `r2o_dump_rules` (`:406-412`) | **P** | **Совпадает:** sendto, буфер 32768, 4096 раундов, EINTR, DONE, ошибка ядра, SO_RCVTIMEO 200 мс. **Подтверждённое отличие:** C трактует `-EAFNOSUPPORT/-EOPNOTSUPP` как пустой успех для **любого** семейства; Rust делает это только для IPv6-правил (`family == Ipv6 && matches!(code, -97 / -95)`), для IPv4 — ошибка. |
| dump_rules | 61-67 | 7 | static: запрос правил family + `dump` с пределом `D2K_ROUTEMARK_MAX=32` | `r2o_dump_rules` (`:398-453`) | **P** | **Подтверждённое отличие:** C при >32 правилах не ошибается: парсер считает `*n` сверх cap, `merge` усекает и выставляет `truncated`; Rust при `selectors.len()+batch > 32` возвращает `InvalidData` и **не сохраняет** семейство (остаётся прежний набор). Тест на переполнение отсутствует. |
| lookup_route | 72-110 | 39 | static: один `RTM_GETROUTE`, до 4 `recv` по 8192; rc 1→0/2, rc 2→3; `ENETUNREACH/EHOSTUNREACH/ENETDOWN/EAFNOSUPPORT` → 3 | `r2o_lookup_default` (`:455-515`) | **P** | **Совпадает:** один lookup, коды 2/3, набор errno `-97/-100/-101/-113`, пустой Unicast → «нет устройства» (2). **Отличия:** C 4 раунда × 8192, Rust 4096 × 32768; C при исчерпании — «нет ответа», Rust — `Pending`/ошибка. Проверено парсером и живым IPv4-тестом, не всеми кодами. |
| dump_socket | 115-128 | 14 | static: `AF_NETLINK/SOCK_RAW/CLOEXEC`, `SO_RCVTIMEO=200000` | socket+SO_RCVTIMEO в `r2o_receive_request` (`:463-530`) | **E** | Флаги/таймаут совпадают; C переиспользует сокет до ошибки части, Rust создаёт на каждый запрос — наблюдаемое поведение то же. `r2o_монитор_читает_правила...` (`:1240`). |
| d2k_routemark_load | 130-177 | 48 | 4 независимые части: правила v4/v6, маршруты v4/v6; после ошибки — новый сокет; merge+oifs; `routes4_ok/routes6_ok`, первый текст ошибки, -1 если все части упали | `r2o_refresh` (`:372-397`) | **P** | **Совпадает:** порядок 4 частей, независимость семейств, сохранение прежнего при ошибке, `rc==2` → пустой список oifs (без гейта). **Не перенесены:** `routes4_ok/routes6_ok`, `st->found/truncated`, `changed`, «первая ошибка» как единый текст; Rust возвращает `Vec<String>` всех ошибок. Сокет на каждый запрос, а не после сбоя. |
| d2k_routemark_watch_open | 179-209 | 31 | `SOCK_NONBLOCK`, bind, 4 группы: 8/7 обязательны, 19/11 опциональны | `r2o_open_watch` (`:283-332`) | **E** | Группы/обязательность совпадают: `(8,true),(7,true),(19,false),(11,false)`; bind/CLOEXEC/NONBLOCK те же. `r2o_монитор_читает_правила...` (`:1240`) вызывает open, но результат намеренно не проверяется — обязательность IPv4 тестом не подтверждена. |
| d2k_routemark_watch_drain | 211-228 | 18 | до `D2K_ROUTEMARK_WATCH_READS=256`; `>0` → relevant, EINTR, ENOBUFS→1, иное/0 → вернуть накопленное; исчерпание → 1 | `r2o_drain_watch` (`:334-370`) | **E** | 256 чтений, `MSG_DONTWAIT`, EINTR/ENOBUFS/EAGAIN и «предел → true» совпадают. Тест на границу отсутствует, но код построчно эквивалентен. |

Итог по файлу: E 4, P 4, N 0. Пробелы: обработка `EAFNOSUPPORT` для IPv4-правил,
переполнение >32 правил (C усекает с `truncated`, Rust ошибается), внешние
`routes4_ok/routes6_ok/found/truncated`, лимиты раундов lookup.

---

## 9a. Углублённая сверка 5 N-функций

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
  длины, ACK-коды, идемпотентные DEL. Расхождения: SET_HTTPS 7 суток
  vs 6 часов; ARM_SHAPE 6/17 vs 6; SET_ADDR_PROBE `src_port=0` vs
  требование ≠0 + отдельная 0x0095; DEL_NAME_PROBE shape не
  проверяется в C. Остальные ветви (SET_NAME/BOUND/PROBE/ADDR,
  SUFFIX/BYPASS, DEL_*, STALL_BUDGETS) совпадают по полям и ACK.
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
   реализован в цикле; `SET_HTTPS` отвергает TTL > 6 часов вместо обрезки до 7 суток;
   ARM_SHAPE не обслуживает UDP; v22 CLIENT_TCP идёт с пустыми TCP-опциями.
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
| P | 100 |
| N | 10 |
| ? | 0 |
| **Всего** | **159** |

Доли: E — 30.8 % (49/159); E или P — 93.7 % (149/159); N — 6.3 % (10/159).
P не считается доказанным паритетом: это покрытие без полного доказательства ветвей.

По файлам:

| Файл | Функций | E | P | N |
|---|---:|---:|---:|---:|
| detect/bridge.c | 17 | 2 | 14 | 1 |
| detect/classify.c | 36 | 16 | 18 | 2 |
| detect/main.c | 8 | 0 | 8 | 0 |
| detect/poison.c | 12 | 8 | 4 | 0 |
| detect/props.c | 7 | 0 | 7 | 0 |
| detect/raw.c | 62 | 13 | 42 | 7 |
| detect/response.c | 7 | 7 | 0 | 0 |
| detect/trigger.c | 9 | 3 | 6 | 0 |
| detect/include/d2k_detect.h | 1 | 0 | 1 | 0 |
| **Всего** | **159** | **49** | **100** | **10** |

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
| `d2k_detect_stop_all` | 45-45 | 50 | липкий общий флаг остановки службы | `Drop for DiscoveryWorker` (`main.rs:14251-14261`) | **P** | Отдельного глобального флага нет, но остановка службы достижима: `Drop` взводит `cancel` и все `active_cancels`, будит jobs и join-ит потоки. Нет C/Rust differential на «остановить все» и липкость флага. |
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
| `d2k_resp_name` | 74-82 | 255 | имена `clear/blocked/flaky`, default `not_applicable` | classify_json.rs:103-109, main.rs:1278-1283 | **P** | C один switch с точными строками; Rust те же имена разнесены по `classify_json.rs` и `main.rs`, единой функции/теста имён нет. Нужна сверка default-ветви. |
| `d2k_now_ms` | 86-91 | 188 | монотонное время в мс | Instant (classify.rs:1307, 1937) | P | инъекции d2k_clock_offset_ms нет |
| `d2k_sleep_ms` | 96-105 | 194 | пауза между сегментами | thread::sleep (raw_probe.rs:1238, response.rs:856) | P | отдельного символа нет, семантика nanosleep совпадает |
| `d2k_trigger_accepts` | 109-124 | 903 | критерий прохода по типу accept | classify.rs:543 trigger_accepts | E | tests/classify.rs:833 trigger_acceptance_matches_the_donor_rules |
| `d2k_trigger_sni` | 126-134 | 236 | извлечь SNI из имени триггера | classify.rs:1461 strip_prefix("tls:") | P | inline strip_prefix; прямого теста нет, ответная ветка CLI-теста может не дойти |
| `d2k_detect_stopped` | 136-139 | 92 | проверка отмены | classify.rs:1041 stopped, raw_probe.rs:641 is_cancelled | E | tests/classify.rs:818 и cancellation_after_* в classify.rs:2596+ |
| `d2k_opts_defaults` | 141-162 | 815 | умолчания: repeats 3, timeout 6000, write_gap 60, long_gap 700, mark `D2K_BYPASS_MARK` | classify.rs:860 Default, 1888 configured_options | **P** | **Подтверждено:** C `D2K_BYPASS_MARK=0x40000000` (`detect/include/d2k_detect.h:34`, `classify.c:160`); Rust `BYPASS_MARK=0x2d` (`raw_probe.rs:23`, `response.rs:71`). Числа повторов/сроков совпадают; метка зонда по умолчанию разная — влияет на policy-routing/SO_MARK. |
| `d2k_opts_acceptable` | 164-170 | 153 | фильтр приемлемости находки | raw_probe.rs:1122 executable_poison_hit | P | общего колбэка accept нет; в CLI R2O фильтр плана включён всегда, в C CLI accept не задан |
| `d2k_opts_skipped` | 172-181 | 206 | пропуск гипотезы по имени | classify.rs:885 poison_selected | P | --only/--skip сведены в одну функцию, профильного теста нет |
| `d2k_trace_add` | 183-204 | 1018 | добавить наблюдение в трассу | classify.rs:1048 add_observation | E | tests/classify.rs:384 classifier_reports_each_question_and_probe_as_it_runs |
| `obs_done` | 210-215 | 133 | объявить наблюдение наружу | classify.rs:1235 progress callback | E | tests/classify.rs:384; колбэк вызывается в measure |
| `d2k_note` | 217-227 | 264 | до `D2K_NOTES_MAX` заметок в `res->notes[]` через `vsnprintf` | classify.rs:1248 append_reason | **P** | C хранит массив отдельных notes и счётчик; Rust `append_reason` дописывает текст в одно поле `reason`, массива/лимита notes нет. Для `note_gap_loss` отдельного аналога нет (N). |
| `note_gap_loss` | 238-247 | 504 | предупреждение о потере паузы между копиями | — | N | такой оговорки в R2O нет |
| `d2k_split_offsets` | 253-287 | 915 | точки разреза в диапазоны | classify.rs:28 split_offsets | E | tests/classify.rs:337, :349, :361 |
| `dial_marked_mode` | 292-364 | 2591 | TCP-connect с меткой: `require_mark`, различение отказа `SO_MARK` и обычного connect | response.rs:723 dial_probe_target, :289 probe_socket | **P** | C принимает `require_mark` и отдельно разбирает отказ установки метки; Rust `dial_probe_target`/`probe_socket` не имеют `require_mark` и различают только общий connect/SO_MARK error. P — нужен тест «SO_MARK запрещён». |
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
| `sweep_poisons` | 887-1076 | 8251 | перебор: свойства, сборка, RST-правило, selftest, список гипотез, контроль | raw_probe.rs:78 sweep_poisons | **P** | C ведёт trace о непринятом RST-правиле, отдельный текст selftest и compose при `control=None`; Rust `sweep_poisons` часть диагностики не выносит, текст selftest иной, а `d2k_compose_from_props` при `control=None` ведёт себя иначе (header, п. 6). P. |
| `cross_check_tls12` | 1084-1092 | 367 | проверка покрытия TLS 1.2 | — | N | C-заглушка не перенесена, поля covers_tls12 нет |
| `d2k_classify_run` | 1095-1476 | 22179 | дерево зондов и вердикт | `classify.rs:1298` `run_with_backend_progress` | P | Нет notes/`covers_tls12`, иной счёт probes ответного направления. **Ключевое:** production-discovery использует `full_detect_semantics=false`, `confirm_clear=true` (`classify.rs:869-870`, `main.rs:15380-15391`), то есть не donor-семантику C: нет удвоенного dial-retry, иначе обрабатываются частичные transport-ошибки, control без `until_pass`, добавлен whole-confirm. Существующие дифференциалы идут с `full_detect_semantics=true` и этот путь не покрывают. |
| `d2k_send_nosig` | 1481-1494 | 309 | `send` с `MSG_NOSIGNAL` (если есть) и `SO_NOSIGPIPE` (если есть) | libc::send `MSG_NOSIGNAL` (response.rs:815/1100) | **P** | C условно ставит оба флага; Rust использует только `MSG_NOSIGNAL`, macOS-ветка `SO_NOSIGPIPE` отсутствует. На Linux эквивалентно, на macOS — нет. |

### classify.c: построчная сверка

- **Имена/время/триггер (57–139):** `d2k_verdict_name` — точный
  switch `clear/prefix/whole_packet/opaque/inconclusive/address/
  poisonable/flaky/unreachable/response`, Rust `Verdict::as_str`
  (`classify.rs:907`); `d2k_resp_name` — `clear/blocked/flaky/
  not_applicable`, Rust разнесён по `classify_json.rs`/`main.rs`;
  `d2k_now_ms` — `CLOCK_MONOTONIC + d2k_clock_offset_ms`, Rust
  `Instant` без инъекции; `d2k_sleep_ms` — `nanosleep`, Rust
  `thread::sleep`; `d2k_trigger_accepts` — ServerHello `16 03 .. 02`,
  TLSRecord `16/15 03`, иначе `n>0`, Rust `trigger_accepts`; 
  `d2k_trigger_sni` — `strip_prefix("tls:")`, Rust inline;
  `d2k_detect_stopped` — callback, Rust `stopped/is_cancelled`.
  E/P по строкам.
- **Опции/трасса/заметки (141–247):** `d2k_opts_defaults` — repeats
  3, timeout 6000, write 60, long 700, mark **0x40000000**; Rust
  `configured_options` те же числа, но `BYPASS_MARK=0x2d` —
  **подтверждённое расхождение**. `d2k_opts_acceptable` — callback,
  Rust `executable_poison_hit`; `d2k_opts_skipped` — список skip,
  Rust `poison_selected`; `d2k_trace_add` — до `D2K_TRACE_MAX`,
  копия/обрезка, Rust `add_observation`; `obs_done` — callback,
  Rust progress; `d2k_note` — массив notes/`vsnprintf`, Rust
  `append_reason` в одно поле; `note_gap_loss` — N.
- **split/dial/probe/measure (253–710):** `d2k_split_offsets` —
  диапазоны, Rust `split_offsets`; `dial_marked_mode` — `require_mark`
  и различение SO_MARK, Rust `dial_probe_target/probe_socket` без
  `require_mark`; `d2k_dial_deadline_err` — текст/errno, Rust
  `is_dial_timeout_text/ProbeError`; `dial_marked` — обёртка;
  `once_probe` — запись/ответ, Rust `probe_trigger/raw_split/
  probe_tcp_split`; `unacked_bytes` — TIOCOUTQ/SO_NWRITE;
  `d2k_probe_data_ack` — neutral ack; `measure` — повторы. E/P.
- **decoy/selftest (717–880):** `bind_decoy` — привязка разнесена;
  `answered_by_props` — `answered + same_hypothesis`, теста нет;
  `fam_ix` — inline; `self_ix` — `raw_selftest_index`;
  `selftest_cached_age` — TTL 600 с; `selftest_store` —
  `store_raw_selftest`; `d2k_raw_note_rc` — `note_raw_probe`;
  `raw_selftest` — цикл встроен в sweep; `raw_doubted` —
  `should_recheck`; `raw_recheck` — `raw_recheck`. E/P.
- **sweep/classify (887–1494):** `sweep_poisons` — нет trace о
  непринятом RST, иной текст selftest, compose без контроля;
  `cross_check_tls12` — C-заглушка, Rust поля `covers_tls12` нет, N;
  `d2k_classify_run` — полное дерево, но production-discovery
  использует `full_detect_semantics=false`, `confirm_clear=true`
  (`classify.rs:869-870`, `main.rs:15380-15391`): нет удвоенного
  dial-retry, иначе обрабатываются частичные transport-ошибки,
  control без `until_pass`, добавлен whole-confirm; дифференциалы
  идут с `true` и этот путь не покрывают; `d2k_send_nosig` —
  `MSG_NOSIGNAL` + `SO_NOSIGPIPE` в C, Rust только `MSG_NOSIGNAL`.

## 3. detect/main.c — 8 функций

CLI `d2k-detect` и форматы вывода. R2O использует другой интерфейс (`r2o-controller --classify HOST PORT`),
поэтому соответствие функциональное, а не построчное. В JSON R2O нет массива `notes` и поля `covers_tls12`,
порядок ключей и форма `response` иные; в человеческом отчёте нет блока свойств коробки и оговорок.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `usage` | 19-49 | 3084 | справка `d2k-detect classify`: `--sni/--raw/--repeats/--timeout/--only/--skip/--control-sni/--white/--control-raw/--hello/--no-raw/--mark/--allow-loopback/--json/--progress/--dump-trigger` | main.rs:1721-1739 help | **P** | C — подкоманда `classify` и полный текст справки; Rust — `--classify HOST PORT` и другой набор/текст флагов. Функциональное соответствие, не построчное; часть флагов (`--dump-trigger`, `--white`) и умолчаний иная. |
| `print_json_str` | 51-65 | 338 | JSON-строка: `"`/`\` экранируются, control <0x20 → `\u%04x`, UTF-8 как есть | `serde_json` (`classify_json.rs:71`) | **P** | C ручное экранирование; Rust `serde_json`. Для UTF-8/control результат эквивалентен, но прямой тест на все байты отсутствует. |
| `print_tri` | 67-73 | 181 | необязательное tri-поле: UNSET пропуск, TRUE/FALSE → true/false | `classify_json.rs:4 insert_tri_state` | **P** | C `print_tri`; Rust `insert_tri_state` в `result_json_value`. Наследует JSON-тест, отдельного нет. |
| `print_json` | 75-187 | 4176 | JSON: target/verdict/reason/repeats/probes/duration/trigger_len/boundary/split_pos/reassembles/strategy/notes/response/covers_tls12/props/path/composed/raw_usable/trace | `classify_json.rs:18 result_json_value` | **P** | C печатает `notes[]`, `covers_tls12`, `response{verdict,reason,target,control}`, trace с cuts/delay/err; Rust `result_json_value` **не имеет notes/covers_tls12**, форма `response` иная, порядок ключей serde_json, тексты причин иные. P. |
| `print_progress` | 193-199 | 271 | stderr: `[сек] probe прошло/не прошло err` | main.rs:1187 report_progress | **P** | C печатает время, имя, pass/fail и `err`; Rust `report_progress` — только завершённые наблюдения, без столбца `err`. P. |
| `tri_word` | 201-205 | 156 | «не измерено/да/нет» | main.rs:811 r2o_tri_state | **P** | C точные русские слова; Rust `r2o_tri_state`; отдельного теста нет. |
| `print_human` | 207-275 | 3700 | человеческий отчёт: target/trigger/verdict/reason/probes/duration/repeats/boundary/reassembly/strategy+пояснение/response/notes/opaque warning/properties/trace | main.rs:1254-1302 | **P** | C содержит блок свойств коробки, `notes`, имя/длину триггера, пояснение стратегии и предупреждение `raw_usable`; Rust human-отчёт этих блоков не имеет, тексты иные. P. |
| `main` | 277-450 | 8186 | CLI: `classify host:port`, разбор флагов, trigger/control/white, dump/json/progress, `d2k_classify_run` | main.rs:1104-1306, 1555/1586 | **P** | C `--hello modern|legacy` (без both), control по умолчанию `d2k_trigger_control("d2k")` (legacy), mark default `0x40000000`, `--dump-trigger`; Rust `--classify`, control через `classify_control_trigger` (tls13), mark `0x2d`, иной набор флагов/валидаций. P. |

### main.c: построчная сверка

- **`usage` (19–49) ↔ `print_help` (`main.rs:1721`):** C —
  подкоманда `classify` и полный список флагов; Rust — `--classify`
  и иной набор/текст. P, функциональное соответствие.
- **`print_json_str`/`print_tri` (51–73) ↔ serde_json/
  `insert_tri_state`:** C ручное экранирование и tri-поле; Rust
  serde_json и `insert_tri_state`. Для UTF-8/control эквивалентно,
  прямого теста на все байты нет. P.
- **`print_json` (75–187) ↔ `result_json_value`
  (`classify_json.rs:18`):** C печатает `notes[]`, `covers_tls12`,
  `response{verdict,reason,target,control}` и trace с cuts/delay/err;
  Rust **не имеет notes/covers_tls12**, форма response и порядок
  ключей иные, тексты причин иные. P.
- **`print_progress` (193–199) ↔ `report_progress`
  (`main.rs:1187`):** C stderr `[сек] probe pass/fail err`; Rust —
  только завершённые наблюдения, без `err`. P.
- **`tri_word`/`print_human` (201–275) ↔ `r2o_tri_state`/
  `main.rs:1254-1302`:** C человеческий отчёт содержит блок свойств
  коробки, `notes`, имя/длину триггера, пояснение стратегии и
  предупреждение `raw_usable`; Rust этих блоков не имеет. P.
- **`main` (277–450) ↔ `main.rs:1104-1306/1555/1586`:** C
  `classify host:port`, `--hello modern|legacy` (без both), control
  по умолчанию `d2k_trigger_control("d2k")` (legacy), mark
  `0x40000000`, `--dump-trigger`; Rust `--classify`, control через
  `classify_control_trigger` (tls13), mark `0x2d`, иной набор
  флагов/валидаций. P.

## 4. detect/poison.c — 12 функций

Каталог гипотез и перевод находки в строку стратегии/язык плана. Порядок и состав 85 гипотез совпадают
и закреплены тестом. `poison_has_fake` и `arm_from_poison` не знают осей `autottl`/`tcp_ts_up`,
которые есть в C-структуре; на текущем каталоге это не проявляется, но функция не эквивалентна для
произвольного `d2k_poison`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_poison_supports_family` | 17-22 | 290 | допустимость гипотезы для семейства | classify.rs:389 poison_supports_family | E | tests/classify.rs:861 (проверка ipid на IPv6) |
| `d2k_poison_has_fake` | 24-40 | 1239 | фальшивка, если не syn_data/oob/fake_between и есть badsum/md5/ttl/autottl/seq_shift/tcp_ts | classify.rs:382 poison_has_fake | **P** | **Расхождение:** C возвращает true при `p->autottl` (`poison.c:38`); Rust `Poison` не имеет `autottl`/`tcp_ts_up` и возвращает `badsum||md5||ttl>0||seq_shift!=0||tcp_ts`. Для autottl-only гипотезы C считает «есть фальшивка», Rust — нет. Тест покрывает badsum/ts. |
| `add` | 47-60 | 335 | добавить гипотезу в список | classify.rs:215 add_poison | E | tests/classify.rs:861 порядок и 85 записей |
| `d2k_poison_same` | 62-70 | 300 | сравнение без имени: name занулён, repeats≤1→1, затем `memcmp` всего struct | classify.rs:200 same_hypothesis | **P** | C сравнивает **все** поля `d2k_poison`, включая `autottl/autottl_delta/min/max/tcp_ts_up/split_pos`; Rust `same_hypothesis` сравнивает подмножество полей `Poison` (autottl/tcp_ts_up отсутствуют). На текущем каталоге расхождений нет, для произвольной гипотезы — есть. |
| `already_listed` | 73-82 | 248 | отсев уже перечисленной гипотезы | classify.rs:327-330 | E | tests/classify.rs:861 все 85 уникальны |
| `init_poisons` | 84-180 | 5674 | полный список гипотез в порядке стоимости | classify.rs:223 build_poisons | E | tests/classify.rs:861 |
| `d2k_poisons` | 182-189 | 284 | неизменяемый список гипотез | classify.rs:377 poisons | E | tests/classify.rs:861 |
| `d2k_note_props_hit` | 194-208 | 540 | свойства по проходу гипотезы | classify.rs:173 note_props_hit | E | tests/classify.rs:907 poison_outcomes_update_only_properties_they_prove |
| `d2k_note_props_miss` | 216-223 | 242 | свойства по промаху гипотезы | classify.rs:189 note_props_miss | E | tests/classify.rs:907 |
| `d2k_strategy_for_poison` | 226-398 | 7211 | строка стратегии nfqws2 | classify.rs:394 strategy_for_poison | E | tests/classify.rs:879; raw emission differential |
| `d2k_strategy_for` | 401-404 | 144 | `--lua-desync=multisplit:payload=unknown:dir=out:pos=%d` | classify.rs:1933 strategy_for | **P** | C и Rust формируют ту же строку; отдельного теста строки нет. P. |
| `d2k_arm_from_poison` | 413-475 | 4050 | гипотеза → `d2k_arm`: oob, badsum/md5, repeats, gap, disorder/pos, between, ttl, autottl/delta/min/max, seq_out, decoy, tcpts/tcpts_up, ipidzero, split_pos, seqovl_hello/seqovl | classify_measured.rs:30 plan_text_for_poison, :50 measured_plan_text, r2k-core plan.rs | **P** | C переносит **autottl** и **tcp_ts_up** отдельными осями; Rust `Poison` (classify.rs) этих полей не имеет, `plan_text_for_poison/measured_plan_text` покрывают split/badsum и основные флаги. Для autottl/tcp_ts_up план не выражается; дифференциалы split/badsum есть, полного набора полей/отказов нет. |

### poison.c: построчная сверка

- **`d2k_poison_supports_family` (17–22) ↔
  `poison_supports_family` (`:389`):** C `family==4` или
  `family==6 && !ip_id_zero`; Rust то же. E.
- **`d2k_poison_has_fake` (24–40) ↔ `poison_has_fake`
  (`:382`):** C учитывает `badsum/md5/ttl/autottl/seq_shift/tcp_ts`;
  Rust `Poison` не имеет `autottl/tcp_ts_up` и проверяет
  `badsum/md5/ttl/seq_shift/tcp_ts`. autottl-only: C true, Rust
  false. P.
- **`add`/`already_listed`/`init_poisons`/`d2k_poisons` (47–189):**
  C cap 128 и 85 гипотез, `pthread_once`; Rust `Vec`/`OnceLock`,
  `build_poisons` 85 в том же порядке, `same_hypothesis` для дедупа.
  E, `tests/classify.rs:861`.
- **`d2k_poison_same` (62–70) ↔ `same_hypothesis` (`:200`):** C
  `memcmp` всего struct после зануления имени и нормализации repeats;
  Rust сравнивает подмножество полей `Poison`; autottl/tcp_ts_up не
  входят. Для каталога совпадает, для произвольной гипотезы — нет. P.
- **`d2k_note_props_hit/miss` (194–223) ↔ `note_props_hit/miss`:**
  C и Rust одинаковые ветви badsum/ttl/disorder/seqovl/decoy;
  miss не выводит `validates_checksum=true`. E,
  `tests/classify.rs:907`.
- **`d2k_strategy_for_poison` (226–398) ↔ `strategy_for_poison`
  (`:394`):** строки стратегий совпадают (syndata/oob/fakedsplit/
  fake+seqovl/multisplit/multidisorder/fake+repeats/ts/ipid/badsum/
  md5/seq_shift/ttl/decoy), `tests/classify.rs:879` + raw emission.
  C возвращает пустую строку, Rust `None` для невыразимого — контракт
  «нет стратегии» эквивалентен. E.
- **`d2k_strategy_for` (401–404) ↔ `strategy_for` (`:1933`):** та же
  строка `multisplit:payload=unknown:...`, теста нет. P.
- **`d2k_arm_from_poison` (413–475) ↔ `plan_text_for_poison/
  measured_plan_text`:** C переносит oob/badsum/md5/repeats/gap/
  disorder/between/ttl/autottl/delta/min/max/seq_out/decoy/tcpts/
  tcpts_up/ipidzero/split_pos/seqovl_hello/seqovl; Rust `Poison`
  не имеет autottl/tcp_ts_up, эти оси не выражаются. Дифференциалы
  split/badsum есть, полного набора нет. P.

## 5. detect/props.c — 7 функций

Вопросы о свойствах и сборка кандидатов из вектора. В R2O цикл вопросов и `compose_from_props`
встроены в `raw_probe::sweep_poisons`; отдельного дифференциала на весь список вопросов нет,
покрыт только составной ECH-вопрос и перепроверка самопроверки. Расхождение: при `control = None`
C всё равно выдаёт кандидат «всё сразу», R2O его не выдаёт.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `prop_probes` | 49-196 | 9436 | 12 вопросов в порядке стоимости: seqovl-1, disorder, badsum, badsum+hello, badsum-x2-g20, md5, seq-out-of-window, ts, seqovl-sni, badsum-x7, white-hello-ts, syndata | raw_probe.rs:840 property_probes | **P** | C и Rust совпадают по составу, порядку, label/name и полям poison; вопросы autottl/tcp_ts_up сняты в обоих. Полного C/Rust differential списка нет; тесты покрывают ECH-вопрос и self-test. |
| `apply_set` | 198-257 | 2251 | ответ вопроса → поле `d2k_dprops`: overlap/reorder/checksum/parses_l7/duplicates/syn/md5/seq_window/timestamps/overlap_sni/dense/white_ts | raw_probe.rs:1005 apply_property | **P** | Все ветви совпадают с Rust: false/true по проходу, `ParsesL7` также ставит `validates_checksum=false`, `WhiteTimestamp` — parses_l7 + timestamps/checksum по фактическим осям. Тест покрывает только white-ts; остальные ветви без unit. |
| `d2k_run_properties` | 261-265 | 216 | обёртка `run_properties_family(...,4,...)` | raw_probe.rs:85-87 (семейство из адреса) | **P** | C отдельная IPv4-обёртка; Rust семейство берёт из адреса цели, отдельного символа нет. |
| `d2k_run_properties_family` | 267-416 | 9648 | цикл вопросов: stop/skip, tcp_ts fallback, overlap SNI, decoy/white, label, majority, local_err, apply_set, acceptable-hit | raw_probe.rs:189-345 | **P** | Логика встроена в `sweep_poisons`: те же 12 вопросов, `poison_selected`, `raw_profile_allows`/WhiteTimestamp fallback, `sni_bounds` для seqovl-sni, `select_bridge_decoy`, majority `pass>total/2`, local error в трассу, `apply_property`, `executable_poison_hit`. Отдельной функции/полного differential нет. |
| `tri_no` | 418-418 | 60 | `t == D2K_TRI_FALSE` | inline `== TriState::False` | **P** | Хелпер заменён сравнением; отдельного теста нет. |
| `tri_yes` | 419-419 | 59 | `t == D2K_TRI_TRUE` | inline `== TriState::True` | **P** | Хелпер заменён сравнением; отдельного теста нет. |
| `d2k_compose_from_props` | 426-498 | 3144 | сборка: base badsum/decoy, duplicates×2, left-overlap, reorder, fallback «всё сразу», decoy/seqovl из control | `raw_probe.rs:1047` `compose_from_props` | **P** | **Подтверждено:** C при `n==0 && cap>0` всегда создаёт «СОБРАНО: всё сразу», даже при `ctl=NULL` (`props.c:477-486`); Rust создаёт его только `if control.is_some()` (`raw_probe.rs:1094-1096`). Остальные правила (badsum при `validates_checksum!=TRUE`, decoy при `parses_l7`, серия×2, overlap, reorder) совпадают. C `cap` и привязка `decoy/seqovl` в конце; Rust `Vec` и control.len. P. |

### props.c: построчная сверка

- **`prop_probes` (49–196) ↔ `property_probes` (`:840`):** 12
  вопросов в одном порядке и с теми же label/name/полями: seqovl-1,
  disorder, badsum, badsum+hello, badsum-x2-g20, md5,
  seq-out-of-window, ts, seqovl-sni, badsum-x7, white-hello-ts,
  syndata. Вопросы autottl/tcp_ts_up сняты в обоих. P — полного
  differential списка нет.
- **`apply_set` (198–257) ↔ `apply_property` (`:1005`):** все ветви
  совпадают (left overlap/reorder/checksum/parses_l7/duplicates/
  syn/md5/seq window/timestamps/overlap_sni/dense/white_ts);
  `ParsesL7` ставит `validates_checksum=false`, `WhiteTimestamp` —
  по фактическим осям. Тест только white-ts. P.
- **`d2k_run_properties`/`_family` (261–416) ↔ `sweep_poisons`
  (`:189-345`):** wrapper IPv4; цикл встроен в sweep: stop/skip,
  `raw_profile_allows`/WhiteTimestamp fallback, `sni_bounds` для
  seqovl-sni, `select_bridge_decoy`, majority `pass>total/2`,
  local error в трассу, `apply_property`, `executable_poison_hit`.
  Отдельной функции/полного differential нет. P.
- **`tri_no`/`tri_yes` (418–419):** inline сравнения с
  `TriState::False/True`; хелперы заменены. P.
- **`d2k_compose_from_props` (426–498) ↔ `compose_from_props`
  (`:1047`):** base `badsum = validates_checksum!=TRUE`,
  `decoy_hello = parses_l7==TRUE`; duplicates×2 (2/20 и 7/0),
  left-overlap (seqovl_exact+decoy, repeats 7), reorder (disorder,
  repeats 7) — совпадают. **Расхождение:** при `n==0` C всегда
  создаёт «СОБРАНО: всё сразу» (`badsum+decoy+seqovl_exact+disorder`,
  repeats 7) даже при `ctl=NULL`; Rust создаёт его только
  `if control.is_some()`. C `cap` и привязка decoy/seqovl в конце,
  Rust `Vec`/control.len. P; header, п. 6.

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
| `d2k_raw_supported` | 164-164 | 41 | есть ли сырой слой (Linux) | raw_probe.rs:63 raw_supported | **P** | C Linux возвращает **1 безусловно** (`raw.c:164`); Rust `raw_supported` открывает `AF_INET/SOCK_RAW/IPPROTO_RAW` и при ошибке возвращает false. В непривилегированном процессе C считает слой доступным, Rust — нет; не-Linux C-заглушка возвращает 0. |
| `raw_rule_system` | 224-255 | 1285 | fork/setpgid/exec sh, закрытие fd>2, deadline, kill группы | raw_probe.rs:1285 run_command | **P** | C создаёт процесс-группу, закрывает все fd кроме 0–2, по deadline `kill(-pid,SIGKILL)`; Rust `run_command` запускает program+args, `try_wait`, при таймауте убивает только child. Нет process-group kill и закрытия fd. |
| `d2k_raw_rst_fail_count` | 262-262 | 74 | отказы вставки правила (поток) | raw_probe.rs:54 rst_rule_failure_count | E | raw_probe.rs:2770 rst_rule_failure_counts_are_per_worker_thread |
| `d2k_raw_dial_count` | 263-263 | 62 | число сырых соединений (поток) | raw_probe.rs:58 raw_dial_count | P | теста счётчика нет |
| `seed_init` | 265-269 | 153 | инициализация ГСЧ и порта | raw_probe.rs:1419 random_u32, :1439 OnceLock | P | getrandom вместо srandom |
| `seed_once` | 271-274 | 74 | однократная инициализация | raw_probe.rs:1439 OnceLock | P | OnceLock |
| `next_source_port` | 283-292 | 252 | `g_sport_counter++`, `30000 + counter % 25000` | raw_probe.rs:1441 next_source_port | **P** | Диапазон 30000..54999 совпадает. C seed `srandom(now_ms ^ pid)`, Rust `getrandom % 25000` + `AtomicU32.fetch_add`, теста нет. |
| `rst_nft` | 313-317 | 108 | режим nftables | raw_probe.rs:1496 r2o_rst_uses_nft | P | переменная R2O_FW вместо D2K_FW |
| `sweep_stale_rst_rules` | 319-348 | 992 | iptables/ip6tables -S OUTPUT → parse RST rule → -D для мёртвого владельца | raw_probe.rs:1749 sweep_stale_iptables | **P** | C разбирает `RST_PREFIX`, legacy suffix и owned `d2k-rst:<pid>`, порт только 30000..54999, снимает с тегом владельца. Rust фильтрует только `--comment r2o-rst:`, парсит pid/`--sport`, legacy-форму и диапазон не знает; `d2k_parse_rst_rule` — N. |
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
| `d2k_raw_set_segment_max` | 814-814 | 89 | потолок сегмента под датапат | — | N | **Production-вызов:** `core/d2kc.c:575,789` ставит `d2k_arm_segment(send_maxlen)`. R2O `classify_measured.rs:12,143` жёстко пишет `segment 1400`; discovery-split `main.rs:6300` считает `send_cap-72 min 1400`. На узком канале measured-poison план может быть отвергнут вместо нарезки. Сеттера нет. |
| `raw_send` | 830-858 | 847 | SEQ+seq_shift, нарезка payload по `seg_max` (1400), sendto каждого сегмента | raw_probe.rs:1213 (план), :1195 (syn_data) | **P** | C режет нагрузку на `seg_max` (default 1400, setter `d2k_raw_set_segment_max`), seq+off. Rust plan-путь `emit_plan_packets` шлёт пакеты плана; syn_data-путь собирает **один** `build_control_packet` с `trigger.payload` и не режет по 1400. План E, syn_data — пробел. |
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
| `d2k_raw_set_segment_max` | 1329-1329 | 57 | stub вне Linux | — | N | Не-Linux заглушка; в R2O сеттера нет ни в одной ветке. |
| `d2k_raw_rst_fail_count` | 1330-1330 | 56 | stub вне Linux | raw_probe.rs:54 | E | тот же счётчик, что в Linux-ветке; raw_probe.rs:2770 |
| `d2k_raw_dial_count` | 1331-1331 | 52 | stub вне Linux | raw_probe.rs:58 | P | thread-local счётчик |
| `d2k_raw_flush_pending` | 1332-1332 | 35 | stub вне Linux | raw_probe.rs:1745 | P | функция есть |
| `d2k_raw_pending_count` | 1333-1333 | 48 | stub вне Linux | — | N | геттера нет |
| `d2k_raw_probe_poison_family` | 1335-1343 | 513 | stub вне Linux | classify.rs:764-772 cfg(not(linux)) | P | sweep возвращает None |
| `d2k_raw_probe_handshake_as` | 1345-1353 | 464 | stub вне Linux | classify.rs:746-754 cfg(not(linux)) | P | сырой слой отключён |
| `d2k_raw_probe_handshake` | 1357-1361 | 256 | обёртка IPv4 | raw_probe.rs:1174 | P | отдельного символа нет |
| `d2k_raw_probe_handshake_family` | 1364-1370 | 371 | рукопожатие с профилем метки | raw_probe.rs:1174/1841 | P | offer_ts всегда передаёт вызывающий |
| `d2k_raw_probe_poison` | 1372-1377 | 305 | обёртка IPv4 | raw_probe.rs:1174 | P | отдельного символа нет |

### raw.c: построчная сверка

- **RST-правила (63–553):** `parse_long_exact` — точный разбор числа
  (первый символ цифра, `strtol`, `errno`, конец строки), Rust inline
  `parse::<u16>` без части проверок; `d2k_parse_rst_rule`/
  `d2k_parse_stale_rst_rule` — N (R2O не разбирает строки iptables);
  `pid_alive` — `kill(pid,0)||EPERM`, Rust `libc::kill`; `raw_supported`
  — C 1, Rust реальная проба сокета; `raw_rule_system` — C
  fork/setpgid/close fd/deadline/kill group, Rust `run_command` без
  группы; `d2k_raw_rst_fail_count` E, `d2k_raw_dial_count` P;
  `seed_init/seed_once` — srandom vs getrandom/OnceLock;
  `next_source_port` — 30000..54999 совпадает; `rst_nft` — D2K_FW vs
  R2O_FW; `sweep_stale_rst_rules` — C legacy+owned+range 30000..54999,
  Rust только `r2o-rst`; `rst_rule_cmd_form/cmd` — d2k vs r2o теги;
  `rst_delete_once` — C -C/-D, Rust nft-тест; `rst_remember/
  retry_pending_releases/rst_release_locked/raw_flush_pending` — лимит
  64/5 попыток; `d2k_raw_pending_count` N; `raw_atexit` — без trylock;
  `rst_key_of` — поля на месте; `suppress_kernel_rst/
  release_kernel_rst` — RstRule/RstGuard, нет снятия после таймаута
  команды; `local_addr_for` — UDP connect. P/N по строкам.
- **Сборка пакетов (556–771):** `local_addr_for` P; `rd16/rd32/
  wr16/wr32/checksum/tcp_checksum/build_ipv4_tcp/tcp_checksum_family/
  build_ip_tcp` — E, differential `raw_profile`/`measured_tcp_split`
  и checksum-тесты.
- **Отправка/приём/план (773–1321):** `raw_sendto` — C IPv4
  `sin_port=dport`, IPv6 port 0, Rust `send_ip_packet` порт не
  заполняет; сокетного теста нет. `d2k_raw_set_segment_max` — N
  (production gap). `raw_send` — C нарезает по `seg_max` (1400),
  Rust plan-путь E, syn_data одним пакетом. `raw_send_syn` — E,
  `r2o-raw-profile-differential.sh`. `raw_recv` — Rust строже
  фильтрует длины/фрагменты/локальный адрес; `raw_read_payload` —
  якорь есть, теста нет; `raw_close` — Drop; `raw_handshake/raw_dial`
  — RTO/эхо есть, полного сетевого теста нет; `d2k_raw_probe_
  handshake_as` P; `raw_send_plan` E; `d2k_raw_probe_poison_family`
  P — план покрыт, сетевой путь нет.
- **Не-Linux ветки (1328–1377):** `d2k_raw_supported` false,
  `d2k_raw_set_segment_max` N, counters P/E, `d2k_raw_pending_count`
  N, `d2k_raw_probe_*` stubs P, обёртки IPv4 P.

## 7. detect/response.c — 7 функций

Ответное направление TLS 1.2. Самый закрытый файл среза: разбор потока записей, рукопожатие,
счёт серии, нейтральное имя и решение покрыты юнит-тестами и общими C-векторами
(`tests/fixtures/d2o/tls-response-vectors.tsv`, `d2o_response_fixture.c`, EINTR-дифференциал).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `resp_timeout` | 64-70 | 160 | `timeout>0 && timeout<3000 ? timeout : 3000` | response.rs:164 response_timeout | **E** | C и Rust одинаково ограничивают одно рукопожатие 3 с; `tests/response.rs:649`. |
| `d2k_resp_scan12` | 83-118 | 996 | поток TLS-записей: alert 0x15 → конец, 0x16 → склейка handshake, type 14/len 0 → ServerHelloDone | response.rs:1248 scan12 | **E** | C и Rust одинаково проверяют полную запись, `0x15`/`0x16`, склейку handshake через `body`, `hdr[0]==14 && body==0`; 13 векторов `tests/response.rs:122/138/479`. |
| `d2k_resp_handshake12` | 123-207 | 2623 | legacy ClientHello, socket, SO_MARK/TCP_NODELAY/SNDTIMEO/RCVTIMEO, connect/send, 64 КиБ, poll/recv, scan12 | response.rs:1050 handshake | **E** | C и Rust: legacy hello, те же socket options, `MSG_NOSIGNAL`, deadline, `RESPONSE_CAP=65536`, `scan12`; C разрешает адрес внутри, Rust `count_handshakes` — снаружи. Исходы Done/Failed/Unmeasured совпадают; `tests/response.rs:649/555`. |
| `count_handshakes` | 215-228 | 403 | последовательные `repeats`, `r>0` done, `r<0` unmeasured | response.rs:1148 count_handshakes | **E** | C последовательно; Rust тоже, но резолвит адрес на каждую попытку и считает lookup failure как failed, `probes++`. `tests/response.rs:649`. |
| `d2k_neutral_sni` | 233-269 | 1252 | 10 случайных байт `/dev/urandom`, xorshift fallback, `z<hex>.example.com` | response.rs:1172 neutral_sni | **E** | C и Rust: 10 байт, fallback time/pid/counter/xorshift, hex-суффикс и тот же формат; `tests/response.rs:203`. |
| `d2k_resp_decide` | 274-304 | 1957 | unmeasured>0 / control==0 / target==repeats / target==0 / flaky с точными reason | response.rs:1304 decide | **E** | C и Rust совпадают все 5 ветвей и тексты; `tests/response.rs:421/479`. |
| `d2k_probe_response` | 310-324 | 806 | neutral SNI, target count, control count, decide | response.rs:1207 probe_response | **E** | C и Rust: target/control на одном адресе, neutral SNI, `decide`; Rust дополнительно валидирует `repeats>0` и legacy hello, C при тех же входах даёт NotApplicable через control==0. `tests/response.rs:649/780`. |

### response.c: построчная сверка

- **`resp_timeout` (64–70) ↔ `response_timeout` (`:164`):** оба
  `timeout>0 && timeout<3000 ? timeout : 3000`. E.
- **`d2k_resp_scan12` (83–118) ↔ `scan12` (`:1248`):** C и Rust
  проверяют полную запись, `0x15` → FatalAlert, `0x16` → склейка
  handshake, `type 14 && body 0` → ServerHelloDone; 13 векторов.
  E.
- **`d2k_resp_handshake12` (123–207) ↔ `handshake` (`:1050`):**
  legacy ClientHello, socket, `SO_MARK/TCP_NODELAY/SNDTIMEO/
  RCVTIMEO`, `MSG_NOSIGNAL`, deadline, `RESPONSE_CAP=65536`,
  `scan12`; C резолвит внутри, Rust — в `count_handshakes`.
  Done/Failed/Unmeasured совпадают. E.
- **`count_handshakes` (215–228) ↔ `:1148`:** C последовательные
  `repeats`, `r>0` done, `r<0` unmeasured; Rust резолвит каждую
  попытку, lookup failure = failed, `probes++`. E.
- **`d2k_neutral_sni` (233–269) ↔ `neutral_sni` (`:1172`):**
  `/dev/urandom` 10 байт, xorshift fallback, `z<hex>.example.com`.
  E.
- **`d2k_resp_decide` (274–304) ↔ `decide` (`:1304`):** 5 ветвей
  (unmeasured/control==0/target==repeats/target==0/flaky) и тексты
  совпадают. E.
- **`d2k_probe_response` (310–324) ↔ `probe_response`
  (`:1207`):** target/control на одном адресе, neutral SNI,
  `decide`; Rust дополнительно валидирует repeats/legacy hello, при
  тех же входах C даёт NotApplicable. E.

## 8. detect/trigger.c — 9 функций

Чем меряем: ClientHello из снятого профиля, произвольный hex, контроль, приманка и вопрос о метке
времени клиента. Байты приветствий совпадают с C побайтно (тесты `tests/hello.rs`). Контроль и
разбор TCP-опций клиента в R2O перенесены не как отдельные функции: контроль собран в CLI,
признак метки передаётся булевым `client_tcp_has_timestamps`, переопределения нет.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_trigger_tls` | 21-50 | 1378 | ClientHello из снятого профиля (legacy/modern) с SNI; n≥16; name `tls:<sni>`; accept ServerHello; sni_off/len | classify.rs:87 Trigger::tls, :96 Trigger::tls13, hello.rs:549 | **E** | C `d2k_hello_from_profile(legacy?LEGACY:MODERN, sni)`, пустой SNI/ошибка/n<16 → -1, затем `d2k_hello_sni`. Rust `Trigger::tls`/`tls13` через `legacy_client_hello`/`modern_client_hello`, name/accept те же; смещения SNI — `hello::sni_bounds` на месте вызова. Байты совпадают: `tests/hello.rs:42` legacy, `:50` modern, `:62` fake; `tests/classify.rs:946`. |
| `hexval` | 52-58 | 203 | значение hex-цифры 0-9/a-f/A-F | trigger.rs:11 inline | **E** | C `hexval`; Rust match в `parse_raw_hex`. `tests/trigger.rs:41`. |
| `d2k_trigger_raw_hex` | 67-108 | 1322 | hex-триггер: разделители `space/tab/nl/cr/:/ -`, нечётный/битый/короткий/длинный отказ; name `raw:NB`; accept Any | classify.rs:77 Trigger::raw_hex, trigger.rs:4 parse_raw_hex | **E** | C пропускает те же разделители, `n<2`/нечётный/битый/`n>=sizeof payload` → ошибка, name `raw:%dB`, accept ANY. Rust `TRIGGER_MAX=16384`, те же проверки, name/accept те же. `tests/trigger.rs:41-58`. |
| `d2k_trigger_control` | 118-128 | 376 | контроль: `probe-<tag>.invalid-control.example`, legacy TLS, name `control`, accept TLSRecord | main.rs:1555 classify_control_trigger | **P** | C строит legacy-приветствие с тегом из аргумента; Rust `classify_control_trigger` использует `--control-sni`/`--control-raw`, по умолчанию имя `probe-d2k.invalid-control.example` (тег фиксирован) и **`Trigger::tls13` (modern)**; control_raw — raw_hex + name control + `TlsRecord`. Имя/профиль/источник различаются. |
| `d2k_opts_decoy` | 130-136 | 153 | приманка: `o->decoy`, если len≥2, иначе `o->control` | raw_probe.rs:602 select_bridge_decoy | **P** | C просто выбирает готовый `decoy`/`control` без trigger. Rust `select_bridge_decoy(trigger,control,trigger_snapped)` возвращает fallback control≥2 либо **клонирует trigger с SNI из control**; это другая конструкция. Прямого `options.decoy`/селектора нет; fallback на control есть. |
| `d2k_trigger_host_ts_override` | 156-156 | 66 | глобальный сеттер `host_ts_override` | `ClassifyOptions.client_tcp_has_timestamps` (`classify.rs:833`), `raw_offer_timestamps` (`raw_probe.rs:673`) | **P** | C статический `host_ts_override` (-1/0/1), влияет на `host_offers_ts`. Rust передаёт `Option<bool>` явно; глобального сеттера/CLI-override нет. Поведение выражается, API иное. |
| `host_offers_ts` | 158-178 | 638 | override → cached чтение `/proc/sys/net/ipv4/tcp_timestamps`, default 1 | raw_probe.rs:673 raw_offer_timestamps | **P** | C `host_ts_override>=0` затем `static cached`; Rust `HOST_TCP_TIMESTAMPS OnceLock`, парсит тот же файл, default 1. Кэш/дефолт совпадают, override отсутствует. |
| `d2k_trigger_offers_ts` | 180-199 | 615 | нет профиля → host_offers_ts; иначе разбор TCP-опций, kind 8/10 → 1 | raw_probe.rs:673/731 | **P** | C парсит `client_tcp_options` байт за байтом (kind 0 break, 1 skip, неверная длина →0, 8/10 →1). Rust `raw_offer_timestamps(Option<bool>)` использует готовый bool из профиля, байты не разбирает; расхождение представления, не результата для уже снятого профиля. |
| `d2k_trigger_allows_poison` | 201-207 | 165 | `!p->tcp_ts` или `offers_ts(t)` | raw_probe.rs:731 raw_profile_allows, :967 fallback | **P** | Формула `!tcp_ts` или `offer_ts` совпадает. Но Rust `property_probe_poison` при `WhiteTimestamp`, если TS не предложен и checksum не validated, **заменяет** poison: `tcp_ts=false`, `badsum=true`; C просто возвращает 0. Это дополнительная fallback-ветвь, не входящая в `d2k_trigger_allows_poison`. |

### trigger.c: построчная сверка

- **`d2k_trigger_tls` (21–50) ↔ `Trigger::tls/tls13`
  (`classify.rs:87/96`):** C legacy/modern через
  `d2k_hello_from_profile`, SNI nonempty, `n>=16`, name `tls:<sni>`,
  accept ServerHello, `sni_off/len` из `d2k_hello_sni`; Rust те же
  name/accept и байты (`tests/hello.rs:42/50/62`), `sni_bounds` на
  месте вызова. E.
- **`hexval`/`d2k_trigger_raw_hex` (52–108) ↔ `parse_raw_hex`
  (`trigger.rs:4`):** те же разделители, лимит 16384, отказ
  нечётному/битому/короткому, name `raw:NB`, accept Any;
  `tests/trigger.rs:41-58`. E.
- **`d2k_trigger_control` (118–128) ↔ `classify_control_trigger`
  (`main.rs:1555`):** C legacy-приветствие с тегом из аргумента;
  Rust по умолчанию `probe-d2k.invalid-control.example` и
  **tls13/modern**, control_raw — raw_hex. P — имя/профиль/источник
  различаются.
- **`d2k_opts_decoy` (130–136) ↔ `select_bridge_decoy` (`:602`):**
  C выбирает готовый `decoy`/`control`; Rust клонирует trigger с SNI
  из control. Это другая конструкция, прямого `options.decoy` нет. P.
- **`host_ts_override/host_offers_ts/offers_ts` (156–199) ↔
  `raw_offer_timestamps` (`:673`):** C глобальный override + cached
  чтение `/proc/sys/net/ipv4/tcp_timestamps`, затем разбор TCP-опций
  (kind 8/10); Rust `HOST_TCP_TIMESTAMPS OnceLock` и `Option<bool>` из
  профиля, без override и без разбора байтов на этом уровне. P.
- **`d2k_trigger_allows_poison` (201–207) ↔ `raw_profile_allows`
  (`:731`):** формула `!tcp_ts || offer_ts` совпадает; Rust
  `property_probe_poison` добавляет fallback WhiteTimestamp →
  `tcp_ts=false,badsum=true`, которого в C-функции нет. P.

## 9. detect/include/d2k_detect.h — 1 функция

Единственная функция заголовка — правило большинства для вопросов о свойствах.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_prop_majority` | 490-493 | 108 | `repeats>0 && pass>repeats/2` | raw_probe.rs:665 majority | **P** | C inline и Rust `majority` дают `total!=0 && pass>total/2` — эквивалентно. Отдельного unit нет; используется в цикле свойств (`props.c`/`sweep_poisons`) и проверяется косвенно в property-тестах. |

---

## Углублённая сверка 12 N-функций

- **`d2k_detect_stop_all` (bridge.c 45):** C ставит липкий
  `g_stop_all`, который читает `stop_asked` вместе с флагом задачи. R2O
  отменяет только конкретную задачу через `AtomicBool`
  (`classify.rs:603,1041`); глобального «остановить все классификаторы»
  нет. Для одиночного CLI-прогона эквивалентно; для службы остановка
  достижима через `Drop for DiscoveryWorker` (`main.rs:14251-14261`),
  который взводит `cancel`/`active_cancels` и join-ит потоки. P: липкость
  общего флага и C/Rust differential не проверены.
- **`trace_questions` (classify.c 284–309):** C складывает qtrace вопросов
  свойств в `d2k_vres`. R2O наблюдения остаются в `ClassifyResult.trace`,
  отдельного qtrace-формата нет. N — диагностика.
- **`note_gap_loss` (classify.c 238–247):** C предупреждает, что движок
  не умеет паузу между копиями фальшивки и копии идут вплотную. R2O такой
  оговорки не формирует; при этом планы R2O умеют `gap_us`/`gap_ms`, так
  что предупреждение относится к C-движку, а не к отсутствию воздействия.
  N — текст/диагностика.
- **`cross_check_tls12`/`covers_tls12` (classify.c 1084–1092):** C —
  честная заглушка: ставит `D2K_TRI_UNSET` и note «не проверено», вызов
  из CLI запрещён. R2O поля `covers_tls12` не имеет и покрытие не
  заявляет. N, но это **не** функциональный пробел обхода: обе стороны
  честно говорят «не измерено».
- **`d2k_parse_rst_rule` (raw.c 79–118), `d2k_parse_stale_rst_rule`
  (121–124), `d2k_rst_rule_stale` (137–143):** C разбирает строки
  iptables/nft-правил подавления RST и определяет, не брошено ли правило
  по владельцу/таймауту. R2O `raw_probe.rs` создаёт nft-правило
  (`nft_rst_rule...`), но чужой/legacy текст правил не разбирает и
  stale-cleanup не выполняет. N — реальный пробел обслуживания правил,
  не packet-path классификации.
- **`d2k_raw_pending_count` (raw.c 488–495, stub 1333):** C-геттер числа
  отложенных снятий RST-правил. R2O геттера не имеет; отложенные снятия
  живут внутри `raw_probe`/`RST_RULE_FAILURES`. N — диагностика.
- **`d2k_raw_set_segment_max` (raw.c 814, stub 1329):** C-сеттер
  `seg_max` (по умолчанию 1400) — **production-вызов**:
  `core/d2kc.c:575,789` ставит `d2k_arm_segment(send_maxlen)` при старте и
  при смене `send_maxlen`. R2O `classify_measured.rs:12,143` жёстко пишет
  `segment 1400`, а discovery-split `main.rs:6300` считает
  `send_cap-72 min 1400`. На узком канале measured-poison план может быть
  отвергнут вместо нарезки. N — реальный packet-path пробел для
  measured-планов, не тестовый сеттер.
- **`d2k_trigger_host_ts_override` (trigger.c 156):** C-сеттер
  `host_ts_override` для CLI/тестов («стек предлагает метку»). Ось
  реализована в R2O через `ClassifyOptions.client_tcp_has_timestamps`
  (`classify.rs:833`) и `raw_offer_timestamps` (`raw_probe.rs:673`), но
  глобального сеттера/CLI-флага и теста на override нет. P, не N.

**Итог:** 12 строк N-среза = 10 функций; после проверки 10 строк (8
функций) остались N, а `d2k_detect_stop_all` и
`d2k_trigger_host_ts_override` переведены в P. Из N: 4 диагностических
геттера/заглушки, 3 функции разбора чужих RST-правил
(`parse_rst_rule`, `parse_stale_rst_rule`, `rst_rule_stale`) и
production-сеттер `raw_set_segment_max`. Ни одна N не является ветвью
классификации пакета, кроме последствий `segment_max` для measured-планов.

## Углублённая сверка classify/raw

- **`classify.c` (36 функций):** `d2k_verdict_name`, `d2k_resp_name`,
  `d2k_now_ms`, `d2k_sleep_ms`, `d2k_trigger_accepts`, `d2k_trigger_sni`,
  `d2k_detect_stopped`, `d2k_opts_defaults/acceptable/skipped`,
  `d2k_trace_add`, `obs_done`, `d2k_note`, `d2k_split_offsets`,
  `dial_marked*`, `d2k_dial_deadline_err`, `once_probe`, `unacked_bytes`,
  `d2k_probe_data_ack`, `D2K_DATA_ACK_PROBE`, `measure`, `bind_decoy`,
  `answered_by_props`, `fam_ix/self_ix/selftest_*`, `d2k_raw_note_rc`,
  `raw_selftest`, `raw_doubted`, `raw_recheck`, `sweep_poisons`,
  `cross_check_tls12`, `d2k_classify_run`, `d2k_send_nosig` сверены с
  `classify.rs`/`raw_probe.rs`/`response.rs`.
  **Подтверждено E:** `d2k_split_offsets` = `classify.rs:28`
  (фильтр 0<cut<n, первые 8, сортировка, dedup, спаны; тесты
  `tests/classify.rs:337/349/361`); `unacked_bytes` = `response.rs:953/963`
  (TIOCOUTQ/SO_NWRITE); `d2k_probe_data_ack` = `response.rs:898
  probe_neutral_ack` (нейтральный байт, TIOCOUTQ, poll, «любое событие =
  не тишина»; тест `live_neutral_ack_confirms_delivery_even_when_control_is_silent`);
  `raw_recheck` = `raw_probe.rs:746` + C/Rust recheck-тест.
  **P:** `raw_selftest` — цикл встроен в `sweep`, отдельного теста цикла
  нет; `sweep_poisons` — `control=None` C выдаёт «всё сразу», R2O нет;
  `d2k_classify_run` — production-discovery `full_detect_semantics=false`,
  `confirm_clear=true`, дифференциалы идут с `true`; `d2k_send_nosig` —
  macOS-ветка `SO_NOSIGPIPE` не перенесена; `d2k_trigger_sni`/`trace_add`/
  `opts_*` — P на форматы/лимиты.
- **`raw.c` (62 функции):** разбор RST-правил (`d2k_parse_rst_rule`,
  `d2k_parse_stale_rst_rule`, `d2k_rst_rule_stale`) — N (R2O создаёт nft
  rule, но чужой/legacy текст не разбирает); nft lifecycle
  (`rst_nft`, `rst_rule_cmd*`, `rst_delete_once`, `retry_pending_releases`,
  `d2k_raw_flush_pending`) — P; packet build/checksum
  (`build_ipv4_tcp`, `tcp_checksum*`, `build_ip_tcp`) — E по
  `raw_probe.rs` тестам; `raw_send` — P (`syn_data` одним пакетом вместо
  нарезки по `seg_max`); `raw_send_syn/raw_recv/raw_read_payload/
  raw_close/raw_handshake/raw_dial` — P (RTO/эхо/сеть не покрыты полным
  differential); `d2k_raw_set_segment_max` — N, production-вызов
  `d2kc.c:575,789`, R2O measured-план жёстко 1400 (см. N-раздел);
  non-Linux stubs — N/P. `d2k_raw_supported` — E; `d2k_raw_probe_*` —
  P (плановая часть покрыта, сетевой путь — нет).
- **Вывод:** classify/raw — 98 функций; новые подтверждённые E:
  split_offsets, unacked_bytes, probe_data_ack, raw_recheck. Основные
  пробелы — RST-парсеры, `raw_set_segment_max`, `sweep_poisons` control=None,
  production `full_detect_semantics=false`, macOS send_nosig.

## Углублённая сверка: bridge/main/poison/props/response/trigger

- **`bridge.c` (17):** `d2k_detect_stop_all` — P (Drop
  `DiscoveryWorker`), `plannable_hit` (`executable_poison_hit`),
  `map_verdict`, `bridge_input`, `progress_seen`, `retry_base_timeout`,
  `sched_tcp` (`d2k_detect_sched_tcp*`), `base_seen/base_stop`,
  `d2k_detect_sched_tcp_ack/base` — P: оркестрация перенесена в
  `main.rs` discovery/classify, но полного C/Rust differential на все
  входы/выходы и retry-base-timeout нет. `trace_questions` — N
  (qtrace-формат). Остальные E по base/queue differentials.
- **`main.c` (8):** `usage`, `print_json_str`, `print_tri`,
  `print_json`, `print_progress`, `tri_word`, `print_human`, `main` —
  P: CLI/JSON/человеческий отчёт и коды выхода отличаются; endpoint
  классификации покрыт `test-classifier-*`, но не побайтовым выводом.
- **`poison.c` (12):** `d2k_poison_supports_family`,
  `d2k_poison_has_fake`, `add`, `d2k_poison_same`, `already_listed`,
  `init_poisons`, `d2k_poisons` — E/P: список гипотез и фильтры
  сверены classifier/raw differentials; `d2k_note_props_hit/miss`,
  `d2k_strategy_for_poison`, `d2k_strategy_for` — P (текст/порядок
  свойств). **P:** `d2k_arm_from_poison` не выражает оси `autottl` и
  `tcp_ts_up`; `d2k_poison_has_fake` для них тоже не учитывает.
- **`props.c` (7):** `prop_probes`, `apply_set`,
  `d2k_run_properties(_family)` — E/P: 5 вопросов и tri-state
  перенесены в `raw_probe.rs`; `tri_no/tri_yes` — E*.
  **P:** `d2k_compose_from_props` при `control=None` C выдаёт
  «всё сразу» (`props.c:477-486`), R2O — нет
  (`raw_probe.rs:1094-1096`).
- **`response.c` (7):** `resp_timeout`, `d2k_resp_scan12`,
  `d2k_resp_handshake12`, `count_handshakes`, `d2k_neutral_sni`,
  `d2k_resp_decide`, `d2k_probe_response` — E/P. `scan12`/neutral/
  decide/probe покрыты `test-classifier-white-decoy` и
  `r2o-tls-verify`; **P:** `handshake12` (65 536-байтовый предел,
  таймаут, legacy ClientHello без supported_versions) не имеет
  адресного C/Rust differential; `count_handshakes` — косвенно.
- **`trigger.c` (9):** `d2k_trigger_tls`, `hexval`,
  `d2k_trigger_raw_hex`, `d2k_trigger_control`, `d2k_opts_decoy` —
  E: `trigger.rs`/`hello.rs`, ClientHello differential, raw-hex
  unit. **P:** `d2k_trigger_host_ts_override` (ось через
  `ClassifyOptions.client_tcp_has_timestamps`, глобального сеттера/CLI
  нет); `host_offers_ts`/`d2k_trigger_offers_ts` — R2O получает булев
  признак из снятого профиля, а не разбирает TCP-опции триггера;
  `d2k_trigger_allows_poison` — P (семейство/форма/TS-профиль, полного
  differential нет).
- **Вывод:** 60 функций; E — списки/парсеры триггеров, scan12,
  neutral/decide/probe, tri-state; P — bridge-оркестрация, CLI-вывод,
  autottl/tsup, control=None compose, handshake12, host_ts; N —
  `trace_questions`, `note_gap_loss`, `cross_check_tls12`,
  `d2k_raw_pending_count`, RST-парсеры, `set_segment_max` (см. выше).

## Главные пробелы (N)

10 строк среза соответствуют 8 отсутствующим функциям: пары Linux/#else в `raw.c` дают дубли
у `pending_count` и `set_segment_max`. `d2k_detect_stop_all` и
`d2k_trigger_host_ts_override` после проверки переведены в P.

1. `trace_questions` — нет `qtrace`-аналога: ответы вопросов остаются в `ClassifyResult.trace` и не уходят планировщику как отдельный журнал.
2. `note_gap_loss` — нет оговорки о том, что найденный приём опирался на паузу между копиями.
3. `cross_check_tls12` и поле `covers_tls12` — не перенесены (в C это честная заглушка).
4. `d2k_parse_rst_rule`, `d2k_parse_stale_rst_rule`, `d2k_rst_rule_stale` — R2O не разбирает строки iptables и не снимает чужие/legacy-правила по владельцу.
5. `d2k_raw_pending_count` (обе ветки) — геттера отложенных снятий нет.
6. `d2k_raw_set_segment_max` (обе ветки) — production-сеттер `seg_max` не перенесён: measured-план жёстко 1400 (`classify_measured.rs:12`), discovery-split считает `send_cap-72`. На узком канале measured-poison план отвергается вместо нарезки.

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
- `d2k_raw_set_segment_max` — **production-вызов**, не тестовый сеттер:
  `core/d2kc.c:575,789` ставит `d2k_arm_segment(send_maxlen)` при старте и
  при смене предела. R2O measured-план жёстко пишет `segment 1400`
  (`classify_measured.rs:12,143`), discovery-split считает
  `send_cap-72 min 1400` (`main.rs:6300`). N остаётся, но это
  packet-path-риск для measured-планов на узком канале.
- `d2k_trigger_host_ts_override` — переведён в P: ось реализована через
  `ClassifyOptions.client_tcp_has_timestamps` (`classify.rs:833`) и
  `raw_offer_timestamps` (`raw_probe.rs:673`); глобального сеттера/CLI и
  теста на override нет.
- `d2k_detect_stop_all` — переведён в P: отдельного липкого флага нет, но
  остановка службы достижима через `Drop for DiscoveryWorker`
  (`main.rs:14251-14261`), который взводит `cancel`/`active_cancels` и
  join-ит потоки. C/Rust differential на «остановить все» отсутствует.



## Ограничения проверки

- Тесты и дифференциалы в этом проходе не запускались: в среде нет `git`, `cargo`, компилятора C. Ссылки в колонке доказательства — на файлы и имена тестов, а не на результат прогона. Координатор дополнительно прогнал групповые differentials, перечисленные выше; это не отменяет ограничение для отдельных E-рядов.
- Не проверялись: реальный DPI-бокс, OpenWrt/musl и mipsel-сборка, поведение при нехватке прав на raw-сокет, гонки нескольких классификаторов на одном роутере, тайминги на живом канале.
- Пункты E по static-хелперам наследуют владельца: отдельного теста на сам хелпер может не быть.

## Итог

- Полностью подтверждено разбором и наличием профильного теста/дифференциала (E): **49 из 159 (30.8 %)**.
- Покрыто реализацией, но без полного доказательства ветвей (P): **100 из 159**.
- Не перенесено (N): **10 из 159 (6.3 %)**. Из них 4 — диагностические
  геттеры/заглушки (`trace_questions`, `note_gap_loss`, `cross_check_tls12`,
  `d2k_raw_pending_count`), 3 — разбор чужих RST-правил, 2 строки —
  `d2k_raw_set_segment_max` (production-сеттер, packet-path-риск для
  measured-планов), 1 — не-Linux stub.
- Не установлено (?): **0**.
- Для паритета среза остаётся закрыть 10 N и доказать ветви у 100 P; один только факт наличия теста в дереве не заменяет прогон.
