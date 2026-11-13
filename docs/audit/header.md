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

### Текущий прогресс (2026-11-12)

Проверены все пять групп, **1982 из 1982** функций:

| Группа | Функций | E | P | N | ? |
|---|---:|---:|---:|---:|---:|
| core-net | 548 | 197 | 351 | 0 | 0 |
| core-state | 692 | 182 | 509 | 0 | 0 |
| datapath-core | 400 | 156 | 244 | 0 | 0 |
| datapath-plan | 183 | 176 | 7 | 0 | 0 |
| detect | 159 | 72 | 87 | 0 | 0 |
| **Итого** | **1982** | **783** | **1199** | **0** | **0** |

Это не оценка паритета: 1284 P означают «код есть, доказательство ветвей
неполное», 43 N — в основном диагностические/CLI-функции и несколько реальных
расхождений (`wire_udp` IPID_ZERO, `udpruntime` raw UDP,
`tls12/tls13` record-layer). `SET_HTTPS` TTL закрыт 2026-11-12 и в список
открытых расхождений больше не входит.

Статусы пересчитаны строго по колонке «статус»: описание вида «N цифр подряд»
больше не считается статусом, экранированные `\|` не сдвигают колонки.


## Итог и подтверждённые расхождения (2026-11-12)

Покрытие реестра: **1982/1982** функций. Статусы: **E 783 / P 1199 /
N 0 / ? 0**. Это не 100 % паритет: E требует целевого теста/дифференциала,
P означает неполное доказательство ветвей, N — отсутствие реализации.

| # | Область | D2O | R2O | Подтверждение |
|---|---|---|---|---|
| 1 | `SET_HTTPS` TTL | обрезает до **7 суток** (`d2k_ctl.h:231`, `ctlsrv.c:446`) | **закрыто 2026-11-12:** датапат обрезает до 7 суток, кодировщик принимает любой `u32`; тесты `encodes_the_exact_https_name_and_ttl_for_the_datapath`, `set_https_command_accepts_an_exact_name_with_a_bounded_ttl` | `core-state.md`, `datapath-plan.md` |
| 2 | `ARM_SHAPE` | принимает transport 6 и 17 (`ctlsrv.c:329`) | **закрыто 2026-11-12:** R2O принимает 6/17, кэширует QSN-снимок и отдаёт `EV_SHAPE` (v22)/`EVENT_HELLO` (v48), пустое имя — wildcard; тест `arm_shape_serves_quic_snapshot_and_empty_name_is_wildcard` | `deep-datapath-core.md` |
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
| 16 | Binding | `tcp_profile` хранится, `family` default 4 (`catalog.c:834-890`) | **закрыто 2026-11-12 (данные):** `Binding.tcp_profile` и `default_family()=4` добавлены, читаются/пишутся/проверяются (`catalog.rs:166-201`, тест `binding_tcp_profile_round_trips_and_rejects_unknown_values`); **частично закрыто:** `exact_key`, `own_first_bound_plan_id`, `own_first_plans`, `newer_name_binding` (discovery), `has_covering_binding` сравнивают профиль, выведенный из shape; остаются `family_recovery`, `unfit` и отсутствие отдельного `trigger_tcp_profile` | `core-state.md` |
| 17 | plan identity | FNV-1a `plan-%08x` в TLV (`compose.c:218-240`) | trial-id 16 байт (`discovery.rs:1450`) | `core-state.md` |
| 18 | P-256 | production TLS1.2 ECDHE (`tls12.c:650-655`) | `ring`; прямых C/Rust-векторов нет | `core-state.md` |
| 19 | HTTP-search `probe_run` | 403 с телом РКН → `INJECTED`; 101/битый CL/TE → CUT; `head` включает тело | Rust не классифицирует тело, 101 → `Empty`, битый CL/TE → `InvalidData`; judge видит только заголовки | `deep-core-verify.md` |
| 20 | HTTP-search кандидаты | `CANDS[]`: split, disorder, fake-badsum, fake-seqshift (4) | 5 кандидатов, включая `fake-badsum-whole`, другой порядок | `deep-core-verify.md` |
| 21 | HTTP-search save | файл `d2k-http-plans 1`, `fflush/fsync/rename` | JSON-каталог, отдельного файла/формата нет | `deep-core-verify.md` |
| 22 | verify page budget | бюджетный повтор шлёт фактический `req`, дедлайн сбрасывается | повтор строит запрос из `options.path`, общий deadline; redirect только при `complete` | `deep-core-verify.md` |
| 23 | detect mark | `D2K_BYPASS_MARK=0x40000000` (`detect/include/d2k_detect.h:34`) | `BYPASS_MARK=0x2d` (`raw_probe.rs:23`, `response.rs:71`) | `detect.md` |
| 24 | raw-hex accept | первый байт `0x16` → `accept_serverhello` (`verdict.c:33-35,126-129`) | **уточнено 2026-11-12:** это правило `core/verdict.c`, а не detect-триггера; R2O core-вердикт не портировал (N). Detect `d2k_trigger_raw_hex` всегда `ACCEPT_ANY` (`detect/trigger.c:106`), `Trigger::raw_hex` возвращён к `Accept::Any`; тест `raw_hex_acceptance_matches_the_detect_trigger` | `core-state.md` |
| 25 | endpoint role | `server_is_low` по эфемерному диапазону ≥32768 для любого порта (`sched.c:1798-1805`) | `DiscoveryTarget::from_event` только 443, `from_http_portal` только 80 (`discovery.rs:355-460`) | `core-state.md` |
| 26 | HTTPS probe non-upgrade | `http_probe_done`: SET_HTTPS только для `SERVED`/`TLS_BLOCKED`, иначе `http_search_portal` (`d2kc.c:331-344`) | `main.rs:17033` шлёт `SET_HTTPS(host, ttl_seconds)` для любого результата; у не-upgrade `ttl_seconds=0` (`https_probe.rs:170-178`), HTTP-поиск только через `pending_http_searches` | `core-net.md` |
| 27 | HTTPS first flight | донорский `modern` ClientHello из `d2k_hello_from_profile` (`httpsprobe.c:171-177`) | rustls-сгенерированный ClientHello (`response.rs:572-605`) | `core-net.md` |
| 28 | HTTPS result loss | `done[17]`; при переполнении `lost++`, результат отбрасывается (`httpsprobe.c:337-340`) | `sync_channel(16)` + блокирующий `send`, счётчика `lost` нет (`https_probe.rs:132,181-183`) | `core-net.md` |
| 29 | HTTP-upgrade 307 | `X-D2K-HTTP-Upgrade: provider-portal` (`httpup_logic.c:145`) | **брендинг R2O:** `X-R2O-HTTP-Upgrade: provider-portal` (`httpup.rs:513`); имена `d2k`/`d2o` запрещены в рабочем коде, differential нормализует заголовок | `core-net.md` |
| 30 | HTTP-search plan identity | `d2k-plan 1 11` + FNV-префикс `d2k-http:` (`httpsearch.c:300,330-333`) | **брендинг R2O:** `r2o-plan 1 11` + `b"r2o-http:"` (`http_search.rs:699,784`); имена `d2k`/`d2o` запрещены в рабочем коде | `core-net.md` |
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
- `?` (0): не осталось; все строки реестра разобраны и имеют E/P/N.

## Следующий этап: исправление подтверждённых расхождений

После завершения аудита (все 1982 функции получили строку и глубокую сверку)
перехожу к фиксу. Приоритет:

1. **Packet-path/безопасность:** `wire_udp` IPID_ZERO/TOS; raw UDP/TTL
   (`IP_NODEFRAG`, `qp_recv_ttl`); `raw_set_segment_max`; полный
   `shape_opts`; HTTP80 capacity 128/1024; ENOBUFS-дренаж только истёкших.
2. **Данные/каталог:** `Binding.tcp_profile` и default `family=4` закрыты
   для load/save; `exact_key`/`own_first`/`newer_name_binding`/`covering`
   сравнивают профиль из shape, но отдельного `trigger_tcp_profile`,
   `family_recovery` и `unfit` пока нет;
   FNV `plan-%08x`; HTTP live failures/счётчики; QUIC `name_ok`; TLS 1.2
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

## Фактические прогоны этого прохода (2026-11-12)

Выполнены на закреплённом доноре `a378e230947ebfd011439e1cac0f1e994d883aae`:

- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/test-core-crypto-differential.sh` —
  **PASS**, 13 кейсов (SHA-256/HMAC/HKDF/AES-128-ECB/GCM).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-fallback-differential.sh` —
  **PASS** (`family=0 result=-1`; `family=4/6 result=0 dropped=7 sent=19`).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-control-events-differential.sh` —
  **PASS** (ACK/APPLIED, candidate ACK, lost-ACK settle).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-catalog-persist-differential.sh` —
  **PASS** (save_atomic, конкурентное внешнее обновление).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-known-plans-differential.sh` —
  **PASS** (совместимость known-plan, tried hashes, volume bucket, порядок успехов,
  стабильная дедупликация, лимит 8 планов).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-meas-differential.sh` —
  **PASS** (send/receive interruption: C/Rust `ERROR` и `REJECTED` совпадают).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-queue-order-differential.sh` —
  **PASS** (queue expiry/order, QUIC-yield TCP priority).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-measured-split-differential.sh` —
  **PASS** (measured split, bridge raw-split gate, unplannable-hit fallback,
  scheduler adapter contracts).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-resource-limit-differential.sh` —
  **PASS** (CPU-разбор донора, AIMD-пороги/backoff/потеря ресурса/потолок слотов).
- `R2O_EXPECTED_DONOR_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
  R2O_DONOR_CORE=/mnt/e/d2o-a378w/core sh scripts/r2o-http-search-differential.sh` —
  **PASS** (HTTP no-executed-trial, baseline local failure/cut retry rules).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-ack-applied-persist-differential.sh` —
  **PASS** (own-first candidate budget reset, proven RX survives snapshot reask).
- `R2O_EXPECTED_DONOR_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
  R2O_DONOR_DATAPATH=/mnt/e/d2o-a378w/datapath sh scripts/r2o-quic-hello-differential.sh` —
  **PASS** (ClientHello из проверенного Initial, повтор полного CH, истечение кэша,
  сборка CH из нескольких датаграмм).
- `R2O_DONOR_CORE=/mnt/e/d2o-a378w/core
  R2O_EXPECTED_DONOR_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
  sh scripts/r2o-quic-local-address-differential.sh` —
  **PASS** (политика локального адреса QUIC).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-layered-rx-differential.sh` —
  **PASS** (own-first layered RX identity-repeat, gzip-control, inconclusive-plan).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-ech-rx-ladder-differential.sh` —
  **PASS** (порядок refill ECH RX-лестницы, батчи по 8 планов, курсор,
  отсутствие fallback-плеч).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-raw-profile-differential.sh` —
  **PASS** (SYN-профили family 4/6 с TS и без, selftest key 0/1/2/3,
  инвалидация после 3 ошибок, white-TS без client timestamps, recheck).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-scheduler-cooldown-differential.sh` —
  **PASS** (challenge cooldown: сигнал/endpoint, late-RST, exhausted).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-catalog-sync-differential.sh` —
  **PASS** (area ACK/deadline, удаление после отключения группы, swap-with-last
  при удалении, асинхронные HTTP bound set/delete кадры).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-control-dropped-differential.sh` —
  **PASS** (учёт control-событий без подключённого peer как dropped).
- `R2O_EXPECTED_DONOR_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
  R2O_DONOR_DATAPATH=/mnt/e/d2o-a378w/datapath sh scripts/r2o-route-gate-differential.sh` —
  **PASS** (маршрутный UDP-поток остаётся ядру, hex-метки и `none`).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-own-first-differential.sh` —
  **PASS** (порядок/deadline own-планов, ECH witness/config fallback).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-panel-bind-default-differential.sh` —
  **PASS** (безопасный LAN-выбор панели и умолчания bind).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-scheduler-concurrent-endpoint-differential.sh` —
  **PASS** (конкурентный опрос одного endpoint при свободных слотах).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-raw-connect-fallback-differential.sh` —
  **PASS**, 18 тестов (raw-connect timeout recovery, control/retry на том же peer,
  отмена на каждой стадии, CLEAR-подтверждение, seeded baseline, transport-ошибки).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-raw-split-support-differential.sh` —
  **PASS** (Linux-гейт raw-split без CAP_NET_RAW; `raw_split=1`).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-raw-emission-cancel-differential.sh` —
  **PASS** (production tcp-split packets после нормализации IPv4 ID/checksum;
  отмена raw-эмиссии: `result=cancelled packets=2 waited_ms=20`).
- `R2O_DONOR_CORE=/mnt/e/d2o-a378w/core
  R2O_EXPECTED_DONOR_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
  sh scripts/r2o-discord-voice-lifecycle-helper.sh` —
  **PASS** (endpoint lifecycle A→B, очередь, lease, proof, persistence;
  address-план и общий `@discord-voice`).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/test-quic-app-bytes-differential.sh` —
  **PASS** (`VERDICT|match`; уникальные QUIC stream bytes совпадают, включая
  смещения >32 бит: `4294967306`, `8589934602`).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/test-quic-budget-init-differential.sh` —
  **PASS** (budget 0/1/25/2^31-1/2^31/2^32-1; `need` 50/2/50/4294967294/0/4294967294).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/test-quic-short-control-differential.sh` —
  **PASS** (`VERDICT|match`; partial→NOT_RUN, complete→PASS, stalled/refused→CUT).
- `R2O_DONOR_CORE=/mnt/e/d2o-a378w/core sh scripts/r2o-discovery-quic-stop-differential.sh` —
  **PASS** (host lifecycle-тест планировщика C: «все проверки прошли»; Rust-тест
  «остановка QUIC worker обслуживает удаление временной пробы»).
- `R2O_DONOR_DATAPATH=/mnt/e/d2o-a378w/datapath
  sh scripts/r2o-quic-stun-watch-differential.sh` —
  **PASS** (C `test_quic_session`: «все проверки прошли»; C/Rust исключают STUN
  и Discord Discovery из QUIC conntrack-stall).
- `R2O_DONOR_CORE=/mnt/e/d2o-a378w/core
  R2O_EXPECTED_DONOR_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
  sh scripts/r2o-discord-discovery-differential.sh` —
  **PASS**, 23 теста (RTP/RTCP, SSRC, capacity, control reconnect, повторный
  discovery, смена endpoint, истечение voice proof).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/test-discord-scheduled-udp-differential.sh` —
  **PASS** (UDP emission `delay_us=15000` и packet bytes совпали;
  `METRICS queue=1 refusals=1`).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/test-discord-udp-observer-reconnect-differential.sh` —
  **PASS**, 24 теста (SSRC reconnect, endpoint change, 10-минутный двусторонний
  сеанс; `suspects=1`, `expire=1` совпали).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/test-discord-voice-confirm-delete-retry-differential.sh` —
  **PASS** (`attempts=2 retained=0`: повтор удаления после неудачного подтверждения).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/test-discord-voice-discovery-arm-differential.sh` —
  **PASS** (`PREFIX:000100002112a442…`; `stun-before-discovery ×1`, серия Discovery
  проверена, звук проверяется в приложении).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/test-discord-voice-shutdown-cleanup-differential.sh` —
  **PASS** (`attempts=2 retained=0`: очистка при shutdown с повтором удаления).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/test-discord-voice-trial-clock-differential.sh` —
  **PASS** (`trial_at_nine_minutes_after_launch|active`,
  `queued_after_ten_minutes|expired`).
- `R2O_DONOR_ROOT=/mnt/e/d2o-a378w sh scripts/r2o-diagnostics-differential.sh` —
  **не выполнен**: сборка донорского `test_httpsearch` падает на duplicate
  symbols `d2k_plan_apply`, `d2k_plan_max_emit`, `d2k_actions_cancel`,
  `d2k_actions_free` (archive `libd2k_udp.a` и объект того же файла).
  Это ограничение донорского Makefile, а не отказ R2O; R2O-тесты не запускались.

Эти прогоны усиливают соответствующие E-строки, но не заменяют перечисленные
в таблицах пробелы (P/N) и не покрывают живые/аппаратные сценарии.

## Как читать таблицы

Каждая строка — одна C-функция. Колонка «строки» — диапазон `line..end_line`
в закреплённом дереве D2O. «Размер» — число строк тела. «Назначение» —
краткое описание по телу, а не по имени. «R2O-аналог» — конкретный файл и
строка/символ; «нет» означает, что аналог не найден. «Доказательство/пробел» —
тест, дифференциал или конкретная непроверенная ветвь.

> Важно: наличие строки в таблице не является доказательством паритета.
> Доказательством является статус E с тестом либо P с явно названным пробелом.
