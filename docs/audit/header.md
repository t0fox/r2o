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
| datapath-plan | 183 | 108 | 69 | 5 | 1 |
| detect | 159 | 49 | 100 | 10 | 0 |
| **Итого** | **1982** | **630** | **1310** | **40** | **2** |

Это не оценка паритета: 1310 P означают «код есть, доказательство ветвей
неполное», 40 N — в основном диагностические/CLI-функции и несколько реальных
расхождений (`SET_HTTPS` TTL, `ARM_SHAPE` UDP, `wire_udp` IPID_ZERO,
`udpruntime` raw UDP, `tls12/tls13` record-layer).

Статусы пересчитаны строго по колонке «статус»: описание вида «N цифр подряд»
больше не считается статусом, экранированные `\|` не сдвигают колонки.


## Итог и подтверждённые расхождения (2026-11-11)

Покрытие реестра: **1982/1982** функций. Статусы: **E 621 / P 1319 /
N 40 / ? 2**. Это не 100 % паритет: E требует целевого теста/дифференциала,
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

## Отчёты групп

| Группа | Функций | Отчёт | Состояние |
|---|---:|---|---|
| core-net: TLS/HTTP/ECH/QUIC/voice/verify | 548 | `docs/audit/core-net.md` | готов |
| core-state: catalog/sched/diagnostics/link/… | 692 | `docs/audit/core-state.md` | готов |
| datapath-core: d2kd/session/hold/udp/nfq/… | 400 | `docs/audit/datapath-core.md` | готов |
| datapath-plan: plans/ctl/raw/route/… | 183 | `docs/audit/datapath-plan.md` | готов |
| detect: trigger/poison/raw/classify/response | 159 | `docs/audit/detect.md` | готов |

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
