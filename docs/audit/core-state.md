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
| `jparse_raw_int` | 207–239 | 33 | `-`? + цифры, **не более 18**; `.`/`e`/`E` → отказ; вызывается и из `jskip_value`, т.е. float запрещён в **любом** поле | типы serde (`i32/u8/u16/i64`) + `validate` | **P** | **Совпадает для известных полей:** диапазоны i32/u8/u16 проверяются типами, float в них отвергается. **Подтверждённое отличие:** C отвергает float/exponent и 19-значное целое **и в неизвестных полях** через `jskip_value`; serde_json неизвестные поля пропускает без проверки грамматики числа, поэтому `"future":1.5` C отвергнет, Rust примет. Тест на этот вход не найден. |
| `jparse_i32` | 241–250 | 10 | int64 → проверка `INT_MIN..INT_MAX` | serde_json `i32` | **P*** | Диапазон тот же; C сначала парсит int64 с 18-цифровым пределом, Rust — типом. |
| `jparse_u8` | 252–261 | 10 | 0..255 | serde_json `u8` | **P*** | Диапазон тот же. |
| `jparse_u16` | 263–272 | 10 | 0..65535 | serde_json `u16` | **P*** | Диапазон тот же. |
| `jparse_bool_i` | 274–284 | 11 | ровно `true`/`false` | serde_json `bool` | **P*** | Эквивалентно. |
| `jparse_string_dyn` | 305–402 | 98 | escape `\" \\ \/ \b \f \n \r \t \uXXXX`; **U+0000 и любая суррогатная половина → отказ**; неэкранированные <0x20 → отказ | serde_json `String` + `validate_string` | **P** | **Совпадает:** escape-набор, отказ на битом `\u`, запрет управляющих байтов. **Отличия:** (1) serde_json отвергает одиночный суррогат, но **принимает `\u0000`**; (2) NUL отвергается только для строк, прошедших `validate_string` (`catalog.rs:1095-1104`), а неизвестные поля пропускаются — C отвергает файл целиком; (3) C не собирает суррогатные пары и отвергает их, Rust собирает валидную пару. Для известных полей с NUL поведение совпадает. |
| `jparse_string_fixed` | 408–422 | 15 | динамический разбор, затем `n+1 > outcap` → отказ (без обрезки) | `String` + `validate_string` в `Catalog::validate` (`catalog.rs:543-625`) | **P** | Лимиты совпадают с C-буферами: box.id 39, plan.id 39, proto 7, signal.kind 23, binding kind 7/target 255/plan_id 39/probe_path 511/ech_origin 255, domain name/suffix 255, plan_id 39. `plan.text` без предела, как и C. Проверка выполняется после разбора, а не в момент строки; на отказ файла это не влияет. |
| `read_fixed_digits` | 428–445 | 18 | ровно N цифр без пропуска пробелов | `time` Rfc3339 | **P*** | Разбор даты/времени целиком передан `time`; отдельного шага нет. |
| `eat_lit` | 447–454 | 8 | ожидать конкретный символ с отказом | `time` Rfc3339 | **P*** | То же. |
| `jparse_rfc3339` | 462–500 | 39 | `YYYY-MM-DDTHH:MM:SS[.дробь]Z`; проверка только `month 1..12`, `day 1..31`, `hour<=23`, `min<=59`, `sec<=60` — **без календарной сверки** | `catalog::parse_timestamp` (`catalog.rs:1156-1164`) | **P** | **Подтверждённое отличие:** C принимает 31 февраля и секунду 60 (нормализует через `days_from_civil`), Rust `time::OffsetDateTime` отвергает несуществующую дату и, вероятно, секунду 60. Для реальных каталогов совпадает; unit `accepts_old_catalogs`/`rejects_trailing`. |
| `jskip_value` | 545–611 | 67 | пропуск любого JSON-значения; глубина **64** (`D2K_JSON_MAX_DEPTH`, `catalog.c:531`); числа — тем же `jparse_raw_int`, т.е. float → отказ | serde_json (ignore unknown) + `check_json_depth` (`catalog.rs:1126-1153`) | **P** | **Совпадает:** глубина 64, неизвестные поля не ломают разбор. **Подтверждённое отличие:** float/exponent в неизвестном поле C отвергает, serde_json принимает и отбрасывает. Ограничение глубины Rust считает по сырому тексту (скобки в строках игнорируются), C — по фактическому спуску; на валидном JSON эквивалентно. Unit `rejects_excessive_nesting`. |
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
| `handle_binding_key` | 834–885 | 52 | поля binding: kind/target/plan_id/level/confirmed/successes/enabled/transport/family(4/6)/shape/tcp_profile(0..2)/verified_by/input/probe_path/ech_origin/recheck_since/budget | `catalog.rs:166-198 Binding` + validate | **P** | **Подтверждённое расхождение:** C хранит и проверяет `tcp_profile` (`catalog.c:862-869`), family только 4/6 (`:852-859`); Rust `Binding` (`catalog.rs:166-198`) **не имеет `tcp_profile`** — serde молча игнорирует ключ, при save поле теряется. `family` в `Binding` есть, но без C-валидации 4/6 в `validate`. Для старых каталогов shape 1/2 + tcp_profile 1/2 теряется измеренный TS-профиль. |
| `parse_binding` | 886–890 | 5 | `memset`, `out->family=4`, затем `parse_object` | `catalog.rs:166-198 Binding` | **P** | C явно ставит `family=4` до разбора (`catalog.c:887-888`) и валидирует 4/6 при наличии. Rust `#[derive(Default)]` + `#[serde(default)]` даёт family=0; `serialize_family` пишет 0 как 4 только при сохранении, `validate` не нормализует. Старый каталог без `family` в памяти получает 0; поведение потребителей family=0 отличается от C. |
| `elem_binding` | 891–893 | 3 | элемент массива bindings | Vec<Binding> | **P*** | static-хелпер |
| `d2k_cat_shape_fits` | 905–912 | 8 | `stored==0 или got==0` → 1; иначе **только равенство** | `group_shape_fits` (`live.rs:284`, `main.rs:3023`) | **P** | **Подтверждённое расхождение:** C `stored==0 \|\| got==0 \|\| stored==got`; Rust дополнительно принимает `saved==SHAPE_MODERN && observed==SHAPE_ECH_TCP` (`1` vs `6`). C-вызовы `sched.c:3522/5088/7858` такую пару отвергают, Rust — нет. |
| `handle_box_key` | 918–939 | 22 | id (fixed 39), created/updated (RFC3339), fingerprint, plans и bindings (null→пусто) | `catalog.rs:31-43 BoxRecord` | **P** | Поля/порядок совпадают, `BoxRecord` содержит `bindings` (`catalog.rs:41-42`), `null_to_default` для plans/bindings; id ≤39, timestamps через `parse_timestamp`; unit `round_trips`. |
| `parse_box` | 940–943 | 4 | `memset` + объект box | `BoxRecord` + `#[serde(default)]` | **P*** | C обнуляет поля до разбора (нет поля → 0), Rust default; эквивалентно. |
| `elem_box` | 944–946 | 3 | элемент массива boxes | `Vec<BoxRecord>` | **P*** | Тонкий адаптер; лимита числа коробок в C нет, в Rust тоже. |
| `handle_domain_observation` | 953–970 | 18 | name[256]/plan_id[40], key transport/family/shape, probe_path[256], ech_origin[256], evidence u8, at RFC3339 | `catalog.rs:213-226 DomainObservation`, `:199-207 GroupKey` | **P** | Лимиты совпадают (255/39/255/255), поля те же; Rust `GroupKey` flatten. Unit `groups`. |
| `parse_domain_observations` | 972–989 | 18 | массив наблюдений; **256** максимум (`D2K_GROUP_OBSERVATION_MAX`) | `CatalogInput.domain_observations` + `MAX_DOMAIN_OBSERVATIONS=256` (`catalog.rs:17,357-361`) | **P** | Лимит и глубина совпадают; Rust отвергает 257-е наблюдение в `parse` и `validate`. Отдельного differential на ровно 256/257 нет. |
| `handle_net_whitelist_key` | 991–999 | 9 | name[256], searched, tx_only, confirmed_utc | `catalog.rs:242-256 NetworkWhitelist` | **P** | Поля/лимит 255 совпадают; `confirmed_utc` → `Option<i64>` с `optional_timestamp`, `tx_only` пишется только true. Unit catalog. |
| `handle_catalog_key` | 1001–1027 | 27 | корневые ключи: `boxes`, `domain_observations`, `domain_groups_frozen`, `domain_groups_disabled`, `domain_groups_disabled_at`, `network_whitelist`; `schema`/`updated`/`domain_groups` пропускаются | `CatalogInput` (`catalog.rs:1222-1239`) → `Catalog.domain_state` (`:364-381`), `CatalogOutput` (`:1240+`) | **E** | C разбирает те же top-level поля; `domain_observations` ≤256, frozen/disabled/disabled_at, network_whitelist. Rust `CatalogInput` читает их, `schema != 1` отвергает, неизвестные ключи игнорирует, конвертирует в `DomainState`; `CatalogOutput` пишет обратно. Есть `skips_unknown_fields`, persist differential и `validate` лимитов. |
| `parse_catalog_obj` | 1028–1034 | 7 | `memset`, `parse_object` с глубиной 1 | `Catalog::parse` (`catalog.rs:344-389`) | **P** | C стартует глубину с 1; Rust `check_json_depth` (64) + serde_json. **Отличие:** Rust дополнительно отвергает файл >64 МиБ (`MAX_CATALOG_BYTES`), у C предела размера нет. Разбор верхнего объекта эквивалентен. |
| `prune_unavailable_domain_groups` | 1036–1053 | 18 | после restore удалить группу, если нет **enabled** плана с тем же `plan_id` и proto (`transport 17` → `quic`, иначе `tls`) | `DomainState::restore` (`groups.rs:15`) → `rebuild` | **P** | **Подтверждённое расхождение:** C после `d2k_group_restore` проходит по группам и удаляет те, чей план отключён/отсутствует в каталоге (`catalog.c:1036-1053`). Rust `restore`/`rebuild` работают только с `DomainState` и не видят `boxes`, поэтому группа остаётся при отключённом/удалённом плане. Unit `derived_domain_groups_are_ignored` покрывает недоверие сохранённым `domain_groups`, но не prune по плану. |
| `free_box` | 1062–1070 | 9 | освободить планы/привязки коробки | `Drop`/`Vec` | **P*** | Ручное освобождение заменено владением; утечек нет. |
| `d2k_catalog_free` | 1072–1082 | 11 | освободить каталог | `Drop` | **P*** | То же. |
| `d2k_catalog_memory_bytes` | 1084–1097 | 14 | память каталога: `n_boxes*sizeof`, планы/привязки, `strlen(text)+1`, `sizeof(groups)` | `catalog_bytes` = длина `to_json_at()` (`main.rs:16768`) | **P** | **Расхождение метрики:** C считает **in-memory** размер структур и текстов; Rust — длину **сериализованного JSON**. Числа систематически разные (JSON включает ключи/форматирование, но не capacity Vec). Для диагностического поля `catalog_bytes` смысл меняется; C/Rust differential на объём нет. |
| `read_whole_file` | 1103–1143 | 41 | fopen/fseek/ftell/fread весь файл | `std::fs::read` (`catalog.rs:396`) | **P*** | Чтение целиком эквивалентно; **отличие:** C не ограничивает размер, Rust `Catalog::load` отвергает >64 МиБ до чтения (`catalog.rs:391-396`). |
| `d2k_catalog_load` | 1145–1191 | 47 | разбор JSON, restore групп, prune, запрет мусора после `}`, освобождение при ошибке | `Catalog::load`/`parse` (`catalog.rs:344-404`) | **P** | **Совпадает:** schema=1, null→пусто, restore наблюдений, запрет trailing garbage (serde_json `from_slice`), освобождение через Err. **Подтверждённые отличия:** (1) нет `prune_unavailable_domain_groups`; (2) файл >64 МиБ отвергается, C читает любой; (3) `d2k_group_restore` и `DomainState::restore` могут расходиться в деталях ранжирования. Persist differential покрывает старые каталоги/trailing garbage, но не prune и не 64 МиБ. |
| `write_json_string` | 1198–1218 | 21 | escape `\" \\ \n \r \t \b \f`, control <0x20 → `\u00xx`, UTF-8 как есть | `serde_json` | **P*** | Набор escape совпадает; serde_json может выбрать `\u001f`/короткие формы так же. Побайтовая сверка не заявлена. |
| `wr_indent` | 1220–1222 | 3 | 2 пробела на глубину | `serde_json::to_string_pretty` (2 пробела) | **P*** | Тот же отступ; порядок/форматирование массивов проверяются persist differential частично. |
| `write_json_array` | 1230–1240 | 11 | `[]` или многострочный список с запятыми без последней | `serde_json` pretty | **P*** | Семантика та же; байтовый формат массивов не сверялся целиком. |
| `write_signal_elem` | 1242–1257 | 16 | kind/ttl/ttl_delta/tos/ipid/volume/seen; `packets` только при nonzero | `catalog.rs:139-150 Signal` (`packets` skip if zero) | **P*** | Порядок полей и пропуск нулевого `packets` совпадают; persist differential частичный. |
| `write_fp` | 1259–1266 | 8 | method + signals | `catalog.rs:46-49 Fingerprint` | **P** | Поля/порядок те же; signals ≤8 проверяется `validate`. |
| `write_plan_elem` | 1268–1280 | 13 | id/proto/text/added(RFC3339)/successes/enabled | `catalog.rs:153-163 Plan` | **P** | Поля/порядок те же; `added` форматируется `time` вместо ручного `format_rfc3339`. Persist differential частичный. |
| `write_binding_elem` | 1282–1332 | 51 | kind/target/plan_id/level/confirmed/successes/enabled/transport/family/shape/**tcp_profile**/verified_by/input/probe_path/ech_origin/recheck_since/budget; family 0→4; необязательные только при значении | `catalog.rs:165-198 Binding` | **P** | **Подтверждённый пробел:** C всегда пишет `tcp_profile` (`catalog.c:1307`); в Rust `Binding` поля нет, ключ исчезает при save. Остальное совпадает: `serialize_family` 0→4, `probe_path`/`ech_origin` только непустые, `recheck_since`/`budget` только ненулевые. Полный побайтовый формат save не сравнивался. |
| `write_box_elem` | 1334–1351 | 18 | id/created/updated/fingerprint/plans/bindings | `catalog.rs:31-43 BoxRecord` | **P** | Поля/порядок те же; timestamps форматируются `time`. Persist differential — через save_atomic. |
| `write_domain_key` | 1353–1358 | 6 | `transport/family/shape/probe_path/ech_origin` | `GroupKey` (`catalog.rs:199-207`) | **P*** | JSON-поля те же; C пишет в одну строку, serde — pretty. |
| `write_domain_observation` | 1359–1366 | 8 | name/plan_id/key/evidence/at | `DomainObservation` (`catalog.rs:211-220`) | **P*** | Поля те же; форматирование pretty иное. |
| `write_domain_group` | 1367–1372 | 6 | suffix/plan_id/key/evidence_count | `DomainGroup` (`catalog.rs:223-233`), `at` skip | **P*** | Поля те же, `at` не пишется в обоих. |
| `d2k_catalog_save` | 1374–1442 | 69 | schema=1, updated=now, boxes, domain_groups/observations/frozen/disabled/disabled_at, network_whitelist; проверка каждой записи + fflush/fsync/fclose | `Catalog::to_json_at(updated)` (`catalog.rs:445-487`) | **P** | **Семантика полей совпадает** (schema 1, derived groups, conditional whitelist). **Отличия:** C выставляет `updated=time(NULL)` внутри и пишет поверх файла; Rust принимает `updated` параметром и отдельного не-атомарного save нет — только `save_atomic`. Побайтовый формат save не сравнивался. |
| `d2k_catalog_save_atomic` | 1445–1477 | 33 | путь ≤255, запись `.new`, save, rename, fsync каталога, удаление tmp при ошибке | `Catalog::save_atomic` (`catalog.rs:489-541`) | **E** | `r2o-catalog-persist-differential.sh` (включая конкурентное внешнее обновление). **Отличия реализации:** Rust tmp `.new.<pid>.<nonce>` + `create_new`, C фиксированный `.new`; оба fsync-ят файл и каталог, удаляют tmp при ошибке. |

### `core/compose.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_net_whitelist_count` | 107–109 | 3 | число имён встроенного белого списка TCP 16-20 (266) | `r2o_rx_volume.rs:1-8 r2o_rx_volume_name_count` | **E*** | Rust `R2O_RX_VOLUME_NAMES` = 266 строк; тест `r2o_rx_volume.rs:85` (`== 266`, first `9gag.com`, last `zoho.com`). |
| `d2k_net_whitelist_name` | 110–112 | 3 | имя белого списка по индексу, NULL за концом | `r2o_rx_volume.rs:10-14 r2o_rx_volume_name` | **E*** | Rust `lines().nth(index)`, `None` за концом; тот же список/порядок, тест `:85-87`. |
| `wr16be` | 150–150 | 1 | запись big-endian u16 | push_u16 | **P*** | static-хелпер TLV |
| `rd16be` | 151–151 | 1 | чтение big-endian u16 | read_u16 | **P*** | static-хелпер TLV |
| `wr32be` | 152–155 | 4 | запись big-endian u32 | push_u32 | **P*** | static-хелпер TLV |
| `tlv_rec` | 162–174 | 13 | TLV-запись с проверкой вместимости | plan_text::push_record | **P*** | static-хелпер; используется только TLV-тест-билдерами, прямого differential нет |
| `tlv_header` | 186–198 | 13 | заголовок D2KP и записи id/proto | plan_text::header | **P*** | static-хелпер; используется только TLV-тест-билдерами |
| `plan_tlv_stamp_ident` | 218–240 | 23 | проверяет REC_ID на offset 12 (len 16), считает FNV-1a по TLV с нулевым id, пишет `plan-%08x` (12 байт + NUL) в REC_ID | `discovery.rs:1450 plan_text_for_trial`, `:1462 text_with_id` | **P** | **Подтверждённое различие:** C считает идентификатор из байтов TLV (FNV-1a 32) и вписывает `plan-%08x` в 16-байтное поле; Rust подставляет в текст **переданный вызывающим 16-байтный trial-id** (`plan_text_for_trial`) и не имеет FNV-функции над TLV. C/Rust differential этого TLV-штампа нет. |
| `overlap_plan_tlv` | 258–270 | 13 | TLV-план перекрытия слева | compose_d2o overlap_plan_text + plan_text::compile_text | **P** | TLV-вариант используется только C-тестом test_plantlv; Rust собирает текст и компилирует, прямого TLV-differential нет |
| `reorder_plan_tlv` | 277–290 | 14 | TLV-план обратного порядка | compose_d2o reorder_plan_text + plan_text::compile_text | **P** | TLV-вариант используется только C-тестом; прямого TLV-differential нет |
| `badsum_fake_plan_tlv` | 296–316 | 21 | TLV-план badsum + fake с повторами/gap | compose_d2o badsum_fake_plan_text + plan_text::compile_text | **P** | TLV-вариант используется только C-тестом; текст покрыт compose differential, TLV — нет |
| `checksum_plan_tlv` | 322–326 | 5 | TLV-план проверки контрольной суммы | compose_d2o checksum + plan_text::compile_text | **P** | TLV-вариант используется только C-тестом; прямого TLV-differential нет |
| `to_hex` | 331–338 | 8 | байты в hex | hex-хелпер | **E*** | static-хелпер |
| `ev_matches_flow` | 351–366 | 16 | сравнение события с потоком в обе стороны | main.rs flow match helpers | **P** | перенесено; direct unit/diff на C-функцию нет |
| `wait_for_event3` | 397–421 | 25 | ожидание одного из трёх типов событий с code/filter/flow и дедлайном | main.rs ask event loop | **P** | реализовано в run_r2o_ask; C/Rust differential нет |
| `wait_for_event` | 423–429 | 7 | ожидание одного типа события | main.rs ask event loop | **P** | обёртка; см. wait_for_event3 |
| `props_bind_any` | 494–524 | 31 | socket/bind/getsockname локального TCP/UDP-порта, IPv6 `IPV6_V6ONLY=1`, ошибка при `out_fd==NULL` | `main.rs:22501-22611 BoundTcpProbe::open` | **P** | **Совпадает:** socket, bind, getsockname, отказ при нулевом порту, family 4/6. **Отличия:** Rust **не ставит `IPV6_V6ONLY`**, ставит `SO_MARK=0x2d` (C bind не метит), всегда владеет `OwnedFd` и не имеет ветви `out_fd==NULL`; C закрывает fd при отсутствии out_fd. |
| `d2k_props_bind` | 526–528 | 3 | bind IPv4 TCP | `BoundTcpProbe::open(4, ..)` | **P*** | Тонкая обёртка family=4; наследует отличия `props_bind_any`. |
| `d2k_props_bind_family` | 530–532 | 3 | bind TCP family 4/6 | `BoundTcpProbe::open` | **P*** | family 4/6; наследует отсутствие `IPV6_V6ONLY`. |
| `d2k_props_bind_udp` | 534–536 | 3 | bind IPv4 UDP | нет прямого аналога в ask-пути | **P*** | UDP-bind для вопросов не используется (вопросы TCP); отдельного Rust-хелпера нет. |
| `d2k_props_bind_udp_family` | 538–540 | 3 | bind UDP family 4/6 | нет прямого аналога | **P*** | То же; C-обёртка над `props_bind_any(SOCK_DGRAM)`. |
| `d2k_props_contact` | 542–545 | 4 | TCP-обращение к цели IPv4 с отправкой приветствия | CLI `run_r2o_ask` (`main.rs:493+`, `BoundTcpProbe`) | **P** | Реализовано только в CLI-опросе; production-discovery R2O этим путём вопросы не задаёт. C/Rust differential контакта нет. |
| `d2k_props_contact_on` | 547–551 | 5 | то же с готовым fd | `BoundTcpProbe` (fd внутри) | **P*** | C принимает `use_fd`; Rust владеет сокетом с момента open, отдельного «готового fd» нет. |
| `d2k_props_contact_on_family` | 553–558 | 6 | то же для family 4/6 | `BoundTcpProbe::connect` | **P*** | family 4/6; наследует отсутствие tcp-профиля. |
| `tcp_timestamps_read` | 567–578 | 12 | прочитать `/proc/sys/net/ipv4/tcp_timestamps`, допустить '0'..'2' | `raw_probe.rs:676` (только для host_offers_ts) | **P** | Rust читает тот же файл, но **не для connect-профиля**: helper'а `tcp_timestamps_read/write` вокруг connect нет. Для `host_offers_ts` чтение и дефолт 1 совпадают. |
| `tcp_timestamps_write` | 580–588 | 9 | записать tcp_timestamps | нет | **N** | Во всём `crates/` нет записи в `/proc/sys/net/ipv4/tcp_timestamps`; временное переключение sysctl не портировано. |
| `connect_with_tcp_profile` | 591–636 | 46 | под мьютексом прочитать/переключить tcp_timestamps, connect, восстановить; -2 при сбое профиля | нет | **N** | Rust не меняет sysctl и не имеет кодов -2/восстановления; `BoundTcpProbe::connect` делает обычный неблокирующий connect. Профиль TCP-опций задаётся только параметром `client_tcp_has_timestamps` для уже снятого приветствия, а не настройкой ядра. |
| `d2k_props_contact_on_family_tcp_profile` | 638–753 | 116 | полный TCP-contact: опции, nonblock connect, локальные адрес/порт, отправка hello, опциональный tcp-профиль | `main.rs:22501+ BoundTcpProbe`, `run_r2o_ask` | **P** | Перенесены socket/TCP_NODELAY/таймауты/неблокирующий connect/getsockname/отправка, но **параметр `tcp_timestamps` и sysctl-переключение отсутствуют**; C возвращает -3 при сбое профиля, Rust такого кода не имеет. `SO_NOSIGPIPE`-ветки macOS нет (Rust использует `MSG_NOSIGNAL`). |
| `build_fake_body` | 786–796 | 11 | тело fake: decoy-префикс + заполнитель 0f, длина `2*truth` | classify_measured.rs `fake_len=n*2`, `append_measured_payload` | **E** | C `want=truth_len*2`, `memset(0f)`, decoy копируется в голову с обрезкой до want; Rust `fake_len = n.saturating_mul(2)`, `append_measured_payload(..., fake_len, decoy)` даёт те же байты (decoy/0f). Покрыто `tests/measured_plan.rs`. |
| `d2k_props_question_plan` | 798–841 | 44 | TLV-план вопроса 0..4: overlap (`0f`+seqovl), reorder (2 split+reverse+pace), checksum (`0f`×64), protocol (control hello+`2*truth`), duplicates (`0f`×`2*truth`, repeats 2, gap 20 мс) | `ask.rs:432-491 question_plan` → `plan_text_for_poison` | **P** | **Совпадает:** порядок вопросов и параметры воздействий (seqovl, disorder, badsum, decoy hello, repeats/gap) те же. **Подтверждённые отличия:** C собирает TLV, id плана — FNV-1a `plan-%08x`; Rust собирает текст `r2o-plan` и подставляет переданный 16-байтный `plan_id`; у overlap C `payload 1` с id=1, Rust `plan_text_for_poison` даёт `payload 2` (эффект тот же, байты разные). C/Rust differential планов вопросов нет; unit `ask.rs:568` проверяет `record_question_passed`. |
| `d2k_props_question_passed` | 845–864 | 20 | ответ вопроса → d2k_props: overlap/reorder/checksum=NO, protocol→parses=YES+checksum=NO, duplicates=YES | `ask.rs:492-506 record_question_passed` | **E** | Ветви совпадают посимвольно; Rust-тест `ask.rs:568` проверяет protocol и запись только по проходу. |
| `question_retire` | 874–879 | 6 | снять пробный план: DEL_NAME_PROBE с transport 6, имя/shape/sport/family | `main.rs:528+ client.delete_name_probe` | **P*** | Кадр DEL_NAME_PROBE тот же; C игнорирует ошибку снятия, Rust возвращает ошибку и в части ветвей прерывает опрос. |
| `d2k_props_ask` | 881–884 | 4 | опрос свойств без трассировки | `main.rs:332 run_r2o_ask`, `ask::question_plan` | **P** | Обёртка существует только в CLI; в discovery C-опрос заменён raw-пробами (см. `prop_send_next`). |
| `step_rc` | 889–898 | 10 | записать `rc`/`err` шага трассы | `r2o_print_ask_trace`/`AskStep` (`main.rs`) | **P*** | C пишет в массив `d2k_props_step`; Rust печатает строку трассы, структуры шага нет. |
| `d2k_props_ask_traced` | 900–1191 | 292 | 5 вопросов: bind порт, SET_NAME_PROBE, ACK, contact, APPLIED+ServerHello/REFUSED, снятие непрошедшего, остановка на первом прошедшем | `main.rs:332-780 run_r2o_ask`, `:646 wait_for_ask_proof`, `:677 record_question_passed`, `ask.rs:432` | **P** | **Совпадает:** 5 вопросов в одном порядке, bind до установки, SET_NAME_PROBE, ACK, contact, APPLIED+ServerHello, снятие непрошедшего, остановка на первом прошедшем. **Отличия:** (1) C id плана — FNV-1a TLV, Rust — 16-байтный `plan_id`/`trial_id`; (2) C не сверяет trial_id в ACK, Rust отвергает чужой; (3) C считает проход по `applied && server_hello`, Rust требует ещё `exchange_seen`; (4) C игнорирует ошибку снятия плана, Rust возвращает ошибку и может прервать опрос; (5) CLI differential не сравнивает stdout. |
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
| `d2k_arm_plan` | 1552–1751 | 200 | один сборщик: md5→отказ; seg=`d2k_arm_segment(send_cap)`; disorder_pos (только MODERN, без других полей) / oob sni_middle / payload 1 fake (decoy hello или 0f×64) / payload 2 seqovl hello или 0f×N / poison badsum,tcpts,ipidzero,ttl,seqshift=-66000 / split payload_start+1 и sni_middle / fake repeats,gap_us,place before/between / seqovl / order / pace 12/15 мс | `r2o_fallback.rs:168+ plan` (49 fallback-arm), `classify_measured.rs plan_text_for_poison` (измеренные arm) | **P** | **Совпадает:** одиночные fallback-плечи, `disorder_pos` (fallback +2), `oob`, `seqovl`/`seqovl_hello`, fake badsum/ttl/seq_out, between/repeats/gap, pace. **Подтверждённые отличия:** `r2o_fallback::plan` не умеет `tcpts`/`ipidzero` (их умеет `classify_measured`), `disorder_pos` в fallback только +2; C принимает произвольные сочетания arm и `decoy`, Rust разделён на два builder'а. `r2o-fallback-differential.sh` покрывает 49 arm × 5 `send_cap`, но не произвольные комбинации и не `d2k_arm_plan` целиком. |
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
| `http_search_portal` | 168–174 | 7 | класс 3 (портал) → `d2k_httpsearch_portal`: пропуск при `!g_hs`, family 0, UNKNOWN/PROBING, `d2k_https_upgrade(st)` | `r2o_http_search_https_action` (`main.rs:4729-4750`) | **P** | **Совпадает:** портал обрабатывается только при `response_code==3` и отсутствии live-bound failure. **Отличия:** Rust при известном состоянии (`Some(state)`) даёт `Suppress` для `should_redirect()` (Served/TlsBlocked) и `Queue` иначе; при неизвестном — `Wait` при `probe_pending`, иначе `Suppress`. C при UNKNOWN/PROBING просто выходит, а upgrade-состояния в httpsearch не передаёт. Набор состояний тот же, но pending/unknown различаются. |
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
| `atomic_peak` | 141–144 | 4 | CAS-цикл: поднять пик до `live`, при гонке перечитать | CAS-цикл в `memory_acquire` (`diagnostics.rs:178-189`) | **P*** | Алгоритм тот же (compare-exchange до `live`), отдельной функции нет. |
| `d2k_diag_memory_acquire` | 145–151 | 7 | учесть выделение сайта | diagnostics::memory_acquire | **P** | unit memory_tracking_and_madvise_json_match_d2o_shape |
| `d2k_diag_memory_release` | 152–156 | 5 | учесть освобождение сайта | diagnostics::memory_release | **P** | тот же unit |
| `d2k_diag_memory_alloc_failure` | 157–160 | 4 | учесть отказ аллокатора | diagnostics::memory_alloc_failure | **P** | тот же unit |
| `d2k_diag_memory_snapshot` | 161–169 | 9 | снимок сайтов памяти | diagnostics::memory_snapshot | **P** | unit |
| `d2k_diag_memory_counts` | 170–179 | 10 | суммарные tracked tcp/tls/quic bytes | diagnostics::tracked_memory_bytes | **P** | unit |
| `d2k_diag_set_madvise` | 180–180 | 1 | сохранить статистику madvise | Recorder::set_madvise | **P** | unit memory_tracking_and_madvise_json_match_d2o_shape |
| `record_anomaly` | 181–187 | 7 | записать аномалию в кольцо (12 слотов) | Recorder::record_anomaly | **P*** | static-хелпер |
| `d2k_diag_record_write_error` | 188–191 | 4 | `write_failures++` и аномалия kind=2 с **кодом ошибки** `error` | `Recorder::record_write_error` (`diagnostics.rs:1165-1176`) | **P** | **Подтверждённое расхождение:** C сохраняет `error` в `anomaly.code`, `write_anomalies` печатает его как `error_code` (`diagnostics.c:388`); Rust-функция принимает только `stage` и всегда пишет `"error_code": null`. Все вызовы (`path/serialize/size-limit/open-temp/flush-close/rename`) теряют errno/код. Unit `records_only_while_enabled`; C/Rust differential на код ошибки нет. |
| `d2k_diag_record` | 192–201 | 10 | записать событие в кольцо 64: id/at/family/trigger/elapsed/queue/units/target/ip/path/kind/shape/protocol/outcome/reason; пределы target 255, protocol 15, outcome 31, **reason 255**, ip 47, path 15, kind 7 | Recorder::record (`:754`) | **P** | **Подтверждённое расхождение:** C `reason[256]` → `copy` режет до **255** байт; Rust явно задаёт `("reason", 1024)` (`diagnostics.rs:768`). Остальные пределы совпадают. Rust сам добавляет `id`, если его нет, и всегда перезаписывает `at`; C берёт id/at из структуры. C не проверяет `enabled` (это делает вызывающий), Rust `record` выходит при `!enabled` — эквивалентно при штатном включении. |
| `d2k_diag_record_limit` | 202–212 | 11 | записать переход лимита (32) | Recorder::record_limit | **P** | unit/differential частично |
| `value` | 213–217 | 5 | число после ключа в /proc | diagnostics::meminfo/read_number | **P*** | static-хелпер |
| `compact_kib` | 218–220 | 3 | сжать KiB в i32 или -1 | diagnostics compact | **P*** | static-хелпер |
| `compact_bytes_kib` | 221–221 | 1 | байты в KiB с округлением вверх или -1 | diagnostics compact | **P*** | static-хелпер |
| `compact_bytes` | 222–222 | 1 | байты в i32 или -1 | diagnostics compact | **P*** | static-хелпер |
| `compact_count` | 223–223 | 1 | счётчик в u8 с насыщением | diagnostics compact | **P*** | static-хелпер |
| `proc_pid_dir_present` | 225–229 | 5 | существует ли /proc/<pid> как каталог | diagnostics::process_detail | **P*** | static-хелпер |
| `optional_proc_status` | 230–237 | 8 | различить unsupported/unavailable для smaps_rollup | diagnostics::read_smaps_rollup | **P*** | static-хелпер |
| `read_proc` | 238–259 | 22 | pid из pid-файла, comm, VmRSS/HWM/RssAnon/Threads/VmData/VmSwap | diagnostics::process_memory (`:1411`) | **P** | C требует **точного** `comm == names[i]` и читает только основной pid-файл; Rust принимает `name == spec.comm \|\| name.starts_with(spec.comm)` (из-за усечения comm до 15 байт) и пробует `fallback_pidfile` (`r2o-controller4.pid` и т.п.). Поля status читаются теми же ключами; unit `process_memory_follows_pidfiles_and_restarts`, C-oracle нет. |
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
| `d2k_domain_member` | 66–72 | 7 | normalize(name)+normalize(suffix)+base(suffix), затем совпадение по границе метки | domain::is_member (`:74`) | **P** | C требует успешный `d2k_domain_base(suffix)`; Rust — `registrable_domain(suffix).is_some()`. Сравнение `name==suffix \|\| prefix.ends_with('.')` эквивалентно. Отличие наследует `normalize` (односложные имена). Unit `tests/domain.rs`. |

### `core/groups.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_group_key_make` | 9–17 | 9 | ключ области: transport/family/shape/path/ech_origin; path/origin короче полей, иначе -1 | `catalog::GroupKey` + `validate_key` (`groups.rs:424`) | **P** | C проверяет только длины path/origin и копирует; контекст transport/family/shape проверяется позже в `valid()` при learn/restore. Rust `validate_key` проверяет контекст сразу: transport 6/shape 1/2/6/8–13 или 17/3, family 4/6, path/origin ≤255 без NUL. Для штатных вызовов результат тот же; C/Rust differential групп нет. |
| `d2k_group_key_same` | 19–23 | 5 | равенство transport/family/shape/path/ech_origin | `GroupKey: PartialEq` | **E** | C пять сравнений; Rust derived `PartialEq` по всем полям. `tests/groups.rs`. |
| `valid` | 24–36 | 13 | NUL-терминация, family 4/6, transport 6/shape 1/2/6/8–13 или 17/3, evidence ровно 1/2/4/8, BLOCKED/PLAN_FAILED требуют plan_id | `validate_key` + `canonical_evidence` (`:389`) | **P** | Транспорт/форма/семейство и требование plan_id совпадают. **R2O-расширения:** `OPERATOR_REJECT=32`; `learn` принимает маску `BLOCKED|PLAN_FAILED=5` как base (`groups.rs:65-80`), тогда как C `valid` пропускает только точные `1/2/4/8` — raw-наблюдение с 5 C отвергнет, Rust примет. C-проверка NUL через `memchr`; Rust `contains(&0)`. |
| `member` | 38–41 | 4 | суффикс по границе метки: `name==suffix` или `name[-len-1]=='.'` | `groups::member` (`:443`) | **E** | Формула совпадает посимвольно; `tests/groups.rs`. |
| `votes` | 45–60 | 16 | живые/устаревшие голоса: DIRECT_CLEAR без исключения → 0; BLOCKED&same plan&name!=suffix; итог `live>=2 && live>stale && live+stale>=3` | `groups::votes` (`:484`) + `latest_vote` (`:514`) | **P** | Формула и условия совпадают; C обновляет `*latest` внутри `votes`, Rust считает `latest_vote` отдельным проходом. C-oracle нет, unit `tests/groups.rs`. |
| `failures` | 61–71 | 11 | число PLAN_FAILED для суффикса/ключа/плана | `groups::failures` (`:531`) | **P*** | Три условия (`PLAN_FAILED`, key, plan_id, member) совпадают; unit `tests/groups.rs`. |
| `add_group` | 72–102 | 31 | замена/выбор по failures, count, at, plan_id; запрет покрытой группы; frozen при 64 | `groups::add_group` (`:544`) | **P** | Выбор совпадает: меньше failures, затем больше count, затем свежее at, затем лексикографически меньший plan_id; удаление покрытых групп и `frozen` при 64 — те же. Unit `tests/groups.rs`; C/Rust differential нет. |
| `rebuild` | 103–120 | 18 | из BLOCKED-наблюдений: base, перебор суффиксов от длинного к короткому, последний с голосами | `groups::rebuild` (`:326`) | **P** | C требует `d2k_domain_base`, идёт от первого суффикса к короткому и перезаписывает `best` при `count!=0` (побеждает самый короткий с голосами); Rust `registrable_domain` + `labels[start..]`, та же перезапись. Наследует разницу PSL/`normalize`; unit `tests/groups.rs`. |
| `cover` | 122–132 | 11 | самый длинный покрывающий суффикс для ключа; disabled/overflow → NULL | `groups::covering_group` (`:450`) | **P*** | C `disabled \|\| n_groups>MAX` → NULL; Rust то же, `max_by_key(len)`. Unit `tests/groups.rs`. |
| `d2k_group_learn` | 133–245 | 113 | приём: normalize/base, admitted_clear, слот по plan_id/any/replace, frozen/capacity, disabled-reenable, reclaim oldest, замена, OR PLAN_FAILED, очистка дублей, rebuild | `groups::learn` (`:65`) | **P** | Основная логика совпадает построчно: slot/any/replace, changed/frozen, reclaim exact INCONCLUSIVE→BLOCKED→first, disabled_at=max, PLAN_FAILED OR, admitted exception, очистка без PLAN_FAILED, rebuild. **Подтверждённые отличия:** (1) Rust `OPERATOR_REJECT` — ранний `Ok(false)` и отдельная маска, C такого бита не знает; (2) Rust принимает base-evidence `BLOCKED|PLAN_FAILED=5`, C `valid` — только 1/2/4/8; (3) при disabled C удаляет только `evidence==BLOCKED`, Rust — любой `evidence & BLOCKED` (шире); (4) C не делает rebuild при вставке INCONCLUSIVE, Rust делает (набор групп не меняется). Unit `tests/groups.rs`. |
| `d2k_group_restore` | 246–273 | 28 | канонизация масок, normalize/base, at≥0, дубликаты (same plan или нет PLAN_FAILED), rebuild | `groups::restore` (`:15`) + `canonical_evidence` (`:389`) | **P** | Канонизация совпадает: снять INCONCLUSIVE, ADMITTED_EXCEPTION требует DIRECT_CLEAR, BLOCKED снимает DIRECT_CLEAR|PLAN_FAILED, DIRECT_CLEAR+PLAN_FAILED→PLAN_FAILED; дубликаты — то же условие. **R2O-расширение:** OPERATOR_REJECT (база BLOCKED|PLAN_FAILED|5). |
| `d2k_group_match` | 274–293 | 20 | нормализация, disabled/overflow, longest suffix, исключение DIRECT_CLEAR или PLAN_FAILED того же плана | `groups::match_domain` (`:358`) | **P** | Формула и выбор longest совпадают; **Rust дополнительно исключает `OPERATOR_REJECT`**. C/Rust differential нет, unit `tests/groups.rs`. |
| `d2k_group_forget` | 294–310 | 17 | удалить PLAN_FAILED имени/транспорта/семейства, rebuild при удалении | `groups::forget_failures` (`:271`) | **E** | C и Rust: normalize, фильтр name/transport/family/PLAN_FAILED, swap_remove, rebuild при dropped>0, возврат числа. Unit `tests/groups.rs`. |
| `d2k_group_expire` | 311–324 | 14 | удалить PLAN_FAILED с `at < now-max_age`, rebuild | `groups::expire_failures` (`:304`) | **E** | Условия `max_age<=0 \|\| now<max_age` и `at < cutoff` совпадают; swap_remove/rebuild. Unit `tests/groups.rs`. |

### `core/link.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `execution_context` | 45–51 | 7 | пустой хвост → 0 (id/binding не измерены); иначе ровно 20 байт: execution_id BE p[0..8], binding p[8..20]; ошибка при неверной длине/чтении binding | `control::decode_applied/decode_refused` + `BindingContext` | **E*** | C `n==0` не ошибка, `n!=20`/`binding_read` → -1; Rust-декодеры APPLIED/REFUSED читают те же 20 байт; `d2o_control_differential`. |
| `say` | 56–64 | 9 | текст ошибки link | io::Error/Result | **P*** | static-хелпер |
| `wait_readable` | 70–86 | 17 | poll с повтором на EINTR | poll в ControlClient | **P*** | static-хелпер |
| `read_exact` | 92–106 | 15 | дочитать ровно N байт, EINTR повтор | Read::read_exact | **P*** | static-хелпер |
| `write_all` | 108–131 | 24 | дописать всё, MSG_NOSIGNAL | Write::write_all / send | **P*** | static-хелпер |
| `hex_nibble` | 133–138 | 6 | значение hex-цифры | plan_text::hex_nibble | **P*** | static-хелпер |
| `hex_decode` | 144–159 | 16 | hex в байты с проверкой | plan_text::decode_hex | **P*** | static-хелпер |
| `d2k_link_open` | 161–189 | 29 | AF_UNIX SOCK_STREAM; пустой/длинный путь → ошибка; connect | `ControlClient::connect` (`control`/`main.rs`) | **P** | Реализовано; C использует блокирующий `connect` и `sizeof(sockaddr_un)`, Rust — `UnixStream`/connect. C/Rust differential на ошибки connect/длину пути нет. |
| `d2k_link_close` | 191–195 | 5 | закрыть link | Drop | **P*** | static-хелпер |
| `d2k_link_peer_closed` | 197–221 | 25 | poll(0); POLLNVAL→EBADF/-1; HUP/ERR→1; иначе 0 | `ControlClient` peer-closed check | **P** | C различает POLLNVAL и HUP/ERR, EINTR повторяет; Rust-проверка peer-close есть, но отдельного differential нет. |
| `d2k_link_next` | 223–522 | 300 | прочитать кадр 6+plen, разобрать ключ потока и все типы событий (HELLO/HTTP/SUSPECT/STATS/EXCHANGE/CLIENT_TCP/SHAPE/ACK/APPLIED/PROTO/REFUSED) | r2k_core::control::{read_frame,decode_*} | **E** | d2o_control_differential.c + tests/control.rs; декодирование APPLIED/REFUSED/ACK покрыто отдельно |
| `d2k_link_set_name` | 524–527 | 4 | SET_NAME без пробного порта | control::encode_set_name | **P** | точный кадр проверен tests/control.rs; C/Rust differential кодирования не найден |
| `d2k_link_set_name_probe` | 531–536 | 6 | SET_NAME_PROBE с local port | control::encode_set_name_probe | **P** | unit-тест; C/Rust differential кодирования не найден |
| `send_name_plan` | 538–630 | 93 | family 4/6, fd, name 1..255, transport 6/17, hex even, plan cap; frame: len/name/shape/family/[sport]/plan/[trial или area_id] | `control::encode_set_name*` | **P** | **Подтверждённое расхождение:** C **не проверяет `shape` вовсе** и кодирует любой байт (`link.c:591`); Rust `encode_set_name` отвергает форму вне `{1,2,3,4,5,6,7} ∪ {8..13}`. C также не проверяет совместимость плана с формой/транспортом; Rust `valid_name_probe_plan_records`/`valid_domain_plan_records` проверяют transport/proto. Для валидных команд кадры совпадают (tests/control.rs); C/Rust differential кодирования нет. |
| `d2k_link_set_name_family` | 632–637 | 6 | SET_NAME/SET_NAME_PROBE по family | control::encode_set_name | **P** | Тонкая обёртка выбирает команду по `sport_be`; наследует расхождение `send_name_plan` (C не проверяет shape). |
| `d2k_link_set_name_bound` | 639–643 | 5 | SET_NAME_BOUND с identity: только `token != NULL`, затем `send_name_plan` | control::encode_set_name_bound | **P** | **Подтверждённое расхождение:** C принимает любую `shape` и любой `token` (в т.ч. нулевой); Rust требует **`shape == SHAPE_HTTP`** и **ненулевой trial_id** (`control.rs:1399-1406`), иначе отказ. C-датапат (`ctlsrv.c`) может отвергнуть позже; стадия отказа иная. |
| `d2k_link_del_name_bound` | 645–657 | 13 | условное удаление name binding: имя/transport/known/kind NAME/!temporary | control::encode_delete_name_bound | **P** | Построчно совпадает: `family` не передаётся (C не проверяет), Rust `encode_delete_name_bound` проверяет transport 6/17, `binding.is_known()`, `kind==1`, `!temporary`. Тест `encodes_a_bounded_exact_name_binding_delete`; C/Rust diff нет. |
| `d2k_link_set_name_probe_trial` | 659–668 | 10 | SET_NAME_PROBE с trial_id: требует `sport_be != 0` | control::encode_set_name_probe | **P** | C проверяет только ненулевой порт; Rust дополнительно требует `valid_name_probe_plan_records(shape, plan)` и family 4/6, trial не проверяет. Для валидного плана кадр совпадает; набор отказов шире. |
| `area_context_valid` | 670–675 | 6 | допустимая комбинация transport/shape/family для области | control::valid_domain_area_context | **P*** | static-хелпер; формула сверена ниже (P). |
| `d2k_link_set_suffix_family` | 677–684 | 8 | SET_SUFFIX с планом | control::encode_set_suffix | **P** | **Подтверждённое расхождение:** C `send_name_plan(..., SET_SUFFIX)` проверяет только имя/family/transport/hex; Rust `encode_set_suffix` дополнительно проверяет shape (1/2/3/6 или 8–13), family и **`valid_domain_plan_records`** (transport/proto плана). C кодирует несовместимый план, Rust отвергает. |
| `d2k_link_set_https` | 686–705 | 20 | fd>=0, name 1..253; ttl любой u32 BE; frame len/name/ttl | `control.rs:1777-1792 encode_set_https` | **E** | **Расхождение закрыто 2026-11-12:** `encode_set_https` принимает любой `u32` и кодирует его как есть, как C-link; обрезку до `MAX_HTTPS_TTL_SECONDS = 7 суток` (`D2K_HTTPS_TTL_MAX_S`) выполняет датапат. Тесты: `encodes_the_exact_https_name_and_ttl_for_the_datapath` (включая `21_601` и `u32::MAX`) и `set_https_command_accepts_an_exact_name_with_a_bounded_ttl`. |
| `d2k_link_set_stall_budgets` | 707–729 | 23 | SET_STALL_BUDGETS список бюджетов | control::encode_set_tcp_stall_budgets | **P** | unit бюджеты tcp/reset; C/Rust diff нет |
| `send_area_key` | 731–752 | 22 | общий кодировщик domain-area команд (name/key/area_id) | control::encode_domain_area_key | **P*** | static-хелпер |
| `d2k_link_del_suffix_family` | 754–757 | 4 | DEL_SUFFIX | control::encode_delete_suffix | **P** | кодировщик есть; C/Rust differential нет |
| `d2k_link_set_bypass_family` | 758–761 | 4 | SET_BYPASS | control::encode_set_bypass | **P** | кодировщик есть; differential нет |
| `d2k_link_del_bypass_family` | 762–765 | 4 | DEL_BYPASS | control::encode_delete_bypass | **P** | кодировщик есть; differential нет |
| `d2k_link_area_identified` | 767–777 | 11 | area-команда с identity/area_id | control::encode_set_suffix/encode_domain_area_key | **P** | unit area_ack_round_trips; C/Rust differential нет |
| `addr_shape_ok` | 783–787 | 5 | 1/2/3(QUIC)/5(VOICE)/6(ECH_TCP)/**8..13** | `control::valid_addr_shape` (`control.rs:1462`) | **P*** | **Подтверждённое расхождение:** C принимает контекстные TCP-формы 8–13 (`d2k_link.h:311-328`, `link.c:786`); Rust `valid_addr_shape` — только `{1,2,3,5,6}`. `SET_ADDR`/`DEL_ADDR` с формой 8–13 C кодирует, Rust отвергает. |
| `d2k_link_set_addr` | 789–792 | 4 | SET_ADDR IPv4 | control::encode_set_addr | **P** | Тонкая обёртка family=4; наследует расхождение `addr_shape_ok`. |
| `d2k_link_set_addr_family` | 794–848 | 55 | SET_ADDR family 4/6: shape, hex, 16-байтный адрес, план без проверки совместимости | control::encode_set_addr | **P** | C проверяет `addr_shape_ok` (включая 8–13), кодирует `family + 16 байт + shape + hex`; Rust дополнительно вызывает `valid_addr_plan_records` (transport/proto плана) и не принимает 8–13. Для формы 1/2/3/5/6 и совместимого плана кадр совпадает. |
| `addr_probe_flow_bytes` | 852–866 | 15 | 38 байт: family, src/dst 16-байт, src_port_be, dst_port_be, transport 17; **src_port_be=0 разрешён**, dst≠0 | `control::udp_addr_probe_flow` (`control.rs:1670`) | **P*** | **Подтверждённое расхождение:** C явно допускает `src_port_be=0` — голосовой опыт «на любой клиентский порт» (`link.c:855`); Rust `udp_addr_probe_flow` требует `source.port()!=0` (`control.rs:1677`). `SET_ADDR_PROBE`/`DEL_ADDR_PROBE` voice с нулевым исходным портом C кодирует, Rust отвергает. |
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
| `d2k_link_del_addr_family` | 1056–1076 | 21 | family 4/6, ip nonnull, shape ok; frame len=20: family+16 addr+shape | `control::encode_delete_addr` | **P** | C собирает фиксированный 18-байтный кадр (len 20) и проверяет `addr_shape_ok`; Rust кодировщик проверяет family/shape и план не нужен. Для формы 1/2/3/5/6 кадр совпадает; C/Rust differential нет. |
| `d2k_ev_outer_appdata` | 1079–1094 | 16 | `seen_types & (1 << (23-20))` — внешний тип 23, а не первый код | `r2k_core::control` event seen_types | **P*** | C проверяет маску, а не `code`; Rust декодирует `seen_types` и использует её в classify/verify. Отдельного differential нет. |

### `core/match.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `same_evidence` | 38–73 | 36 | одна улика: kind volume/rx-volume/rx-volume-wire → `abs(volume delta)<=4`; иначе `abs(ttl delta)<=2` и tos/ipid точно; ttl_delta/seen не читаются | catalog.rs:1077-1090 `same_signal` | **P*** | Совпадает посимвольно: C `int`-вычитание и `abs`, Rust `i64::from().abs()`, `abs_diff`, `tos/ipid`; `VOLUME_SLACK=4`, `TTL_SLACK=2`. Unit `tests/catalog.rs`; отдельного boundary-теста на 4/5 и 2/3 нет. |
| `d2k_fp_same` | 75–125 | 51 | method, внешний обход b→a, все приметы того же рода в a, `kind_seen && !agreed → false`, хотя бы один общий род | catalog.rs:59-84 `Fingerprint::is_compatible_with` | **P** | Логика совпадает: направленный обход наблюдаемого, просмотр всех same-kind, break на первом согласии, `any_agreement`, `common>0`. Unit `tests/catalog.rs` (partial evidence, all same-kind signals); C/Rust differential нет. |
| `d2k_catalog_match` | 127–136 | 10 | первый индекс коробки с совместимым отпечатком, иначе -1 | catalog.rs:537-541 `match_fingerprint` | **E** | C возвращает `i`/`-1`; Rust `position` → `Option<usize>`. Unit `tests/catalog.rs`. |

### `core/meas.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `nap_us` | 52–55 | 4 | `nanosleep` на us: `tv_sec=us/1e6`, `tv_nsec=(us%1e6)*1000` | `std::thread::sleep(Duration::from_micros)` (`raw_probe.rs:1238` в `emit_plan_packets`, `response.rs:856` в `probe_trigger`) | **P*** | C округляет в нс; Rust `Duration::from_micros` точен до нс. Оба игнорируют результат прерывания (C `nanosleep` → `(void)`, Rust sleep не возвращает ошибку). Фактическая пауза не измерялась. |
| `d2k_mark_real` | 61–70 | 10 | `setsockopt(SO_MARK, int mark)`; вне Linux/без `SO_MARK` → -1 | `response.rs:289-310 probe_socket` (`SO_MARK` c_int), `:303-307`; `raw_probe.rs` RawConn | **P*** | C приводит `u32`→`int`, возвращает результат `setsockopt`; R2O `probe_socket` ставит тот же `SO_MARK` и **игнорирует** ошибку, а признак `marked` вычисляется отдельно через `get_socket_mark` (`response.rs:803-805`). C при ошибке метки продолжает опыт с `marked=0`; R2O — тоже (проба идёт, `marked=false`). Платформенная ветка та же; отдельного differential нет. |
| `d2k_accept_serverhello` | 87–94 | 8 | `len>=6 && b[0]==0x16 && b[1]==0x03 && b[5]==0x02` | `classify.rs:549-553 trigger_accepts(ServerHello)` | **P** | Байтовое правило совпадает посимвольно. Целевого C/Rust differential нет; используется в `response.rs:882` и `raw_probe.rs:1264`; сокетные тесты `response.rs:1442-1463`. |
| `d2k_accept_tls_record` | 96–99 | 4 | `len>=3`, `b[0]` ∈ {0x16,0x15}, `b[1]==0x03` | `classify.rs:554-556 trigger_accepts(TlsRecord)` | **P** | Совпадает, включая Alert 0x15 и версию только по старшему байту 0x03. Используется для белого ClientHello (`main.rs:34054`); отдельного C/Rust differential нет. |
| `d2k_accept_any` | 101–104 | 4 | `len>0` | `classify.rs:557 trigger_accepts(Any)` | **P** | Совпадает: `!bytes.is_empty()`. Покрыто сокетными тестами `response.rs:1480-1528`, не C-оракулом. |
| `cuts_valid` | 109–116 | 8 | строго возрастающие `0<cut<len`; любой плохой разрез — отказ всего опыта | `classify.rs:28-56 split_offsets`; `raw_probe.rs:1150-1152` | **P** | **Подтверждённое расхождение:** C отвергает **весь** опыт при `cut<=prev` или `cut>=len`; Rust `split_offsets` молча фильтрует такие разрезы, берёт первые 8, сортирует и дедуплицирует, затем строит диапазоны. Raw-путь R2O (`probe_tcp_split`) требует **ровно один** разрез (`cuts.len()!=1 → Local("invalid cut")`), C штатно шлёт несколько. Дифференциала на multi-cut/невалидные разрезы нет. |
| `send_all` | 124–136 | 13 | доотправка куска до `len`; `send()<=0` → -1 (сбой опыта, не «молчание») | `response.rs:807-847` send-loop в `probe_trigger` | **P*** | partial write обрабатывается циклом в обоих. `MSG_NOSIGNAL` есть. C блокирующий с `SO_SNDTIMEO=8 с`; Rust неблокирующий: `EAGAIN` → `poll(POLLOUT, PROBE_SEND_TIMEOUT)`, `EINTR` → `Transport("write: ...")`, `send==0` → `Local`. `r2o-meas-differential.sh` покрывает send-timeout/EINTR. |
| `connect_bounded` | 142–173 | 32 | fcntl nonblock; connect; immediate success → restore flags; EINPROGRESS → poll(POLLOUT,timeout) → SO_ERROR; restore flags | `response.rs:254-287 connect_until`, `:289-310 probe_socket` | **P** | Ветви совпадают: `EINPROGRESS/EALREADY/EINTR`, poll по `POLLOUT` до дедлайна, затем `SO_ERROR`. C восстанавливает исходные `fcntl` flags и работает блокирующе; R2O `SOCK_NONBLOCK` оставляет сокет неблокирующим, а send/recv обходят `EAGAIN` через poll. Поведение эквивалентно; differential на все errno-ветви не заявлен. |
| `d2k_meas_once` | 175–267 | 93 | literal IPv4/IPv6 (zone-id отвергнут), mark, TCP_NODELAY, SO_SNDTIMEO 8 с, SO_RCVTIMEO wait (0/>5000→5000), connect 8 с, разрезы+gap, recv 512, accept | `response.rs:776-889 probe_trigger`; `raw_probe.rs:1140-1172 probe_tcp_split` | **P** | **Расхождения:** (1) C всегда обычный TCP-сокет; R2O на Linux при непустых `cuts` и `!no_raw` уходит в raw-путь, который принимает только один разрез; (2) C отвергает IPv6 zone-id (`%`), R2O резолвит host через `ToSocketAddrs` и фильтрует семейство; (3) C `marked_out=(mark==0)`, при `mark!=0` ставит метку; R2O `expected_mark=mark.unwrap_or(BYPASS_MARK=0x2d)` и проверяет `get_socket_mark`, `Some(0)` отключает маркировку. Перенесены: TCP_NODELAY, send/recv 512, accept-фильтр, gap, `SO_SNDTIMEO`/`SO_RCVTIMEO` через poll/дедлайн. `r2o-meas-differential.sh` покрывает send/recv EINTR и таймауты, не multi-cut/zone. |
| `d2k_meas` | 269–293 | 25 | серия: `repeats<=0→3`; ERR→err+fail; PASS→pass; UNPROVEN→unproven+fail; SILENT→fail; `marked` — AND | `classify.rs:997-1005 Tally`, `:1082-1240 measure`, `:634-642 with_mark_status` | **P** | Логика совпадает: `unmarked` sticky по серии, ERR→`errors+1`/`fail+1`, UNPROVEN→`unproven+1`/`fail+1`, PASS→`pass+1`. Тесты `classify.rs:2135-2178`, `2309-2361` проверяют unmarked/unproven. Отдельного C/Rust differential на серию нет. |
| `udp_now_ms` | 307–311 | 5 | `CLOCK_MONOTONIC` в мс | `std::time::Instant` | **P*** | static-хелпер; монотонность `Instant`, прямого сравнения с `CLOCK_MONOTONIC` нет. |
| `d2k_udp_port_claim` | 313–339 | 27 | `getsockname(fd)` → порт; `port==0→-1`; кольцо 4096, возраст 480 с; недавний → 1 без записи, иначе запись/0 | `r2o_quic_http3.rs:16-22,127-148 r2o_quic_port_was_recently_claimed` | **P** | C: `UDP_RECENT_CAP=4096` (`meas.c:300`), `D2K_UDP_RESIDUAL_MS=480000`; Rust: `R2O_QUIC_RECENT_PORTS=4096`, `R2O_QUIC_RESIDUAL_PORT_AGE=480s`, `VecDeque` + `Instant`. API иной: C принимает fd, Rust — порт; Rust-цикл `udp_socket_fresh` держит до 16 старых сокетов, чтобы не переиспользовать порт (`:82-124`). Отдельного C/Rust differential нет. |
| `d2k_udp_port_forget_all` | 341–346 | 6 | сброс реестра недавних UDP-портов | нет прямого аналога | **N** | Подтверждено: единственный вызов в D2O — `core/test_quic_arm_data.c:440`; production-вызовов нет. В R2O реестр живёт в `static OnceLock<Mutex<...>>` (`r2o_quic_http3.rs:21-22`) и не сбрасывается. Это тестовый сброс, не packet-path контракт. |

### `core/measured.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `append_fmt` | 10–20 | 11 | `vsnprintf` в `buf+pos` с `cap-pos`; `n<0` или `n>=cap-pos` → -1; иначе `pos+=n` | `String` + `write!` (`classify_measured.rs:142-378`), финальный `checked_text` (`:430-434`) | **P*** | C проверяет место на каждом добавлении и отвергает усечение; Rust пишет в неограниченный `String`, а предел 8191 проверяет один раз в `checked_text` (`:431-433`). Для планов <8192 байт результат совпадает; при переполнении C вернул бы -1 раньше, Rust — `Err` в конце. |
| `append_hex` | 22–28 | 7 | каждый байт как `%02x`, ошибка добавления пробрасывается | `classify_measured.rs:422-428 hex` | **P*** | Формат тот же (`{byte:02x}`); Rust собирает в `String`, C — в буфер с проверкой cap. Отдельного differential нет. |
| `d2k_white_decoy_hello` | 33–44 | 12 | проверить `out/cap>=5/name`; `hello_rename` тела профиля `rx_fake` (SNI), копия первых 3 байт записи, длина записи `hl` | `hello.rs:598-600 r2o_rx_fake_client_hello` → `client_hello_from_profile` | **E** | C переименовывает тело `d2k_rx_fake_template+5` и восстанавливает 5-байтную запись; Rust `client_hello_from_profile` переименовывает полный профиль `profiles/r2o_rx_fake.hex`, сохраняя запись. C-фикстура `main.rs:34050-34061` сравнивает payload с `tests/fixtures/r2o-rx-fake-hcaptcha-c.bin`; длинное имя — C-фикстура плана (`r2o_rx_volume.rs:165-177`). |
| `template_plan` | 57–82 | 26 | tcp-template-v1: minexec 13 при autottl иначе 8; segment `d2k_arm_segment(send_cap)`; payload hello; `poison 1 [badsum][tcpts][autottl=delta,min-max]`; fake ×8; split; forward | `r2o_rx_volume.rs:26-58 r2o_rx_volume_plan_for_client` | **P** | **Совпадает:** проверка `hello_len<=send_cap && send_cap-hello_len>=132`, payload hex, fake `repeats=8 gap_us=0 place=before tlsmod=rnd,dupsid`, split/order. **Отличия:** (1) C принимает **badsum** как порчу, R2O RX-план — только `tcpts`/`autottl`; (2) C `segment=d2k_arm_segment(send_cap)`, R2O фиксирует `R2O_RX_VOLUME_SEGMENT=1400` (`r2o_rx_volume.rs:3,57`); при `send_cap=1280` C даёт 1208, R2O 1400; (3) R2O требует нормализованное имя и проверяет его `domain::normalize`; C полагается на `hello_rename`. C-фикстуры split2/split5 покрывают tcpts; autottl — unit `:112-128`. |
| `d2k_rx_volume_plan_named` | 84–88 | 5 | обёртка `..._client(..., client_has_ts=1)` | `r2o_rx_volume.rs:21-23 r2o_rx_volume_plan` | **P** | R2O `r2o_rx_volume_plan` = `r2o_rx_volume_plan_for_client(..., true)`, как C. Отличия наследуются: нет параметра `shape` (C требует `MODERN`), фиксированный segment 1400, брендинг `r2o-plan`. C-фикстуры variant 0/4 и длинное имя; варианты 1/2/3 — unit `:94-110`. |
| `d2k_rx_volume_plan_client` | 90–110 | 21 | variant 0..4 → split `{2,1,3,4,5}`; `shape==MODERN`; белый hello; `client_has_ts` → tcpts (minexec 8) или autottl (`1,2-12`, minexec 13) | `r2o_rx_volume.rs:26-58 r2o_rx_volume_plan_for_client` | **P** | **Подтверждённое расхождение сигнатуры:** C отвергает `shape != D2K_SHAPE_MODERN` (`measured.c:96-98`); Rust `shape` не принимает и всегда строит modern-план. Совпадают: split-таблица, проверка variant, `r2o_rx_fake_client_hello`, `send_cap-hello>=132`, minexec 8/13, `poison tcpts`/`autottl=1,2-12`, fake ×8, split/order. Segment фиксирован 1400 (C `d2k_arm_segment`). |
| `d2k_rx_volume_plan` | 114–117 | 4 | RX-volume план с именем по умолчанию `hcaptcha.com` | `r2o_rx_volume.rs:62-72 r2o_rx_volume_candidate` (fallback-имена) | **P** | Отдельной функции с именем по умолчанию нет: R2O использует `hcaptcha.com` только для запасных вариантов после списка 266 имён (`candidate(name_count+variant)`). Для variant 0..4 текст совпадает с C-фикстурой после замены брендинга; API/точка вызова иные. |
| `measured_payload` | 121–138 | 18 | `payload-pad64 ID LEN 15`, пробел+base64(prefix), prefix обрезается до LEN, перевод строки | `classify_measured.rs:381-397 append_measured_payload`, `:399-420 base64` | **P** | Формат и обрезка `prefix.len().min(length)` совпадают; base64-таблица и `=` для 1/2 байт те же. **Отличие:** Rust отвергает `length==0` (`:387-389`), C допускает (но все C-вызовы передают >0: `2n`, `n-mid`, `ov`). C-фикстуры покрывают обычные payload; границы 1/2/3 байта и пустой префикс — без differential. |
| `d2k_tcp_split_plan` | 140–151 | 12 | проверить `trigger_len<=16384`, `0<split<trigger_len`; segment=`d2k_arm_segment(send_cap)`; `d2k-plan 1 5 … segment … split +split order forward pace gap_us` | `main.rs:6292-6317 r2o_discovery_measured_split_plan` | **E** | `scripts/r2o-measured-split-differential.sh` компилирует `tests/d2o_measured_split_differential.c` с `core/measured.c` и сравнивает с Rust для `send_cap` 0/1492/1280/100/72, split 0/1/1024, verdict prefix/whole. Сегмент `send_cap.saturating_sub(72).min(1400)` совпадает с `d2k_arm_segment`; проверено `main.rs:6307-6312`. |
| `d2k_arm_plan_measured_cap` | 153–385 | 233 | сборка измеренного плана: split-only, composite template, disorder, oob, fake/between/seqovl, ttl/md5/tcpts/tsup/ipidzero/autottl, minexec и segment | `classify_measured.rs:50-379 measured_plan_text` | **P** | **Подтверждённые пробелы:** (1) `Poison` (`classify.rs:133-152`) **не содержит** `autottl` и `tcpts_up`, поэтому ветви C `a->autottl` (`measured.c:343-345`) и `a->tcpts_up` (`:349`) невыразимы; (2) R2O `fake` (`classify_measured.rs:118-119`) не учитывает `autottl`/`tcpts_up`, C `measured.c:229-230` учитывает; (3) `SEGMENT_SIZE=1400` (`:12,143,170,204,228,234,254,258`) вместо `d2k_arm_segment(send_cap)` — на `send_cap=1280` C даёт 1208; (4) `minexec` R2O `md5?12:parameterized?5:4` (`:245-251`), C `autottl?13:md5?12:param?5:4` (`measured.c:326-333`); (5) composite template R2O требует `tcp_ts && decoy_hello && !badsum` (`:147-174`), C принимает `decoy_hello && (tcpts || badsum)` и `autottl` (`measured.c:180-188`), т.е. badsum-композит и autottl-композит не собираются. **Совпадают:** split-only (кроме segment), disorder_pos, oob, disorder+overlap, payload-slice, seqovl, ttl/md5/tcpts/ipidzero, fake/order/pace/settle. C-фикстуры покрывают обычные fake/split/oob; редкие ветви — unit. |
| `d2k_arm_plan_measured` | 387–390 | 4 | обёртка `d2k_arm_plan_measured_cap(..., send_cap=0)` | `classify_measured.rs:30-37 plan_text_for_poison(..., send_cap=0)` | **P** | Обёртка совпадает; все пробелы те же, что у `d2k_arm_plan_measured_cap`. |

### `core/net4.c`

**Прочитано построчно: 4/4 функции, 64 строки C (1–64).** Сверено с `quic_replay.rs:22-53 r2o_quic_address_is_local` и `scripts/test-core-net4-differential.sh` (C-оракул `crates/r2k-core/tests/d2o_net4_differential.c`, донор закреплён на `a378e230…`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_ip4_parse` | 7–30 | 24 | 4 октета по 1–3 цифры, 0..255, ровно точки/конец, старший байт вперёд | `Ipv4Addr::from_str` (`examples/m5_net4_trace.rs:15`) | **P** | **Подтверждённое расхождение:** C принимает ведущие нули (`010.0.0.1` → 10.0.0.1; `001.002.003.004`), Rust 1.98 — `Err(AddrParseError)` (проверено `rustc`). Остальное совпадает: 1–3 цифры, ≤255, ровно 4 октета, конец строки, старший байт вперёд. `test-core-net4-differential.sh` (пин a378) покрывает `0.0.0.0/127.0.0.1/192.168.1.1/255.255.255.255` и битые литералы, но **не ведущие нули**. |
| `d2k_ip4_text` | 32–38 | 7 | 4 байта → `%u.%u.%u.%u`, 0 при нехватке cap или ошибке | `Ipv4Addr::Display` (`examples/m5_net4_trace.rs`) | **E** | Для валидных адресов текст совпадает; C возвращает 0 при `n<0`/`n>=cap`, Rust `Display` пишет в `String` без предела. `test-core-net4-differential.sh` сравнивает `parse→text` на валидных адресах. |
| `d2k_ip4_private` | 40–51 | 12 | 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, 0.0.0.0 | `quic_replay.rs:24-33 ipv4_is_local` | **E** | Диапазоны совпадают: `is_unspecified`, `a==10/127`, `172 && b∈16..=31`, `192.168`, `169.254`, `100 && b∈64..=127`. C собирает `v` из big-endian байт; Rust работает по `octets()`. `test-core-net4-differential.sh` + `r2o-quic-local-address-differential.sh`. |
| `d2k_ip6_private` | 53–64 | 12 | `::`/`::1`, fc00::/7, fe80::/10, ff00::/8, v4-mapped → ip4_private | `quic_replay.rs:35-52` IPv6-ветка | **E** | C: `NULL→1`; 15 нулевых байт + `ip[15]<=1`; `(ip[0]&0xfe)==0xfc`; `ip[0]==0xfe && (ip[1]&0xc0)==0x80`; `ip[0]==0xff`; `::ffff:` → `ip4_private`. Rust: `is_unspecified/is_loopback`, те же маски, `mapped_v4` = 10 нулей + `ff ff`, затем `ipv4_is_local`. Единственное отличие — C трактует `NULL` как private, Rust принимает значение. `test-core-net4-differential.sh`. |

### `core/p256.c`

**Прочитано построчно: 22/22 функции, 316 строк C (1–316).** Сверено с `r2o_tls.rs:75-103` (ring provider, `SECP256R1` в TLS12/TLS13) и `core/tls12.c:642-660` (C-путь `d2k_p256_keypair`/`d2k_p256_ecdh`). Собственной арифметики P-256 в R2O нет — её заменяет ring; C-векторы `core/test_p256.c` против Rust не запускались.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `fe_copy` | 31–31 | 1 | `memcpy` 8 слов элемента поля | ring (внутренняя арифметика P-256) | **P*** | static-хелпер; собственной реализации в R2O нет, арифметику выполняет ring через rustls (`r2o_tls.rs:92-103`). |
| `ge` | 34–39 | 6 | `a>=b` для 256-битных слов, сравнение с 7-го слова; равенство → 1 | ring | **P*** | static-хелпер; используется `fe_add`/`fe_mul`/`scalar_ok`. В R2O заменён внутренним сравнением ring. |
| `is_zero` | 41–45 | 5 | OR всех 8 слов == 0 | ring | **P*** | static-хелпер; используется `pt_double`/`pt_add`/`scalar_ok`. |
| `sub_raw` | 48–56 | 9 | 256-битное вычитание с заимствованием `borrow=(d>>63)&1` | ring | **P*** | static-хелпер; C собирает `d=a[i]-b[i]-borrow` в `uint64`. |
| `add_raw` | 59–67 | 9 | 256-битное сложение с переносом `carry=s>>32` | ring | **P*** | static-хелпер. |
| `fe_add` | 69–74 | 6 | `a+b mod P`: при переносе или `t>=P` вычесть P | ring | **P*** | static-хелпер; P-256 модуль. |
| `fe_sub` | 76–80 | 5 | `a-b mod P`: при заёме добавить P | ring | **P*** | static-хелпер. |
| `fe_mul` | 84–113 | 30 | Montgomery CIOS, `t[10]`, `m=t[0]` (так как `-p^-1 mod 2^32=1`), 8 раундов, финальное вычитание P | ring | **P*** | static-хелпер; C не использует `__int128` и рассчитан на ARM/MIPS32. ring применяет свою реализацию (вероятно, ассемблер/constant-time); побайтовых C/Rust-векторов нет. |
| `fe_sqr` | 115–115 | 1 | `fe_mul(a,a)` | ring | **P*** | static-хелпер. |
| `to_mont` | 124–124 | 1 | `a·R² mod P` | ring | **P*** | static-хелпер; `R2` — константа `2^512 mod P`. |
| `from_mont` | 125–128 | 4 | `a·1` в Montgomery-домене | ring | **P*** | static-хелпер. |
| `fe_inv` | 131–141 | 11 | `a^(P-2)` по малой теореме Ферма, MSB-first square/multiply, старт `ONE_M` | ring | **P*** | static-хелпер; C-ветвь по битам экспоненты. |
| `fe_from_be` | 143–148 | 6 | 8 слов из big-endian байт `b+28-4i` | ring | **P*** | static-хелпер; разбор 32-байтного скаляра/координаты. |
| `fe_to_be` | 150–156 | 7 | обратная сериализация 8 слов в big-endian | ring | **P*** | static-хелпер. |
| `pt_double` | 161–190 | 30 | якобиево удвоение, `a=-3`; `inf` при `p.inf`/`y==0`; формулы δ,γ,β,α | ring | **P*** | static-хелпер; C считает в Montgomery-домене. |
| `pt_add` | 192–232 | 41 | якобиево сложение; `p.inf/q.inf`; при `H==0`: `R==0 → double`, иначе `inf`; формулы I,J,V | ring | **P*** | static-хелпер. |
| `pt_mul` | 235–246 | 12 | MSB-first double-and-add по 32 байтам, **не constant-time** | ring | **P*** | static-хелпер; C прямо документирует «не постоянного времени» (ключ одноразовый). ring, вероятно, constant-time; выходные точки должны совпадать, но C/Rust-векторов нет. |
| `pt_affine` | 249–260 | 12 | `z^-1`, `x/z²`, `y/z³`, `from_mont`; `-1` при бесконечности | ring | **P*** | static-хелпер. |
| `scalar_ok` | 262–266 | 5 | `0<k<N` | ring (валидация внутри) | **P*** | static-хелпер; C проверяет `!is_zero && !ge(s,N)`. ring валидирует скаляр внутри генерации/ECDH, отдельной функции нет. |
| `d2k_p256_public` | 268–280 | 13 | `scalar_ok`, `pt_mul(G)`, аффинные координаты, `0x04`+X+Y | ring (через rustls, без экспорта pub) | **P** | **Production-путь:** C `tls12.c:642-660`; R2O `r2o_tls.rs:92-96` включает `SECP256R1` в TLS12 и TLS13. Отдельного API «публичный ключ из приватного» в R2O нет — ring генерирует эфемерную пару внутри TLS; C/Rust-векторов публичного ключа нет. |
| `d2k_p256_keypair` | 282–289 | 8 | 32 случайных байта, `scalar_ok`, до 16 попыток | `ring::agreement::EphemeralPrivateKey` через rustls | **P** | **Production:** `tls12.c:642-660` (ECDHE TLS 1.2). C явно повторяет генерацию до 16 раз при `k==0 || k>=N`; ring генерирует ключ внутри, его retry/отбраковка не сравнивались. C-векторов keypair нет. |
| `d2k_p256_ecdh` | 291–316 | 26 | `scalar_ok`, `peer[0]==0x04`, `x,y<P`, проверка `y²=x³-3x+B`, `pt_mul`, вывод X | `ring::agreement` (P256) через rustls | **P** | **Production:** `tls12.c:655`. C сам проверяет точку на кривой; ring также отвергает невалидную точку, но C/Rust-векторы ECDH и поведение при точке не на кривой не сравнивались. |

### `core/plantlv.c`

**Прочитано построчно: 20/20 функций, 863 строки C (1–863).** Сверено с `plan_text.rs` (741 строка), `plan.rs` (`scan`/`check_references`: `:692,711-717,798-808`), `scripts/test-controller-plantlv-differential.sh` и фикстурами `scripts/fixtures/plantlv_cases.txt` / `plantlv_stricter_cases.txt`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `b64_value` | 126–131 | 6 | base64-символ → 0..63, иначе -1 | `plan_text.rs:712-721 base64_value` | **E*** | Отображение A-Z/a-z/0-9/+/ совпадает; static-хелпер, покрыт фикстурой `payload-pad64`. |
| `parse_base64` | 133–161 | 29 | `len%4==0`; `=` только в последнем квартете; нулевые хвостовые биты; пустая строка — 0 байт | `plan_text.rs:677-710 base64` | **E*** | Ветви совпадают, включая `b&15`/`c&3`, пустой вход и отказ на неполном паддинге. Фикстуры `payload-pad64`/`pad-prefix-too-long`. |
| `say` | 163–169 | 7 | `vsnprintf` в err/cap, молчание при cap==0 | `Result<String, String>` | **E*** | Текст ошибок C/Rust не сравнивается (differential печатает только ok/err и TLV); смысл ошибки сохраняется. |
| `hex_nib` | 171–176 | 6 | 0-9/a-f/A-F → 0..15, иначе -1 | `plan_text.rs:668-675 hex_nibble` | **E*** | Посимвольно совпадает. |
| `parse_hex` | 180–204 | 25 | чётная длина; пустая строка — 0 байт; hex → байты | `plan_text.rs:650-666 hex` | **E*** | C выделяет `n/2`, Rust `Vec::with_capacity`; обе отвергают нечётную длину и не-hex. Фикстуры `payload-hex`/`odd-hex`. |
| `anchor_by_name` | 206–217 | 12 | 6 якорей: payload_start 0, sni_start 1, sni_end 2, hello_middle 3, record_end 4, sni_middle 5 | `plan_text.rs:723-733 anchor` | **E*** | Те же имена/номера; фикстура `split-anchors`/`split-unknown-anchor`. |
| `split_fields` | 221–233 | 13 | разбиение по пробелам/табам, не более 8 полей; больше — отказ | `plan_text.rs:81-87` | **E*** | C возвращает -1 при `n>=cap`; Rust `fields.len()>8`. Пустые поля отбрасываются в обоих. |
| `parse_uint` | 237–245 | 9 | первый символ цифра; `strtoul`; без знака/пробела/хвоста; `<=max` | `plan_text.rs:625-631 number` | **E*** | Для канонического текста эквивалентно: Rust требует все ASCII-цифры, `u64`, `<=max`; ведущие нули оба принимают. C дополнительно ловит `ERANGE`. |
| `parse_int` | 248–256 | 9 | необязательный `+`/`-`; модуль ограничен `lo`/`hi`; `-INT_MIN` без переполнения | `plan_text.rs:308-310`, `:340-342` (`parse::<i32>`/`<i16>`) | **E*** | C разбирает знак и модуль, Rust — стандартный `parse`; диапазоны те же (`i32` для seqshift, `i16` для split). |
| `kv_u32` | 259–263 | 5 | `key=value`, точное совпадение ключа, значение `parse_uint` | `plan_text.rs:642-648 kv_number` | **E*** | C `strncmp`+`field[kl]=='='`; Rust `split_once('=')`+`actual_key != key`; эквивалентно. |
| `str_u32` | 268–270 | 3 | голое u32 без ключа | `plan_text.rs:451 number(..., u32::MAX)` | **E*** | Используется для `pace`/`delay`/чисел payload; эквивалентно. |
| `plan_free` | 272–275 | 4 | освободить payload-буферы и обнулить план | `Drop`/`Vec` | **E*** | RAII заменяет ручное освобождение; ошибки парсера возвращают `Err` без утечек. |
| `parse_text` | 277–685 | 409 | полный разбор `d2k-plan`: заголовок, id, proto, payload/pad/slice, wire, input, settle/segment, poison+autottl, split, oob, fake, seqovl, order, pace, ipfrag, udplen, quicsplit, quicdeny, delay, guard; лимиты и cross-field проверки | `plan_text.rs:67-610 compile_text` + `plan.rs` | **P** | **Совпадают:** длина строки <8192, trim space/tab/CR, `#`, ≤8 полей, schema/minexec 0..65535, id 16 байт, proto-коды, payload/pad/slice, wire 1/2 + minexec, input/tls-sni, settle/segment, poison-флаги/ttl/seqshift, split-якоря/int16, oob/1 байт, fake/tlsmod, seqovl, order, pace/delay>0, ipfrag 1..4, udplen/quicsplit/quicdeny, guard; cross-field — `plan.rs:313-323,499-614,692,711-717,798-808`. **Расхождения:** (1) C принимает только `d2k-plan`, R2O — `r2o-plan` и `d2k-plan` (брендинг); (2) R2O отвергает NUL во всём тексте (`plan_text.rs:68-70`), C обрабатывает строку до NUL; (3) C `autottl` при повторе — last-wins, R2O отвергает повтор (`plan_text.rs:296-298`); (4) C `plantlv` принимает `autottl` при `minexec<13`, R2O `Plan::parse` отвергает (`plan.rs:510-515,711-712`) — C отклонил бы позже в датапате; (5) C `sscanf("%d,%u-%u")` допускает пробелы/знак, R2O строго `split_once`+`parse` (канонический текст совпадает). Фикстуры покрывают 60+ кейсов; `plantlv_stricter_cases.txt` фиксирует autottl-low-minexec и висячие ссылки. |
| `put` | 691–695 | 5 | запись n байт; при переполнении `w.bad=1` | `Vec<u8>`/`push_u16` | **E*** | C проверяет `pos+n<=cap`, Rust растёт динамически и проверяет `MAX_PLAN_BYTES=65000` в конце (`plan_text.rs:605-607`); для планов ≤65000 эквивалентно. |
| `put_u8` | 696–696 | 1 | TLV: один байт | `Vec::push` | **E*** | Тривиальный хелпер. |
| `put_u16` | 697–697 | 1 | TLV: big-endian u16 | `plan_text.rs:735-737 push_u16` | **E*** | `to_be_bytes` совпадает. |
| `put_u32` | 698–701 | 4 | TLV: big-endian u32 | `plan_text.rs:739-741 push_u32` | **E*** | `to_be_bytes` совпадает. |
| `put_rec` | 702–707 | 6 | TLV-запись `type u16, len u16, value`; len>0xFFFF — ошибка | `plan_text.rs:598-604` | **E*** | C `put_rec`; Rust `u16::try_from(value.len())`; порядок type/len/value тот же. |
| `d2k_plan_text_to_tlv` | 709–845 | 137 | компиляция текста в TLV `D2KP`: magic, schema, minexec, flags=0, count, ID, PROTO, payloads, poisons(+AUTOTTL), splits, fakes, seqovls, ORDER, PACE, INPUT, SETTLE, SEGMENT, INPUT_TLS, DELAY, WIRE, IPFRAG, UDPLEN, QSPLIT, QDENY, OOB, GUARD | `plan_text.rs:67-610 compile_text` | **P** | Порядок записей, magic `D2KP`, `flags=0`, count, длины, `autottl` сразу за порчей, безусловный ORDER, fake 10/11 байт — совпадают; `Plan::parse` повторно проверяет TLV (`plan_text.rs:608`). **Расхождения** наследуются от `parse_text`: NUL, `r2o-plan`, повтор autottl, autottl minexec<13. Differential `test-controller-plantlv-differential.sh` сравнивает ok/err и точные hex-байты на 60+ фикстурах. |
| `d2k_plan_text_to_hex` | 847–863 | 17 | TLV → lowercase hex в буфер, `cap>=2n+1` | нет отдельной функции; `compile_text` возвращает байты, hex — у вызывающего | **P** | TLV-часть покрыта `compile_text`; отдельного API «план → hex-строка» в R2O нет. C использует hex для `d2k_link_set_name`/sched, R2O передаёт TLV-байты напрямую (`encode_set_name`), поэтому форматирование hex не востребовано; при необходимости вызывающий может hex-кодировать байты. |

### `core/props.c`

**Прочитано построчно: 5/5 функций, 91 строка C (1–91).** Сверено с `quic_replay.rs` (`r2o_quic_blob_candidate`, `r2o_quic_discovery_candidates`, `r2o_quic_original_fallback_candidates`), `r2o_quic_http3.rs` (`r2o_quic_http3_get_with_wire_len`, measure) и trial-runner `main.rs:20496`; одноимённого hook-API в R2O нет.

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
| `refuse_is_permanent` | 301–312 | 12 | отказ, который не лечится повтором: `TOO_LONG`(3), `NOT_APPLIED`(5), `FLOW_UNFIT`(6) | `main.rs:19088-19099` + `flow_journal.rs:20-23` | **P** | **Подтверждённое расщепление:** C-хелпер вызывается в трёх местах — `local_refusal_verdict` (`sched.c:4487`), `on_refused_foreign` (`:9901`), провал группы (`:10113`). Rust обрабатывает 3/5 как `worker.record_client_unfit()` (`main.rs:19091-19095`), а 6 — отдельно: `r2o_catalog_mark_flow_unfit` + повторная постановка (`:19097-19170`). Единой функции/таблицы нет; группа-провал по коду отказа не сопоставлена. |
| `refuse_is_damage` | 320–322 | 3 | `DAMAGED`(4) — поток испорчен недоисполнением | `flow_journal.rs:21,724-758,95,111` | **P*** | C-предикат только выбирает текст журнала (`sched.c:4522`). Rust `record_execution_failure(..., damaged)` пишет `PlanDamaged` с кодом 4, тексты «поток испорчен»/«поток повреждён»; тест `flow_journal.rs:352`. Контроллерный REFUSED-обработчик вид события отдельно не разбирает. |
| `verify_default` | 388–413 | 26 | transport 17 → QUIC-зонд; не 6 → `unsupported`; LEGACY → TLS1.2; иначе TLS1.3 | `main.rs:5500-5660` (`r2o_family_recovery_sibling_trial_with_ech_state`, `tls12 = shape == SHAPE_LEGACY`), `:20496 r2o_run_quic_discovery_trial`, `fetch.rs:844` | **P** | **Совпадает:** LEGACY→TLS1.2, MODERN/ECH→TLS1.3, QUIC→QUIC-путь. **Отличия:** Rust не имеет ветви «unsupported transport» — цели создаются только для 6/17; QUIC подтверждение идёт через `r2o_quic_http3`/replay, а TCP — через `FetchOptions.tls12`; единого диспетчера нет. |
| `bind_default` | 415–418 | 4 | transport 17 → UDP bind, иначе TCP bind | `main.rs:22501-22560 BoundTcpProbe::open`; UDP — `r2o_quic_http3.rs:84,162`, `voice_measure.rs:660`, `raw_probe.rs:1469` | **P*** | TCP-путь единый; UDP-bind разнесён по QUIC/voice/raw, общего `bind_default` нет. family 4/6 и эфемерный порт сохраняются. |
| `verify_rx_default` | 420–427 | 8 | TCP → identity-зонд; иначе обычный verify | `fetch.rs:434-446 r2o_d2o_verification_encoding` (`Identity`), `main.rs:3172-3195` RX volume options | **P** | Identity-кодировка выбирается по пути; RX-лестница использует её в `r2o_discovery_volume_fetch_options`. C-ветка «не TCP → verify_default» в Rust выражена выбором QUIC/volume-пути. C/Rust differential identity-RX частичный. |
| `verify_rx_gzip_default` | 429–436 | 8 | TCP → gzip-контроль; иначе обычный verify | `fetch.rs:434-446` (`Gzip`), `main.rs:3172-3195` | **P** | Gzip-кодировка и RX-контроль есть; отдельного differential на gzip-ветку подтверждения нет. |
| `mark_default` | 438–440 | 3 | `SO_MARK` через hook | `main.rs:22542-22555` (`BoundTcpProbe::open`), `:24454` (raw probe) | **P*** | **Подтверждённое отличие:** C при `mark=0` не ставит метку; Rust `BoundTcpProbe::open` делает `mark.unwrap_or(0x2d)`, т.е. при `None` ставит **0x2d**. Отдельного mark-хелпера нет. |
| `classify_unconfigured` | 451–463 | 13 | заглушка при неподключённом классификаторе: `FLAKY` + `owns_search=1` | нет состояния; классификатор всегда подключён (`main.rs:15274+`, `raw_probe`) | **P*** | C-путь существует только для library-пользователя без `d2k_sched_tcp_hook`; в production `d2kc` hook ставится. R2O не имеет «неподключённого» состояния, поэтому поведение не воспроизводится, но и не наблюдается. |
| `voice_default` | 482–484 | 3 | голосовой замер по умолчанию | `voice_measure.rs:250-268 r2o_measure_voice_for_flow`, `:141 r2o_measure_voice` | **P** | C-обёртка `d2k_voice_run`; Rust-ветви voice опций/mark/discovery переданы, полного C/Rust differential нет. |
| `d2k_sched_cpu_parse` | 488–511 | 24 | разбор первой строки /proc/stat: busy/total, idle=iowait | r2o_resource_limit::r2o_parse_cpu_stat (48) | **E** | r2o-resource-limit-differential.sh |
| `cpu_read_proc` | 513–527 | 15 | чтение /proc/stat и числа онлайн-ядер | r2o_resource_limit::R2oResourceReading::r2o_read_proc (114) | **E** | r2o-resource-limit-differential.sh |
| `meminfo_field` | 531–549 | 19 | поле MemTotal/MemAvailable из /proc/meminfo | r2o_resource_limit::r2o_meminfo_field (87) | **E*** | static-хелпер; resource differential |
| `d2k_sched_meminfo_parse` | 551–560 | 10 | разбор MemTotal/MemAvailable и отказ при total=0 | r2o_resource_limit::r2o_parse_meminfo (98) | **E** | r2o-resource-limit-differential.sh |
| `mem_read_proc` | 562–570 | 9 | чтение /proc/meminfo | r2o_resource_limit::R2oResourceReading::r2o_read_proc (114) | **E** | resource differential |
| `read_u64_file` | 573–582 | 10 | u64 из файла /proc | r2o_resource_limit::r2o_read_counter (107) | **E*** | static-хелпер; resource differential |
| `ct_read_proc` | 584–589 | 6 | conntrack count/max из /proc | r2o_resource_limit::R2oResourceReading::r2o_read_proc (114) | **E** | resource differential |
| `client_alpn_nonhttp` | 1114–1137 | 24 | TCP, не ECH, пустой `measure_path`, MODERN; блок рукопожатия/`own_first==2+base_blocked`; нет RX/TX-cut; вернуть ALPN клиента, в т.ч. **пустой** (rc=0), если он не HTTP | `main.rs:15331-15350 r2o_discovery_client_alpn_verification_allowed` | **P** | **Подтверждённые отличия:** (1) C при `d2k_hello_alpn rc==0` (ALPN нет) возвращает 1 — зонд повторяет клиента без ALPN; Rust требует `client_hello.is_some_and(non_http_alpn)`, т.е. **пустой ALPN не допускает**; (2) C проверяет `measure_path[0]==0`, Rust — `probe_path == "/"`; (3) C `handshake_blocked = verdict_proves_block \|\| (own_first==2 && base_blocked)`, Rust получает готовый bool. Дифференциал `donor_and_r2o_preserve_captured_mqtt_and_absent_alpn` покрывает MQTT/absent, но не C-ветку «нет ALPN → можно». |
| `fresh_trial_id` | 1139–1154 | 16 | 16 байт из `/dev/urandom`, EINTR-повтор, при всех нулях **последний** байт = 1 | `main.rs:23529-23538 random_id` | **P*** | Rust `read_exact` (EINTR ретраится std), при всех нулях ставит **первый** байт = 1. Ненулевость и длина совпадают; позиция байта и C-oracle не проверялись. |
| `addr_probe_remove` | 1516–1535 | 20 | если identity валидна: dst из сохранённой пары либо `t->ip:port/443`; `DEL_ADDR_PROBE` transport 17; identity сбрасывается **только после успешной отправки** | `main.rs:20340-20347 encode_delete_addr_probe` (QUIC), `:16359,17917 encode_delete_voice_addr_probe` (voice) | **E** | Совпадает: удаление по сохранённым client/server/trial, повтор при ошибке. C использует `d2k_link_del_addr_probe_family` с transport 17; Rust — отдельные QUIC/voice команды. `test-discord-voice-confirm-delete-retry/shutdown-cleanup` + QUIC addr cleanup тесты. |
| `question_retire` | 1557–1570 | 14 | если план вопроса стоял и порт известен: `DEL_NAME_PROBE` по форме вопроса/порту; закрыть bound fd, сбросить флаги | CLI `main.rs:528-713 delete_name_probe`; в discovery control-план вопроса не ставится | **P*** | C-очистка точная; Rust CLI снимает пробу после каждого вопроса, а production-discovery вопроса через control не задаёт (см. `prop_send_next`), поэтому снимать нечего. Отдельного C/Rust differential нет. |
| `candidate_retire` | 1572–1590 | 19 | addr-probe либо `DEL_NAME_PROBE` по trial shape/port; закрыть probe fd, сбросить `trial_installed` | `main.rs:19652-19710` (`delete_name_probe` при ошибке установки/чужом trial + `DeleteProbe`), `:16355 retire_r2o_voice_trial` | **P** | Rust снимает name-probe при ошибке установки и по `DeleteProbe`; voice — отдельной командой. C снимает и в `task_fail`/`task_done`; полной матрицы переходов Rust нет. |
| `trial_retire` | 1592–1595 | 4 | `question_retire` + `candidate_retire` | нет единой функции; сочетание `delete_name_probe`/`retire_r2o_voice_trial` в переходах | **P*** | Составной хелпер; в Rust очистка разнесена по вызывающим, единого `trial_retire` нет. |
| `say` | 1603–1611 | 9 | журнал наружу через `say_fn`, строка 512 | прямые `println!`/`eprintln!` в `main.rs` | **P*** | Колбэк-инъекции нет; формат/адресация строк не сверялись. |
| `say_quiet` | 1615–1632 | 18 | подавление повтора по ключу: **`SCHED_QUIET_SLOTS=64`**, **`SCHED_QUIET_MS=10 мин`** (`sched.c:178,182`), кольцо | нет | **P*** | **Подтверждённый пробел:** в R2O нет подавления повторов журнала по ключу; `quiet` в `main.rs:4832` относится к `HttpSearchDisposition`, не к логу. Прежнее описание «8 слотов/5 мин» в таблице было неверным. |
| `d2k_sched_set_send_cap` | 1634–1637 | 4 | установить предел отправки датапата | поле `send_cap` в discovery (`main.rs`) | **P*** | Поле есть, отдельного сеттера/теста нет. |
| `d2k_sched_set_say` | 1639–1643 | 5 | установить колбэк журнала и контекст | нет (прямой вывод) | **P*** | Механизм заменён; API-совместимость не нужна, но и эквивалента инъекции нет. |
| `verdict_name` | 1647–1662 | 16 | 11 русских фраз: «проходит как есть» … «имя разрешается в приватный адрес», default «неизвестный вердикт» | `classify.rs:908-921 Verdict::as_str` | **P** | **Подтверждённое расхождение:** C — русские человекочитаемые строки, включая `NO_QUIC`/`LOCAL_ADDRESS`, без `POISONABLE`; Rust — 10 английских машинных имён (`clear/prefix/whole_packet/opaque/inconclusive/address/poisonable/flaky/unreachable/response`) без `NO_QUIC`/`LOCAL_ADDRESS`. Это лог-текст/набор, не классификация. |
| `signal_of` | 1672–1694 | 23 | code 1/4→`rst`, 2→`repeat`, 3→`silent`, иначе `код-N`; ttl/ttl_delta/tos/ipid только для `rst`; `seen=1` | `main.rs:3389-3427 r2o_discovery_suspect_signal` | **P** | Посимвольно совпадает: те же коды/строки, `is_rst`-гейт для полей, `seen=1`, `ttl_delta=ttl-ref_ttl`. Тесты `main.rs:29861` (rst-поля) и `:29885` (trigger 3/silent); `repeat` и прочие коды отдельно не проверены, C/Rust differential нет. |
| `is_rx_volume_kind` | 1699–1701 | 3 | `rx-volume` или `rx-volume-wire` | inline `matches!` в `main.rs:3438+` | **P*** | Rust не выделяет helper, но набор родов `volume`/`rx-volume`/`rx-volume-wire` совпадает. |
| `fp_add` | 1703–1730 | 28 | слить сигнал: volume-роды по `abs(Δvolume)<=4` + packets, остальные по `abs(Δttl)<=2`+tos+ipid; иначе добавить до 8 | `catalog.rs:111-135 Fingerprint::merge_observed`, `:1077-1088 same_signal`, константы `:15,18,19` | **P** | Пороги и слияние совпадают: `MAX_SIGNALS=8`, `VOLUME_SLACK=4`, `TTL_SLACK=2`, tos/ipid, packets только для volume-родов. **Отличие:** Rust `merge_observed` при пустом отпечатке копирует `method`, при несовпадении method выходит; C `fp_add` method не трогает (это делает вызывающий). Unit catalog; C/Rust differential нет. |
| `volume_bucket` | 1746–1751 | 6 | `kb<=0→0`, иначе `floor(log2(kb))+1` | `main.rs:3442-3448 r2o_discovery_volume_bucket` | **P*** | C-цикл `kb>>=1; b++` и Rust `i32::BITS - leading_zeros` дают одно и то же для всех `i32>0`. |
| `is_volume_kind` | 1753–1755 | 3 | `volume`/`rx-volume`/`rx-volume-wire` | inline `matches!` (`main.rs:3438+`) | **P*** | Набор тот же. |
| `box_volume_bucket_agrees` | 1760–1772 | 13 | есть ли у коробки объёмная примета того же рода и той же корзины | `main.rs:3449-3505 r2o_discovery_volume_known_plans` (`same_bucket`) | **P** | C проверяет только совпадение kind+корзины. Rust сначала требует `fingerprint.is_compatible_with(observed)`, затем `same_bucket` по observed_buckets/box signals, затем фильтрует планы (enabled/proto/tls/len/tried/transport/proto/validate) и сортирует по bucket+successes. Итоговый отбор шире одной функции; C/Rust differential нет. |
| `server_is_low` | 1798–1805 | 8 | сервер: ровно один порт ≥32768 → другой конец; иначе меньший порт | `discovery.rs:355-395 from_event`, `:416-460 from_http_portal` | **P** | **Подтверждённое расхождение:** C выводит роль по эфемерному диапазону (32768) для **любого** порта; Rust `from_event` принимает только пары с `443` (`(443,443)→None`, `(_,443)`/`(443,_)`), `from_http_portal` — только `80`. TLS/SNI на не-443 порту C обработает, Rust цель не создаст. |
| `client_ip_of` | 1807–1811 | 5 | IP клиента: противоположный серверу конец | `DiscoveryTarget::from_event` (`discovery.rs:355-395`) | **P** | C берёт `high_ip`/`low_ip` по `server_is_low`; Rust формирует `endpoint` сервера из пары 443/80. Для 443/80 эквивалентно, для прочих портов — нет. |
| `server_of` | 1813–1822 | 10 | IP:port сервера в текст и порт | `endpoint`/`host` в `DiscoveryTarget` (`discovery.rs:383-410`) | **P** | C `inet_ntop` по выбранному концу; Rust строковый `endpoint` из `from_event`/`from_http_portal`. Тот же порт-гейт 443/80. |
| `same_flow` | 1824–1830 | 7 | transport/family/ports/low_ip/high_ip | полный 38-байтный ключ в `R2oRecentTcpNameCache` (`main.rs:7809-7847`) | **P*** | Rust ищет по полному `HelloEvent.key` (transport/ports/адреса/proto), C — по сокращённому набору. Для TCP эквивалентно; C допускает любой транспорт, Rust `note` принимает только `key[37]==6` (`main.rs:7815-7817`). |
| `remember` | 1841–1862 | 22 | имя потока в кольцо **`SCHED_SEEN=512`** (`sched.c:338`), ключ same_flow, `observed_ms`, имя без нормализации | `R2oRecentTcpNameCache::note` (`main.rs:7815-7847`) | **P** | **Подтверждённые отличия:** C хранит 512 записей любого транспорта и сырое `ev->name`; Rust — 512 (`main.rs:7527`), только TCP (`key[37]==6`), нормализует host через `domain::normalize`, TTL 10 мин (`:7529`), полный 38-байтный ключ. Кэш Rust используется прежде всего для `ech_witness_names`, а не общего recall. C/Rust differential нет. |
| `recall` | 1864–1869 | 6 | точное имя по same_flow | только `ech_witness_names` (`main.rs:7850-7880`) | **P** | **Пробел:** C `recall` возвращает имя по точному потоку; Rust `ech_witness_names` фильтрует по family/адресу и TTL и возвращает список имён для ECH-witness. Общего точного recall по flow нет. |
| `cooldown_find_endpoint` | 1871–1884 | 14 | `used && !challenge && transport/family/name/ip/port` | `R2oDiscoveryCooldownRing` (`main.rs:8509-8600`) | **P*** | C линейный поиск; Rust `Vec<Option<Entry>>` с типизированным ключом (name/transport/family/ip/port). Эквивалентно; differential `r2o-scheduler-cooldown`. |
| `cooldown_find_challenge` | 1886–1897 | 12 | `used && challenge && transport/family/name` | `R2oDiscoveryCooldownRing` (challenge-ключ) | **P*** | C линейный поиск; Rust ключ помечает challenge. Эквивалентно. |
| `dead_find` | 1899–1910 | 12 | ключ name/transport/family/addr | `R2oDeadAddressKey` + `R2oDeadAddressCache` (`main.rs:8305-8415`) | **P*** | Rust ключ `(host, transport, family, ip)`, слоты 128 (`R2O_DISCOVERY_COOLDOWN_CAPACITY`); C тот же набор полей. Эквивалентно. |
| `dead_step` | 1915–1935 | 21 | свободный/самый ранний слот, streak++ (≤255), delay 10/30/60 мин, until=now+delay | `R2oDeadAddressCache::step` (`main.rs:8370-8408`) | **E** | Совпадает: поиск по ключу → free → earliest expiry; `streak.saturating_add(1)`; `r2o_discovery_clear_retry_after` 10/30/60; `expires=now+retry`. `r2o-scheduler-dead-address-differential.sh`. |
| `dead_clear` | 1937–1940 | 4 | очистить запись ключа | `R2oDeadAddressCache::clear` (`main.rs:8414-8423`) | **E** | C `memset` найденной записи; Rust обнуляет все слоты с ключом (ключ уникален). `r2o-scheduler-dead-address-differential.sh`. |
| `is_late_volume_suspicion` | 1942–1946 | 5 | code ∈ {RST_AFTER_APP=5, FIN_RETRY=6, TCP_STALL=8} | `main.rs:7357-7359 r2o_discovery_late_trigger` | **P*** | Коды C (`d2k_journal.h:41,42,56`) и Rust `Some(5|6|8)` совпадают. |
| `cooldown_blocks` | 1948–1973 | 26 | проверить активный cooldown с учётом challenge/exhausted/late_rst_only/кода | main.rs R2oDiscoveryCooldownRing::blocks | **E** | r2o-scheduler-cooldown-differential.sh |
| `cooldown_clear_endpoint` | 1975–1980 | 6 | снять endpoint-cooldown по name/transport/family/ip/port | `main.rs:13579 r2o_clear_failed_endpoint`, `:8498 R2oDiscoveryCooldownRing::remove` | **E** | C `memset` найденной записи; Rust удаляет `Endpoint(failure_key)` и связанные failed/seen/clear-поля. `r2o-scheduler-cooldown-differential.sh`. |
| `cooldown_clear_nonchallenge` | 1982–1998 | 17 | снять не-challenge cooldown; опционально только `exhausted`, опционально сохранить `ech_input` | `main.rs:13565 r2o_clear_seen_endpoint`, `:13579 r2o_clear_failed_endpoint` | **P** | **Подтверждённый пробел:** Rust очищает endpoint/seen/failed-состояние, но отдельных параметров `exhausted_only` и `preserve_ech` нет; вызовы ECH/QUIC очищают шире. Отдельного differential нет. |
| `clear_backoff_ms` | 2000–2004 | 5 | streak≤1 → **10 мин**, 2 → **30 мин**, иначе **60 мин** | `main.rs:14356-14362 r2o_discovery_clear_retry_after` + константы `:7332-7338` | **E** | C `SCHED_CLEAR_BACKOFF_1_MS=10 мин`, `_2_MS=30 мин`, `_MAX_MS=60 мин` (`sched.c:162-164`); Rust FIRST=10, SECOND=30, MAX=60 мин. `r2o-scheduler-cooldown-differential.sh`. |
| `cooldown_victim` | 2012–2027 | 16 | свободная → самая истёкшая → не-challenge с ближайшим концом → challenge с ближайшим концом | `main.rs:8519-8575 R2oDiscoveryCooldownRing::record_with_late_rst_only` | **P*** | Rust сначала ищет свободный слот, затем ранг: expired 0, не-challenge 1, challenge 2, при равенстве — ближайший `expires_at`. C-ранги: free 0, expired 1, не-challenge 2, challenge 3; порядок эквивалентен. Ring-тесты/cooldown differential, отдельного unit на victim нет. |
| `cooldown_record` | 2032–2097 | 66 | kind 0 direct CLEAR, 1 challenge, 2 exhausted, 3 late-RST, 4 legal denial (451); сроки 60/10 мин и 10/30/60 мин | `main.rs:12620-12665 r2o_record_discovery_cooldown_state`, `:13589 r2o_record_late_rst_only_cooldown` | **E** | Совпадают виды/сроки/`late_rst_only`/challenge-priority. Rust хранит challenge отдельно (`challenge_cooldowns`), endpoint — в ring; kind 4 выражен через challenge-ключ/`denied`. `r2o-scheduler-cooldown-differential.sh`. |
| `late_close_what` | 2100–2104 | 5 | текст причины позднего закрытия: FIN_RETRY/TCP_STALL/поздний RST | `main.rs:7357-7359 r2o_discovery_late_trigger` (код), тексты — в discovery detail | **P*** | Коды 5/6/8 совпадают; дословные тексты Rust формируются иначе. |
| `box_stall_budget` | 2114–2122 | 9 | первый `rx-volume`/`rx-volume-wire` с `1<=packets<=65535` | `main.rs:2367-2377 r2o_box_tcp_stall_budget` | **E** | Посимвольно совпадает: оба рода, диапазон, первый найденный; тест `main.rs:32896` проверяет бюджеты коробок. |
| `budget_listed` | 2124–2127 | 4 | есть ли бюджет в массиве | `Vec::contains` в `r2o_tcp_stall_budgets` (`main.rs:2379-2394`) | **P*** | Отдельного helper нет; дедуп через `contains`. |
| `name_stall_budgets` | 2131–2148 | 18 | бюджеты коробок с enabled name-binding на host, transport 0/6, дедуп, максимум 8 | `main.rs:2396-2417 r2o_tcp_stall_budgets_for_name` | **E** | Совпадает: kind `name`, target, transport 0/6, дедуп, `R2O_TCP_STALL_BUDGETS_MAX=8`. Тест `main.rs:32899`. |
| `tcp_stall_in_name_band` | 2153–2166 | 14 | если бюджетов нет → 1; иначе `packets ± SLACK` попадает в любой бюджет | `main.rs:2419-2427 r2o_tcp_stall_in_name_band` | **E** | Совпадает, включая `SLACK=3` и saturating-add; тесты `main.rs:32902-32903`. |
| `stall_budgets_push` | 2170–2191 | 22 | отправить SET_STALL_BUDGETS только при изменении списка (сравнение с `stall_sent`) | `main.rs:4174-4184` (queue `encode_set_tcp_stall_budgets` при компиляции каталога) | **P** | **Подтверждённое отличие:** C сравнивает новый список с последним отправленным и молчит при равенстве; Rust ставит команду в очередь при каждой компиляции каталога, без сравнения с отправленным. Кодировщик покрыт control-тестами. |
| `task_of` | 2193–2202 | 10 | найти задачу по name/transport/family (family по умолчанию 4) | `main.rs:9272+ R2oDiscoverySearches.active` по `R2oDiscoveryTaskKey` | **P*** | Rust-ключ `(String,u8,u8)` включает host/transport/family; поиск через HashMap, а не линейный. Эквивалентно. |
| `task_free_slot` | 2204–2209 | 6 | первый свободный слот задачи | `R2oDiscoverySearches` capacity/permit (`R2O_DISCOVERY_TASK_CAPACITY`) | **P*** | Явного массива слотов нет; свободное место определяется capacity/permit, а не `T_FREE`. |
| `task_watching_slot` | 2217–2222 | 6 | слот `T_WATCHING` для вытеснения новым поиском | `main.rs:12788 r2o_forget_watching_task`, `:12849-12855` выбор completed-watching, `:34205` тест | **E** | Rust хранит завершённые watching-задачи в `completed` и при переполнении вытесняет первую; тест `r2o_discovery_reuses_the_first_watching_slot_when_the_task_table_is_full`. |
| `tcp_hello_kind` | 2240–2243 | 4 | ECH-TCP или обычная форма ClientHello | `engine.rs:1051-1065` (`client_shape`) | **P*** | Rust выставляет `SHAPE_ECH_TCP` при `ech_offer`, иначе MODERN/LEGACY; отдельного helper нет. |
| `hello_fits_client` | 2245–2252 | 8 | transport≠6 → 1; `trigger_shape` не MODERN/LEGACY/ECH_TCP → 1; иначе `tcp_hello_kind` == UNKNOWN или == want | `main.rs:12879-12890` (снимок берётся только при `shape == target.shape`), `engine.rs:1051-1065` (`client_shape`) | **P** | **Подтверждённое отличие:** C допускает **UNKNOWN** снимок (`got == UNKNOWN`) и использует его; Rust `cached_client_hello` берёт снимок только при точном равенстве формы цели, иначе снимок не применяется. Формы MODERN/LEGACY/ECH_TCP совпадают; C/Rust differential нет. |
| `quic_pack_ech` | 2256–2266 | 11 | QSN → ClientHello → TLS-запись 0x16 0x03 0x01 → `d2k_hello_ech_offer` | `main.rs:4925-4943 r2o_quic_snapshot_has_ech` | **E** | Построчно совпадает: `r2k_quic_snapshot_parse` → `r2k_quic_initial_client_hello_from_datagrams` → запись 5 байт → `r2k_core::tls::parse.ech_offer`. Тест `main.rs:26418`. |
| `quic_named_find` | 2268–2274 | 7 | кольцо `quic_named`: len/family/name и `observed_ms+600000 >= now` | `main.rs:12753-12770` (`queued_quic_snapshots` — HashSet задач), `:6973` (снимок в pending job) | **P** | **Подтверждённый пробел:** Rust хранит QUIC-снимок в pending-job/очереди задачи и `queued_quic_snapshots`, но **не имеет кольца снимков по имени с 10-минутным сроком**. Повторное использование «последняя пачка этого имени» из C не найдено; Rust берёт снимок из текущего события/задачи. |
| `client_offers_ts` | 2286–2301 | 16 | если опции неизвестны → `trigger_tcp_profile != NO_TS`; иначе 0→break, 1→skip, битая длина→0, 8/10→1 | `raw_probe.rs:673-682 raw_offer_timestamps` + `ClientShapeEvent.tcp_has_timestamp` | **P** | **Подтверждённое расхождение default:** C при неизвестных опциях берёт **профиль триггера** (`!= NO_TS`); Rust `raw_offer_timestamps(None)` читает `/proc/sys/net/ipv4/tcp_timestamps` (обычно 1). Если триггер измерен как NO_TS, а опции клиента не сняты, C даёт false, Rust — true. Разбор известных опций эквивалентен `PacketView::tcp_options_timestamp_profile`. |
| `client_tcp_profile` | 2303–2318 | 16 | !known/overflow→UNKNOWN; 0→NO_TS; 1→skip; битая→UNKNOWN; 8/10→TS; конец→NO_TS | `packet.rs:39-65 PacketView::tcp_options_timestamp_profile` | **P** | Алгоритм совпадает посимвольно; тесты `packet.rs:253-284`. **Отличие представления:** `r2o_client_shape_from_legacy` (`main.rs:9381-9384`) сводит результат к `Option<bool>` (`== TS`), поэтому UNKNOWN превращается в `Some(false)`, а `ClientShapeEvent` не хранит профиль/сырые опции (header, п. 10). |
| `flowkey_same` | 2320–2325 | 6 | transport/family/ports/a_ip/b_ip | полный 38-байтный ключ (`control.rs`/`HelloEvent.key`) | **P*** | Rust сравнивает ключ целиком (включая proto/ports/адреса); эквивалентно для TCP. Отдельного helper нет. |
| `take_shape_opts` | 2328–2341 | 14 | при совпадении имени и flowkey скопировать `tcp_shape_opts[4][40]` и вычислить профиль | `main.rs:13257 queue_client_snapshot`, `:9400 remember_client_snapshot`, `ClientShapeEvent` | **P** | **Подтверждённый пробел (header, п. 10):** C хранит **сырые TCP-опции** (4×40) в задаче и пересчитывает профиль; Rust уже на приёме события сводит опции к `Option<bool>` (`tcp_has_timestamp`) и сырые байты не хранит. `take_shape_opts` как отдельный шаг отсутствует; для последующей проверки/повторов доступен только bool. |
| `drop_client_opts` | 2342–2345 | 4 | сбросить `client_opts_known/len` | нет прямого аналога | **P*** | В Rust нет состояния сырых опций, сбрасывать нечего; bool приходит в событии и не переиспользуется как «опции задачи». |
| `fill_hellos` | 2347–2491 | 145 | подготовить trigger/control hello: QUIC снимок/PROFILE, ECH input, TCP снимок, cold profile, decoy | `main.rs:15351-15383 r2o_discovery_trigger`, `:9356-9397 r2o_client_shape_from_legacy`, `:13257 queue_client_snapshot`, `:12879-12890` кэш формы | **P** | **Совпадает:** выбор снимка клиента, cold profile MODERN/LEGACY, ECH-вход и контроль `disk.rzd.ru`. **Подтверждённые отличия:** (1) C хранит QUIC-снимки по имени 10 минут и умеет пересобирать/переименовывать чужой снимок через `d2k_quic_prepare_target`; Rust использует pending-снимок задачи и `r2o_quic_profile_snapshot`, без кольца по имени; (2) C при неудачном переименовании контроля падает на собственный Initial приманки; Rust control всегда `Trigger::tls("disk.rzd.ru")`; (3) C копирует сырые TCP-опции, Rust — только `tcp_has_timestamp`. |
| `worker_arg_alloc` | 2519–2527 | 9 | `mmap(MAP_ANONYMOUS)` под `worker_arg`, иначе `malloc` | `main.rs:7900-7970 R2oDiscoveryQueueEntry` + `R2oDiagTrackedMemory` (512 байт, site 0) | **P*** | C выделяет аргументы через mmap, чтобы `munmap` возвращал страницы ядру; Rust держит аргументы worker в owned-структурах (`Box`/`Vec`), а в диагностике учитывает фиксированные **512 байт** на ожидающую задачу. Механизм/учёт различаются, утечек по владению нет. |
| `worker_arg_free` | 2529–2536 | 8 | `munmap`/`free` аргументов | `Drop for R2oDiagTrackedMemory` (`main.rs:7940-7950`), владение worker-job | **P*** | C освобождает mmap явно; Rust освобождает Drop-ом и снимает диагностический счётчик. Эквивалентно по владению, не по аллокатору. |
| `d2k_sched_ech_baseline_result` | 2538–2556 | 19 | fd<0 или CHALLENGE → INCONCLUSIVE «ECH: …»; accepted+name_ok=1+level APPLICATION+body_complete → CLEAR и `rx_direct_complete=1`; иначе INCONCLUSIVE | `main.rs:5308-5340 r2o_family_recovery_decision`, ECH-поля `FetchResult` | **P** | **Подтверждённые отличия:** C требует `level == APPLICATION` и `name_ok == 1`; Rust принимает `handshake_verified` как короткий путь и для не-ECH допускает `ech_accepted=None` (`is_none_or`), затем требует `complete`, `application_verified`, статус 200..600, без CF/Blocked/LegalDenial. Отдельной функции «ECH baseline» нет; ECH-дифференциалы покрывают часть. |
| `worker_volume` | 2561–2629 | 69 | кэш входа (`tls12`, wire len, port, ip, path); при смене — vol/vol_path hook; при `rx_short` один повтор по `measure_alt`, принимается только `alt.rx_cut`; обновляет `measure_path`/`vol_path` по `measured_path` | `main.rs:3172-3196 r2o_discovery_volume_fetch_options`, `:3197-3221 r2o_discovery_measure_volume`, кэш `:7368-7500` | **P** | **Совпадает:** TX/RX-лестница, повтор по alternate path, принятие повтора только при доказанном cut, перенос measured_path. **Отличие ключа кэша:** C — `tls12/wire/port/ip/path`; Rust `R2oDiscoveryVolumeSearchKey` — `wire_len/send_cap/probe_path/alternate_path/network_probe/white_name` (+ target в вызове), без `tls12/ip/port` в явном виде. C/Rust differential объёмного кэша частичный. |
| `worker_volume_cut` | 2632–2664 | 33 | сформировать INCONCLUSIVE и текст: RX wire-basis/compressed, identity expected/at KB, chunked, TX at KB; `res_ready=1`, wake | `main.rs:3223-3231 r2o_discovery_volume_cut` (bool), reason — в `fetch`/`DiscoveryOutcome` | **P** | Rust возвращает только булев cut (`tx cut или rx.evidence`), а тексты причин формируются в fetch/outcome. C-тексты и точные условия `rx_compressed_complete`/`rx_wire_basis` не сопоставлены; unit объёма частичный. |
| `seed_input_of` | 2667–2673 | 7 | FNV-1a: байты приветствия, **IP-строка**, порт, длина | `classify.rs:1067-1077 seed_input` | **P** | **Подтверждённое расхождение:** Rust хеширует `trigger.payload`, **`target.host`**, порт и длину; C — байты, **`ip`**, порт и длину. Для IP-цели совпадает, для домена seed разный. Offset/prime те же. |
| `d2k_sched_progress_note` | 2680–2695 | 16 | thread-local `progress_sink`; обрезка вопроса по границе UTF-8; `ask_probes += pass+fail` под мьютексом | `main.rs:15396+` (`progress: &mut dyn FnMut(&str, usize, usize, usize)`), `Tally` | **P*** | C использует thread-local и поле задачи; Rust передаёт callback в классификатор. Счёт проб/обрезка строки в Rust иные по форме; отдельного differential нет. |
| `ask_settle` | 2700–2703 | 4 | `fin = ask_base + max(run_probes,0)`, поднять `ask_probes` до `fin` | счёт `Tally`/`ClassifyResult` (`classify.rs`), ask-прогресс | **P*** | C-максимум защищает от недосчёта; Rust ведёт `pass/fail` в `Tally` и прогрессе. Точное правило «не пересчитать» не вынесено отдельной функцией. |
| `sched_quic_yield` | 2707–2729 | 23 | проверить stop/yield-request, wait на condvar, вернуть паузу в мс | `main.rs:12140 r2o_quic_yield_waiting_for_tcp`, worker gate | **P** | C усыпляет поток до `quic_yield_waiting=0`/stop и измеряет паузу; Rust решает «уступить TCP» через worker gate/очередь. `r2o-scheduler-concurrent-endpoint/queue` покрывают часть, точная пауза не сверена. |
| `sched_quic_progress` | 2731–2733 | 3 | прогресс QUIC-вопроса через `progress_note(question, probes, 0)` | progress-callback classify (`main.rs:15396+`) | **P*** | Тонкая обёртка; отдельного differential нет. |
| `sched_mono_ms` | 2735–2739 | 5 | `CLOCK_MONOTONIC` в мс | `std::time::Instant` | **P*** | Единицы/монотонность те же; обёртки нет. |
| `worker_run_body` | 2741–3253 | 513 | тело worker: VOICE/VERIFY/CONTACT/addr-recheck/ECH GREASE+real/baseline/own-first base/volume first+after+carried/QUIC arm/TCP white/seed/classify и фиксация результата | `main.rs:15311 r2o_discovery_ech_grease_fallback`, `:15322 r2o_discovery_ech_replay_required`, `:15274 r2o_classify_discovery_target_with_client_hello_and_ech`, `:15396 r2o_classify_discovery_target_with_client_hello_and_ech_progress`, `:10605-10643` base before own plans, `:11913-11990 r2o_saved_address_recheck`, `:3233 r2o_discovery_cached_volume_cut`, `:14628 r2o_discovery_volume_recovery`, `r2o_measure_voice_for_flow`, `r2o_quic_*` | **P** | **Подтверждено в Rust:** VOICE (`r2o_measure_voice_for_flow`), VERIFY (`r2o_run_discovery_candidate_trial_*`, encoding/retry), CONTACT (`BoundTcpProbe`), addr-recheck (`r2o_saved_address_recheck` + `main.rs:11913-11990`: Silent/CoolingDown/Accepted, `address_recheck_probes/acknowledged`), ECH GREASE/real/baseline, `own_first` base (`run_base_with_backend_progress` до своих планов, `base.blocked/seed_whole`), volume (`r2o_discovery_cached_volume_cut`/`r2o_discovery_volume_recovery`), QUIC arm, TCP white/seed. **Остаются P-пробелы:** точная матрица verifier'ов (`rx_phase`, `layered_rx`, `measure_path`, ALPN) и комбинации ECH+volume, addr+voice, QUIC deny recheck не сведены в один differential; C-ветка `volume_carried && CLEAR` (3228-3239) в Rust выражена через cached-volume/volume-recovery, но эквивалентность этой конкретной развилки не доказана. |
| `worker_run` | 3255–3270 | 16 | `worker_executing=1`, `worker_started_ms`, вызов тела, `last_measurement_done_ms` для CLASSIFY/VERIFY/VOICE | `main.rs:16688-16806` (счётчики workers), `diagnostics.rs:461-464` | **P** | **Подтверждённый пробел:** Rust ведёт `workers_started/joined`, но в диагностическом снимке `last_measurement_age_ms` выставляется `None` (`main.rs:16803`), отдельного обновления `last_measurement_done_ms` по завершении worker нет. `worker_executing` выражен состоянием задачи/очереди. |
| `quic_text_is_split` | 3276–3278 | 3 | текст плана содержит `\nquicsplit ` | `plan_text.rs:463,480-482` (разбор/уникальность), `quic_replay.rs:478,606` (генерация директивы) | **P*** | Rust не ищет подстроку в тексте, а разбирает `quicsplit` как директиву плана; для сгенерированных планов эквивалентно. |
| `quic_client_multi` | 3280–3286 | 7 | имя/family в кольце `quic_multi` — клиент шлёт несколько датаграмм | нет кольца `quic_multi`; форма пачки — `r2k_quic_initial_client_hello_from_datagrams`/QSN | **P** | **Подтверждённый пробел:** поиск по `crates/` не нашёл кольца/флага multi-datagram по имени и family. Rust умеет собирать ClientHello из нескольких Initial, но не помнит «этот клиент multi» для решения о разрезе CRYPTO. |
| `quic_split_unfit` | 3293–3298 | 6 | QUIC: multi-client или неснятый/неполный Initial → разрез неприменим | `quic_replay.rs:558+ r2o_quic_adaptive_split_eligible`, `r2k-core/src/quic.rs:167 initial_split_crypto` | **P** | **Подтверждённое отличие:** C-предикат учитывает `quic_client_multi` и `d2k_quic_hello_incomplete`; Rust `adaptive_split_eligible` смотрит на `split_decision/applicable` и данные, а `initial_split_crypto` отказывает без SNI. Кольца multi и проверки неполного Initial как отдельного гейта нет. |
| `task_budget` | 3306–3329 | 24 | бюджет: rx-volume packets цели → `vol.rx_cut_packets` → rx-volume коробки `box_id` → поле 25 | `main.rs:5529 packet_budget: Option<u32>`, `:15059 R2O_VOLUME_TX_LADDER_PACKET_BUDGET`, `:3285-3289` | **P** | Rust передаёт `packet_budget` в fetch/классификатор и использует `R2O_VOLUME_TX_LADDER_PACKET_BUDGET`, но **не имеет** C-функции с приоритетом «цель → RX-cut → коробка → поле 04.10» и поля `budget_src`. Точная последовательность источников не сопоставлена. |
| `note_worker_start_failure` | 3331–3337 | 7 | `worker_start_failures++`, `local_error=1`, запомнить suspect/target | `diagnostics.rs:461-464,677-679`, `main.rs:16806` | **P*** | **Подтверждённый пробел:** поле `worker_start_failures` в диагностике есть, но в production-снимке выставляется **0** (`main.rs:16806`), инкремента нет; `local_error`/last target в Rust не заведены. |
| `start_worker` | 3339–3398 | 60 | mmap-аргументы, перенос hello/opts, 1 МиБ стека, spawn-hook, счётчики | `main.rs:16688+` (`r2o_ensure_workers`, thread spawn), `7900-7970` память | **P** | **Отличия:** Rust использует `std::thread` с умолчательным стеком, без `pthread_attr_setstacksize(1 МиБ)` и spawn-hook; аргументы — owned-структуры, не mmap. Перенос hello/opts/budget и счётчики частично есть. |
| `join_worker` | 3405–3424 | 20 | stop=1, разбудить condvar, join, счётчики/сброс | worker `Drop`/`r2o_join` (`main.rs:5290-5305`), `workers_joined` | **P** | Rust останавливает worker через канал/`AtomicBool` и join в Drop; отдельного `stop`-флага задачи и `worker_join_failures` нет. `worker-memory/permit` дифференциалы частичные. |
| `box_ensure` | 3430–3442 | 13 | найти/создать коробку по id | `catalog.rs` (`Catalog.boxes`, добавление в `add_measured_binding_with_fingerprint`) | **P*** | Отдельного `box_ensure` нет; Rust ищет/создаёт запись в `Catalog` при подтверждении. Эквивалентно по результату, не по API. |
| `wall_s` | 3459–3461 | 3 | `wall_base_s + (now_ms-mono_base_ms)/1000` | `main.rs` wall-clock (`SystemTime::now`) / live timestamp | **P*** | C переводит монотонные мс в стенную эпоху через базу; Rust берёт `SystemTime` напрямую. Скачки часов обрабатываются иначе, отдельного differential нет. |
| `bind_confirmed` | 3463–3568 | 106 | записать box/fp/plan/binding: successes++, confirmed, recheck_since=0, budget сброс при смене плана, shape/tcp_profile/verified_by/input только сильнее | `discovery.rs add_measured_binding_with_fingerprint`, `main.rs:21856 apply_discovery_outcome` | **P** | Основные ветви (box/fp/plan/binding, successes/confirmed, input «client сильнее profile») есть. **Не сопоставлены:** сброс `budget` при смене plan_id, `recheck_since`-сброс, `tcp_profile` в `Binding` отсутствует (header #16), точные правила `shape/verified_by`. |
| `fnv1a` | 3574–3581 | 8 | FNV-1a 64 по сырому тексту | `r2o_fallback.rs:52-58 tried_key` | **P*** | Rust считает FNV по тексту с заменой `r2o-plan`→`d2k-plan` и берёт low 32 бита; C — по исходному тексту. Для C-планов (`d2k-plan`) совпадает, для R2O-текста нормализация меняет хеш. |
| `tried_add` | 3593–3596 | 4 | добавить hash в `tried[]`, при переполнении `tried_full=1` | `r2o_fallback.rs FallbackQueue.tried: Vec<u32>`, `main.rs:15036` | **P*** | Rust хранит `Vec`/`HashSet` без флага переполнения; `tried_full` и журнальное сообщение отсутствуют. |
| `plan_ident` | 3598–3605 | 8 | `plan-%08x` (FNV low32) + wire id 16 байт ASCII | `discovery.rs:1450-1460 plan_text_for_trial`, `:1462+ stable_plan_id` | **P** | **Подтверждённое расхождение (header #17):** C — `plan-%08x` и те же байты на проводе; Rust для trial подставляет **16-байтный random id** (`plan_text_for_trial`), а каталожный `stable_plan_id` — 32 hex из двойного FNV. Формат/значение идентификатора различаются. |
| `is_hex_digit` | 3607–3609 | 3 | `0-9a-fA-F` | `plan_text.rs` (`is_ascii_hexdigit`/разбор) | **P*** | Хелпер; отдельной функции нет, набор символов тот же. |
| `question_shape` | 3635–3640 | 6 | QUIC→QUIC; иначе форма hello, UNKNOWN→GRANDFATHER | `main.rs:6330-6344 r2o_discovery_plan_shape`/`r2o_plan_wire_shape` | **P*** | Rust сводит ECH→MODERN в `r2o_discovery_plan_shape`, QUIC обрабатывается отдельно; UNKNOWN→GRANDFATHER как отдельное правило не найдено. |
| `probe_shape` | 3642–3672 | 31 | ECH_TCP при ech_offer; QUIC→QUIC; LEGACY при legacy hello; иначе MODERN | `main.rs:6339-6344 r2o_plan_wire_shape`, `control.rs:r2k_link_shape_tcp_context` | **P*** | Rust `r2o_plan_wire_shape` применяет TCP-контекст (TS/no-TS), но C-ветка «ECH→ECH_TCP, иначе MODERN» и выбор по форме триггера разнесены; полного differential нет. |
| `task_wire_shape` | 3674–3676 | 3 | TCP → `d2k_link_shape_tcp_context(shape, trigger_tcp_profile)`, иначе shape | `r2k_core::control::r2k_link_shape_tcp_context` | **P*** | Rust-функция есть и используется в `r2o_plan_wire_shape`; C-профиль `trigger_tcp_profile` в Rust представлен `Option<bool>`, UNKNOWN сводится к NO_TS. |
| `binding_wire_shape` | 3678–3682 | 5 | shape или GRANDFATHER; TCP → context с `bd->tcp_profile` | `main.rs:6339-6344 r2o_plan_wire_shape`, `Binding` без `tcp_profile` | **P*** | **Подтверждённый пробел:** `Binding` в Rust не хранит `tcp_profile` (header #16), поэтому wire-shape привязки нельзя пересчитать так же, как C. |
| `stamp_plan_id` | 3684–3704 | 21 | заменить `id <32hex>` на wire id на месте, иначе -1 | `discovery.rs:1450-1460 plan_text_for_trial`, `text_with_id` | **E** | Rust канонизирует текст и заменяет единственный `id <32hex>` на trial id; multiple/absent id отвергаются. Используется во всех plan differentials; C-функция правит на месте, Rust возвращает новый текст. |
| `prop_close` | 3727–3732 | 6 | закрыть `prop_fd`, если >0, и поставить -1 | `BoundTcpProbe`/`OwnedFd` RAII; `delete_name_probe` (`main.rs:19799`) | **P*** | C вручную закрывает fd и защищается от нуля; Rust владеет сокетом типом и закрывает Drop-ом. Эквивалентно по владению, отдельной функции нет. |
| `contact_close` | 3738–3743 | 6 | закрыть `c_fd`, если >0, и поставить -1 | `BoundTcpProbe` Drop, worker contact job | **P*** | C-закрытие после join; Rust сокет живёт в `BoundTcpProbe`/задаче и освобождается Drop-ом. |
| `ver_close` | 3749–3754 | 6 | `d2k_verify_close` при `ver.fd>0`, иначе только -1 | `FetchResult`/`TcpStream` RAII, `fetch.rs` | **P*** | C закрывает fd результата зонда; Rust `TcpStream`/rustls закрываются при выходе из fetch. Отдельного `ver_close` нет. |
| `task_reset` | 3762–3811 | 50 | если worker жив — не трогать; report local-abort; закрыть prop_bound/probe fd; memset; **MADV_DONTNEED** целых страниц с учётом madvise-статистики; fd=-1, worker_started_ms=-1 | task slots/queue cleanup (`main.rs:12788+`), `diagnostics.rs:281-300` (JSON), `MadviseStats` | **P** | **Подтверждённый пробел:** Rust очищает task slot/очередь и ведёт `MadviseStats` в диагностике, но **production-вызова `madvise(MADV_DONTNEED)` не найдено**; счётчики madvise заполняются только тестами/JSON. C-сброс fd-полей заменён владением. |
| `box_injects_rst` | 3834–3840 | 7 | в отпечатке коробки есть сигнал kind `rst` | `discovery.rs:2086,2107,2141` (сигнал `rst`), отдельного предиката нет | **P*** | Rust хранит/сравнивает сигнал `rst` в отпечатке, но функции «коробка вбрасывает RST» не найдено; используется ли это для генерации guard — см. `plan_arm_rst_guard`. |
| `rst_guard_wanted` | 3842–3847 | 6 | TCP и trigger_code ∈ {RST, RST_CUT, RST_AFTER_APP} | нет прямого предиката; `plan_text.rs:510-511` только разбирает `guard rst_alien` | **P** | **Подтверждённый пробел:** Rust не имеет функции выбора «нужен ли guard» по коду подозрения; парсер плана поддерживает строку, но генератор не найден. |
| `plan_arm_rst_guard` | 3853–3860 | 8 | дописать `guard rst_alien\n`, если guard ещё нет и хватает места | `plan_text.rs:505-515` (разбор `guard rst_alien`), `engine.rs:4519+` (исполнение) | **P*** | Датапат Rust исполняет guard и парсер принимает строку, но **сборщик плана её не добавляет** (grep `guard rst_alien` — только парсер/тесты). C-функция дописывает строку; аналога-генератора нет. |
| `prop_send_next` | 3864–3970 | 107 | следующий вопрос свойств: снять прежний, собрать план, trial id, bind+mark, SET_NAME, JOB_CONTACT, APPLIED по ключу | `ask::question_plan` + CLI `run_r2o_ask` (`main.rs:469`); discovery — `raw_probe::sweep_poisons` | **P** | **Расхождение слоя:** C вызывает это в production-discovery при `verdict==OPAQUE && transport==6 && !have_arm && !owns_search` (`sched.c:11462-11474`, `:12182-12200`) и ставит временный план через управляющий сокет; R2O discovery вопросов через control не задаёт — только raw-пробы (12 свойств, `raw_probe.rs:840`), а `question_plan`/`wait_for_ask_proof` есть лишь в CLI `--ask` (`main.rs:469,646`). На роутере без raw-сокета C всё равно получает вектор, R2O — нет. |
| `prop_finish` | 3974–3989 | 16 | снять план последнего вопроса, закрыть fd, `sync_pending=1` | CLI `run_r2o_ask`: `question_retire` (`main.rs:737`); в discovery аналога нет | **P*** | В production-discovery R2O снимать нечего, потому что control-план вопроса не ставится. Снятие временного плана после raw-пробы не требуется; `sync_pending` выражен проходом каталога. |
| `task_fail` | 3993–4030 | 38 | join, report failed, contact close, QUIC-deny при stall_cut, trial_retire, закрытие fd, `sync_pending`, T_RESTING и rest_until, сброс планов | task failure/cancel path (`main.rs:12788+`, `R2oDiscoverySearches`), `r2o_install_quic_deny` | **P** | Rust останавливает задачу/чистит очередь и ставит QUIC-deny в соответствующей ветке; C-порядок (join → report → deny → retire → sync → rest) и rest_until не сопоставлены один-в-один. Scheduler differentials частичные. |
| `quic_deny_find` | 4032–4038 | 7 | найти слот по name/family | `r2o_quic_deny.rs:161-166 r2o_find` | **E** | Rust `r2o_find` сравнивает name/family в массиве 16 слотов; тесты `r2o_quic_deny.rs`. |
| `quic_deny_install` | 4040–4112 | 73 | выбрать слот (free → inactive с ближайшим until), записать name/family, `d2k-plan` quicdeny, SET_NAME shape QUIC, streak++, delay 10/30/60, пометить QUIC-привязки recheck_since | `main.rs:21392-21485 r2o_install_quic_deny`; `r2o_quic_deny.rs:47-82 record_cut`, `:199-215 delay` | **P** | **Совпадает:** 16 слотов, streak 1→10 мин/2→30/иначе 60, active/rechecking, пометка bindings `recheck_since`, запись в каталог. **Отличия:** C печатает `d2k-plan 1 11` и `plan-%08x`/wire id, Rust — `r2o-plan` + 16-байтный random id; C шлёт через `d2k_link_set_name_family`, Rust — `encode_set_name`; выбор victim в C `!active` с earliest until, в Rust `r2o_slot` — free → inactive earliest. Тесты QUIC-deny есть. |
| `quic_deny_active` | 4114–4120 | 7 | активен ли запрет по name/family | `r2o_quic_deny.rs:154-159 r2o_is_active` | **E** | Совпадает: `active` + name/family; тесты `r2o_quic_deny.rs`. |
| `quic_deny_recheck` | 4129–4153 | 25 | если поиск уже идёт — 1; иначе task_done/свободный слот, заполнить name/transport/family/ip/port/trig, `deny_recheck=1`, запустить | `r2o_quic_deny.rs:84-99 start_recheck`, `main.rs:17754-17840 r2o_run_quic_discovery_trial` | **P** | **Совпадает:** перепроверка после срока своим запросом, флаг rechecking, повтор при cut. **Отличия:** C создаёт задачу с `trigger_code=QUIC_STALL` и `deny_recheck=1`; Rust запускает QUIC-trial через `r2o_run_quic_discovery_trial`, поля/триггер иные. Отдельного differential нет. |
| `quic_deny_tick` | 4155–4181 | 27 | по истечении: recheck, если он идёт — ждать; иначе active=0, DEL_NAME QUIC, sync, лог | `r2o_quic_deny.rs:84-153 due_rechecks/start_recheck/recheck_clear/pending_removals/finish_removal`, `main.rs:17731-17760` | **P** | Rust-модуль покрывает due/recheck/removal и тесты снятия только после подтверждения DEL; C-тик дополнительно проверяет `task_of`/`deny_recheck` и снимает запрет при незавершённой перепроверке. Полного differential тика нет. |
| `task_done` | 4183–4191 | 9 | join, report cancelled, contact/prop/ver close, task_reset, T_FREE | task cancel/free (`main.rs:12788+`) | **P** | Rust отменяет задачу через cancel-флаг/очередь и освобождает slot; C-порядок close/reset/T_FREE и report cancelled не сопоставлены. Queue/lifetime differentials частичные. |
| `rx_decoy_name` | 4195–4197 | 3 | имя приманки RX: `network_whitelist.name` или `hcaptcha.com` | `main.rs:10570` (`unwrap_or("hcaptcha.com")`), `:14388` (список кандидатов) | **P*** | Значение по умолчанию то же; отдельной функции нет. |
| `net_whitelist_undecided` | 4201–4203 | 3 | `!searched && !name` | `main.rs:3272-3279 r2o_discovery_network_whitelist_probe` | **E*** | Логика совпадает: не решено → `!searched && name.is_empty()`. |
| `net_whitelist_needs_probe` | 4211–4214 | 4 | не решено **или** (`rx_cut && name && tx_only`) | `main.rs:3272-3279` | **E** | Построчно совпадает, включая `rx_cut`/`tx_only`; `r2o-net-whitelist-probe-differential.sh`. |
| `sched_probe_cap` | 4220–4222 | 3 | `SCHED_MAX_PROBES + (net_probing ? net_whitelist_count : 0)` | `main.rs:10661,11160,14728` (`R2O_DISCOVERY_PROBE_CAP + network_probe count`) | **P*** | Формула та же; C-константа `SCHED_MAX_PROBES` и Rust `R2O_DISCOVERY_PROBE_CAP` отдельно, точное равенство не проверялось. |
| `vol_cut_measured` | 4224–4226 | 3 | TX `VOL_CUT` или RX-обрыв | `main.rs:3223-3231 r2o_discovery_volume_cut` | **P*** | Rust: `tx.verdict == Cut \|\| rx.evidence.is_some()`; C: `rx_cut \|\| verdict == VOL_CUT`. Эквивалентно по смыслу, отдельной функции нет. |
| `vol_cut_kb` | 4227–4229 | 3 | RX `rx_at_kb` приоритетнее TX `at_kb` | `fetch.rs` volume result (`rx_at_kb`/`at_kb`), `main.rs` volume cut | **P*** | Поля объёма есть; отдельного приоритетного селектора не найдено, C/Rust differential нет. |
| `rx_ladder_pending` | 4233–4236 | 4 | при `net_probing` — непройденные имена, иначе — варианты разреза | `main.rs:14580+ r2o_ech_rx_ladder_candidate_count`, `main.rs:14728+` | **P*** | Rust считает кандидатов лестницы/белых имён, но отдельного предиката «ещё есть» с теми же полями нет. |
| `next_rx_volume_plan` | 4242–4290 | 49 | следующий план: белое имя (variant 0) или 5 вариантов decoy; дедуп по тексту/hash; `net_probe_scratch` | `main.rs:14580+ r2o_ech_rx_ladder_candidate`, `:6292 r2o_discovery_measured_split_plan`, `r2o-rx-volume` | **P** | **Совпадает:** имена/варианты, дедуп по hash, `hcaptcha.com` как decoy. **Отличия:** C ведёт `rx_hashes`/`net_probe_scratch` в задаче; Rust возвращает кандидата из `r2o_rx_volume`/`measured_split_plan`, поля-атрибуции иные. |
| `refill_from_fallback` | 4292–4368 | 77 | долив: RX-лестница → fallback донора; при RX-cut только лестница; `fb_queue/fb_from`, лог | `main.rs:11286+` (`FallbackQueue`/`r2o_fallback`), `r2o_fallback.rs` | **P** | **Совпадает:** fallback только после своих/измеренных, при RX-cut только SNI-лестница, дедуп tried. **Отличия:** C хранит `plans/plan_boxes/net_probe_name/fb_queue` в задаче; Rust — `FallbackQueue` и `measured_split_plan`; порядок/порции полностью не сопоставлены. |
| `claim_early_refusal` | 4394–4410 | 17 | собрать flow ключа зонда и взять первый совпавший ранний REFUSED; сбросить `ver_unsent_seen` | `main.rs:19088+` (REFUSED-поток), early-очередь не вынесена | **P*** | C хранит `ver_unsent_early[]` и после возврата зонда ищет совпадение по flow; Rust обрабатывает REFUSED-события в общем цикле (`main.rs:19088-19170`), отдельного «раннего» списка/функции не найдено. |
| `ack_reason_text` | 4412–4419 | 8 | код ACK → текст: BAD_PLAN/NO_ROOM/BAD_ARGS/неизвестно | `main.rs:4384-4392 ack_reason_text`, `:15770 r2o_ask_ack_reason` | **P*** | Набор кодов и тексты совпадают; отдельного differential/теста на все коды нет. |
| `candidate_trial_matches` | 4424–4431 | 8 | `SET_NAME_PROBE` → `!by_addr` и trial_ack_id; `SET_ADDR_PROBE` → `by_addr` и addr_probe_trial_id | `main.rs:applied_quic_trial_matches`/`r2o_trial` matching, `:20340+` | **P** | Rust сопоставляет APPLIED/ACK по trial/plan/flow, но отдельной функции «какая команда к какому trial» нет; ack-applied differential частичный. |
| `exec_refusal` | 4437–4466 | 30 | late/non-late ACK ok=0: лог, вернуть probe/exec_probed, снять trial/socket, state=T_PLANNING | `main.rs:16473,22158` (`ack_reason_text`), trial refusal path | **P** | Тексты причин совпадают; C-счётчики `exec_probed/exec_refused`, возврат `probes_used`, сброс `own_probed` и переход T_PLANNING в Rust разнесены. Scheduler differentials частичные. |
| `ech_witness_transport_proof` | 4468–4474 | 7 | TCP+ECH, не replay, origin≠name; accepted+name_ok=1+body_complete+status 100..599; level CHALLENGE или CF | `main.rs:14518-14535 r2o_ech_witness_transport_proof` | **P** | **Подтверждённые отличия:** Rust принимает CF **или** статус 429 с `!Blocked/LegalDenial`, дополнительно требует `fetch.complete` и 100..599; C требует `level == CHALLENGE` (или CF), `body_complete`, `name_ok==1`. Набор условий различается; ECH-дифференциалы частичные. |
| `ech_witness_rx_cut` | 4476–4483 | 8 | TCP+ECH, не replay, origin≠name; accepted+name_ok=1+status 200..399+неполное тело+framing valid+body>=8192 | `main.rs:14539-14558 r2o_ech_witness_rx_cut`, тесты `:29215-29242` | **E** | Условия совпадают; Rust дополнительно требует `tls.is_some()` и `!Blocked/LegalDenial`. Тесты покрывают границы (accept/reject). |
| `local_refusal_verdict` | 4485–4537 | 53 | permanent → следующий кандидат; бюджет исчерпан → следующий; иначе повтор с `unsent_tries++`, probe++ и JOB_VERIFY | `main.rs:19088-19170` (TOO_LONG/NOT_APPLIED/FLOW_UNFIT), `r2o_record_plan_refused` | **P** | **Совпадает:** 3/5/6 → кандидат не судим, 6 отдельно ведёт к повторному замеру; повтор ограничен. **Отличия:** C-счётчики `unsent_tries/probes`, `SCHED_UNSENT_RETRIES`, переход T_VERIFY/JOB_VERIFY и точный выбор «следующий/повтор» в Rust разнесены по controller-циклу; C/Rust differential нет. |
| `install_next` | 4539–4750 | 212 | сброс unsent; перебор `plans`: probe cap, ladder skip, QUIC split-unfit, trial id, guard, hex, bind port, mark, SET_NAME_PROBE/SET_ADDR_PROBE, backoff/fallback/refill | `main.rs:5717+ r2o_run_discovery_candidate_trial`, `:20340+` (`SET_ADDR_PROBE`), `:5512+` | **P** | **Совпадает:** trial id на попытку, wire-only stamp/guard, bind+mark, QUIC/addr probe, снятие прежнего trial, probe cap. **Отличия:** C сам конвертирует текст в TLV и шлёт `d2k_link_set_*_probe_trial`; Rust использует `compile_text`/`r2o_plan_records_for_wire` и control-команды; guard-генератор отсутствует (см. `plan_arm_rst_guard`); `own_probed`/`unsent_tries`/`ladder_unmeasurable` разнесены. ack/queue/QUIC differentials частичные. |
| `binding_for` | 4760–4775 | 16 | найти name-binding по name/transport/family | `discovery.rs:52 own_first_bound_plan_id`, `main.rs:10589` | **P*** | Rust ищет по host/transport 6/family/shape, но не имеет отдельной функции `binding_for`; C допускает любой транспорт. |
| `known_plans` | 4777–4831 | 55 | планы совместимой коробки: proto tls/quic, enabled/len, дедуп по text/tried, приоритет совпадающей volume-корзины и successes | `discovery.rs:274 known_plans`, `main.rs:10941+` | **E** | C/Rust fixture `d2o_known_plans.tsv` (`discovery.rs:1644,1762`) и `r2o-known-plans-differential.sh`; порядок bucket/successes совпадает. |
| `budget_rank` | 4866–4868 | 3 | passed→2, cut→0, иначе 1 | `main.rs:2453-2460 r2o_catalog_budget_rank` | **E** | Посимвольно совпадает; используется в `binding_beats`. |
| `binding_beats` | 4869–4872 | 4 | сначала budget_rank, затем confirmed | `main.rs:2463-2468 r2o_catalog_binding_beats` | **E** | Совпадает: `left_budget > right_budget` или равенство и `left.confirmed > right.confirmed`. |
| `bound_plan_here` | 4881–4901 | 21 | enabled/level 3+, name, transport/family, shape, TCP profile, не CLIENT для QUIC, не newer, план существует | `discovery.rs:52-100 own_first_bound_plan_id` | **P** | **Подтверждённые отличия:** C проверяет `bd->tcp_profile == t->trigger_tcp_profile` и `verified_by == CLIENT` для QUIC; `Binding` Rust не хранит `tcp_profile`, а `verified_by`-условие в `own_first_bound_plan_id` не выражено. `newer_name_binding` есть. own-first/ack differentials частичные. |
| `own_rank_before` | 4906–4912 | 7 | lead, tier, successes, свежесть | `discovery.rs:344 own_rank_before` | **P*** | Rust `RankedOwnPlan` сравнивает lead/tier/successes/freshness; поля упакованы иначе, порядок тот же. |
| `own_first_plans` | 4914–5053 | 140 | свои подтверждённые планы: same form/cross TLS, ECH replay, bound-plan lead, own_seen/tried, порция ≤ room, fill 0/1/2 | `discovery.rs own_first_plans`/`own_first_bound_plan_id`, `main.rs:10589-10953` | **E** | `r2o-own-first-differential.sh`; C/Rust покрывают форму/lead/дедуп/лимит. **Остаточный пробел:** `tcp_profile`/`verified_by`-условия (см. `bound_plan_here`). |
| `verdict_proves_block` | 5057–5060 | 4 | PREFIX/WHOLE/OPAQUE | `classify.rs` verdict helper (`Verdict`), main.rs discovery | **P*** | Rust-набор из трёх «доказывающих» вердиктов используется в discovery; отдельной функции нет. |
| `clear_measured_shape` | 5074–5080 | 7 | asked_shape, иначе QUIC/ECH/LEGACY/MODERN | `discovery.rs:850+ update_direct_clear_bindings` (target.shape) | **P*** | C выводит форму из задачи/профиля; Rust direct-clear получает `target.shape` и добавляет `modern_covers_ech`. Отдельной функции нет. |
| `clear_binding_matches` | 5082–5089 | 8 | name/target/transport/family, TCP profile, `shape_fits` | `discovery.rs:885-889` (`matches_target`, modern→ECH) | **P*** | **Отличие:** Rust считает `MODERN` покрывающей `ECH_TCP` (`modern_covers_ech`); C `d2k_cat_shape_fits` — только равенство/0. `tcp_profile` в Rust `Binding` отсутствует. |
| `forget_clear_target_bindings` | 5123–5172 | 50 | первый независимый CLEAR → recheck_since + DEL_NAME своим ключом; второй (gap 60 с) → удалить из каталога | `discovery.rs:850-925 update_direct_clear_bindings`, `main.rs:15957,22096` | **E** | **Совпадает:** `RECHECK_GAP=60s`, mark/remove/waiting, modern→ECH, удаление только второго независимого. Rust возвращает `delete_runtime` и caller шлёт DEL_NAME; C шлёт внутри. Тесты discovery. |
| `props_text` | 5178–5186 | 9 | текст вектора: «не измерено/да/нет» по 5 свойствам | `ask::DpiProps` display (`main.rs` ask), `props_text`-аналог | **P*** | Русские строки/порядок полей в Rust формируются иначе; отдельного differential нет. |
| `probes_word` | 5191–5201 | 11 | склонение «опыт/опыта/опытов» | `main.rs` plural helper, live/report text | **P*** | C-правило (11–14 → опытов) в Rust не выделено; тексты не сверялись. |
| `verdict_to_plans` | 5209–5551 | 343 | по вердикту собрать кандидатов: early-return, ECH trial, QUIC arm, volume fingerprint + known plans, measured arm, RX-лестница, PREFIX/WHOLE split, owned fallback, compose | `main.rs:14573 r2o_ech_rx_ladder_candidate`, `:3438 r2o_discovery_volume_known_plans`, `:6292 r2o_discovery_measured_split_plan`, `r2o_fallback`/`own_first_plans`, `compose_d2o`/`compose_from_props`, `quic_replay.rs:427 r2o_quic_discovery_candidates` | **P** | C-порядок: (1) CLEAR/UNREACHABLE/ADDRESS/RESPONSE/NO_QUIC/LOCAL_ADDRESS → пусто (`:5224-5234`); (2) ECH trial — known plans witness (`:5242-5262`); (3) QUIC — один план из arm+qprops, `arm_hash/arm_path`, `stall_cut`, `quic_split_unfit` (`:5264-5386`); (4) volume signal + `known_plans` (`:5390-5422`); (5) measured arm первым (`:5429-5459`); (6) RX-лестница: room по `rx_cut`, `net_probing`, `plan_boxes`, `rx_volume_candidate_pending` (`:5465-5517`); (7) PREFIX/WHOLE split (`:5519-5528`); (8) `owned_fallback`/`refill_from_fallback` (`:5539-5544`); (9) `d2k_compose` (`:5547-5550`). **Подтверждено в Rust:** `stall_cut` (`main.rs:4898,6898,20606,21068`), `owned_fallback` (`r2o_fallback.rs:10,23,334`; `main.rs:11125-11899`), measured split (`main.rs:6292`), volume-known plans (`:3438`), compose/fallback. **Остаются P-пробелы:** `arm_hash/arm_path`-атрибуция, `plan_boxes`/`net_probe_name`-раскладка и `rx_volume_candidate_pending` как отдельная очередь не найдены; вместо них `primary_source`/`owned_fallback_queue`/`fallback_reason` (`main.rs:11125-11298`). Полного differential порядка источников кандидатов нет. |
| `d2k_sched_new` | 5566–5610 | 45 | calloc; cat/link/mark/measure_mark; `stall_sent[0]=25`; meas_limit=default; wake pipe nonblock; mutex/cond; QUIC hooks | `main.rs:10388-10400` (R2oDiscoveryQueue/Searches constructors), `R2oDiscoveryWorker` | **P** | **Совпадает:** дефолты лимита/бюджета, wake-канал/очередь, mutex/cond, QUIC progress/yield hooks. **Отличия:** Rust не использует pipe, а канал/condvar; `wall_base`/mono-база выражены `Instant`/`SystemTime`; C/Rust diff нет. |
| `d2k_sched_set_measure_mark` | 5612–5614 | 3 | установить `measure_mark` | поле `measure_mark`/`r2o_mark` в discovery (`main.rs`) | **P*** | Поле есть; отдельного сеттера/теста нет. |
| `json_str` | 5624–5632 | 9 | JSON-строка: `"`/`\` и control → `\u00xx` | `serde_json`, `live.rs` snapshot | **P*** | Rust сериализует через serde_json; экранирование эквивалентно, формат вывода может отличаться. |
| `json_time` | 5634–5645 | 12 | unix_s<=0 → `0001-01-01T00:00:00Z`, иначе RFC3339 UTC | `main.rs:8811 r2o_live_timestamp`, `live.rs` | **P*** | Нулевое время/RFC3339 совпадают; Rust формирует из `Instant`/wall-clock иначе. |
| `level_name` | 5650–5659 | 10 | 1 транспорт / 2 сервер / 3 обмен / 4 приложение / 5 последующие | `live.rs` binding `level_name` | **P*** | Тексты уровней в Rust есть; дословное совпадение не сверялось. |
| `signal_human` | 5663–5680 | 18 | текст `rst`/`volume`/`rx-volume`/`rx-volume-wire`/`silent`/`repeat`, иначе kind | `live.rs` signal human | **P*** | Набор родов и формат текста Rust иные; отдельного differential нет. |
| `task_phase` | 5685–5705 | 21 | текст фазы по `task_state` | `live.rs`/`main.rs` search phase | **P*** | C-фазы T_* и Rust-строки фаз не сопоставлены дословно; T_WATCHING-фазы в Rust нет. |
| `live_binding_for` | 5707–5721 | 15 | enabled, !recheck, transport/family, target | `live.rs` r2o_live_status | **P*** | Rust ищет активную привязку для live-снимка; отдельной функции нет. |
| `live_autopick_status` | 5723–5807 | 85 | причина autopick: нет событий/подозрений/имени, local error, cooldown, T_QUEUED/WATCHING/RESTING/VOICE, иначе phase + binding | `main.rs` r2o_live_status/autopick, `live.rs` | **P** | **Совпадает:** основные причины и cooldown_seconds. **Отличия:** C-состояния T_* и Rust-фазы/очередь различны; panel live tests, C/Rust diff нет. |
| `d2k_sched_diagnostics` | 5811–5813 | 3 | подключить observer событий | `diagnostics::Recorder` hook (`main.rs:17089+`) | **P*** | Rust-рекордер подключается в controller-цикле; сеттера API нет. |
| `d2k_sched_limit_diagnostics` | 5814–5816 | 3 | подключить observer смены лимита | `diagnostics::Recorder`/resource limit | **P*** | Отдельного hook-сеттера нет; смена лимита пишется рекордером. |
| `worker_type` | 5817–5825 | 9 | QUIC/TCP/VERIFY/CONTACT/VOICE/UNKNOWN | `main.rs` worker type/diagnostics | **P*** | Rust-тип worker выводится из job; строки совпадают не дословно. |
| `d2k_sched_diagnostic_counts` | 5826–5875 | 50 | counts: boxes/bindings/plans/observations/active/queued/catalog bytes/limit/resources/cpu/mem/conntrack/workers/task_states/snapshots | `main.rs:16688-16806`, `diagnostics.rs:461-464,676-679`, `r2o_resource_limit` | **P** | **Подтверждённые пробелы:** `worker_start_failures` всегда 0 (`main.rs:16806`), `last_measurement_age_ms` = None (`:16803`), `worker_join_failures`/`worker_oldest_age_ms` не заполняются; task_states/снимки считаются иначе (HashMap/очередь). Diagnostics differential частичный. |
| `d2k_sched_diagnostic_madvise` | 5876–5876 | 1 | отдать `MadviseStats` | `diagnostics.rs:281-300 madvise_json`, `MadviseStats` | **P** | JSON-форма совпадает по тесту `memory_tracking_and_madvise_json_match_d2o_shape`; **production-вызова madvise нет** (см. `task_reset`). |
| `d2k_sched_diagnostic_madvise_reset` | 5877–5877 | 1 | сбросить статистику | `MadviseStats` reset (diagnostics) | **P*** | Сброс структуры есть; отдельного вызова/теста нет. |
| `d2k_sched_write_live` | 5879–6049 | 171 | атомарно `live.json`: boxes/signals/plans/bindings/groups/searches/measurements/autopick/targets/confirms/probes/client_unfit | `live.rs::snapshot` (63)/`write_snapshot` (199), `main.rs` live status | **P** | **Совпадает:** атомарная запись, основные секции, `0001-01-01`, cooldown. **Отличия:** C-поля `linked/link_note/catalog_at`, порядок/набор полей и T_* не совпадают с Rust `live.rs` дословно; полного C/Rust differential live.json нет. |
| `d2k_sched_free` | 6051–6072 | 22 | снять addr-probe, join worker, report shutdown, close contact/prop/ver, destroy cond/mutex, close pipe, free areas | controller shutdown (`main.rs` Drop/join), worker Drop | **P** | Rust освобождает через Drop/RAII и останавливает worker-каналы; C-порядок addr-probe/join/report и `areas` не сопоставлены. Shutdown tests частичные. |
| `wake_loop` | 6077–6080 | 4 | записать байт в wake-pipe | канал/condvar worker (`notify_one`) | **P*** | Механизм заменён; эквивалент — пробуждение очереди. |
| `d2k_sched_wake_fd` | 6082–6082 | 1 | fd для poll | нет (канал/`try_result`) | **P*** | fd-контракт не нужен. |
| `d2k_sched_active` | 6084–6093 | 10 | число активных состояний (queued/shape/asking/planning/verify/watching) | `main.rs` searches active/live | **P** | Rust считает active по своим фазам/очереди; T_SHAPE_WAIT/T_WATCHING отдельно не выражены. |
| `plan_by_id` | 6096–6103 | 8 | включённый план коробки по id | `Catalog` plan lookup (`discovery.rs`) | **P*** | Rust ищет план в `BoxRecord.plans` с `enabled`; отдельной функции нет. |
| `d2k_sched_sync` | 6112–6125 | 14 | начать полную синхронизацию: сброс курсора/счётчиков, `sync_active=1` | `CatalogSyncCursor` (`main.rs:3887-4076`), `main.rs:1906` | **E** | `r2o-catalog-sync-differential.sh`; сброс курсора/счётчиков эквивалентен. |
| `d2k_sched_sync_pending` | 6127–6129 | 3 | `!area_command` и (`sync_pending` или `sync_active`) | `CatalogSyncCursor`/pending state | **P*** | Rust-состояние курсора/очереди иное; отдельного предиката нет. |
| `addr_binding_shape` | 6144–6165 | 22 | однозначная wire-shape адресной привязки: TCP context, QUIC/VOICE только UDP, shape 0 → STUN/VOICE или PROBE/QUIC, иначе 0 | `main.rs` `addr_binding_shape`/catalog sync, `control.rs` shape helpers | **P** | **Совпадает:** TCP-контекст, UDP-формы, shape 0 → verified_by. **Отличия:** `Binding.tcp_profile` в Rust нет, поэтому TCP-контекст нельзя пересчитать; `verified_by`-константы/поля иные. Catalog sync tests частичные. |
| `newer_name_binding` | 6171–6193 | 23 | есть ли более сильная enabled name-binding того же ключа (budget/confirmed, TCP profile, QUIC verified_by) | `discovery.rs newer_name_binding`, `main.rs:2518 r2o_catalog_binding_beats` | **P** | **Совпадает:** budget/confirmed, level 3+, recheck, shape; **отличия:** `tcp_profile` отсутствует, QUIC `verified_by`-условие не выражено, `plan_by_id`-проверка иная. known/own-first differentials частичные. |
| `area_key_same` | 6195–6198 | 4 | kind/transport/shape/family/name | `CatalogSyncCursor` area key (`main.rs:3887+`) | **P*** | Rust хранит ключ области структурой; набор полей тот же, отдельной функции нет. |
| `area_find` | 6200–6204 | 5 | линейный поиск установленной области | `CatalogSyncCursor` (`installed_areas`) | **P*** | Rust ищет по ключу в `HashMap`/векторе; эквивалентно. |
| `area_store` | 6206–6212 | 7 | вставить/заменить область, лимит 320 (GROUP_MAX+OBS_MAX) | `CatalogSyncCursor`/`installed_areas` | **P*** | Лимит и замена по ключу есть; структура хранения иная. |
| `area_retry_delay` | 6214–6221 | 8 | 15 с, удвоение до 5 мин | `CatalogSyncCursor` area retry (`main.rs:3887-4076`) | **E** | `r2o-catalog-sync-differential.sh`; база/удвоение/потолок совпадают. |
| `area_failure` | 6223–6237 | 15 | retry_count++, confirmed=0 (если не remove), maybe_active для timeout/send, permanent для BAD_PLAN/BAD_ARGS/UNKNOWN, retry_at | `CatalogSyncCursor` area failure (`main.rs:4004+`) | **E** | `r2o-catalog-sync-differential.sh`; причины/permanent/retry совпадают. |
| `area_ack_reason` | 6239–6246 | 8 | ACK NO_ROOM/BAD_PLAN/BAD_ARGS/UNKNOWN → reason | `CatalogSyncCursor` area ACK (`main.rs:4256+`) | **P*** | Rust-маппинг причин есть; отдельной функции/всех кодов нет. |
| `area_reason_name` | 6248–6258 | 11 | reason → `ack_timeout/send_error/no_room/bad_plan/bad_args/unknown_ack` | `CatalogSyncCursor`/live area reason | **P*** | Строки причин в Rust есть; дословное совпадение не сверялось. |
| `area_retry_due` | 6260–6265 | 6 | есть не-permanent область с `retry_at<=now` | `CatalogSyncCursor` (`main.rs:3887+`) | **E** | `r2o-catalog-sync-differential.sh`. |
| `area_plan` | 6267–6273 | 7 | найти план области по id и proto tls/quic | `Catalog` plan lookup, `CatalogSyncCursor` | **P*** | Rust ищет план в `BoxRecord.plans` по id; proto-проверка выражена иначе. |
| `own_exact_confirmed` | 6278–6293 | 16 | enabled, level>=3, !recheck, name/target, transport/family, TCP shape context или точная shape | `discovery.rs` confirmed lookup (`has_covering_binding`/own-first) | **P** | **Отличия:** C сравнивает `d2k_link_shape_tcp_context(bd->shape, bd->tcp_profile)` с ключом; Rust `Binding` без `tcp_profile`, сравнение shape иное. Groups/catalog tests частичные. |
| `desired_area` | 6297–6332 | 36 | группа → suffix/plan/ключ; observation → исключение при DIRECT_CLEAR/PLAN_FAILED, own_exact_confirmed и still_elected | `CatalogSyncCursor` desired area (`main.rs:3905+`) | **P** | **Совпадает:** приоритет исключений, own exact, still_elected, plan lookup. **Отличия:** C-структуры `d2k_group_state` и Rust `LiveGroup`/observations различны; catalog sync tests частичные. |
| `desired_has_key` | 6334–6341 | 8 | ключ ещё желаем любой desired-областью | `CatalogSyncCursor` (`main.rs:4040+`) | **P*** | Rust проверяет желаемые области/ключи; отдельной функции нет. |
| `write_live_groups` | 6347–6438 | 92 | JSON groups: suffix/key/plan/probe_path/ech_origin, install/exception state, active/possibly_active/remove, evidence/exceptions | `main.rs` live groups, `live.rs` snapshot | **P** | **Совпадает:** основные поля/состояния. **Отличия:** C-структуры `d2k_group_state` и Rust `live.rs` не сопоставлены дословно; panel tests, полного C/Rust diff нет. |
| `sync_area_send` | 6442–6518 | 77 | SET/DEL_SUFFIX/BYPASS с trial id, hex, 5-с дедлайном; attempt копирует retry/reason/confirmed, store, area_pending | `main.rs:3905-4076` (`CatalogSyncCursor` area commands), `ControlClient` | **E** | `r2o-catalog-sync-differential.sh`; identity/5 с/типы команд и сохранение состояния совпадают. |
| `area_exceptions_ready` | 6520–6532 | 13 | все desired-исключения группы подтверждены и не remove | `CatalogSyncCursor` (`main.rs:4076+`) | **P** | Rust проверяет исключения перед установкой suffix; структура/порядок совпадают, отдельного differential нет. |
| `area_exception_groups_suspended` | 6534–6551 | 18 | общие правила группы для той же цели сняты до исключения | `CatalogSyncCursor` (`main.rs:4076+`) | **P** | C проверяет `confirmed/maybe_active` группы; Rust-состояние `installed_areas` иное, catalog sync tests частичные. |
| `group_exception_status` | 6553–6586 | 34 | none/pending/retrying/rejected/active по observations; rank permanent>retrying>pending | `main.rs` live group exception status | **P** | Rust live-статус исключений есть; ранги/строки не сверены дословно. |
| `sync_areas` | 6588–6642 | 55 | ACK-таймаут 5 с; удаление нежелаемых; exceptions (kind 2) раньше suffix (kind 1); лимит областей | `main.rs:3905-4076` (`CatalogSyncCursor`), `observe_area_ack` (`:4256+`) | **E** | `r2o-catalog-sync-differential.sh`; порядок исключений/групп, 5 с и удаление совпадают. |
| `plan_text_max_emit` | 6648–6658 | 11 | TLV → Plan::load → `max_emit`; 0 при ошибке/нет посылок | `plan_text::compile` + `plan::max_emit` (`main.rs` send_cap) | **P** | Rust считает `max_emit` из скомпилированного плана; C-путь через `d2k_plan_load` эквивалентен, отдельного differential нет. |
| `d2k_sched_sync_step` | 6660–6907 | 248 | порция 8: skip disabled/recheck/newer/QUIC-deny/UDP CLIENT/level<3/TCP shape 0/missing plan; guard RST; send_cap; SET_NAME/ADDR; затем areas; stall budgets; сводка/refused | `main.rs:3887-4256 CatalogSyncCursor::send_step`, `catalog_area_*` | **E** | `r2o-catalog-sync-differential.sh` + catalog persist. **Совпадает:** chunk 8, все skip-условия, guard, send_cap, addr/name, areas, сводка. **Отличия:** C-`plan_text_to_hex`/`d2k_link_*` заменены `compile_text`/control-командами; `tcp_profile`/`verified_by`-поля в Rust `Binding` отсутствуют (см. header #16). |
| `has_other_family_target_plan` | 6915–6935 | 21 | есть подтверждённый план той же цели другого семейства | main.rs discovery other family plan | **P** | family queue differential частично |
| `remember_resources` | 6939–6959 | 21 | 8 слотов по host, TTL 1 ч; HTML-hint не вытесняет действующий proven-путь | `r2o_resource.rs:38-65 remember_hints`, `main.rs:5982,14695` | **P** | **Совпадает:** host-слоты, TTL, proven не вытесняется упоминанием. **Отличия:** C хранит `ref/proven/expires_ms` в `sched.resources[8]`; Rust `R2oResourceMemory`/`remember_hints` с иной структурой. Unit `r2o_resource`. |
| `remember_measured_path` | 6969–6983 | 15 | запомнить только доказанный `rx_cut` measured_path (proven, 1 ч) | `r2o_resource.rs:67-100 remember_proven_path`, `main.rs:14704` | **P** | **Совпадает:** только rx_cut, только path_ok, proven/TTL. Rust-структура и вызовы иные; unit `r2o_resource`. |
| `public_resource_peer` | 6985–6993 | 9 | IPv4 public (не 0/10/127/multicast/link-local/private/CGNAT); IPv6 global unicast `20::/3` | `main.rs:3037-3060 r2o_public_resource_ip` | **E*** | Посимвольно совпадает: те же диапазоны IPv4 и `first & 0xe0 == 0x20` для IPv6. |
| `select_resource_path` | 6995–7048 | 54 | 443, не by_addr, public peer; binding (level 3, name/transport/family/shape/path_ok, newest) → proven → mention; alt из proven/mention | `main.rs:3062-3105 r2o_target_confirmed_probe_path`, `:3107-3140 r2o_discovery_resource_probe_paths` | **P** | **Совпадает:** binding → proven → hint, newest confirmed, alt path, path_ok. **Отличия:** C `t->measure_path/measure_alt` пишутся в задаче; Rust возвращает `(primary, alternate)` из `R2oResourceMemory`. C/Rust differential нет. |
| `ech_rr_known` | 7052–7059 | 8 | HTTPS RR cache: used/not expired/name → has && public_name match; иначе -1 | нет прямого RR-кэша; `R2oEchChallengeCache` — только 30-мин карантин | **P** | **Подтверждённый пробел:** поиск по `crates/` не нашёл кэша «имя → has/public_name» с TTL 6 ч/30 мин. Rust резолвит HTTPS RR через `resolve_ech_config` и хранит только challenge-карантин; повторный резолв может отличаться по числу DNS-запросов. |
| `ech_rr_store` | 7061–7072 | 12 | записать RR: has/public_name, TTL 6 ч при yes, 30 мин при no; кольцо 256 | нет прямого аналога | **P** | **Подтверждённый пробел:** отдельного RR-кэша с TTL yes/no нет; `R2oEchChallengeCache` хранит только имена-карантины. |
| `ech_chal_has` | 7074–7079 | 6 | имя в 30-мин карантине ECH-witness | `R2oEchChallengeCache::contains` (`main.rs:10392+`, тесты `:26789-26802`) | **E*** | Совпадает: name + expiry 30 мин; тест кольца/истечения. |
| `ech_chal_add` | 7081–7086 | 6 | добавить имя в кольцо карантина (30 мин), без дубля | `R2oEchChallengeCache::record` (`main.rs:26789-26802`) | **E*** | Совпадает: запись/обновление, 30 мин; тест кольца/eviction. |
| `ech_pick_witness` | 7088–7116 | 29 | два прохода (allow_chal): RR known/chal, bad, real/первые 4, resolve+store public_name, вернуть origin | `main.rs` ECH witness resolve (`resolve_ech_config`/`r2o_discovery_ech_witness`), `R2oEchChallengeCache` | **P** | **Совпадает:** public_name == target, challenge-карантин, real/allow_chal, отказ bad. **Отличия:** Rust не хранит RR-кэш и resolved public_name; проверка/выбор свидетеля разнесены по discovery. ECH differentials частичные. |
| `ech_witness_untried` | 7118–7128 | 11 | есть не-bad witness с known!=0 и не в карантине | `main.rs` ECH witness list/challenge | **P*** | Rust проверяет кандидатов через resolve/challenge; отдельной функции нет. |
| `ech_witness_reject` | 7130–7136 | 7 | пометить bad и добавить origin в карантин | `R2oEchChallengeCache::record`, `main.rs:29135+` | **P*** | Карантин есть; C-флаг `ech_bad[]` в задаче, Rust-состояние иное. |
| `ech_witness_add` | 7140–7150 | 11 | пропуск self/дублей/лимита; если RR known==0 — не добавлять | `main.rs` ECH witness candidates | **P*** | Логика кандидатов разнесена; RR-кэша нет. |
| `start_search` | 7152–7328 | 177 | fill_hellos; resource path; ECH offer; witness-лестница (RR/bindings/seen); family recovery; rx_volume_only; own_first; JOB_CLASSIFY | `main.rs` discovery start/enqueue (`:10388+`, `:12879-13120`), `r2o_discovery_trigger`, `own_first_plans` | **P** | **Совпадает:** fill/hello, resource path, ECH candidates, family recovery, own_first, CLASSIFY. **Отличия:** C-порядок witness-лестницы (RR→bindings→same addr→bindings sorted→any addr) и `rx_volume_only`/`shape_armed`/`addr_recheck` в Rust разнесены; T_SHAPE_WAIT/очередь иные. discovery/ECH/own-first differentials частичные. |
| `box_id_for` | 7332–7413 | 82 | box_id из задачи/единственного fp-match/«box-без-приметы»/FNV(fp+text) с солью при clash | `catalog.rs` box id/`discovery.rs:1020` (C-оракул), `add_measured_binding_with_fingerprint` | **P** | **Совпадает:** один совместимый fp → существующая box; иначе FNV-имя; соль при конфликте; без примет — отдельная запись. Rust-функция вынесена в catalog/measured binding, полного C/Rust differential нет. |
| `voice_trial_send` | 7424–7444 | 21 | stamp plan id, hex, SET_ADDR_PROBE (transport 17, family 4, client sport 0, dst, lease), lease_ms | `main.rs:16301-16320 encode_r2o_voice_trial`, `voice_discovery.rs:20 r2o_voice_arm_plan` | **E** | `test-discord-voice-discovery-arm/lifecycle`; trial/lease/dst/client-address совпадают. |
| `voice_ip_fmt` | 7446–7449 | 4 | IPv4 → текст, fallback «?» | `std::net::Ipv4Addr Display` | **P*** | Fallback «?» в Rust не выражен; для валидного IPv4 эквивалентно. |
| `voice_ip_text` | 7450–7453 | 4 | статический буфер IPv4 | `Ipv4Addr Display`/`String` | **P*** | Буфер заменён owned-строкой. |
| `voice_ip_text2` | 7454–7457 | 4 | второй статический буфер | `Ipv4Addr Display`/`String` | **P*** | То же. |
| `voice_trial_owned` | 7461–7464 | 4 | !by_addr, identity valid, client sport 0, dst port != 0 | `voice_discovery.rs` binding address-scoped | **P*** | Rust проверяет address-scoped привязку/trial; отдельной функции нет. |
| `voice_trial_same_context` | 7469–7479 | 11 | family 4; (dst IP/port + client IP) в любом направлении, client port не сравнивается | `voice_discovery.rs:292 r2o_voice_observed_flow_from_event` | **P** | **Совпадает:** endpoint + client IP, любой client port. Rust flow-событие/сопоставление иное по структуре; voice differentials частичные. |
| `voice_start` | 7481–7510 | 30 | найти known voice discovery prefix (transport 17/family 4/shape VOICE/verified_by DISCOVERY/addr/prefix), сбросить планы, T_VOICE_MEASURE, JOB_VOICE | `voice_discovery.rs:26 r2o_voice_discovery_prefix_from_plan_text`, `main.rs:9801 R2oVoiceDiscoveryWorker` | **E** | `r2o-discord-discovery-differential.sh`; условия привязки/prefix и запуск worker совпадают. |
| `voice_finish_measure` | 7512–7609 | 98 | join; verdict != BLOCKED → report/fail; flow match/marked/arm/copies; arm→plan; trial id; SET_ADDR_PROBE на следующий поток; probes; T_VOICE_TRIAL | `main.rs:16383 confirm_r2o_voice_trial`, `voice_discovery.rs:728 evaluate_r2o_discovery`, `:39 save_confirmed_voice_binding` | **P** | **Совпадает:** BLOCKED-only, flow match, marked/arm/copies, plan→addr probe, client sport 0, lease, probes. **Отличия:** C `voice_res`/task-поля и Rust `R2oVoiceTrialContext`/evaluate разнесены; voice lifecycle differential частичный. |
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
| `on_suspect` | 8181–8592 | 412 | главный вход: счёт событий, last_suspect, recall имени, Telegram/decoy/clean-handshake, dead address, cooldown, voice pending, binding_covering, fp_add, T_QUEUED/WATCHING/voice-переходы, trigger shape/flow, launch_or_queue | `main.rs:20090 ControlClient::r2o_queue_tcp_suspect`, `:13534 R2oDiscoveryQueue::queue_after_fresh_suspect`, `:8509 cooldown`, `:8305 dead` | **E** | `r2o-scheduler-differential.sh`, cooldown/dead-address/queue-order/coalesce. **Отличия слоя:** C `recall` по точному flow; Rust очередь ключуется target-ом и хранит recent client shape/ECH отдельно; voice pending/T_WATCHING выражены иначе. |
| `quic_own_initial` | 8607–8621 | 15 | вернуть свой QUIC Initial: задача `snap` или общий `quic_shape` того же имени/family + seq | `main.rs` pending QUIC snapshot/task (`:6880-6975`, `:7024-7090`) | **P*** | Rust хранит снимок в pending-job/задаче (`snapshot`/`pending_snapshots`), общего `quic_shape[name/family]` с seq нет. Эквивалент по источнику, не по API. |
| `remeasure_snapped` | 8623–8682 | 60 | report superseded; заменить trig байтами, opts, сбросить snap/reasked/researched/family_fast/own_first/seed/plans/tried/RX/ECH/own_seen, launch | `main.rs:8894-8940 r2o_adopt_own_first_client_snapshot`, `:13427 remember_client_snapshot`, pending rechecks (`:9400-9460`) | **P** | **Совпадает:** новый поиск с байтами клиента, сброс кандидатов/счётчиков, один перемер. **Отличия:** C сбрасывает `snap_*`, `seed`, `rx_hashes`, `own_seen`, `ech_grease` в задаче; Rust использует `client_hellos`/`pending_rechecks`/`recent_client_shapes`, набор сбросов иной. |
| `quic_note_multi` | 8690–8730 | 41 | запомнить multi-datagram имя/family в кольце; split-привязки → recheck_since + DEL_NAME | нет кольца `quic_multi`; `r2o_quic_initial_client_hello_from_datagrams` только собирает CH | **P** | **Подтверждённый пробел:** Rust не помнит «клиент multi» по имени/family и не помечает split-привязки к recheck при обрывке Initial. `r2o_quic_split_unfit`/`quic_client_multi` отсутствуют. |
| `on_shape` | 8732–9008 | 277 | TCP: целый ClientHello, opts wait→shape, ECH input; QUIC: QSN/снипок, named ring, multi-note; сохранить общий shape; подменить/перезапустить задачу, T_SHAPE_WAIT, remeasure | `main.rs:9390-9460 r2o_handle_client_shape_event`, `:13427 remember_client_snapshot`, `queued_quic_snapshots` | **P** | **Совпадает:** проверка целого CH, сохранение recent shape, ECH input, QUIC snapshot, перезапуск T_ASKING, T_SHAPE_WAIT. **Подтверждённые отличия:** Rust не хранит сырые TCP options (только `tcp_has_timestamp`), нет `quic_named` ring/10-мин reuse и `quic_multi` note; `ech_inputs` заменены `ech_input_names`/recent shapes. Вся матрица состояний не сравнивалась. |
| `group_record` | 9013–9032 | 20 | записать observation группы: name/plan/key/evidence/at; `d2k_group_learn`, revision/sync | `groups.rs`/`main.rs` group learn | **P** | Rust `d2k_group_learn`/groups-слой есть; C/Rust differential нет, поля/дедуп не сверены. |
| `record_shape` | 9035–9040 | 6 | QUIC→QUIC; ECH→ECH_TCP; иначе LEGACY или MODERN | `main.rs` discovery record shape | **P*** | Rust форма привязки выводится из target/plan; отдельной функции нет. |
| `budget_uncountable_note` | 9043–9050 | 8 | однократно сообщить, что бюджет не считается (UDP/TCP_INFO) | `main.rs` budget note/`r2o_volume_observation` | **P*** | Rust-поле/текст бюджета есть; однократность и точный текст не сверены. |
| `budget_cut_reject` | 9072–9151 | 80 | при обрыве бюджета: не подтверждать, пометить привязки budget=CUT, сохранить лучший partial (pk/succ/text), volume_block → partial_finish, иначе fallback | `main.rs` budget/layered-rx (`:15000+`), `apply_discovery_outcome` | **P** | **Совпадает:** budget=CUT, partial best, volume-block отдельно, fallback. **Отличия:** C `partial_*`/`budget_note`/`budget_src` в задаче; Rust `DiscoveryOutcome`/volume observation и поля бюджета иные. budget/layered-rx differentials частичные. |
| `say_question_trace` | 9159–9168 | 10 | печать qtrace: label, answered/sent, outcome UNKNOWN/YES/NO | `main.rs` discovery qtrace log | **P*** | Rust печатает трассу иначе; дословный формат не сверялся. |
| `ladder_candidate_at` | 9175–9184 | 10 | план по индексу — кандидат RX-лестницы: net_probe_name или hash в rx_hashes | `main.rs` next_rx/measured split | **P*** | Rust не хранит `net_probe_name[]`/`rx_hashes[]` в задаче; принадлежность лестнице выражена иначе. |
| `ladder_candidate` | 9185–9187 | 3 | текущий next_plan — лестница | `main.rs` next_rx/measured split | **P*** | Тонкая обёртка; отдельного аналога нет. |
| `candidate_path` | 9189–9200 | 12 | источник: свой план/приём замера/RX-лестница/перебор/вывод | `main.rs` discovery candidate path | **P*** | Rust-атрибуция `arm_hash/arm_path`/`rx_hashes`/`fb_queue` не найдена в том же виде. |
| `search_report` | 9207–9260 | 54 | закрыть report; path=own-plan/ladder/fallback/property; protocol tcp/stun/discovery/udp/quic; diagnostic event id/target/family/trigger/outcome/reason/elapsed/queue/probe_units/ip/path/kind/shape; строка `итог поиска` | `main.rs` r2o_discovery_diagnostic_event, `diagnostics::Recorder`, `:16803-16806` | **P** | **Совпадает:** id/target/protocol/outcome/path/elapsed/queue/probe_units/ip/kind/shape. **Отличия:** C `probes+ask_probes`, `report_queue_ms`; Rust diagnostics fields и `last_measurement`/worker counters частично не заполняются. `r2o-diagnostics-differential.sh` проверяет event_json частично. |
| `verify_confirm` | 9262–9653 | 392 | подтвердить кандидата: budget/лестница (9268–9285), bound-plan (9286–9298), QUIC ECH replay (9299–9304), ECH replay/application (9305–9318), name_ok только диагностика (9330–9334), split-unfit (9335–9345), `unfit_here` (9346–9365), bind_confirmed (9366–9427), группа (9431), ech_origin (9435), budget-mark (9453–9474), measure_path (9475), by_addr permanent (9489), net-whitelist (9514), отчёты/бюджет (9537–9573), report (9616), T_WATCHING (9621), yield T_ASKING (9622–9636), sync_pending (9643), remeasure snapshot (9648–9652) | `main.rs:5347 r2o_confirm_discovery_outcome`, `:21856 apply_discovery_outcome`, `:5321 r2o_family_recovery_decision`, `:21518 r2o_install_quic_candidate`, `:15322 r2o_discovery_ech_replay_required`, `:14628 r2o_discovery_volume_recovery` | **P** | **Совпадает:** полный HTTPS-ответ + APPLIED, ECH accepted/peer_name/complete/application, CF/Blocked/LegalDenial, QUIC/ECH addr-binding, ECH replay, volume recovery, budget CUT/PASSED логи. **Подтверждённые пробелы:** (1) `unfit_here` по `t->unfit_plan_id[]` перед подтверждением (9346–9365) в Rust не найден — FLOW_UNFIT обрабатывается после события (`main.rs:19097-19169`); (2) `yield_to_own_plan` — остановка чужих `T_ASKING` при появлении своего подтверждённого плана (9622–9636) в Rust не найдена; (3) `bd->budget` PASSED/UNCHECKED/CUT в `apply_discovery_outcome` не выставляется, хотя константы `R2O_D2K_CAT_BUDGET_*` есть; (4) `tcp_profile` отсутствует в `Binding` (header #16); (5) `group_record(BLOCKED_CONFIRMED)` прямого вызова в `apply_discovery_outcome` не найдено; (6) `measure_path` для name-binding и `net_whitelist` name/tx_only/searched не сопоставлены один-в-один. |
| `partial_finish` | 9668–9689 | 22 | взять лучший partial: заменить plan/box/ver, `partial_finishing=1`, `verify_confirm`, сброс флага, `cooldown_record(kind 2)` + 10 мин | `main.rs:3299 r2o_discovery_mark_partial_rx_inconclusive`, `:7340 R2O_DISCOVERY_INCOMPLETE_RETRY`, budget/layered-rx, `apply_discovery_outcome` | **P** | **Подтверждённое расхождение срока:** C `cooldown_record(kind 2)` ставит `until_ms = now + SCHED_INCOMPLETE_BACKOFF_MS`, где `SCHED_INCOMPLETE_BACKOFF_MS = 10 * 60 * 1000` (`sched.c:165,2077-2088`), и печатает «не раньше чем через 10 мин». Rust для partial/incomplete использует `R2O_DISCOVERY_INCOMPLETE_RETRY = 15 секунд` (`main.rs:7340`, `:3329`, `:11421`, `:11830`), то есть повтор идёт в 40 раз раньше. **Также отличаются:** C хранит `partial_text/box/ver`, `partial_finishing` (влияет на гейты `verify_confirm`), Rust — `DiscoveryOutcome`/`volume_recovery` без этих полей. Совпадает: выбор лучшего partial, подтверждение через общий путь, пометка бюджета «оборван». |
| `plan_id_is_ours` | 9691–9696 | 6 | все нули → 0; иначе memcmp с `ver_plan_id` | `main.rs:22313 r2o_ask_applied_matches`, `:6474 r2o_family_applied_flow_matches`, `:10302 applied_quic_trial_matches` | **P** | **Подтверждённое расхождение:** C безусловно отвергает нулевой `plan_id` (три «нет идентификатора»), даже если `ver_plan_id` тоже нулевой. Rust сравнивает `event.plan_id == plan_id`; при ожидаемом нулевом id и нулевом событии проверка проходит (при остальных совпадениях). В штатных discovery-путях plan_id ненулевой, но контракт различается. |
| `applied_trial_is_ours` | 9700–9705 | 6 | `trial_id` непустой и совпадает с trial кандидата (`SET_NAME_PROBE`/`SET_ADDR_PROBE`) | `main.rs:22313 r2o_ask_applied_matches`, `:6474 r2o_family_applied_flow_matches`, `:10302 applied_quic_trial_matches` | **P** | **Подтверждённое расхождение:** C требует хотя бы один ненулевой байт `trial_id` И `candidate_trial_matches`; Rust проверяет только равенство `event.trial_id == trial_id`. В family-recovery ожидается `[0;16]`, поэтому нулевой trial события не отвергается явно; в ask/QUIC trial ненулевой. C/Rust differential на нулевой id нет. |
| `applied_of_candidate` | 9708–9723 | 16 | APPLIED относится к кандидату: family/transport/plan/addr trial и endpoint | `main.rs:6474 r2o_family_applied_flow_matches`, `:10302 applied_quic_trial_matches`, `:22313 r2o_ask_applied_matches` | **P** | **Совпадает:** family/transport, plan_id, trial_id, локальный/серверный адрес и порт. **Отличия:** C отдельно различает name/addr trial (`SET_NAME_PROBE`/`SET_ADDR_PROBE`); Rust проверяет конкретную пару ключа и endpoint, но не тип trial. Нулевые plan/trial см. выше. `r2o-ack-applied-persist-differential.sh` покрывает часть цепочки. |
| `on_applied` | 9739–9857 | 119 | APPLIED: voice trial→watch, props early/applied, verify early, verify_wait ok | `main.rs:15752 observe_applied`, `:20292 remember_applied_event`, `:10160 r2o_voice_applied_flow_matches`, `:22313 r2o_ask_applied_matches`, `:5661 r2o_collect_controller_applied_events_until` | **P** | **Подтверждено в Rust:** voice-ветвь (`r2o_voice_applied_flow_matches`: trial_id, transport 17, plan id, точная convo-пятёрка) и переход `voice_flow_key` (`main.rs:19066-19074`); verify/family — сбор APPLIED по key/plan/trial (`r2o_collect_controller_applied_events_until`, `r2o_ask_applied_matches`); общее кольцо `pending_applied_events` до 256 (`remember_applied_event`). **Подтверждённые отличия:** (1) C для `T_PROPS_CONTACT` копит ранние APPLIED в `prop_early[]` по plan_id и затем в `T_PROPS_WAIT` при `prop_reply_seen` вызывает `on_exchange` (`sched.c:9787-9822`); в production-discovery Rust control-опрос свойств не выполняется, а CLI `--ask` использует `wait_for_ask_proof` без этого per-task кольца; (2) C различает `T_VERIFY`/`T_TRIAL_SETTLE` (раннее кольцо `ver_early[]`) и `T_VERIFY_WAIT` (`ver_ok`), Rust — общий сбор событий и `applied`-флаг без отдельного состояния; (3) `r2o-ack-applied-persist-differential.sh` проверяет персистентность/ACCEPT, а не все пять ветвей C. |
| `on_refused_foreign` | 9900–9939 | 40 | постоянный отказ на чужом потоке: `unfit_client++`, recall имени, план в `t->unfit_plan_id[]` до 8, лог один раз на имя | `main.rs:19091-19170` (`record_client_unfit`/`r2o_catalog_mark_flow_unfit`, `flow_unfit_done`) | **P** | **Совпадает:** постоянный отказ считается и называется, каталог не трогается, поиск по имени не запускается. **Отличия:** C пишет план в per-task `unfit_plan_id[]`, который читает `verify_confirm` (pre-confirm гейт); Rust ведёт `flow_unfit_done`/`r2o_catalog_mark_flow_unfit` и **не имеет** pre-confirm проверки списка (см. `verify_confirm`). |
| `on_refused_unfit` | 9960–10051 | 92 | NOT_APPLIED/FLOW_UNFIT: пометить name-привязки (name/transport/family/profile) `recheck_since`, при необходимости снять с провода, `unfit_done` ring, запустить повторный замер | `main.rs:19097-19170` (`r2o_catalog_mark_flow_unfit`, `flow_unfit_done`, queue) | **P** | **Совпадает:** mark recheck, повторный замер, защита от повторов по plan_id, профиль. **Подтверждённые отличия:** (1) C фильтрует привязки по `tcp_profile` (`sched.c:10000`) и хранит `tcp_profile` в ключе `unfit_done` (`9967-10045`); Rust `r2o_catalog_mark_flow_unfit` (`main.rs:2951-2999`) не читает `binding.tcp_profile`, а `R2oFlowUnfitDone` (`:9309-9340`) не содержит профиля. Поэтому Rust может пометить привязку другого TCP-профиля и подавить повторный замер пары «цель+план» без учёта профиля; (2) C при необходимости снимает план с провода (`d2k_link_del_name_family`) внутри, Rust — проходом каталога. |
| `on_refused` | 10053–10157 | 105 | маршрутизация REFUSED: PROPS_WAIT по flow+plan; VERIFY/TRIAL_SETTLE early; VERIFY_WAIT по flow+plan; FLOW_UNFIT → on_refused_unfit; постоянный → group PLAN_FAILED (если нет own exact); NOT_APPLIED → on_refused_unfit; иначе foreign | `main.rs:15752 observe_refused`, `:19070-19178` | **P** | **Подтверждённый пробел:** C для постоянного отказа ищет группу по transport/family/shape/suffix/plan, проверяет `own_exact_confirmed`, пишет `D2K_GROUP_PLAN_FAILED` через `d2k_group_learn`, увеличивает `revision`/`sync_pending` и ставит подозрение (`sched.c:10113-10148`). Rust `EVENT_REFUSED` (`main.rs:19086-19178`) обрабатывает только `TOO_LONG|NOT_APPLIED` (`record_client_unfit`) и `FLOW_UNFIT` (`r2o_catalog_mark_flow_unfit`/очередь); группового `PLAN_FAILED` и `own_exact_confirmed` в этой ветке нет. `has_covering_binding` проверяет покрытие, но не заменяет запись провала группы. `r2o-scheduler-differential.sh` покрывает часть маршрутизации, не эту ветку. |
| `note_clean_handshake` | 10176–10199 | 24 | кольцо 16 слотов: name/transport/family/client_ip, обновление seen_ms, TTL 60 с | `main.rs:7689-7711 R2oCleanHandshakeCache::note` | **P** | **Подтверждённое расхождение ключа:** C ищет/создаёт слот по `transport + family + client_ip + name` (`sched.c:10184-10186`), то есть запись привязана к LAN-клиенту. Rust `entries: VecDeque<(String, u8 family, Instant)>` (`main.rs:7690-7711`) хранит только `name + family`, без client_ip и transport. Ёмкость 16 и TTL 60 с совпадают (`SCHED_CLEAN_HS_SLOTS=16`, `SCHED_CLEAN_HS_MS=60000`; `R2O_CLEAN_HANDSHAKE_CAPACITY=16`, `R2O_CLEAN_HANDSHAKE_TTL=60s`). |
| `clean_handshake_recent` | 10202–10215 | 14 | есть ли свежее чистое рукопожатие этого клиента/имени: transport/family/client_ip/name, TTL 60 с | `main.rs:7713-7729 r2o_recent` / `suppresses_unplanned_tcp_suspicion` | **P** | **Подтверждённое расхождение:** C проверяет точный `client_ip` и `transport` вместе с name/family (`sched.c:10208-10211`); Rust `r2o_recent(name, family, now)` сравнивает только name+family. Поэтому Rust подавляет неплановое подозрение по имени/семейству, даже если чистое рукопожатие было у другого LAN-клиента. TTL 60 с и ёмкость 16 совпадают. |
| `on_exchange` | 10217–10323 | 107 | clean handshake без плана; voice proof; props early/reply/pass → vector+verdict_to_plans; outer appdata — только наблюдение, не подтверждение | `main.rs:19180-19186` clean handshake, `:17983` VOICE_PROOF, `:18118 r2o_take_silent_voice_trial`, `:10192` voice trial, CLI `wait_for_ask_proof` | **P** | **Совпадает:** clean handshake без плана (`note_clean_handshake` ↔ `EVENT_R2O_TCP_CLEAN_HANDSHAKE` + `R2oCleanHandshakeCache::note`); voice proof (`D2K_UDP_PROOF_VOICE_DISCOVERY`/`STUN` ↔ `EVENT_R2O_VOICE_*_PROOF`, `r2o_take_silent_voice_trial`); outer appdata не создаёт привязку. **Подтверждённые отличия:** (1) C `T_PROPS_CONTACT` копит `prop_early_x[]` по местному порту, а `T_PROPS_WAIT` при `server_hello` сохраняет `prop_reply` до APPLIED, затем `d2k_props_question_passed` + `question_retire` + `verdict_to_plans` (`sched.c:10246-10299`); в production-discovery Rust control-опрос не выполняется, а CLI `--ask` идёт через `wait_for_ask_proof` без per-task колец; (2) C `d2k_ev_outer_appdata` снижает подтверждённую `T_WATCHING` задачу (`task_done`) после лога; в Rust grep `outer_appdata` пуст, отдельного обработчика/эквивалента не найдено; (3) voice-коды/состояния Rust выражены `R2oVoiceTrialContext`, а не `voice_answered/voice_proven` в `task`. |
| `d2k_sched_event` | 10325–10457 | 133 | диспетчер: HELLO→remember; ACK области/SET/DEL/пробы/voice; SUSPECT; STATS; SHAPE; CLIENT_TCP; APPLIED; REFUSED; EXCHANGE | `main.rs` ControlClient::watch_events + note_datapath_event | **E** | `r2o-control-events/ack-applied/scheduler` differentials; **отличия:** C area/trial ACK разбирает в одном месте, Rust — `CatalogSyncCursor`/`ControlClient`. |
| `own_first_continue` | 10465–10523 | 59 | join/retire; own_probed→tried; seed_use=1, own_first=3; новый срок; сброс plans/box/rx/ask; сохранить `vol` при `skip_volume_once && rx_cut`; взять снимок; start_search | `main.rs` own-first continue, `cached_volume_cut` (`:11025,11217,11354`) | **P** | **Совпадает:** сброс фазы, tried, снимок, новый срок. **Отличия:** C `skip_volume_once`/`rx_cut` сохраняет `t->vol`; Rust использует `cached_volume_cut`/volume cache, поля и условия иные. |
| `rx_saved_bootstrap` | 10528–10572 | 45 | выбрать лучшую MODERN name-binding (exact family приоритет, binding_beats), поставить один план, `rx_bootstrap_only`, family note | `main.rs` layered-rx/own-first (`:14628+`, `:10916+`) | **P** | **Совпадает:** только MODERN/TCP, name-binding level 3, точное семейство приоритетнее, binding_beats. **Отличия:** C `plan_boxes`/`n_known`/`rx_bootstrap_only`; Rust layered-rx outcome/`R2oDiscoveryVolume` иной. |
| `layered_rx_result` | 10574–10652 | 79 | identity-1 → identity-2 (framing/delta≤4 КБ) → gzip-контроль; evidence; own_first==2 не подтверждать; иначе verdict_to_plans; 500 мс | `main.rs` layered-rx (`:14628+`), `r2o_volume` | **E** | `r2o-layered-rx-differential.sh`; условия phase/partial/gzip/evidence и повтор на новом порту совпадают. |
| `queued_before` | 10658–10662 | 5 | hot_event desc, queued_event asc, queued_ms asc | `main.rs` queue order (`Reverse(hot_event), queued_event`) | **E*** | `r2o-queue-order-differential.sh`; порядок совпадает. |
| `quic_yield_tick` | 10666–10701 | 36 | TCP ждёт и слот занят → QUIC CLASSIFY паркуется; resume при освобождении/смене turn; перенос wait; start-gap | `main.rs:12140 r2o_quic_yield_waiting_for_tcp`, queue/worker gate | **E** | `r2o-scheduler-concurrent-endpoint/queue`; park/resume и wait-перенос совпадают. |
| `queued_pick` | 10703–10726 | 24 | parked QUIC → TCP первым; family recovery приоритет; иначе queued_before | `main.rs` queue pick/family queue | **E** | `r2o-queue-order/family-queue` differentials. |
| `queued_release` | 10728–10754 | 27 | нет места/start-gap → 0; queued_pick; last_measure_start; лог; launch; measure_started | `main.rs` queue release/worker permit | **E** | `r2o-queue-order/worker-permit` differentials. |
| `voice_pending_dispatch` | 10756–10782 | 27 | отложенное voice-подозрение: ждать trial/watch/grace 2 мин, снять/дождаться, task_done, event_sequence++, on_suspect(replayed) | `main.rs` voice pending dispatch (`:10155+`, `:18149+`) | **P** | **Совпадает:** pending endpoint, grace/снятие опыта, повторный on_suspect. **Отличия:** C `pending_voice_suspect`/`voice_pending_dispatch`; Rust `pending_voice_suspect_valid`/`R2oVoiceTrialContext` и очередь, grace-константы иные. |
| `d2k_sched_tick` | 10784–12364 | 1581 | главный тик: clock/admission (10793–10807), `res_sample`+limit (10809), wake drain (10812), yield/deny (10817–10818), group expiry 7 сут (10822–10830), sync/area retry (10831–10837); T_QUEUED (10844–10865), T_RESTING (10867), lifetime/SHAPE_WAIT/WATCHING/own_first=2/voice/ASKING (10872–10944), VOICE_MEASURE/WATCH/TRIAL (10946–10991), T_ASKING (10994–11528), PROPS_CONTACT (11530–11605), PROPS_WAIT (11607–11634), VERIFY (11636–11992), VERIFY_WAIT (11994–12042), TRIAL_SETTLE (12044–12061), PLANNING (12063–12358), queue release/voice (12360–12363) | `main.rs:7971 R2oDiscoverySearches`, `:12071` worker loop, `:12140` QUIC yield, `r2o_resource_limit`, `r2o_route`, `groups.rs`, `live.rs` | **P** | **Построчно прочитаны все блоки.** Совпадает: clock/admission, res_sample/AIMD, wake/queue, group expiry, sync, T_QUEUED/RESTING, lifetime, voice measure/watch/trial, T_ASKING (yield/addr/ECH/base/family/resources/RX/snap/own-first/known/props/verdict), PROPS_CONTACT/WAIT, VERIFY/VERIFY_WAIT, TRIAL_SETTLE, PLANNING (own-first/family/budget/known/research/net-whitelist/fallback). **Подтверждённые пробелы:** (1) `yield_to_own_plan` (C 11007–11028) — остановка/переход чужих `T_ASKING` при подтверждённом своём плане; в Rust не найдено; (2) `T_WATCHING` как отдельной фазы нет — C lifetime/WATCHING-переходы (10881–10885, 8948–8992) разнесены; (3) `shape_misses` не инкрементируется (см. `d2k_plantab_shape_misses`); (4) `worker_start_failures`/`last_measurement_age_ms` в диагностике не заполняются; (5) `tcp_profile`/сырые TCP options отсутствуют в `Binding`/задаче; (6) полная матрица ECH+volume/addr+voice/QUIC-deny и точные тайминги `T_TRIAL_SETTLE`/`VERIFY_WAIT` не доказаны. |

### `core/verdict.c`

**Прочитано построчно: 7/7 функций, 342 строки C (1–342).** Сверено с `classify.rs` (`measure` `:1082-1240`, `run_with_backend_progress` `:1298+`, `finish_cancelled` `:1952`) и `main.rs:1177-1178` (`full_detect_semantics=true, confirm_clear=false`); полного C/Rust differential дерева нет.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `looks_like_tls` | 33–35 | 3 | `bytes[0] == 0x16` → ServerHello, иначе Any | — | **N** | **Уточнение 2026-11-12:** это static-правило `core/verdict.c`, а не detect-триггер. R2O не портировал core-вердикт (`d2k_classify_cancelable` имеет только тестовый вызов), поэтому отдельной реализации нет. Detect-триггер `Trigger::raw_hex` обязан оставаться `Accept::Any` по `detect/trigger.c:106`; прежняя правка ошибочно применила правило `looks_like_tls` к detect-пути. |
| `reverse_note` | 53–62 | 10 | MODERN → "", LEGACY → «обратное направление не проверено», UNKNOWN → «вид не разобран…» | `classify.rs` CLEAR/`probe_response` | **P*** | **Подтверждённое расхождение:** C добавляет оговорку к CLEAR по `d2k_hello_shape` (LEGACY/UNKNOWN); Rust по форме приветствия оговорку не строит — при наличии SNI запускает `probe_response` и может вернуть `Response`, иначе при `Accept::ServerHello` добавляет «(ответное направление не проверено: нет SNI)». Текст C «форма TLS 1.2 — обратное направление не проверено» не воспроизводится. |
| `pause_note` | 74–80 | 7 | `gap_us==0` → «без пауз», иначе «с паузой N мкс»; буфер 96 | classify.rs reason | **P*** | C `snprintf` в 96 байт; Rust `String` без обрезки. Текст и границы не сравнивались. |
| `stop_requested` | 92–94 | 3 | `stop && *stop` (volatile sig_atomic) | `AtomicBool::load`/cancel (`classify.rs:1041`) | **P*** | C указатель может быть NULL; Rust `Option<&AtomicBool>`/cancel-флаг. Эквивалентно. |
| `classify_cancelled` | 96–102 | 7 | verdict=INCONCLUSIVE, `marked=(mark!=0)&&all_marked`, reason «профильный замер отменён…» | `finish_cancelled` (`classify.rs:1952`) | **P** | C текст и явный `marked`; Rust ставит Inconclusive и reason «замер брошен по требованию остановки на N-м зонде…», `finish` не выставляет `marked` в этой функции. C-путь не production (только test_verdict.c). |
| `d2k_classify_cancelable` | 104–334 | 231 | дерево: guard len<2 → FLAKY; база; `err==repeats` → UNREACHABLE; частичный pass → FLAKY; полный → confirm 2 → CLEAR/INCONCLUSIVE; иначе разрез 1 → PREFIX/FLAKY/контроль → OPAQUE/INCONCLUSIVE; метка по AND | `run_with_backend_progress` (`classify.rs:1298`) + `measure`/`finish` | **P** | **Совпадает:** guard len<2 → Flaky (текст иной), база, `errors==repeats` → Unreachable, частичный pass → Flaky, confirm 2 → Clear/Inconclusive, разрез 1 → Flaky, AND-метка. **Подтверждённые отличия/расширения R2O:** (1) CLI `--classify` ставит `full_detect_semantics=true, confirm_clear=false` (`main.rs:1177-1178`) — удвоенное подтверждение CLEAR пропускается, добавлен dial-timeout-retry и разделение timeout→Flaky/иное→Unreachable; (2) при CLEAR с SNI Rust делает `probe_response` и может вернуть `Response`, C только текстовую оговорку; (3) после успешного разреза 1 C сразу даёт `PREFIX` split=1, Rust измеряет long-gap, последний байт и бинарный поиск → `WholePacket`/`Prefix` с boundary; (4) при прошедшем контроле C даёт `OPAQUE`/`INCONCLUSIVE`, Rust сначала делает raw-sweep (`Poisonable`) и `neutral_ack` (`Address`); (5) `one.error` оставляет default `Flaky` с другим текстом, C даёт FLAKY с «N из M не состоялись». Полного C/Rust differential дерева нет. |
| `d2k_classify` | 336–342 | 7 | обёртка `d2k_classify_cancelable(..., stop=NULL)` | `classify::run` (`:1929`) | **P** | C-обёртка без отмены; Rust `run` → `run_with_backend(TcpProbeBackend)`. C-путь production-вызовов не имеет. |

### `core/x25519.c`

**Прочитано построчно: 12/12 функций, 198 строк C (1–198).** Сверено с `r2o_tls.rs:92-103` (ring `X25519` в TLS12/TLS13), `ech.rs:9,80-137` (`X25519HkdfSha256`), `quic.rs`/`quic_replay.rs` (X25519 key_share); прямых C/Rust-векторов X25519 и теста low-order точки нет.

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
| `d2k_resource_word` | 27–35 | 9 | равная длина; lower-case `s[i]`; сравнение с `word[i]` без lower | `r2o_resource.rs:407-413 r2o_resource_word` | **P*** | C приводит только haystack; все C-вызовы передают `script/style/body/link/href/rel/stylesheet/.css` в нижнем регистре. Rust `eq_ignore_ascii_case` сворачивает обе стороны; для этих вызовов эквивалентно, при верхнем регистре в `word` C вернул бы 0. Отдельного теста хелпера нет. |
| `d2k_resource_space` | 36–38 | 3 | `' '`, `\t`, `\r`, `\n`, `\f` | `r2o_resource.rs:415-417 r2o_resource_space` | **P*** | Посимвольно совпадает (`b'\x0c'` = `\f`). |
| `d2k_resource_path_ok` | 39–50 | 12 | непустой, `<512`, `/`, не `//`, без `/../` и `/./`, `[A-Za-z0-9/._-]`, кончается `.css` без регистра | `r2o_resource.rs:309-330 r2o_resource_path_ok/path_bytes_ok` | **P** | Ветви совпадают: `n==0 || n>=512`, `path[0]=='/'`, `path[1]!='/'`, `strstr("/../")`/`"/./"` ↔ `windows(4)`/`windows(3)`, allowed-байты, `n>=4`, `.css` через `eq_ignore_ascii_case`. Целевого C/Rust differential нет. |
| `d2k_resource_add` | 51–73 | 23 | `https://`/`//`; первый `/`; `<256`; без ведущей/хвостовой точки; LDH+`.`; lower-case; один ресурс на хост; максимум 2 | `r2o_resource.rs:265-305 r2o_add_url_bytes` | **P*** | Совпадает: strip `https://`/`//`, первый `/`, `r2o_resource_path_bytes_ok`, `host.is_empty()`, `len>=256`, точки, allowed-байты, `to_ascii_lowercase`, dedupe по host, push. C `strcpy` в фиксированные массивы, Rust `String`; C отбрасывает третий ресурс в `add`, Rust останавливает `feed` после двух (`:150-152`). |
| `d2k_resource_tag` | 74–113 | 40 | завершить тег: raw `/script`/`/style`; script/style/body; `link` с одним `href`/`rel=stylesheet`; href <1024 | `r2o_resource.rs:221-259 r2o_finish_tag`, `:332-405 r2o_link_stylesheet_href` | **P*** | Ветви совпадают: `strcspn(" \t\r\n\f/>")` ↔ position по space/`/`/`>`; raw-префиксы case-sensitive; `body` → `seen=32768`; `script/style/link`; парсер атрибутов с `=`, кавычками, отказом при незакрытой кавычке, одним `href`/`rel`, `href<1024`, `stylesheet`. Rust `split(0)` повторяет C-терминацию тега. |
| `d2k_resource_feed` | 114–159 | 46 | лимит 32768; сбор URL по байту `h`; теги/комментарии/кавычки; `>` завершает тег; `url_used>8` перед `add` | `r2o_resource.rs:148-219 R2oResourceScan::{feed,r2o_feed_url}` | **P** | Совпадает: лимит `seen<32768`, буфер тега 2048, комментарий `<!-- -->`, quote, `>` → finish, URL-аккумулятор от `h` с делимитерами `"'();,<>` и space, лимит 600. **Отличие:** Rust прерывает обход при `resources.len()>=2` (`:150-152`), C идёт до 32768, а третий ресурс отбрасывает в `add`; итоговый набор тот же, объём сканирования разный. Целевого C/Rust differential нет. |

**Прочитано построчно:** `include/d2k_link.h` 3/3 (521 строка), `include/d2k_resource.h` 6/6 (160 строк).

## Углублённая сверка: domain/groups/match/net4/verdict/props (37 функций)

| C-функция | строки | R2O-аналог | статус | доказательство / пробел |
|---|---:|---|---|---|
| `d2k_domain_normalize` | 6–29 | `domain.rs:8-58` `normalize` | **P** | **Совпадает:** одна хвостовая точка, длина 1..253 после снятия, lower-case, метка 1..63, запрет ведущего/хвостового дефиса и пустых меток, только `a-z0-9-`, обязательный нецифровой символ. **Отличие:** C принимает односоставное нечисловое имя (`localhost`), Rust требует ≥2 метки (`domain.rs:51-54`). Для `d2k_domain_base/member` не проявляется (там нужен известный PSL-суффикс). Тесты `tests/domain.rs:3-22`; C/Rust differential нет. |
| `rule_exists` (static) | 31–40 | `domain.rs:63-69` `psl::suffix/domain` | **P*** | C — бинарный поиск по сгенерированному `d2k_psl_blob` (`psl_index.h:1-2`, source SHA256 `257b298d…`); Rust — crate `psl`. Совпадение снимков PSL не доказано; отдельного differential нет. |
| `d2k_domain_base` | 42–64 | `domain.rs:61-71` `registrable_domain` | **P** | Логика совпадает: longest rule, exception снимает один уровень (`exception_count-1`), wildcard `*.suffix`, неизвестный TLD → отказ, результат — `suffix_count+1` меток. Rust — `psl::suffix` + `is_known` + `psl::domain`. Тесты `tests/domain.rs:24-43` (private wildcard `googlevideo.com`, `co.uk`, `blogspot.com`, exception `city.kawasaki.jp`, неизвестный TLD). C/Rust differential на PSL-набор не найден. |
| `d2k_domain_member` | 66–72 | `domain.rs:74-86` `is_member` | **P** | C нормализует name и suffix, требует успешный `d2k_domain_base(s)` и проверяет границу метки; Rust — `normalize` обоих, `registrable_domain(suffix)`, равенство или `prefix.ends_with('.')`. Тесты `tests/domain.rs:45-52` (`badexample.co.uk` и `co.uk` отвергнуты). Зависит от совпадения PSL. |
| `d2k_group_key_make` | 9–17 | `catalog::GroupKey` + `validate_key` (`groups.rs:424-441`) | **P** | C проверяет только `strlen(path)<256` и `strlen(origin)<256`, обнуляет ключ и копирует; transport/family/shape/evidence проверяются позже в `valid()`. В R2O отдельного конструктора нет: `validate_key` вызывается в `learn`/`restore` и сразу требует transport 6 + shape 1/2/6/8..13 или 17/3, family 4/6, path/origin ≤255 без NUL. Для штатных вызовов результат тот же; прямой контракт различается. |
| `d2k_group_key_same` | 19–23 | `catalog.rs:199-206` derived `PartialEq for GroupKey` | **E** | C сравнивает `transport/family/shape` и обе строки через `strcmp`; Rust — все пять полей производным `PartialEq`. Дедупликация по ключу проверена `tests/groups.rs:116-163`; отдельного differential нет. |
| `valid` (static) | 24–36 | `validate_key` + `canonical_evidence` (`groups.rs:389-441`) | **P** | **Совпадает:** NUL-терминированность name/plan/path/origin, family 4/6, transport 6 с shape 1/2/6/8..13 или transport 17 shape 3, plan_id обязателен для BLOCKED/PLAN_FAILED. **Отличия:** R2O принимает `OPERATOR_REJECT=32` (база 1/4/5) и base-evidence `BLOCKED\|PLAN_FAILED=5`, C `valid` пропускает только точные 1/2/4/8; Rust также проверяет name≤255 и plan_id≤39. Наблюдение с 5 C отвергнет, Rust примет. |
| `member` (static) | 38–41 | `groups.rs:443-448` `member` | **E** | Формула `name==suffix` или `prefix.ends_with('.')` совпадает; используется в тестах `tests/groups.rs:116-163` (исключение `clean.googlevideo.com` не ломает группу). |
| `votes` (static) | 45–60 | `groups.rs:484-512` `votes` + `:514-529` `latest_vote` | **P** | Правило `live>=2 && live>stale && live+stale>=3`, stale при PLAN_FAILED/DIRECT_CLEAR, ранний отказ при DIRECT_CLEAR без ADMITTED_EXCEPTION, `latest` только по live-голосам — совпадают. Rust считает latest отдельным проходом после `votes` (`rebuild` `:346-349`). C-oracle нет; тесты `tests/groups.rs` покрывают базовые 3 голоса и исключения, не все соотношения live/stale. |
| `failures` (static) | 61–71 | `groups.rs:531-542` `failures` | **P*** | План/ключ/суффикс/PLAN_FAILED совпадают. Тесты `tests/groups.rs:166-234` проверяют независимое сохранение PLAN_FAILED для plan-a и plan-b; отдельного differential нет. |
| `add_group` (static) | 72–102 | `groups.rs:544-594` `add_group` | **P** | Выбор по failures→count→at→plan_id, отказ при покрытии широкой группой того же плана, удаление покрытых узких групп, `frozen` при 64 — совпадают. Rust сохраняет `at` дважды (`:569-570`) — безвредно. Тесты `tests/groups.rs`. |
| `rebuild` (static) | 103–120 | `groups.rs:326-356` `rebuild` | **P** | C `d2k_domain_base` + суффиксы от первого `dot` до длины base, последний `count!=0` побеждает; Rust `registrable_domain` + `labels[start..]`, та же перезапись `best`. Наследует разницу PSL/`normalize`. |
| `cover` (static) | 122–132 | `groups.rs:450-463` `covering_group` | **P*** | `disabled`/overflow → None, иначе longest suffix по ключу; проверено косвенно `tests/groups.rs:142-162` (admitted clear). |
| `d2k_group_learn` | 133–245 | `groups.rs:65-269` `learn` | **P** | **Совпадает:** слот same-plan/any/replace, `changed/frozen`, reclaim expired INCONCLUSIVE→BLOCKED→first INCONCLUSIVE→first BLOCKED, `disabled_at=max`, PLAN_FAILED OR, admitted exception, очистка дублей без PLAN_FAILED, rebuild после не-INCONCLUSIVE. **Подтверждённые отличия:** (1) Rust `OPERATOR_REJECT` — ранний `Ok(false)` для того же name/key, C бита не знает; (2) Rust принимает base-evidence `BLOCKED\|PLAN_FAILED=5`, C `valid` — только 1/2/4/8; (3) при disabled C удаляет только `evidence==BLOCKED`, Rust — любой `evidence & BLOCKED` (шире); (4) C не делает rebuild при вставке INCONCLUSIVE, Rust делает — мутаций наблюдений при INCONCLUSIVE нет, набор групп не меняется. Тесты `tests/groups.rs:116-234`, `:236-257` (private suffix), `:259+` (capacity/re-enable); полного C/Rust differential нет. |
| `d2k_group_restore` | 246–273 | `groups.rs:15-63` `restore` + `canonical_evidence` (`:389-422`) | **P** | **Совпадает:** снятие INCONCLUSIVE с не-INCONCLUSIVE, проверка ADMITTED_EXCEPTION только с DIRECT_CLEAR, BLOCKED снимает DIRECT_CLEAR/PLAN_FAILED, DIRECT_CLEAR+PLAN_FAILED → PLAN_FAILED; normalize/base, `at>=0`, `disabled_at>=0`, дубли по name/key с тем же планом либо без PLAN_FAILED у обоих; rebuild. C проверяет канонический `test`, но сохраняет исходную маску; Rust также возвращает `canonical`, не записывая его. **R2O-расширение:** OPERATOR_REJECT (база BLOCKED/PLAN_FAILED/5). Тесты `tests/groups.rs:9-113`; C/Rust differential нет. |
| `d2k_group_match` | 274–293 | `groups.rs:358-387` `match_domain` | **P** | Исключения DIRECT_CLEAR/PLAN_FAILED того же плана и longest suffix совпадают; **Rust дополнительно исключает OPERATOR_REJECT**. Тесты `tests/groups.rs:10-78`, `:116-163`. |
| `d2k_group_forget` | 294–310 | `groups.rs:271-302` `forget_failures` | **E** | normalize, фильтр name/transport/family/PLAN_FAILED, swap_remove, rebuild, возврат числа — совпадают. Тест `tests/groups.rs:166-234` (два плана, забывание после повторного изучения). |
| `d2k_group_expire` | 311–324 | `groups.rs:304-324` `expire_failures` | **E** | `max_age<=0` или `now<max_age`, `at < now-max_age`, swap_remove/rebuild, возврат числа — совпадают. Тест `tests/groups.rs:210` (7 суток и +1 секунда). |
| `same_evidence` (static) | 38–73 | `catalog.rs:1077-1088` `same_signal` | **P** | volume/rx-volume/rx-volume-wire: `abs(saved-observed)<=4`; ttl: `abs_diff<=2`; tos/ipid точно. C `int`-разность и модуль, Rust `i64`/`u8::abs_diff`. Тесты `tests/catalog.rs:94-153` покрывают ttl±1, конфликт ttl, tos/ipid; ветка volume без прямого теста, C/Rust differential нет. |
| `d2k_fp_same` | 75–125 | `catalog.rs:59-83` `Fingerprint::is_compatible_with` | **P** | Направленный обход observed→saved, все приметы одного рода, `kind_seen && !agreed → false`, отсутствие рода не противоречие, `any_agreement` в конце. C `common++` только при согласии рода; Rust `any_agreement` через `signal_agrees`. Тесты `tests/catalog.rs:94-153`: несколько `rst` одного рода, частичное покрытие, конфликт, нет общих родов, method mismatch. |
| `d2k_catalog_match` | 127–136 | `catalog.rs:537-541` `match_fingerprint` | **P** | Первый совместимый индекс, `-1`/`None` при отсутствии. Тесты `tests/catalog.rs:95-153` (совпадение box 0, отсутствие, конфликт). Проверки индекса >0 нет; C/Rust differential нет. |
| `d2k_ip4_parse` | 7–30 | `std::net::Ipv4Addr::from_str` (`examples/m5_net4_trace.rs:15`) | **P** | **Подтверждённое расхождение:** C принимает ведущие нули (`010.0.0.1` → 10.0.0.1), Rust 1.98 даёт `Err(AddrParseError(Ipv4))` (проверено `rustc`). `test-core-net4-differential.sh` покрывает только обычные/битые литералы, не ведущие нули. |
| `d2k_ip4_text` | 32–38 | `Ipv4Addr::Display` | **E** | `scripts/test-core-net4-differential.sh` сравнивает C `d2k_ip4_text` и Rust `Display` на валидных адресах. |
| `d2k_ip4_private` | 40–51 | `quic_replay.rs:23-46` `ipv4_is_local` | **E** | Differential покрывает 0/8? (C только `v==0`), 10/8, 127/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10 и public 8.8.8.8. Rust-диапазоны совпадают. |
| `d2k_ip6_private` | 53–64 | `quic_replay.rs:47-58` IPv6-ветка | **E** | Differential покрывает ::, ::1, fc00::, fe80::, ff02::, IPv4-mapped private/public, 2001:db8::1. |
| `looks_like_tls` (static) | 33–35 | — | **N** | **Уточнение 2026-11-12:** правило принадлежит `core/verdict.c`; R2O не портировал core-вердикт. Detect-триггер `Trigger::raw_hex` всегда `Accept::Any` (`detect/trigger.c:106`), поэтому применять это правило к нему нельзя. C-дерево production-вызовов не имеет (только `core/test_verdict.c`). |
| `reverse_note` (static) | 53–62 | `classify.rs` CLEAR/`probe_response` | **P** | C добавляет оговорку к CLEAR по `d2k_hello_shape` (LEGACY/UNKNOWN); Rust по форме оговорку не строит — при SNI запускает `probe_response` (может вернуть `Response`), иначе при `Accept::ServerHello` пишет «ответное направление не проверено: нет SNI». Текст C не воспроизводится. |
| `pause_note` (static) | 74–80 | `classify.rs` reason-строки | **P** | Формат «замерено без пауз/с паузой N мкс» перенесён; C-буфер 96 байт, Rust `String` без обрезки. |
| `stop_requested` (static) | 92–94 | `classify.rs` `stopped(options)` | **P** | Проверка atomic-флага отмены эквивалентна. |
| `classify_cancelled` (static) | 96–102 | `classify.rs` cancel-ветка | **P** | VERDICT=INCONCLUSIVE, marked=(mark!=0)&&all_marked, reason про снимок клиента — перенесено. |
| `d2k_classify_cancelable` | 104–334 | `classify.rs:1298-1959` | **P** | Дерево base→confirm→split1→control, CLEAR_CONFIRM_REPEATS=2, UNREACHABLE/FLAKY/CLEAR/PREFIX/OPAQUE/INCONCLUSIVE и AND-метка перенесены; тесты `classify.rs:2096-2444`. **Подтверждённые отличия:** CLI `--classify` ставит `full_detect_semantics=true, confirm_clear=false` (`main.rs:1177-1178`) — удвоенное подтверждение CLEAR пропускается, добавляется dial-timeout-retry; CLEAR с SNI делает `probe_response` и может вернуть `Response`; после разреза 1 Rust ищет long-gap/last/binary → `WholePacket`/`Prefix` с boundary; при прошедшем контроле добавляются raw-sweep (`Poisonable`) и `neutral_ack` (`Address`). Полного C/Rust differential дерева нет. |
| `d2k_classify` | 336–342 | `classify.rs` публичный `classify` | **P** | Обёртка с `stop=NULL`; эквивалентна. |
| `original_probe` (static) | 35–44 | `quic_replay.rs`/`r2o_quic_http3.rs` | **P** | **Прямого hook-аналога нет:** Rust строит кандидатов (`r2o_quic_discovery_candidates`, `r2o_quic_original_fallback_candidates`) и вызывает `r2o_quic_http3_*` с `server_name`; пары probe/data-hook с `control ? NULL : target_sni` нет. Отдельного differential нет. |
| `original_data` (static) | 47–50 | `quic_replay.rs` data-stage | **P** | C передаёт target_sni/path/port/wait/mark одной структурой; Rust принимает path/server_name параметрами в `r2o_quic_http3_get_with_wire_len`; эквивалентность полей не доказана. |
| `wire_measure` (static) | 52–78 | `quic_replay.rs`/`r2o_quic_http3.rs` | **P** | **Подтверждённый пробел:** в Rust grep `target_sni`/`pool[0]` по QUIC-модулям пуст — fallback «литеральный IP без SNI → pool[0]» не найден; `probe_path` копируется в `r2o_quic_discovery_probe_path`, `next/marked` живут в `R2oQuicRawAskResult`/trial. Одноимённой обёртки нет. |
| `d2k_quic_original_measure` | 80–83 | `quic_replay.rs` original arms | **P** | C-обёртка одной строкой; Rust список исходных кандидатов и исполнение разнесены. Результаты покрыты QUIC differentials, сама обёртка/`probe_path` — нет. |
| `d2k_quic_strategy_measure` | 88–91 | `quic_replay.rs` strategy arms | **P** | C-обёртка; Rust список стратегий (`Clearance/SplitCrypto/UdpLength/TtlStrategy`) и исполнение разнесены. Покрыто `r2o-quic-*` differentials частично. |

**Прочитано построчно:** `domain.c` 4/4 (72 строки), `groups.c` 14/14 (324), `match.c` 3/3 (136), `meas.c` 12/12 (346), `measured.c` 9/9 (390), `net4.c` 4/4 (64), `verdict.c` 7/7 (342), `props.c` 5/5 (91).

## Углублённая сверка: CLI d2kfetch/d2kvoice/d2kask (34 функции)

**Прочитано построчно: 34/34 функций, 1404 строки C (d2kfetch 356, d2kvoice 135, d2kask 913).**

| C-функция | строки | R2O-аналог | статус | доказательство / пробел |
|---|---:|---|---|---|
| `json_string` (static) | 41–62 | `r2o-fetch.rs` JSON через `serde_json::json!` | **P** | C вручную проверяет UTF-8: 2/3/4 байта, continuation, overlong `E0`, surrogate `ED`, границы `F0/F4`; валидные байты печатает как есть, невалидный байт — как `\u00xx` (каждый байт отдельно, не `\ufffd`). Rust хранит только `String`, невалидный UTF-8 отсекается при разборе аргументов (`r2o-fetch.rs:60`), serde экранирует `"`/`\` и control. Для валидных строк вывод эквивалентен; побайтового differential нет. |
| `vol_verdict_code` (static) | 64–72 | `r2o-fetch.rs:226-231` match по `R2oFetchVolumeTxVerdict` | **P** | Четыре состояния отображаются дословно: `unreachable/cut/passed/short`; C default → `unknown`, у Rust enum всего четыре варианта, поэтому default недостижим. Отдельного теста/дифференциала на JSON-поле нет. |
| `usage` (static) | 74–102 | `r2o-fetch.rs:693-720 print_help` | **P** | Общие флаги: `--name/--ip/--port/--path/--wire/--snapshot/--tls12/--deadline/--ladder/--mark/--quic/--json/--version`. Rust добавляет `--help/-h`, `-V`, `--control`, `--quic-budget`; C принимает `-v`, Rust — `-v/-V`. Текст и семантика `--wire 0` (`0` = длина профиля) описаны по-разному. |
| `resolve_first` (static) | 104–114 | `r2o-fetch.rs:165-188` `ToSocketAddrs::next` | **P** | C: `getaddrinfo(AF_UNSPEC, SOCK_STREAM)`, затем `getnameinfo(NI_NUMERICHOST)` первого адреса. Rust: `(name, port).to_socket_addrs()?.next()?.ip()`. Выбор «первого» совпадает, но C не передаёт порт в `getaddrinfo`, Rust передаёт; `--ip ""` в обоих → DNS-отказ с кодом 2. Разный порядок адресов при нескольких A/AAAA не проверялся. |
| `snapshot_wire` (static) | 117–155 | `fetch.rs:53-147 r2o_fetch_snapshot_wire_len` | **P** | **Подтверждённые отличия:** (1) C открывает основной control `d2k_link_open(NULL)` и шлёт `ARM_SHAPE(name,6)`, ждёт `D2K_EV_SHAPE`; Rust подключается к отдельному snapshot-сокету (`r2k_snapshot_socket_path`), первым обязан прийти `EVENT_PROTOCOL`, затем `EVENT_HELLO`. (2) C проверяет только `kind==SHAPE && transport==6`; Rust — `EVENT_HELLO`, `key[37]==6`, host равен нормализованному имени без регистра и `wire_len.is_some()`, иначе кадр пропускается. (3) C не нормализует имя, Rust вызывает `domain::normalize` и отвергает `localhost`/IP/не-ASCII. (4) C передаёт остаток бюджета в `d2k_link_next`, Rust ставит `read_timeout` на остаток дедлайна. Таймаут/чужое событие отдельным differential не покрыты. |
| `main` | 157–356 | `crates/r2o-controller/src/bin/r2o-fetch.rs:11-507` | **P** | **Совпадает:** режимы GET/TLS12/QUIC/ladder/snapshot/json, `--wire 0` → длина профиля, `--ip ""` → `dns_failed`/exit 2, итоговые коды TCP 0 (полный ответ), 1 (обрыв/ошибка), 2 (локальный отказ/ DNS), поля JSON `schema/client/name/shape/ip/port/path/protocol/body_*/headers_inspected/wire_requested/mark/elapsed_ms/local_port/negotiated_tls/http_status/response_complete/level/local_refusal/measured/name_ok/reason`. **Подтверждённые отличия:** (1) C разбирает `atoi/atol/strtoul` без проверки (`--port 65537` → 1, отрицательный deadline допустим), Rust строго парсит `u16/u64` и отвергает; (2) C `ladder` полностью вытесняет `quic` и меряет TCP, Rust при `--ladder --quic` выполняет обе проверки и combines exit; (3) C ladder всегда зовёт `d2k_volume_probe_path` (RX внутри), Rust вызывает TX и RX отдельно и пропускает RX при port 80 или reason «нет TCP к »; (4) C QUIC-режим использует `d2k_verify_probe_quic_path_mark_on` и успех только по `body_complete`, Rust — `r2o_fetch_quic_with_budget`, JSON `body_bytes:null` + `quic_stream_bytes`, exit 0 при `complete` или `budget_passed`; (5) C печатает `--version` из `D2K_RELEASE_ID`, Rust — `CARGO_PKG_VERSION`; (6) человеческий вывод различается компоновкой (C печатает gzip/chunked в строке тела, Rust — отдельными строками); (7) Rust добавляет `--quic-budget` (требует `--quic`) и `--control`. Полного побайтового JSON/exit differential нет. |
| `usage` (static) | 22–37 | `main.rs:819-833` usage `--voice-check`, `:843-861` `--voice-list` | **P** | C — отдельный бинарь `d2kvoice` с `--addr/--control/--conntrack/--wait/--mark/--list/--discovery`; Rust — подкоманды `r2o-controller --voice-check …` и `--voice-list [--conntrack ФАЙЛ]`. Набор возможностей совпадает, но `--list` разнесён в отдельную подкоманду, текст помощи другой. |
| `split_hostport` (static) | 39–48 | `voice_measure.rs:803-816 r2o_parse_voice_address` | **P** | **Совпадает:** последний `:`, непустой host, порт 1..65535. **Отличия:** C делает `strtoul` без проверки хвоста (`1.2.3.4:12abc` → 12) и принимает ведущие нули IPv4 через `d2k_ip4_parse`; Rust `parse::<u16>()` отвергает хвост, а `Ipv4Addr::from_str` — ведущие нули. C host-буфер 64 байта, Rust `String`. |
| `verdict_word` (static) | 50–61 | `voice_measure.rs:296-305 r2o_format_voice_measurement` | **P** | Все семь текстов совпадают дословно: «резать нечего», «режут этот поток», «UDP не ходит вовсе», «мерить нечего», «не воспроизводится», «мерить этим зондом нечем», «измерение не закончено». C default → «неизвестный вердикт»; Rust match исчерпывающий, default недостижим. Отдельного C/Rust differential нет. |
| `main` | 63–135 | `voice_measure.rs:93-139` parse, `main.rs:819-867` commands, `voice_measure.rs:141-350` measure/print | **P** | **Совпадает:** `--addr/--control/--conntrack/--wait/--mark/--discovery`, `--list` с кодом 1 при пустом списке и 0 иначе, итоговый код `CLEAR ? 0 : 1`, печать «Разговор/Вердикт/Зондов/ВНИМАНИЕ». **Отличия:** (1) C `--wait/--mark` — `strtoul` без проверки (в т.ч. `--wait -1`, мусорный хвост), Rust строго `u64`/`0x`+decimal; C `--mark` понимает восьмеричную форму (`base 0`), Rust — только hex/десятичную; (2) C `--list` — флаг в том же бинаре, Rust — отдельная подкоманда с строгим набором аргументов; (3) C при `discovery_verified` печатает `fake_arm ×arm_copies`, Rust отдельно печатает `discovery_prefix` как `stun-before-discovery ×1` либо общую строку, а найденную приманку — как `Приманка: кандидат …`; (4) C `--addr` принимает ведущие нули IPv4, Rust отвергает. Печать и коды не сверялись побайтовым differential. |
| `need_value` (static) | 120–128 | `ask.rs:61-70` inline value fetch | **P** | C проверяет только `i+1<argc`; Rust на каждом флаге с значением берёт следующий OsString и возвращает «{flag} требует значения». **Отличие:** повтор флага C принимает (последний выигрывает), Rust отвергает любой повтор через `one()` (`ask.rs:72-78`). |
| `parse_flag_u16` (static) | 134–149 | `ask.rs:168-177 parse_positive_port` | **P** | **Совпадает:** 1..65535, десятичная запись, отказ на пустой/минус/хвост/0. **Отличия:** C `strtoul` пропускает ведущие пробелы (`" 12"` → 12), Rust `parse::<u16>()` отвергает; C допускает `+12`, Rust также; C на 64-битной платформе ловит только `ERANGE` `unsigned long`, Rust строго `u16`. |
| `parse_flag_u32` (static) | 157–172 | `ask.rs:190-207 parse_mark` | **P** | **Совпадает:** base 0 (hex `0x`, octal с ведущим `0`, decimal), запрет `-`/пустой, отказ на хвост. **Отличия:** C `strtoul` на 64-битной платформе принимает `4294967296` и молча обрезает до 0 при cast, Rust `u32::from_str_radix` отвергает; C `0` → 0, Rust специально возвращает 0 для строки `"0"`. |
| `parse_flag_ms` (static) | 179–194 | `ask.rs:179-188 parse_positive_ms` | **P** | **Совпадает:** положительное целое, отказ на 0/минус/хвост/переполнение. **Отличия:** C `strtol` допускает ведущие пробелы и `long` (на 32-бит max 2^31−1), Rust `u64` без пробелов и до 2^64−1; отрицательные оба отвергают. |
| `parse_args` | 202–301 | `ask.rs:44-160 parse_ask_options` | **P** | **Совпадает:** обязательные `--control/--ip/--sni`, ровно один из `--hello-hex` и `--arm-wait-ms`, `--control-hex` и `--control-sni` взаимоисключающие, `--control-sni` требует `--arm-wait-ms`, порог 443 по умолчанию, mark 0 по умолчанию, неизвестный флаг — отказ. **Подтверждённые отличия:** (1) C повтор флага молча перезаписывает, Rust отвергает; (2) C `--ip` — произвольная строка без проверки, Rust сразу `IpAddr`; (3) C `--sni` только непустой, Rust 1..253 байта; (4) C не требует UTF-8 (байты argv), Rust требует; (5) C `--capture`/help отсутствуют, Rust `--ask --help` обрабатывается до парсера. |
| `hex_nibble` (static) | 315–320 | `ask.rs:230-240` inline nibble match | **E*** | 0-9/a-f/A-F ↔ 0..15, остальное ошибка; покрыто `ask.rs:660-674` (недопустимый `x`, нечётное число, пробелы/`\r`). |
| `save_hex` (static) | 329–349 | `main.rs:783-808 save_ask_snapshot` | **P** | Формат совпадает: комментарий `# снимок …, имя …, N байт — снят …`, hex по 32 байта, завершающий `\n`, сообщение об успехе. **Отличия:** C пишет `fopen/fprintf/fclose` и отдельно ловит неполный `fclose`, Rust — `fs::write` всего буфера; бренд в комментарии `d2kask` против `r2o-controller`; тексты ошибок иные. |
| `read_hex_file` (static) | 361–414 | `ask.rs:209-261 read_hex_file/decode_hex` | **P** | **Совпадает:** строки, начинающиеся после пробелов/табов с `#`, пропускаются; пробелы/`\t`/`\r`/`\n` игнорируются; не-hex — ошибка; cap 2048; нечётное число цифр и пустой файл — ошибка. **Отличия:** C читает `fgets` строкой 8200 и останавливается на NUL (`for (; *p; p++)`), Rust читает весь файл и NUL считает недопустимым; C ограничен размером строки, Rust — нет. |
| `wait_shape` (static) | 424–455 | `main.rs:19871-19920 wait_for_client_shape` | **P** | **Совпадает:** суммарный бюджет `wait_ms`, пропуск чужих событий, ошибка при `shape_len>cap`. **Отличия:** C ждёт любой `D2K_EV_SHAPE` без проверки имени/семейства; Rust принимает только `EVENT_CLIENT_SHAPE` с `key[0]==family` и `host.eq_ignore_ascii_case`, остальные кадры складывает в `pending_events`; C использует `d2k_link_next`, Rust — `wait_for_control_frame` порциями по 100 мс. |
| `pval_str` (static) | 462–468 | `main.rs:811-817 r2o_tri_state` | **P*** | Тексты «да/нет/не измерено» совпадают; Rust-функция используется в итоговом векторе, но C-функция `print_question`/`print_vector` имеет два потребителя. Отдельного differential нет. |
| `print_header` (static) | 470–476 | `main.rs:401-407` header output | **P** | C печатает `d2kask: спрашиваем настоящую коробку DPI`, затем цель/SNI/control/mark. Rust печатает цель/SNI/control/mark без заголовка, а к метке добавляет «зонд отправляется без метки». Формат различается. |
| `print_snapshot` (static) | 482–502 | `main.rs:408-432` snapshot output | **P** | C печатает `снимок …: how (detail), N байт`, SNI и `вид приветствия: MODERN/LEGACY/UNKNOWN`, различает таймаут и «не получен». Rust печатает `снимок …: N байт, SNI …` либо `не получен за N мс`, без строки вида приветствия; SNI при ошибке — «не найден». |
| `pos_decided` (static) | 519–528 | `main.rs:455-465` `passed_question` + `AskQuestion::ALL` | **P** | C вычисляет «решён ли вопрос сам по себе» из итогового вектора, включая особый случай `checksum` при `parses_l7=YES`. Rust хранит только `passed_question` (первый пройденный) и печатает последующие как «не задан: предыдущий вопрос уже дал ответ»; отдельной функции `pos_decided` нет. Спецслучай checksum частично отражён в `compose_plan_texts` (`ask.rs:337-344`), но не в печати вопросов. |
| `pos_value` (static) | 530–539 | `main.rs:746-766` property output | **P** | C отображает позицию вопроса в поле `d2k_props`; Rust печатает пять полей напрямую. Значения полей совпадают, отдельной функции нет. |
| `step_rc_str` (static) | 547–561 | `main.rs:15799-15825 r2o_print_ask_trace` | **P** | C переводит 10 кодов `D2K_STEP_*` в тексты. Rust не имеет enum шагов: `r2o_print_ask_trace` принимает готовую строку `stop_reason` и печатает её; часть смыслов (нет порта, нет обмена, не отправлено) выражена отдельными аргументами. Прямого соответствия 10 кодов нет. |
| `ack_code_str` (static) | 565–573 | `main.rs:15770-15777 r2o_ask_ack_reason` | **P*** | `BAD_PLAN/BAD_ARGS/NO_ROOM` совпадают дословно; `ACK_OK` C печатает как «принято», Rust при `ack.ok` не вызывает функцию (`main.rs:567-582`). Default «неизвестная причина» совпадает. |
| `print_seen_types` (static) | 579–594 | `main.rs:15780-15796 r2o_ask_print_seen_types` | **P*** | Типы 20/21/22/23, маска `1<<(type-20)`, порядок и тексты совпадают; пустая маска → «ни одной». Отдельного теста нет. |
| `print_step` (static) | 597–624 | `main.rs:15799-15825 r2o_print_ask_trace` | **P** | **Совпадает:** строка плана с длиной и статусом, обмен с местного порта/байтами/первой записью/типами, «до обращения не дошло», «события обмена не пришло», причина остановки. **Отличия:** C имеет отдельные ветви «план не собрался», «датапат ОТВЕРГ — ack», «подтверждения нет»; Rust получает статус готовой строкой и печатает `план: N байт, {status}`; C отдельно печатает `err` шага, Rust — `stop_reason`; C печатает код `unsent` только через `step_rc_str`, Rust добавляет строку «отказ отправки плана: код N». |
| `print_question` (static) | 632–674 | `main.rs:430-744` per-question output | **P** | C печатает для каждого вопроса блок `[i/5]`, причину «не задан» (раньше остановился/нет control), затем план/обмен/метку/ответ и примечания checksum/parse. Rust печатает однострочный результат по ходу опроса, а после первого прошедшего — только последующие «не задан: предыдущий вопрос уже дал ответ»; полного блока `pos_decided`/`pos_value` и примечаний C нет. |
| `all_unknown` (static) | 676–682 | `main.rs:746-766` properties output | **P*** | C проверяет все пять полей на `D2K_P_UNKNOWN`; Rust не имеет отдельной функции, но `DpiProps::default()` даёт `Unset`, а итоговые значения печатаются через `r2o_tri_state`. Отдельного теста/дифференциала нет. |
| `print_not_asked_at_all` (static) | 684–696 | `main.rs:434-443` no-trigger output | **P** | C печатает вводную строку и пять отдельных блоков `[i/5] … спрошен: нет`. Rust при отсутствии триггера печатает одну строку «опрос не выполнен» и пять однострочных «[i/5] … — не задан: снимок триггера не получен». Формат различается. |
| `print_vector` (static) | 698–705 | `main.rs:746-766` vector output | **P** | Пять полей и значения совпадают (`tolerates_left_overlap`, `tolerates_reorder`, `validates_checksum`, `parses_l7`, `counts_duplicates`); C печатает заголовок «итоговый вектор (не измерено / да / нет)», Rust — «итоговые свойства инспектора». Порядок полей в Rust иной (checksum, parse, duplicates). |
| `print_plans` (static) | 707–725 | `main.rs:767-778` composed plans output | **P** | C печатает до 8 планов с отступом 4 пробела, обрезает каждую строку по `\n`, при нуле планов печатает причину недоступности приманки. Rust печатает полный текст каждого плана без отступа и без ограничения 8; при пустом списке — «нет (не хватает имени control-приманки)». |
| `main` | 736–913 | `main.rs:294-329` dispatch, `:332-780 run_r2o_ask` | **P** | **Совпадает:** коды 2 на отказ аргументов/hex, 0 на состоявшийся прогон, 1 на отказ среды; чтение `--hello-hex/--control-hex`, ARM_SHAPE и ожидание снимка, проверка SNI, пять вопросов в порядке `overlap, reorder, checksum, parse, duplicates`, остановка после первого прошедшего, итоговый вектор и `d2k_compose`. **Подтверждённые отличия:** (1) C проверяет только наличие SNI в снимке, Rust `validate_hello` требует совпадения SNI с `--sni`; для control C не сверяет имя с `--control-sni`, Rust сверяет; (2) C зовёт `d2k_link_open` и один `d2k_props_ask_traced`, Rust ведёт каждый вопрос через `ControlClient` (`SET_NAME_PROBE`, случайные plan/trial id, `BoundTcpProbe`, ожидание proof) — это отдельная реализация протокола, а не перенос одного вызова; (3) C печатает полный отчёт по всем пяти вопросам после прогона, Rust печатает по ходу и сокращает отчёт; (4) C `d2k_compose` получает `d2k_hello_shape`, Rust `hello_shape` возвращает ошибку на UNKNOWN вместо `D2K_SHAPE_UNKNOWN`; (5) C `--save-trigger/--save-control` пишет через `save_hex`, Rust через `save_ask_snapshot`; (6) C `main` всегда 0 после успешного прохождения, Rust может вернуть 1 на ошибке `ControlClient`/`compose`. Полного C/Rust differential этого CLI нет; тесты `ask.rs:520-756` покрывают парсер, планы и compose. |

## Углублённая сверка: plantlv.c (20 функций)

**Прочитано построчно: 20/20 функций, 863 строки C (1–863).**

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

**Прочитано построчно: 43/43 функции, 1094 строки C (1–1094).** Сверены:
`d2k_link_open/close/peer_closed`, `wait_readable`, `read_exact`, `write_all`,
`hex_nibble`, `hex_decode`; полный декодер `d2k_link_next` (HELLO,
HTTP_RESPONSE/HTTP_PORTAL, SUSPECT, STATS, EXCHANGE, CLIENT_TCP, SHAPE, ACK,
APPLIED, PROTO, REFUSED, default); `send_name_plan` (имя 1..255, transport
6/17, hex, shape/family, optional sport, plan, optional trial/area_id);
`send_area_key`, `area_context_valid`, все `set/del_*` name/suffix/bypass/
addr/addr_probe/arm_shape/del_name/del_name_probe; `d2k_link_set_https`,
`d2k_link_set_stall_budgets`; `d2k_ev_outer_appdata`. Подтверждённые отличия
перечислены ниже.

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
  1. `SET_HTTPS` — **закрыто 2026-11-12.** C-link кодирует любой
     `u32 ttl`, обрезку до **7 суток** делает датапат
     (`d2k_ctl.h:231`, `ctlsrv.c:446`); R2O-кодировщик теперь тоже
     принимает любой `u32`, датапат обрезает до
     `MAX_HTTPS_TTL_SECONDS = 7 суток`. Тесты кодировщика и датапата.
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

**Прочитано построчно: 41/41 функция, 605 строк C (1–605).** R2O-сверка: `diagnostics.rs:159-236` (memory), `:754-788` (`record`), `:790-1003` (`tick`), `:1155-1231` (`record_write_error`/`write_report`), `:1411-1542` (`process_memory`/`process_detail`/`read_smaps_rollup`). Сверены: кольца
events/limits/samples/memory_history/anomalies/growth, счётчики памяти по 6 сайтам,
`copy`/`js`/`number`, `read_proc`/`read_detail`/`read_status`, 60-секундный sample,
история памяти и аномалия роста RSS, `d2k_diag_write` (schema=1, memory_tracking,
madvise, anomalies, events, limit_transitions, memory_history, samples,
memory_details).

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
  `rollup_status/errno/rollup[5]` (`diagnostics.c:426-433`), Rust в
  memory_history кладёт `0/null/null` (`diagnostics.rs:949-968`); C даёт
  `null` для недоступных RSS/VmData/VmSwap/RssAnon, Rust — `0`
  (`unwrap_or(0)`, `diagnostics.rs:938-941`). P.
- **`d2k_diag_write`:** C вручную пишет `report.json` schema=1 с лимитом
  448 КиБ; Rust сериализует `Recorder::write_report` через serde_json с тем
  же `REPORT_MAX`. **Отличия:** C пишет `http_storage_limits` только при
  `ns>0` (`diagnostics.c:476-481`), Rust — всегда (`diagnostics.rs:1130-1135`);
  C выводит `reason_source` из `protocol=="http"` (`diagnostics.c:493`),
  Rust берёт его из события. `r2o-diagnostics-differential.sh` сравнивает
  `ring_bytes/event/snapshots/http_records`; остальные поля — unit, не
  C-oracle. P.
- **`d2k_diag_record`/`record_limit`/`record_anomaly`/`write_anomalies`:**
  кольца и счётчики `event_total/limit_total/anomaly_total/write_failures`
  перенесены; `record_anomaly` пишет kind/code/rss_delta/accounted_delta/
  stage в кольцо 8. **Подтверждённые расхождения:** (1) предел `reason` —
  255 байт в C (`reason[256]`) и **1024** в Rust (`diagnostics.rs:766-772`);
  (2) `d2k_diag_record_write_error` в C сохраняет код ошибки в
  `anomaly.code` и печатает `error_code`, Rust `record_write_error(stage)`
  всегда пишет `null` (`diagnostics.rs:1165-1176`) — errno/код теряются.
  Остальные пределы совпадают. P, отдельного C/Rust differential на
  переполнение колец и код ошибки нет.

## Углублённая сверка: catalog.c (60 функций)

**Прочитано построчно: 60/60 функций, 1477 строк C (1–1477).** Сверены:
JSON-курсор/числа/строки/RFC3339/пропуск/предел глубины, `parse_object`/
`parse_array`/`grow`, signal/fingerprint/plan/binding/box/domain/
network_whitelist/catalog handlers, `prune_unavailable_domain_groups`, free/
memory_bytes, load с проверкой хвоста, все writer'ы, `d2k_catalog_save` и
`d2k_catalog_save_atomic`.

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
  `stored==0 || got==0 || stored==got` (`catalog.c:905-912`); Rust
  `group_shape_fits` (`live.rs:284-288`, `main.rs:3023`) принимает
  `saved==0 || saved==observed || (saved==MODERN && observed==ECH_TCP)` —
  то есть **не принимает `got==0`** при ненулевом `stored` и дополнительно
  принимает modern→ECH_TCP.
- **`handle_domain_observation`/`parse_domain_observations`/
  `handle_net_whitelist_key`/`handle_catalog_key`/`parse_catalog_obj`:**
  domain_state/observations до 256, network_whitelist и top-level
  frozen/disabled/disabled_at перенесены (`catalog.rs`/`groups.rs`);
  unit `derived_domain_groups_are_ignored`.
  **`prune_unavailable_domain_groups` — подтверждённое расхождение:**
  C после restore удаляет группы без enabled-плана в каталоге; Rust
  `restore`/`rebuild` не видят `boxes` и такого prune не делают.
- **`read_whole_file`/`d2k_catalog_load`:** загрузка, schema=1, запрет
  мусора после объекта — P: `r2o-catalog-persist-differential.sh` и
  `tests/catalog.rs` покрывают старые каталоги, null и trailing garbage, но
  **не покрывают** отсутствие `prune_unavailable_domain_groups` и предел
  64 МиБ (Rust отвергает больший файл, C — нет).
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

**Прочитано построчно: 53/53 функции, 1799 строк C (1–1799).** Сверены:
белый список 266 имён, TLV-билдеры (`tlv_rec`/`tlv_header`/`plan_tlv_stamp_ident`),
пять планов вопросов (overlap/reorder/badsum/checksum/protocol), `ev_matches_flow`,
`wait_for_event3`/`wait_for_event`, bind/contact и TCP-profile connect,
`d2k_props_ask_traced` (applied+server_hello+unsent, ключ потока, снятие пробы),
текстовые планы и fallback-перебор, `d2k_arm_plan`, `d2k_compose`.

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

### Построчная таблица `compose.c` (53 функции)

| C-функция | строки | R2O-аналог | статус | доказательство / пробел |
|---|---:|---|---|---|
| `d2k_net_whitelist_count` | 107–109 | `r2o_rx_volume.rs:6` | **E** | 266 имён и порядок проверены unit `r2o_rx_volume.rs:84`. |
| `d2k_net_whitelist_name` | 110–112 | `r2o_rx_volume.rs:11` | **E** | Тот же список, `Option` вместо NULL; unit `:84`. |
| `wr16be` | 150–150 | `push_u16`/`to_be_bytes` (`plan_text.rs`) | **P*** | Big-endian u16; static-хелпер, отдельного differential нет. |
| `rd16be` | 151–151 | `u16::from_be_bytes` | **P*** | Big-endian u16; используется в `plan_tlv_stamp_ident`. |
| `wr32be` | 152–155 | `push_u32`/`to_be_bytes` | **P*** | Big-endian u32; static-хелпер. |
| `tlv_rec` | 162–174 | `plan_text.rs:598-604` | **P*** | type/len/value, `len<=0xFFFF`, проверка cap; Rust проверяет `u16::try_from`. |
| `tlv_header` | 186–198 | `plan_text.rs:67-610` | **P** | D2KP/schema 1/minexec 1/flags 0/count + ID(нули)+PROTO(6,1); Rust `r2o-plan` и `minexec` вычисляется, не всегда 1. |
| `plan_tlv_stamp_ident` | 218–240 | `main.rs` random plan/trial id | **P** | C FNV-1a по TLV с нулевым ID → `plan-%08x`; Rust подставляет случайный 16-байтный id. Разная идентичность/атрибуция APPLIED. |
| `overlap_plan_tlv` | 258–270 | `ask.rs:438-443` + `plan_text` | **P** | 5 записей, payload 1 `0f`, seqovl 1/0, order forward; Rust собирает текст, не TLV. |
| `reorder_plan_tlv` | 277–290 | `ask.rs:444-448` | **P** | split payload_start+1, split sni_middle+0, order reverse, pace 12000; Rust текст, тот же смысл. |
| `badsum_fake_plan_tlv` | 296–316 | `ask.rs:449-466` | **P** | 7 записей, payload 1 + poison badsum + fake; Rust текст, plan id иной. |
| `checksum_plan_tlv` | 322–326 | `ask.rs:449-453` | **P** | 64×`0f`, badsum repeats=1; Rust `compose_badsum_fake_plan` с payload `[0x0f;64]`. |
| `to_hex` | 331–338 | `hex()` (`classify_measured.rs:422`) | **E*** | Нижний регистр, 2 символа/байт; используется C-тестами и differential-планами. |
| `ev_matches_flow` | 351–366 | `main.rs:628` expected_key, `R2oAskProof` | **P** | Сравнение неупорядоченной пары адрес:порт + family/transport; Rust сравнивает канонический ключ потока. C/Rust differential нет. |
| `wait_for_event3` | 397–421 | `main.rs:646 wait_for_ask_proof` | **P** | C ждёт до трёх типов, code-фильтр и flow; Rust ждёт APPLIED/EXCHANGE/REFUSED по trial/plan/ключу. |
| `wait_for_event` | 423–429 | `main.rs:646` | **P** | Обёртка `wait_for_event3`; Rust отдельного аналога нет. |
| `props_bind_any` | 494–524 | `BoundTcpProbe::open` (`main.rs`) | **P** | **Отличия:** C ставит `IPV6_V6ONLY` для family 6, Rust не ставит; C при `out_fd==NULL` закрывает fd и возвращает -1, Rust владеет сокетом. |
| `d2k_props_bind` | 526–528 | `BoundTcpProbe::open` | **P*** | Обёртка family=4/SOCK_STREAM. |
| `d2k_props_bind_family` | 530–532 | `BoundTcpProbe::open` | **P** | family 4/6; Rust `BoundTcpProbe::open(family, Some(0))`. |
| `d2k_props_bind_udp` | 534–536 | UDP bind в `voice_measure` | **P*** | Обёртка family=4/SOCK_DGRAM; отдельного C/Rust differential нет. |
| `d2k_props_bind_udp_family` | 538–540 | UDP bind в `voice_measure` | **P** | family 4/6; Rust использует `UdpSocket`/raw bind. |
| `d2k_props_contact` | 542–545 | `BoundTcpProbe::connect` | **P*** | Обёртка use_fd=-1/family=4. |
| `d2k_props_contact_on` | 547–551 | `BoundTcpProbe::connect` | **P*** | Обёртка family=4. |
| `d2k_props_contact_on_family` | 553–558 | `BoundTcpProbe::connect` | **P** | C без TCP-timestamps (`-1`); Rust connect тем же путём, профиль timestamps не задаёт. |
| `tcp_timestamps_read` | 567–578 | `raw_probe.rs:676` host_offers_ts | **P** | C читает `/proc/sys/net/ipv4/tcp_timestamps`; Rust читает sysctl только для признака клиента, не для connect-профиля. |
| `tcp_timestamps_write` | 580–588 | нет | **N** | Подтверждено grep: Rust не пишет `/proc/sys/net/ipv4/tcp_timestamps`. |
| `connect_with_tcp_profile` | 591–636 | нет | **N** | C меняет sysctl вокруг `connect()` под mutex; Rust такого пути не имеет. |
| `d2k_props_contact_on_family_tcp_profile` | 638–753 | `BoundTcpProbe::connect` + `probe_socket` | **P** | Перенесены literal IPv4/IPv6, TCP_NODELAY, SO_NOSIGPIPE, timeouts, nonblock connect, poll/SO_ERROR, getsockname, send; **нет** параметра tcp_timestamps, кода -3 и восстановления sysctl. |
| `build_fake_body` | 786–796 | `ask.rs:470-471`, `compose_badsum_fake_plan` | **E** | `truth_len*2`, заполнение `0f`, decoy в голову; unit `ask.rs:520-559`. |
| `d2k_props_question_plan` | 798–841 | `ask.rs:432-490 question_plan` | **P** | Порядок и эффекты 5 вопросов совпадают; C TLV + FNV id, Rust текст + random plan_id. |
| `d2k_props_question_passed` | 845–864 | `ask.rs:492-505 record_question_passed` | **E** | Те же поля и спецслучай parse→checksum=false; unit `ask.rs:562-574`. |
| `question_retire` | 874–879 | `delete_name_probe` (`main.rs:528`) | **P** | Тот же кадр DEL_NAME_PROBE; C игнорирует ошибку, Rust может прервать опрос. |
| `d2k_props_ask` | 881–884 | `main.rs:836` `r2o_measure_voice`-подобный вызов | **P*** | Обёртка `d2k_props_ask_traced(..., NULL)`. |
| `step_rc` | 889–898 | `main.rs:15799 r2o_print_ask_trace` | **P*** | Трасса шага: C rc+err, Rust строки/поля. |
| `d2k_props_ask_traced` | 900–1191 | `main.rs:455-734` | **P** | **Отличия:** C требует `applied && server_hello`, Rust `applied && exchange_seen && server_hello`; C не сверяет trial_id ACK, Rust отвергает чужой; C игнорирует ошибку снятия, Rust может прервать; C flowkey неупорядоченный, Rust канонический. |
| `append_fmt` | 1203–1213 | `String`/`checked_text` (`ask.rs`) | **P*** | C проверяет cap на каждом добавлении; Rust пишет в String и проверяет предел в конце. |
| `emit_header_proto` | 1221–1227 | `ask.rs:252-260` | **P** | C `d2k-plan 1 1`, id нули, proto; Rust `r2o-plan 1 minexec`, minexec 5/12. |
| `emit_header` | 1229–1231 | `ask.rs` header | **P** | Обёртка proto `tcp tls`. |
| `append_hex` | 1233–1239 | `hex()` | **E*** | Нижний hex; differential планов. |
| `overlap_plan_text` | 1245–1256 | `ask.rs:438-443` | **E** | `d2o_compose_differential.c`; payload 1 0f, seqovl, order forward. |
| `reorder_plan_text` | 1271–1279 | `ask.rs:444-448` | **E** | Тот же differential; два split, reverse, pace 12000. |
| `badsum_fake_plan_text` | 1288–1305 | `ask.rs` compose_badsum_fake_plan | **E** | Payload, poison badsum, fake repeats/gap, order, pace; differential. |
| `checksum_plan_text` | 1312–1316 | `ask.rs` checksum | **E** | 64×0f + badsum; differential. |
| `build_decoy_hello` | 1346–1351 | `ask.rs:315-324` | **E** | Modern для MODERN, иначе LEGACY; differential/фикстуры. |
| `parse_protocol_plan_text` | 1356–1361 | `ask.rs:340-344` | **E** | Decoy hello + badsum; differential. |
| `duplicates_plan_text` | 1367–1372 | `ask.rs:332-336` | **E** | Decoy hello, repeats=2, gap=20000; differential. |
| `body_room` | 1384–1388 | `ask.rs:347-352` / fallback | **P*** | C `send_cap-120`, иначе 0; Rust те же 120 в fallback/decoy; отдельного differential нет. |
| `everything_plan_text` | 1397–1426 | `ask.rs:346-358` | **E** | Fallback «всё сразу»; `d2o_compose_differential.c` и unit. |
| `d2k_fallback_arms` | 1499–1501 | `r2o_fallback.rs` total | **E** | `r2o-fallback-differential.sh`, `fallback_plans_match_donor`. |
| `fb_arm_at` | 1504–1540 | `r2o_fallback.rs:114 arm` | **E** | Те же 50 плеч и порядок; differential. |
| `d2k_fallback_plan` | 1543–1550 | `r2o_fallback.rs:168 plan` | **E** | Обёртка arm→plan; differential. |
| `d2k_arm_plan` | 1552–1751 | `r2o_fallback.rs`, `classify_measured.rs` | **P** | 50 arm × 5 send_cap покрыты, но произвольные сочетания disorder/oob/seqovl/fake/ttl/tcpts/ipidzero не сравнивались. |
| `d2k_compose` | 1763–1799 | `ask.rs:305-368 compose_plan_texts` | **E** | Порядок веток, checksum-исключение, fallback; `d2o_compose_differential.c` + unit `ask.rs:689-756`. |

## Углублённая сверка: d2kc.c (28 функций)

**Прочитано построчно: 28/28 функций, 931 строка C (1–931).**

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

### Построчная таблица `d2kc.c` (28 функций)

| C-функция | строки | R2O-аналог | статус | доказательство / пробел |
|---|---:|---|---|---|
| `on_signal` | 111–111 | обработка SIGINT/SIGTERM в `main.rs` | **P*** | C ставит `stop_asked`; Rust использует atomic-флаг/канал. Отдельного differential нет. |
| `now_ms` | 113–117 | `Instant`/`SystemTime` | **P*** | C `CLOCK_MONOTONIC` в мс; Rust `Instant` для интервалов и wall-clock для логов. |
| `save_atomic` | 122–125 | `save_atomic` (`catalog.rs`) | **E** | `r2o-catalog-persist-differential.sh`: tmp+fsync+rename, включая конкурентное обновление. |
| `self_mem` | 136–148 | `diagnostics::process_memory` | **P** | C читает VmRSS/VmHWM/VmData/Threads из `/proc/self/status`; Rust читает те же поля, но набор точек/формат иные. C/Rust differential нет. |
| `sched_say` | 150–157 | лог-колбэк `main.rs`/`Recorder` | **P*** | C печатает локальное время и `flush`; Rust пишет через журнал/`eprintln`. |
| `http_search_portal` | 168–174 | `r2o_http_search_https_action` | **P** | C отбирает класс 3 (не UNKNOWN/PROBING/upgrade) и зовёт `d2k_httpsearch_portal`; Rust действие Queue/Suppress/Wait. |
| `hs_open_port` | 176–208 | `BoundTcpProbe::open` | **P** | C ставит `SO_MARK` только при `g_probe_mark!=0`, bind/getsockname в блокирующем сокете; Rust `unwrap_or(0x2d)`, nonblock+CLOEXEC. |
| `hs_close_port` | 210–210 | `Drop`/`close` | **P*** | C `close(fd)`; Rust владеет `OwnedFd`. |
| `hs_hex` | 212–219 | `compile_text`/hex | **P** | C переводит текст плана в hex через `d2k_plan_text_to_hex`; Rust передаёт TLV-байты. Для валидных планов тот же план, стадия/формат различаются. |
| `hs_set_probe` | 221–233 | `encode_set_name_probe` | **P** | Поля/порядок совпадают, C жёстко `SHAPE_HTTP`; Rust передаёт `wire_shape`. |
| `hs_del_probe` | 235–244 | `encode_delete_name_probe` | **P** | Тот же кадр DEL_NAME_PROBE; C игнорирует/логирует ошибку, Rust возвращает `Result`. |
| `hs_set_plan` | 246–257 | `encode_set_name_bound` | **P** | C кодирует bound-план с token; Rust требует shape `SHAPE_HTTP` и ненулевой trial_id (`control.rs:1399-1406`). |
| `hs_del_plan` | 259–269 | `encode_delete_name_bound` | **P** | **Подтверждённое расхождение:** C проверяет `binding->family == family` и `d2k_binding_known`; Rust `encode_delete_name_bound(host,6,binding)` не сверяет family. |
| `hs_start` | 271–274 | `http_search` runner | **P** | Тонкая обёртка `d2k_hs_runner_start`; Rust запускает задачу через свой runner/поток. |
| `hs_say` | 357–357 | лог HTTP-поиска | **P*** | C перенаправляет в `sched_say`; Rust использует общий лог. |
| `hs_changed` | 277–284 | сохранение HTTP-планов | **P** | C пишет отдельный `http-plans.txt` формата `d2k-http-plans 1`; в Rust grep `http-plans` пуст, кандидаты живут в JSON-каталоге. |
| `http_portal` | 288–308 | `r2o_http_search_https_action` + `encode_set_https` | **P** | C различает rc 0/1/2 (лог/SET_HTTPS), Rust — Queue/Suppress/Wait; TTL SET_HTTPS после фикса кодируется любым `u32`, датапат обрезает до 7 суток. |
| `http_push` | 310–315 | `encode_set_https` | **P** | Тот же кадр SET_HTTPS; C логирует ошибку, Rust возвращает `Result`. |
| `http_save` | 317–322 | `save_cache` | **P** | C `d2k_httpsprobe_save` с wall-clock; Rust сохраняет кэш через свой `save_cache`/JSON. |
| `http_probe_done` | 324–355 | drain + save | **P** | Обработка результатов до 8, push/save, предупреждение о потерях; **счётчик `d2k_httpsprobe_lost` в Rust отсутствует**, поэтому лог потерь не перенесён. |
| `poison_cmp` | 365–367 | stable sort/`Reverse` | **P*** | C `qsort` по убыванию successes; Rust сортирует стабильно/через `Reverse`, порядок равных может отличаться. |
| `hs_measured_poisons` | 368–392 | `measured_http_candidate_keys` | **P** | C берёт до 8 спеков на план и 64 всего, сортирует по successes и передаёт сырой spec; Rust извлекает poison-id, маппит `fake-badsum`/`fake-seqshift`/`fake:{spec}`, дедуплицирует, cap 8. |
| `usage` | 394–404 | `main.rs` help/serve args | **P** | C поддерживает `--health-file`, `--log`, `--https-cache`, `--measure-mark`; Rust `--serve` позиционный и не имеет части флагов. |
| `offline_self_check` | 406–411 | `--self-check` | **P** | C проверяет `D2K_CTL_PROTO_VERSION == D2K_RUNTIME_WIRE` и SHA-256("abc"); в `r2o-controller` отдельного `--self-check` нет, SHA-256 покрыт crypto-дифференциалом. |
| `diagnostic_event` | 415–417 | `Recorder::record` | **P** | Тот же колбэк события; Rust хранит поля в `Recorder`. |
| `diagnostic_limit` | 418–420 | `Recorder::record_limit` | **P** | Тот же колбэк лимита; формат/счётчики различаются. |
| `diagnostic_tick` | 421–468 | `Recorder::tick`/`write_report` | **P** | C 1 с/60 с, `report.new`+rename, лимит `D2K_DIAG_REPORT_MAX`; Rust `tick`/`write_report` с tmp+rename. Unit `diagnostic_tick_lifecycle_matches_d2o`; C/Rust differential сравнивает только часть JSON. |
| `main` | 470–931 | `main.rs` serve loop | **P** | **Совпадает:** загрузка каталога, приветствие PROTO с version/release, `TICK_MS=3000`, `SAVE_EVERY_MS=60000`, `REPORT_EVERY_MS=15 мин`, `LIVE_EVERY_MS=2 с`, 256 событий за круг, обработка HELLO/SUSPECT/EXCHANGE/APPLIED/REFUSED/HTTP, сохранение каталога, health-file, остановка измерителя. **Отличия:** Rust не имеет `--health-file/--log/--https-cache/--measure-mark`, `http-plans.txt` и `d2k_httpsprobe_lost`; структура цикла и набор колбэков иные. Полного C/Rust differential `d2kc` нет. |

## Углублённая сверка: sched.c (282 функции)

**Прочитано построчно: 282/282 функции, 12 364 строки C (1–12364).** Проверены:
ресурсные хелперы (`/proc/stat`, `meminfo`, conntrack, EWMA, AIMD-предел),
все состояния `T_*` (включая `T_SHAPE_WAIT`, voice/QUIC), кольца cooldown/
dead-address/late-RST/clean-handshake, ECH-свидетели и RR, QUIC named/multi и
quicdeny/recheck, каталог/области/исключения, `stall_budgets_push`,
`known_plans`/`own_first_plans`/`refill_from_fallback`/RX-лестница и подбор
белого имени, `on_suspect`/`on_shape`/`on_applied`/`on_refused`/`on_exchange`,
`verify_confirm`, `worker_run_body`, `d2k_sched_tick` целиком.

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
- **`refuse_is_permanent` (301–312):** C считает постоянными `TOO_LONG`,
  `NOT_APPLIED` и `FLOW_UNFIT` (`sched.c:310-311`) и использует это в
  `4487`, `9901`, `10113`. Rust разложил предикат на две ветки:
  `TOO_LONG|NOT_APPLIED → record_client_unfit` (`main.rs:19089-19096`) и
  `FLOW_UNFIT → каталог/повторный замер` (`19097-19172`). Набор кодов
  совпадает, порядок обработки `FLOW_UNFIT` отдельный. Единой функции нет —
  **P**, поведение по кодам подтверждено, полного differential нет.
- **`refuse_is_damage` (320–322):** C распознаёт только `DAMAGED` и
  использует его в `local_refusal_verdict` (`4522`), чтобы напечатать
  «поток испорчен недоисполнением плана» вместо «посылка не ушла». В Rust
  есть `R2O_JOURNAL_REFUSE_DAMAGED=4`, `PlanDamaged` и тексты
  (`flow_journal.rs:21,70,95,111`), но в `EVENT_REFUSED` главного цикла
  (`main.rs:19086-19178`) отдельной ветки `DAMAGED` нет: код только
  печатается и не меняет формулировку/журнал. **P**, подтверждённый пробел
  именно в объяснении недосланного.
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
  differential/unit. **После построчного прохода 2026-11-12** все 282 функции
  прочитаны; новых подтверждённых расхождений сверх перечисленных выше не
  найдено. Полного C/Rust byte-diff по-прежнему нет — это ограничение
  доказательств, а не скрытый пробел.

## Углублённая сверка: crypto.c / p256.c / x25519.c (61 функция)

**Прочитано построчно: 61/61 функций, 1185 строк C (crypto.c 671, p256.c 316, x25519.c 198).**

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
  `d2k_hkdf_expand_label`/`_ctx` — P: C ограничивает label ≤58
  (`d2k_crypto.h:88`) и ctx ≤32; Rust `quic.rs:893-906` допускает label до
  249 (`u8::try_from(6+len)`) и всегда пишет `ctx_len=0`;
  `examples/m6_crypto_trace.rs:24-36` принимает ctx, но кодирует его как
  `context.len() as u8` без проверки >255. Production-метки совпадают,
  границы и контекст — нет.
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

