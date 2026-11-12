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
| `client_alpn_nonhttp` | 1114–1137 | 24 | TCP, не ECH, пустой `measure_path`, MODERN; блок рукопожатия/`own_first==2+base_blocked`; нет RX/TX-cut; вернуть ALPN клиента, в т.ч. **пустой** (rc=0), если он не HTTP | `main.rs:15331-15350 r2o_discovery_client_alpn_verification_allowed` | **P** | **Подтверждённые отличия:** (1) C при `d2k_hello_alpn rc==0` (ALPN нет) возвращает 1 — зонд повторяет клиента без ALPN; Rust требует `client_hello.is_some_and(non_http_alpn)`, т.е. **пустой ALPN не допускает**; (2) C проверяет `measure_path[0]==0`, Rust — `probe_path == "/"`; (3) C `handshake_blocked = verdict_proves_block || (own_first==2 && base_blocked)`, Rust получает готовый bool. Дифференциал `donor_and_r2o_preserve_captured_mqtt_and_absent_alpn` покрывает MQTT/absent, но не C-ветку «нет ALPN → можно». |
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

