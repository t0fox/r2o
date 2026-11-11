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
| `handle_binding_key` | 834–885 | 52 | поля binding: kind/target/plan_id/level/confirmed/transport/family/shape/tcp_profile/... | catalog::Binding serde + validate | **P** | **Пробел:** C разбирает и проверяет `tcp_profile` (0/1/2) и сохраняет его; в Rust `Binding` (`catalog.rs:165-198`) поля `tcp_profile` нет — serde молча игнорирует его как неизвестное, при сохранении значение теряется. Для старых каталогов с shape 1/2 и tcp_profile 1/2 это потеря измеренного TS-профиля; R2O может вывести его из shape только для shape 8–13. |
| `parse_binding` | 886–890 | 5 | разобрать binding; `family` по умолчанию 4 | `catalog.rs:165-181` `Binding` | **P*** | **Расхождение default:** C `memset` + `out->family=4`, затем поле перезаписывается, если есть. Rust `Binding` выводит `Default` (family=0), `#[serde(default)]` не подставляет 4; `serialize_family` пишет 0 как 4 только при сохранении, `validate` family не нормализует. Старый каталог без `family` загрузится с family=0 в памяти. |
| `elem_binding` | 891–893 | 3 | элемент массива bindings | Vec<Binding> | **P*** | static-хелпер |
| `d2k_cat_shape_fits` | 905–912 | 8 | совместимость форм: 0 подходит любой, иначе равенство | catalog shape-fits helper | **P*** | static-хелпер; используется group/own-first тестами |
| `handle_box_key` | 918–939 | 22 | поля box: id/created/updated/fingerprint/plans/bindings | catalog::BoxRecord serde | **P** | unit round_trips |
| `parse_box` | 940–943 | 4 | разобрать box | catalog::BoxRecord | **P*** | static-хелпер |
| `elem_box` | 944–946 | 3 | элемент массива boxes | Vec<BoxRecord> | **P*** | static-хелпер |
| `handle_domain_observation` | 953–970 | 18 | поля domain observation: name/plan_id/key/evidence/at | catalog::DomainObservation serde | **P** | unit groups/catalog |
| `parse_domain_observations` | 972–989 | 18 | массив наблюдений до 256 | Vec<DomainObservation> | **P** | unit groups |
| `handle_net_whitelist_key` | 991–999 | 9 | поля network_whitelist: name/searched/tx_only/confirmed_utc | catalog::NetworkWhitelist | **P** | unit catalog |
| `handle_catalog_key` | 1001–1027 | 27 | корневые ключи: boxes/domain_*/network_whitelist, неизвестные пропускаются | catalog::Catalog serde | **P** | unit skips_unknown_fields |
| `parse_catalog_obj` | 1028–1034 | 7 | разобрать корневой объект | catalog::Catalog::parse | **P*** | static-хелпер |
| `prune_unavailable_domain_groups` | 1036–1053 | 18 | удалить группы, чей план отключён/отсутствует | catalog::validate/derive groups | **P** | unit derived_domain_groups_are_ignored |
| `free_box` | 1062–1070 | 9 | освободить планы/привязки коробки | Drop | **P*** | static-хелпер |
| `d2k_catalog_free` | 1072–1082 | 11 | освободить каталог | Drop | **P*** | static-хелпер |
| `d2k_catalog_memory_bytes` | 1084–1097 | 14 | оценка памяти каталога | diagnostics catalog_bytes (main.rs:16768); отдельной функции нет | **P** | реализовано косвенно; C/Rust differential на объём нет |
| `read_whole_file` | 1103–1143 | 41 | прочитать файл целиком | std::fs::read | **P*** | static-хелпер |
| `d2k_catalog_load` | 1145–1191 | 47 | загрузка каталога: JSON, domain observations, prune, запрет мусора после объекта | catalog::Catalog::load | **E** | r2o-catalog-persist-differential.sh + tests/catalog.rs (старые каталоги, null, trailing garbage) |
| `write_json_string` | 1198–1218 | 21 | JSON-строка с escape | serde_json | **P*** | static-хелпер |
| `wr_indent` | 1220–1222 | 3 | отступ 2 пробела | serde_json::to_string_pretty | **P*** | static-хелпер |
| `write_json_array` | 1230–1240 | 11 | массив с отступами | serde_json | **P*** | static-хелпер |
| `write_signal_elem` | 1242–1257 | 16 | JSON signal, packets только при nonzero | catalog::Signal serde | **P** | persist differential сравнивает каталог частично |
| `write_fp` | 1259–1266 | 8 | JSON fingerprint | catalog::Fingerprint serde | **P** | то же |
| `write_plan_elem` | 1268–1280 | 13 | JSON plan с RFC3339 added | catalog::Plan serde | **P** | то же |
| `write_binding_elem` | 1282–1332 | 51 | JSON binding с family>=4, опциональными probe_path/ech_origin/recheck_since/budget | catalog::Binding serde | **P** | то же |
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
| `props_bind_any` | 494–524 | 31 | bind локального TCP/UDP-порта с IPV6_V6ONLY | main.rs bind helpers | **P*** | static-хелпер |
| `d2k_props_bind` | 526–528 | 3 | bind IPv4 TCP | main.rs ask/classify bind | **P*** | static-хелпер |
| `d2k_props_bind_family` | 530–532 | 3 | bind TCP family 4/6 | main.rs bind helpers | **P*** | static-хелпер |
| `d2k_props_bind_udp` | 534–536 | 3 | bind IPv4 UDP | main.rs bind helpers | **P*** | static-хелпер |
| `d2k_props_bind_udp_family` | 538–540 | 3 | bind UDP family 4/6 | main.rs bind helpers | **P*** | static-хелпер |
| `d2k_props_contact` | 542–545 | 4 | TCP-обращение к цели IPv4 с отправкой приветствия | main.rs ask contact | **P** | перенесено; C/Rust differential нет |
| `d2k_props_contact_on` | 547–551 | 5 | то же с готовым fd | main.rs ask contact | **P*** | static-хелпер |
| `d2k_props_contact_on_family` | 553–558 | 6 | то же для family 4/6 | main.rs ask contact | **P*** | static-хелпер |
| `tcp_timestamps_read` | 567–578 | 12 | прочитать /proc/sys/net/ipv4/tcp_timestamps | main.rs tcp profile probe | **P*** | static-хелпер Linux |
| `tcp_timestamps_write` | 580–588 | 9 | записать tcp_timestamps | main.rs tcp profile probe | **P*** | static-хелпер; глобальная запись под мьютексом |
| `connect_with_tcp_profile` | 591–636 | 46 | connect при временно изменённом tcp_timestamps, восстановление | main.rs tcp profile connect | **P** | реализовано; C/Rust differential на гонку/восстановление нет |
| `d2k_props_contact_on_family_tcp_profile` | 638–753 | 116 | полный TCP-contact: socket, mark, nonblock connect, local addr/port, отправка hello | main.rs ask contact + classify dial | **P** | основной путь; покрыт classifier/ask частично, отдельного C/Rust diff нет |
| `build_fake_body` | 786–796 | 11 | тело fake: decoy-префикс + заполнитель 0f, длина 2*truth | ask::compose_badsum_fake_plan | **P*** | static-хелпер |
| `d2k_props_question_plan` | 798–841 | 44 | план одного из 5 вопросов свойств (overlap/reorder/checksum/protocol/duplicates) | ask::question_plan | **P** | unit question_order_and_plan_parameters; C/Rust differential планов вопросов не найден |
| `d2k_props_question_passed` | 845–864 | 20 | записать ответ вопроса в d2k_props (parse снимает checksum) | ask::record_question_passed | **P** | unit protocol_parse_requires_control_and_success_updates_only_its_proven_fields |
| `question_retire` | 874–879 | 6 | снять пробный план вопроса с датапата | main.rs ask question retire | **P*** | static-хелпер |
| `d2k_props_ask` | 881–884 | 4 | опрос свойств без трассировки | ask::compose_plan_texts/run_r2o_ask | **P** | обёртка; см. d2k_props_ask_traced |
| `step_rc` | 889–898 | 10 | записать rc/err шага | ask::AskStep | **P*** | static-хелпер |
| `d2k_props_ask_traced` | 900–1191 | 292 | 5 вопросов по очереди: bind порт, SET_NAME_PROBE, ACK, contact, EXCHANGE/APPLIED/REFUSED, остановка на первом прошедшем | main.rs run_r2o_ask + ask.rs | **P** | логика перенесена; CLI differential не сравнивает stdout, отдельные ветви NO_ACK/UNSENT/APPLIED проверены unit |
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
| `d2k_arm_plan` | 1552–1751 | 200 | текст плана из arm (disorder/oob/seqovl/fake/ttl/tcpts) и проверки сочетаний | r2o_fallback::arm_plan / classify_measured | **P** | r2o-fallback-differential.sh покрывает 50 arm и 5 send_cap; произвольные сочетания arm не сравнивались |
| `d2k_compose` | 1763–1799 | 37 | набор планов из вектора свойств, decoy и send_cap | compose_d2o::compose_plan_texts | **E** | d2o_compose_differential.c + compose_d2o unit |

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
| `d2k_hkdf_expand_label` | 350–353 | 4 | HKDF-Expand-Label TLS 1.3 без контекста | crate hkdf + префикс tls13 | **P** | test-core-crypto-differential.sh: hkdf-client-in, hkdf-quic-key; отказ при label>249 не сравнивался |
| `d2k_hkdf_expand_label_ctx` | 355–427 | 73 | HKDF-Expand-Label TLS 1.3 с контекстом, границы label/ctx | crate hkdf + info-кодирование | **P** | test-core-crypto-differential.sh: hkdf-derived-ctx; границы label>249/ctx>32 в Rust-обёртке не проверялись |
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
| `parse_flag_u32` | 157–172 | 16 | u32 с автооснованием (0x/0) | ask::parse_mark | **P*** | static-хелпер; C принимает восьмеричные, Rust — 0x/десятичные |
| `parse_flag_ms` | 179–194 | 16 | положительное число мс | ask::parse_positive_ms | **P*** | static-хелпер |
| `parse_args` | 202–301 | 100 | разбор CLI d2kask и взаимные исключения hello/control | ask::parse_ask_options | **P** | набор флагов совпадает; Rust строже к --ip и повтору флагов (C берёт последний), коды ошибок отличаются |
| `hex_nibble` | 315–320 | 6 | значение hex-цифры | ask::decode_hex | **P*** | static-хелпер |
| `save_hex` | 329–349 | 21 | сохранение снимка ClientHello в hex-файл с комментарием | main.rs save_ask_snapshot (783) | **P** | реализовано; формат файла/ошибки не сравнивались |
| `read_hex_file` | 361–414 | 54 | чтение hex-файла с комментариями и пробелами | ask::read_hex_file | **P** | unit-тест ask.rs; C/Rust differential нет |
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
| `http_search_portal` | 168–174 | 7 | передать HTTP-портал в поиск обхода | http_search.rs | **P** | покрыто r2o-http-search-differential.sh частично |
| `hs_open_port` | 176–208 | 33 | открыть локальный TCP-порт с SO_MARK для HTTP-поиска | main.rs http search worker | **P** | реализовано; C/Rust differential на порт/марку нет |
| `hs_close_port` | 210–210 | 1 | закрыть порт HTTP-поиска | main.rs | **P*** | static-хелпер |
| `hs_hex` | 212–219 | 8 | скомпилировать HTTP-план в hex | plan_text::compile_text | **P** | использует plantlv; ошибки печатаются иначе |
| `hs_set_probe` | 221–233 | 13 | поставить пробный HTTP-план SET_NAME_PROBE | control::encode_set_name_probe | **P** | кодирование покрыто control tests |
| `hs_del_probe` | 235–244 | 10 | снять пробный HTTP-план | control::encode_delete_name_probe | **P** | кодирование покрыто control tests |
| `hs_set_plan` | 246–257 | 12 | поставить постоянный HTTP-план SET_NAME_BOUND | control::encode_set_name_bound | **P** | кодирование покрыто control tests |
| `hs_del_plan` | 259–269 | 11 | условно снять HTTP-план по binding | control::encode_delete_name_bound | **P** | кодирование покрыто control tests |
| `hs_start` | 271–274 | 4 | запустить HTTP-раннер | main.rs http search worker | **P** | жизненный цикл покрыт http-search differential частично |
| `hs_changed` | 277–284 | 8 | сохранить http-plans.txt | main.rs http_search persistence | **P** | формат/момент сохранения не сравнивались |
| `http_portal` | 288–308 | 21 | реакция на HTTP-портал: HTTPS-проба или SET_HTTPS | main.rs http portal path | **P** | покрыто HTTP differential частично |
| `http_push` | 310–315 | 6 | отправить SET_HTTPS имя/ttl | control::encode_set_https | **P** | кодирование покрыто control tests |
| `http_save` | 317–322 | 6 | сохранить кэш HTTPS | https_probe::save | **P** | формат кэша не сравнивался |
| `http_probe_done` | 324–355 | 32 | разобрать результаты HTTPS-проб, обновить кэш и датапат | https_probe::drain/results | **P** | покрыто r2o-httpsprobe/panel differentials частично |
| `hs_say` | 357–357 | 1 | журнал HTTP-поиска | main.rs log callback | **P*** | static-хелпер |
| `poison_cmp` | 365–367 | 3 | сортировка примет по successes | sort_by_key | **P*** | static-хелпер |
| `hs_measured_poisons` | 368–392 | 25 | взять измеренные poison-спеки из каталога (до 64, по успехам) | http_search::measured_poisons | **P** | реализовано; C/Rust differential нет |
| `usage` | 394–404 | 11 | справка d2kc с --control/--catalog/--live/--log/--https-cache/--mark/--measure-mark | main.rs help/--serve | **P** | R2O использует позиционные --serve СОКЕТ КАТАЛОГ и не имеет части флагов; текст другой |
| `offline_self_check` | 406–411 | 6 | офлайн-проверка wire-версии и SHA-256(abc) | main.rs --version/self-check | **P** | SHA-256 покрыт crypto differential; отдельного --self-check CLI нет |
| `diagnostic_event` | 415–417 | 3 | передать событие в диагностику | diagnostics::Recorder::record | **P** | дифференциал диагностики покрывает часть полей |
| `diagnostic_limit` | 418–420 | 3 | передать смену лимита в диагностику | diagnostics::Recorder::record_limit | **P** | то же |
| `diagnostic_tick` | 421–468 | 48 | включение/выключение diagnostics/, сэмпл раз в 60 с и запись report.json | diagnostics::Recorder::tick/write_report | **P** | unit diagnostic_tick_lifecycle_matches_d2o; C/Rust differential сравнивает только часть JSON |
| `main` | 470–931 | 462 | главный цикл d2kc: каталог, link, sched, https/httpsearch, poll, sync, save/live/report, health, graceful stop, exit 1 при потере link | main.rs serve_catalog + ControlClient + R2oCatalogPersistence + diagnostics | **P** | есть process/persistence/diagnostics tests; отсутствуют --measure-mark, --log, --health-file, --https-cache=, --release-id, --self-check и периодическая сводка событий; --serve CLI не совпадает |

### `core/d2kfetch.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `json_string` | 41–62 | 22 | JSON-экранирование строки с проверкой UTF-8 | serde_json::to_string | **P*** | static-хелпер; serde_json может иначе экранировать невалидный UTF-8 |
| `vol_verdict_code` | 64–72 | 9 | код вердикта объёмной лестницы | bin/r2o-fetch.rs:227 match R2oFetchVolumeTxVerdict | **P** | строки unreachable/cut/passed/short совпадают; CLI-differential не проверяет |
| `usage` | 74–102 | 29 | справка d2kfetch | r2o-fetch print_help | **P** | набор флагов расширен (--quic-budget/--control); текст отличается |
| `resolve_first` | 104–114 | 11 | первый адрес getaddrinfo AF_UNSPEC/SOCK_STREAM | std::net::ToSocketAddrs | **P** | порядок/семейство может отличаться от getaddrinfo; проверяется только localhost в r2o-fetch-cli-differential.sh |
| `snapshot_wire` | 117–155 | 39 | ловушка ARM_SHAPE и ожидание D2K_EV_SHAPE с дедлайном | fetch::r2o_fetch_snapshot_wire_len + r2o_fetch_cli/snapshot tests | **P** | Rust-тесты снимка есть; C/Rust differential снимка не найден |
| `main` | 157–356 | 200 | CLI d2kfetch: name/ip/port/path/wire/snapshot/ladder/quic/tls12/deadline/mark/json/version | r2o-fetch bin + fetch.rs | **P** | известные расхождения: level не выдаёт 5/6, name_ok выводится из TLS, location всегда строка; r2o-fetch-cli-differential.sh сравнивает только DNS-fail и QUIC-refusal |

### `core/d2kvoice.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `usage` | 22–37 | 16 | текст справки d2kvoice | main.rs r2o_voice_check_command help text (819) | **P** | флаги те же, текст/формат командной строки отличается; CLI-дифференциала нет |
| `split_hostport` | 39–48 | 10 | разбор IP:ПОРТ по последнему двоеточию | main.rs r2o_voice_check_command parse (819) | **P*** | static-хелпер; IPv6-литерал в C всё равно отвергается d2k_ip4_parse |
| `verdict_word` | 50–61 | 12 | русский текст вердикта голосового замера | voice_measure::r2o_format_voice_measurement | **P** | строки совпадают; формат всего вывода не сравнивался |
| `main` | 63–135 | 73 | CLI d2kvoice: --addr/--control/--conntrack/--wait/--mark/--list/--discovery, печать вердикта, exit 0/1/2 | main.rs r2o_voice_check_command/r2o_voice_list_command (819/843) + voice_measure/voice_targets | **P** | есть unit/voice и Discord differential; известны расхождения: C --wait 0 => default 3000, Rust 0; --voice-list принимает только --conntrack; блок «Приём» может отличаться |

### `core/diagnostics.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `copy` | 98–104 | 7 | копирование строки с обрезкой по UTF-8 | diagnostics::truncate_utf8 | **P*** | static-хелпер |
| `js` | 105–130 | 26 | JSON-экранирование с проверкой UTF-8 | serde_json | **P*** | static-хелпер; serde_json иначе обрабатывает невалидные последовательности |
| `number` | 131–131 | 1 | число или null для отрицательного | serde_json::Value | **P*** | static-хелпер |
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
| `d2k_diag_record` | 192–201 | 10 | записать событие поиска в кольцо (64) | Recorder::record | **P** | differential сравнивает event_json частично |
| `d2k_diag_record_limit` | 202–212 | 11 | записать переход лимита (32) | Recorder::record_limit | **P** | unit/differential частично |
| `value` | 213–217 | 5 | число после ключа в /proc | diagnostics::meminfo/read_number | **P*** | static-хелпер |
| `compact_kib` | 218–220 | 3 | сжать KiB в i32 или -1 | diagnostics compact | **P*** | static-хелпер |
| `compact_bytes_kib` | 221–221 | 1 | байты в KiB с округлением вверх или -1 | diagnostics compact | **P*** | static-хелпер |
| `compact_bytes` | 222–222 | 1 | байты в i32 или -1 | diagnostics compact | **P*** | static-хелпер |
| `compact_count` | 223–223 | 1 | счётчик в u8 с насыщением | diagnostics compact | **P*** | static-хелпер |
| `proc_pid_dir_present` | 225–229 | 5 | существует ли /proc/<pid> как каталог | diagnostics::process_detail | **P*** | static-хелпер |
| `optional_proc_status` | 230–237 | 8 | различить unsupported/unavailable для smaps_rollup | diagnostics::read_smaps_rollup | **P*** | static-хелпер |
| `read_proc` | 238–259 | 22 | pid из pid-файла, comm, VmRSS/HWM/Anon/Threads/VmData/VmSwap | diagnostics::process_memory | **P** | unit process_memory_follows_pidfiles_and_restarts; C-oracle нет |
| `read_detail` | 260–304 | 45 | stat starttime, VmSize/Data/Stk/Swap, fd_count, smaps_rollup | diagnostics::process_detail | **P** | unit first_process_detail_survives_process_exit |
| `read_status` | 305–309 | 5 | код статуса smaps_rollup в строку | diagnostics::read_status | **P*** | static-хелпер |
| `write_detail` | 310–328 | 19 | JSON memory_detail процесса | diagnostics memory_details | **P** | unit/differential частично |
| `write_limit_reason` | 329–343 | 15 | JSON limit_reason по counts | diagnostics::limit_reason_values | **P** | unit diagnostics_id_and_counts_match_d2o |
| `write_limit_reason_state` | 344–356 | 13 | JSON limit_reason по flags/mask | diagnostics::limit_reason_values | **P** | unit |
| `write_memory_tracking` | 357–369 | 13 | JSON memory_tracking (сайты, coverage) | diagnostics::memory_tracking_json | **P** | unit memory_tracking_and_madvise_json_match_d2o_shape |
| `write_madvise` | 370–381 | 12 | JSON madvise (success/fail/errno-гистограмма) | diagnostics::madvise_json | **P** | unit |
| `write_anomalies` | 382–394 | 13 | JSON аномалий и счётчиков перезаписи | Recorder::write_report | **P** | unit records_only_while_enabled |
| `d2k_diag_sample` | 395–468 | 74 | сэмпл раз в 60 с: meminfo, conntrack, процессы, история памяти, детектор неучтённого RSS-роста | Recorder::tick/process_memory | **P** | unit d2o_periodic_rss_sample_matches_c и first_process_detail; полный C differential не сравнивает все поля |
| `d2k_diag_write` | 469–605 | 137 | сериализация report.json schema=1 (события, лимиты, память, сэмплы, процессы) | Recorder::write_report + serde_json | **P** | r2o-diagnostics-differential.sh сравнивает ring_bytes/event/snapshots/http_records; остальные поля — unit, не C/Rust diff |

### `core/domain.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_domain_normalize` | 6–29 | 24 | строгая нормализация DNS-имени: lower-case, метки, длина, запрет IP | domain::normalize | **P** | unit tests/domain.rs; R2O дополнительно отвергает односоставные имена (labels<2), C — нет; C/Rust differential не найден |
| `rule_exists` | 31–40 | 10 | бинарный поиск правила в сгенерированном PSL | psl crate (suffix lookup) | **P*** | static-хелпер; таблица PSL заменена crate psl |
| `d2k_domain_base` | 42–64 | 23 | регистрируемый домен по PSL: longest rule, exception, wildcard | domain::registrable_domain | **P** | unit tests/domain.rs (private wildcard/exception); прямого сравнения с C PSL-таблицей нет |
| `d2k_domain_member` | 66–72 | 7 | проверка вхождения имени в суффикс по границе метки | domain::is_member | **P** | unit tests/domain.rs; R2O требует известный registrable suffix, C — только normalize+base |

### `core/groups.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_group_key_make` | 9–17 | 9 | собрать ключ области (transport/family/shape/path/ech_origin) с проверкой длин | catalog::GroupKey (From/validate_key) | **P** | ключ и ограничения перенесены; C/Rust differential групп нет |
| `d2k_group_key_same` | 19–23 | 5 | сравнить ключи области | GroupKey PartialEq | **P** | unit tests/groups.rs |
| `valid` | 24–36 | 13 | валидация наблюдения: NUL, семейство, транспорт/форма, evidence | groups::learn/restore + validate_key | **P** | unit tests/groups.rs (rejects invalid/ambiguous) |
| `member` | 38–41 | 4 | вхождение имени в суффикс по границе метки | groups::member | **P*** | static-хелпер; unit tests/groups.rs |
| `votes` | 45–60 | 16 | подсчёт живых/устаревших голосов за суффикс (>=2, >stale, >=3) | groups::votes | **P** | unit tests/groups.rs; семантика совпадает, C-oracle нет |
| `failures` | 61–71 | 11 | число PLAN_FAILED для суффикса/ключа/плана | groups::failures | **P*** | static-хелпер; unit tests/groups.rs |
| `add_group` | 72–102 | 31 | добавить/заменить группу с выбором по failures, count, at, plan_id | groups::add_group | **P** | unit tests/groups.rs |
| `rebuild` | 103–120 | 18 | перестроить группы из BLOCKED-наблюдений и голосов | groups::rebuild | **P** | unit tests/groups.rs |
| `cover` | 122–132 | 11 | самый длинный покрывающий суффикс для ключа | groups::covering_group | **P*** | static-хелпер |
| `d2k_group_learn` | 133–245 | 113 | приём наблюдения: дедуп, замена, admitted exception, переполнение/frozen/disabled, rebuild | groups::learn | **P** | unit tests/groups.rs покрывают дедуп, исключения, capacity reenable; побитовое совпадение с C не сравнивалось |
| `d2k_group_restore` | 246–273 | 28 | валидация и канонизация сохранённых наблюдений, rebuild | groups::restore + canonical_evidence | **P** | unit tests/groups.rs; R2O ввёл OPERATOR_REJECT, которого нет в C |
| `d2k_group_match` | 274–293 | 20 | выбор группы для имени с учётом исключений и PLAN_FAILED | groups::match_domain | **P** | unit tests/groups.rs; C/Rust differential нет |
| `d2k_group_forget` | 294–310 | 17 | удалить PLAN_FAILED-наблюдения имени/транспорта/семейства и rebuild | groups::forget_failures | **P** | unit tests/groups.rs |
| `d2k_group_expire` | 311–324 | 14 | удалить PLAN_FAILED старше max_age и rebuild | groups::expire_failures | **P** | unit tests/groups.rs |

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
| `send_name_plan` | 538–630 | 93 | общий кодировщик name-команды: имя/shape/family/plan hex/trial id, проверки | control::encode_set_name* | **P*** | static-хелпер; точные кадры в tests/control.rs, C/Rust diff нет |
| `d2k_link_set_name_family` | 632–637 | 6 | SET_NAME/SET_NAME_PROBE по family | control::encode_set_name | **P** | unit-тест; C/Rust diff нет |
| `d2k_link_set_name_bound` | 639–643 | 5 | SET_NAME_BOUND с identity | control::encode_set_name_bound | **P** | unit bound_set_name_round_trips; C/Rust diff нет |
| `d2k_link_del_name_bound` | 645–657 | 13 | условное удаление name binding | control::encode_delete_name_bound | **P** | unit encodes_a_bounded_exact_name_binding_delete; C/Rust diff нет |
| `d2k_link_set_name_probe_trial` | 659–668 | 10 | SET_NAME_PROBE с trial_id | control::encode_set_name_probe | **P** | unit-тест; C/Rust diff нет |
| `area_context_valid` | 670–675 | 6 | допустимая комбинация transport/shape/family для области | control::valid_domain_area_context | **P*** | static-хелпер |
| `d2k_link_set_suffix_family` | 677–684 | 8 | SET_SUFFIX с планом | control::encode_set_suffix | **P** | кодировщик есть; точный C/Rust differential области не заявлен |
| `d2k_link_set_https` | 686–705 | 20 | SET_HTTPS имя+ttl | `control.rs:1777-1790` `encode_set_https` | **P** | **Расхождение:** C-link проверяет только имя (1..253) и кодирует любой `u32 ttl`; обрезку до `D2K_HTTPS_TTL_MAX_S` делает датапат (`ctlsrv.c:446`). Rust-link отвергает `ttl > MAX_HTTPS_TTL_SECONDS` (6 ч) ещё на кодировании. Наблюдаемый итог для сверх-6ч различается стадией (C: обрезка, R2O: отказ). Unit `encodes_the_exact_https_name_and_ttl` покрывает только допустимый TTL. |
| `d2k_link_set_stall_budgets` | 707–729 | 23 | SET_STALL_BUDGETS список бюджетов | control::encode_set_tcp_stall_budgets | **P** | unit бюджеты tcp/reset; C/Rust diff нет |
| `send_area_key` | 731–752 | 22 | общий кодировщик domain-area команд (name/key/area_id) | control::encode_domain_area_key | **P*** | static-хелпер |
| `d2k_link_del_suffix_family` | 754–757 | 4 | DEL_SUFFIX | control::encode_delete_suffix | **P** | кодировщик есть; C/Rust differential нет |
| `d2k_link_set_bypass_family` | 758–761 | 4 | SET_BYPASS | control::encode_set_bypass | **P** | кодировщик есть; differential нет |
| `d2k_link_del_bypass_family` | 762–765 | 4 | DEL_BYPASS | control::encode_delete_bypass | **P** | кодировщик есть; differential нет |
| `d2k_link_area_identified` | 767–777 | 11 | area-команда с identity/area_id | control::encode_set_suffix/encode_domain_area_key | **P** | unit area_ack_round_trips; C/Rust differential нет |
| `addr_shape_ok` | 783–787 | 5 | допустимая форма адресной привязки | control::valid_addr_shape | **P*** | static-хелпер |
| `d2k_link_set_addr` | 789–792 | 4 | SET_ADDR IPv4 | control::encode_set_addr | **P** | unit-тест адресных планов; C/Rust diff нет |
| `d2k_link_set_addr_family` | 794–848 | 55 | SET_ADDR family 4/6, проверка shape/hex/размера | control::encode_set_addr | **P** | unit-тест; C/Rust diff нет |
| `addr_probe_flow_bytes` | 852–866 | 15 | 38-байтный ключ UDP-потока для addr-probe | control::udp_addr_probe_flow | **P*** | static-хелпер; control tests |
| `d2k_link_set_addr_probe` | 868–875 | 8 | SET_ADDR_PROBE IPv4 | control::encode_set_addr_probe | **P** | unit/quic_replay/voice tests; C/Rust diff нет |
| `d2k_link_set_addr_probe_family` | 877–909 | 33 | SET_ADDR_PROBE с lease/trial/plan | control::encode_set_addr_probe | **P** | unit-тест; C/Rust diff нет |
| `d2k_link_del_addr_probe` | 911–917 | 7 | DEL_ADDR_PROBE IPv4 | control::encode_delete_addr_probe | **P** | unit-тест; C/Rust diff нет |
| `d2k_link_del_addr_probe_family` | 919–937 | 19 | DEL_ADDR_PROBE family 4/6 | control::encode_delete_addr_probe | **P** | unit-тест; C/Rust diff нет |
| `d2k_link_arm_shape` | 939–942 | 4 | ARM_SHAPE IPv4 | control::encode_arm_shape | **P** | unit arm_shape_roundtrip; C/Rust diff нет |
| `d2k_link_arm_shape_family` | 944–979 | 36 | ARM_SHAPE: имя, transport 6/17, family 4/6 | `control.rs:902-915` `encode_arm_shape` | **P** | Кодирование совпадает: C и Rust принимают transport 6/17, family 4/6, имя до 253/255. **Но** датапат R2O `arm_client_shape` (`control.rs:2002`) отвергает transport 17, а C `ctlsrv.c:329` принимает 6/17 — это уже зафиксированное расхождение конца пути, не link-кодера. |
| `d2k_link_del_name_family` | 981–1012 | 32 | DEL_NAME с shape/family | control::encode_delete_name | **P** | unit-тест; C/Rust diff нет |
| `d2k_link_del_name_probe` | 1014–1018 | 5 | DEL_NAME_PROBE IPv4 | control::encode_delete_name_probe | **P** | кодировщик есть; unit/дифференциала именно для DEL_NAME_PROBE не найдено |
| `d2k_link_del_name_probe_family` | 1020–1049 | 30 | DEL_NAME_PROBE: имя, shape, family 4/6, source port | `control.rs:1906-1926` `encode_delete_name_probe` | **P** | **Расхождение:** C-link не проверяет `shape` вовсе (только имя/порт/family), Rust требует `valid_tcp_probe_shape(shape)` и отвергает неизвестную форму. C-датапат всё равно отверг бы такую команду, но отказ происходит позже. Точный кадр C/Rust не сравнивался. |
| `d2k_link_del_addr` | 1051–1054 | 4 | DEL_ADDR IPv4 | control::encode_delete_addr | **P** | unit-тест; C/Rust diff нет |
| `d2k_link_del_addr_family` | 1056–1076 | 21 | DEL_ADDR family 4/6 | control::encode_delete_addr | **P** | unit-тест; C/Rust diff нет |
| `d2k_ev_outer_appdata` | 1079–1094 | 16 | есть ли в обмене TLS application data (бит 23) | r2k_core::control event seen_types | **P*** | static-хелпер; events tests |

### `core/match.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `same_evidence` | 38–73 | 36 | совместимость одной улики: volume±4, ttl±2, tos/ipid точно | catalog::same_signal | **P*** | static-хелпер; unit tests/catalog.rs |
| `d2k_fp_same` | 75–125 | 51 | совместимость отпечатков: method, все роды сигналов, хотя бы один общий | catalog::Fingerprint::is_compatible_with | **P** | unit tests/catalog.rs (partial evidence, all same-kind signals); C/Rust differential нет |
| `d2k_catalog_match` | 127–136 | 10 | поиск коробки по отпечатку | catalog::Catalog::match_fingerprint | **P** | unit tests/catalog.rs |

### `core/meas.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `nap_us` | 52–55 | 4 | пауза между кусками отправки | std::thread::sleep | **P*** | static-хелпер; тайминг не сравнивался |
| `d2k_mark_real` | 61–70 | 10 | SO_MARK на сокете зонда | setsockopt в response/raw_probe | **P*** | static-хелпер платформенного слоя |
| `d2k_accept_serverhello` | 87–94 | 8 | принять только TLS ServerHello | `classify.rs:543-547` `trigger_accepts(Accept::ServerHello)` | **P** | Байтовое правило совпадает: `len>=6`, record type `0x16`, major `0x03`, handshake type `0x02`. Целевого C/Rust differential нет; правило используется в `response.rs:882` и покрыто тестами `response.rs:1442-1463`. |
| `d2k_accept_tls_record` | 96–99 | 4 | принять TLS handshake/alert запись | `classify.rs:548-550` `trigger_accepts(Accept::TlsRecord)` | **P** | Совпадает: `len>=3`, type `0x16|0x15`, major `0x03`. Используется для белого ClientHello (`main.rs:34054`), но отдельного C/Rust differential на accept нет. |
| `d2k_accept_any` | 101–104 | 4 | принять любой непустой ответ | `classify.rs:551` `trigger_accepts(Accept::Any)` | **P** | Совпадает: `!bytes.is_empty()`. Покрыто сокетными тестами `response.rs:1480-1528`, не C-оракулом. |
| `cuts_valid` | 109–116 | 8 | проверка строго возрастающих разрезов внутри приветствия; любой плохой разрез — отказ всего опыта | `classify.rs:28-56` `split_offsets` фильтрует/сортирует; `raw_probe.rs:1150` требует ровно один разрез | **P** | **Расхождение:** C отвергает весь опыт при `cut<=prev` или `cut>=len`; R2O `split_offsets` молча выбрасывает такие разрезы, сортирует и берёт первые 8. Raw-путь R2O при `cuts.len()!=1` возвращает `Local("invalid cut")`, тогда как C штатно шлёт несколько разрезов через сокет. Нужен differential на несколько/невалидные разрезы. |
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
| `template_plan` | 57–82 | 26 | шаблон tcp-template-v1: hello в payload, poison badsum/tcpts/autottl, fake ×8, split | `r2o_rx_volume.rs:26-58` `r2o_rx_volume_plan_for_client` | **P** | C-фикстуры `r2o-rx-volume-hcaptcha-split2-c.txt` и `split5-c.txt` покрывают ветку `tcpts` (client_has_ts=1) и точный текст; ветка `autottl=1,2-12` проверена unit-тестом `r2o_rx_volume.rs:112-128`, но не C-фикстурой. C `badsum`-ветка в этом шаблоне не покрыта. |
| `d2k_rx_volume_plan_named` | 84–88 | 5 | RX-volume план с явным именем (всегда client_has_ts=1) | `r2o_rx_volume.rs:21-23` `r2o_rx_volume_plan` | **P** | Обёртка `for_client(..., true)` совпадает; C-фикстуры покрывают variant 0/4 и длинное имя, варианты 1/2/3 — только unit `r2o_rx_volume.rs:94-110`. C дополнительно проверяет `shape==MODERN`; в Rust параметра shape нет (см. `client`). |
| `d2k_rx_volume_plan_client` | 90–110 | 21 | RX-volume план с учётом TCP timestamps клиента | `r2o_rx_volume.rs:26-58` `r2o_rx_volume_plan_for_client` | **P** | **Расхождение сигнатуры:** C отвергает `shape != D2K_SHAPE_MODERN` (`measured.c:96-98`), R2O shape не принимает и всегда строит modern-план. Ветка `client_has_ts=0` (autottl) есть только в unit-тесте `r2o_rx_volume.rs:112-128`, C-фикстуры для неё нет. |
| `d2k_rx_volume_plan` | 114–117 | 4 | RX-volume план для hcaptcha.com | r2o_rx_volume::r2o_rx_volume_plan | **E** | та же C-фикстура варианта 0 |
| `measured_payload` | 121–138 | 18 | `payload-pad64 ID LEN 15 [base64(prefix)]`, префикс обрезается до LEN | `classify_measured.rs:381-399` `append_measured_payload`, `:401-425` `base64` | **P** | Формат и обрезка `prefix_len>len` совпадают; base64-таблица стандартная, паддинг `=` для 1/2 байт. C-фикстуры покрывают обычные payload, но не границы 1/2/3 байта и не пустой префикс; отдельного C/Rust differential нет. |
| `d2k_tcp_split_plan` | 140–151 | 12 | план split payload_start с gap и сегментом под `send_cap` | `main.rs:6292` `r2o_discovery_measured_split_plan` | **E** | `scripts/r2o-measured-split-differential.sh` компилирует `tests/d2o_measured_split_differential.c` с `core/measured.c` и сравнивает вывод с Rust для `send_cap` 0/1492/1280/100/72, split 0/1/1024, verdict prefix/whole. Тест `main.rs:28767` формирует тот же вывод; сегмент `send_cap-72 min 1400` совпадает с `d2k_arm_segment`. |
| `d2k_arm_plan_measured_cap` | 153–385 | 233 | сборка измеренного плана: split-only, template, disorder, oob, fake/between/seqovl, ttl/md5/tcpts/tsup/ipidzero/autottl, выбор minexec и segment | `classify_measured.rs:45-378` `measured_plan_text` | **P** | **Конкретные пробелы:** (1) `Poison` (`classify.rs:127-146`) не содержит `autottl` и `tcpts_up`, поэтому R2O не может собрать ветви `a->autottl` (C `measured.c:343-345`) и `a->tcpts_up` (`:349`); (2) `segment` жёстко 1400 (`classify_measured.rs:12,143`), тогда как C берёт `d2k_arm_segment(send_cap)` (`measured.c:170`, `d2k_arm.h:79-82`) — на `send_cap=1280` C даёт 1208; (3) C `minexec=13` при autottl, Rust — 5/12. Остальные ветви (split/oob/disorder/seqovl/md5/tcpts/ipidzero) перенесены; C-фикстуры покрывают обычные fake/split/oob, редкие — unit. |
| `d2k_arm_plan_measured` | 387–390 | 4 | обёртка `d2k_arm_plan_measured_cap(..., send_cap=0)` | `classify_measured.rs:30-37` `plan_text_for_poison(..., send_cap=0)` | **P** | Обёртка совпадает; все пробелы те же, что у `d2k_arm_plan_measured_cap`. |

### `core/net4.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_ip4_parse` | 7–30 | 24 | строгий разбор IPv4-литерала в сетевой порядок | std::net::Ipv4Addr::from_str | **P** | **Расхождение:** C принимает ведущие нули (`010.0.0.1`), Rust 1.98 — `Err(AddrParseError(Ipv4))` (проверено `rustc`). `test-core-net4-differential.sh` покрывает обычные/битые литералы, но не ведущие нули. |
| `d2k_ip4_text` | 32–38 | 7 | IPv4 в текст | std::net::Ipv4Addr Display | **E** | test-core-net4-differential.sh |
| `d2k_ip4_private` | 40–51 | 12 | классификация приватных/специальных IPv4 (loopback, RFC1918, link-local, CGNAT, 0) | r2o_quic_address_is_local / is_private | **E** | test-core-net4-differential.sh; политика локальных адресов также покрыта r2o-quic-local-address-differential.sh |
| `d2k_ip6_private` | 53–64 | 12 | классификация приватных/специальных IPv6 (::, ::1, ULA, link-local, mcast, v4-mapped) | std::net::Ipv6Addr::is_unique_local/is_unicast_link_local + v4-mapped проверка | **E** | test-core-net4-differential.sh |

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
| `d2k_p256_public` | 268–280 | 13 | P-256 public key из приватного скаляра | `ring` SECP256R1 / `r2o_tls.rs:95,101,288` | **P** | Production-путь: `core/tls12.c:655` вызывает keypair/ecdh для ECDHE secp256r1. Отдельного публичного P-256 API в R2O нет; `d2k_p256_public` используется внутри `d2k_p256_keypair`, прямых C/Rust-векторов нет. |
| `d2k_p256_keypair` | 282–289 | 8 | генерация ключевой пары P-256 с отбраковкой скаляра (до 16 попыток) | `ring::agreement::EphemeralPrivateKey` | **P** | **Production:** `core/tls12.c:650-655` (ECDHE TLS 1.2). R2O генерирует ключ внутри `ring`; явная retry-политика 16 попыток и C-векторы не проверены. |
| `d2k_p256_ecdh` | 291–316 | 26 | ECDH P-256 с проверкой точки на кривой | `ring::agreement` (P256) | **P** | **Production:** `core/tls12.c:655`. Проверка точки делегирована `ring`; C-векторы ECDH и поведение при точке не на кривой не сравнивались. |

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
| `original_probe` | 35–44 | 10 | hook исходного QUIC-замера: probe с SNI цели/без SNI для control | r2o_quic_http3 / quic_replay hooks | **P*** | static-хелпер; QUIC differentials |
| `original_data` | 47–50 | 4 | hook данных исходного QUIC-замера (path/port/wait/mark) | r2o_quic_http3 | **P*** | static-хелпер |
| `wire_measure` | 52–78 | 27 | обёртка arm-контекста: подмена probe/data, извлечение SNI, перенос next/marked/path | quic_replay::R2oQuicArmContext | **P** | QUIC-обвязка перенесена; отдельного C/Rust differential для этой обёртки нет |
| `d2k_quic_original_measure` | 80–83 | 4 | QUIC-замер исходным набором arm | quic_replay + r2o_quic_http3 | **P** | покрыто QUIC differentials на уровне результатов |
| `d2k_quic_strategy_measure` | 88–91 | 4 | QUIC-замер стратегий (split/frag/ttl/length/fake) | quic_replay strategy arms | **P** | покрыто r2o-quic-* differentials частично |

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
| `verdict_name` | 1647–1662 | 16 | русское имя вердикта | classify::Verdict::as_str/описания | **P*** | static-хелпер; строки близки, но не сверялись |
| `signal_of` | 1672–1694 | 23 | превратить событие отказа в cat_signal (rst/repeat/silent, ttl/tos/ipid) | main.rs r2o_discovery_suspect_signal | **P** | unit scheduler/classifier; C/Rust differential нет |
| `is_rx_volume_kind` | 1699–1701 | 3 | kind является rx-volume/rx-volume-wire | catalog Signal kind check | **P*** | static-хелпер |
| `fp_add` | 1703–1730 | 28 | добавить/слить сигнал в отпечаток с допусками TTL/volume | catalog::Fingerprint merge | **P** | unit catalog fingerprint; C/Rust differential нет |
| `volume_bucket` | 1746–1751 | 6 | логарифмическая корзина объёма | r2o_discovery_volume_bucket | **P*** | static-хелпер |
| `is_volume_kind` | 1753–1755 | 3 | kind является volume/rx-volume | catalog Signal kind check | **P*** | static-хелпер |
| `box_volume_bucket_agrees` | 1760–1772 | 13 | совпадение volume-корзины коробки и отпечатка | main.rs r2o_discovery_volume_known_plans | **P** | реализовано; differential нет |
| `server_is_low` | 1798–1805 | 8 | определить, какой конец потока сервер (ephemeral/port) | main.rs discovery endpoint helper | **P*** | static-хелпер |
| `client_ip_of` | 1807–1811 | 5 | IP клиента из события | main.rs discovery endpoint helper | **P*** | static-хелпер |
| `server_of` | 1813–1822 | 10 | IP:port сервера из события | main.rs discovery endpoint helper | **P*** | static-хелпер |
| `same_flow` | 1824–1830 | 7 | сравнение запомненного потока с событием | main.rs discovery flow key | **P*** | static-хелпер |
| `remember` | 1841–1862 | 22 | запомнить имя для потока (64 слота) | main.rs discovery seen-name ring | **P** | unit discovery.rs; C/Rust differential нет |
| `recall` | 1864–1869 | 6 | вспомнить имя по потоку | main.rs discovery seen-name ring | **P*** | static-хелпер |
| `cooldown_find_endpoint` | 1871–1884 | 14 | найти cooldown endpoint по name/transport/family/ip/port | main.rs R2oDiscoveryCooldownRing | **P*** | static-хелпер |
| `cooldown_find_challenge` | 1886–1897 | 12 | найти challenge-cooldown по имени | main.rs R2oDiscoveryCooldownRing | **P*** | static-хелпер |
| `dead_find` | 1899–1910 | 12 | найти мёртвый адрес | main.rs discovery dead-address ring | **P*** | static-хелпер |
| `dead_step` | 1915–1935 | 21 | увеличить streak мёртвого адреса и выдать backoff | main.rs R2oDiscoveryCooldownRing/queue: dead-address backoff | **E** | r2o-scheduler-dead-address-differential.sh |
| `dead_clear` | 1937–1940 | 4 | снять мёртвый адрес после успеха | main.rs discovery dead clear | **E** | r2o-scheduler-dead-address-differential.sh |
| `is_late_volume_suspicion` | 1942–1946 | 5 | код относится к позднему закрытию (RST_AFTER_APP/FIN_RETRY/TCP_STALL) | main.rs r2o_discovery_late_trigger | **P*** | static-хелпер |
| `cooldown_blocks` | 1948–1973 | 26 | проверить активный cooldown с учётом challenge/exhausted/late_rst_only/кода | main.rs R2oDiscoveryCooldownRing::blocks | **E** | r2o-scheduler-cooldown-differential.sh |
| `cooldown_clear_endpoint` | 1975–1980 | 6 | снять endpoint-cooldown | main.rs discovery cooldown clear | **E** | r2o-scheduler-cooldown-differential.sh |
| `cooldown_clear_nonchallenge` | 1982–1998 | 17 | снять не-challenge cooldown (опционально exhausted/ECH) | main.rs discovery cooldown clear_nonchallenge | **P** | используется в ECH/QUIC путях; отдельного differential нет |
| `clear_backoff_ms` | 2000–2004 | 5 | backoff после CLEAR: 30/60/120 мин | main.rs r2o_discovery_clear_retry_after | **E** | r2o-scheduler-cooldown-differential.sh |
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
| `client_offers_ts` | 2286–2301 | 16 | несёт ли клиент TCP timestamps (по опциям или профилю) | main.rs discovery client_offers_ts | **P** | классификатор использует; C/Rust differential нет |
| `client_tcp_profile` | 2303–2318 | 16 | профиль TCP клиента: unknown/no-ts/ts | main.rs discovery client_tcp_profile | **P** | то же |
| `flowkey_same` | 2320–2325 | 6 | сравнение flowkey | main.rs discovery flow key | **P*** | static-хелпер |
| `take_shape_opts` | 2328–2341 | 14 | перенести TCP-опции снимка в задачу | main.rs discovery take_shape_opts | **P*** | static-хелпер |
| `drop_client_opts` | 2342–2345 | 4 | сбросить TCP-опции клиента | main.rs discovery drop_client_opts | **P*** | static-хелпер |
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
| `worker_run_body` | 2741–3253 | 513 | тело worker: VOICE/VERIFY/CONTACT/addr-recheck/ECH/baseline/volume/classify и фиксация результата | main.rs discovery worker + classify/verify/voice/fetch | **P** | крупная функция; ветви покрыты множеством differentials, но не все комбинации ECH/volume/addr |
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
| `prop_send_next` | 3864–3970 | 107 | следующий вопрос свойств: план, bind, mark, SET_NAME, JOB_CONTACT | main.rs discovery prop_send_next | **P** | логика перенесена; ask/scheduler differentials частично |
| `prop_finish` | 3974–3989 | 16 | завершить опрос свойств и запросить sync | main.rs discovery prop_finish | **P*** | static-хелпер |
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
| `verdict_to_plans` | 5209–5551 | 343 | по вердикту собрать кандидатов: ECH trial, QUIC arm, known plans, measured arm, RX-лестница, split, fallback, compose | main.rs discovery verdict_to_plans | **P** | крупная ветвистая функция; known/own-first/fallback/QUIC differentials покрывают часть |
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
| `verify_confirm` | 9262–9653 | 392 | подтвердить кандидата: ECH/QUIC/форма/budget, bind_confirmed, группа, адресный план, сеть, live, report, T_WATCHING | main.rs r2o_confirm_discovery_outcome (5347) + apply_discovery_outcome (21856) | **P** | ack-applied/budget/ECH differentials покрывают часть; крупная функция |
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
| `d2k_sched_tick` | 10784–12364 | 1581 | главный тик: clock, ресурсы, wake, QUIC yield/deny, группы, sync, все состояния задач, очередь, voice, диагностика | main.rs R2oDiscoverySearches (7971)/ControlClient event loop + r2o_resource_limit | **P** | крупнейшая функция; scheduler/queue/cooldown/dead/own-first/resource/voice differentials покрывают основные ветви, полная матрица состояний — нет |

### `core/verdict.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `looks_like_tls` | 33–35 | 3 | выбрать accept-фильтр по первому байту приветствия | classify::Trigger::accept | **P*** | static-хелпер; в R2O accept задаётся при сборке Trigger |
| `reverse_note` | 53–62 | 10 | пояснение о непроверенном обратном направлении | classify.rs reason | **P*** | static-хелпер; текст причины не совпадает дословно |
| `pause_note` | 74–80 | 7 | текст о паузе между кусками | classify.rs reason | **P*** | static-хелпер; текст причины не совпадает |
| `stop_requested` | 92–94 | 3 | проверка флага отмены | AtomicBool cancel | **P*** | static-хелпер |
| `classify_cancelled` | 96–102 | 7 | вердикт inconclusive при отмене | classify::finish_cancelled | **P** | реализовано; API/текст отличаются, C-путь verdict.c в d2kc не используется |
| `d2k_classify_cancelable` | 104–334 | 231 | дерево классификации TCP: база, подтверждение clear, разрез 1, контроль, prefix/opaque/inconclusive | classify::run_with_backend + measure + finish | **P** | дерево перенесено в classify.rs (full_detect_semantics и response-стадии добавлены); classifier differentials покрывают базовые вердикты, но не все тексты/отмену исходного API |
| `d2k_classify` | 336–342 | 7 | обёртка классификации без отмены | classify::run | **P** | см. d2k_classify_cancelable |

### `core/x25519.c`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `car25519` | 32–50 | 19 | перенос 16-словного поля 2^255-19 | crate x25519-dalek/hpke | **P*** | static-хелпер; отдельной арифметики нет |
| `sel25519` | 54–61 | 8 | константное переключение двух элементов поля | crate x25519-dalek | **P*** | static-хелпер |
| `pack25519` | 63–82 | 20 | упаковка элемента поля в 32 байта | crate x25519-dalek | **P*** | static-хелпер |
| `unpack25519` | 84–89 | 6 | распаковка 32 байт в элемент поля | crate x25519-dalek | **P*** | static-хелпер |
| `A` | 91–91 | 1 | сложение элементов поля 2^255-19 | crate x25519-dalek | **P*** | static-хелпер |
| `Z` | 92–92 | 1 | вычитание элементов поля 2^255-19 | crate x25519-dalek | **P*** | static-хелпер |
| `M` | 94–104 | 11 | умножение элементов поля 2^255-19 | crate x25519-dalek | **P*** | static-хелпер |
| `S` | 106–106 | 1 | возведение в квадрат в поле 2^255-19 | crate x25519-dalek | **P*** | static-хелпер |
| `inv25519` | 109–117 | 9 | обращение в поле 2^255-19 | crate x25519-dalek | **P*** | static-хелпер |
| `d2k_x25519` | 119–168 | 50 | X25519 ECDH, отказ при нулевом результате | crate x25519-dalek / hpke | **P** | используется в hpke/ECH и TLS1.3; прямых C/Rust векторов X25519 не найдено (ECH-дифференциалы косвенные) |
| `d2k_x25519_base` | 170–198 | 29 | X25519 от базовой точки 9 | crate x25519-dalek | **P** | public key внутри hpke; отдельного differential с C нет |

### `core/include/d2k_link.h`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_link_shape_tcp_profile` | 309–319 | 11 | профиль TCP (unknown/no-ts/ts) из wire-shape | r2k_core::control::r2k_link_shape_tcp_profile | **E*** | static inline; unit tcp_shape_context_table_matches_d2o |
| `d2k_link_shape_tcp_base` | 321–331 | 11 | базовая TLS-форма из wire-shape | r2k_core::control::r2k_link_shape_tcp_base | **E*** | static inline; unit |
| `d2k_link_shape_tcp_context` | 333–339 | 7 | wire-shape из базовой формы и TCP-профиля | r2k_core::control::r2k_link_shape_tcp_context | **E** | unit tcp_shape_context_table_matches_d2o (таблица против C) |

### `core/include/d2k_resource.h`

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---:|---:|---|---|---|---|
| `d2k_resource_word` | 27–35 | 9 | сравнить слово в буфере (CSS-токен) | r2o_resource::r2o_resource_word | **P*** | static inline; unit r2o_resource |
| `d2k_resource_space` | 36–38 | 3 | пробельный символ | r2o_resource::r2o_resource_space | **P*** | static inline |
| `d2k_resource_path_ok` | 39–50 | 12 | допустимый публичный путь (не /, не query, длина) | r2o_resource::r2o_resource_path_ok | **P** | unit; отдельного C/Rust differential нет |
| `d2k_resource_add` | 51–73 | 23 | добавить URL-подсказку в скан | R2oResourceScan::r2o_add_url | **P*** | static inline |
| `d2k_resource_tag` | 74–113 | 40 | завершить тег и извлечь stylesheet | R2oResourceScan::r2o_finish_tag | **P*** | static inline |
| `d2k_resource_feed` | 114–159 | 46 | потоковый разбор HTML на публичные пути | R2oResourceScan::feed | **P** | unit r2o_resource; C/Rust differential нет |

## Углублённая сверка: domain/groups/match/net4/verdict/props (37 функций)

| C-функция | строки | R2O-аналог | статус | доказательство / пробел |
|---|---:|---|---|---|
| `d2k_domain_normalize` | 6–29 | `domain.rs:8-58` `normalize` | **P** | C принимает односоставное нечисловое имя (`localhost`), Rust требует ≥2 метки (`domain.rs:52-54`). Для `d2k_domain_base/member` это не проявляется (там нужен известный PSL-суффикс), но прямой контракт функции различается. |
| `rule_exists` (static) | 31–40 | `domain.rs:63-69` `psl::suffix/domain` | **P*** | C ищет правило в зашитом `psl_index.h`; Rust использует crate `psl`. Совпадение снимка PSL не доказано. |
| `d2k_domain_base` | 42–64 | `domain.rs:61-71` `registrable_domain` | **P** | Логика «longest rule, exception, wildcard, unknown TLD → отказ» соответствует `psl::domain` + `is_known()`. C/Rust differential на PSL-набор не найден. |
| `d2k_domain_member` | 66–72 | `domain.rs:74-86` `is_member` | **P** | C требует, чтобы `suffix` имел известный base; Rust делает то же через `registrable_domain(suffix).is_none()`. Зависит от совпадения PSL. |
| `d2k_group_key_make` | 9–17 | `catalog::GroupKey` (struct, `catalog.rs`) | **P** | Поля transport/family/shape/probe_path/ech_origin и лимиты строк перенесены; отдельной функции-конструктора нет. |
| `d2k_group_key_same` | 19–23 | `PartialEq for GroupKey` | **P** | Сравнение всех пяти полей эквивалентно; тест — unit групп/catalog. |
| `valid` (static) | 24–36 | `groups.rs:60-100` `learn` + `validate_key` | **P** | Проверки family 4/6, transport 6/17, shape, evidence 1/2/4/8 и непустого plan_id для BLOCKED/FAILED перенесены. |
| `member` (static) | 38–41 | `domain::is_member` | **P** | Сравнение суффикса по границе точки совпадает; зависит от PSL. |
| `votes` (static) | 45–60 | `groups.rs:484` `votes` | **P** | Правило `live>=2 && live>stale && live+stale>=3`, stale при PLAN_FAILED/DIRECT_CLEAR, latest по `at` перенесено. |
| `failures` (static) | 61–71 | `groups.rs` `failures`/`add_group` | **P** | Считает PLAN_FAILED по name/key/plan_id; используется при выборе группы. |
| `add_group` (static) | 72–102 | `groups.rs:544` `add_group` | **P** | Детерминированные выборы по failures/count/at/plan_id, вытеснение вложенной группы и `frozen` при MAX_GROUPS перенесены. |
| `rebuild` (static) | 103–120 | `groups.rs:326` `rebuild` | **P** | Пересборка по BLOCKED-наблюдениям, `base`, перебор суффиксов и `votes` совпадает. |
| `cover` (static) | 122–132 | `groups.rs:450` `covering_group` | **P** | Самый длинныйcovering-суффикс по key; отключённое состояние и лимит групп учтены. |
| `d2k_group_learn` | 133–245 | `groups.rs:60-269` `learn` | **P** | Слот same-plan/any/replace, frozen/reclaim, disabled/disabled_at, admitted clear, PLAN_FAILED как exception и дедупликация — перенесены. R2O добавляет OPERATOR_REJECT, которого нет в C (расширение, не пробел). C/Rust differential нет. |
| `d2k_group_restore` | 246–273 | `groups.rs:14-58` `restore` | **P** | Канонизация evidence, проверка дублей и `rebuild` совпадают; отдельного C/Rust теста нет. |
| `d2k_group_match` | 274–293 | `catalog.rs:287` `match_domain` | **P** | Исключения DIRECT_CLEAR/PLAN_FAILED и выбор самого длинного суффикса перенесены. |
| `d2k_group_forget` | 294–310 | `groups.rs:271` `forget_failures` | **P** | Удаление только PLAN_FAILED по name/transport/family и `rebuild` совпадают. |
| `d2k_group_expire` | 311–324 | `groups.rs:304` `expire_failures` | **P** | Удаление PLAN_FAILED старше `now-max_age` и `rebuild` совпадают. |
| `same_evidence` (static) | 38–73 | `catalog.rs:1077-1090` `same_signal` | **P** | volume/rx-volume: `\|d\|<=4`; ttl: `\|d\|<=2`; tos/ipid точно — совпадает с C. Тестов/дифференциала именно на эту функцию нет. |
| `d2k_fp_same` | 75–125 | `catalog.rs:59-84` `Fingerprint::is_compatible_with` | **P** | Направленный обход b→a, все приметы одного рода, `kind_seen && !agreed → false`, `common>0` — совпадает. |
| `d2k_catalog_match` | 127–136 | `catalog.rs:537-541` `match_fingerprint` | **P** | Первый совместимый индекс; эквивалентно. |
| `d2k_ip4_parse` | 7–30 | `std::net::Ipv4Addr::from_str` (`examples/m5_net4_trace.rs:15`) | **P** | **Подтверждённое расхождение:** C принимает ведущие нули (`010.0.0.1` → 10.0.0.1), Rust 1.98 даёт `Err(AddrParseError(Ipv4))` (проверено `rustc`). `test-core-net4-differential.sh` покрывает только обычные/битые литералы, не ведущие нули. |
| `d2k_ip4_text` | 32–38 | `Ipv4Addr::Display` | **E** | `scripts/test-core-net4-differential.sh` сравнивает C `d2k_ip4_text` и Rust `Display` на валидных адресах. |
| `d2k_ip4_private` | 40–51 | `quic_replay.rs:23-46` `ipv4_is_local` | **E** | Differential покрывает 0/8? (C только `v==0`), 10/8, 127/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10 и public 8.8.8.8. Rust-диапазоны совпадают. |
| `d2k_ip6_private` | 53–64 | `quic_replay.rs:47-58` IPv6-ветка | **E** | Differential покрывает ::, ::1, fc00::, fe80::, ff02::, IPv4-mapped private/public, 2001:db8::1. |
| `looks_like_tls` (static) | 33–35 | выбор `Accept` в `classify.rs:61-65`, `response.rs:882` | **P** | C решает по `h.bytes[0]==0x16`; Rust использует поле `Trigger.accept`, выставляемое конструктором. Для штатных конструкторов эквивалентно, но прямой differential на «первый байт ≠ 0x16 при accept=ServerHello» отсутствует. |
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
  что `control.rs::encode_*`; точные кадры проверяются unit-тестами
  `tests/control.rs`, но C/Rust differential кодирования не заявлен.
- **Подтверждённые расхождения:**
  1. `SET_HTTPS`: C-link кодирует любой `u32 ttl` и оставляет обрезку
     датапату; Rust `encode_set_https` отвергает `ttl > 6ч`.
  2. `DEL_NAME_PROBE`: C-link не проверяет `shape`; Rust требует
     `valid_tcp_probe_shape` и отвергает неизвестную форму раньше.
  3. `ARM_SHAPE`: кодировщики совпадают (transport 6/17), но датапат R2O
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
- **`copy`/`js`:** C `copy` обрезает строку по байтам и может разрезать
  UTF-8; `js` затем экранирует невалидные байты как `\u00xx`. Rust
  `truncate_utf8` отступает до границы символа, а строки из `/proc` читает
  через `read_to_string` (невалидный UTF-8 → пустая строка/ошибка). Это
  реальное различие для не-UTF-8 `comm`/`status`, но не для штатных ASCII
  имён процессов; статусы P сохранены.
- **`read_proc`/`read_detail`/`d2k_diag_sample`:** чтение pid-файлов,
  `VmRSS/HWM/Anon/Threads/VmData/VmSwap`, `stat` starttime, fd_count,
  `smaps_rollup`, 60-секундный сэмпл, история 1440 и детектор неучтённого
  RSS-роста перенесены в `diagnostics.rs::process_memory/process_detail/
  Recorder::tick`. Есть unit-тесты `process_memory_follows_pidfiles_and_restarts`,
  `first_process_detail_survives_process_exit`,
  `d2o_periodic_rss_sample_matches_c`; полного C/Rust differential всех полей нет.
- **`d2k_diag_write`:** C вручную пишет `report.json` schema=1 с лимитом
  448 КиБ; Rust сериализует `Recorder::write_report` через serde_json с тем же
  `REPORT_MAX`. `r2o-diagnostics-differential.sh` сравнивает
  `ring_bytes/event/snapshots/http_records`, остальные поля — unit-тесты, не
  C-oracle. Порядок ключей JSON может отличаться, но JSON-объект от порядка
  не зависит.
- **`d2k_diag_record`/`record_limit`/`record_anomaly`/`write_anomalies`:**
  кольца и счётчики `event_total/limit_total/anomaly_total/write_failures`
  перенесены; `record_anomaly` пишет kind/code/rss_delta/accounted_delta/stage
  в кольцо 8. Статусы P, отдельного C/Rust differential на переполнение колец
  нет.

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
  boxes/fingerprint/plans/bindings и правило shape 0→любая, иначе равенство
  перенесены (`discovery.rs`/`live.rs` `group_shape_fits`).
- **`handle_domain_observation`/`parse_domain_observations`/
  `handle_net_whitelist_key`/`handle_catalog_key`/`parse_catalog_obj`/
  `prune_unavailable_domain_groups`:** domain_state/observations до 256,
  network_whitelist и отбрасывание групп без включённого плана перенесены
  в `catalog.rs`/`groups.rs`; unit `derived_domain_groups_are_ignored`.
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
- **`d2k_catalog_memory_bytes`/`free_box`/`d2k_catalog_free`:** оценка
  памяти косвенная (`diagnostics catalog_bytes`), освобождение — RAII; P*.

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
  `wait_for_event`, `props_bind_any`, `d2k_props_bind*`,
  `d2k_props_contact*`, `tcp_timestamps_read/write`,
  `connect_with_tcp_profile`, `d2k_props_contact_on_family_tcp_profile`
  перенесены в `main.rs`/`ask.rs`; C/Rust differential на все errno,
  гонку tcp_timestamps и восстановление профиля не заявлен — P.
- **Вопросы свойств:** `build_fake_body`, `d2k_props_question_plan`,
  `d2k_props_question_passed`, `question_retire`, `d2k_props_ask`,
  `step_rc`, `d2k_props_ask_traced` сверены с `ask.rs::question_plan/
  record_question_passed` и `main.rs::run_r2o_ask`. Порядок пяти вопросов,
  остановка на первом прошедшем, NO_ACK/UNSENT/APPLIED/REFUSED и снятие
  плана перенесены; CLI differential не сравнивает stdout/exit, отдельные
  ветви — unit. P.
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
- **HTTP-поиск:** `http_search_portal`, `hs_open_port`, `hs_close_port`,
  `hs_hex`, `hs_set_probe`, `hs_del_probe`, `hs_set_plan`, `hs_del_plan`,
  `hs_start`, `hs_changed` перенесены в `http_search.rs`/`main.rs`; кодирование
  команд покрыто `control.rs` unit, но C/Rust differential на порт/марку/
  сохранение `http-plans.txt` не заявлен — P.
- **HTTP-портал/HTTPS:** `http_portal`, `http_push`, `http_save`,
  `http_probe_done`, `poison_cmp`, `hs_measured_poisons` — P; HTTPS-кэш и
  порядок poison по `successes` проверяются косвенно
  (`r2o-httpsprobe`/`http-search` differentials).
- **CLI/самопроверка:** `usage`/`offline_self_check` — P. R2O `--serve`
  принимает `СОКЕТ КАТАЛОГ.json [--discover] [--mark N]`, но **не имеет**
  `--measure-mark`, `--log`, `--health-file`, `--https-cache=`,
  `--release-id`, `--self-check` и периодической сводки событий, которые
  есть у `d2kc`; SHA-256(abc) покрыт crypto differential, отдельного
  `--self-check` CLI нет.
- **Диагностика:** `diagnostic_event`, `diagnostic_limit`, `diagnostic_tick`
  — P; `Recorder::record/record_limit/tick/write_report` перенесены,
  `diagnostic_tick_lifecycle_matches_d2o` покрывает жизненный цикл, но
  C/Rust differential сравнивает только часть JSON.
- **`main` (462 строки):** P. Каталог, link, sched, https/httpsearch, poll,
  sync, save/live/report, health, graceful stop и exit 1 при потере link
  перенесены в `serve_catalog`/`ControlClient`/`R2oCatalogPersistence`/
  `diagnostics`; полного CLI-паритета нет (см. флаги выше), `--serve`
  имеет другую форму.

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

## Проверка полноты

Строк среза: 692. Строк в таблицах: 692. E=127, P=564, N=1, ?=0; E+P+N+?=692. `E*`/`P*` учтены в E/P соответственно (static-хелперы).

