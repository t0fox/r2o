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
| `d2k_classify_run` | 1095-1476 | 22179 | дерево зондов и вердикт | `classify.rs:1298` `run_with_backend_progress` | P | Нет notes/`covers_tls12`, иной счёт probes ответного направления. **Ключевое:** production-discovery использует `full_detect_semantics=false`, `confirm_clear=true` (`classify.rs:869-870`, `main.rs:15380-15391`), то есть не donor-семантику C: нет удвоенного dial-retry, иначе обрабатываются частичные transport-ошибки, control без `until_pass`, добавлен whole-confirm. Существующие дифференциалы идут с `full_detect_semantics=true` и этот путь не покрывают. |
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
| `d2k_compose_from_props` | 426-498 | 3144 | сборка кандидатов из вектора свойств | `raw_probe.rs:1047` `compose_from_props` | P | При `control=None` C всегда создаёт кандидат «всё сразу» (`props.c:477-486`), R2O его не выдаёт (`raw_probe.rs:1094-1096`). Остальные правила размещения/порогов перенесены. |

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
| `d2k_raw_set_segment_max` | 814-814 | 89 | потолок сегмента под датапат | — | N | **Production-вызов:** `core/d2kc.c:575,789` ставит `d2k_arm_segment(send_maxlen)`. R2O `classify_measured.rs:12,143` жёстко пишет `segment 1400`; discovery-split `main.rs:6300` считает `send_cap-72 min 1400`. На узком канале measured-poison план может быть отвергнут вместо нарезки. Сеттера нет. |
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
| `d2k_trigger_host_ts_override` | 156-156 | 66 | переопределение «стек предлагает метку» | `ClassifyOptions.client_tcp_has_timestamps` (`classify.rs:833`), `raw_offer_timestamps` (`raw_probe.rs:673`) | **P** | Ось реализована через параметр профиля клиента, а не глобальный сеттер; CLI-флага и теста на override нет. Поведение «стек предлагает метку» выражается, но не тем же API. |
| `host_offers_ts` | 158-178 | 638 | читает tcp_timestamps один раз | raw_probe.rs:673 raw_offer_timestamps | P | OnceLock, без override |
| `d2k_trigger_offers_ts` | 180-199 | 615 | предлагает ли клиент метку времени | raw_probe.rs:673/731 | P | передаётся bool из снятого профиля, байты опций не разбираются |
| `d2k_trigger_allows_poison` | 201-207 | 165 | совместима ли гипотеза с профилем клиента | raw_probe.rs:731 raw_profile_allows, :967 fallback | P | та же логика в иной форме |

## 9. detect/include/d2k_detect.h — 1 функция

Единственная функция заголовка — правило большинства для вопросов о свойствах.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_prop_majority` | 490-493 | 108 | большинство повторов | raw_probe.rs:665 majority | P | формула совпадает, отдельного теста нет; владелец — цикл свойств (P) |

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
