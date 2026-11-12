# Аудит паритета: detect — измеритель DPI (D2O C → R2O Rust)

Дата: 2026-11-11; построчная сверка продолжена 2026-11-12. Код D2O не менялся, роутер не затрагивался.

## Baseline

- D2O (oracle): `E:\d2o-a378w`, SHA `a378e230947ebfd011439e1cac0f1e994d883aae`.
- R2O: `E:\r2o`, ветка `main`; проход 2026-11-12 велся от HEAD `0f59821`.
  Ссылки на строки даны по рабочему дереву; в нём возможны незакоммиченные правки других сессий.
- Срез: E:\r2o-tooling\audit\slice-detect.csv — **159 функций** из 9 файлов:
  `detect/raw.c` (62), `detect/classify.c` (36), `detect/bridge.c` (17), `detect/poison.c` (12),
  `detect/trigger.c` (9), `detect/main.c` (8), `detect/props.c` (7), `detect/response.c` (7),
  `detect/include/d2k_detect.h` (1).
- Метод: прочитано тело каждой функции `line..end_line`; Rust-аналоги искались по всему
  `crates/`, а не только по кандидатам CSV; проверялись ветви, коды ошибок, таймауты,
  отмена и побочные эффекты.

> Ограничение прохода 2026-11-11: `git` и `cargo` в среде отсутствовали, тесты не запускались.
> В проходе 2026-11-12 исходники прочитаны построчно, `cargo test -p r2o-controller --test classify`
> дал 35 passed; detect-differential скрипты в этом проходе не перезапускались.
> Статус E означает «Rust-реализация совпадает по разобранным ветвям и в дереве есть
> профильный юнит-тест или C/Rust-дифференциал, названный в колонке доказательства».
> Production- и аппаратные сценарии (реальный DPI, OpenWrt/musl, mipsel) не проверялись.

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
| E | 47 |
| P | 102 |
| N | 10 |
| ? | 0 |
| **Всего** | **159** |

Доли: E — 29.6 % (47/159); E или P — 93.7 % (149/159); N — 6.3 % (10/159).
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
| detect/response.c | 7 | 5 | 2 | 0 |
| detect/trigger.c | 9 | 3 | 6 | 0 |
| detect/include/d2k_detect.h | 1 | 0 | 1 | 0 |
| **Всего** | **159** | **47** | **102** | **10** |

---

## 1. detect/bridge.c — 17 функций

Мост между планировщиком d2k и перенесённым измерителем: вход из `d2k_hello`, запуск дерева,
перевод вердикта и находки в `d2k_vres`, прогресс и вопросы свойств. В R2O этот слой не выделен:
его роль играет discovery-конвейер `main.rs` (вызов классификатора, seed базового вопроса,
гейты `r2o_discovery_split_gate`/`search_owned`) плюс `classify.rs`. Поэтому здесь много P:
поведение есть, но не одним символом с тем же контрактом. Дифференциалы есть для клона приманки,
фильтра невыразимых находок и гейта socket-only split (`scripts/r2o-measured-split-differential.sh`,
`scripts/r2o-bridge-clone-decoy-differential.sh`).

**Прочитано построчно: 17/17 функций, 641 строка C (1–641).** R2O-сверка: `main.rs:15396-15466` (discovery-адаптер), `:6229-6256` (split/owns_search-гейты), `classify.rs:1041,1244,1252,1842`, `raw_probe.rs:602,641,1122`, `response.rs:898`. Сверены: вход `bridge_input`
(триггер 2..16384 + accept ServerHello, контроль TLSRecord/vouched=0, клон приманки через
`d2k_hello_rename`, white, repeats/write_gap/timeout/mark/cancel, IPv6-адрес); `sched_tcp`
(bridge_input → seed → classify_run → stopped→Inconclusive → map_verdict → socket-only split gate →
refused unplannable → raw_selftest/RST owns_search → arm_from_poison/arm_input); хуки
`sched_tcp*`; базовый вопрос (`tr.name=""`, no_raw, base_seen/base_stop, ответ "whole",
base.valid/base_blocked) и neutral-ack.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_detect_stop_all` | 45-45 | 50 | липкий общий флаг остановки службы | `Drop for DiscoveryWorker` (`main.rs:14251-14261`) | **P** | Отдельного глобального флага нет, но остановка службы достижима: `Drop` взводит `cancel` и все `active_cancels`, будит jobs и join-ит потоки. Нет C/Rust differential на «остановить все» и липкость флага. |
| `stop_asked` | 50-55 | 156 | две причины броска: флаг задачи и службы | classify.rs:1041 stopped, raw_probe.rs:641 is_cancelled | P | один AtomicBool вместо двух источников; общего флага службы нет |
| `plannable_hit` | 76-93 | 540 | фильтр находок: невыразимое планом не обрывает перебор | raw_probe.rs:1122 executable_poison_hit, classify.rs:1252 append_reason | E | tests/classify.rs:599 accepted_but_unplannable_poison_keeps_opaque_verdict_and_search_ownership; scripts/r2o-measured-split-differential.sh |
| `map_verdict` | 95-112 | 953 | перевод D2K_DV_* в D2K_V_* | classify.rs:894 Verdict, :1657 ветка Poisonable | P | единое перечисление; отдельного второго enum и таблицы соответствия нет |
| `bridge_input` | 116-255 | 8964 | сборка входа измерителя из `d2k_hello`: trigger 2..16384 + ServerHello, TCP-опции, SNI-имя `tls:`, control 2..16384/TLSRecord/`vouched=0`, клон приманки, white, repeats/gap/timeout/mark/cancel, адрес | `main.rs:15396-15466` discovery-адаптер, `raw_probe.rs:602 select_bridge_decoy` | **P** | **Ветви проверены:** `owns_search=1` до любых ошибок; trigger копируется побайтно, accept ServerHello, TCP options только при `tcp_known && len<=buf`; SNI → `tls:<name>` при `0<len<=253`, без NUL; control TLSRecord + `control_vouched=0`; decoy-клон только `snapped && len>5 && b[0]==0x16` и валидном SNI контроля — `d2k_hello_rename` тела, запись `16 03 xx`, иначе fallback len=0; white 2..16384 TLSRecord; `repeats/write_gap_ms=gap_us/1000/timeout=wait/mark/cancel`; IPv6-адрес `[ip]:port`. R2O-адаптер не выделен одним символом, клон-приманка покрыт differential `raw_probe.rs:2235`; полного C/Rust differential адаптера нет. |
| `progress_seen` | 261-273 | 653 | ход вопросов планировщику; подавление счётчиков seed-«whole» | `main.rs:10573` closure + `update_probe_progress` | **P** | C: если `seeded_whole && probe=="whole"` — `d2k_sched_progress_note(probe,0,0)` и сброс флага; иначе `note(probe,pass,fail)`. R2O closure передаёт прогресс без отдельного подавления seeded-whole, поэтому счётчики прошлого прогона могут печататься повторно. |
| `trace_questions` | 284-309 | 1043 | qtrace вопросов свойств в `d2k_vres`: только `свойство:*`, обрезка по границе UTF-8, sent/answered ≤255, outcome UNKNOWN/YES/NO | — | **N** | C перебирает `res.trace`, отбирает `probe` с префиксом `свойство:`, режет label до `sizeof(st->label)-1` по границе UTF-8, `sent=pass+fail` (clamp 255), `answered=pass` (clamp), `err[0]→UNKNOWN`, иначе `d2k_prop_majority(pass,repeats)→YES/NO`. В R2O наблюдения остаются в `ClassifyResult.trace`/discovery-событиях, отдельного массива `D2K_QTRACE_MAX` и печати qtrace нет. |
| `retry_base_timeout` | 314-316 | 139 | распознать наш dial timeout для seed | classify.rs:1244 is_dial_timeout_text | E | tests/classify.rs:796 only_our_connect_deadline_gets_one_doubled_retry_and_stays_flaky |
| `sched_tcp` | 320-463 | 8837 | полный прогон: seed, progress, plannable-hit, classify, stopped, split-only gate, unplannable, RST-owns-search, arm | `main.rs:15396` discovery-pipeline, `:6229-6256` гейты | **P** | **Ветви проверены:** seed принимается только при `valid && !retry_base_timeout` (`seed_whole/repeats/pass/fail/err`); `on_obs=progress_seen`; `accept=plannable_hit`; `d2k_classify_run`; `res.stopped → INCONCLUSIVE` с `probes`; `map_verdict`; `split_gap_us=write_gap_ms*1000`; socket-only split (`raw_dial_count==raw_dial_base`) → `FLAKY` и `split_pos=0`; `refused.first && !has_hit → OPAQUE` + текст; `raw_selftest_failed && !has_hit → owns_search=0`; ядерный RST-сбой при живом dial и `!has_hit → owns_search=0` + note в начало; `marked=0`; `arm_from_poison` + проверка размера/наличия decoy, заполнение `arm_input/arm_name/arm_path`, иначе текст «планом не задаётся». R2O-конвейер не выделен одним символом; notes/qtrace/owns_search перенесены частично; полного differential нет. |
| `d2k_detect_sched_tcp` | 466-474 | 446 | крючок планировщика без white | main.rs:15396 | P | отдельного крючка нет, один путь discovery |
| `d2k_detect_sched_tcp_white` | 478-485 | 468 | крючок с ECH-приманкой | main.rs:15460 white + 15396 | P | приманка есть, отдельного символа нет |
| `d2k_detect_sched_tcp_seeded` | 488-497 | 545 | крючок с seed базового вопроса | classify.rs:1842 run_base + main.rs:10634 seed | P | seed перенесён, отдельного крючка нет |
| `d2k_detect_sched_tcp_seeded_white` | 503-511 | 573 | seed и white одновременно | classify.rs:1842 + main.rs:15460/15396 | P | оба входа есть, отдельного крючка нет |
| `base_seen` | 531-535 | 160 | отметка, что базовый вопрос задан | classify.rs:1842 run_base_with_backend_progress | P | run_base спрашивает только базу, колбэка отметки нет |
| `base_stop` | 537-541 | 136 | останов после базового вопроса | classify.rs:1842 | P | останов структурный, отдельного cancel-колбэка нет |
| `d2k_detect_sched_tcp_ack` | 548-573 | 889 | перепроверка мёртвого адреса | response.rs:898 probe_neutral_ack, classify.rs:1588 | P | тест tests/classify.rs:679; отдельного hook-символа с probes нет |
| `d2k_detect_sched_tcp_base` | 575-641 | 3012 | отдельный базовый вопрос: `tr.name=""`, `no_raw=1`, `base_stop`/`base_seen`, вердикт по первому trace `whole` | `classify.rs:1842 run_base_with_backend_progress` | **P** | **Ветви проверены:** `bridge_input`; `tr.name=""`; `opt.no_raw=1`; `base_stop = base_done || task_stop`; `base_seen` отмечает `whole`; `d2k_classify_run`; `b = trace[0]` только если probe=="whole"; `asked=pass+fail`; `base.valid` при `asked>=res.repeats && !retry_base_timeout` (с `base.repeats/pass/fail/err`); вердикты: нет `b`→`map_verdict`, `asked<repeats || repeats<=0`→INCONCLUSIVE, `err && pass==0`→UNREACHABLE, `pass==repeats`→CLEAR, `pass>0`→FLAKY, иначе INCONCLUSIVE + `base_blocked=1`. R2O `run_base` возвращает `BaseProbe{seed,blocked,probes}`, но не verdict/reason; полного C/Rust differential базового вопроса нет. |

## 2. detect/classify.c — 36 функций

Ядро дерева: триггер, опции, трасса, measure, самопроверка сырого слоя, перебор и итоговый вердикт.
Сильные места R2O: `measure`, `split_offsets`, `trigger_accepts`, нейтральный ACK и кэш самопроверки
покрыты тестами и C/Rust-дифференциалами. Слабые: нет `notes`/`covers_tls12`, нет trace о непринятом
правиле RST, текст причины при отказе сырого слоя и счёт probes ответного направления отличаются,
`note_gap_loss` отсутствует вовсе.

**Прочитано построчно: 36/36 функций, 1494 строки C (1–1494).** Сверены: имена вердиктов/ответа,
часы/сон/отмена, accept-критерии, опции и skip/only, трасса/notes, split_offsets, dial с SO_MARK и
require_mark, once_probe (raw-split и сокетный путь), TIOCOUTQ/SO_NWRITE, neutral-ack, measure с
seed и transport-retry, decoy, selftest-кэш `(family, offer_ts)`/TTL/серия ошибок, raw_doubted/
raw_recheck, sweep_poisons (свойства → compose → перебор), cross_check_tls12, полное дерево
`d2k_classify_run` (база/удвоенный срок/ответное направление/разрез/контроль/neutral-ack/RST/
пересборка/бинарный поиск границы) и `d2k_send_nosig`.

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

**Прочитано построчно: 8/8 функций, 450 строк C (1–450).** Сверено с `classify_json.rs:4-118` (`result_json_value`: `props/trace/response`, без `notes`/`covers_tls12`), `main.rs:811` (`r2o_tri_state`), `:1104-1306` (разбор `--classify`), `:1555-1584` (`classify_control_trigger`, modern `tls13`), `:1586-1604` (`classify_target_trigger`), `:1719+` (help).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `usage` | 19-49 | 3084 | справка `d2k-detect classify`: `--sni/--raw/--repeats/--timeout/--only/--skip/--control-sni/--white/--control-raw/--hello/--no-raw/--mark/--allow-loopback/--json/--progress/--dump-trigger` | main.rs:1721-1739 help | **P** | C — подкоманда `classify` и полный текст справки; Rust — `--classify HOST PORT` и другой набор/текст флагов. Функциональное соответствие, не построчное; часть флагов (`--dump-trigger`, `--white`) и умолчаний иная. |
| `print_json_str` | 51-65 | 338 | JSON-строка: `"`/`\` экранируются, control <0x20 → `\u%04x`, UTF-8 как есть | `serde_json` (`classify_json.rs:71`) | **P** | C ручное экранирование; Rust `serde_json`. Для UTF-8/control результат эквивалентен, но прямой тест на все байты отсутствует. |
| `print_tri` | 67-73 | 181 | необязательное tri-поле: UNSET пропуск, TRUE/FALSE → true/false | `classify_json.rs:4 insert_tri_state` | **P** | C `print_tri`; Rust `insert_tri_state` в `result_json_value`. Наследует JSON-тест, отдельного нет. |
| `print_json` | 75-187 | 4176 | JSON: target/verdict/reason/repeats/probes/duration/trigger_len/boundary/split_pos/reassembles/strategy/notes/response/covers_tls12/props/path/composed/raw_usable/trace | `classify_json.rs:18 result_json_value` | **P** | **Совпадает:** target/verdict/reason/repeats/probes/duration/trigger_len/boundary>0/split_pos>0/reassembles/strategy/response{verdict,reason,target,control}/props(7 полей+hop_ttl)/path/composed/raw_usable/trace(cuts/delay_ms/pass/fail/err). **Отличия:** Rust не печатает `notes[]` и `covers_tls12` (в C они есть, `print_json:106-124`); порядок ключей задаёт serde_json (`BTreeMap`), у C фиксированный; тексты причин классификатора/ответа иные. `classify_json.rs` не имеет отдельного теста на полный набор полей. |
| `print_progress` | 193-199 | 271 | stderr: `[сек] probe прошло/не прошло err` | main.rs:1187 report_progress | **P** | C печатает время, имя, pass/fail и `err`; Rust `report_progress` — только завершённые наблюдения, без столбца `err`. P. |
| `tri_word` | 201-205 | 156 | «не измерено/да/нет» | main.rs:811 r2o_tri_state | **P** | C точные русские слова; Rust `r2o_tri_state`; отдельного теста нет. |
| `print_human` | 207-275 | 3700 | человеческий отчёт: target/trigger/verdict/reason/probes/duration/repeats/boundary/reassembly/strategy+пояснение/response/notes/opaque warning/properties/trace | main.rs:1254-1305 | **P** | C печатает `Цель/Триггер (имя+длина)/Вердикт/Зондов (повторы)/Граница/Пересборка/Стратегия+пояснение по path/Ответ/Оговорки/ВНИМАНИЕ raw_usable/Свойства коробки (6 полей+hop_ttl)/Трасса`. Rust печатает `цель/вердикт/причина/зонды/время`, при наличии — `отказов RST`, `граница`, `пересборка`, `стратегия`, `ответное направление` (русские имена), trace, `замер прерван`, предупреждение о сырых зондах. **Отличия:** нет имени/длины триггера, числа повторов, `notes[]`, блока свойств и пояснения стратегии; R2O добавляет rst_failures/stopped. Тексты иные. |
| `main` | 277-450 | 8186 | CLI: `classify host:port`, разбор флагов, trigger/control/white, dump/json/progress, `d2k_classify_run` | main.rs:1104-1306, 1356-1553, 1555/1586 | **P** | C: `classify <host:port>`, флаги `--sni/--raw/--repeats/--timeout/--write-gap/--long-gap/--only/--skip/--control-sni/--white/--control-raw/--hello/--no-raw/--mark/--allow-loopback/--json/--dump-trigger/--progress`; `memset(opt,0)` затем `d2k_classify_run` вызывает `d2k_opts_defaults` (repeats 3, timeout 6000, write 60, long 700, mark `0x40000000`), `--mark` через `strtoul`, `--repeats/--timeout` через `atoi`, `--hello modern|legacy` (без both), control по умолчанию `d2k_trigger_control("d2k")` — **modern** TLS, `signal(SIGPIPE,SIG_IGN)`. Rust: `--classify HOST PORT [SNI]`, те же основные флаги плюс `--modern/--legacy/--save-plan/--arm`, REPEATS можно позиционно; `parse_classify_options` валидирует числа/метку, значения ≤0 отбрасывает, mark `None` → `0x2d` (#23), `full_detect_semantics=true`, `confirm_clear=false`, control через `classify_control_trigger` (tls13/modern), `--dump-trigger` до контроля, SIGPIPE не игнорируется глобально (MSG_NOSIGNAL на отправке). P — CLI/умолчания/API различаются. |

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
- **`main` (277–450) ↔ `main.rs:1104-1306/1356-1553/1555/1586`:**
  C `classify host:port`, `--hello modern|legacy` (без both), control
  по умолчанию `d2k_trigger_control("d2k")` — **modern** TLS,
  `memset(opt,0)` + `d2k_opts_defaults` внутри `d2k_classify_run`
  (repeats 3, timeout 6000, write 60, long 700, mark `0x40000000`),
  `strtoul`/`atoi` без строгой проверки, `signal(SIGPIPE,SIG_IGN)`.
  Rust `--classify HOST PORT [SNI]`, флаги `--modern/--legacy/
  --save-plan/--arm`, строгая валидация чисел/метки, mark `None` →
  `0x2d` (#23), `full_detect_semantics=true`, control через
  `classify_control_trigger` (tls13/modern), SIGPIPE не игнорируется
  глобально. P — CLI/умолчания/API различаются.

## 4. detect/poison.c — 12 функций

Каталог гипотез и перевод находки в строку стратегии/язык плана. Порядок и состав 85 гипотез совпадают
и закреплены тестом. `poison_has_fake` и `arm_from_poison` не знают осей `autottl`/`tcp_ts_up`,
которые есть в C-структуре; на текущем каталоге это не проявляется, но функция не эквивалентна для
произвольного `d2k_poison`.

**Прочитано построчно: 12/12 функций, 475 строк C (1–475).** Сверено с `classify.rs:178-201` (`note_props_hit/miss`), `:203-219` (`same_hypothesis`), `:221-380` (`build_poisons`, 85 записей), `:382-397` (`poison_has_fake`/`poison_supports_family`), `:399-540` (`strategy_for_poison`/`overlap_fake`/`disorder_fake`), `:1939-1941` (`strategy_for`), `classify_measured.rs:30-379` (`arm_from_poison` → план). Список `init_poisons` сверен с
`build_poisons` (`classify.rs:229-380`) по каждой из 85 записей: имена, порядок, ttl/repeats/gap_ms,
seqovl/seqovl_exact, decoy_hello, badsum/md5/disorder/disorder_pos, syn_data/oob/fake_between,
tcp_ts/ip_id_zero/seq_shift — совпадают; дедупликация `badsum-xN-gG` повторяет C.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_poison_supports_family` | 17-22 | 290 | допустимость гипотезы для семейства | classify.rs:389 poison_supports_family | E | tests/classify.rs:861 (проверка ipid на IPv6) |
| `d2k_poison_has_fake` | 24-40 | 1239 | фальшивка, если не syn_data/oob/fake_between и есть badsum/md5/ttl/autottl/seq_shift/tcp_ts | classify.rs:382 poison_has_fake | **P** | **Расхождение:** C возвращает true при `p->autottl` (`poison.c:38`); Rust `Poison` не имеет `autottl`/`tcp_ts_up` и возвращает `badsum\|\|md5\|\|ttl>0\|\|seq_shift!=0\|\|tcp_ts`. Для autottl-only гипотезы C считает «есть фальшивка», Rust — нет. Тест покрывает badsum/ts. |
| `add` | 47-60 | 335 | добавить гипотезу в список | classify.rs:215 add_poison | E | tests/classify.rs:861 порядок и 85 записей |
| `d2k_poison_same` | 62-70 | 300 | сравнение без имени: name занулён, repeats≤1→1, затем `memcmp` всего struct | classify.rs:200 same_hypothesis | **P** | C сравнивает **все** поля `d2k_poison`, включая `autottl/autottl_delta/min/max/tcp_ts_up/split_pos`; Rust `same_hypothesis` сравнивает подмножество полей `Poison` (autottl/tcp_ts_up отсутствуют). На текущем каталоге расхождений нет, для произвольной гипотезы — есть. |
| `already_listed` | 73-82 | 248 | отсев уже перечисленной гипотезы | classify.rs:327-330 | E | tests/classify.rs:861 все 85 уникальны |
| `init_poisons` | 84-180 | 5674 | полный список гипотез в порядке стоимости | classify.rs:223 build_poisons | E | tests/classify.rs:861 |
| `d2k_poisons` | 182-189 | 284 | неизменяемый список гипотез | classify.rs:377 poisons | E | tests/classify.rs:861 |
| `d2k_note_props_hit` | 194-208 | 540 | свойства по проходу гипотезы | classify.rs:173 note_props_hit | E | tests/classify.rs:907 poison_outcomes_update_only_properties_they_prove |
| `d2k_note_props_miss` | 216-223 | 242 | свойства по промаху гипотезы | classify.rs:189 note_props_miss | E | tests/classify.rs:907 |
| `d2k_strategy_for_poison` | 226-398 | 7211 | строка стратегии nfqws2 | classify.rs:394 strategy_for_poison | E | tests/classify.rs:879; raw emission differential |
| `d2k_strategy_for` | 401-404 | 144 | `--lua-desync=multisplit:payload=unknown:dir=out:pos=%d` | classify.rs:1933 strategy_for | **P** | C и Rust формируют ту же строку; отдельного теста строки нет. P. |
| `d2k_arm_from_poison` | 413-475 | 4050 | гипотеза → `d2k_arm`: oob, badsum/md5, repeats, gap, disorder/pos, between, ttl, autottl/delta/min/max, seq_out, decoy, tcpts/tcpts_up, ipidzero, split_pos, seqovl_hello/seqovl | classify_measured.rs:30 plan_text_for_poison, :50 measured_plan_text, r2k-core plan.rs | **P** | **Совпадает:** `syn_data` → отказ (`classify_measured.rs:62-64`); `seq_shift != 0 && != -66000` → отказ с тем же смыслом (`:65-70`); `repeats=0` + fake → 1 (`:93-99`); `gap_ms*1000`; `seqovl_exact` → длина приманки; `between` отключает fake/disorder; badsum/md5/ttl/seq_out/decoy/tcpts/ipidzero/disorder_pos/split_pos/seqovl переносятся. **Отличия:** (1) C переносит **autottl** и **tcp_ts_up** отдельными осями (`poison.c:442-445,460`), Rust `Poison` этих полей не имеет — план не выражается; (2) C `oob` ставит флаг, Rust отдельная ветка oob есть в `measured_plan_text`; (3) C `a->name=NULL`, имя хранится в `d2k_vres.arm_name`, Rust `PoisonHit.name`. Дифференциалы split/badsum есть, полного набора полей/отказов нет. |

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

**Прочитано построчно: 7/7 функций, 498 строк C (1–498).** Сверено с `raw_probe.rs:840-965` (`property_probes`), `:967-1045` (`property_probe_poison`, `apply_property`), `:189-345` (`sweep_poisons`), `:1047-1099` (`compose_from_props`). Все 12 вопросов `prop_probes`
(`props.c:49-196`) сверены с `property_probes` (`raw_probe.rs:840-965`): порядок, label, имя,
ttl/repeats/gap_ms, seqovl/seqovl_exact, decoy_hello, badsum/md5/tcp_ts/seq_shift/split_pos,
syn_data — совпадают. Все ветви `apply_set` (`props.c:198-257`) совпадают с `apply_property`
(`raw_probe.rs:1005-1045`), включая `ParsesL7 → validates_checksum=false` и условные
`WhiteTimestamp → timestamps/checksum`.

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

**Прочитано построчно: 62/62 функции, 1377 строк C (1–1377).** Проверены обе ветви
`__linux__`/`!__linux__`: разбор `RST_PREFIX`/legacy/owned-тега и диапазон 30000..54999;
fork/setpgid/close fd/дедлайн 5000 мс/kill группы; nft `add/delete/get` с timeout 300s и
iptables `-w -I/-D/-C`; pending-очередь 64/5 попыток/atexit; потоковые счётчики и порт
30000..54999; `build_ipv4_tcp` (опции TS/MD5-замещение, badsum xor 0xbeef, IP/TCP суммы);
IPv6-обёртка и pseudo-header; raw_send с нарезкой `seg_max`; SYN-профили с TS/без TS и RTO
1000→2000; raw_recv/read_payload с якорем `c->ack`; raw_dial с SO_MARK/HDRINCL/подавлением RST;
raw_send_plan (arm → text → TLV → load → apply → wire_build → send, delay_us, disorder 12 мс,
seq += len + oob); probe_poison (plan для выразимых, raw_send только для `none`/syn_data).

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

**Прочитано построчно: 7/7 функций, 324 строки C (1–324).** Сверено с `response.rs:164-171` (`response_timeout`), `:1050-1146` (`handshake`), `:1148-1170` (`count_handshakes`), `:1172-1204` (`neutral_sni`), `:1207-1244` (`probe_response`), `:1248-1290` (`scan12`), `:1304-1340` (`decide`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `resp_timeout` | 64-70 | 160 | `timeout>0 && timeout<3000 ? timeout : 3000` | response.rs:164 response_timeout | **E** | C и Rust одинаково ограничивают одно рукопожатие 3 с; `tests/response.rs:649`. |
| `d2k_resp_scan12` | 83-118 | 996 | поток TLS-записей: alert 0x15 → конец, 0x16 → склейка handshake, type 14/len 0 → ServerHelloDone | response.rs:1248 scan12 | **E** | C и Rust одинаково проверяют полную запись, `0x15`/`0x16`, склейку handshake через `body`, `hdr[0]==14 && body==0`; 13 векторов `tests/response.rs:122/138/479`. |
| `d2k_resp_handshake12` | 123-207 | 2623 | legacy ClientHello, socket, SO_MARK/TCP_NODELAY/SNDTIMEO/RCVTIMEO, connect/send, 64 КиБ, poll/recv, scan12 | response.rs:1050 handshake | **P** | Ветви совпадают: legacy hello, family по наличию `:` в хосте, socket options, `MSG_NOSIGNAL`, deadline, `RESPONSE_CAP=65536`, poll/recv/scan12, `have==CAP → Unmeasured`, alert → Failed, ServerHelloDone → Done. **Отличие:** C при `mark==0` подставляет `D2K_BYPASS_MARK=0x40000000`, Rust `ResponseOptions::default().mark=None` → `BYPASS_MARK=0x2d` (header, п. 23). При явно одинаковой метке путь эквивалентен; `tests/response.rs:649/555`. |
| `count_handshakes` | 215-228 | 403 | последовательные `repeats`, `r>0` done, `r<0` unmeasured | response.rs:1148 count_handshakes | **E** | C последовательно; Rust тоже, резолвит адрес на каждую попытку, lookup failure = failed (C `getaddrinfo` failure → 0), `probes++` — расширение R2O. `tests/response.rs:649`. |
| `d2k_neutral_sni` | 233-269 | 1252 | 10 случайных байт `/dev/urandom`, xorshift fallback, `z<hex>.example.com` | response.rs:1172 neutral_sni | **E** | C и Rust: 10 байт, fallback time/pid/counter/xorshift, hex-суффикс и тот же формат; `tests/response.rs:203`. |
| `d2k_resp_decide` | 274-304 | 1957 | unmeasured>0 / control==0 / target==repeats / target==0 / flaky с точными reason | response.rs:1304 decide | **E** | C и Rust совпадают все 5 ветвей и тексты; `tests/response.rs:421/479`. |
| `d2k_probe_response` | 310-324 | 806 | neutral SNI, target count, control count, decide | response.rs:1207 probe_response | **P** | Для валидных входов target/control на одном адресе, neutral SNI, `decide` совпадают. **Отличия:** (1) Rust валидирует `repeats>0` и legacy hello до зондов и возвращает NotApplicable с другим текстом; C при `repeats<=0` делает 0 попыток и приходит к NotApplicable через `control==0`; (2) наследует метку #23. `tests/response.rs:649/780`. |

### response.c: построчная сверка

- **`resp_timeout` (64–70) ↔ `response_timeout` (`:164`):** оба
  `timeout>0 && timeout<3000 ? timeout : 3000`. E.
- **`d2k_resp_scan12` (83–118) ↔ `scan12` (`:1248`):** C и Rust
  проверяют полную запись, `0x15` → FatalAlert, `0x16` → склейка
  handshake, `type 14 && body 0` → ServerHelloDone; 13 векторов.
  E.
- **`d2k_resp_handshake12` (123–207) ↔ `handshake` (`:1050`):**
  legacy ClientHello, family по `:` в хосте, socket,
  `SO_MARK/TCP_NODELAY/SNDTIMEO/RCVTIMEO`, `MSG_NOSIGNAL`,
  deadline, `RESPONSE_CAP=65536`, `scan12`; C резолвит внутри,
  Rust — в `count_handshakes`. Done/Failed/Unmeasured совпадают.
  **P:** C при `mark==0` подставляет `D2K_BYPASS_MARK=0x40000000`,
  Rust при `None` — `BYPASS_MARK=0x2d` (header, п. 23); при
  одинаковой метке путь эквивалентен.
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
  (`:1207`):** для валидных входов target/control на одном адресе,
  neutral SNI, `decide` совпадают. **P:** Rust до зондов валидирует
  `repeats>0` и legacy hello (NotApplicable с другим текстом), C при
  `repeats<=0` делает 0 попыток и приходит к NotApplicable через
  `control==0`; наследует метку #23.

## 8. detect/trigger.c — 9 функций

Чем меряем: ClientHello из снятого профиля, произвольный hex, контроль, приманка и вопрос о метке
времени клиента. Байты приветствий совпадают с C побайтно (тесты `tests/hello.rs`). Контроль и
разбор TCP-опций клиента в R2O перенесены не как отдельные функции: контроль собран в CLI,
признак метки передаётся булевым `client_tcp_has_timestamps`, переопределения нет.

**Прочитано построчно: 9/9 функций, 207 строк C (1–207).** Сверено с `classify.rs:60-108` (`Accept`, `Trigger::{raw_hex,tls,tls13}`), `trigger.rs:4` (`parse_raw_hex`), `raw_probe.rs:602-629` (`select_bridge_decoy`), `:673-683` (`raw_offer_timestamps`), `:731-733` (`raw_profile_allows`), `:967-985` (`property_probe_poison`), `main.rs:1555` (`classify_control_trigger`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_trigger_tls` | 21-50 | 1378 | ClientHello из снятого профиля (legacy/modern) с SNI; n≥16; name `tls:<sni>`; accept ServerHello; sni_off/len | classify.rs:87 Trigger::tls, :96 Trigger::tls13, hello.rs:549 | **E** | C `d2k_hello_from_profile(legacy?LEGACY:MODERN, sni)`, пустой SNI/ошибка/n<16 → -1, затем `d2k_hello_sni`. Rust `Trigger::tls`/`tls13` через `legacy_client_hello`/`modern_client_hello`, name/accept те же; смещения SNI — `hello::sni_bounds` на месте вызова. Байты совпадают: `tests/hello.rs:42` legacy, `:50` modern, `:62` fake; `tests/classify.rs:946`. |
| `hexval` | 52-58 | 203 | значение hex-цифры 0-9/a-f/A-F | trigger.rs:11 inline | **E** | C `hexval`; Rust match в `parse_raw_hex`. `tests/trigger.rs:41`. |
| `d2k_trigger_raw_hex` | 67-108 | 1322 | hex-триггер: разделители `space/tab/nl/cr/:/ -`, нечётный/битый/короткий/длинный отказ; name `raw:NB`; accept Any | classify.rs:77 Trigger::raw_hex, trigger.rs:4 parse_raw_hex | **E** | C пропускает те же разделители, `n<2`/нечётный/битый/`n>=sizeof payload` → ошибка, name `raw:%dB`, accept **всегда ANY** (`trigger.c:106`). Rust `TRIGGER_MAX=16384`, те же проверки, name и `Accept::Any`. Правило «первый байт 0x16 → ServerHello» принадлежит `core/verdict.c:33-35` (`looks_like_tls`), а не detect-триггеру, и здесь не применяется. `tests/trigger.rs:41-58`; `raw_hex_acceptance_matches_the_detect_trigger`. |
| `d2k_trigger_control` | 118-128 | 376 | контроль: `probe-<tag>.invalid-control.example`, **modern TLS** (`legacy=0`), name `control`, accept TLSRecord | main.rs:1555 classify_control_trigger | **P** | C строит **modern**-приветствие (`d2k_trigger_tls(name, 0, ...)` → `D2K_SHAPE_MODERN`), Rust по умолчанию тоже `Trigger::tls13` (modern); профиль совпадает. Имя по умолчанию `probe-d2k.invalid-control.example` и name `control` совпадают. Отличие — C принимает произвольный `tag` в `probe-<tag>...`, Rust жёстко фиксирует тег `d2k`; CLI-путь `--control-sni` даёт `control:<sni>` в обеих реализациях, `--control-raw` — raw_hex + name control + `TlsRecord`. P только по API тега. |
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
  нечётному/битому/короткому, name `raw:NB`, accept **ANY**;
  `tests/trigger.rs:41-58`. Важно: C detect всегда ставит
  `D2K_ACCEPT_ANY` (`trigger.c:106`); правило первого байта 0x16
  относится к `core/verdict.c:33-35` и detect-путь не затрагивает.
  E.
- **`d2k_trigger_control` (118–128) ↔ `classify_control_trigger`
  (`main.rs:1555`):** C вызывает `d2k_trigger_tls(name, 0, ...)`,
  то есть **modern** TLS (`D2K_SHAPE_MODERN`), и ставит name
  `control`/accept `TLSRecord`; Rust по умолчанию тоже `tls13`
  (modern) с тем же именем. Отличие — C принимает произвольный
  `tag`, Rust фиксирует `d2k`; `--control-sni`/`--control-raw`
  дают те же имена/accept, что C CLI. P — только API тега.
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

**Прочитано построчно: 1/1 функция (`d2k_prop_majority`, 490–493); остальные строки заголовка —
typedef/#define/прототипы, сверены по использованиям в `detect/*.c`.**

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_prop_majority` | 490-493 | 108 | `repeats>0 && pass>repeats/2` | raw_probe.rs:665 majority | **P** | C inline и Rust `majority` дают `total!=0 && pass>total/2` — эквивалентно. Отдельного unit нет; используется в цикле свойств (`props.c`/`sweep_poisons`) и проверяется косвенно в property-тестах. |

---

## Углублённая сверка 12 N-функций

**Прочитано построчно: 12/12 строк N-среза (10 функций); тела прочитаны, R2O-отсутствие/частичность подтверждены поиском по `crates/`.**

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

В проходе 2026-11-11 агент-аудитор тесты не запускал. В проходе 2026-11-12 выполнены
`cargo fmt --check` и `cargo test -p r2o-controller --test classify` — **35 passed**
(включая `raw_hex_acceptance_matches_the_detect_trigger`). Detect-differential скрипты
в этом проходе не перезапускались. Ранее координатор прогнал на закреплённом
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
