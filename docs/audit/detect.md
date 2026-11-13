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
| E | 58 |
| P | 101 |
| N | 0 |
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

## detect/bridge.c (17 функций)

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
| `d2k_detect_stop_all` | 45 | 1 | липкий общий флаг остановки службы (`g_stop_all=1`) | `Drop for DiscoveryWorker` (`main.rs:14251-14261`), `STOP`/`cancel` | **P** | C ставит один `volatile sig_atomic_t` на процесс; снять его нельзя. Rust останавливает воркеры через `cancel`/`active_cancels` и join в `Drop`; отдельного глобального липкого флага и C/Rust differential «остановить все» нет. |
| `stop_asked` | 50–55 | 6 | две причины: общий `g_stop_all` и флаг задачи (`task_stop`) | `classify.rs:1041 stopped`, `raw_probe.rs:641 is_cancelled`, `main.rs` cancel | **P** | C проверяет оба источника, задачный флаг важнее; Rust обычно один `AtomicBool` на задачу/воркер, общего флага службы нет. Для одной задачи эквивалентно; для «остановить службу» C срабатывает даже без флага задачи, Rust — через отмену всех воркеров. |
| `plannable_hit` | 76–93 | 18 | фильтр находок: `d2k_arm_from_poison` успешен → 1; иначе запомнить первое невыразимое (`name/why`) и остальные имена, вернуть 0 | `raw_probe.rs:1122 executable_poison_hit`, `classify.rs:1252 append_reason` | **E** | **Совпадает:** невыразимое планом не обрывает перебор; первое сохраняется с причиной, остальные — списком; вызывающий продолжает искать выразимое. Тест `tests/classify.rs:599 accepted_but_unplannable_poison_keeps_opaque_verdict_and_search_ownership`; `r2o-measured-split-differential.sh`. |
| `map_verdict` | 95–112 | 18 | D2K_DV_* → D2K_V_*: CLEAR/PREFIX/WHOLE/OPAQUE/ADDRESS/RESPONSE/UNREACHABLE/FLAKY; POISONABLE→OPAQUE; default→INCONCLUSIVE | `classify.rs` `r2o_map_verdict` | E | C держит таблицу перевода; POISONABLE намеренно сводится к OPAQUE. Rust `r2o_map_verdict` повторяет все коды 0..10 и default; тест `map_verdict_matches_donor_table`. Отдельный `Verdict::Poisonable` остаётся для внутренней классификации. |
| `bridge_input` | 116–255 | 140 | вход измерителя из `d2k_hello`: trigger 2..16384, accept ServerHello, TCP-опции при `tcp_known`, SNI-имя `tls:<sni>`, control 2..16384/TLSRecord/`vouched=0`, клон приманки через `d2k_hello_rename`, white, repeats/gap/timeout/mark/cancel, `[ip]:port` | `main.rs:15396-15466` discovery-адаптер, `raw_probe.rs:602 select_bridge_decoy` | **P** | **Совпадает:** `owns_search=1` ставится до проверок; trigger копируется побайтно, accept ServerHello; TCP-опции только при `tcp_known && len<=buf`; SNI → `tls:` при `0<len<=253` и без NUL; control TLSRecord и `control_vouched=0`; decoy-клон только `snapped && len>5 && b[0]==0x16` и валидном SNI контроля — `d2k_hello_rename` тела + запись `16 03 xx`, иначе `decoy.len=0`; white TLSRecord; `repeats`, `write_gap_ms=gap_us/1000`, `timeout=wait_ms`, `mark`, `cancel`; IPv6-адрес `[ip]:port`. **Отличия:** R2O-адаптер не выделен одним символом; клон-приманка покрыта `raw_probe.rs:2235`, полного C/Rust differential входа нет. |
| `progress_seen` | 261–273 | 13 | прогресс вопроса планировщику; для seeded-«whole» отдать `(0,0)` один раз, чтобы счётчики прошлого прогона не удваивались | `main.rs:10573` closure + `update_probe_progress` | **P** | C при `seeded_whole && probe=="whole"` вызывает `d2k_sched_progress_note(probe,0,0)` и сбрасывает флаг; иначе передаёт `pass/fail`. Rust closure передаёт прогресс без отдельного подавления seeded-whole, поэтому счётчики прошлого прогона могут печататься повторно. |
| `trace_questions` | 284–309 | 26 | перенести наблюдения `свойство:*` в `d2k_vres.qtrace`: обрезка label по границе UTF-8, `sent/answered` ≤255, outcome UNKNOWN/YES/NO по `d2k_prop_majority` | `classify.rs` `trace_questions`, `ClassifyResult.qtrace` | E | C отбирает только `probe` с префиксом `свойство:`, режет label до 63 байт по границе UTF-8, `sent=pass+fail` (clamp 255), `answered=pass` (clamp), `err→UNKNOWN`, иначе `pass*2>repeats` → YES/NO. Rust `trace_questions` делает то же, `qtrace` ограничен `QTRACE_MAX=16` и заполняется в `finish`. Тест `trace_questions_matches_c_for_property_observations` (включая UTF-8 и UNKNOWN) и `trace_questions_is_bounded_and_notes_match_c`. |
| `retry_base_timeout` | 314–316 | 3 | распознать наш `dial tcp ...: i/o timeout` для seed базового вопроса | `classify.rs:1244 is_dial_timeout_text` | **E** | **Точное совпадение:** префикс `dial tcp ` и подстрока `: i/o timeout`; тест `tests/classify.rs:796 only_our_connect_deadline_gets_one_doubled_retry_and_stays_flaky`. |
| `sched_tcp` | 320–463 | 144 | полный прогон: seed, progress, `plannable_hit`, `d2k_classify_run`, stopped→INCONCLUSIVE, `map_verdict`, split-only gate, unplannable, raw selftest/RST owns_search, `arm_from_poison` | `main.rs:15396-15466` discovery-pipeline, `:6229-6256` гейты | **P** | **Совпадает:** seed принимается только при `valid && !retry_base_timeout` (`seed_whole/repeats/pass/fail/err`); `on_obs=progress_seen`; `accept=plannable_hit`; `d2k_classify_run`; `res.stopped → INCONCLUSIVE` с числом зондов; `map_verdict`; `split_gap_us=write_gap_ms*1000`; socket-only split (`raw_dial_count==raw_dial_base`) → FLAKY и `split_pos=0`; `refused.first && !has_hit → OPAQUE` + текст; `raw_selftest_failed && !has_hit → owns_search=0`; сбой RST при живом dial и `!has_hit → owns_search=0` + note в начало; `marked=0`; `arm_from_poison` + проверка размера/наличия decoy, заполнение `arm_input/arm_name/arm_path`, иначе текст «планом не задаётся». **Отличия:** R2O-конвейер не выделен одним символом; notes/qtrace/owns_search перенесены частично; полного differential нет. |
| `d2k_detect_sched_tcp` | 466–474 | 9 | крючок планировщика без white | `main.rs:15396` discovery | **P** | C-крючок с фиксированной сигнатурой `d2k_sched_tcp_fn`; Rust использует общий discovery-путь. Для обычной цели эквивалентно; отдельного символа/differential нет. |
| `d2k_detect_sched_tcp_white` | 478-485 | 8 | прогон с белым именем-приманкой, без seed | `main.rs` discovery white | **P** | C `sched_tcp(ip,port,trigger,control,white,mark,repeats,gap_us,wait_ms,stop,NULL)`. Rust white-приманка есть в discovery, но отдельного крючка с той же сигнатурой нет; композиция иная. |
| `d2k_detect_sched_tcp_seeded` | 488-497 | 10 | прогон с ответом базового вопроса, без white | `main.rs:10580-10902` (`seed_whole` в discovery) | **P** | C создаёт пустой `d2k_hello none` и вызывает `sched_tcp(ip,port,trigger,control,none,mark,repeats,gap_us,wait_ms,stop,seed)`; `sched_tcp` при `seed->valid && !retry_base_timeout(seed->err)` ставит `seed_whole/seed_repeats/seed_pass/seed_fail/seed_err` (`:336-342`). Rust discovery получает `seed_whole` (`main.rs:10580,10644,10821,10902`) и передаёт его в измерение; отдельного символа с этой сигнатурой нет. |
| `d2k_detect_sched_tcp_seeded_white` | 503-511 | 9 | прогон с seed и white одновременно | `main.rs:10580-10923` (`white_name` + `seed_whole`) | **P** | C `sched_tcp(...,white,...,seed)` — оба входа сразу; `bridge_input` заполняет `opt.white` (accept TLSRECORD) и `white.name=\"white\"`, а `sched_tcp` — seed-поля. Rust discovery передаёт `white_name` и `seed_whole` в один и тот же вызов измерения (`main.rs:10902-10923`); отдельного символа нет. |
| `base_seen` | 531–535 | 5 | прогресс + отметка `base_done` по наблюдению `whole` | `classify.rs:1842 run_base_with_backend_progress` | **P** | C использует `on_obs` и `strcmp(probe,"whole")`; Rust `run_base` спрашивает только базу, отдельного колбэка отметки нет — останов структурный. |
| `base_stop` | 537-541 | 5 | останов базового вопроса: `base_done` или внешний stop | `main.rs` base discovery (cancel/`base.seed_whole`) | **P** | C `return b->base_done \|\| stop_asked(b->task_stop)`; `base_done` ставит `base_seen` при наблюдении `probe==\"whole\"`, `stop_asked` читает общий и задачный флаги. Rust базовый вопрос завершается по наблюдению whole/`seed_whole` и cancel-токену; отдельной функции нет. |
| `d2k_detect_sched_tcp_ack` | 548–573 | 26 | перепроверка мёртвого адреса нейтральным ACK: до `repeats`, `probes`, -1/0/1 | `response.rs:898 probe_neutral_ack`, `classify.rs:1588` | **P** | **Совпадает:** `d2k_opts_defaults` (repeats=3), mark/cancel, до `repeats` вызовов `d2k_probe_data_ack`; `-2`/локальная ошибка/отмена → -1, подтверждение → 1, тишина на всех → 0; `probes` считает соединения. **Отличия:** Rust `probe_neutral_ack` вызывается из дерева, отдельного hook-символа с `probes` нет; тест `tests/classify.rs:679`. |
| `d2k_detect_sched_tcp_base` | 575-641 | 67 | базовый вопрос: `bridge_input`, `tr.name=""`, `no_raw=1`, `base_stop`, `classify_run`, разбор `trace[0]=="whole"`, base.valid, вердикты CLEAR/UNREACHABLE/FLAKY/INCONCLUSIVE/base_blocked | `main.rs` base discovery | **P** | **Ветви сверены:** C `bridge_input` (при ошибке — out); `tr.name=""`, `opt.no_raw=1`; `bc.task_stop=stop`, `base_done=0`, `cancel=base_stop`, `on_obs=base_seen`; `classify_run`; `b = trace[0]=="whole" ? &trace[0] : NULL`; `asked=pass+fail`; `out.probes=asked`; при `asked>=repeats && !retry_base_timeout(err)` — `base.valid/repeats/pass/fail/err`; вердикты: `!b` → map_verdict, `asked<repeats` → INCONCLUSIVE, `err && pass==0` → UNREACHABLE, `pass==repeats` → CLEAR, `pass>0` → FLAKY, иначе INCONCLUSIVE + `base_blocked=1`. Rust базовый вопрос в discovery; условия/тексты иные, C/Rust differential нет. |

## detect/classify.c (36 функций)

Ядро дерева: триггер, опции, трасса, measure, самопроверка сырого слоя, перебор и итоговый вердикт.
Сильные места R2O: `measure`, `split_offsets`, `trigger_accepts`, нейтральный ACK и кэш самопроверки
покрыты тестами и C/Rust-дифференциалами. Слабые: нет `notes`/`covers_tls12`, нет trace о непринятом
правиле RST, текст причины при отказе сырого слоя и счёт probes ответного направления отличаются,
`note_gap_loss` отсутствует вовсе.

**Прочитано построчно: 36/36 функций, 1494 строки C (1–1494).** Сверено с `classify.rs:28-58` (`split_offsets`), `:60-130` (`Trigger`), `:543-558` (`trigger_accepts`), `:1076-1240` (`measure`/run), `:1298+` (`run_with_backend_progress`), `:1939-1941` (`strategy_for`), `raw_probe.rs:120-186` (`raw_selftest`), `:189-345` (`sweep_poisons`), `:602-760` (`select_bridge_decoy`/`raw_offer_timestamps`/selftest), `:840-1099` (`property_probes`/`compose_from_props`), `response.rs:254-310,776-889,898,953-963` (`connect`/`probe_trigger`/`neutral_ack`/`unacked_bytes`). Сверены: имена вердиктов/ответа,
часы/сон/отмена, accept-критерии, опции и skip/only, трасса/notes, split_offsets, dial с SO_MARK и
require_mark, once_probe (raw-split и сокетный путь), TIOCOUTQ/SO_NWRITE, neutral-ack, measure с
seed и transport-retry, decoy, selftest-кэш `(family, offer_ts)`/TTL/серия ошибок, raw_doubted/
raw_recheck, sweep_poisons (свойства → compose → перебор), cross_check_tls12, полное дерево
`d2k_classify_run` (база/удвоенный срок/ответное направление/разрез/контроль/neutral-ack/RST/
пересборка/бинарный поиск границы) и `d2k_send_nosig`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_verdict_name` | 57-72 | 604 | имя вердикта дерева | classify.rs:907 `Verdict::as_str` | **E** | C `switch`: `clear/prefix/whole_packet/opaque/inconclusive/address/poisonable/flaky/unreachable/response`, default `""`. Rust `Verdict::as_str` те же строки; `tests/classify.rs:1025` проверяет clear/inconclusive. |
| `d2k_resp_name` | 74-82 | 255 | имена `clear/blocked/flaky`, default `not_applicable` | `response.rs` `ResponseVerdict::as_str`; `classify_json.rs` | E | C один `switch` с точными строками. Rust `ResponseVerdict::as_str` возвращает те же четыре строки, `classify_json` использует её; тест `response_verdict_names_match_donor`. |
| `d2k_now_ms` | 86-91 | 188 | монотонное время в мс + `d2k_clock_offset_ms` | `now_ms.rs` `d2k_now_ms`/`set_clock_offset_ms` | E | C `clock_gettime(CLOCK_MONOTONIC)`, `tv_sec*1000+tv_nsec/1e6+offset`, ширина 64 бита. Rust `now_ms.rs` использует тот же syscall, `AtomicI64`-сдвиг и saturating-арифметику; тест `now_ms_survives_64bit_offset_like_c` (50 суток и граница i32). |
| `d2k_sleep_ms` | 96-105 | 194 | пауза между сегментами | `now_ms.rs` `d2k_sleep_ms`; `raw_probe.rs` | **E** | C `ms<=0` → return; `nanosleep(ms/1000, (ms%1000)*1e6)`. Rust `d2k_sleep_ms` немедленно возвращается при `<=0`, иначе `thread::sleep`; используется в ожидании дочернего процесса. Тест `sleep_ms_is_noop_for_nonpositive_like_c`. |
| `d2k_trigger_accepts` | 109-124 | 903 | критерий прохода по типу accept | `classify.rs:543 trigger_accepts` | **E** | C: SERVERHELLO `n>=6 && b[0]==0x16 && b[1]==0x03 && b[5]==0x02`; TLSRECORD `n>=3 && b[0]∈{0x16,0x15} && b[1]==0x03`; default `n>0`. Rust те же байты/длины; `tests/classify.rs:833 trigger_acceptance_matches_the_donor_rules`. |
| `d2k_trigger_sni` | 126-134 | 236 | извлечь SNI из имени `tls:<sni>` | `classify.rs` `Trigger::sni` | E | C `strlen(name)>4 && strncmp(name,"tls:",4)==0` → `name+4`, иначе `""`. Rust `Trigger::sni` использует `strip_prefix("tls:")`; тест `trigger_sni_and_opts_skipped_match_c` (tls:/raw:/пусто). |
| `d2k_detect_stopped` | 136-139 | 92 | проверка отмены через callback | `classify.rs:1041 stopped`, `raw_probe.rs:641 is_cancelled` | **E** | C `c && c->fn && c->fn(c->ctx)`. Rust `stopped`/`is_cancelled`; `tests/classify.rs:818`, `cancellation_after_*` (`classify.rs:2596+`). |
| `d2k_opts_defaults` | 141-162 | 815 | умолчания: repeats 3, timeout 6000, write_gap 60, long_gap 700, mark `D2K_BYPASS_MARK` | `classify.rs:860 Default`, `:1888 configured_options` | **P** | **Ветви сверены:** C заполняет только `<=0`/`==0`: repeats 3, timeout 6000, write_gap 60, long_gap 700, mark `D2K_BYPASS_MARK`. **Подтверждено:** C `D2K_BYPASS_MARK=0x40000000` (`detect/include/d2k_detect.h:34`, `classify.c:160`); Rust `BYPASS_MARK=0x2d` (`raw_probe.rs:23`, `response.rs:71`). Числа повторов/сроков совпадают; метка по умолчанию разная — влияет на policy-routing/SO_MARK. |
| `d2k_opts_acceptable` | 164-170 | 153 | фильтр приемлемости находки | `raw_probe.rs` `make_poison_hit`/`executable_poison_hit` | E | C `!accept` → 1, иначе `accept(p,ctx)`; CLI/bridge ставит `plannable_hit`. Rust `make_poison_hit` возвращает `Ok(None)`/`Err` для невыразимой гипотезы и `Some(PoisonHit)` для исполнимой — это и есть фильтр приемлемости. Тесты `opts_acceptable_matches_plannable_filter`, `accepted_syn_data_poison_is_retained_with_its_plan_rejection_reason`. |
| `d2k_opts_skipped` | 172-181 | 10 | пропуск гипотезы по имени: линейный `strcmp` по `skip[]` | `classify.rs` `opts_skipped`/`poison_selected` | E | C проходит `o->nskip`, `strcmp` → 1. Rust `opts_skipped` делает линейный точный `==` по `skip_poisons`, `poison_selected` дополнительно учитывает `only_poison`. Тест `trigger_sni_and_opts_skipped_match_c` (точное имя, регистр, отсутствие, only). |
| `d2k_trace_add` | 183-204 | 1018 | добавить наблюдение в трассу, при переполнении — последний слот | `classify.rs:1048 add_observation` | **E** | C `ntrace>=D2K_TRACE_MAX` → `&trace[MAX-1]`; иначе слот `ntrace++`, `memset`, копия probe с обрезкой до поля/NUL. Rust `add_observation`; `tests/classify.rs:384`. |
| `obs_done` | 210-215 | 5 | объявить наблюдение наружу через `on_obs` | `classify.rs:1235` progress callback | **E** | C `if (opt->on_obs) opt->on_obs(opt->on_obs_ctx, o)`; Rust progress callback вызывается после записи наблюдения; `tests/classify.rs:384`. |
| `d2k_note` | 217-227 | 264 | до `D2K_NOTES_MAX` заметок в `res->notes[]` через `vsnprintf` | `classify.rs` `push_note` | **E** | C `nnotes>=MAX` → return; `vsnprintf(notes[nnotes], sizeof(notes[0]), fmt, ap)`; `nnotes++`. Rust `push_note` ограничивает 8 заметками и 255 байтами (по границе UTF-8), используется `note_gap_loss`/`cross_check_tls12`. Тесты `note_caps_and_truncates_like_c`, `trace_questions_is_bounded_and_notes_match_c`. |
| `note_gap_loss` | 238-247 | 9 | при `gap_ms>0` — note, что движок не умеет паузу между копиями | `classify.rs` `note_gap_loss`, `ClassifyResult.notes` | E | C `gap_ms<=0` → выход; иначе note с текстом про паузу N мс. Rust `note_gap_loss` добавляет тот же текст в `notes`; вызывается при принятии `PoisonHit` с `gap_ms`. Тест `trace_questions_is_bounded_and_notes_match_c` (0 — без note, 20 — с «20 мс»). |
| `d2k_split_offsets` | 253-287 | 915 | точки разреза → диапазоны; вне `(0,n)` отброшены; сортировка/дедуп; последний до `n` | `classify.rs:28 split_offsets` | **E** | C `cuts[i]>0 && cuts[i]<n`, до 8; вставки; пропуск `cl[i]==prev`; `out[used]={prev,cl[i]}`; финальный `{prev,n}`; возврат used. Rust `split_offsets` те же фильтр/сорт/дедуп/диапазоны; `tests/classify.rs:337,349,361`. |
| `dial_marked_mode` | 292-364 | 2591 | TCP-connect с меткой: `require_mark`, различение отказа `SO_MARK` и connect | `response.rs` `dial_probe_target_mode`/`probe_socket_with_mark`/`require_mark_failed` | **E** | C: `getaddrinfo` по family, socket, `SO_MARK`, `require_mark && mark && !marked` → «transport control: SO_MARK», `TCP_NODELAY`, nonblock, connect/poll/SO_ERROR. Rust `probe_socket_with_mark` ставит SO_MARK и при `require_mark` возвращает ту же ошибку; `dial_probe_target_mode` повторяет connect/poll/SO_ERROR. Тест `require_mark_failure_matches_c`; live-ветка SO_MARK требует привилегий (ограничение среды). |
| `d2k_dial_deadline_err` | 368-374 | 183 | признак нашего срока соединения | `classify.rs:1244 is_dial_timeout_text`, `:575 ProbeError` | **E** | C `err` начинается с `"dial tcp "` и содержит `": i/o timeout"`. Rust `is_dial_timeout_text`/`ProbeError`; `tests/classify.rs:796`. |
| `dial_marked` | 376-380 | 4 | соединение без `require_mark` | `response.rs` `dial_marked` | **E** | C `dial_marked_mode(...,0)`. Rust `dial_marked` делегирует `dial_probe_target_mode(...,false)`; обязательной метки нет. |
| `once_probe` | 385-492 | 4437 | один зонд: raw-split или сокетная запись кусков, ожидание ответа | `response.rs:776 probe_trigger`, `:891 raw_split_enabled`, `raw_probe.rs:1140 probe_tcp_split` | **E** | **Ветви сверены:** C raw-ветка при `ncuts>0 && !no_raw && raw_supported`: ровно один разрез в `(0,len)`, resolve, `raw_probe_poison_family`; сокетная: `dial_marked`, `split_offsets`, запись кусков `send_nosig`, пауза `gap` с проверкой дедлайна/отмены, `poll(POLLIN,left)`, `recv`, `trigger_accepts`. Rust `probe_trigger`/`raw_split_enabled`/`probe_tcp_split`; `tests/classify.rs:957`, `response.rs:1476/1512`, meas EINTR differentials. |
| `unacked_bytes` | 499-518 | 388 | байты в очереди отправки, -1 — не наблюдается | `response.rs:953/963 unacked_bytes` | **E** | C Linux `ioctl(TIOCOUTQ)`, macOS `getsockopt(SO_NWRITE)`, иначе -1. Rust `unacked_bytes` те же вызовы; TIOCOUTQ/SO_NWRITE; `tests/classify.rs:990`. |
| `d2k_probe_data_ack` | 520-586 | 2519 | подтверждение нейтрального байта `x` по очереди отправки | `response.rs:898 probe_neutral_ack` | **E** | **Ветви сверены:** C платформа без TIOCOUTQ/SO_NWRITE → -2; `dial_marked`; первичная `unacked_bytes<0` → -1; `send_nosig("x")`; цикл: `q==0` → 1, `q<0` → -1, deadline ≤0 → 0, отмена → -1, `poll(POLLIN,≤20 мс)>0` → 1. Rust `probe_neutral_ack`; `tests/classify.rs:990`. |
| `measure` | 608-710 | 4054 | повторы одного зонда, seed-ветка, raw-connect-retry, запись наблюдения | `classify.rs:1076 measure` | **E** | **Ветви сверены:** C `trace_add`, cuts≤4/gap; `seed_whole && ncuts==0 && name=="whole" && seed_repeats==repeats && !dial_deadline_err` → seed pass/fail/err; иначе `repeats`: отмена, `once_probe`, `probes++`; `RAW_CONNECT_TIMEOUT` → trace transport + control `dial_marked_mode(require_mark=1)` + retry; `rc<0` → fail/err (первый), `rc>0` → pass (until_pass break), `rc==0` → fail; obs pass/fail; `obs_done`. Rust `measure`; `tests/classify.rs:535,694,732`; seeded/progress. |
| `bind_decoy` | 717-728 | 279 | привязать приманку и длину перекрытия | `raw_probe.rs` `select_bridge_decoy`, `classify_measured.rs` | **E** | C при `decoy_hello`: контрольное приветствие → `decoy/decoy_len`; при `seqovl_exact` `seqovl=d->len`. Rust `select_bridge_decoy` клонирует приманку с SNI контроля (fixture `d2o_bridge_clone_decoy.tsv`), `classify_measured` при `seqovl_exact` берёт `overlap = decoy.len()` и кладёт приманку payload 2. Тест `seqovl_exact_overlap_equals_decoy_length_like_c`. |
| `answered_by_props` | 732-739 | 7 | не повторять гипотезу, уже отвеченную свойствами | `raw_probe.rs:484` (`answered` + `same_hypothesis`) | **E** | C линейно по `res->nanswered`, `d2k_poison_same` → 1. Rust `answered` использует `Poison::same_hypothesis`, который делегирует полному `poison_same` (имя игнорируется, repeats≤1→1); тест `poison_has_fake_and_same_match_c` проверяет autottl-различие и переименование. |
| `fam_ix` | 766-766 | 1 | индекс семейства: 6 → 1, иначе 0 | `raw_probe.rs` `fam_ix` | E | C `return family==6 ? 1 : 0`. Rust `fam_ix` используется `raw_selftest_index`; тест `fam_ix_matches_c_family_slots` проверяет 4/6/0 и слоты 0..3. |
| `self_ix` | 769-771 | 3 | индекс кэша `(family, offer_ts)`: 0/1 с меткой, 2/3 без | `raw_probe.rs:719-721 raw_selftest_index` | **E** | C `fam_ix(family)+(offer_ts?0:2)`. Rust `(if family==6 {1} else {0}) + if offer_ts {0} else {2}` — точное совпадение; `raw_probe.rs:2348` (`RAW_SELFTEST_KEY`). |
| `selftest_cached_age` | 774-789 | 445 | возраст кэша самопроверки или -1 | `raw_probe.rs` `raw_selftest_age`/`selftest_age_from` | **E** | C под mutex: `ok[k]` → `d=now-at[k]`; `0<=d<TTL(600000)` → age, иначе `ok=0`; иначе -1. Rust `selftest_age_from` проверяет `age < 600 с`, `raw_selftest_age` очищает просроченный слот. Тест `selftest_cached_age_ttl_matches_c` (None/0/599/600 с). |
| `selftest_store` | 791-799 | 282 | записать исход самопроверки: ok/at/сброс серии | `raw_probe.rs:735 store_raw_selftest` | **E** | C `k=self_ix`; под mutex `ok[k]=ok`, `at[k]=now`, `streak[k]=0`. Rust `store_raw_selftest`; `raw_probe.rs:2348` (`RAW_SELFTEST_INVALIDATION`). |
| `d2k_raw_note_rc` | 801-823 | 1035 | счётчики raw_ok/raw_err и серия ошибок на семейство | `raw_probe.rs:701 note_raw_probe` | **E** | **Ветви сверены:** C `rc<0` → `raw_probes_err++`, иначе `raw_probes_ok++`; под mutex: `rc<0` → `++streak[k]>=3` гасит оба набора семейства; иначе `streak=0`. Rust `note_raw_probe` + локальные `raw_ok/raw_errors`; `raw_probe.rs:2348`; `tests/classify.rs:990`. |
| `raw_selftest` | 827-854 | 943 | самопроверка сырого слоя: до `repeats`, первый успех завершает | `raw_probe.rs:120-186` | **P** | C `trace_add("raw-selftest")`; цикл: отмена, `raw_probe_handshake_as`, `probes++`; `rc<0` fail+err, `rc>0` pass+break, `rc==0` fail; `obs_done`; `selftest_store(ok=pass>0)`. Rust `raw_selftest`; цикл встроен в `sweep_poisons`, отдельного теста цикла нет. |
| `raw_doubted` | 860-863 | 3 | cached и ok==0 и err>=2 | `raw_probe.rs:669-671 should_recheck` | **E** | C `res->raw_selftest_cached && res->raw_probes_ok==0 && res->raw_probes_err>=2`. Rust `cached && successes==0 && errors>=2`; self-тест `raw_probe.rs:2513`. |
| `raw_recheck` | 867-880 | 544 | немедленная перепроверка; при провале откатить props и raw_usable=0 | `raw_probe.rs:746 raw_recheck` | **E** | C `cached=0`; `raw_selftest` успех → 1; иначе `props=props0`, `raw_usable=0`, `raw_selftest_failed=1`, 0. Rust `raw_recheck`; `raw_probe.rs:2513` + `R2O_RAW_RECHECK_C_OUTPUT`. |
| `sweep_poisons` | 887-1076 | 8251 | перебор: resolve, selftest, RST-правило, свойства, compose, список гипотез, контроль | `raw_probe.rs:78 sweep_poisons` | **P** | **Ветви сверены:** C `getaddrinfo`/family/ip/port; `selftest_cached_age` → trace «кэш», иначе `raw_selftest` (провал → raw_usable=0/return 0); `rst_fail_count != base` → trace; `props0`, `d2k_run_properties_family`/acceptable → path «свойство»; `raw_doubted` → `raw_recheck`; `compose_from_props` кандидаты; для каждого: family/skip, trace, повторы с единогласием/`raw_note_rc`/`raw_recheck`, pass==repeats && acceptable → hit/path «собрано»; затем `d2k_poisons` список: only/family/disorder/len/skip/trigger_allows, `bind_decoy`, `answered_by_props`, trace, повторы, `raw_doubted`, pass==repeats → `note_props_hit`, acceptable, path «перебор», hit; miss. **Отличия:** C ведёт trace о непринятом RST-правиле, отдельный текст selftest, compose при `control=None` иной; Rust часть диагностики не выносит. |
| `cross_check_tls12` | 1084-1092 | 367 | проверка покрытия TLS 1.2 | `classify.rs` `cross_check_tls12`, `ClassifyResult.covers_tls12` | E | C при `cross_check_tls12` ставит `covers_tls12=UNSET` и note «НЕ ПРОВЕРЕНО: режим не перенесён». Rust поле `covers_tls12: TriState` (Unset) и `notes`; `cross_check_tls12` вызывается из `finish`, текст совпадает. Тест `trace_questions_is_bounded_and_notes_match_c`. |
| `d2k_classify_run` | 1095-1476 | 22179 | дерево зондов и вердикт | `classify.rs:1298 run_with_backend_progress` | **P** | **Ветви сверены:** C `opts_defaults`, `raw_flush_pending`, rst/dial base, target/repeats/trigger_len/tri; разбор `host:port`, `[]`, `%`, loopback, trigger<2 → FLAKY; база `measure("whole")`; при dial-timeout — один повтор с `timeout*2`; base err → FLAKY (наш срок) или UNREACHABLE; base pass==repeats → CLEAR + response (SNI) / ответное направление не проверено; base 0<p<repeats → FLAKY; split pos=1; err → FLAKY; pass==0 → контроль (until_pass), neutral-ack (0/repeats → ADDRESS; -2/ошибка → observed=0), `sweep_poisons` → POISONABLE, иначе control_vouched → ADDRESS / INCONCLUSIVE, OPAQUE; pass==repeats → split-long → reassembles, двоичный поиск границы (×(len-1), mid; err→FLAKY, pass==repeats→lo, pass==0→hi, иначе FLAKY) → PREFIX; done: stopped/duration. **Ключевое:** production-discovery использует `full_detect_semantics=false`, `confirm_clear=true` (`classify.rs:869-870`, `main.rs:15380-15391`), то есть не donor-семантику C: нет удвоенного dial-retry, иначе обрабатываются частичные transport-ошибки, control без `until_pass`, добавлен whole-confirm. Существующие дифференциалы идут с `full_detect_semantics=true`. |
| `d2k_send_nosig` | 1481-1494 | 309 | `send` с `MSG_NOSIGNAL` (если есть) и `SO_NOSIGPIPE` (если есть) | `raw.rs` `r2o_raw_send_flags` | **E** | C под `#ifdef MSG_NOSIGNAL` ставит флаг, под `#ifdef SO_NOSIGPIPE` — опцию сокета. Rust raw-модуль собирается только на Linux, где действует `MSG_NOSIGNAL`; флаг включён в каждый `sendto`. Тест `raw_send_flags_include_nosignal`. macOS-ветка неприменима: датапат Linux-only. |

### detect/classify.c: построчная сверка

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

## detect/main.c (8 функций)

CLI `d2k-detect` и форматы вывода. R2O использует другой интерфейс (`r2o-controller --classify HOST PORT`),
поэтому соответствие функциональное, а не построчное. В JSON R2O нет массива `notes` и поля `covers_tls12`,
порядок ключей и форма `response` иные; в человеческом отчёте нет блока свойств коробки и оговорок.

**Прочитано построчно: 8/8 функций, 450 строк C (1–450).** Сверено с `classify_json.rs:4-118` (`result_json_value`: `props/trace/response`, без `notes`/`covers_tls12`), `main.rs:811` (`r2o_tri_state`), `:1104-1306` (разбор `--classify`), `:1555-1584` (`classify_control_trigger`, modern `tls13`), `:1586-1604` (`classify_target_trigger`), `:1719+` (help).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `usage` | 19-49 | 3084 | справка `d2k-detect classify`: `--sni/--raw/--repeats/--timeout/--only/--skip/--control-sni/--white/--control-raw/--hello/--no-raw/--mark/--allow-loopback/--json/--progress/--dump-trigger` | main.rs:1721-1739 `print_help` | **P** | C — подкоманда `classify <host:port>` и полный текст справки (`main.c:19-49`); Rust — `--classify HOST PORT [SNI]` с иным набором/текстом (`--modern/--legacy/--save-plan/--arm`, без `--white`/`--dump-trigger` в том же виде). Функциональное соответствие, не построчное; умолчания и часть флагов различаются. |
| `print_json_str` | 51-65 | 338 | JSON-строка: `"`/`\\` экранируются, control <0x20 → `\u%04x`, UTF-8 как есть | `serde_json` (`classify_json.rs`) | E | C экранирует кавычку/обратную косую, control <0x20 как `\u%04x`, UTF-8 пропускает. Rust формирует JSON через `serde_json`, который даёт те же escape-последовательности для валидной UTF-8; тест `json_string_escaping_matches_c_print_json_str` проверяет кавычку, обратную косую, `\u0001`, `\u001f` и кириллицу. |
| `print_tri` | 67-73 | 181 | необязательное tri-поле: UNSET пропуск, TRUE/FALSE → `true`/`false` с ведущей запятой | `classify_json.rs` `insert_tri_state` | E | C `print_tri` пишет поле только при `!=D2K_TRI_UNSET`, значение `true/false`. Rust `insert_tri_state` при `Unset` ничего не вставляет, при `True/False` — JSON-булево; тест `tri_state_fields_match_c_print_tri`. |
| `print_json` | 75-187 | 4176 | JSON: target/verdict/reason/repeats/probes/duration/trigger_len/boundary/split_pos/reassembles/strategy/notes/response/covers_tls12/props/path/composed/raw_usable/trace | `classify_json.rs:18-118 result_json_value` | **P** | **Совпадает по полям:** `target`, `verdict`, `reason`, `repeats`, `probes`, `duration` (`<ms>`), `trigger_len`, `boundary>0`, `split_pos>0`, `reassembles`, `strategy` (непустая), `path` (непустой), `composed`, `raw_usable`, `props` (7 tri + `hop_ttl>0`), `response{verdict,reason,target,control}`, `trace{probe,cuts,delay_ms,pass,fail,err}`. **Подтверждённые пробелы:** (1) Rust не печатает `notes[]` и `covers_tls12` (`main.c:106-124`); (2) нет `duration` как строки с суффиксом `ms`? — есть (`format!("{}ms")`); (3) порядок ключей у C фиксированный, у serde_json — `BTreeMap` (алфавитный), пробелы/переносы иные; (4) тексты `verdict/reason/response.reason` — русские строки R2O, не C; (5) `response.verdict` C печатает `not_applicable/clear/blocked/flaky`, Rust — те же (`classify_json.rs:104-109`). Отдельного теста полного набора полей нет. |
| `print_progress` | 193-199 | 271 | stderr `[%4ld с] %-28s прошло=%d не прошло=%d %s` | main.rs:1187-1201 `report_progress` | **P** | **Совпадает:** время с начала, имя пробы, `прошло/не прошло` в stderr. **Отличия:** C печатает каждое наблюдение из `on_obs` и добавляет `err`; Rust печатает только завершённое наблюдение (`completed>=repeats`, control/neutral-ack с pass>0, transport) и **не печатает `err`**. Формат `[{:4} с] {:<28}` совпадает. |
| `tri_word` | 201-205 | 156 | «не измерено/да/нет» | main.rs:811-817 `r2o_tri_state` | **E*** | **Точное совпадение строк:** `Unset → "не измерено"`, `True → "да"`, `False → "нет"`; Rust `r2o_tri_state` (`main.rs:811-817`). Отдельного unit нет; используется в `print_human`, где проверяется косвенно. |
| `print_human` | 207-275 | 3700 | человеческий отчёт: цель/триггер (имя+длина)/вердикт+reason/зонды+время+повторы/граница/пересборка/стратегия+пояснение path/ответ/оговорки/ВНИМАНИЕ raw_usable/свойства (6 tri+hop_ttl)/трасса | main.rs:1254-1305 | **P** | **Совпадает по крупным строкам:** цель, вердикт, причина, зонды, время, граница, пересборка, стратегия, ответное направление, трасса, предупреждение о сырых зондах, прерывание. **Подтверждённые отличия:** (1) нет строки «Триггер: имя (N байт)» и числа повторов; (2) нет `notes[]` («Оговорка:»); (3) нет блока «Свойства коробки» (6 полей + `hop_ttl`) — `r2o_tri_state` объявлен, но в отчёте не используется; (4) нет пояснения стратегии по `path` («свойство/собрано/перебор»); (5) Rust добавляет `отказов установки правила подавления RST` и `замер прерван`; (6) тексты и порядок строк иные. |
| `main` | 277-450 | 8186 | CLI `classify <host:port>`: разбор флагов, `--sni/--raw` взаимоисключающие, SNI из адреса, trigger/control/white, `--dump-trigger`, `signal(SIGPIPE,SIG_IGN)`, `d2k_classify_run`, json/human | main.rs:1104-1306, `:1356-1553`, `:1555-1604`, `:1586-1604` | **P** | **Совпадает:** подкоманда/режим классификации, `--sni`/`--raw` взаимоисключающие, имя из хоста при отсутствии SNI, `--hello modern\|legacy` (без `both`), `--control-raw`/`--control-sni` взаимоисключающие, запрет контроля тем же именем, контроль по умолчанию `probe-d2k.invalid-control.example` + name `control` + accept TLSRecord, `--white`, `--json`, `--progress`, `--dump-trigger`, `--no-raw`, `--allow-loopback`, `--only/--skip`. **Подтверждённые отличия:** (1) C `memset(opt,0)` и `d2k_opts_defaults` внутри `d2k_classify_run` дают repeats=3/timeout=6000/write_gap=60/long_gap=700/mark=`0x40000000`; Rust явно задаёт timeout 6 с, write 60 мс, long 700 мс, mark `None→0x2d` (#23); `--repeats` позиционно/флагом; (2) C `atoi`/`strtoul(...,0)` без строгой проверки, Rust `parse_classify_options` валидирует и отбрасывает ≤0; (3) C `signal(SIGPIPE,SIG_IGN)`, Rust полагается на `MSG_NOSIGNAL`; (4) C control-sni даёт name `control:<sni>` и `control_vouched=1`, Rust `classify_control_trigger` делает то же (`main.rs:1575-1578`) — совпадает; (5) C control-raw: `raw_hex` + name `control` + accept TLSRecord, Rust то же (`:1563-1567`); (6) Rust добавляет `--save-plan`, `--arm`, `--modern/--legacy`, `full_detect_semantics=true`, `confirm_clear=false`; (7) C `--mark` через `strtoul` принимает hex/восьмеричное, Rust только `0x`/десятичное (см. `parse_mark`). P — CLI/умолчания/API/метка различаются. |

### detect/main.c: построчная сверка

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

## detect/poison.c (12 функций)

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
| `d2k_poison_supports_family` | 17-22 | 290 | допустимость гипотезы для семейства: IPv6 запрещает `ip_id_zero` | `classify.rs:389-397 poison_supports_family` | **E** | C `p && (family==4 \|\| (family==6 && !p->ip_id_zero))`; Rust те же три условия: NULL/семейство/ipid. Тест `tests/classify.rs:861` (ipid на IPv6). |
| `d2k_poison_has_fake` | 24-40 | 1239 | фальшивка, если не syn_data/oob/fake_between и есть badsum/md5/ttl/autottl/seq_shift/tcp_ts | `classify.rs` `poison_has_fake` | E | C `syn_data/oob/fake_between` → 0; иначе `badsum \|\| md5 \|\| ttl>0 \|\| autottl \|\| seq_shift!=0 \|\| tcp_ts`. Rust `Poison` получил `autottl`, `poison_has_fake` учитывает его; тест `poison_has_fake_and_same_match_c` покрывает все шесть положительных и три исключающих поля. |
| `add` | 47-60 | 335 | добавить гипотезу в список: cap 128, `memset`, `vsnprintf(name)` | classify.rs:215 `add_poison` | **E** | C при `g_npoisons>=128` возвращает последний слот; иначе `g_npoisons++`, `memset`, `vsnprintf(p->name, ..., fmt, ap)`. Rust `add_poison` в `build_poisons`; `tests/classify.rs:861` (порядок и 85 записей). |
| `d2k_poison_same` | 62-70 | 300 | сравнение без имени: name занулён, repeats≤1→1, `memcmp` всего struct | `classify.rs` `poison_same`, `Poison::same_hypothesis` | E | C копирует обе структуры, зануляет `name`, нормализует `repeats<=1→1`, сравнивает все поля, включая autottl. Rust `poison_same` делает то же через clone/clear/normalize/`==`, `same_hypothesis` делегирует ему; тест проверяет имя, repeats 0/1, иное число и autottl. |
| `already_listed` | 73-82 | 248 | отсев уже перечисленной гипотезы (кроме себя) | classify.rs:327-330 (dedup в `build_poisons`) | **E** | C линейно сравнивает `d2k_poison_same` со всеми предыдущими, пропуская `q==p`. Rust `build_poisons` дедуплицирует `badsum-xN-gG`; `tests/classify.rs:861` все 85 уникальны. |
| `init_poisons` | 84-180 | 5674 | полный список 85 гипотез в порядке стоимости | classify.rs:223 `build_poisons` | **E** | **Состав сверен:** C 9 головных (`seqovl-1`, `badsum-x2-g20/g80`, `badsum-x7`, `disorder`, `disorder-pos2`, `badsum`, `md5`, `seq-out-of-window`), `syndata`, `oob`, `fakedsplit`/`fakedsplit-x7`, 3×3 `fake-xR+seqovl-hello/681/ttl62`, 3 `seqovl-hello*`, 3×3 `seqovl-N+disorder*`, 7×2 `seqovl-N[+hello]`, 16 `badsum-xN-gG` с дедупом, 8×2 `ttl-N`/`badsum+ttl-N`, `disorder+badsum[+hello]`, 3 `disorder+badsum+ttl-N`, `badsum+ts/ipid/hello`. Rust `build_poisons` те же имена/порядок/поля/дедуп; `tests/classify.rs:861`. |
| `d2k_poisons` | 182-189 | 284 | неизменяемый список гипотез после `pthread_once` | classify.rs:377 `poisons` | **E** | C `pthread_once(init_poisons)`, `*n=g_npoisons`, вернуть `g_poisons`. Rust `OnceLock<Vec<Poison>>`/`poisons()`; `tests/classify.rs:861`. |
| `d2k_note_props_hit` | 194-208 | 540 | свойства по проходу: badsum→checksum FALSE; ttl→hop_ttl; disorder→reorder FALSE; seqovl→overlap FALSE; decoy→parses TRUE | classify.rs:179 `note_props_hit` | **E** | C `if badsum ... else if ttl>0 ... else if disorder ... else if seqovl>0`; отдельно `decoy_hello → parses_l7=TRUE`. Rust те же ветви/порядок; `tests/classify.rs:907`. |
| `d2k_note_props_miss` | 216-223 | 242 | свойства по промаху: disorder→reorder TRUE; seqovl без decoy→overlap TRUE | classify.rs:195 `note_props_miss` | **E** | C `if disorder → tolerates_reorder=TRUE; else if seqovl>0 && !decoy_hello → tolerates_left_overlap=TRUE`; badsum-промах ничего не пишет. Rust те же условия; `tests/classify.rs:907`. |
| `d2k_strategy_for_poison` | 226-398 | 7211 | строка стратегии nfqws2 по полям гипотезы | classify.rs:400 `strategy_for_poison` | **E** | **Ветви сверены:** `syn_data` → `syndata`; `oob` → `multisplit ... pos=1:oob`; `fake_between` → `fakedsplit ... pos=1` + badsum/repeats; `has_fake && (seqovl>0 \|\| seqovl_exact)` → `fake` (blob, tls_mod при decoy, badsum, ttl, repeats) + `multisplit` (exact → seqovl=681+pattern, иначе seqovl=N + pattern при decoy) + `multidisorder` при disorder; `seqovl_exact` → multisplit 681+pattern [+ multidisorder]; `seqovl>0 && disorder` → multisplit seqovl [+ pattern] + multidisorder; `disorder_pos>0` → multidisorder pos=N; `disorder` → multidisorder pos=1,midsld [+ fake prefix]; `seqovl>0` → multisplit seqovl [+ pattern]; default `fake` + repeats/tcp_ts=-1000/ip_id=zero + badsum+ttl / decoy tls_mod / badsum / tcp_md5 / tcp_seq / ip_ttl. Rust `strategy_for_poison` те же ветви/строки; `tests/classify.rs:879`; raw emission differential. |
| `d2k_strategy_for` | 401-404 | 144 | `--lua-desync=multisplit:payload=unknown:dir=out:pos=N` | `classify.rs` `strategy_for` | E | C `snprintf` ровно эту строку с `pos`. Rust `strategy_for(pos)` формирует ту же строку и используется в split-вердиктах; тест `strategy_for_matches_c_format` (pos=1/7). |
| `d2k_arm_from_poison` | 413-475 | 4050 | гипотеза → `d2k_arm`: oob, badsum/md5, repeats, gap, disorder/pos, between, ttl, autottl/delta/min/max, seq_out, decoy, tcpts/tcpts_up, ipidzero, split_pos, seqovl_hello/seqovl | classify_measured.rs:30 `plan_text_for_poison`, `:50 measured_plan_text`, `r2k-core/src/plan.rs` | **P** | **Ветви сверены:** C `memset`; `syn_data` → отказ «данные в SYN…»; `oob` → флаг; `name=NULL`; `seq_shift!=0 && !=-66000` → отказ; badsum/md5/repeats (0 + has_fake → 1)/gap_ms/disorder/disorder_pos/between/ttl/autottl+delta+min+max/seq_out/decoy_hello/tcpts/tcpts_up/ipidzero/split_pos; `seqovl_exact → seqovl_hello=1`, иначе `seqovl>0 → seqovl`. **Отличия:** C переносит **autottl** и **tcp_ts_up** отдельными осями, Rust `Poison` этих полей не имеет — план не выражается; `oob` в Rust отдельной веткой `measured_plan_text`; имя хранится иначе (`d2k_vres.arm_name` vs `PoisonHit.name`). Дифференциалы split/badsum есть, полного набора полей/отказов нет. |

### detect/poison.c: построчная сверка

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

## detect/props.c (7 функций)

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
| `prop_probes` | 49-196 | 147 | 12 вопросов в порядке стоимости | `raw_probe.rs:840-965 property_probes` | **P** | **Состав сверен:** C при `cap<12` → 0; `memset` 12; далее `seqovl-1`/SET_LEFT_OVERLAP, `disorder`/SET_REORDER, `badsum`/SET_CHECKSUM, `badsum+hello`/SET_PARSES_L7, `badsum-x2-g20`/SET_DUPLICATES, `md5`/SET_MD5, `seq-out-of-window` (-66000)/SET_SEQ_WINDOW, `ts`/SET_TIMESTAMPS, `seqovl-sni`/SET_OVERLAP_SNI, `badsum-x7`/SET_DUP_DENSE, `white-hello-ts` (tcp_ts+decoy+repeats 8+split_pos 2)/SET_WHITE_TS, `syndata`/SET_SYN. Autottl/tcp_ts_up сняты. Rust `property_probes` те же 12 вопросов/порядок; API `Vec` без жёсткого cap. Полного C/Rust differential списка нет; ECH/self-test покрыты. |
| `apply_set` | 198-257 | 60 | ответ вопроса → `d2k_dprops` | `raw_probe.rs:1005-1045 apply_property` | **P** | **Ветви сверены:** C LEFT_OVERLAP/REORDER → `ok?FALSE:TRUE`; CHECKSUM только ok→FALSE; PARSES_L7 ok→`TRUE`+checksum FALSE; DUPLICATES/DUP_DENSE ok→TRUE; SYN/MD5/SEQ_WINDOW/TIMESTAMPS ok→FALSE; OVERLAP_SNI ok→TRUE; WHITE_TS ok→`parses_l7=TRUE`, `timestamps=FALSE` только при `p->tcp_ts`, `checksum=FALSE` только при `p->badsum`. Rust `apply_property` те же ветви; unit на все ветви нет, white-ts покрыт. |
| `d2k_run_properties` | 261-265 | 5 | IPv4-обёртка `run_properties_family(...,4,...)` | `raw_probe.rs:85-87` (`property` path) | **P** | C `d2k_run_properties_family(ip4,4,...)`. Rust семейство берёт из адреса цели/`PacketView`, отдельного символа с фиксированной 4 нет. |
| `d2k_run_properties_family` | 267-416 | 150 | цикл вопросов: stop/skip, tcp_ts fallback, overlap SNI, decoy/white, label, majority, local_err, apply_set, acceptable-hit | `raw_probe.rs:189-345 sweep_poisons` | **P** | **Ветви сверены:** C `prop_probes`; для каждого: stop/skip; `p.tcp_ts && !offers_ts` → кроме WHITE_TS пропуск; WHITE_TS → `tcp_ts=0`, при `validates_checksum==TRUE` пропуск, иначе `badsum=1`; OVERLAP_SNI требует `sni_len>0/sni_off>0/sni_off+sni_len<tr->len` и ставит `seqovl=sni_off+sni_len`; WHITE_TS требует `opt->white.len>=2` и ставит decoy=white; иначе decoy_hello → `d2k_opts_decoy` и флаг клона; label (`свойство:`/`клон клиента`/`битая сумма`); trace `delay_ms=gap_ms`; до `repeats`: `raw_probe_poison_family`, `probes++`, `done++`, `raw_note_rc`; `rc<0` → local_err/err и break; `rc>0` → pass++; break по `majority(pass)` или недостижимости; `answered` при !local_err; obs pass/fail; `apply_set` при !local_err; `got && acceptable` → hit, 1. **Отличия:** Rust цикл встроен в `sweep_poisons`, отдельной функции нет; порядок вопросов/ветви совпадают, тексты label/differential не сверены полностью. |
| `tri_no` | 418-418 | 1 | проверка `D2K_TRI_FALSE` | `raw_probe.rs` `tri_no` | E | C `return t == D2K_TRI_FALSE`. Rust `tri_no` используется в `compose_from_props`; тест `tri_yes_no_match_donor` проверяет False/True/Unset. |
| `tri_yes` | 419-419 | 1 | проверка `D2K_TRI_TRUE` | `raw_probe.rs` `tri_yes` | E | C `return t == D2K_TRI_TRUE`. Rust `tri_yes` используется в `property_probe_poison`/`compose_from_props`; тест `tri_yes_no_match_donor`. |
| `d2k_compose_from_props` | 426-498 | 73 | кандидаты из вектора: base badsum/decoy, серия 2/20 и 7/0, fake+overlap, fake+disorder, «всё сразу», decoy/seqovl из ctl | `raw_probe.rs:1047-1099 compose_from_props` | **P** | **Ветви сверены:** C `base.badsum = !tri_yes(checksum)`; `parses_l7==TRUE → decoy_hello`; duplicates TRUE и место ≥2 → 2 кандидата (repeats 2/gap 20; repeats 7); overlap FALSE → fake+seqovl_exact+decoy+repeats 7; reorder FALSE → fake+disorder+repeats 7; при `n==0` → «всё сразу» (badsum/decoy/seqovl_exact/disorder/repeats 7); затем для decoy_hello `decoy=ctl/ctl_len`, при seqovl_exact `seqovl=ctl_len`. Rust `compose_from_props` те же кандидаты/порядок; **подтверждённое отличие:** при `control=None` C всё равно выдаёт «всё сразу», Rust — нет (header, п. 6). |

### detect/props.c: построчная сверка

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

## detect/raw.c (62 функции)

Сырой слой: свой TCP, правило подавления RST, сборка пакетов и исполнение измеренного плана.
Сильная часть — пакетные строители, SYN-профиль и исполнение плана: есть C/Rust-дифференциалы
(`r2o-raw-emission-cancel-differential.sh`, `r2o-raw-profile-differential.sh`). Слабая — уборка
брошенных правил: R2O не разбирает строки iptables, чистит только собственный тег `r2o-rst`,
не знает legacy-формы без комментария и не проверяет диапазон портов 30000..54999.

**Прочитано построчно: 62/62 функции, 1377 строк C (1–1377).** Сверено с `raw_probe.rs:54-58` (счётчики), `:120-186` (selftest), `:602-760` (decoy/offer/selftest), `:1213-1321` (send/plan/probe), `:1350-1463` (build/checksum/local addr), `:1478-1745` (RstRule/RstGuard/sweep/pending), `:1841-2041` (RawConn/recv), `:2156` (read_payload), `classify_measured.rs:12,143` (segment 1400). Проверены обе ветви
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
| `parse_long_exact` | 63-77 | 15 | точное десятичное `long`: длина 1..31, первая цифра, `strtol`, `errno==0`, `end` в конце | `raw_probe.rs` `parse_long_exact` | E | C копирует в `buf[32]`, требует `0 < len < 32`, первую цифру, полное потребление `strtol`; ширина — C `long`. Rust `parse_long_exact` проверяет те же длину/цифры и парсит в `std::os::raw::c_long` (i64 на x86_64, i32 на mipsel); тест `parse_long_exact_matches_c_bounds` покрывает 31/32 байта, `+1`, `-1`, `12a` и переполнение `c_long`. |
| `d2k_parse_rst_rule` | 79-118 | 39 | разбор строки iptables: префикс `-A OUTPUT -p tcp -m tcp --sport `, порт 30000..54999, legacy-суффикс или owned-форма `--comment d2k-rst:PID` (кавычки допустимы), PID>0 | `raw_probe.rs` `parse_rst_rule` | E | C разбирает строку построчно: trim, точный префикс, цифровой порт 30000..54999, legacy-суффикс либо `d2k-rst:PID` (с кавычками), PID>0. Rust `parse_rst_rule` повторяет все ветви; тест `rst_rule_parser_matches_donor_legacy_and_owned_forms` проверяет legacy/owned/quoted и отказы. |
| `d2k_parse_stale_rst_rule` | 121-124 | 4 | прежний вход: наше ли правило, порт | `raw_probe.rs` `parse_stale_rst_rule` | E | C-обёртка `d2k_parse_rst_rule(line,port,NULL)`. Rust `parse_stale_rst_rule(line)` возвращает только порт; тест `rst_rule_parser_matches_donor_legacy_and_owned_forms`. |
| `pid_alive` | 128-132 | 5 | жив ли PID: крючок, иначе `kill(pid,0)==0` или EPERM | `raw_probe.rs` `pid_alive` | E | C `d2k_raw_alive_hook` или `kill(pid,0)==0` или `errno==EPERM`. Rust `pid_alive(pid)` делает тот же `kill(pid,0)` и считает EPERM живым; используется `rst_rule_stale`; тест `rst_rule_parser_matches_donor_legacy_and_owned_forms` проверяет живого/мёртвого владельца через инъекцию. |
| `d2k_rst_rule_stale` | 137-143 | 7 | брошенное правило: разобралось и владелец 0/мёртв | `raw_probe.rs` `rst_rule_stale`/`rst_rule_stale_with` | E | C `parse_rst_rule(...) && (owner==0 \|\| !pid_alive(owner))`. Rust `rst_rule_stale` возвращает `Some((port,owner))` только для legacy или мёртвого владельца; `pid_alive` учитывает EPERM. Тест `rst_rule_parser_matches_donor_legacy_and_owned_forms`; `sweep_stale_iptables` снимает и legacy/`d2k-rst:` правила. |
| `d2k_raw_supported` | 164-164 | 1 | Linux: сырой слой доступен | `raw_probe.rs` `raw_supported` | E | C под Linux `return 1`; non-Linux stub возвращает 0. Rust `raw_probe` компилируется только под Linux, `raw_supported()` возвращает true; вне Linux бэкенд `classify.rs` отдаёт false. Тест `raw_supported_matches_c_linux_contract`. |
| `raw_rule_system` | 224-255 | 32 | запуск команды правила: fork/setpgid, закрыть fd 3+, `execl("/bin/sh","-c")`, waitpid с дедлайном 5 с, SIGKILL группе | `raw_probe.rs:1497` `run_command`, `COMMAND_TIMEOUT` | **P** | **Ветви сверены:** C fork; в ребёнке `setpgid(0,0)`, закрывает fd 3..max, `execl("/bin/sh","sh","-c",cmd)`, `_exit(127)`; родитель `setpgid(pid,pid)`, `waitpid(WNOHANG)` до `deadline=now+5000`, по сроку `kill(-pid,SIGKILL)`+`kill(pid,SIGKILL)`+wait, возврат `D2K_RAW_RULE_KILLED`. Rust `run_command` (Command) с `COMMAND_TIMEOUT`, `try_wait`/kill; API/код возврата иные, но дедлайн/убийство есть. |
| `d2k_raw_rst_fail_count` | 262-262 | 1 | счётчик отказов RST-правила текущего потока | `raw_probe.rs:58 RST_RULE_FAILURES` | **E** | C `return t_rst_rule_failures` (thread-local). Rust `thread_local! Cell<u64>` `RST_RULE_FAILURES`, инкремент в `RstGuard`; тест `raw_probe.rs:2770`. |
| `d2k_raw_dial_count` | 263-263 | 1 | счётчик сырых соединений текущего потока | `raw_probe.rs` `raw_dial_count`/`note_raw_dial` | E | C `return t_raw_dials` (thread-local), инкремент в `raw_dial`. Rust `RAW_DIALS` — thread-local `Cell<u64>`, инкремент вынесен в `note_raw_dial` и вызывается при открытии raw-соединения; тест `raw_dial_counter_matches_c` проверяет +1. |
| `seed_init` | 265-269 | 5 | `srandom(now_ms ^ pid)`, стартовый счётчик порта `random()%25000` | `raw_probe.rs` `random_u32`, `NEXT_SOURCE_PORT` | E | C `srandom((uint64_t)now_ms ^ pid)`, `g_sport_counter=random()%25000`. Rust инициализирует `OnceLock<AtomicU32>` значением `random_u32()%25_000`; источник энтропии иной, диапазон и однократность те же. Тест `source_port_counter_matches_c_increment_and_range`. |
| `seed_once` | 271-274 | 4 | однократная инициализация сида | `raw_probe.rs` `OnceLock` в `next_source_port` | E | C `pthread_once(&g_seed_once, seed_init)`. Rust `OnceLock::get_or_init` инициализирует счётчик ровно один раз; тест вызывает `next_source_port` дважды и проверяет последовательный счёт C. |
| `next_source_port` | 283-292 | 10 | исходный порт: под mutex `counter++`, `30000+counter%25000` | `raw_probe.rs` `next_source_port`/`source_port_from_counter` | E | C инкрементит `g_sport_counter` и берёт `30000 + counter%25000`. Rust `fetch_add(1).wrapping_add(1)` воспроизводит порядок «сначала ++, затем %» (ранее был сдвиг на единицу), `source_port_from_counter` считает ту же формулу. Тест `source_port_counter_matches_c_increment_and_range` (0/24999/25000/u32::MAX, два вызова подряд). |
| `rst_nft` | 313-317 | 5 | включён ли nft-режим: `D2K_FW=="nft"` | `raw_probe.rs` `r2o_rst_uses_nft` | E | C читает `D2K_FW` и сравнивает с `"nft"`. Rust `r2o_rst_uses_nft(d2k_fw, r2o_fw)` отдаёт приоритет `D2K_FW`, затем `R2O_FW`; `RstRule::install` читает обе переменные. Тест `nft_rst_rule_uses_r2o_table_and_exact_tuple_with_donor_timeout` проверяет `nft`, `None`, fallback и приоритет `iptables`. |
| `sweep_stale_rst_rules` | 319-348 | 30 | `iptables/ip6tables -w -S OUTPUT`, разбор брошенных, `-D` с тегом владельца | `raw_probe.rs:1749-1824 sweep_stale_iptables` | **P** | **Ветви сверены:** C при `rst_nft()` → return; для iptables/ip6tables `popen("-w -S OUTPUT")`, `d2k_rst_rule_stale`, `-D` с `--comment d2k-rst:PID` (или legacy без тега). Rust спавнит `-w -S OUTPUT` с таймаутом, фильтрует `--comment r2o-rst:`, проверяет `kill`, строит `-D` с `r2o-rst:PID`; legacy-правила без метки не обрабатывает. |
| `rst_rule_cmd_form` | 382-400 | 19 | команда правила: nft `add/delete/get element inet d2k_rst`, iptables `-w -I/-D OUTPUT ... --sport ... [comment] -j DROP` | `raw_probe.rs:1561-1609` (`nft_args`, `iptables_args`) | **P** | C собирает строку: nft-verb по op, family rst4/rst6, `sport . addr . dport [timeout 300s]`; iptables `-w op OUTPUT -p tcp --sport N --tcp-flags RST RST [-m comment --comment d2k-rst:PID] -j DROP`. Rust `nft_args`/`iptables_args` те же поля, но имена `r2o_rst`/`r2o-rst:`; API — `Vec<String>` вместо строки. |
| `rst_rule_cmd` | 402-405 | 4 | команда правила с текущим `g_rst_comment` | `raw_probe.rs:1586-1609 iptables_args`/`nft_args` | **P** | C `return rst_rule_cmd_form(op,k,g_rst_comment)`. Rust передаёт `comment` явно в `iptables_args`/`nft_args`; отдельной обёртки с глобальным комментарием нет. |
| `rc_exit1` | 407-410 | 4 | успех команды: `WIFEXITED && WEXITSTATUS==1` | `raw_probe.rs` `rc_exit1` | E | C проверяет wait-статус `WIFEXITED`/`WEXITSTATUS==1`. Rust `ExitStatus::code()==Some(1)` вынесен в `rc_exit1` и используется в `rst_delete_once_locked` для nft/iptables; тест `rc_exit1_matches_c_wait_status` (exit 0/1/2). |
| `rst_delete_once` | 416-422 | 7 | одна попытка снять: `-D`; exit 1 → `-C`, exit 1 = правила нет | `raw_probe.rs:1638-1665 rst_delete_once(_locked)` | **P** | C `-D`; rc==0 → 1; не exit1 → 0; иначе `-C` exit1. Rust nft: delete success → 1, code 1 + get code 1 → 1; iptables: -D, затем -C; `rst_delete_once` берёт `IPTABLES_LOCK`. Эквивалентно. |
| `rst_abandon` | 424-434 | 11 | одноразовый лог «правило не снято за 5 попыток» с family/port | `raw_probe.rs:1691-1693,1716-1718` | **P** | C печатает family/порт/`RST_RELEASE_ATTEMPTS` один раз (`g_rst_abandon_said`). Rust `RST_ABANDON_REPORTED.call_once` печатает текст без family/port; точка вызова та же. |
| `register_atexit` | 437-437 | 1 | однократная регистрация `atexit(raw_atexit)` | `raw_probe.rs` `register_rst_cleanup` | E | C `(void)atexit(raw_atexit)` под `pthread_once`. Rust `register_rst_cleanup` использует `Once::call_once` и `libc::atexit`; тест `register_rst_cleanup_is_once` вызывает дважды и проверяет `is_completed`. |
| `rst_remember` | 440-450 | 11 | запомнить неснятое правило (до 64), иначе abandon | `raw_probe.rs:1675-1694 rst_release` | **P** | C `register_atexit`; при `pending_n<64` запись с attempts, иначе `rst_abandon`. Rust `RST_PENDING` `Vec`, `RST_PENDING_MAX=64`, attempts=2, иначе `RST_ABANDON_REPORTED`; API/структура иные. |
| `retry_pending_releases` | 454-468 | 15 | повтор снятия: skip attempts>=5 (не final), удалить при успехе, иначе ++ и abandon | `raw_probe.rs:1697-1733 retry_pending_rst_releases(_locked)` | **P** | C проходит массив, `!final && attempts>=5` → skip; успех → swap-remove; иначе `++attempts`, при >=5 и !final — abandon. Rust `Vec::remove(index)` и `saturating_add`, те же пороги/условия; final повторяет все. |
| `rst_release_locked` | 471-476 | 6 | снять правило: две попытки, иначе запомнить с attempts=2 | `raw_probe.rs:1675-1695 rst_release` | **P** | C `!rst_delete_once && !rst_delete_once` → `rst_remember(k,2)`. Rust `rst_release` две попытки `rst_delete_once`, затем push с attempts=2; эквивалентно. |
| `d2k_raw_flush_pending` | 481-486 | 6 | отложенные снятия: под mutex non-final retry | `raw_probe.rs:1745-1747 flush_pending_rst_releases` | **P** | C `pthread_mutex_lock(&g_raw_state)`, `retry_pending_releases(0)`, unlock. Rust `flush_pending_rst_releases()` → `retry_pending_rst_releases(false)`; мьютекс внутри `IPTABLES_LOCK`. |
| `d2k_raw_pending_count` | 488-495 | 8 | число отложенных снятий RST под mutex | `raw_probe.rs` `rst_pending_count` | E | C lock `g_raw_state`; `n=g_rst_pending_n`; unlock; return. Rust `rst_pending_count()` берёт `RST_PENDING`, lock и возвращает `len`; тест `rst_pending_count_starts_empty_and_is_bounded`. |
| `raw_atexit` | 497-504 | 8 | при выходе: `trylock`, final retry, unlock | `raw_probe.rs:1735-1737 rst_cleanup_at_exit` | **P** | C `pthread_mutex_trylock`, при неудаче не ждать; final retry; unlock. Rust `rst_cleanup_at_exit` вызывает `retry_pending_rst_releases(true)` без trylock (мьютекс блокирующий); поведение при занятом замке иное. |
| `rst_key_of` | 506-515 | 10 | ключ правила: sport/dport/family/dst (4/16) | `raw_probe.rs` `RstRule` | E | C копирует sport/dport/family/dst в `rst_key`. Rust `RstRule` хранит те же поля (`source_port`, `destination`/family, `destination_port`) и использует их в обеих формах команд. Тест `rst_key_fields_are_used_in_both_command_forms` проверяет nft rst6/rst4, адрес, sport/dport и iptables `--sport`. |
| `suppress_kernel_rst` | 517-545 | 29 | поставить правило: lock, retry pending, `-I`; при отсутствии xt_comment — fallback без метки; failure count, killed → release | `raw_probe.rs:1500-1628 RstRule::install/RstGuard` | **P** | **Ветви сверены:** C lock `g_raw_state`; `retry_pending_releases(0)`; `-I`; если rc>0, comment, не nft, exit<=2 и `-I` без comment ==0 → `g_rst_comment=0`, лог, rc=0; при rc!=0 `t_rst_rule_failures++`, killed → `rst_release_locked`; unlock; `rc==0`. Rust `RstRule::install`: `R2O_FW`, sweep once, `IPTABLES_LOCK`, retry, nft/iptables, comment fallback, `RST_RULE_FAILURES`; `RstGuard::drop` release. |
| `release_kernel_rst` | 547-553 | 7 | снять правило под mutex | `raw_probe.rs:1630-1636 RstGuard::drop` | **P** | C `rst_key_of`, `pthread_mutex_lock`, `rst_release_locked`, unlock. Rust `RstGuard::drop` → `rst_release(rule)`; RAII/точка та же, блокировка внутри `IPTABLES_LOCK`. |
| `local_addr_for` | 556-596 | 41 | локальный адрес через UDP-connect: IPv6 и IPv4 ветки, getsockname | `raw_probe.rs:1463-1472 local_address_for` | **P** | C v6: socket/connect/getsockname → 16 байт; v4: socket/connect/getsockname → 4 байта; ошибки → 0. Rust `UdpSocket::bind("0.0.0.0:0"/"[::]:0")`, `connect(remote)`, `local_addr()?.ip()`; API иной, результат тот же. |
| `rd16` | 598-598 | 1 | big-endian u16 | `raw_probe.rs` `u16::from_be_bytes` | **E** | C `static uint16_t rd16(const uint8_t *b){return (uint16_t)((b[0]<<8)\|b[1]);}`. Rust `from_be_bytes` на срезе ровно 2 байта; владелец `build_ipv4_tcp`; differential `raw_probe.rs:2550`. |
| `rd32` | 600-604 | 5 | big-endian u32 | `raw_probe.rs` `u32::from_be_bytes` | **E** | C `static uint32_t rd32(const uint8_t *b){return (uint32_t)b[0]<<24 \| (uint32_t)b[1]<<16 \| (uint32_t)b[2]<<8 \| b[3];}`. Rust `u32::from_be_bytes` на точном срезе; владелец `build_ipv4_tcp` (seq/ack/опции); differential `raw_probe.rs:2550` сравнивает собранный пакет. |
| `wr16` | 606-606 | 1 | big-endian u16 | `raw_probe.rs` `to_be_bytes` | **E** | C `static void wr16(uint8_t *b,uint16_t v){b[0]=(uint8_t)(v>>8);b[1]=(uint8_t)v;}`. Rust `to_be_bytes` пишет те же два байта; владелец `build_ipv4_tcp`, differential `raw_probe.rs:2550`. |
| `wr32` | 608-612 | 5 | big-endian u32 | `raw_probe.rs` `to_be_bytes` | **E** | C `b[0]=v>>24; b[1]=v>>16; b[2]=v>>8; b[3]=v`. Rust `to_be_bytes` — те же четыре байта; владелец `build_ipv4_tcp`, differential `raw_probe.rs:2550`. |
| `checksum` | 614-628 | 15 | интернет-сумма: 16-битные слова, нечётный хвост, fold, ~ | `raw_probe.rs:1370-1417` (`build_control_packet`/`tcp_checksum`) | **E** | C `sum += rd16`, нечётный байт `<<8`, fold `(sum&0xffff)+(sum>>16)`, `~sum`. Rust `checksum` та же формула; `raw_probe.rs:2870 builds_an_ipv4_syn_with_valid_ip_and_tcp_checksums`. |
| `tcp_checksum` | 630-648 | 19 | TCP-сумма IPv4: псевдозаголовок, пропуск слова checksum, нечётный хвост | `raw_probe.rs:1370-1417 tcp_checksum` | **E** | C `sum=rd16(src)+rd16(src+2)+rd16(dst)+rd16(dst+2)+6+tlen`, слова кроме `i==16`, fold, `~`. Rust `tcp_checksum` те же поля/пропуск; `raw_probe.rs:2870/2896`. |
| `build_ipv4_tcp` | 652-736 | 85 | IPv4+TCP: options ts/md5, data_off, ip_len, ip_id random/zero, TTL 64, proto 6, IP checksum, seq/ack/flags/window 65535, TCP checksum, badsum xor 0xbeef/0x1234 | `raw_probe.rs:1370-1417 build_control_packet` + poison builder | **E** | **Ветви сверены:** C extra≤64; ts 12 байт `01 01 08 0a 00000001 00000000`; md5 заменяет options 20 байт; padding до 4; `data_off=5+olen/4`, `tcp_len=data_off*4+plen`, `ip_len=20+tcp_len`; `0x45`; `ip_id=random%65535` или 0; TTL `p->ttl?:64`; proto 6; src/dst; IP checksum; TCP sport/dport/seq/ack/`data_off<<4`/flags/window 0xffff/options/payload; TCP checksum; badsum `^0xbeef`, 0→0x1234. Rust `build_control_packet`/`build_ipv4_tcp` те же поля; `raw_probe.rs:2550 measured_tcp_split_wire_packets_match_donor`. |
| `tcp_checksum_family` | 738-747 | 10 | TCP-сумма с семейством: IPv4 как есть, IPv6 добавляет адресные слова | `raw_probe.rs:1370-1417` | **E** | C `base=tcp_checksum(v4)`, для v6 `sum=~base` + 6 слов src/dst, fold, `~`. Rust `tcp_checksum`family`/`tcp_checksum` учитывает v6; `raw_probe.rs:2896 builds_an_ipv6_syn_with_valid_tcp_checksum`. |
| `build_ip_tcp` | 750-771 | 22 | IPv6-обёртка IPv4-сборщика: 40-байтный заголовок, next=6, hop, src/dst, family-checksum | `raw_probe.rs:1370-1417` | **E** | C v4 → `build_ipv4_tcp`; v6 требует cap≥60 и `!ip_id_zero`, строит TCP в `pkt+20`, затем `0x60`, payload length, next 6, hop, src/dst, checksum семейства, badsum. Rust `build_control_packet` v6; `raw_probe.rs:2550/2896`. |
| `raw_sendto` | 773-791 | 19 | отправка полного IP-пакета: v6 sockaddr_in6, v4 sockaddr_in с портом, точная длина | `raw_probe.rs:2002-2039 send_ip_packet` | **P** | C v6 `sendto(...) == n`; v4 `sendto >=0`. Rust `send_ip_packet` `sendto(MSG_DONTWAIT)` и требует `sent==len`; флаг/точка ошибки иные. |
| `d2k_raw_set_segment_max` | 814-814 | 1 | установить потолок сегмента (0 → 1400) | `classify_measured.rs` `set_segment_max`/`segment_max` | E | C `seg_max = seg ? seg : D2K_ARM_SEGMENT_MAX`. Rust `seg_max` — `AtomicUsize`, ноль заменяется на `DEFAULT_SEGMENT_MAX=1400`; `measured_plan_text` и расчёт `send_cap` используют `segment_max()`. Тест `segment_max_zero_uses_default_and_restores`. |
| `raw_send` | 830-858 | 29 | отправка нагрузки сегментами ≤`seg_max`: seq+off, seq_shift, сборка/отправка, seq не двигается | `raw_probe.rs:1209-1262 raw_send_plan` | **P** | **Ветви сверены:** C при `seq_shift` сдвигает seq; цикл `take=min(plen-off,seg_max)`, `build_ip_tcp(seq+off)`, `raw_sendto`, `off+=take`; `seq` соединения не двигает. Rust измерительный план исполняет `raw_send_plan` (план→TLV→apply→wire_build), не этот сегментный цикл; для плановых плеч эффект тот же, байты/сегментация иные. |
| `raw_send_syn` | 864-896 | 33 | SYN с опциями: MSS 1452, SACK, TS или plain (MSS/NOP/WS 7/SACK), сборка и отправка | `raw_probe.rs:1941,1964` (`raw_syn_options`/`build_control_packet`) | **E** | C `opts_ts` 20 байт (`02 04 05 ac`, `04 02`, `08 0a`, `1`, `03 03 07`) или `opts_plain` 14 байт; `build_ip_tcp(...SYN...)`; `raw_sendto`. Rust `raw_syn_options(offer_ts)` и `build_control_packet`; `scripts/r2o-raw-profile-differential.sh`/`RAW_SYN_PROFILE`. |
| `raw_recv` | 900-949 | 50 | recvfrom с фильтрами: дедлайн/отмена, family/peer, IPv4 ihl/len/dst, порты, data_off | `raw_probe.rs:2041+ receive_segment` | **P** | **Ветви сверены:** C цикл до deadline/отмены; `recvfrom`; EAGAIN/EWOULDBLOCK/EINTR → WAIT, иное → ERROR; v6 требует n≥20/AF_INET6/peer=dst, ihl=0; v4 n≥40, ihl≥20, n≥ihl+20, dst; dport/sport; off≥20/≤tlen; flags/seq/ack/payload. Rust `receive_segment` те же фильтры, nonblock + poll; профильного сетевого теста нет. |
| `raw_read_payload` | 952-988 | 37 | ждать данные: RST → -1, выравнивание по `c->ack`, обрезка повторов | `raw_probe.rs:2041+ receive_segment`/`read_payload` | **P** | C deadline; отмена; `raw_recv`; ERROR → -2; не 0 → continue; RST → -1; `plen>0`: `seq-c->ack>0` → continue, `skip=c->ack-seq`, `skip>=plen` → continue, копия `min(plen,cap)`; иначе -1. Rust `read_payload` те же правила выравнивания; профильного теста нет. |
| `raw_close` | 990-1006 | 17 | снять правило, закрыть send/recv fd, освободить buffers | `RawConn`/`OwnedFd`/`RstGuard::drop` | **P** | C `rule_up` → `release_kernel_rst`; close send/recv; free buffers. Rust `OwnedFd`/`RstGuard` закрываются `Drop`; отдельной функции нет. |
| `raw_handshake` | 1008-1089 | 82 | SYN с RTO 1s→2×, RST/SYN-ACK, ack==seq+1, timestamp option, ACK, таймаут → `RAW_CONNECT_TIMEOUT` | `raw_probe.rs:1942-1999` (`RawConn::connect` loop) | **P** | **Ветви сверены:** C `raw_send_syn`; deadline; `rto=1000`, `next_syn=now+rto`; цикл: отмена, по `now>=next_syn` повтор SYN и `rto*=2`; `raw_recv(next_syn<deadline?next_syn:deadline)`; ERROR → error; не 0 → continue; RST → error; SYN+ACK с `ack==seq+1` → timestamp из options, `seq++`, `ack=seq+1`, ACK; иначе continue; таймаут → `RAW_CONNECT_TIMEOUT`. Rust `RawConn::connect` те же RTO/повтор/проверка/ACK; теста ретрансмита SYN нет. |
| `raw_dial` | 1092-1180 | 89 | собрать raw-соединение: local addr, buffers, send/recv сокеты, SO_MARK, HDRINCL, v6 bind, RCVTIMEO 300 мс, sweep once, port, seq, suppress RST, handshake | `raw_probe.rs:1840-2000 RawConn::connect` | **P** | **Ветви сверены:** C `memset`, offer_ts, fd=-1, family 4/6, dst/dport; `local_addr_for`; `malloc(buffers)`; `socket(AF, SOCK_RAW, IPPROTO_RAW)`; SO_MARK при mark!=0 и HDRINCL; `socket(AF, SOCK_RAW, IPPROTO_TCP)`, v6 bind, `SO_RCVTIMEO=300 мс`; `pthread_once(sweep)`; `next_source_port`; `seq=random`; `t_raw_dials++`; `suppress_kernel_rst`; `raw_handshake`. Rust `RawConn::connect` те же шаги (SOCK_CLOEXEC/NONBLOCK, OwnedFd), `offer_ts`, `RstGuard`; полного сетевого теста нет. |
| `d2k_raw_probe_handshake_as` | 1187-1197 | 11 | самопроверка: `raw_dial`, close, 1 | `raw_probe.rs probe_handshake_as` | **P** | C `raw_dial(ip,port,mark,offer_ts,err,cap)`; при ошибке вернуть код; `raw_close`; 1. Rust `probe_handshake_as` выполняет тот же dial/close и возвращает результат; отдельного теста нет. |
| `raw_send_plan` | 1209-1262 | 54 | измерительный план: arm_from_poison, текст→TLV→load→apply, wire_build по actions, delay_us, seq += len+oob | `scripts/r2o-raw-emission-cancel-differential.sh`; `raw_probe.rs:2550/2810` | **E** | **Ветви сверены:** C `arm_from_poison`; decoy cap; input trigger/sni/decoy; `malloc` buffers; `arm_plan_measured`; `plan_text_to_tlv`; `plan_load`; `pkt.seq/payload/have_sni/sni`; `plan_apply` требует `fate==DROP`; conn family/ack/window 65535/ttl 64/src/dst/ports/options; по actions: отмена, `delay_us/1000` sleep, `wire_build`, `raw_sendto`; disorder grace 12 мс; `seq += len+oob`; cleanup. Rust emission differential/`raw_probe` plan path; те же шаги/порядок. |
| `d2k_raw_probe_poison_family` | 1272-1321 | 50 | один зонд: dial, plan-send для именованных/не-syn_data, прямой send для none/syn_data, чтение ответа, accept | `raw_probe.rs` plan/poison path | **P** | **Ветви сверены:** C `raw_dial`; `resp`; если `name!=\"none\" && !syn_data` → `raw_send_plan`, иначе `raw_send` с PSH\|ACK\|SYN; `raw_read_payload`; ERROR → error; 0 → 0; `trigger_accepts`; close. Rust plan-based path; полного сетевого теста нет. |
| `d2k_raw_supported` | 164-164 | 1 | Linux: сырой слой доступен | `raw_probe.rs` `raw_supported` | E | C под Linux `return 1`; non-Linux stub возвращает 0. Rust `raw_probe` компилируется только под Linux, `raw_supported()` возвращает true; вне Linux бэкенд `classify.rs` отдаёт false. Тест `raw_supported_matches_c_linux_contract`. |
| `d2k_raw_set_segment_max` | 1329-1329 | 1 | не-Linux: no-op | `classify_measured.rs` `set_segment_max` (cfg) | E | C `(void)seg` под `#else`. Не-Linux-ветка Rust не пишет `SEGMENT_MAX` (только `let _ = segment`), наблюдаемое поведение — no-op. |
| `d2k_raw_rst_fail_count` | 1330-1330 | 1 | не-Linux: 0 | `cfg(target_os="linux")` | **E** | C `return 0` под `#else`. Вне Linux raw-путь R2O не компилируется/не активен, счётчик отказов RST равен 0 — то же наблюдаемое значение. |
| `d2k_raw_dial_count` | 263-263 | 1 | счётчик сырых соединений текущего потока | `raw_probe.rs` `raw_dial_count`/`note_raw_dial` | E | C `return t_raw_dials` (thread-local), инкремент в `raw_dial`. Rust `RAW_DIALS` — thread-local `Cell<u64>`, инкремент вынесен в `note_raw_dial` и вызывается при открытии raw-соединения; тест `raw_dial_counter_matches_c` проверяет +1. |
| `d2k_raw_flush_pending` | 1332-1332 | 1 | не-Linux: no-op | `cfg(target_os="linux")` | **P** | C пустая функция под `#else`. Rust вне Linux raw-путь не активен, `RST_PENDING`/`RstGuard` не используются; отложенных снятий RST нет — наблюдаемое поведение no-op. |
| `d2k_raw_pending_count` | 1333-1333 | 1 | не-Linux: 0 | `lib.rs` `rst_pending_count` (cfg) | E | C `return 0`. На не-Linux Rust-функция `rst_pending_count()` возвращает 0; на Linux — длину `RST_PENDING`. |
| `d2k_raw_probe_poison_family` | 1335-1343 | 9 | не-Linux: ошибка «сырой слой только на Linux» | `ProbeError::Unsupported` | **P** | C `snprintf(err,...,"сырой слой только на Linux")`, return -1. Rust вне Linux raw-путь возвращает `Unsupported` с аналогичным смыслом; текст иной. |
| `d2k_raw_probe_handshake_as` | 1345-1353 | 9 | не-Linux: ошибка «сырой слой только на Linux» | `ProbeError::Unsupported` | **P** | C `snprintf(err,...,"сырой слой только на Linux")`, return -1. Rust вне Linux возвращает `Unsupported` с тем же смыслом; текст иной. |
| `d2k_raw_probe_handshake` | 1357-1361 | 5 | обёртка family 4 | `raw_probe.rs` (family из адреса) | **P** | C `return d2k_raw_probe_handshake_family(ip4,4,...)`. Rust family берёт из адреса/`PacketView`; отдельного символа с фиксированной 4 нет. |
| `d2k_raw_probe_handshake_family` | 1364-1370 | 7 | обёртка `offer_ts=1` | `raw_probe.rs` (offer_ts параметр) | **P** | C `return d2k_raw_probe_handshake_as(ip4,ip6,family,ip,port,mark,1,err,cap)`. Rust `offer_ts` передаёт вызывающий; отдельной обёртки с фиксированной 1 нет. |
| `d2k_raw_probe_poison` | 1372-1377 | 6 | обёртка family 4 | `raw_probe.rs` (family из адреса) | **P** | C `return d2k_raw_probe_poison_family(ip4,ip6,4,ip,port,mark,hello,plan,err,cap)`. Rust family берёт из адреса/`PacketView`; отдельного символа с фиксированной 4 нет. |

### detect/raw.c: построчная сверка

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

## detect/response.c (7 функций)

Ответное направление TLS 1.2. Самый закрытый файл среза: разбор потока записей, рукопожатие,
счёт серии, нейтральное имя и решение покрыты юнит-тестами и общими C-векторами
(`tests/fixtures/d2o/tls-response-vectors.tsv`, `d2o_response_fixture.c`, EINTR-дифференциал).

**Прочитано построчно: 7/7 функций, 324 строки C (1–324).** Сверено с `response.rs:164-171` (`response_timeout`), `:1050-1146` (`handshake`), `:1148-1170` (`count_handshakes`), `:1172-1204` (`neutral_sni`), `:1207-1244` (`probe_response`), `:1248-1290` (`scan12`), `:1304-1340` (`decide`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `resp_timeout` | 64-70 | 160 | потолок одного рукопожатия: `timeout_ms>0 && timeout_ms<3000 ? timeout_ms : 3000` | response.rs:164 `response_timeout` | **E** | **Точное совпадение:** C возвращает `opt->timeout_ms`, если он в диапазоне 1..2999 мс, иначе 3000 (`response.c:64-70`); Rust `response_timeout` возвращает `timeout`, если он не ноль и меньше 3 с, иначе 3 с (`response.rs:164-171`). `timeout_ms<=0` и нулевой `Duration` одинаково дают 3 с. Тест `tests/response.rs:649`. |
| `d2k_resp_scan12` | 83-118 | 996 | поток TLS-записей: неполная запись — ждать; `0x15` — останов с `done=0`; `0x16` — склейка handshake; type 14/len 0 — ServerHelloDone | response.rs:1248 `scan12` | **E** | **Построчно совпадает:** C и Rust идут по полным записям (`have-pos>=5`, `rlen=BE16(p+3)`, `have-pos<5+rlen` → продолжить чтение), тип `0x15` завершает разбор (C `*done=0`, Rust `FatalAlert`), тип `0x16` разбирает payload как непрерывный поток 4-байтных handshake-заголовков (`body` 24 бита, `hdr[0]==14 && body==0` → ServerHelloDone), прочие типы пропускаются. В `handshake` C `rc=0` и Rust `Trial::Failed` дают один исход «не дошло». Тесты `tests/response.rs:122` (склейка через записи), `:138` (0x0e внутри сертификата), `:338` (заголовок через записи, alert), `:479` (общие C-векторы). |
| `d2k_resp_handshake12` | 123-207 | 2623 | legacy ClientHello, getaddrinfo по `:` в хосте, socket, `SO_MARK`/`TCP_NODELAY`/`SNDTIMEO`/`RCVTIMEO`, connect/send, 64 КиБ, poll/recv, `scan12`; 1/0/-1 | response.rs:1050 `handshake` | **P** | **Совпадает:** legacy-приветствие (`d2k_trigger_tls(...,1)` ↔ `legacy_client_hello`), семейство по наличию `:` в хосте, `TCP_NODELAY`, таймауты `response_timeout`, `MSG_NOSIGNAL`, дедлайн, `RESPONSE_CAP=65536`, цикл poll/recv, `scan12`, переполнение буфера → `-1`/`Unmeasured`, alert/обрыв → «не дошло». **Подтверждённые отличия:** (1) при `mark==0` C ставит `D2K_BYPASS_MARK=0x40000000` (`response.c:153`, `d2k_detect.h:34`), Rust — `BYPASS_MARK=0x2d` (`response.rs:71,1064-1067`); при явно одинаковой метке путь эквивалентен; (2) C резолвит адрес внутри функции, Rust получает `SocketAddr` (резолв в `count_handshakes`), поэтому ошибка `getaddrinfo` у C = Failed-попытка, у Rust — `continue`; счётчики совпадают; (3) ошибка сборки hello у C = 0 (Failed), у Rust = `Err`, который `probe_response` превращает в NotApplicable с другим текстом; (4) `malloc` C при OOM → Failed, Rust `vec!` паникует/абортит. Тесты `tests/response.rs:171` (лимит → Unmeasured), `:555` (прерванный poll = провал, как C), `:649`. |
| `count_handshakes` | 215-228 | 403 | последовательные `repeats`: `r>0` → done++, `r<0` → unmeasured++, вернуть done | response.rs:1148 `count_handshakes` | **E** | **Совпадает:** C и Rust считают рукопожатия строго последовательно; `Done` увеличивает счётчик, `Failed` пропускается, `Unmeasured` увеличивает `unmeasured`; результат — число завершённых. Rust дополнительно считает `probes` (каждая попытка) и резолвит адрес на каждую попытку — C делает то же внутри `d2k_resp_handshake12`. `Err` из Rust достижим только при недопустимом SNI, который `probe_response` отсекает заранее. Тест `tests/response.rs:649`. |
| `d2k_neutral_sni` | 233-269 | 1252 | 10 случайных байт из `/dev/urandom`, fallback xorshift, hex из младших тетрад, `z<hex>.example.com` | response.rs:1172 `neutral_sni` | **P** | **Совпадает:** 10 байт, low-nibble hex, формат `z%s.example.com`; fallback — xorshift 13/7/17 с сидом из времени/pid/счётчика. **Подтверждённые отличия fallback:** (1) C читает `/dev/urandom` циклом до 10 байт (частичное чтение допускается), Rust `read_exact` при неполном чтении уходит в fallback; (2) C сид `(tv_nsec<<20) ^ tv_sec ^ (pid<<40) ^ (++counter*golden)` и `x\|=1`, Rust `as_nanos() ^ pid.rotate_left(17) ^ (counter*golden)` без `\|=1`; при нулевом состоянии Rust xorshift останется нулевым (вероятность ~2^-64), C это исключает; (3) C `snprintf` обрезает по `cap`, Rust возвращает `String`. Для обычного пути результат — случайное нейтральное имя, побайтового равенства быть не может. Тест `tests/response.rs:203` проверяет, что контроль идёт на том же адресе; отдельного теста fallback нет. |
| `d2k_resp_decide` | 274-304 | 1957 | `unmeasured>0` → NOT_APPLICABLE; `control==0` → NOT_APPLICABLE; `target==repeats` → CLEAR; `target==0` → BLOCKED; иначе FLAKY; точные reason | response.rs:1304 `decide` | **E** | **Точное совпадение всех пяти ветвей и текстов:** C (`response.c:274-304`) и Rust (`response.rs:1304-1340`) проверяют в одном порядке `unmeasured`, `control==0`, `target==repeats`, `target==0`, иначе FLAKY; reason побайтово совпадают, включая «64 КБ», «сертификат в TLS 1.2 идёт открытым текстом» и `target/repeats`. `res->target/control` выставляются до решения. Тесты `tests/response.rs:421` (unmeasured/control/flaky), `:479` (общие векторы), `:649`. |
| `d2k_probe_response` | 310-324 | 806 | `memset(res)`, target-count по SNI, нейтральное имя, control-count, `decide` | response.rs:1207 `probe_response` | **P** | **Совпадает:** цель и контроль считаются на одном `host:port`; контроль — другое случайное имя (`neutral_sni`); решение — `decide(target,control,unmeasured,repeats)`. **Подтверждённые отличия:** (1) Rust до зондов проверяет `repeats>0` и представимость в `i32` и валидность legacy-приветствия, возвращая NotApplicable с текстом «число повторов…»/«недопустимое имя…»; C при `repeats<=0` делает 0 попыток и приходит к NotApplicable через `control==0` с другим текстом, а недопустимый SNI у C даёт Failed-попытки и тот же вывод `control==0`; (2) Rust заполняет `probes` (число попыток), C такого поля нет; (3) наследует различие метки по умолчанию `0x2d`/`0x40000000`; (4) `options.timeout` Rust нормализует заранее, C — внутри каждого `handshake` (значение то же). Тесты `tests/response.rs:203` (clear на loopback), `:221` (blocked), `:421`, `:649`, `:780`. |

### detect/response.c: построчная сверка

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

## detect/trigger.c (9 функций)

Чем меряем: ClientHello из снятого профиля, произвольный hex, контроль, приманка и вопрос о метке
времени клиента. Байты приветствий совпадают с C побайтно (тесты `tests/hello.rs`). Контроль и
разбор TCP-опций клиента в R2O перенесены не как отдельные функции: контроль собран в CLI,
признак метки передаётся булевым `client_tcp_has_timestamps`, переопределения нет.

**Прочитано построчно: 9/9 функций, 207 строк C (1–207).** Сверено с `classify.rs:60-108` (`Accept`, `Trigger::{raw_hex,tls,tls13}`), `trigger.rs:4` (`parse_raw_hex`), `raw_probe.rs:602-629` (`select_bridge_decoy`), `:673-683` (`raw_offer_timestamps`), `:731-733` (`raw_profile_allows`), `:967-985` (`property_probe_poison`), `main.rs:1555` (`classify_control_trigger`).

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_trigger_tls` | 21-50 | 1378 | ClientHello из снятого профиля (legacy/modern) с SNI; n≥16; name `tls:<sni>`; accept ServerHello; sni_off/len | classify.rs:87 Trigger::tls, :96 Trigger::tls13, hello.rs:549 | **E** | C `d2k_hello_from_profile(legacy?LEGACY:MODERN, sni)`, пустой SNI/ошибка/n<16 → -1, затем `d2k_hello_sni`. Rust `Trigger::tls`/`tls13` через `legacy_client_hello`/`modern_client_hello`, name/accept те же; смещения SNI — `hello::sni_bounds` на месте вызова. Байты совпадают: `tests/hello.rs:42` legacy, `:50` modern, `:62` fake; `tests/classify.rs:946`. |
| `hexval` | 52-58 | 7 | hex-цифра → 0..15, иначе -1 | `trigger.rs parse_raw_hex` (match) | **E** | C три диапазона: `0-9` → `c-'0'`, `a-f` → `c-'a'+10`, `A-F` → `c-'A'+10`, иначе -1. Rust `parse_raw_hex` match с теми же диапазонами; `tests/trigger.rs:41`. |
| `d2k_trigger_raw_hex` | 67-108 | 1322 | hex-триггер: разделители `space/tab/nl/cr/:/ -`, нечётный/битый/короткий/длинный отказ; name `raw:NB`; accept Any | classify.rs:77 Trigger::raw_hex, trigger.rs:4 parse_raw_hex | **E** | C пропускает те же разделители, `n<2`/нечётный/битый/`n>=sizeof payload` → ошибка, name `raw:%dB`, accept **всегда ANY** (`trigger.c:106`). Rust `TRIGGER_MAX=16384`, те же проверки, name и `Accept::Any`. Правило «первый байт 0x16 → ServerHello» принадлежит `core/verdict.c:33-35` (`looks_like_tls`), а не detect-триггеру, и здесь не применяется. `tests/trigger.rs:41-58`; `raw_hex_acceptance_matches_the_detect_trigger`. |
| `d2k_trigger_control` | 118-128 | 376 | контроль: `probe-<tag>.invalid-control.example`, **modern TLS** (`legacy=0`), name `control`, accept TLSRecord | main.rs:1555 classify_control_trigger | **P** | C строит **modern**-приветствие (`d2k_trigger_tls(name, 0, ...)` → `D2K_SHAPE_MODERN`), Rust по умолчанию тоже `Trigger::tls13` (modern); профиль совпадает. Имя по умолчанию `probe-d2k.invalid-control.example` и name `control` совпадают. Отличие — C принимает произвольный `tag` в `probe-<tag>...`, Rust жёстко фиксирует тег `d2k`; CLI-путь `--control-sni` даёт `control:<sni>` в обеих реализациях, `--control-raw` — raw_hex + name control + `TlsRecord`. P только по API тега. |
| `d2k_opts_decoy` | 130-136 | 153 | приманка: `o->decoy`, если len≥2, иначе `o->control` | raw_probe.rs:602 select_bridge_decoy | **P** | C просто выбирает готовый `decoy`/`control` без trigger. Rust `select_bridge_decoy(trigger,control,trigger_snapped)` возвращает fallback control≥2 либо **клонирует trigger с SNI из control**; это другая конструкция. Прямого `options.decoy`/селектора нет; fallback на control есть. |
| `d2k_trigger_host_ts_override` | 156-156 | 66 | глобальный сеттер `host_ts_override` | `ClassifyOptions.client_tcp_has_timestamps` (`classify.rs:833`), `raw_offer_timestamps` (`raw_probe.rs:673`) | **P** | C статический `host_ts_override` (-1/0/1), влияет на `host_offers_ts`. Rust передаёт `Option<bool>` явно; глобального сеттера/CLI-override нет. Поведение выражается, API иное. |
| `host_offers_ts` | 158-178 | 638 | override → cached чтение `/proc/sys/net/ipv4/tcp_timestamps`, default 1 | raw_probe.rs:673 raw_offer_timestamps | **P** | C `host_ts_override>=0` затем `static cached`; Rust `HOST_TCP_TIMESTAMPS OnceLock`, парсит тот же файл, default 1. Кэш/дефолт совпадают, override отсутствует. |
| `d2k_trigger_offers_ts` | 180-199 | 615 | нет профиля → host_offers_ts; иначе разбор TCP-опций, kind 8/10 → 1 | raw_probe.rs:673/731 | **P** | C парсит `client_tcp_options` байт за байтом (kind 0 break, 1 skip, неверная длина →0, 8/10 →1). Rust `raw_offer_timestamps(Option<bool>)` использует готовый bool из профиля, байты не разбирает; расхождение представления, не результата для уже снятого профиля. |
| `d2k_trigger_allows_poison` | 201-207 | 165 | `!p->tcp_ts` или `offers_ts(t)` | raw_probe.rs:731 raw_profile_allows, :967 fallback | **P** | Формула `!tcp_ts` или `offer_ts` совпадает. Но Rust `property_probe_poison` при `WhiteTimestamp`, если TS не предложен и checksum не validated, **заменяет** poison: `tcp_ts=false`, `badsum=true`; C просто возвращает 0. Это дополнительная fallback-ветвь, не входящая в `d2k_trigger_allows_poison`. |

### detect/trigger.c: построчная сверка

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

## detect/include/d2k_detect.h (1 функция)

Единственная функция заголовка — правило большинства для вопросов о свойствах.

**Прочитано построчно: 1/1 функция (`d2k_prop_majority`, 490–493); остальные строки заголовка —
typedef/#define/прототипы, сверены по использованиям в `detect/*.c`.** Сверено с `raw_probe.rs:665-667 majority`.

| C-функция | строки | размер | назначение | R2O (file:line/символ) | статус | доказательство/пробел |
|---|---|---:|---|---|---|---|
| `d2k_prop_majority` | 490-493 | 108 | `repeats>0 && pass>repeats/2` | `raw_probe.rs` `majority` | E | C inline и Rust `majority` дают `total != 0 && pass > total/2`. Тест `prop_majority_matches_c` покрывает 0/0, 1/1, 1/2, 2/3, 2/4, 3/4. |

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
