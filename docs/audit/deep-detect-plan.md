# Глубокий аудит: detect N-ряды и datapath-plan N/ключевые P

Дата: 2026-11-11. Независимый проход только по исходникам; существующие отчёты не изменялись,
роутер не затрагивался. Новый файл — этот.

## Baseline

- D2O (oracle): `E:\d2o-a378w`, HEAD `a378e230947ebfd011439e1cac0f1e994d883aae`
  (прочитан из worktree-файла `.git/worktrees/d2o-a378w/HEAD`; `git status` чист).
- R2O: `E:\r2o`, HEAD на момент записи `05f947b546eaeb8c66134f21a9ad2750901879e9`
  (ветка `main`). Во время аудита HEAD двигался (`64ae7ffc` → `3e61a01f` → `89eb4f1` →
  `05f947b`), но все эти коммиты — только `docs/audit`; `git status --porcelain -- crates`
  пуст, то есть проверенный код `crates/` стабилен.
- Важно: `docs/audit/detect.md` и `docs/audit/datapath-plan.md` ссылаются на HEAD
  `9272eafa7992e88dff99cd25056e93157008a3d5` и уже отстали. Более того, `detect.md` в рабочем
  дереве правится другой сессией (на момент проверки в нём по-прежнему N=12 и N-статус
  `d2k_detect_stop_all`/`d2k_trigger_host_ts_override`); мой проверенный список ниже —
  независимый. Номера строк даны по текущему дереву `E:\r2o`, а не по цитатам старых отчётов.
- Срезы: `E:\r2o-tooling\audit\slice-detect.csv` — 159 функций; `slice-datapath-plan.csv` — 183.
- Метод: прочитано тело каждой проверяемой C-функции по `line..end_line`; Rust-реализация
  искалась по коду и вызовам, а не только по кандидатам CSV; проверялись ветви, коды ошибок,
  отмена, побочные эффекты и места вызова. Для ключевых P дополнительно сверены парсеры,
  финализаторы и тесты.
- Ограничение: живой DPI, OpenWrt/musl/mipsel, root-raw-send и rtnetlink на роутере не
  проверялись. C/Rust differential в этом проходе не запускался. Тесты запускались только
  четыре точечных (см. §6); для остальных цитат — «тест есть, не перезапускался».

## Статусы

- **E** — эквивалент подтверждён существующим тестом/фикстурой/дифференциалом.
- **P** — реализация есть, но ветвь/край/форма отличаются либо не доказаны.
- **N** — реализации/наблюдаемого API нет.
- **?** — не установлено (нет ни доказанного эквивалента, ни доказанного отсутствия).

---

## 1. detect: все N-ряды (12 строк среза)

**Прочитано построчно: 12/12 строк N-среза; тела прочитаны по фактическим строкам, R2O-отсутствие/частичность подтверждены.**

| C-функция | C-строки | группа | текущий | проверенный | Rust (file:line/символ) | доказательство/конкретный пробел |
|---|---|---|---|---|---|---|
| `d2k_detect_stop_all` | bridge.c:45 | detect/bridge | N | **P** | `main.rs:14251-14261` `Drop for DiscoveryWorker`; `main.rs:78` `R2O_CONTROLLER_STOP`; `classify.rs:1041` `stopped` | Отдельного процессного символа нет, но остановка службы достижима: `Drop` воркера взводит `cancel` и все `active_cancels`, а классификатор читает `AtomicBool`. Это то же наблюдаемое «бросить все замеры», но привязано к объекту воркера, а не к глобальному липкому флагу. Старый N не подтверждён. |
| `trace_questions` | bridge.c:284-309 | detect/bridge | N | **N** | `main.rs:8121-8145` `update_probe_progress`; `classify_json.rs:68-83` `trace` | R2O отдаёт живую строку «вопрос · проверок/прошло/отказов» в панель и хранит `Observation` в `ClassifyResult.trace`, но не формирует `qtrace` с итогом YES/NO/UNKNOWN для планировщика, как C `d2k_quic_step`/`D2K_QTRACE_MAX`. Итоговый ответ вопроса после завершения поиска никуда отдельно не уходит. |
| `note_gap_loss` | classify.c:238-247 | detect/classify | N | **N** | `classify.rs:935-958` `ClassifyResult`; `classify_measured.rs:335-337` | Поля `notes` нет; предупреждение «приём опирался на паузу» не печатается. При этом R2O реально переносит `gap_ms` в `gap_us` плана, то есть теряется отчётность, а не packet-path. Для полного паритета нужен `notes`/строка в причине. |
| `cross_check_tls12` | classify.c:1084-1092 | detect/classify | N | **N** | `classify.rs:935-958` — поля `covers_tls12` нет | В C это честная заглушка: при `cross_check_tls12` она ставит `D2K_TRI_UNSET` и note. В R2O нет ни флага, ни поля, ни note. Функционального обхода здесь нет, но API/JSON-поле отсутствует. |
| `d2k_parse_rst_rule` | raw.c:79-118 | detect/raw | N | **N** | `raw_probe.rs:1749-1824` `sweep_stale_iptables` | R2O не разбирает строки `iptables -S`: нет точного префикса `-A OUTPUT -p tcp -m tcp --sport`, диапазона `30000..54999`, legacy-суффикса без комментария и owned-формы `d2k-rst:PID`. Уборка знает только `--comment r2o-rst:`. |
| `d2k_parse_stale_rst_rule` | raw.c:121-124 | detect/raw | N | **N** | то же | Отдельного legacy-входа нет. |
| `d2k_rst_rule_stale` | raw.c:137-143 | detect/raw | N | **N** | `raw_probe.rs:1780-1795` | R2O ищет только свой тег `r2o-rst:` и проверяет `kill(pid,0)`; правило прежней версии без владельца и чужие `d2k-rst` не классифицируются и не снимаются. |
| `d2k_raw_pending_count` | raw.c:488-495 | detect/raw | N | **N** | `raw_probe.rs:1475` `RST_PENDING`; геттера нет | Очередь отложенных снятий внутри есть (`Vec<PendingRstRelease>`, предел 64), но диагностического API нет. C-функция используется только тестами (`detect/test_raw.c:539+`), на packet path не влияет. |
| `d2k_raw_set_segment_max` | raw.c:813-814 | detect/raw | N | **N** | `classify_measured.rs:12` `SEGMENT_SIZE=1400`, `:143`, `:355-376`; сеттера нет | **Существеннее, чем в старом отчёте.** В D2O это production-вызов: `core/d2kc.c:575` и `:789` ставят `d2k_arm_segment(send_maxlen)`. R2O в измеренном TCP-плане всегда пишет `segment 1400` и при нехватке `send_cap` отвергает план, а не режет по `send_cap-72`. На туннеле/LTE замер идёт сегментами 1400, а план датапата — другими. Это реальный packet-path пробел. |
| `d2k_raw_set_segment_max` (#else stub) | raw.c:1329 | detect/raw | N | **N** | то же | Заглушка вне Linux; в R2O единого сеттера нет ни в одной ветке. |
| `d2k_raw_pending_count` (#else stub) | raw.c:1333 | detect/raw | N | **N** | то же | То же; геттера нет. |
| `d2k_trigger_host_ts_override` | trigger.c:154-156 | detect/trigger | N | **P** | `classify.rs:833` `client_tcp_has_timestamps: Option<bool>`; `raw_probe.rs:673-683` `raw_offer_timestamps`; `main.rs:10433-10437` | Ось переопределения реализована как параметр классификатора: `Some(v)` принудительно задаёт ответ, `None` читает `/proc/sys/net/ipv4/tcp_timestamps`. C-сеттер — глобальный и тестовый; в R2O нет глобального сеттера/CLI и нет отдельного теста переопределения. Это P, не N: поведение достижимо через API. |

### Сверка N-списка detect

Старый отчёт: 12 строк = 10 различных функций (пары Linux/#else у `pending_count` и
`set_segment_max`). Список подтверждён: `stop_all`, `trace_questions`, `note_gap_loss`,
`cross_check_tls12`, `parse_rst_rule`, `parse_stale_rst_rule`, `rst_rule_stale`,
`pending_count`, `set_segment_max`, `host_ts_override`.

После проверки: **10 N-строк = 8 функций** (N остаются `trace_questions`, `note_gap_loss`,
`cross_check_tls12`, `parse_rst_rule`, `parse_stale_rst_rule`, `rst_rule_stale`,
`pending_count`, `set_segment_max`). `stop_all` и `host_ts_override` переведены в P:
у обоих есть работающий Rust-механизм, хотя форма/API иные.

---

## 2. datapath-plan: N/?-ряды (6 строк)

**Прочитано построчно: 6/6 строк N/?-среза; тела прочитаны, статусы сверены с R2O.**

| C-функция | C-строки | группа | текущий | проверенный | Rust (file:line/символ) | доказательство/конкретный пробел |
|---|---|---|---|---|---|---|
| `d2k_plantab_shape_misses` | plans.c:1058-1060 | datapath/plans | N | **N** | `control.rs:92`, `:166`, `:193-195` `r2o_shape_misses` | Поле `shape_misses` объявлено, инициализировано и читается геттером, но **нигде не инкрементируется**: grep по `crates/` даёт только эти четыре места. В C счётчик растёт в трёх ветвях `d2k_plantab_find_target` (`plans.c:1140`, `:1209`, `:1233`) и наблюдаем через `d2k_plantab_shape_misses`; session использует его для `quic_shape_miss` (`session.c:1270-1277`). R2O всегда отдаёт 0. |
| `d2k_plantab_has_ech_target` | plans.c:288-314 | datapath/plans | ? | **?** | точного предиката нет; `hold.rs:574-587`, `:1335-1341` — общий `incomplete_tls_head`; `engine.rs:1051-1065` — `client_shape` | Предикат «есть ECH-привязка имени/адреса/суффикса с учётом sport и bypass» отсутствует. R2O удерживает любой неполный TLS-record (`hold.rs`), то есть покрывает обычный однозаписный случай шире C, но не доказывает C-семантику для `extensions_truncated` при полной записи, ECH-привязки по адресу/суффиксу и `controller_probe`. Нужен адресный differential: ECH-привязка → удержание, без неё → нет. Оставить `?`, не N: поведение может быть покрыто общим hold. |
| `d2k_routemark_describe` | routemark.c:327-343 | datapath/routemark | N | **N** | `main.rs:954-964` — лог только политики `0xmark/0xmask` | Форматтера набора правил «0xmark/0xmask v4, …» нет. Лог `--only-mark` печатает одну выбранную политику, а не весь `sel[]`. Влияние — диагностика/лог. |
| `d2k_ctl_listen_fd` | ctl.c:143 | datapath/ctl | N | **N** | `control.rs:1750` приватный `listener`; цикл `main.rs:1388` вызывает `control.poll()` | fd наружу не отдаётся; внешний epoll-цикл C заменить нечем. Для архитектуры R2O это осознанно, но ABI-функции нет. |
| `d2k_ctl_peer_fd` | ctl.c:144 | datapath/ctl | N | **N** | `control.rs:1757` приватный `peer: Option<UnixStream>` | То же: пир инкапсулирован, доступа к fd нет. |
| `d2k_ctl_sent` | ctl.c:316 | datapath/ctl | N | **N** | `control.rs:1983` только `dropped_events` | Счётчика поставленных в кольцо кадров нет. C `sent++` делает в `d2k_ctl_event` (`ctl.c:253`) до фактической записи; R2O умеет считать только потери. |

### Сверка N-списка datapath-plan

Старый отчёт: N = 5 (`shape_misses`, `routemark_describe`, `ctl_listen_fd`, `ctl_peer_fd`,
`ctl_sent`), `?` = 1 (`has_ech_target`). Это подтверждено.

В постановке задачи `has_ech_target` ошибочно назван N, а `peer_fd`/`sent` — одной строкой.
Фактически: `has_ech_target` — `?`; `ctl_peer_fd` и `ctl_sent` — две разные N-строки. Поэтому
N остаётся 5, а не 4 и не 6.

---

## 3. Ключевые P: проверка по телам

**Прочитано построчно: ключевые P из таблицы; тела и ветви проверены по фактическим строкам.**

| C-функция | C-строки | группа | текущий | проверенный | Rust (file:line/символ) | доказательство/конкретный пробел |
|---|---|---|---|---|---|---|
| `d2k_plan_apply` | plan_apply.c:343-873 | datapath/plan_apply | P | **P** | `plan/apply.rs:155` `Plan::apply` | Три конкретных расхождения: (1) OOB-суффикс остаётся с `wire_profile=0`; (2) qsplit-ветвь обходит `delay_us`; (3) `MAX_EMISSIONS=26` против 65536 в C. Подробно §3.1. |
| `d2k_plan_fits` | ctlsrv.c:39-72 | datapath/ctlsrv | P | **P** | `control.rs:255-258` `r2o_plan_valid`; `engine.rs:2091-2093` | Ветвь длины покрыта `name_plan_отклоняется_если_..._mtu` (`control.rs:2766`). Ветвь `POISON_IPID_ZERO` реализована всегда (R2O отвергает), тогда как C проверяет её только при `limits != 0`; теста на неё нет. |
| `d2k_ctlsrv_command` — `SET_HTTPS` | ctlsrv.c:439-454 | datapath/ctlsrv | P | **P (TTL закрыт)** | `control.rs:1055-1096` `set_https`; `r2k-core/control.rs:64`, `:1777-1792` `encode_set_https` | **Закрыто 2026-11-12:** `MAX_HTTPS_TTL_SECONDS = 7 суток`, датапат **обрезает** TTL (`ttl.min(max)`), кодировщик принимает любой `u32` — как C (`d2k_ctl.h:231`, `ctlsrv.c:446`). Тесты кодировщика (`21_601`, `u32::MAX`) и датапата (7 суток). Остаётся P: C требует доступный `cx->http80` (`ctlsrv.c:440`), R2O-проверки портала нет; TTL=0 удаляет имя в обоих. |
| `d2k_ctlsrv_command` — `ARM_SHAPE` | ctlsrv.c:329-377 | datapath/ctlsrv | P | **P** | `control.rs:1988-2050` `arm_client_shape`; `r2k-core/control.rs:917-935` `decode_arm_shape` | C принимает транспорт 6 и 17 (`ctlsrv.c:341`) и для TCP сначала шлёт `EV_CLIENT_TCP` с реальными TCP-опциями, затем `EV_SHAPE` (`:360-371`). R2O декодер принимает 6/17, но датапат отвергает всё, кроме 6 (`control.rs:2002`); кэш ищет только `family+host`, без транспорта; на попадании отдаёт один `EVENT_CLIENT_SHAPE` (`main.rs:1390-1398`), а v22-транслятор шлёт `EVENT_LEGACY_CLIENT_TCP` с пустыми опциями (`r2k-core/control.rs:1208-1216`). UDP ARM_SHAPE не обслуживается. |
| `d2k_ctlsrv_command` (остальные ветви) | ctlsrv.c:189-509 | datapath/ctlsrv | P | **P** | `control.rs:260-368` `NamePlans::handle`; `main.rs:68-86` `handle_control_command` | Покрыты SET_NAME/BOUND/PROBE/ADDR/SUFFIX/BYPASS/DEL_*/HTTPS/ARM_SHAPE. Расхождения: C `SET_SUFFIX`/`DEL_SUFFIX`/`SET_BYPASS`/`DEL_BYPASS` допускает только формы 1/2/6 при transport 6 или 3 при 17 (`ctlsrv.c:381-384`), R2O `valid_domain_area_context` дополнительно принимает context-формы 8-13 и ECH_NO_TS/TS (`control.rs:1597-1604`) → ACK OK там, где C дал бы BAD_ARGS. C `SET_ADDR_PROBE` разрешает `src_port=0` как голосовой wildcard (`ctlsrv.c:302-306`), R2O `valid_udp_addr_probe_flow` требует ненулевой src-порт (`r2k-core/control.rs:1701-1709`). C `SET_NAME` проверяет в основном family и HTTP/proto, R2O дополнительно требует совместимость transport/proto с формой (`control.rs:859-868`) — R2O строже. |
| `d2k_raw_*` | raw.c:193-256, 341-404, 406-512 | datapath/raw | P | **P** | `raw.rs:35-44` `RawSocket`, `:48-93` `open`, `:147-223` `send_packet`, `:559-651` `outgoing_packet`; `engine.rs:2091` | C держит `fd`, `fd6`, `fragment_fd` (`raw.c:201-204`): IPv4 открыт сразу (`:217`), IPv6 — лениво (`:354-372`), IPv4-фрагменты — отдельным сокетом с `IP_NODEFRAG` (`:384-399`); mark=0 допустим (`:234`). R2O: один `fd` на выбранное семейство, mark обязателен (`raw.rs:55-60`), отдельного fragment-сокета и `IP_NODEFRAG` нет, IPv6-сокет не открывается лениво; фрагменты уходят через тот же fd (`raw.rs:186-195`). `d2k_raw_limits` (`CANT_IPID|CANT_IPSUM`, raw.c:201) как маски нет; `POISON_IPID_ZERO` R2O отвергает на отправке (`raw.rs:162-167`) и в `validate_runtime_plan` (`engine.rs:2091-2093`). |
| `d2k_compose_from_props` | props.c:426-498 | detect/props | P | **P** | `raw_probe.rs:1047-1099` `compose_from_props` | При `out.is_empty()` C **всегда** создаёт «СОБРАНО: всё сразу», даже при `ctl == NULL` (`props.c:477-486`), и в конце проставляет `decoy=ctl`, `decoy_len=0`, `seqovl=ctl_len` (`:488-496`). R2O создаёт этот кандидат только `if control.is_some()` (`raw_probe.rs:1094-1096`), и `seqovl` ставит только при `Some` (`:1091`). Без контроля/приманки R2O не пробует последний собранный кандидат. |
| `d2k_classify_run` | classify.c:1095-1476 | detect/classify | P | **P** | `classify.rs:1298-1837` `run_with_backend_progress` | P, но старый отчёт недооценил: production discovery использует **не** donor-режим. Подробно §3.2: `ClassifyOptions::default()` даёт `full_detect_semantics=false`, `confirm_clear=true` (`classify.rs:869-870`), а `r2o_discovery_classify_options` (`main.rs:15380-15391`) их не переопределяет. C всегда full: нет удвоенного retry по dial timeout, иная обработка частичных transport-ошибок, control без `until_pass`, нет `whole-confirm` и `unproven`-гейтов; плюс счёт probes ответного направления и отсутствие notes/covers/qtrace. |

### 3.1 `d2k_plan_apply`: OOB, qsplit, MAX_EMISSIONS

1. **OOB-суффикс теряет `wire_profile`.** C при `oob_enabled` собирает три посылки и уходит
   на `finalize` (`plan_apply.c:507`), где цикл `:812` ставит `p->wire_profile` **всем**:
   префиксу, срочному байту и суффиксу. R2O ставит профиль только первым двум
   (`apply.rs:284-285`), суффикс создаётся с `wire_profile=0` (`:280-283`), после чего
   `segment()` клонирует посылку (`:939-968`), сохраняя 0. C `wire.c:122-127,204-210` для
   profile=0 даёт другой IP ID/DF/TTL, чем для measured profile; значит суффикс OOB-плана
   уйдёт на провод с другими заголовками, чем в C. Тест
   `urgent_oob_plan_sends_prefix_urgent_byte_and_suffix` (`tests/apply.rs:273`) профиль не
   проверяет и потому дефект не ловит (запущен, PASS — см. §6).
2. **qsplit обходит `delay_us`.** C трансформирует payload в общем цикле (`plan_apply.c:645-666`),
   затем применяет `pace/settle/delay` (`:785-809`). R2O qsplit-ветвь возвращает `Actions`
   сразу (`apply.rs:203-251`), до `apply_timing` (`:402`). Парсер qsplit не запрещает
   `delay` (`plan.rs:553-566` не перечисляет `delay_us`), поэтому `qsplit+delay` принимается,
   но задержка молча теряется. `pace` при одном payload в C всё равно даёт 0, поэтому
   наблюдаем именно `delay`.
3. **`MAX_EMISSIONS=26`.** R2O `apply.rs:9` (`WIRE_BATCH_MAX`, `plan.rs:10`) отвергает
   `emission_capacity > 26` (`:335-340`) и нарезку >26 (`:704-709`). C `plan_apply.c:830`
   допускает до 65536 сегментов, а отдельного лимита 26 в `d2k_plan_apply` нет; D2O
   ограничивает 26 только на выдаче session (`session.c:2517`,
   `datapath/include/d2k_plan.h:50` `D2K_WIRE_BATCH_MAX 26`). Для датапата итоговый отказ
   совпадает, но для `detect/raw.c:1240` (C вызывает `d2k_plan_apply` напрямую) и для
   измеренных планов с `repeats > 26` — нет. Это P-край, а не «доказанный E».

### 3.2 `d2k_classify_run`: production-ветвь отличается от C

- `ClassifyOptions::default()`: `full_detect_semantics=false`, `confirm_clear=true`
  (`classify.rs:869-870`). `r2o_discovery_classify_options` (`main.rs:15380-15391`) задаёт
  только mark/timestamps/cancel/seed, поэтому **серверный discovery** идёт по «core
  cancelable path», а не по donor-семантике. CLI `--classify` явно ставит
  `full_detect_semantics=true`, `confirm_clear=false` (`main.rs:1169-1185`), и именно CLI
  проверяют дифференциалы.
- Следствия в discovery:
  - нет одного удвоенного retry по `dial tcp ... i/o timeout` (C `classify.c:1182-1196`;
    R2O только при `full`, `classify.rs:1345-1364`);
  - базовая ошибка обрабатывается только при `base.errors == repeats`
    (`classify.rs:1390-1398`), а C при `has_err && pass==0` различает dial deadline и
    unreachable (`classify.c:1197-1212`); частичная transport-ошибка в R2O не даёт
    `flaky/unreachable`, а проваливается дальше по дереву;
  - control измеряется без `until_pass` (`classify.rs:1538`), тогда как C передаёт
    `until_pass=1` (`classify.c:1272-1273`);
  - добавляется `whole-confirm` на 2 пробы и требование 5/5 для clear
    (`classify.rs:1400-1450`, `CLEAR_CONFIRM_REPEATS=2`), а также `unproven`-гейты
    (`:1567-1585`), которых в C `d2k_classify_run` нет.
- Счёт probes ответного направления: C добавляет `2 * opt->repeats` безусловно при наличии
  SNI (`classify.c:1226`), R2O добавляет фактическое число попыток (`classify.rs:1463-1473`;
  `response.rs:1158` инкрементирует на каждой попытке). При ошибке/раннем выходе числа
  расходятся.
- `notes`/`covers_tls12`/`qtrace` отсутствуют (см. N-таблицу). `cross_check_tls12` в C
  вызывается для hit/prefix/whole (`classify.c:1352,1426,1459`), в R2O вызова нет.
- Тест `test-classifier-full-tree-control-differential.sh` и фикстура
  `tests/classify.rs:322` используют `full_detect_semantics=true`, то есть **не покрывают
  production discovery** с дефолтами. Это конкретный пробел доказательства, а не только
  «нет notes».

### 3.3 `d2k_raw_*`: сокеты, mark, IP_NODEFRAG

- C: `d2k_raw_open` всегда открывает IPv4 (`raw.c:217`), IPv6 — лениво при первом IPv6-пакете
  (`raw.c:354-372`), IPv4-фрагменты — отдельным `fragment_fd` с `IP_NODEFRAG`
  (`raw.c:384-399`); `mark=0` допустим (`raw.c:234`).
- R2O: `RawSocket` имеет один `fd` и поле `family` (`raw.rs:35-44`); `open(family, mark,
  interface)` вызывается с одним `options.protocol_family` (`main.rs:936-944`, дефолт
  IPv4 `main.rs:2758`), mark=0 запрещён (`raw.rs:55-60`), `IP_NODEFRAG` не ставится,
  IPv6-фрагменты и IPv4-фрагменты уходят через тот же fd (`raw.rs:186-195`, `:559-651`).
- `d2k_raw_limits` C `CANT_IPID|CANT_IPSUM` (`raw.c:201`) как интерфейса нет; R2O вместо
  маски всегда отвергает `POISON_IPID_ZERO` (`raw.rs:162-167`, `engine.rs:2091-2093`).
- `d2k_raw_send` EINTR/EMSGSIZE/счётчики: логика R2O близка (`raw.rs:186-223`,
  `record_send_outcome`), но живой отправки в тестах нет (нужен root).
- `d2k_raw_sent/errors/busy` (`raw.c:514-524`) — R2O `send_stats()` есть
  (`raw.rs:100-102`); тест `raw_send_stats_count_success_and_busy_errors_like_d2o` есть,
  не перезапускался.

### 3.4 `d2k_compose_from_props`: «всё сразу» без контроля

C: `n==0 && cap>0` → всегда заполняет `out[0]` (`props.c:477-486`), затем для всех
`decoy_hello` ставит `decoy=ctl` и `decoy_len=ctl_len` (даже 0) и `seqovl=ctl_len`
(`:488-496`). R2O: `if control.is_some() { out.push(base) }` (`raw_probe.rs:1094-1096`), а
`seqovl` — `control.map_or(0, ...)` только внутри этой ветви (`:1091`). При отсутствии
контроля R2O не пробует последний кандидат; C пробует его с пустой приманкой. Тест
`test-classifier-raw-production-differential.sh` (compose case) использует контроль
(`COMPOSE_SKIPS`), поэтому этот край не покрыт.

---

## 4. Предлагаемые исправления

### P0 — packet-path/поведение

1. **OOB `wire_profile`.** В `Plan::apply` OOB-ветви (`apply.rs:265-291`) проставлять
   `suffix.wire_profile = self.wire_profile` до `segment()`; в тест
   `urgent_oob_plan_sends_prefix_urgent_byte_and_suffix` добавить проверки профиля всех
   трёх посылок и нарезанного суффикса.
2. **`d2k_raw_set_segment_max`.** Ввести параметр сегмента в измеритель (из
   `send_cap`, формула C `d2k_arm_segment`: `send_cap<=72 → 0`, иначе
   `min(send_cap-72,1400)`) и использовать его в `classify_measured.rs` вместо
   `SEGMENT_SIZE=1400`; при `send_cap < body` резать, а не отвергать. Проверить
   `send_cap=0/72/1280/1492/1500` (C-тест `test_measured.c:501-508`).
3. ~~**SET_HTTPS.**~~ **Выполнено 2026-11-12:** `MAX_HTTPS_TTL_SECONDS` приведён к
   `D2K_HTTPS_TTL_MAX_S` (7 суток), отказ заменён обрезкой в `control.rs:1070`, кодировщик
   `r2k-core/control.rs:1781` принимает любой `u32`. Тесты покрывают `3600`, `21_601`,
   `u32::MAX` и границу 7 суток на датапате. Остаётся: требование `http80` (R2O всегда
   держит портал) — задокументировать/проверить отдельно.
4. **ARM_SHAPE UDP.** Не отвергать transport 17 в `arm_client_shape`; для TCP сохранить
   отдачу TCP-опций (сейчас v22-транслятор шлёт пустые). Добавить тест ARM_SHAPE с
   `transport=17` и тест кэша/события для TCP-опций.
5. **compose без контроля.** Убрать `if control.is_some()` вокруг «всё сразу»; при
   `control=None` создавать кандидата с `decoy_len=0`/`seqovl=0` (или явно доказать, что
   такой план неисполним и C-ветвь недостижима — тогда зафиксировать это в матрице).
6. **Production discovery semantics.** Либо выставить
   `full_detect_semantics=true`, `confirm_clear=false` в
   `r2o_discovery_classify_options` (`main.rs:15380`), либо официально признать отдельную
   продуктовую ветвь и убрать E-доказательство, полученное только через CLI. Добавить
   differential именно серверного discovery (не `--classify`) против C.

### P1 — края/API/диагностика

7. **qsplit + delay.** Применять `apply_timing` (хотя бы `delay_us`) в qsplit-ветви до
   возврата; тест `qsplit+delay`.
8. **`MAX_EMISSIONS`.** Либо оставить 26, но перенести отказ на слой session/батча и
   разрешить `Plan::apply` C-диапазон, либо доказать, что все входы ≤26; differential с
   27+ fake.
9. **ctlsrv-формы.** Либо сузить `valid_domain_area_context` до C-набора 1/2/6 и 17/3,
   либо явно объявить расширение протокола; тест SET_SUFFIX с формами 8-13. Для
   `SET_ADDR_PROBE` разрешить `src_port=0` как голосовой wildcard или отделить voice-команду.
10. **raw-сокеты.** Добавить второй/lazy IPv6-сокет и отдельный fragment-сокет с
    `IP_NODEFRAG` (или обосновать, что ядро R2O не дефрагментирует); разрешить mark=0 как C
    или зафиксировать обязательность; тест на root/живой отправке.
11. **classify-отчётность.** Вернуть `notes` (включая `note_gap_loss`), `covers_tls12`,
    `qtrace`/итог вопросов; синхронизировать счётчик probes ответного направления с
    `2*repeats` либо задокументировать фактический счётчик.
12. **RST-правила.** Портировать `d2k_parse_rst_rule`/`d2k_parse_stale_rst_rule`/
    `d2k_rst_rule_stale` (legacy без комментария, owned `d2k-rst:PID`, диапазон
    `30000..54999`); иначе R2O не снимет брошенное правило C-версии.
13. **`shape_misses`.** Инкрементировать в `select` там, где цель известна, а форма нет
    (аналоги C `plans.c:1140/1209/1233`), и отдавать в событие/диагностику.
14. **Мелкие API.** `d2k_raw_pending_count`, `d2k_ctl_listen_fd/peer_fd`, `d2k_ctl_sent`,
    `d2k_routemark_describe` — добавить геттеры/форматтер; `has_ech_target` — отдельный
    предикат и differential.

---

## 5. Counts

| Срез | Всего | E | P | N | ? |
|---|---:|---:|---:|---:|---:|
| detect (старый отчёт) | 159 | 49 | 98 | 12 | 0 |
| detect (после проверки) | 159 | 49 | **100** | **10** | 0 |
| datapath-plan (старый/проверенный) | 183 | 108 | 69 | 5 | 1 |

- detect: 12 N-строк старого отчёта = 10 функций. Подтверждено 10 N-строк = 8 функций;
  `d2k_detect_stop_all` и `d2k_trigger_host_ts_override` переведены в P (есть работающий
  Rust-механизм, но иная форма/API). E не перепроверялся и не повышался.
- datapath-plan: N=5 подтверждён (`shape_misses`, `routemark_describe`, `ctl_listen_fd`,
  `ctl_peer_fd`, `ctl_sent`); `has_ech_target` остаётся `?`. Ключевые P (8 строк:
  `plan_apply`, `plan_fits`, SET_HTTPS, ARM_SHAPE, `ctlsrv_command`, `raw_*`, compose,
  `classify_run`) подтверждены как P; ни одна не повышена до E.
- Итоговый подтверждённый процент паритета по этим срезам **не пересчитывается**: E-статусы
  старых отчётов в этом проходе не перепроверялись, а N→P — не E. Для консервативной оценки
  использовать E=49/159 и E=108/183, с оговоркой, что production discovery-ветвь
  `classify_run` дифференциалами не покрыта.

---

## 6. Выполненные проверки

Запущено в WSL (`/mnt/e/r2o`, cargo 1.98.0), 2026-11-11:

```text
cargo test -p r2k-core --test apply urgent_oob_plan_sends_prefix_urgent_byte_and_suffix -- --exact
  PASS: 1 passed, 0 failed
cargo test -p r2o-datapath --lib set_https_command_accepts_an_exact_name_with_a_bounded_ttl
  PASS: 1 passed, 0 failed
cargo test -p r2o-datapath --lib arm_shape_serves_cached_client_hello_of_older_target
  PASS: 1 passed, 0 failed
cargo test -p r2o-datapath --lib tcp_shape_context_8_13_selects_by_timestamp_profile
  PASS: 1 passed, 0 failed
```

Оговорка: OOB-тест PASS не опровергает дефект `wire_profile`, потому что профиль в нём не
проверяется. Остальные цитируемые тесты (полный классификатор, raw-production,
`control_server_*`, `name_plan_*`, `raw.rs` MTU-тесты, C `test_raw`/`test_plan_apply`)
**есть, но не перезапускались**. C-дифференциалы в этом проходе не запускались; живой
роутер, root-raw-send и OpenWrt/musl не проверялись.

---

## 7. Итог

- Все 12 N-строк detect проверены по телам: 10 N-строк (8 функций) подтверждены, 2 строки
  (`stop_all`, `host_ts_override`) переклассифицированы в P. Главный недооценённый пробел —
  `d2k_raw_set_segment_max`: это production-вызов D2O (`d2kc.c:575,789`), а R2O жёстко
  сегментирует 1400 и отвергает планы при узком `send_cap`.
- Все 5 N datapath подтверждены; `has_ech_target` остаётся `?` (общий hold шире точного
  C-предиката, адресного differential нет).
- Ключевые P подтверждены. Наиболее конкретные packet-path дефекты: потеря `wire_profile`
  у OOB-суффикса (`apply.rs:280-291`), игнор `delay_us` в qsplit, диапазон/обрезка SET_HTTPS
  (6 ч/отказ против 7 сут/обрезка), отказ ARM_SHAPE для UDP 17, обязательный mark и
  отсутствие `IP_NODEFRAG`/ленивого IPv6, а также production discovery с
  `full_detect_semantics=false`, не покрытый существующими дифференциалами.
- Никаких заглушек и упрощений в R2O не добавлялось; отчёт фиксирует только проверенные
  расхождения и ограничения проверки.
