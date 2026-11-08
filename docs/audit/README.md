# Аудит покрытия D2O → R2O (2026-11-07)

## Назначение

Документ фиксирует исчерпывающую инвентаризацию production-поверхностей D2O и их фактическое покрытие в R2O. Он не является заявлением о готовности: наличие Rust-кода, успешная компиляция или mock-тест сами по себе не дают баллов паритета.

## Зафиксированные ревизии

| Сторона | Дерево | Ревизия | Примечание |
|---|---|---|---|
| D2O | `E:\d2o` | `a378e230947ebfd011439e1cac0f1e994d883aae` | Локальный HEAD main. Матрица закреплена на `a63d964`; часть записей ниже сверена с `8e2c981`. Полная переоценка относительно `a378e23` не выполнялась. |
| R2O | `E:\r2o` | `de0298cd789896cc442be70c0831eafa10192580` | Рабочая ветка `codex/update-functional-parity-matrix-2026-11-06`. Матрица называет базовым `234f729` (origin/main); рабочее дерево содержит более поздние доказательства и правки. |

`git`, `cargo` и `rustc` отсутствуют в Windows PATH. В WSL Ubuntu 26.04 доступны `cargo 1.98.0` и `rustc`; в этом аудите сборки не запускались, поэтому новые результаты тестов не заявляются. Все статусы ниже опираются на исходники и уже существующие дифференциалы.

## Метод

1. Механически извлечены все определения production-функций C: `docs/audit/function-index.md` (**2584 функции**: 2523 в `.c` + 61 `static inline` в заголовках; тестовые файлы, `planlab.c`, `ctlprobe.c`, `probe_mtproto.c` и relay-harness `test.c` исключены). Индекс пересобран независимым лексическим экстрактором 2026-11-08; прежний эвристический индекс содержал 3 ложных срабатывания и пропускал 3 `.c`-функции и 61 header-inline функцию.
2. Извлечён индекс Rust-функций: 3602 функции в 110 файлах `crates/*/src`.
3. Для каждого C-файла определён Rust-владелец, вызывающий путь, существующие тесты и фактический статус. Детали — в отчётах:
   - `docs/audit/datapath-detect-audit.md`;
   - `docs/audit/core-controller-audit.md`;
   - `docs/audit/panel-router-vps-telegram-audit.md`;
   - `docs/audit/matrix-consistency-audit.md`.
4. Проверена природа доказательств: 179 shell-скриптов, из них 144 ссылаются на D2O, 112 собирают/извлекают C, 128 закрепляют ревизию, 43 используют kernel/netns/QEMU/WSL.
5. Статусы: `эквивалентно` — прямой C/Rust differential на перечисленные ветви; `частично` — часть ветвей подтверждена; `реализовано` — путь есть, C-сравнения нет; `не проверено` — пригодного прогона нет; `missing` — Rust-аналога нет; `not-applicable` — вне продуктовой области.

## Валидация 2026-11-08

Независимая проверка пересобрала function-level индекс и сверила его с отчётами и матрицей. Результат:

- production `.c`-функций — 2523; header-inline — 61; всего **2584**;
- прежний индекс содержал 3 ложных срабатывания и пропускал 3 `.c`-функции и 61 header-inline;
- **660** функций не названы в тексте отчётов; для них действует module-level статус, они перечислены отдельно;
- найдены и добавлены 11 отсутствовавших контрактов; после нормализации scored-матрица — **179 контрактов / 271 балл** (Panel `A1–A26`, Router `B1–B54` без `B32/B45/B54`, Telegram `TG1–TG26` без `C2/C25/C26`; coarse `P*`/`F*`/`L*`/`T*` и `S7`/`S8` удалены);
- строгий счёт: **106/271 = 39,11 %**; carry с явно помеченными `304ba893`: **169/271 = 62,36 %**;
- `a63d964` и `304ba893` отсутствуют в локальном git D2O; закреплённые на них evidence здесь не воспроизводятся;
- детальные Panel/Router/Telegram подконтракты (26 + 51 + 23) сведены; 6 строк вынесены вне scored как extension/out-of-scope.

Рост строгого счёта с 25,69 % до 39,11 % — следствие замены 30 coarse-баллов `F*`/`L*`/`T*`/`P*` (18 strict) на 84 детальных Router-балла (67 strict) и добавления 71 балла Panel/Telegram с нулём; ещё 2 балла дали доказанные `M7a`/`M7b`, 8 — `B9`/`B52`/`B53`/`B42`/`B40`, 3 — `A26`/`A21`/`A8`, 1 — `TG20`, 2 — `D20`, 2 — `D23`, 1 — `D22`, 2 — `S12`, 2 — `S13`, 2 — `S14`, 2 — `S15`, 1 — `A3` и 1 — `A25`. Это не новые доказательства; знаменатели 144 и 271 несопоставимы.

Полный разбор — `docs/audit/validation-2026-11-08.md`.

## Трёхуровневая оценка доказательств

Матрица смешивает три разных уровня доказательств. Их нельзя складывать в один процент.

| Уровень | Что принимается | Текущий результат |
|---|---|---|
| **A. Текущая ревизия** | Прямой C/Rust differential, закреплённый на `a63d964`, `a378e23` или `8e2c981` | **106/271 = 39,11 %** (нормализованная матрица) |
| **B. Перенос с 304ba893** | Paired differential на `304ba893`, путь кода с тех пор не менялся и это зафиксировано | **169/271 = 62,36 %** (только строки, явно помеченные `carry (304)`) |
| **C. Legacy-агрегат** | Текущая таблица 57 строк без разделения A/B/C и без проверки helper/mock/build | **80/89 = 89,89 %** |

Вывод: **89,89 % не является оценкой текущей ревизии.** 49 из 80 баллов опираются на дифференциалы, закреплённые на `304ba893`. Это не обязательно означает регресс кода, но означает отсутствие воспроизводимого текущего доказательства. Пока скрипты не перепинены и не перезапущены, корректная формулировка — «перенос подтверждён на 304ba893», а не «эквивалентно текущему D2O».

Классификация 179 shell-скриптов по тексту:

| Класс | Количество |
|---|---:|
| paired differential (`diff`/`cmp`/сравнение выходов) | 51 |
| независимые C- и Rust-suites без сравнения выходов | 43 |
| C-fixture без Rust-сравнения | 18 |
| source-extract differential (извлечение shell-функции D2O) | 13 |
| mock/service differential | 13 |
| source reference | 13 |
| Rust-only | 9 |
| прочее | 19 |

Независимые suites и helper/fixture не доказывают эквивалентность поведения. Например, `r2o-udp-exchange-differential.sh` запускает C-тест и Rust-тесты отдельно и проверяет только `ok` в логе; `r2o-quic-stun-watch-differential.sh` также не сравнивает выходы C и Rust.

## Сквозные пробелы

### MEASURE_MARK контроллера

D2O `d2kc` принимает `--mark` (verifier) и `--measure-mark` (измерения); `d2k_sched_set_measure_mark` использует отдельную метку для volume/voice/classify-измерений. R2O `--serve` принимает только `--mark`, а `parse_serve_options` не знает `--measure-mark`. В R2O измерения идут с `PROBE_MARK` (0x2e), тогда как D2O — с `MEASURE_MARK` (0x2f). Это наблюдаемое различие в трактовке NFQUEUE и требует отдельного контракта.

### Header-inline функции и TCP shape contexts

Прежний индекс учитывал только `.c`-файлы. Валидация 2026-11-08 добавила 61 production `static inline` функцию из заголовков. Среди них обнаружены реальные пробелы:

- `d2k_link_shape_tcp_profile/base/context` кодируют TCP timestamp-совместимость в shape 8–13; R2O знает только shapes 1–7.
- `d2k_runtime_heartbeat/start_ticks/listener_ready/offline` не имеют аналога для datapath/controller.
- `d2k_ip6frag_send.h` использует `AF_PACKET` + ручной route/neighbor lookup; R2O полагается на kernel `AF_INET6`, поведение не сравнивалось.
- HTTP/resource/packet/ctl/binding/diag header-helpers в основном отображены, но не имеют индивидуальных дифференциалов.

### Heartbeat-файлы

D2O datapath, controller, panel и Telegram пишут `D2KH1 ...` через `d2k_runtime_heartbeat`. R2O:
- panel пишет `R2OH1 ...` (другой формат);
- datapath и controller не принимают `--health-file` и не пишут heartbeat;
- S99r2o не передаёт `--health-file` datapath/controller.

Это не только формат, но и отсутствующий side effect для watchdog/health. Нужен контракт «heartbeat file: имя, формат, период, поля, атомарная запись».

### CLI-совместимость

| D2O | R2O | Статус |
|---|---|---|
| `d2kd --flows N` | `--r2o-flow-capacity N`, алиас `--flows` | Алиас добавлен 2026-11-07; тест `d2o_cli_aliases_map_to_the_same_options` |
| `d2kd --udp-reverse-hook` | `--r2o-udp-reverse-visible`, алиас `--udp-reverse-hook` | Алиас добавлен 2026-11-07; тот же тест |
| `d2kd --sched-slots N` | нет | Пропущено; scheduler capacity фиксирована 128 |
| `d2kd --duration SEC` | нет | Пропущено (тестовый режим) |
| `d2kd --log FILE` | нет | Заменено перенаправлением shell |
| `d2kd --health-file PATH` | нет | Пропущено |
| `d2kc --health-file PATH` | нет | Пропущено |
| `d2kc --log FILE` | нет | Заменено shell |
| `d2kc --https-cache PATH` | путь выводится из каталога | Другое поведение |
| `d2kc --measure-mark M` | нет | Пропущено |
| `d2kvoice --list` | `--voice-list` | Подкоманда вместо флага |
| `d2kpanel --version` | `r2o-panel --version` | Другой формат строки |
| `d2k-detect --mark` (default) | `0x40000000` (z2k legacy) | `raw_probe::BYPASS_MARK = 0x2d` | Разный default SO_MARK у standalone detect |

`FLOWS` из D2O-конфига мигрирует в `R2O_FLOW_CAPACITY` только через `r2o-manager config-init`; прямой runtime-конфиг с `FLOWS` не читается.

### Фактические расхождения, обнаруженные при аудите

Это не только отсутствие тестов: часть контрактов реализована иначе.

| Область | D2O | R2O | Следствие |
|---|---|---|---|
| Контейнер плана | `plan_parse.c:354` требует `D2KP` | `r2k-core/src/plan.rs:11` требует `R2OP` | D2O-план (файл или кадр от D2O-контроллера) отвергается R2O |
| Текст плана | `plantlv.c:311` принимает `d2k-plan` | `r2o-controller/src/plan_text.rs:90` принимает `r2o-plan` | Автономный компилятор R2O не принимает D2O-текст |
| Версия control | `runtime/d2k_protocol.h`: `22` | `r2k-core/src/control.rs:7`: `48` | D2O- и R2O-компоненты несовместимы по control-сокету |
| Событие `0x000D` | `D2K_EV_CLIENT_TCP` (`d2k_ctl.h:154`) | `EVENT_R2O_VOICE_SUSPECT` (`control.rs:20`) | Разная семантика одного ID |
| Кольцо control | `D2K_CTL_OUT_RING = 65536` | `MAX_CONTROL_OUTPUT = 128 * 1024` | Разное поведение и счётчики при переполнении |
| Ёмкости планов | одна таблица `--flows` (2048) | `MAX_NAME_PLANS=128`, `MAX_ADDR_PLANS=128`, `MAX_ADDR_PROBES=64` и др. | 129-я цель принимается C и отвергается R2O |
| `tcp_ts_up` | `D2K_POISON_TS_UP` (`d2k_plan.h:89`), `wire.c:159` | нет константы/поля/логики | Poison-профиль не перенесён |
| HTTP execution trace | `datapath/http_trace.c:9` | нет | Нет текстовой трассы `d2kd: HTTP execution ...` |
| Периодическая сводка | `d2kd.c:893-1028`: HTTP80, NAT, routed flows, shape misses, plan capacity | `main.rs:612-763` — подмножество | Часть счётчиков не выводится |
| `d2kfetch --json` | `level` 5/6, `name_ok` по сертификату, `location:null` | `level` не выдаёт 5/6, `name_ok` из TLS, `location` строка | Машиночитаемый контракт расходится |
| `d2kask` | нечисловой `--ip`/плохой ClientHello доходят до «вопросов нет», exit 0; повтор флага — последний | строгий `IpAddr`, exit 1/2; повтор флага — ошибка | CLI/exit-коды расходятся |
| `d2kvoice` | `--wait 0` → 3000 мс; `--list` принимает любые флаги | `--wait 0` → 0; `--voice-list` только `--conntrack` | CLI/поведение расходятся |
| `d2kc` | `--self-check`, `--release-id`, `--measure-mark`, `--health-file`, `--log`, `--https-cache`; usage exit 2 | нет `--self-check`/`--release-id`/`--measure-mark`/`--health-file`/`--log`; ошибка аргументов exit 1 | Сервисный/диагностический контракт неполон |
| `httpsprobe` | `d2k_httpsprobe_lost` | нет прямого аналога | Lost-probe ветвь не подтверждена |
| Diagnostics | allocator/madvise, периодическая RSS-сводка | `diagnostics.rs` без madvise и части периодики | Диагностический контракт частичен |
| `udpruntime` | `d2k_udp_plan_build/send`, raw UDP send из контроллера | raw UDP sender в контроллере отсутствует; datapath использует свой путь | Часть CLI/планового UDP-контура не перенесена |
| Panel: ответ | абсолютный 5-с дедлайн на заголовки и тело (`response_ex`) | таймаут на каждый read/write | Медленный клиент может растянуть ответ; C оборвёт по общему дедлайну |
| Panel: обрыв клиента | C отвечает 400 и продолжает serve | фатальная IO-ошибка может завершить serve | Панель теряет устойчивость |
| Panel: конфиг | незакрытая кавычка в unquoted значении отвергается | `strip_shell_value` принимает | `PANEL_LISTEN=...'` проходит в R2O |
| Panel: known-list | включает `TG_RELAY_URL`, `TG_RELAY_SECRET`, `TG_ENROLL_PORT`, `D2K_PPE_DEOFFLOAD` | эти ключи добавлены в known/ignored 2026-11-07; `AUTOUPDATE`/`D2K_GATE`/`DNS_PORTS`/`HTTP_KEEPALIVE_PORTS`/`D2K_RUNTIME_DIR` также добавлены | Свежий `/api/status` больше не показывает непустой `unknown_keys`; тест `config_parser_accepts_all_shipped_and_donor_known_keys` |
| Panel: action 124 | код 124 службы → `timeout` | `failed` | Расхождение состояния action |
| Router: `clear-found` | удаляет `catalog.json`, `http-plans.txt`, `https-cache.txt`, `measurements/` | `--clear-catalog` удаляет только каталог | Остаются `https-cache.json` и измерения |
| Router: `KEENETIC_POLICY` | `ndmc show ip policy` → `--only-mark` | не перенесён | Нет автоматического выбора политики Keenetic |
| Router: логи | ротация 9 имён, включая `instagram-dns.log` | 7 имён, без Meta DNS логов | Неограниченный рост логов |
| Router: heal | при неготовом listener только лечит firewall | `telegram_reapply` может запустить остановленный Telegram | Побочный запуск службы |
| Router: `engine-restart` | проверяет `MODE=off` до stop | сначала `engine_stop` | При off выполняет лишний stop |
| Router: DNS actions | `dns-ensure/tick/refresh/remove` | нет; только внутренний `dns-ensure` и Meta DNS | Внешний интерфейс не совпадает |
| Router: uninstall | снимает TG/DNS/PPE/fastnat/offload/RST без init | требует активный adapter | Нет аварийной очистки при отсутствующем адаптере |
| Flow-offload | глобальное выключение offload | глобальное выключение; selective-схема удалена | Примечания #20/#24/#26/#81-#96 о selective устарели; `test-router-flowoffload-selective-differential.sh` отсутствует |
| Config default | при отсутствии конфига `MODE=apply` | `MODE=observe` fallback | Новая установка ведёт себя иначе |
| Telegram: limits | `memory_budget` + жёсткий `max_connections=64` | только nofile/hedge | На 128 МиБ возможно ~495 соединений |
| Telegram: stats socket | таймаут чтения запроса | без таймаута | Молчащий клиент блокирует accept-loop и провоцирует watchdog |
| Telegram: config | `TG_PORT=1443`, валидация CF-доменов, `TG_DIAGNOSTIC_DIRECT_TCP` | порт любой, невалидные CF-домены молча отбрасываются, direct TCP отсутствует | Конфигурационный контракт расходится |
| Telegram: crypto | C-векторы `mtproto_auth/encrypted/splitter` | Rust-тесты без C-дифференциалов | Протокольные ветви не сопоставлены |
| Telegram: identity | enrollment/relay proof | identity создаётся, но не используется | Мёртвая ветвь |
| `net4` | `d2k_ip4_parse` допускает ведущие нули (`001`) | `std::net::Ipv4Addr` отвергает | Edge-case CLI-адресов |
| `d2kvoice` IPv6 | `d2k_ip6_private` | общий helper отсутствует; логика продублирована в `quic_replay`/`voice_targets` | Дублирование и риск расхождения |

## Ключевые выводы аудита

### 1. Арифметика матрицы и исторические записи расходятся

Текущая таблица матрицы содержит 57 строк, 89 баллов веса и 80 начисленных баллов (26 «доказанно эквивалентно» + 24 «эквивалентно» = 50 строк, 6 частичных, 1 реализованная). Это совпадает с шапкой и `docs/progress/progress.json`.

При этом журнал после таблицы содержит взаимно исключающие итоги: `53/84`, `54/85`, `55/87`, `58/87`, `62/87`, `63/87`, `72/87`, `73/87`, `75/87`, `75/89`, `76/89`, `78/89`, `79/89`, `80/89`. Часть записей — исторические срезы, но они не помечены как таковые и создают ложное впечатление пересчёта. Их нужно явно отделить от действующей таблицы.

### 2. Матрица объединяет независимые контракты

Наиболее перегруженные строки:

- `IPv6/фрагментация в живом NFQUEUE, маркировка маршрута, fail-open и conntrack` (3) — пять независимых рисков, из них C-oracle для IPv6 NFQUEUE отсутствует.
- `Классификатор: baseline, poison/strategy tree, control и neutral ACK` (1) — под одним баллом скрыты дерево стратегий, properties/compose и полный CLI.
- `Telegram config/DC map, handshake, MTProto/WebSocket retries and full service lifecycle` (1) — конфиг, DC-map, MTProto, WSS, сервисный lifecycle.
- `Панель: control/actions, прочие status branches, настройки и assets` (1) — десятки endpoint-ветвей.
- `Firewall: статические packet rules и backend` (1) — nft/iptables, PORTS, DNS_PORTS, CONNBYTES, marks, voice, broadcast, ICMP, rollback.
- `Update activation ordering, rollback recovery and signed Linux/OpenWrt install` (1) и `ABI/QEMU и сборка OpenWrt targets` (2) — разные уровни: код, упаковка, подпись, runtime.
- `HTTP search` (3) — кандидаты, retries, all-failed, APPLIED, persistence и live behavior.

### 3. Отсутствующие контракты (не отражены или отражены косвенно)

- **CLI D2O:** `d2kd --flows/--sched-slots/--duration/--log/--health-file/--udp-reverse-hook`, `d2kc --health-file/--log/--https-cache/--measure-mark`, `d2kpanel --version` формат. R2O использует другие имена (`--r2o-flow-capacity`, `--r2o-udp-reverse-visible`) и не принимает часть флагов.
- **Heartbeat-файлы:** D2O пишет `D2KH1 ...` для datapath, controller, panel и Telegram. R2O panel пишет `R2OH1`; datapath/controller CLI не имеют `--health-file`. Это наблюдаемый side effect и контракт для watchdog/health.
- **Конфиг:** D2O service использует `FLOWS=...`; R2O читает только `R2O_FLOW_CAPACITY`. Пользовательский `FLOWS` из существующего конфига игнорируется.
- **Plan TLV/text:** `plantlv.c` (20 функций) не имеет отдельного контракта, хотя является протоколом обмена с datapath.
- **HTTP response reader:** ветви framing покрыты differential-векторами, но отдельного контракта в матрице нет.
- **Volume TX/RX/ladder:** `volume.c` (19 функций) не имеет отдельного контракта.
- **Crypto primitives:** `crypto.c`/`p256.c`/`x25519.c` заменены библиотеками (`ring`, `rustls`, `hpke`, `x509-parser`); контракта на такую замену и её границы нет.
- **Datapath plan parse/apply/plans:** `plan_parse.c`/`plan_apply.c`/`plans.c` (107 функций) покрыты косвенно через control/ACK/TCP, но не как отдельный протокол плана.
- **Datapath journal, capture/TLS/wire, HTTP80/http_trace, icmpguard:** отдельные контракты отсутствуют.
- **Router:** install/bootstrap/uninstall lifecycle, log maintenance, NDM hook, fastnat lifecycle, process supervisor, Telegram stop order, Meta DNS scheduler уже имеют тесты, но часть не входит в таблицу как отдельные пункты.
- **Telegram donor parity:** R2O Telegram взят из z2kOW `tg-proxy`, а не из C11 D2O. Нужны отдельные контракты «наличие/поведение файлов донора» и «сервисный lifecycle», а C-only функции D2O — `not-applicable`.
- **VPS:** `relay-enroll` (45 production-функций) и `relay-gate` (19) — отдельные сервисы с systemd units. R2O README явно исключает обязательный VPS/relay; перенос не требуется. Router-side Meta DNS/install пути остаются в своих контрактах.

### 4. Дубли и пересечения

- `Production daemon crash/restart` и `Automatic refusal → Discovery/classification → APPLIED` и `Production controller recovery` описывают пересекающийся процессный lifecycle.
- Три строки flow-offload (успешный lifecycle, write-failure, восстановление) пересекаются; после решения владельца о возврате к D2O lifecycle часть записей #20/#24/#26/#81-#96 устарела.
- `TCP measurement and core TLS/HTTP verifier` пересекается с `Connect/read timeout`, `CLEAR`, `SO_MARK`, `TLS 1.2 response`.
- `Scheduler` и `Discovery` разделяют очередь/cooldown/permits; граница должна быть явной.
- `Discord voice trial`, `endpoint change`, `trial clock` и `production recovery` частично дублируют lifecycle.
- Telegram-строки 58/59 относятся к donor-parity, а строка 60 — к C/D2O-сравнению; это разные источники истины.

### 5. Завышенные или требующие перепроверки зачёты

- **`core/meas.c` и `core/verdict.c` не вызываются текущим `d2kc`.** Production-путь классификации идёт через `detect/classify.c` и хуки `d2k_sched_tcp_*`. Матричные строки, сопоставляющие `d2k_meas_once`/`d2k_classify_cancelable` с Rust, описывают библиотечный API, а не текущий production-путь. Их нужно переформулировать на `detect/classify.c` или пометить как API-only.
- Строка `Панель: control/actions...` начисляет 1 балл за очень широкий набор endpoint-ветвей. Differential покрывает 22 сценария, но не все error/status/assets/settings ветви; физический роутер и браузер не использовались.
- Строка `Firewall: статические packet rules и backend` остаётся 0/1, хотя подпункты MEASURE_MARK/D2K_GATE/voice order уже проверены; это не завышение, а недоразбиение.
- `QUIC/HTTP3` строки 50/51 разделяют framing (1/1) и budgets/stall (0/1), но app-byte/request-count ветви и total deadline разбросаны по журналу и не имеют отдельного контракта.
- `Discord RTC` строка 54 начисляет 3 балла за helper/source-backed lifecycle; production controller с автоматическим restart и длинной RTC-сессией не проверены. Это следует разделить.
- `Telegram` строки 58/59 начисляют баллы по историческим differential-прогонам; донор z2kOW в этом окружении отсутствует, повторная сверка невозможна.
- `IPv6` строка 24 остаётся 0/3, но внутри неё есть уже доказанные IPv4-ветви; это скрывает частичный прогресс, а не завышает его.

## Приоритетные действия

1. **Зафиксировать одну принятую ревизию C-эталона и перепинить все differential-скрипты.** Сейчас 49 из 80 legacy-баллов опираются на `304ba893`; checked-in пины panel/router частично остаются на `304ba893`, хотя матрица заявляет `a378e23`/`8e2c981`. Локальный git D2O не содержит `a63d964` и `304ba893`, поэтому эти доказательства здесь не воспроизводятся. Без перепина строгий процент останется 39,11 %.
2. **Совместимость плана и control-протокола.** Входящий `D2KP` принимается (`Plan::parse_wire`), v22/v48 greeting и release gate выбираются профилем, outbound `R2OP`→`D2KP` и raw-binding ACK реализованы и проверены (`S12`). Live v22 datapath проверен реальным `d2kc`, live v22 controller — реальным C `ctlprobe` (`S13`/`S14`). C-события `0x0002`/`0x0005` теперь заводят Discovery и подавляют ложное подозрение после чистого рукопожатия (`S15`). Остаются: C QUIC SUSPECT (transport 17), коды 5/6/8 используют полную классификацию вместо late-RX, `--fetch` snapshot-канал C-датапата не поддерживается.
3. **`tcp_ts_up` реализован.** `D2K_POISON_TS_UP` (bit 4) переставляет TS option в начало в `wire.rs`; C `test_wire` и Rust-векторы совпадают, text-директива `tsup` и legacy `d2k-plan` header добавлены. Остаётся автоматический producer `measured.c` → `tsup` только там, где C это делает.
4. **Выровнять таблицы планов:** ёмкость `--flows`/2048, LRU-вытеснение вместо отказа при 128/64, счётчики `probe_count`/`shape_misses`/`plan_count`.
5. **Добавить `MEASURE_MARK` контроллера, `--health-file`/heartbeat и оставшиеся CLI-флаги** (`--sched-slots`, `--duration`, `--log`); алиасы `--flows`/`--udp-reverse-hook` уже добавлены и покрыты тестом.
6. **Закрыть panel-пробелы:** абсолютный дедлайн ответа, устойчивость к обрыву клиента, незакрытая кавычка, код 124, missing static fallback, точная граница 32 КиБ. Known-list D2O-ключей уже исправлен и покрыт тестом `config_parser_accepts_all_shipped_and_donor_known_keys`.
7. **Закрыть router-пробелы:** `clear-found` для `https-cache.json`/`measurements` и ротация Meta DNS логов уже исправлены и покрыты `test-router-clear-found-state.sh`/`test-router-log-maintenance.sh`. Остаются `KEENETIC_POLICY`, побочный запуск Telegram в `heal`, `engine-restart` при `MODE=off`, отсутствующие `dns-*` действия, uninstall fallback.
8. **Закрыть Telegram-пробелы:** memory budget/лимит 64 соединений, таймаут stats-сокета, валидация CF-доменов, `TG_PORT=1443`, `TG_DIAGNOSTIC_DIRECT_TCP`, C-векторы crypto/splitter, потребитель identity.
9. **Свести Panel A1–A26, Router B1–B54 и Telegram C1–C26 в матрицу** с бинарными статусами. Нормализация 2026-11-08 это выполнила: scored-матрица содержит 179 контрактов / 271 балл, 106/271 = 39,11 % строго. Дальше нужно перепинить `304`-строки и закрывать реальные пробелы, а не расширять coarse-слой.
10. **Добавить 22 `test-panel-*.sh` в CI** и не полагаться на разовые прогоны с подменой SHA.

## Ограничения

- Полный C/Rust workspace, NFQUEUE/netns, QEMU/ABI и физический роутер в этом прогоне не запускались.
- Исторические записи `REA_EVIDENCE.md` не считаются текущим доказательством.
- Для Telegram источник — z2kOW; локальной копии донора нет, поэтому проверка ограничена наличием Rust-модулей и уже записанными differential-результатами.
- VPS-сервисы исключены по продуктовому решению R2O, а не по технической невозможности.

## Артефакты

- `docs/audit/function-index.md` — полный function-level индекс 2584 C-функций (2523 `.c` + 61 header-inline).
- `docs/audit/unmentioned-functions.md` — 660 функций, не названные в тексте отчётов; module-level статус.
- `docs/audit/validation-2026-11-08.md` — независимая валидация полноты, ссылок, ревизий и контрактов.
- `docs/audit/datapath-detect-audit.md` — datapath и detect.
- `docs/audit/core-controller-audit.md` — core, CLI и controller.
- `docs/audit/panel-router-vps-telegram-audit.md` — panel, router, Telegram, VPS.
- `docs/audit/matrix-consistency-audit.md` — арифметика, дубли, декомпозиция.
