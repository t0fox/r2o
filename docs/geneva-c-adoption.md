# Что взять из geneva_c для r2o

Дата анализа: 2026-11-19.

Источник: [`avatarDD/geneva_c`](https://github.com/avatarDD/geneva_c), ветка `main`,
коммит `bdb767d97e3af0f74de7db4d391bd38808e416cf`.

Это анализ исходников, а не runtime-проверка geneva_c. Числа и поведение ниже
приведены по файлам репозитория; для каждого предлагаемого переноса указано,
чем его проверять в r2o.

## 1. Короткий вывод

geneva_c — не «второй D2O» и не замена r2o. Это самостоятельный C-порт
Geneva (Genetic Evasion) с расширениями до паритета с zapret2 1.0.7. У него
другие задачи и другая архитектура:

- один процесс-исполнитель стратегий с NFQUEUE/WinDivert/divert;
- текстовый язык стратегий Geneva (триггеры, деревья действий, входящий и
  исходящий леса);
- генетический подбор стратегий (`evolve`), оценщик (`eval`) и база
  стратегий;
- 22 лабораторные модели цензоров;
- библиотека из 58 готовых стратегий с долями успеха;
- 26 x-действий, включая комбинаторы в стиле zapret2;
- автоустановка firewall, offline `apply` по pcap, server-side `agent`.

r2o уже имеет собственный production-datapath, controller, Discovery,
каталог, QUIC/TLS/HTTP/Telegram-подсистемы и D2O-дифференциальные тесты.
Копировать архитектуру geneva_c не нужно и вредно: это добавит второй
исполнитель стратегий и вторую модель firewall.

**Брать стоит четыре вещи:**

1. **Лабораторные цензоры как независимый тестовый oracle** (P0). Это самый
   ценный и самый безопасный актив geneva_c: 22 модели DPI, которые можно
   прогонять против r2o в netns без реального провайдера.
2. **Библиотеку Geneva и парсер/каноникализатор стратегий** (P1). 58
   проверенных стратегий и 145 записей тестового корпуса — источник
   кандидатов, фикстур и формата импорта. Не как runtime-движок, а как
   frontend, который компилируется в R2OP.
3. **Отдельные примитивы десинхронизации из x-действий** (P2): поля
   `dataofs`/`flags`/`ack`, `place=after`, `tlsmod=rndsni/padencap/sni=`,
   позиционные маркеры, HTTP-правки, SYN/ACK/window/RST, TLS clone. Только
   те, под которые есть проверяемый сценарий; не все 26 подряд.
4. **Идеи evaluator/GA для опционального глубокого поиска** (P3). Не
   переносить Geneva-движок; использовать структуру GA (элита, турнир,
   hall of fame, checkpoint, DB) поверх параметров R2OP и существующего
   control-сокета r2o.

**Не брать:** WinDivert/BSD/Android/WLAN-бэкенды, server-side `agent`,
полный profile/hostlist/ipset/L7-стек, автоустановку firewall, контрольный
протокол и события, парсеры MTProto/DNS/QUIC, полный Geneva-исполнитель в
datapath и Lua-совместимость. Причины — в разделе 9.

## 1a. Статус переноса (2026-11-20)

P1 выполнен без нового крейта, внутри существующего `r2o-controller`:

- `crates/r2o-controller/src/geneva_library.rs` — все 58 записей
  `library_data.h` и фильтр `library_match`;
- `crates/r2o-controller/src/geneva.rs` — разбор `strategy.c`
  (триггеры, деревья, леса, tamper/fragment/sleep/trace, `dataofs`,
  `flags`, `ack`, `payload`-значения, `py_int`/`%g`);
- `crates/r2o-controller/src/geneva_corpus.rs` — эталон, снятый с
  geneva_c на ПК, только для тестов.

Проверка: 8 тестов, включая 145/145 записей корпуса (130 валидных,
15 негативных), 58/58 записей библиотеки и крайние случаи
`test_strategy.c`. Канонические строки совпадают с `strategy_print`.
Ограничения: x-действия `--ext` не переносились; порядок `fragment` без
параметров в geneva_c случайный, в каноникализаторе зафиксирован
`False`; P0 (цензоры) ещё не начат.

P2.1 (первый примитив) выполнен: `tamper{TCP:dataofs:replace:N}`
перенесён как `REC_POISON_FIELDS` (`minexec=13`), директива
`poison <id> ... dataofs=N` в текстовом плане и подмена TCP data offset
в `r2k-core::wire`. Тесты: `dataofs_compiles_and_is_read_back`,
`dataofs_rejects_out_of_range_and_old_minexec`,
`dataofs_overrides_only_the_tcp_nibble`. Значение `dataofs=0` явно
отвергается: в текущем `Emission` ноль означает «не менять», поэтому
молчаливая замена нулём была бы фиктивной; при необходимости поле
нужно переводить на `Option<u8>` отдельным изменением.

P2.2 выполнен: `flags`, `ack`, `ip_len`, `tcp_window` перенесены как
`REC_POISON_TCP` (`0x0013`, `minexec=14`) с маской присутствующих полей.
Текстовый план принимает `poison <id> ... tcp_flags=FRAPUN ack=N
ack=corrupt ip_len=N window=N`; `ack=corrupt` — детерминированный XOR
`0x9e3779b9`, а не источник случайности, чтобы дифференциал был
воспроизводим. Триггер проверяется только по форме `[TCP:flags:...]`,
его конкретное значение не переносится: R2OP применяет план к
потоку/приветствию, а не к каждому пакету.
`ttl=0` в компиляторе отвергается по той же причине, что
и `dataofs=0`: ноль в `Emission` означает отсутствие подмены. `r2k-core::wire` подменяет девятибитные TCP-флаги
(включая NS), ack, окно и IPv4 total length; для IPv6 `ip_len` явно
отклоняется, а не игнорируется молча. Тесты:
`flags_ack_ip_len_and_window_compile_and_are_read_back`,
`ack_corrupt_is_read_as_corrupt`,
`tcp_fields_require_minexec_14_and_valid_values`,
`tcp_fields_override_header_and_keep_checksums_valid`,
`ack_corrupt_is_deterministic_and_not_the_original`,
`ip_len_overrides_total_length_and_ip_checksum`,
`ip_len_is_rejected_for_ipv6`.

P2.3 выполнен: `place=after` (`2`, `minexec=14`) для TCP/UDP-фальшивок.
Для `place=after` план сам владеет оригиналом (`OriginalFate::Drop`) и
отдаёт посылки в порядке «оригинал, затем фальшивка», поэтому
Geneva-форма `duplicate(,tamper{...})` выражается без перестановки.
Текстовый план принимает `place=after`; `r2o-datapath` проверяет порядок
в `place_after_plan_transmits_original_before_fake`, ядро —
в `place_after_emits_original_then_fake_and_owns_the_queue_copy`.

Для планирования оставшихся единиц использован `rust-anything analyze`
по `avatarDD/geneva_c` (`bdb767d`): 44 единицы, `start_here` —
`ext_opt.c`, `rng.c`, `log.c`, `util.c`, `fw.c`. Инструмент подтвердил,
что `strategy.c`/`engine.c`/`ext/` нельзя переносить целиком без
платформенного слоя; это совпадает с выбранной стратегией «только
проверяемые примитивы и компилятор», а не второй исполнитель Geneva.

Компилятор поддерживаемого подмножества добавлен в
`crates/r2o-controller/src/geneva_compile.rs`. Он принимает ровно одно
исходящее дерево `[TCP:flags:...]-duplicate(,tamper{...})`, переводит
`TCP:flags/dataofs/window/ack:corrupt/chksum:corrupt/options-md5header`,
`IP:ttl/len` и `TCP:seq:add` в `REC_POISON_TCP`/`REC_POISON_FIELDS` и
собирает `fake ... place=after`. Остальные формы отвергаются с текстовой
причиной; входящий лес, `drop`, `fragment`, `sleep`, `trace`, правка
оригинала и `chksum:replace` не эмулируются. Из 58 записей библиотеки
сейчас компилируются 9, остальные 49 явно отвергаются; это исходная
точка для расширения, а не заявка на полный паритет. Тесты:
`duplicate_right_tamper_becomes_after_fake`,
`duplicate_with_ttl_and_ack_corrupt_combines_in_one_poison`,
`duplicate_with_dataofs_and_window_is_supported`,
`md5_option_tamper_selects_detect_tcp_wire_profile`,
`library_has_compilable_subset_and_every_entry_is_classified`.
Байтовый дифференциал с geneva_c: `tests/geneva_compile_differential.rs`
берёт реальный ClientHello из `tests/golden/in.pcap`, применяет ту же
стратегию `duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))`
через geneva_c и через R2OP, нормализует IP ID/контрольные суммы и
сравнивает оба пакета; эталон и команда генерации лежат в
`tests/fixtures/geneva/README.md`.

Для холодного каталога в Discovery добавлен generic-кандидат
`pad64 + seqovl` (`r2o_fallback::r2o_pad64_seed`) перед C-очередью
`d2o`: он уже подтверждался на реальном роутере для WhatsApp/Discord,
поэтому не должен ждать полного перебора. Кандидат проверяется
обычным end-to-end подтверждением и не попадает в каталог без
успешного HTTPS/APPLIED.

## 2. Инвентарь geneva_c

По исходникам:

| Компонент | Объём/факты | Что даёт |
|---|---|---|
| C-ядро | 91 `.c`, 70 `.h`, ~55 000 строк | стратегии, пакеты, executor, firewall, ctl |
| `src/ext` | 92 файла, ~32 000 строк | zapret2-совместимые x-действия, профили, списки, L7, tuner, авто-детекторы |
| Тесты | 34 `tests/test_*.c`, ~19 700 строк | эталонные сценарии для цензоров, стратегий, eval, ctl, firewall |
| Язык стратегий | `src/strategy.c` ~41 КБ | разбор, печать, JSON, pretty, исполнение деревьев |
| Генетика | `src/evolve.c`, `src/mutate.c` | популяция, мутации, кроссовер, турнир, элита, checkpoint |
| Оценщик | `src/evaluator.c`, `src/probe.c` | HTTP/TLS/DNS/TCP/exec/external, фитнес, baseline, canary |
| База стратегий | `src/sdb.c`, `docs/EVOLVE.md` | JSONL, агрегаты по стратегии и цели, top/export/import |
| Цензоры | `src/censor.c`, `src/ext/censor_x.c` | 13 базовых моделей (1–11, 8b, DNS) + 9 расширенных (12–20) |
| Библиотека | `src/library_data.h` | 58 стратегий: 38 China, 10 lab, 6 India, 4 Kazakhstan |
| x-действия | `src/ext/xact*.c` | 26 x-действий, включая 4 комбинатора |
| Offline | `src/pcap.c`, `cmd_strategy.c` | `check`, `apply` по pcap/pcapng, canonical/JSON/pretty |
| Документация | `docs/*.md` ~350 КБ | STRATEGY, ENGINE, EVAL, EVOLVE, CENSOR, EXT, PARITY, PROTOCOL |

Лицензия — BSD 3-Clause, как у Geneva; библиотека стратегий сгенерирована из
`library.py` Geneva (Copyright (c) 2020, University of Maryland College Park).
При переносе данных/кода нужно добавить раздел в `THIRD_PARTY_NOTICES.md` и
сохранить уведомление.

## 3. Сопоставление с r2o

| Область | geneva_c | r2o сегодня | Вывод |
|---|---|---|---|
| Перехват пакетов | NFQUEUE, WinDivert, BSD divert | Linux NFQUEUE, IPv4/IPv6, production-цикл | Архитектуру не брать; r2o сильнее для роутера |
| Формат стратегии | Geneva DSL: триггеры/деревья/леса | R2OP: компактный бинарный план + текстовый компилятор | Держать R2OP; Geneva DSL — только импорт/фикстуры |
| Действия | tamper/duplicate/fragment/drop/sleep/trace | split/fake/poison/seqovl/order/oob/ipfrag/udplen/autottl/qsplit/qdeny | Часть примитивов отсутствует, см. P2 |
| Многосегментный ClientHello | удержание, сборка, replay | capture/hold, сборка, replay | Уже есть |
| Conntrack/потоки | роли, MSS, TTL, retrans, FLOW-триггеры | conntrack, flow table, capture, счётчики | Уже есть |
| L7/протоколы | 16 L7, 31 payload, маркеры | TLS/HTTP/QUIC/STUN/DNS/ECH | Для планов r2o достаточно; не дублировать |
| Discovery/поиск | GA по DSL | D2O-лестница кандидатов, измерение, каталог | Дополнять, не заменять |
| Оценщик | HTTP/TLS/DNS/TCP/exec/external, фитнес | fetch/ask/classify/response/QUIC, свои probes | Взять residual wait и, при необходимости, external hook |
| Каталог/база | JSONL-база стратегий | каталог планов и привязок | Не дублировать; DB полезна только для GA |
| Цензоры | 22 модели | нет | **Взять (P0)** |
| Библиотека стратегий | 58 записей | нет отдельного корпуса | **Взять как импорт/фикстуры (P1)** |
| Firewall | авто nft/iptables/ipfw/pf | router-скрипты, nft/iptables, PPE, watchdog | Не дублировать |
| Control/events | JSON Lines, ctl | свой протокол, panel, manager | Не заменять |
| Платформы | Windows/BSD/Android/WLAN | OpenWrt/Keenetic Linux | Не брать |
| Server-side | `agent` | явно вне scope | Не брать |
| Offline pcap | `check`/`apply` | нет CLI | Взять позже как dev-инструмент |
| Hardening | seccomp, privdrop, daemon, sd_notify | нет seccomp/privdrop | Отдельная задача, не срочно |

## 4. P0: лабораторные цензоры как тестовый oracle

### 4.1. Почему это главное

r2o уже имеет 499 скриптов и десятки C/Rust differential-тестов, но почти все
они проверяют **контракт с D2O**, а не поведение против независимой модели
DPI. Цензоры geneva_c закрывают именно этот пробел: они не знают про R2OP и
не подыгрывают r2o. Одна и та же модель может использоваться для проверки
datapath, Discovery и выбранных стратегий.

Цензоры 12–20 — это не «Geneva-специфика», а удобная матрица сценариев,
совпадающая с возможностями r2o:

| Цензор | Модель | Что проверяет в r2o |
|---|---|---|
| 1–5, 8b, 9–11 | классические DPI: слово, seq, RST, checksum, dataofs | split/fake/poison/OOB/seq/checksum |
| 6–8 | наблюдение за потоком, RST/FIN, привязка к seq | состояние сессий, guard, RST |
| DNS | инъекция поддельного A/AAAA | DNS health/bootstrap/Discovery |
| 12 | freeze: сервер замолкает после N байт | TCP stall/silence, таймауты, смена плана |
| 13 | policer: token bucket на данные сервера | slowdown/volume-детекторы |
| 14 | SNI в первом сегменте, RST с TTL | alien-RST guard, TTL/autottl |
| 15 | сборка ClientHello из 2 сегментов | capture/hold/reassembly |
| 16 | SNI в QUIC Initial (расшифровка) | QUIC split/deny/HTTP3 |
| 17 | блокировка адресов | Discovery, пул адресов, привязки |
| 18 | HTTP Host → 302 на блок-страницу | portal/redirect, HTTP replacement |
| 19 | TTL/checksum/PAWS-фильтр | poison badsum/ttl/tcpts, guard |
| 20 | только целые пакеты и первые IP-фрагменты | ipfrag, IPv6 fragments |

### 4.2. Что портировать

Минимальный первый срез:

- модели 1–11, 8b и DNS — чистые state machine над IPv4/IPv6 TCP/UDP;
- инъекция RST и DNS-ответа — сборка пакета и checksum;
- API вида `Censor::packet(&mut self, raw: &[u8], now) -> CensorResult`,
  где результат содержит `accept/drop` и список инъецированных пакетов;
- без NFQUEUE на первом этапе: unit-тесты на синтетических пакетах,
  портированные из `tests/test_censor.c`;
- второй этап — binary `r2o-censor` с NFQUEUE FORWARD и netns-стендом,
  по аналогии с `tests/e2e/censors.sh`.

Для второго среза (12–20) переиспользовать:

- `r2k_core::packet::PacketView` — адреса, TCP/UDP, payload;
- `r2k_core::tls`/`quic` — SNI ClientHello и QUIC Initial;
- `r2k_core::wire` — сборка пакетов и checksum;
- `r2o_datapath::nfqueue::QueueSocket` — очередь и verdict;
- `r2o_datapath::raw` — отправка инъецированных пакетов.

### 4.3. Критерии приёмки

1. Портированные unit-тесты `test_censor.c` проходят для всех 13 базовых
   моделей: коды `PASS/FIRED/BLOCKED/CONTROL`, точные RST (src/dst/seq/ack/
   flags/window/ttl/checksum), DNS-инъекция.
2. В netns каждый цензор блокирует baseline-запрос, а соответствующий
   r2o-план проходит; для 12–20 — те же сценарии, что в `tests/e2e/censors.sh`.
3. Тест не требует root на CI-раннере, кроме отдельного netns-job; unit-часть
   работает без привилегий.
4. Никаких изменений в production-бинарниках r2o; новый крейт/бинарь —
   test-only.

### 4.4. Оценка

Трудоёмкость: средняя (1–2 недели на 22 модели + стенд). Риск: низкий, потому
что код не попадает в production. Главная сложность — не модели, а
аккуратный NFQUEUE-стенд и воспроизводимость таймингов.

## 5. P1: библиотека Geneva, парсер и импорт стратегий

### 5.1. Что даёт библиотека

`src/library_data.h` — 58 стратегий с полями:

- `rate` — доля успеха (0–100);
- `country` — china/india/kazakhstan/lab;
- `test_type` — http/dns/dns_tcp/echo и др.;
- `description`;
- `server_side`;
- `censors` — метки цензоров.

Это готовый корпус для:

- фикстур парсера/каноникализатора;
- seed-кандидатов для Discovery (после компиляции в R2OP);
- регрессий «стратегия X должна компилироваться/отвергаться»;
- сравнения с Geneva по канонической форме.

### 5.2. Что портировать

Отдельный крейт `r2o-geneva` (не в production-зависимостях на первом этапе):

- AST: `Strategy`, `Forest`, `Tree`, `Trigger`, `Action`, `Tamper`, `Fragment`;
- разбор и печать: `parse`, `canonical`, `pretty`, `json`;
- семантика: gas, wildcard, регистр, целые/строки, несколько `\/`,
  входящий/исходящий лес;
- библиотека: 58 записей + фильтры `--country/--test/--censor/--min-rate`;
- CLI `r2o-geneva check|library`;
- тесты на `tests/geneva_strategies.h`: 145 записей (130 валидных и 15
  негативных) в файле на 148 строк.

Затем — **консервативный компилятор в R2OP**:

- поддерживать только те деревья, которые точно выражаются текущими
  действиями R2OP;
- всё остальное явно отвергать с кодом `unsupported`, не «примерно»
  эмулировать;
- для каждой скомпилированной стратегии проверять байты на эталонном
  пакете (дифференциал с geneva_c `apply` или с golden-пакетами).

Что уже выражается в R2OP:

- `fragment{tcp:N:True|False}` → `split payload_start +N` + `order`;
- `drop` → `qdeny` только для QUIC; для TCP нужен новый action или отказ;
- `tamper{IP:ttl:replace:N}` → poison `ttl=N`;
- `tamper{TCP:chksum:corrupt}` → poison `badsum`;
- `tamper{TCP:seq:replace/…}` → `seqshift`;
- `duplicate(tamper{...})` → `fake` с payload, равным исходному
  ClientHello/HTTP-запросу, и poison;
- `fragment{tcp:-1:False}` → `split hello_middle +0` + `order reverse`.

Что **не** выражается без расширения R2OP:

- `tamper{TCP:dataofs:replace:N}`;
- `tamper{TCP:flags:replace:...}`;
- `tamper{TCP:ack:corrupt}`;
- `tamper{IP:len:replace:N}`;
- `duplicate(..., tamper(...))` с фальшивкой **после** оригинала;
- входящие действия, кроме текущей TLS-правки.

Именно поэтому P1 идёт вместе с P2: сначала добавить в R2OP поля
`dataofs`, `flags`, `ack`, `ip_len`, `tcp_window`, `place=after`, а затем
компилировать библиотеку. Без этого из 58 стратегий напрямую переносится
меньшинство.

### 5.3. Критерии приёмки

1. Все 145 записей корпуса `geneva_strategies.h` дают тот же `ok/error`, а
   валидные — ту же каноническую строку, что geneva_c.
2. `library` выдаёт те же 58 записей и фильтры, что `src/library.c`.
3. Для поддерживаемого подмножества библиотеки компилятор даёт R2OP-план,
   который на эталонном пакете даёт те же байты, что geneva_c `apply` после
   нормализации случайных полей (IP ID, checksum, RNG).
4. Неподдерживаемые стратегии перечислены явно; молчаливой аппроксимации
   нет.

### 5.4. Оценка

Парсер/библиотека — 3–5 дней. Компилятор поддерживаемого подмножества —
1–2 недели после P2. Риск: средний, потому что легко получить «похожую, но
не ту» стратегию. Поэтому критерий — байтовый дифференциал, а не только
успешный разбор.

## 6. P2: примитивы десинхронизации, которых нет в R2OP

Ниже — не «портировать всё», а очередность по ценности и проверяемости.

### 6.1. Tamper-поля для fake/poison (высокий приоритет)

Добавить в `Poison`/`Emission` и в `wire`:

- `dataofs` (0–15) — заменить data offset, не меняя байты; DPI видит
  «опции» как данные;
- `flags` — заменить TCP-флаги (R/RA/FRAPUN и т.п.);
- `ack` — сдвиг/порча ack;
- `ip_len` — заменить IPv4 total length;
- `tcp_window` — заменить окно;
- `tcp_urgptr` — при необходимости.

Это разблокирует самые результативные стратегии библиотеки Geneva:
`duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)` и
родственные. Реализация локальна: новые записи R2OP (`minexec=14`),
`Poison`/`Emission`, `wire::build_tcp_packet`, текстовый парсер, тесты
`r2k-core/tests/apply.rs` + дифференциал с geneva_c.

### 6.2. `place=after` и порядок фальшивок

Сейчас `Fake.placement` — только `before`/`between`. Geneva умеет
`duplicate(..., tamper(...))`, то есть tampered-копия после оригинала.
Добавить `place=after`:

- для UDP `own_after_fakes` уже даёт похожее поведение;
- для TCP нужно либо разрешить `own_after_fakes` в плане, либо ввести
  отдельный режим «оригинал как emission»;
- тест: порядок и seq на проводe совпадают с geneva_c.

### 6.3. TLS fake-модификации

`Fake.tls_mod` сейчас имеет только `rnd` и `dupsid`. Добавить:

- `rndsni` — случайный SNI той же длины;
- `padencap` — padding в конце ClientHello;
- `sni=NAME` — подмена SNI в фальшивке.

Это локализовано в `plan/apply.rs::fake_tls_bytes` и `wire.rs`; полезно для
реалистичных фейков и совместимости с библиотекой.

### 6.4. Позиционные маркеры (дешёво, без datapath)

`split` в R2OP уже принимает абсолютный `payload_start +N`. Значит,
`midsld`, `endsld`, `host`, `method`, `sniext` можно вычислять в controller
и передавать числовой offset. Это не требует нового кода datapath:

- добавить helper в controller: по захваченному HTTP/TLS payload вычислить
  позиции;
- генерировать кандидаты с этими позициями;
- тесты: для эталонных ClientHello/HTTP-запросов offset совпадает с
  geneva_c `markers.c`.

### 6.5. HTTP-правки (`xhttp`)

`domcase`, `hostcase=hoSt`, `methodeol`, `unixeol` — простые байтовые
преобразования. Сложность не в них, а в том, что R2OP сейчас не умеет
заменять **реальный** HTTP-запрос: `payload` используется только для
фальшивок. Нужен новый plan action «заменить вход» или отдельный
HTTP-режим с verdict payload. Это средний риск; делать только если есть
подтверждённый сценарий блокировки HTTP/80.

### 6.6. SYN/ACK/window/RST (`xsynack`, `xsynacksplit`, `xwsize`,
`xwssize`, `xrst`)

Это действия над обратным направлением/рукопожатием. r2o сейчас наблюдает
reverse-пакеты, но не исполняет на них план. Нужен новый путь в engine:
применять план к server→client SYN-ACK и/или инъецировать RST/ACK. Это
существенное изменение; делать только при доказанной необходимости
(например, цензор 14/19 показывает, что DPI смотрит handshake). Пока —
P2/P3, не в первый срез.

### 6.7. TLS ClientHello clone (`xtlsclone`)

Сложный, но потенциально ценный приём: клонировать ClientHello, удалить/
добавить/переставить SNI, отправить как fake. r2o уже умеет править SNI во
входе и строить fake TLS, но не полный clone. Оценка: 1–2 недели +
дифференциал с `ext/tls_clone.c`. Делать после 6.1–6.3 и только под
конкретный DPI-сценарий.

### 6.8. Комбинаторы (`xwhen`, `xstop`, `xrepeat`, `xcutoff`)

Не переносить в R2OP в обозримом будущем. Это потребует дерева условий в
datapath и дублирует логику, которая у r2o уже есть в controller: выбор
плана по наблюдаемому состоянию потока. Если понадобится — лучше добавить
условные **планы** в controller, а не packet-level combinators.

## 7. P3: что делать с генетическим поиском

GA geneva_c (`evolve.c`/`mutate.c`) — качественная реализация:

- популяция, элитные клоны, турнирный отбор;
- мутации деревьев/действий/триггеров, кроссовер поддеревьев;
- hall of fame с кэшем оценок и ограничением повторов;
- атомарный checkpoint и точное продолжение с `--resume`;
- JSONL-база оценок по стратегии и цели;
- ограничения пространства (`--protos`, `--fields`, `--disable-action`,
  `--fix-trigger`, `--no-gas`, `--in/out-trees`, `--in/out-actions`);
- canary-пакеты из реального baseline.

Но переносить его «как есть» в r2o не стоит: это потребует второго
исполнителя Geneva DSL, второго набора evaluation-портов и второй модели
firewall. Более совместимый с r2o путь:

1. **Генотип — параметры R2OP**, а не Geneva-дерево: набор split-точек,
   poison-полей, fake-параметров, seqovl, oob, ipfrag, udplen, segment,
   порядка.
2. **Фенотип — обычный R2OP-план**, который ставится в существующий
   datapath через control-сокет на время пробы и снимается после.
3. **Fitness — существующие измерения r2o** (fetch/classify/response), плюс
   штрафы geneva_c: за длину плана, за неиспользованные действия, за
   лишние пакеты.
4. **Ограничения**: только явный opt-in, только на PC/CI или на роутере с
   бюджетом; максимум популяции/поколений; обязательный rollback; никаких
   permanent install до доказательства.
5. **Checkpoint/DB** — по образцу geneva_c, но в формате r2o и с привязкой
   к цели/семейству/сети.

Это отдельный проект на 3–6 недель. Начинать имеет смысл только после P0/P1
и после того, как R2OP получит tamper-поля: иначе пространство поиска будет
слишком бедным.

## 8. Мелкие заимствования, которые стоит рассмотреть

| Идея | Где в geneva_c | Что сделать в r2o | Приоритет |
|---|---|---|---|
| `--residual-wait` после неудачи | `evaluator.c::pause_after_failure` | пауза перед следующим кандидатом для residual-цензуры; opt-in, чтобы не менять D2O-поведение | P2 |
| Внешний оценщик (`eval_request`/JSON) | `evaluator.c::external_run` | hook для проверки полной загрузки страницы браузером/curl; не заменять штатные probes | P2/P3 |
| Штрафы фитнеса | `eval_punish` | использовать в GA/экспериментальном поиске, не в основной лестнице | P3 |
| Thompson sampling / RR | `ext/tuner.c` | выбор лучшего из нескольких рабочих планов на хост; только при наличии статистики | P3 |
| `--first N` | `engine.c`/`fw.c` | ранний bypass после N пакетов; у r2o уже есть сессионные гейты, отдельно не нужно | — |
| `fw print` | `fw.c` | печать правил для отладки; у r2o есть router-скрипты | — |
| seccomp/privdrop/daemon/sd_notify | `plat.c` | отдельная задача hardening для datapath/controller | P3 |
| pcap `check`/`apply` | `pcap.c`, `cmd_strategy.c` | offline-проверка планов и фикстуры для компилятора | P2 |

## 9. Что не брать и почему

1. **Архитектуру одного исполнителя.** r2o разделяет datapath и controller;
   это позволяет быстро освобождать пакеты и не ждать сетевых проб. Geneva
   executor этого разделения не имеет. Замена архитектуры — регресс.
2. **WinDivert/BSD/Android/WLAN.** r2o — Linux-роутер (OpenWrt/Keenetic).
   Эти бэкенды не нужны продукту и потянут за собой платформенный код.
3. **Server-side `agent`.** r2o явно не требует VPS/relay; это другой
   продукт.
4. **Полный profile/hostlist/ipset/L7-стек.** У r2o уже есть каталог,
   группы доменов, router firewall и целевые парсеры. Дублирование создаст
   два источника истины.
5. **Автоустановку firewall.** r2o router-скрипты уже управляют nft/
   iptables, PPE, watchdog и откатом. Второй менеджер правил опасен.
6. **Контрольный протокол и события.** У r2o свой протокол, panel и
   manager; менять его ради совместимости с geneva_c не нужно.
7. **Парсеры MTProto/DNS/QUIC/TLS.** В r2o уже есть D2O-совместимые
   реализации; porting geneva_c создаст второй набор багов.
8. **Полный Geneva DSL в datapath.** Это второй движок и второй набор
   семантики. Допустим только импорт/компиляция в R2OP.
9. **Lua-совместимость.** В r2o нет Lua и не должно быть.
10. **GA на роутере по умолчанию.** Слишком дорого по CPU/сети для слабых
    устройств; только opt-in/offline.

## 10. Предлагаемая последовательность работ

| Этап | PR | Содержание | Проверка | Риск |
|---|---|---|---|---|
| 1 | P0-a | `r2o-censor` unit-модели 1–11, 8b, DNS | порт `test_censor.c` | низкий |
| 2 | P0-b | `r2o-censor` NFQUEUE + netns-стенд | `censors.sh`-сценарии, r2o-планы | низкий |
| 3 | P0-c | модели 12–20 (TLS/QUIC/HTTP/policer/frag) | сценарии 12–20 | низкий/средний |
| 4 | P1-a | `r2o-geneva`: AST, parse/print/json, library | 145 записей корпуса, 58 стратегий | низкий |
| 5 | P2-a | R2OP `dataofs`/`flags`/`ack`/`ip_len`/`place=after` | `apply.rs`, `wire.rs`, дифференциал geneva_c | средний |
| 6 | P1-b | компилятор поддерживаемого подмножества библиотеки | байтовый дифференциал | средний |
| 7 | P2-b | `tlsmod=rndsni/padencap/sni=`, позиционные маркеры | unit + дифференциал | низкий/средний |
| 8 | P2-c | HTTP-правки, SYN/ACK/window/RST, TLS clone | по мере подтверждения сценариев | средний/высокий |
| 9 | P3 | GA поверх R2OP, opt-in | checkpoint/resume, hall of fame, budget | высокий |

Первый PR должен быть **P0-a**: он не меняет production, даёт немедленную
пользу и создаёт базу для всех остальных проверок.

Фактический статус на 2026-11-20: P1-a выполнен (парсер, каноникализатор,
библиотека, 145/145 корпуса); P2-a выполнен (`dataofs`, `flags`, `ack`,
`ip_len`, `tcp_window`, `place=after`); P1-b начат — компилятор
поддерживает 9 из 58 записей библиотеки и явно отвергает остальные.
P0-a/P0-b/P0-c (цензоры) ещё не начаты; следующий независимый шаг —
P0-a, потому что он не меняет production и даёт тестовый oracle.

## 11. Лицензии и атрибуция

- geneva_c — BSD 3-Clause; Geneva — BSD 3-Clause, Copyright (c) 2020,
  University of Maryland College Park.
- Библиотека `src/library_data.h` сгенерирована из `library.py` Geneva;
  при переносе сохранить уведомление и указать происхождение.
- Добавить раздел в `THIRD_PARTY_NOTICES.md` с пин-коммитом
  `bdb767d97e3af0f74de7db4d391bd38808e416cf` и списком перенесённых
  файлов/данных.
- Не менять лицензию r2o; новые файлы сопровождать комментарием о
  происхождении.

## 12. Итог

geneva_c ценен не как замена r2o, а как **набор независимых тестовых
моделей, проверенных стратегий и отдельных примитивов десинхронизации**.
Наибольшая отдача при минимальном риске — перенос лабораторных цензоров и
библиотеки стратегий. Расширение R2OP tamper-полями и `place=after` — мост,
который делает библиотеку реально применимой. Генетический поиск и
server-side/Windows/BSD-функции — не первый приоритет и не должны менять
архитектуру r2o.
