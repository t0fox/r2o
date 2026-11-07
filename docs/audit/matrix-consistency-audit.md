# Аудит согласованности матрицы паритета D2O → R2O

Дата: 2026-11-07. Аудит статический: проверялись `docs/functional-parity-matrix.md`, `docs/parity-function-inventory.md`, `docs/progress/progress.json`, `REA_EVIDENCE.md`, `tools/progress.mjs`, скрипты `scripts/*.sh|*.py`, C-тесты и Rust-тесты, а также дерево D2O `E:\d2o` (локальный checkout `a378e23`).

Ограничения аудита:

- В окружении нет `git`, `cargo`, `node`, `python`, `clang`/`gcc`; ни один differential не перезапускался. Все выводы о доказательствах сделаны по тексту скриптов, пинам ревизий, наличию `diff`/`cmp`/assert-сравнений и по записям матрицы.
- «Доказано» в этом отчёте означает только прямой C/Rust differential на ревизии, которую матрица сама объявила допустимой: `a63d964` (закреплённый C-эталон), либо явно перечисленные более поздние `a378e23`/`8e2c981`. Скрипты, закреплённые на `304ba893`, не считаются текущим доказательством: это другая ревизия, и она не равна ни заявленному эталону, ни более поздним сравнениям.
- Независимый прогон C-тестов и Rust-тестов без сравнения выходов не считается differential-доказательством. Helper/fixture, mock, source mapping и REA-граф не считаются доказательством поведения.
- Исторические записи #1–#171 не перезапускались и используются только как история заявлений, а не как доказательство.

Классификация доказательств, использованная ниже:

| Тип | Что это | Зачёт |
|---|---|---|
| D | Прямой C/Rust differential (или production-процессный differential с C-oracle) на `a63d964`/`a378e23`/`8e2c981` | полный балл в границах строки |
| D-304 | Прямой differential, закреплённый на `304ba893` | 0 (другая ревизия) |
| U | Независимые C- и Rust-тесты без сравнения выходов | 0 |
| H | Helper/fixture/mock/source mapping/REA | 0 либо partial, если contract прямо ограничен helper-уровнем |
| N | Нет пригодного прогона | 0 |

---

## 1. Арифметика текущей матрицы

### 1.1. Построчный разбор (строки 20–76 файла матрицы)

Статусы приведены как в таблице. «Э» = «Эквивалентно» или «Доказанно эквивалентно», «Ч» = «Частично», «Р» = «Реализовано, паритет частичный».

| # | Строка | Контракт | Вес | Статус | Балл |
|---:|---:|---|---:|---|---:|
| 1 | 20 | Кадр управления, команды и ACK/APPLIED/REFUSED | 3 | Э | 3 |
| 2 | 21 | TCP datapath: поток, разрезы, удержание, RST и счётчики | 3 | Э | 3 |
| 3 | 22 | UDP exchange и QUIC/STUN наблюдение | 2 | Э | 2 |
| 4 | 23 | Raw-профили, отправка, отмена, fallback и connect-fallback | 3 | Э | 3 |
| 5 | 24 | IPv6/фрагментация в живом NFQUEUE, маркировка маршрута, fail-open и conntrack | 3 | Ч | 0 |
| 6 | 25 | TCP flow-table limit, refusal counter, reverse lookup и expiry/reuse | 1 | Э | 1 |
| 7 | 26 | Периодическая сводка TCP/UDP flow-table и интервал службы | 1 | Э | 1 |
| 8 | 27 | Остальные периодические метрики datapath и процесса | 1 | Э | 1 |
| 9 | 28 | Длительная смешанная нагрузка большого числа потоков и peak RSS | 1 | Э | 1 |
| 10 | 29 | Scheduler worker-аргументы и возврат страниц после join | 1 | Э | 1 |
| 11 | 30 | Подтверждение базового CLEAR и отмена | 1 | Э | 1 |
| 12 | 31 | CLEAR только с подтверждённым SO_MARK | 1 | Э | 1 |
| 13 | 32 | Базовые transport errors и переход к разрезу | 1 | Э | 1 |
| 14 | 33 | Классификатор: baseline, poison/strategy tree, control и neutral ACK | 1 | Э | 1 |
| 15 | 34 | TCP measurement and core TLS/HTTP verifier outcomes/retry | 2 | Э | 2 |
| 16 | 35 | Discord Gateway WebSocket upgrade и первый Hello `op=10` | 1 | Э | 1 |
| 17 | 36 | Connect/read timeout classifier и единственный удвоенный baseline retry | 1 | Э | 1 |
| 18 | 37 | Scheduler: cooldown, мёртвый адрес, повтор и параллельные endpoints | 3 | Э | 3 |
| 19 | 38 | Discovery: known-plan reuse, очередь, coalesce, приоритет и worker permits | 3 | Э | 3 |
| 20 | 39 | ACK → точный APPLIED/proof → запись кандидата и reapply fixture | 3 | Э | 3 |
| 21 | 40 | JSON catalog, schema, atomic save и конкурентное слияние | 3 | Э | 3 |
| 22 | 41 | S99/procd: boot waiters, повторный start, detach/stop cancellation, delayed /opt | 1 | Э | 1 |
| 23 | 42 | Production daemon crash/restart and persisted catalogue reapply | 1 | Ч | 0 |
| 24 | 43 | Automatic refusal → Discovery/classification → APPLIED и firewall-rule reapply | 1 | Ч | 0 |
| 25 | 44 | TLS 1.2 reverse-direction response probe and verdicts | 3 | Э | 3 |
| 26 | 45 | HTTP search: кандидаты, повторы, all-failed/confirmed и точный APPLIED | 3 | Э | 3 |
| 27 | 46 | ECH receive ladder, witness и повторные испытания | 2 | Э | 2 |
| 28 | 47 | QUIC Initial/QSN, local-address gate и stop/fallback Discovery | 3 | Э | 3 |
| 29 | 48 | QUIC стратегия: residual/VN, адресный пул, neutral controls, fallback-кандидаты | 3 | Э | 3 |
| 30 | 49 | QUIC short-control: полный ответ или проход живого box budget | 1 | Э | 1 |
| 31 | 50 | HTTP/3 response framing and stream termination | 1 | Э | 1 |
| 32 | 51 | HTTP/3 request budgets, transport limits and stall deadlines | 1 | Ч | 0 |
| 33 | 52 | Discord UDP observer: инициатор, SSRC reconnect, endpoint change, долгий silence | 2 | Э | 2 |
| 34 | 53 | Discord Discovery manual measurement arm propagation | 1 | Э | 1 |
| 35 | 54 | Discord временная voice проба: lease, renewal, 120-секундное ожидание, APPLIED proof | 3 | Э | 3 |
| 36 | 55 | Discord endpoint change, late NAK retention, binding persistence, helper reapply | 1 | Э | 1 |
| 37 | 56 | Discord voice trial clock after queue admission и границы D2O | 1 | Э | 1 |
| 38 | 57 | Production controller recovery and long-running Discord RTC lifecycle | 1 | Ч | 0 |
| 39 | 58 | Telegram firewall route and DNS exclusion behavior | 1 | Э | 1 |
| 40 | 59 | Telegram response observer behavior | 1 | Э | 1 |
| 41 | 60 | Telegram config/DC map, handshake, MTProto/WebSocket retries, full service lifecycle | 1 | Р | 0 |
| 42 | 61 | Meta DNS scheduler lifecycle and packaged range asset | 1 | Э | 1 |
| 43 | 62 | Keenetic direct DNS, TLS edge verification and owned-record removal | 1 | Э | 1 |
| 44 | 63 | Панель: первичный bind и безопасный выбор интерфейса при установке | 1 | Э | 1 |
| 45 | 64 | Панель: недоступное live-состояние и catalog cache token | 1 | Э | 1 |
| 46 | 65 | Панель: control/actions, прочие status branches, настройки и assets | 1 | Э | 1 |
| 47 | 66 | Firewall: статические packet rules и backend | 1 | Э | 1 |
| 48 | 67 | Firewall: successful software flow-offload disable and restore | 1 | Э | 1 |
| 49 | 68 | Firewall: flow-offload write-failure policy | 1 | Э | 1 |
| 50 | 69 | Аппаратное ускорение PPE: backend, datapath, миграция тегов, очистка владельца | 1 | Ч | 0 |
| 51 | 70 | Firewall: код ошибки при отказе отдельного правила | 1 | Э | 1 |
| 52 | 71 | Firewall service: IPv4-only fallback, modules, marker, reapply, очистка семейства | 2 | Э | 2 |
| 53 | 72 | Firewall: динамические DNS-upstream exclusions и refresh | 1 | Э | 1 |
| 54 | 73 | Firewall service: heal/watchdog, reapply и ошибки | 1 | Э | 1 |
| 55 | 74 | Update guard: invalid release, current version, download failure | 1 | Э | 1 |
| 56 | 75 | Update activation ordering, rollback recovery, signed Linux/OpenWrt install | 1 | Э | 1 |
| 57 | 76 | ABI/QEMU и сборка OpenWrt targets | 2 | Э | 2 |

### 1.2. Суммы

- Строк: **57**.
- Сумма весов: **89**.
- Сумма баллов: **80**.
- 80 / 89 = **89,89 %**.
- Статусы: **50** «Э», **6** «Ч», **1** «Р», **0** «не проверено».

Арифметика самой таблицы сходится. Проблемы начинаются в тексте вокруг неё и в распределении по областям.

### 1.3. Расхождения с шапкой и историческими записями

| Место | Заявление | Факт | Вывод |
|---|---|---|---|
| Строка 3 | 57 контрактов, 89 баллов, 80/89 (89,89 %) | 57 / 89 / 80 | Верно |
| Строка 9 | «the 87-point matrix» | 89 баллов | Устаревший текст; противоречит строке 3 |
| Строка 12 | «всего 87 баллов» | 89 баллов | Устаревший текст |
| Строка 94 | 50 доказанных, 5 частичных, 1 реализованный, 1 непроверенный | 50 / 6 / 1 / 0 | Ошибка в счётчиках: одна частичная строка названа непроверенной |
| Строка 288 | «по 46 строкам: 33 доказаны, 12 частичны, 1 реализована, 0 не проверены; 63/87» | 57 / 89 / 80 | Полностью устаревший абзац, оставленный в актуальном документе |
| Таблица «Результат взвешивания» | Datapath 19/14, Discovery 21/19 | `progress.json`: Datapath 18/13, Discovery 22/20 | Ручная таблица областей расходится с собственным генератором; суммы 89/80 совпадают только за счёт взаимной компенсации |
| `docs/progress/progress.json` | 57 / 89 / 80; Datapath 13/18, Discovery 20/22, Classifier 14/14, QUIC 7/7, Discord 8/8, Gateway 1/1, Telegram 2/3, WebPanel 3/3, Firewall 8/9, Release 4/4 | Совпадает с построчным разбором | JSON согласован с таблицей, но не с ручной таблицей областей |
| Строка 3 | Gateway, update staging, periodic metrics, panel, worker memory «дополнительно сверены с a378e23» | Часть скриптов panel/update по-прежнему пинует `304ba893`; Gateway — `a378e23`; update — без пина/mock | Заявление о ревизии не воспроизводится checked-in скриптами для panel |
| `docs/parity-function-inventory.md`, строки 5 и 60 | Inventory заявляет источники `a63d964`/R2O `580cfa9` и что «Complete classifier/Discovery integration, remaining core modules, detect, Telegram, service/config/firewall production functions remain open under Task 1» | Матрица заявляет 80/89 и закрытые classifier/Discovery/panel/firewall/Telegram-строки; R2O-база в матрице — `234f729` | Inventory и матрица описывают разные срезы и разные степени готовности; inventory не обновлён под текущую таблицу |

Историческая хронология заявленных баллов:

| Записи | Заявленный счёт | Проблема |
|---|---|---|
| #73, #87, #89–#92 | 53/84 = 63,10 % | Знаменатель 84. Текущий знаменатель 89; какие 5 баллов веса добавлены, нигде не перечислено |
| #93–#96 | 53/86 = 61,63 % | 84 → 86 (+2) без списка добавленных контрактов |
| #102–#109 | 54/85 = 63,53 % | 86 → 85 (−1): знаменатель уменьшился, что не объяснено |
| #110 | 55/85 | +1 |
| #111–#112 | 56/85 | +1 |
| #113 | 57/85 | +1 |
| #114–#115 | 58/87 | 85 → 87 (+2) без списка контрактов; #115 при этом говорит, что ABI-строка частична и баллов не добавляет |
| #116 | 55/87 = 63,22 % | Счёт упал на 3 балла «из-за» исправления HTTP-reader, хотя ни одна строка не удалялась |
| #117 | 56/87 | +1 |
| #118–#127 | 58/87 | +2 |
| #128 | 61/87 = 70,11 % | +3 за TLS response row |
| #129–#153 | 62/87 = 71,26 % | +1 |
| #154–#155 | 63/87 | +1 (исправление арифметики QUIC/HTTP3: 8/9, а не 9/9) |
| #156 | 73/87 | Временное разбиение; сам автор признаёт, что число не подтверждено |
| #157–#162 | 72/87 = 82,76 % | −1 после аудита flow-offload |
| #163–#165 | 73/87 = 83,91 % | +1 |
| #166 | 75/87 = 86,21 % | +2 за Meta DNS (две строки), что согласуется с таблицей |
| #167 | 75/89 = 84,27 % | Добавлена Gateway-строка (вес 1, балл 1), но баллы не выросли: должно быть 76/89, если Gateway действительно доказан |
| #168 | 76/89 = 85,39 % | +1 update |
| #169 | 78/89 = 87,64 % | +2, хотя закрыта одна строка весом 1 (periodic metrics). Один балл не объяснён; вероятно, им компенсируется пропущенный балл #167 |
| #170 | 79/89 = 88,76 % | +1 panel |
| #171 | 80/89 = 89,89 % | +1 worker memory; совпадает с текущей таблицей |

Итог: **текущая таблица арифметически равна 80/89, но исторический журнал не позволяет восстановить, как получился именно этот знаменатель и почему в двух переходах балл изменился не на ту величину.** Записи #167–#169 взаимно компенсируют ошибку, поэтому итог 80/89 выглядит правильным только на конце цепочки.

Практически все записи #73–#170 противоречат текущей таблице как «текущее состояние»: у них другой знаменатель (84/85/86/87/89) и/или другой счёт. Единственная запись, совпадающая с текущей таблицей, — #171 (80/89). Записи #156 и #157 — не независимые срезы, а временная декомпозиция и её аудит; #157 прямо отменяет завышение #156.

### 1.4. Баллы, начисленные без текущего доказательства

Из 80 баллов **49 баллов** находятся в строках, все основные доказательства которых закреплены только на `304ba893` и не имеют принятого текущего differential:

- L20 (3), L22 (2), L23 (3), L25 (1), L28 (1), L30 (1), L31 (1), L32 (1), L33 (1), L36 (1), L37 (3), L38 (3), L39 (3), L40 (3), L44 (3), L45 (3), L46 (2), L48 (3), L49 (1), L52 (2), L53 (1), L55 (1), L56 (1), L58 (1), L59 (1), L63 (1), L64 (1), L65 (1).

Остальные 31 балл либо имеют хотя бы одно доказательство на `a63d964`/`a378e23`/`8e2c981`, либо их evidence не имеет фиксированной SHA-ревизии (например, L47); часть из них — helper, build-smoke или mock, а не production differential (это отдельно разобрано в разделах 3–5).

Отдельно:

- L22 (2 балла) — оба скрипта (`r2o-udp-exchange-differential.sh`, `r2o-quic-stun-watch-differential.sh`) не сравнивают выходы C и Rust: они независимо запускают C-тесты и Rust-тесты и проверяют `grep`-ом успешность. Это не differential.
- L48 (3 балла) — в графе подтверждения прямо написано: «исторические записи `REA_EVIDENCE.md` (29 окт.)». REA — это source/binary mapping, а не поведенческий differential; сам `REA_EVIDENCE.md` оговаривает, что это «не заявление о полной эквивалентности».
- L58 и L59 (2 балла) — исторические differential, не перезапущенные в текущем окружении; сравниваются с донором z2kOW, а не с C11 D2O. Это не D2O-паритет в строгом смысле.
- L66 (1 балл) — последняя явная запись #164 говорит: «статический firewall контракт остаётся 0/1». Ни одна последующая запись не показывает closure этой строки; тем не менее в таблице стоит 1.
- L71 (2 балла) и L76 (2 балла) — helper/service fixture и build-smoke; kernel/runtime-поведение не проверялось. Это не эквивалентность production-поведения.
- L65 и L73 (по 1 баллу) — заявлены прогоны «временными копиями с заменой только ожидаемого SHA». Checked-in скрипты продолжают пинить `304ba893`/`a63d964`, поэтому заявленная ревизия не воспроизводится без ручной правки.
- L21, L34, L54 — смешанные: часть evidence на `a63d964`/`a378e23`, часть на `304ba893`; L47 — `304ba893` плюс скрипты без SHA-пина. Балл целиком начислен, хотя покрытие неполное.

---

## 2. Дубли и пересечения контрактов

| Строки | Что пересекается | Оценка | Предложение |
|---|---|---|---|
| L42 и L57 | Оба про восстановление controller/process; L42 — crash/restart + catalog reapply, L57 — controller recovery + long RTC | Фактически один процессный контракт; L57 уже 0 | Оставить L42 как «supervisor restart + catalog reapply», L57 сузить до «long-running RTC session» или удалить |
| L41, L42, L57 | S99/procd waiter, daemon crash/restart, controller recovery | Три строки описывают один lifecycle на разных уровнях | L41 — init/waiter; L42 — supervisor/respawn; L57 — RTC; явно указать границы |
| L43, L39, L38 | Auto refusal → Discovery → APPLIED; APPLIED/persistence; Discovery queue | L43 — интеграционный сценарий, L39/L38 — его части | L43 оставить как end-to-end smoke весом 1 только после реального process differential; иначе 0 и не дублировать баллы |
| L66 и L70 | L66 включает `test-firewall-rule-error-differential.sh`, который является единственным доказательством L70 | Один и тот же скрипт даёт 2 балла | Оставить L70 отдельно, из L66 убрать branch rule-error |
| L66 и L73 | L66 включает `test-router-iptables-status-differential.sh`; L73 использует его же | Пересечение status/iptables | L66 — генерация правил, L73 — status/heal; убрать status из L66 |
| L66 и L71 | L66 включает IPv6/legacy cleanup; L71 — IPv4-only fallback, modules, marker, reapply | Пересечение service/backend | L66 — статические правила; L71 — service lifecycle; убрать IPv6 fallback из L66 |
| L71 и L73 | Оба service-level; L71 — reapply, L73 — reapply/heal | Пересечение reapply | L71 — установка/повторная установка; L73 — heal/watchdog/cooldown |
| L72 и L73 | DNS exclusion refresh вызывается из heal | Пересечение refresh | L72 — DNS exclusions; L73 не должен засчитывать DNS refresh |
| L67 и L68 | Оба используют `test-router-flowoffload-d2o-differential.sh`; success и write-failure — две ветви одного fixture | Два балла из одного скрипта | Оставить две строки, но явно указать, что это один fixture и две ветви; либо объединить в один контракт весом 1 |
| L47 и L48 | L47 включает stop/fallback Discovery; L48 — fallback-кандидаты | Пересечение QUIC fallback | L47 — Initial/QSN/local-address; L48 — стратегия/пул/controls; fallback только в одной строке |
| L45 и L39 | L45 включает «точный APPLIED», L39 — APPLIED/proof | Пересечение APPLIED | L45 — HTTP-search кандидаты/повторы; APPLIED оставить в L39 |
| L21, L25, L28 | TCP datapath, flow-table capacity, high-cardinality | L25 и L28 — подобласти TCP datapath | L21 — packet/session decisions; L25 — capacity; L28 — load/RSS; явно разграничить |
| L21 и L34 | L21 — TCP session/datapath, L34 — TCP measurement/verifier | Разные C-модули (`datapath/session.c` vs `core/meas.c`), но один пользовательский путь | Оставить, но L34 сузить до `core/meas.c` + verifier, без повторения session |
| L33 и L30–L32, L36 | L33 «полный классификатор» включает baseline, control, neutral ACK, transport errors, timeout | L30–L32 и L36 — те же ветви, оформленные отдельными строками | L33 — poison/strategy tree и control; L30–L32/L36 — отдельные branches; иначе 3–4 балла дублируются |
| L54 и L55, L53 | L54/L55 используют один `r2o-discord-voice-lifecycle-helper.sh`; L53 — отдельный arm | Один lifecycle trace даёт 4 балла (3+1, плюс часть L53) | L54 — lease/renewal/APPLIED; L55 — endpoint/NAK persistence; L53 — arm; проверить, что helper-трейс не засчитывается дважды |
| L52 и L57 | L52 обещает «долгий silence», L57 — long-running RTC | L52 — observer на synthetic trace, L57 — process | L52 — observer semantics; L57 — процесс; не заявлять 600-секундный RTC в L52 |
| L58, L59, L60 | Один и тот же донор z2kOW; L58/L59 — отдельные части, L60 — всё остальное | Три балла за один source-port, причём L58/L59 исторические | Объединить в один контракт «Telegram donor integration» весом 2–3 или оставить 3 строки, но с 0 баллов до текущего differential |
| L74 и L75 | Оба про `install_release()` и update guards; используют те же update scripts | Пересечение guard/activation | L74 — guard/current/download failure; L75 — staging/stop/activate/health/rollback; убрать guard из L75 |
| L61 и L62 | Meta DNS scheduler и direct DNS/TLS edge | Разные функции, но один домен | Оставить; проверить, что removal не дублирует scheduler stop |
| L63, L64, L65 | Три панельные строки | В целом разграничены, но L65 включает status branches, которые частично в L64 | L64 — unavailable/catalog token; L65 — control/actions/workers/assets/update |

---

## 3. Слишком широко объединённые пункты

| Строка | Что слито в один вес | Почему это плохо | Предлагаемая декомпозиция (вес) |
|---|---|---|---|
| L24 (3) | IPv6 NFQUEUE, фрагментация, route mark, fail-open, conntrack, SNAT | Пять независимых ветвей; C IPv6 oracle отсутствует; одна частичная строка не показывает, что именно доказано | IPv6 live NFQUEUE/fail-open (3); fragment builders IPv4/IPv6 (1); route mark (1); conntrack/NAT (1); IPv6 SNAT/reverse (1) |
| L21 (3) | TCP flow, cuts, hold, RST, counters, silence | Разные C-модули (`session.c`, `hold.c`, `udp_path.c`, `wire.c`), разные типы доказательств | payload/SNI counters (1); silence/expiry/FIN/RST (1); hold/order/ownership (1); RST cut/observation (1); HTTP80 replacement (1) |
| L33 (1) | baseline + poison tree + control + neutral ACK + timeout | «Полный классификатор» смешивает уже отдельно посчитанные L30–L32/L36 | poison/strategy tree (2); control/neutral ACK (1); baseline/CLEAR (1); timeout (1) |
| L34 (2) | `core/meas.c` + `core/verify.c` + TLS/HTTP verifier + retry | Два разных модуля и разные выходы; fixtures не покрывают весь verifier call path | TCP measurement (1); TLS/HTTP verifier outcomes (1); response retry/DNS rotation (1) |
| L45 (3) | HTTP-search кандидаты, повторы, all-failed/confirmed, APPLIED | Один вес на state machine + сетевой поиск + APPLIED; живой поиск исключён | candidate ordering/retry/backoff (2); judge/confirmed (1); APPLIED (1) |
| L47 (3) | QUIC Initial/QSN, local-address gate, stop/fallback Discovery | Три независимые ветви; local-address и stop/fallback имеют разные триггеры | Initial/QSN/SNI (2); local-address gate (1); stop/fallback Discovery (1) |
| L48 (3) | residual/VN, address pool, neutral controls, fallback candidates | Нет ни одного текущего дифференциала; всё держится на REA/source mapping | residual/VN decision (2); address pool/selection (1); neutral controls (1); fallback candidates (1) |
| L52 (2) | initiator, SSRC reconnect, endpoint change, long silence | Observer semantics и длительная RTC-сессия — разные вещи; 600 с в fixture не равно production | SSRC/reconnect/endpoint event (1); silence/expiry semantics (1); long RTC (1, отдельно, 0) |
| L54 (3) | lease, renewal, 120-секундное ожидание, APPLIED proof | Helper trace + scheduled queue; process path не проверен | lease/renewal (2); 120-s waiter/queue admission (1); APPLIED proof/persistence (1) |
| L58 (1) | Telegram route и DNS exclusion | Две разные ветви; историческое доказательство | route plan (1); DNS exclusion (1) |
| L59 (1) | Telegram response observer | Одна ветвь, но historical | observer parse/decision (1) |
| L60 (1) | config/DC map, handshake, MTProto/WebSocket retries, full service lifecycle | Огромный вес 1; source mapping, не поведение | config/DC map (1); MTProto handshake (1); WS/retry (1); service lifecycle (1) |
| L66 (1) | static rules, backend, MEASURE_MARK, D2K_GATE, CONNBYTES, broadcast, nft rollback, legacy cleanup, RST lifetime | Один балл на 9+ ветвей; часть ветвей уже посчитана в L68/L70/L71/L72/L73 | rule generation/backend (2); marks/gate/ports (1); rollback/legacy/RST (1); error code (1) |
| L71 (2) | IPv4-only fallback, modules, marker, reapply, stale-family cleanup | Пять service-ветвей; helper fixture | fallback/module load (1); marker/status (1); explicit reapply (1); stale cleanup (1) |
| L69 (1) | PPE backend, datapath, tag migration, owner cleanup | Hardware datapath не проверен; shell rule generation — только часть | rule generation (1); backend/reapply (1); cleanup/errors (1); hardware/kernel (1) |
| L75 (1) | staging, stop, activate, health, rollback, signed install | Шесть шагов на один балл; OpenWrt/reboot исключены | staging/signature (1); stop/activate/health (1); rollback (1); OpenWrt/procd (1) |
| L76 (2) | cross-build, ABI, QEMU smoke, physical router | Build evidence не равно runtime parity | cross-build/ABI (1); QEMU smoke (1); physical router (1) |
| L23 (3) | profiles, send, cancel, fallback, connect-fallback | Пять ветвей; часть — helper byte-compare | profiles/ECH shapes (2); send/split (1); cancellation (1); fallback/connect (1) |

---

## 4. Подозрительные зачёты

| Строка | Заявление | Что реально в доказательстве | Вердикт |
|---|---|---|---|
| L22 | «Эквивалентно», 2 балла | `r2o-udp-exchange` и `r2o-quic-stun-watch` запускают C-тесты и Rust-тесты независимо, без `diff`/`cmp` | 0; нужен paired output differential |
| L48 | «Эквивалентно», 3 балла | В графе: «исторические записи REA_EVIDENCE.md (29 окт.)»; REA — source mapping | 0; source mapping не является поведенческим differential |
| L58, L59 | «Доказанно эквивалентно», 2 балла | Исторический differential, не перезапущен; сравнивается с z2kOW, а не с D2O C11; Cargo/Clang 18 недоступны | 0 или partial; нужен текущий прогон и явное решение о допустимости z2kOW как эталона |
| L66 | «Доказанно эквивалентно», 1 балл | Последняя запись #164: static firewall point остаётся 0/1; в таблице 1 | Снять 1 балл до появления записи о closure |
| L71 | «Эквивалентно», 2 балла | Helper/service fixture `test-router-ipv6-fallback-differential.sh`; «не live kernel test» | 1/2; live module/queue branch остаётся 0 |
| L76 | «Доказанно эквивалентно», 2 балла | Cross-build + QEMU `--version` + catalog smoke; физическая калибровка исключена | 1/2; это build/ABI evidence, не функциональный parity |
| L65 | «Доказанно эквивалентно», 1 балл | 22 panel scripts закреплены на `304ba893`; прогон на `a378e23` делался временными копиями с заменой SHA | 0/partial; checked-in скрипт не воспроизводит заявленную ревизию |
| L73 | «Доказанно эквивалентно», 1 балл | Пять harnesses перезапускались временными копиями с заменой expected SHA; checked-in пины остались `a63d964`/`8e2c981` | 0/partial; нужен чистый прогон без подмены |
| L54 | «Эквивалентно», 3 балла | `r2o-discord-discovery-differential.sh` вызывает helper; C fixture и Rust unit; process/RTC не проверены | 1–2/3; helper не равен production lifecycle |
| L55 | «Доказанно эквивалентно», 1 балл | Сам текст: «source-backed helper differential, not a long-running controller or RTC session» | 1 балл допустим только как helper-контракт; не как production |
| L52 | «Эквивалентно», 2 балла | Synthetic trace 600 с; нет production RTC | 1–2/2; long-silence branch не доказан на реальном процессе |
| L21 | «Эквивалентно», 3 балла | 1 настоящий output diff (`tcp-payload-stats`) + `tcp-silence`; остальные — независимые C/Rust suites (`hold`, `rst-cut`, `reply-hidden`, `exchange`) | 1–2/3; нужны paired diff для hold/RST |
| L37 | «Эквивалентно», 3 балла | 2 paired diff (`cooldown`, `dead-address`, `concurrent`) + `r2o-scheduler-differential.sh`, который независимо запускает C и Rust tests | 2/3; due ordering/queue не paired |
| L38 | «Эквивалентно», 3 балла | Скрипты закреплены на `304ba893`; часть — source/order fixtures | 0/3 при строгом правиле; 2–3/3 при принятии 304 |
| L33 | «Доказанно эквивалентно», 1 балл | C fixture + Rust scripted backend; production positive path — synthetic loopback; часть ветвей injected | 1 балл допустим как scoped synthetic contract; live DPI не доказан |
| L34 | «Эквивалентно», 2 балла | `meas` 304, `tls-verify` a378, `measured-split` 304, HTTP chunk a63; row смешивает разные ревизии | 1/2; разделить на measurement и verifier |
| L35 | «Доказанно эквивалентно», 1 балл | `tls-verify` на `a378e23`, не на текущем `8e2c981`; loopback | 1 балл допустим как scoped a378 contract; не current-main |
| L28 | «Эквивалентно», 1 балл | Pinned D2O `304ba893` и R2O `03d29dc`; 60 с нагрузки | 0 при строгом правиле; 1 при принятии 304 |
| L29 | «Доказанно эквивалентно», 1 балл | RSS measurement, C `mmap/munmap` vs Rust pool; syscall parity не заявлен | 1 балл как behavior, не syscall parity |
| L42, L43, L57, L69, L51, L60 | 0 баллов | Частичные/непроверенные | Корректно, но L42/L43/L57 дублируют друг друга |
| L41 | «Доказанно эквивалентно», 1 балл | QEMU differential waiter dispatch; crash recovery отдельно | 1 балл корректен в заявленной границе |
| L61, L62 | «Доказанно эквивалентно», 1+1 | `a63d964`/`8e2c981`; Linux fixtures, не Keenetic | Допустимо как fixture-contract, не physical router |
| L67, L68 | «Доказанно эквивалентно», 1+1 | Один и тот же скрипт; success и write-failure | Два балла за один fixture — переоценка; либо 1 балл, либо явно две независимые проверки |

---

## 5. Отсутствующие production-модули D2O

Локальный D2O checkout: `a378e230947ebfd011439e1cac0f1e994d883aae`. Инвентарь указывает источники `a63d964`/R2O `580cfa9`, то есть сам инвентарь устарел относительно матрицы (R2O `234f729`). В инвентаре есть только текстовое примечание о неполном покрытии; отдельных строк/module/API slice для перечисленных ниже модулей нет.

| Модуль | Есть в инвентаре | Есть контракт в матрице | Комментарий |
|---|---|---|---|
| `core/compose.c` | Только примечание | Нет | Оркестрация compose/verify; упоминается в classifier-скриптах, но не как контракт |
| `core/d2kask.c` | Только примечание | Нет | Есть `r2o-ask-differential.sh`, но он не сравнивает выходы; Rust `ask_cli` |
| `core/d2kfetch.c` | Только примечание | Нет | Есть `r2o-fetch-cli-differential.sh` (сравнивает CLI) и Rust `r2o_fetch_cli`; в матрицу не внесён |
| `core/d2kvoice.c` | Только примечание | Нет | Discord-строки покрывают voice logic, но не controller entry point |
| `core/link.c` | Только примечание | Нет | Control link; не отражён |
| `core/net4.c` | Только примечание | Нет | IPv4 helpers; не отражён |
| `core/plantlv.c` | Только примечание | Нет | Plan table; используется как object в fixtures, но отдельного контракта нет |
| `core/udpruntime.c` | Только примечание | Нет | UDP runtime; не отражён |
| `core/volume.c` | Только примечание | Нет | Rust `r2o_volume`/`tests/r2o_volume.rs` есть, C/Rust differential в матрице отсутствует |
| `core/crypto.c` | Частично | Нет | Helper TLS/QUIC; отдельного контракта нет |
| `core/p256.c` | Частично | Нет | Helper; отдельного контракта нет |
| `core/x25519.c` | Частично | Нет | Helper; отдельного контракта нет |
| `core/props.c` | Частично | Нет | DPI properties; `detect/props.c` покрыт detect-слоем, `core/props.c` — нет |
| `core/udpplan.c` | Частично | Нет | UDP plan helpers; упоминается в QUIC-строке, но не как контракт |
| `core/d2kc.c` | Частично | Нет | Controller event loop; inventory упоминает в HTTP-search slice, контракта нет |

Дополнительно без отдельного контракта в матрице:

- `core/httpsprobe.c` — HTTPS classification/cache/TTL/ECH resolve; в inventory есть, в матрице отдельной строки нет.
- `core/h3.c` — HTTP/3 control/request/status; покрыт только косвенно QUIC/H3-строками.
- `core/diagnostics.c` — diagnostics records/snapshots; в матрице только periodic metrics, не diagnostics.
- `core/verify_quic_replay.c` — replay/verification; покрыт косвенно.
- `datapath/http80.c`, `datapath/http_trace.c` — HTTP replacement/trace; отдельного контракта нет.
- `datapath/journal.c` — journal/event retention; отдельного контракта нет.
- `datapath/icmpguard.c` — ICMP guard; отдельного контракта нет (есть helper-тест).
- `datapath/plan_parse.c`, `plan_apply.c`, `plans.c` — plan parsing/install; покрыты косвенно control/Discovery.
- `datapath/capture.c`, `tls.c`, `wire.c`, `wire_udp.c`, `addr.c` — helpers; покрыты косвенно TCP-строкой.
- `datapath/nat.c`, `ctq.c` — NAT/conntrack; покрыты косвенно IPv6-строкой.
- `detect/*` — покрыт module-slice и classifier-строками, но не построчно.
- `panel/*` — покрыт тремя строками, но не всеми endpoint/branch.
- `telegram/*` — три строки, 38 файлов донора; покрытие частичное.
- `relay-enroll`, `relay-gate` — отдельные VPS-сервисы; матрица явно выводит их из scope (строка 9). Контрактов нет и не должно быть в router-runtime матрице, но их нужно явно исключать из любых будущих расчётов.

---

## 6. Предложенная матрица

Правила предложенной матрицы:

- Вес 1–3 назначается независимой проверяемой ветви, а не «модулю целиком».
- Балл начисляется только при прямом C/Rust differential на принятой ревизии (`a63d964`, `a378e23`, `8e2c981`) либо при production-процессном differential с C-oracle.
- `0` = нет принятого доказательства; каждая предложенная строка имеет балл либо 0, либо полный вес. Частично доказанные широкие ветви разнесены на отдельные строки, чтобы не смешивать доказанное и недоказанное в одном балле.
- «Покрытие» — существующие скрипты/тесты; «Пробел» — ветви, которые остаются незакрытыми.

### 6.1. Datapath / NFQUEUE

| ID | Контракт (вес) | Статус | Балл | Покрытие сейчас | Пробел |
|---|---|---|---:|---|---|
| D1a | NFQUEUE receive/verdict/truncation (1) | доказано | 1 | `test-nfq-netns.sh`, `test-datapath-default-mode-differential.sh`, unit queues | IPv6 C-oracle; malformed header injection |
| D1b | NFQUEUE rcvbuf/poll/recv error policy (1) | 0 | 0 | `test-nfq-ipv4-recv-error-differential.sh` (a63), `test-nfq-ipv6-recv-error-recovery.sh` (R2O-only), unit `receive_error_policy...` | `SO_RCVBUFFORCE/SO_RCVBUF` только unit, без прогона; IPv6 C-oracle |
| D2 | IPv6 live NFQUEUE gateway FORWARD, fragments, route mark, fail-open (3) | 0 | 0 | `test-nfq-ipv6-forward-netns.sh`, QEMU/WSL evidence; C `nfq.c` binds только AF_INET | Нет C IPv6 oracle; route mark/fail-open/PPE не проверены в одном прогоне |
| D3 | Fragment builders IPv4/IPv6 shapes 1–4 + session decide (1) | доказано | 1 | `test-ipfrag-differential.sh` (a63), `r2k-core/tests/ipfrag.rs` | Нет live IPv6 raw-send |
| D4 | TCP payload/SNI counters, split hello (1) | доказано | 1 | `r2o-tcp-payload-stats-differential.sh` (output diff), Rust unit | Только IPv4/TCP; нет непустых periodic samples |
| D5 | TCP silence/expiry/FIN/RST/ClientHello retry (1) | доказано | 1 | `test-tcp-silence-current-differential.sh` (a63), `test-datapath-capture-lifecycle-differential.sh` (a63) | Нет длительного процесса/таймингов на реальном роутере |
| D6 | TCP hold/order/ownership/release (1) | 0 | 0 | `r2o-hold-differential.sh` — независимые C/Rust suites, без diff | Нет paired output differential; timeout/revision только unit |
| D7 | TCP RST cut/observation/reply-hidden (1) | 0 | 0 | `r2o-tcp-rst-cut-differential.sh`, `r2o-tcp-rst-observation-differential.sh`, `r2o-tcp-reply-hidden-differential.sh` — независимые suites | Нет paired diff; 304 pin |
| D8 | TCP flow-table capacity/refusal/expiry/reuse (1) | 0 | 0 | `test-datapath-tcp-capacity-differential.sh` (304) | Другая ревизия; нужен прогон на a63/a378 |
| D9 | Periodic flow-table stats + service interval (1) | доказано | 1 | `test-datapath-stats-timer-differential.sh` (a378) | Нулевой/неполный traffic; IPv6 |
| D10 | Other periodic datapath/process metrics (1) | доказано | 1 | `test-datapath-stats-timer-differential.sh` (a378), `test-datapath-process-stats-differential.sh` | Не все метрики; C/Rust traces на одном fixture |
| D11 | High-cardinality mixed load + peak RSS (1) | 0 | 0 | `test-datapath-high-cardinality-differential.sh` (304) | Другая ревизия; физическая калибровка |
| D12 | Worker args/page return after join (1) | доказано | 1 | `test-worker-memory-differential.sh` (a378) | Syscall parity не заявлен; только RSS |
| D13 | IPv4 NAT/conntrack/SNAT/reverse (1) | доказано | 1 | `test-conntrack-retry-current-differential.sh` (a63), `test-nfq-ipv4-recv-error-differential.sh` (a63) | IPv6; ctnetlink errors; live router |
| D14 | Default observe/apply mode (1) | доказано | 1 | `test-datapath-default-mode-differential.sh` (a63) | Явный `--mode apply` parser regression |
| D15 | ICMP guard counters/quoted-packet matching (1) | доказано | 1 | `test-icmp-guard-current-differential.sh` (a63) | Live IPv6 NFQUEUE |
| D16 | Raw IPv6 emission shapes/UDP delivery (1) | доказано | 1 | `test-raw6-send-differential.sh` (a63) | Route mark/MTU on live router |
| D17 | HTTP/80 replacement + hold (1) | 0 | 0 | `http80.c`/`http_trace.c`; C tests; Rust `http_replace` | Нет matrix-контракта и paired diff |
| D18 | Capture/TLS/wire/addr helpers (1) | 0 | 0 | C tests, Rust unit tests | Нет paired diff |
| D19 | Route mark/socket route selection (1) | 0 | 0 | `test-router-route-gate-config.sh` (a63) — только service args | Runtime SO_MARK/route selection не проверен |
| | **Итого Datapath** | | **11/22** | | |

### 6.2. Control / Scheduler / Discovery / Catalog

| ID | Контракт (вес) | Статус | Балл | Покрытие сейчас | Пробел |
|---|---|---|---:|---|---|
| S1 | Control frame/commands/ACK/APPLIED/REFUSED (2) | 0 | 0 | `r2o-control-events`, `r2o-control-dropped`, `r2o-ack-applied-persist` (все 304) | Другая ревизия; длительный процессный restart |
| S2 | Scheduler due order/cooldown/dead address/concurrent endpoints (3) | 0 | 0 | `r2o-scheduler-cooldown`/`dead-address`/`concurrent` (304), `r2o-scheduler-differential` (без diff) | 304; due ordering не paired |
| S3 | Discovery known-plan/coalesce/queue/permits/own-first (3) | 0 | 0 | `r2o-discovery-*`, `r2o-queue-order`, `r2o-worker-permit`, `r2o-own-first` (304) | 304; нет текущего прогона |
| S4 | ACK → APPLIED exact proof → candidate persistence (2) | 0 | 0 | `r2o-ack-applied-persist` (304), `r2o-known-plans` (304) | 304; process restart |
| S5 | JSON catalog atomic save/merge/sync (2) | 0 | 0 | `r2o-catalog-persist`, `r2o-catalog-sync` (304) | 304; concurrent external writer |
| S6 | HTTP search candidate/order/retry/judge/APPLIED (3) | 0 | 0 | `r2o-http-search` (304), `r2o-fetch-cli` (без пина) | 304; живой поиск; APPLIED branch |
| S7 | S99/procd boot waiters/restart/stop/delayed /opt (1) | доказано | 1 | `test-router-procd-lifecycle-qemu.py` (a63), `test-router-openwrt-init.sh` | Только waiter dispatch; crash recovery отдельно |
| S8 | Process crash/restart + catalog reapply (1) | 0 | 0 | `test-controller-process-reapply-qemu.py` (R2O-only), `test-router-process-supervisor.sh` | Нет C-parity; D2O waiter one-shot |
| S9 | Auto refusal → Discovery → APPLIED → firewall reapply (2) | 0 | 0 | Process smoke с fake datapath peer | Нет реального datapath/firewall; failure injection |
| S10 | Long-running controller recovery (1) | 0 | 0 | Нет | Полный цикл после crash/restart |
| | **Итого Discovery** | | **1/20** | | |

### 6.3. Classifier / TLS / HTTP

| ID | Контракт (вес) | Статус | Балл | Покрытие сейчас | Пробел |
|---|---|---|---:|---|---|
| C1 | Raw profiles/ECH shapes/send/cancel/fallback/connect (3) | 0 | 0 | `r2o-raw-profile`, `r2o-raw-emission-cancel`, `r2o-raw-connect-fallback`, `r2o-fallback`, `r2o-raw-split-support` (304) | 304; live DPI; cancel/timing |
| C2 | CLEAR confirmation/cancel (1) | 0 | 0 | `test-classifier-clear-confirm` (304) | 304 |
| C3 | SO_MARK confirmation (1) | 0 | 0 | `test-classifier-so-mark-production` (304) | 304; production getsockopt |
| C4 | Base transport errors → split (1) | 0 | 0 | `test-classifier-full-tree-control` (304) | 304 |
| C5 | Poison/strategy tree/control/neutral ACK (2) | 0 | 0 | `test-classifier-full-tree-control`, `candidate-filter`, `raw-production` (304) | 304; injected/scripted branches |
| C6 | TCP measurement + core verifier (2) | 0 | 0 | `r2o-meas`, `r2o-measured-split` (304) | 304; full call path |
| C7 | TLS/HTTP verifier outcomes/retry (1) | доказано | 1 | `r2o-tls-verify-differential.sh` (a378), `test-http-chunk-framing` (a63) | Loopback; не live DPI |
| C8 | Connect/read timeout + doubled baseline retry (1) | 0 | 0 | `test-classifier-full-tree-control` (304) | 304 |
| C9 | TLS 1.2 reverse response probe/verdicts (3) | 0 | 0 | `test-d2o-shared-fixtures` (304), `test-classifier-full-tree-control` (304) | 304; live DPI |
| C10 | ECH receive ladder/witness/retries (2) | 0 | 0 | `r2o-ech-rx-ladder`, `r2o-layered-rx` (304) | 304; реальные ECH-конфигурации |
| C11 | HTTP response framing/reader (1) | доказано | 1 | `test-http-chunk-framing-differential.sh` (a63), `r2k-core` tests | Остальные call-path/ветви |
| C12 | ClientHello/TLS12/13/ECH parser helpers (1) | 0 | 0 | C `test_hello/test_ech/test_tls12`, Rust unit | Нет paired diff |
| C13 | HTTPS probe/ECH resolver/cache state (1) | 0 | 0 | C `test_httpsprobe`, Rust tests | Нет paired diff |
| C14 | HTTP/3 status/header parser + httpup (1) | 0 | 0 | C `test_h3`, `test_httpup_logic`; Rust tests | Нет paired diff |
| C15 | Compose/crypto/p256/x25519/props helpers (2) | 0 | 0 | C tests, Rust unit | Нет matrix-контракта |
| | **Итого Classifier/TLS** | | **2/23** | | |

### 6.4. QUIC / HTTP3

| ID | Контракт (вес) | Статус | Балл | Покрытие сейчас | Пробел |
|---|---|---|---:|---|---|
| Q1 | QUIC Initial/QSN/SNI/local-address gate (2) | 0 | 0 | `r2o-quic-hello`, `r2o-quic-local-address` (304), `r2o-discovery-quic-stop` | 304; stop/fallback |
| Q2 | Residual/VN/address pool/neutral controls/fallback (3) | 0 | 0 | REA_EVIDENCE (source mapping), controller unit tests | Нет поведенческого differential |
| Q3 | Short-control complete/budget (1) | 0 | 0 | `test-quic-short-control` (304) | 304 |
| Q4 | HTTP/3 framing/stream termination (1) | доказано | 1 | `test-quic-http3-full-stage-differential.sh` (a63), 18/18 | Network errors/lifecycle |
| Q5 | HTTP/3 budgets/transport limits/stall (1) | 0 | 0 | Full-stage 18/18; `test-quic-http3` | 70-KiB HEADERS app_bytes; timing-sensitive stall |
| Q6 | Budget init/app-bytes helper (1) | 0 | 0 | `test-quic-budget-init`, `test-quic-app-bytes` (304) | 304 |
| Q7 | Silent peer handshake timeout (1) | доказано | 1 | Full-stage/`r2o_http3_silent_udp_peer_timeout` (a63) | Нет ICMP/close-port вариантов |
| | **Итого QUIC/HTTP3** | | **2/10** | | |

### 6.5. Discord

| ID | Контракт (вес) | Статус | Балл | Покрытие сейчас | Пробел |
|---|---|---|---:|---|---|
| R1 | UDP observer initiator/SSRC/endpoint event (2) | 0 | 0 | `test-discord-udp-observer-reconnect` (304) | 304; production RTC |
| R2 | Manual measurement arm propagation (1) | 0 | 0 | `test-discord-voice-discovery-arm` (304) | 304 |
| R3 | Voice trial lease/renewal/120-s waiter/APPLIED (3) | 0 | 0 | `r2o-discord-discovery`, `r2o-discord-voice-lifecycle-helper` (304), `test-discord-scheduled-udp` (a63) | 304; production process/long RTC |
| R4 | Endpoint change/late NAK/persistence/reapply (1) | 0 | 0 | `r2o-discord-voice-lifecycle-helper` (304) | 304; source-backed helper |
| R5 | Trial clock after queue admission (1) | 0 | 0 | `test-discord-voice-trial-clock` (304) | 304 |
| R6 | Scheduled UDP emission/queue stats (1) | доказано | 1 | `test-discord-scheduled-udp-differential.sh` (a63) | Periodic/shutdown queue output |
| R7 | Long RTC session/process recovery (1) | 0 | 0 | Нет | Полный RTC, restart, endpoint recovery |
| R8 | Discord Gateway WebSocket upgrade/Hello (1) | доказано | 1 | `r2o-tls-verify-differential.sh` + `d2o_verify_differential` (a378), 14 сценариев | Loopback; не живой Gateway |
| | **Итого Discord** | | **2/11** | | |

### 6.6. Telegram / Meta DNS

| ID | Контракт (вес) | Статус | Балл | Покрытие сейчас | Пробел |
|---|---|---|---:|---|---|
| T1 | Telegram route plan/DNS exclusion (1) | 0 | 0 | `r2o-telegram-route-dns` (304, historical) | Не перезапущен; z2kOW donor, не C11 D2O |
| T2 | Telegram response observer (1) | 0 | 0 | `r2o-telegram-response-observer` (304, historical) | То же |
| T3 | Config/DC map/MTProto/WS retries/service lifecycle (2) | 0 | 0 | Source compare 38 files; `test-router-telegram-service.sh` (R2O-only) | Нет C/Rust behavior diff; CF/WS не проверены |
| T4 | Telegram firewall mark/stop order (1) | доказано | 1 | `test-router-tg-mark-differential.sh`, `test-telegram-stop-order-differential.sh` (8e2c) | Live router netfilter |
| T5 | Meta DNS scheduler lifecycle + range asset (1) | доказано | 1 | `test-router-meta-dns-scheduler-differential.sh`, `test-package-release.sh` | Live `ndmc`; scheduler restart |
| T6 | Direct DNS/TLS edge/owned-record removal (1) | доказано | 1 | `test-meta-edge-differential.sh`, `test-router-meta-dns-remove-differential.sh` (8e2c, CI #445) | Physical Keenetic |
| | **Итого Telegram/Meta** | | **3/7** | | |

### 6.7. WebPanel

| ID | Контракт (вес) | Статус | Балл | Покрытие сейчас | Пробел |
|---|---|---|---:|---|---|
| P1 | Bind selection/install safety (1) | 0 | 0 | `r2o-panel-bind-default`, `test-router-select-panel-ip`, `test-router-panel-bind-install` (304) | 304; physical router |
| P2 | Status unavailable/catalog token/size (1) | 0 | 0 | `test-panel-status-unavailable`, `test-panel-catalog-revision` (304) | 304 |
| P3 | Control/actions/workers/config/static/update (2) | 0 | 0 | 22 panel scripts (304; temp a378) | 304; checked-in pin; browser |
| P4 | Browser flow/layout (1) | 0 | 0 | `crates/r2o-panel/tests/browser.cjs` (R2O-only) | Нет C-oracle; только визуальная проверка |
| | **Итого WebPanel** | | **0/5** | | |

### 6.8. Firewall / PPE

| ID | Контракт (вес) | Статус | Балл | Покрытие сейчас | Пробел |
|---|---|---|---:|---|---|
| F1a | Static nft/iptables rule generation: port/DNS/voice order, broadcast/ICMP (1) | доказано | 1 | `test-firewall-port-scope`, `broadcast`, `rule-error`, `nft-legacy` (8e2c) | Live kernel; полный syntax/effect |
| F1b | Marks/gate/connbytes: MEASURE_MARK, D2K_GATE, CONNBYTES+1, Telegram mark (1) | доказано | 1 | `test-firewall-connbytes-boundary`, `iptables-status`, `test-router-tg-mark-differential` (8e2c) | Live kernel; fault branches |
| F2 | nft rollback/legacy cleanup/RST lifetime (1) | доказано | 1 | `test-firewall-nft-failure`, `nft-legacy`, `nft-down-rst-lifetime` (8e2c) | Live nft transaction |
| F3 | Rule install error code (1) | доказано | 1 | `test-firewall-rule-error-differential.sh` (8e2c) | Полная таблица правил |
| F4 | Flow-offload success/restore (1) | доказано | 1 | `test-router-flowoffload-d2o-differential.sh` (8e2c) | Live fw4/kernel |
| F5 | Flow-offload UCI write-failure (1) | доказано | 1 | Тот же скрипт (8e2c) | Один fixture на две строки |
| F6 | FastNAT lifecycle (1) | доказано | 1 | `test-router-fastnat-lifecycle-differential.sh` (a63) | Реальный sysctl/kernel |
| F7 | DNS upstream exclusions/refresh (1) | доказано | 1 | `test-router-dns-exclusion-differential.sh` (a63) | Live DNS/ndmc |
| F8 | Heal/watchdog/reapply/cooldown (1) | доказано | 1 | `test-router-reapply`, `heal-concurrency`, `firewall-watchdog`, `firewall-status`, `iptables-status` | Kernel; реальный watchdog crash |
| F9a | IPv6 fallback classification/modules/marker/reapply helper (1) | доказано | 1 | `test-router-ipv6-fallback-differential.sh` (a63), `route-gate-config` | Live kernel modules/NFQUEUE |
| F9b | IPv6 live kernel switch/queue recovery (1) | 0 | 0 | QEMU flow-offload only | Полный live module/queue/reapply |
| F10a | PPE rule generation/backend/cleanup/errors (1) | доказано | 1 | `test-router-ppe-rule-generation`, `backend`, `ensure-running`, `legacy-cleanup`, `firewall-lock`, `removal-error` (8e2c) | — |
| F10b | PPE hardware datapath/tag migration/restart (1) | 0 | 0 | — | Реальный PPE kernel, hardware tags, restart |
| | **Итого Firewall/PPE** | | **11/13** | | |

### 6.9. Release / ABI / Service

| ID | Контракт (вес) | Статус | Балл | Покрытие сейчас | Пробел |
|---|---|---|---:|---|---|
| L1 | Update guard current/download failure (1) | доказано | 1 | `test-router-update-availability`, `update-scheduler` (8e2c) | Mock downloads |
| L2a | Staging/signature/stop/activate/health/rollback (1) | доказано | 1 | `test-router-update-lifecycle`, `test-signed-install-rollback.sh`, manager tests | Mock downloads; field |
| L2b | OpenWrt procd/reboot/signed field install (1) | 0 | 0 | — | Всё |
| L3 | Package release manifest/asset bytes (1) | доказано | 1 | `test-package-release.sh`, meta-ranges bytes | Placeholder executables |
| L4a | Cross-build ABI + QEMU smoke 4 targets (1) | доказано | 1 | `r2o-build-openwrt-*`, ARMv5, D2O `make cross` | — |
| L4b | Runtime parity/load on target (1) | 0 | 0 | — | Runtime/физический роутер |
| L5 | Physical router/procd update/reboot (1) | 0 | 0 | — | Всё |
| | **Итого Release/ABI** | | **4/7** | | |

### 6.10. Ранее не учтённые production-модули

| ID | Контракт (вес) | Статус | Балл | Покрытие сейчас | Пробел |
|---|---|---|---:|---|---|
| M1 | `compose.c` + `d2kc.c` orchestration/event loop (3) | 0 | 0 | Inventory note; REA fragments | Нет отдельного контракта и differential |
| M2 | `d2kask.c` (1) | 0 | 0 | `r2o-ask-differential.sh` — независимые suites | Нет paired diff |
| M3 | `d2kfetch.c` CLI (1) | доказано | 1 | `r2o-fetch-cli-differential.sh` (сравнивает C/Rust CLI) | Нет SHA-пина; не все ветви |
| M4 | `d2kvoice.c` controller entry (1) | 0 | 0 | Discord rows частично | Нет контракта |
| M5 | `link.c`, `net4.c`, `udpruntime.c`, `volume.c` (3) | 0 | 0 | Inventory note; Rust `r2o_volume` tests | Нет C/Rust diff |
| M6 | `crypto.c`, `p256.c`, `x25519.c`, `props.c`, `udpplan.c`, `plantlv.c` helpers (3) | 0 | 0 | C unit tests; Rust units | Нет paired diff и контракта |
| M7 | `http80.c`, `http_trace.c`, `journal.c`, `plans.c`, `plan_parse/apply.c` (2) | 0 | 0 | C tests; Rust units | Нет matrix-контракта |
| | **Итого неучтённые модули** | | **1/14** | | |

---

## 7. Итоговые суммы и проценты

**Примечание 2026-11-08.** Независимая валидация добавила D20 (TCP shape contexts), D21 (datapath scheduler), D22 (journal), S11 (diagnostics), P5 (panel deadline/IO), F11 (router clear-found/policy/log), T7 (Telegram limits/stats), L6 (install/uninstall), Q8 (QUIC deny/recheck), C16 (detect CLI) и M8 (header-inline inventory), а также 61 header-inline функцию. Нормализация затем свела Panel A1–A26, Router B1–B54 и Telegram C1–C26 в единую матрицу: **172 контракта / 261 балл**, строгий **77/261 = 29,50 %**, carry с явно помеченными `304` — **140/261 = 53,64 %**. Таблицы ниже — исходное предложение до валидации и нормализации.

### (a) Текущая таблица как есть

- **80 / 89 = 89,89 %**.
- 57 контрактов; 50 «Э», 6 «Ч», 1 «Р», 0 «не проверено».
- Арифметика строк верна; ручная таблица областей и исторические записи — нет.

### (b) Пересчёт по предложенной декомпозиции, только доказанные пункты

Строгий режим (304-доказательства не засчитываются; helper/build/mock без runtime не дают полного балла):

| Граница | Вес | Баллы | Процент |
|---|---:|---:|---:|
| Только существующий scope (57 контрактов, декомпозированные) | 118 | 36 | **30,51 %** |
| Полная предложенная матрица (+ ранее неучтённые модули) | 132 | 37 | **28,03 %** |

Чувствительность (если всё-таки принять `304ba893` как допустимую ревизию, но не давать баллы за helper/build/mock без runtime):

| Граница | Вес | Баллы | Процент |
|---|---:|---:|---:|
| Существующий scope | 118 | 88 | 74,58 % |
| Полная матрица | 132 | 89 | 67,42 % |

Разница между 89,89 % и 30,51 % — не «регресс кода», а результат трёх эффектов:

1. **49 из 80 баллов** опираются только на `304ba893`, ещё 3 балла (L47) — на скрипты без фиксированной SHA-ревизии; ни те, ни другие не являются текущим доказательством относительно `a63d964`/`a378e23`/`8e2c981`.
2. Несколько широких строк (IPv6, TCP, classifier, QUIC, Discord, Telegram, firewall, update, ABI) при декомпозиции дают больше проверяемых ветвей, поэтому знаменатель растёт с 89 до 118/132.
3. Часть текущих баллов держится на helper/fixture/mock/build evidence, которые не доказывают production-поведение.

Даже в мягком варианте с принятием `304ba893` полная матрица даёт **67,42 %**, а не 89,89 %: добавление неучтённых модулей и честное разбиение широких пунктов снижает оценку.

---

## 8. Приоритетные действия

1. **Зафиксировать одну ревизию C-эталона** и либо перевести все скрипты на неё, либо явно разделить «исторические» и «текущие» доказательства. Сейчас 28 строк/49 баллов висят на `304ba893`, ещё L47 (3 балла) — на скриптах без SHA-пина.
2. **Убрать из текущей таблицы широкие строки** L24, L21, L33, L47, L48, L52, L54, L58–L60, L66, L71, L75, L76 и заменить их предложенными контрактами.
3. **Устранить дубли**: L42/L57, L66/L70, L67/L68, L54/L55, L33/L30–L32, L45/L39, L58/L59/L60.
4. **Пересчитать pacing:** ручная таблица областей должна генерироваться из `progress.json`, иначе Datapath/Discovery будут расходиться на 1/1.
5. **Удалить устаревшие абзацы** «87-point matrix», «всего 87 баллов», «46 строк/63/87» и исправить счётчик статусов в строке 94.
6. **Добавить контракты или явно исключить** `compose`, `d2kask`, `d2kfetch`, `d2kvoice`, `link`, `net4`, `plantlv`, `udpruntime`, `volume`, `crypto`, `p256`, `x25519`, `props`, `udpplan`, `d2kc`; сейчас они либо не покрыты, либо покрыты только примечанием inventory.
7. **Для L48, L58, L59, L22** либо получить прямой paired differential, либо поставить 0. REA/source mapping и независимые test suites не являются доказательством паритета.
8. **Для L66** либо найти запись о closure после #164, либо снять балл; для L65/L73 — перестать полагаться на временные копии с заменой SHA и обновить checked-in пины.
