# Research: исходное состояние и решения

**Дата**: 2026-11-28. **Проверенная база**:
[`3b40fe97d8232947bc6556abe5f92947e4deec2b`](https://github.com/t0fox/r2o/commit/3b40fe97d8232947bc6556abe5f92947e4deec2b).
Это анализ исходников. Runtime-тесты, cross-build и физическая приёмка при подготовке
этих документов не выполнялись. Перед реализацией повторно проверить head.

**Повторная сверка**: база реализации — `19de516fb0b6c21722f4e1c244925307bf5c8f65`.
Три исходных ограничения подтверждены. Между базами добавлены
`Components.raw_trials` и отдельные состояния datapath в отчёте. Реализация
использует эти же снимки. Выбран один слот для пассивного UDP внутри
существующего общего пула из четырёх записей.

## Проверенные факты

| Факт | Первичный источник |
| --- | --- |
| `S99r2o` сначала читает конфиг, затем использует `${R2O_RAW_DISCOVERY:-0}`. В template config ключ RAW отсутствует. | [launcher](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/router/S99r2o#L77-L80), [config](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/router/config.default) |
| Общий `enabled()` принимает только точное `1`. Лимиты: 4 записи, 16–1460 байт, lease 12 с, cooldown 60 с. | [raw_flow.rs](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2k-core/src/raw_flow.rs#L13-L22) |
| Datapath требует enabled + V48 + Apply. Controller дополнительно зависит от созданного Discovery. | [datapath](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2o-datapath/src/main.rs#L1847-L1854), [controller](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2o-controller/src/main.rs#L29985-L29999) |
| UDP-наблюдения делят с TCP `MAX_ACTIVE`; суммарная заполненность может не допустить TCP. | [raw_discovery.rs](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2o-datapath/src/raw_discovery.rs#L294-L304) |
| RAW использует один measured split, точный endpoint/profile и transport evidence `verified_by=8`. ACK требует корреляции с исполнением и более поздней kernel timestamp. | [controller RAW](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2o-controller/src/raw_discovery.rs#L12-L109), [ACK](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2o-datapath/src/raw_discovery.rs#L203-L231) |
| Потерявшая `raw_profile` RAW-привязка отбрасывается, а не расширяется. | [catalog](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2o-controller/src/catalog.rs#L436-L443) |
| Живой smoke — IPv4; обоим процессам явно задаёт RAW=1. Проверяет прикладной обмен и reuse после рестарта, но не default-on. | [smoke](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/scripts/test-raw-discovery-nfq.sh#L97-L193) |

## Что уже реализовано для следующих этапов

- Prepared own-first batches уже есть; рейтинг использует lead/tier/successes/freshness,
  но не полную стоимость и знаменатель всех попыток:
  [discovery.rs](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2o-controller/src/discovery.rs#L799-L808).
- Ограниченная отрицательная история уже существует:
  [groups.rs](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2o-controller/src/groups.rs#L4-L13).
  Ошибочно заявлять, что обучение начинается с нуля.
- В текущих DiscoveryTarget/Binding/GroupKey нет отдельного WAN/policy generation:
  [target](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2o-controller/src/discovery.rs#L18-L27),
  [catalog entities](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2o-controller/src/catalog.rs#L186-L244).
- Measured forward/reverse/mixed TCP-order уже реализован:
  [tcp_order.rs](https://github.com/t0fox/r2o/blob/3b40fe97d8232947bc6556abe5f92947e4deec2b/crates/r2o-controller/src/tcp_order.rs#L26-L152).
  Перенос рецепта требует свежей инстанциации, а не повторной реализации этих вариантов.

## Решения

### D1. Единая семантика default-on

**Decision**: Отсутствие/пустая строка означает default-on; `0`/`1` сохраняют смысл;
остальные значения отключают RAW с ограниченной причиной `invalid-config`.
**Rationale**: Обычная установка работает сразу, явный выбор не теряется, ошибка
настройки не включает функцию неожиданно. Пустое значение согласовано с shell `:-`.
**Alternatives considered**: Только изменить config.default недостаточно для старых
конфигов и прямого запуска; считать любую строку кроме `0` включением меняет смысл ошибок.

### D2. Минимальная изоляция UDP

**Decision**: Устранить конкуренцию незавершённых UDP-наблюдений со всей TCP-ёмкостью.
Предпочесть отключение их создания в обычном TCP-пути; допустима bounded reservation.
**Rationale**: UDP пока не даёт подтверждённого плана. Завершение UDP не требуется
для полезной TCP-функции. **Alternatives considered**: Увеличение общего пула скрывает
голодание и повышает расход памяти; завершение UDP расширяет этап.

### D3. Сохранить доказательства и существующие возможности

**Decision**: Не менять RAW scope/wire и ACK-верификацию; проверить их регрессиями.
**Rationale**: Значение по умолчанию не разрешает ослаблять proof.
**Alternatives considered**: Считать ACK прикладным успехом некорректно; расширять
привязки по общему рецепту без проверки противоречит конституции.

### D4. Проверять именно новый default

**Decision**: Живой тест должен запускать обычный сценарий без принудительного `1`,
с отдельными explicit-0/1 и IPv6 случаями; измерения cold/reuse/CPU/RSS разделены.
**Rationale**: Старый тест доказывает работу opt-in, но не установку default-on.
**Alternatives considered**: Смена только changelog либо успешная компиляция не
проверяют пользовательское поведение.

## Открытые доказательства

Неизвестны фактические результаты будущего default-on diff на ARM64/MIPSEL,
Linux IPv6 и физическом устройстве. Это задачи приёмки, а не неизвестная архитектура.
Текущие пределы не повышаются. Численные CPU/RSS результаты публикуются после A/B;
теоретические 32 КиБ таблицы не являются замером RSS и здесь не используются.
