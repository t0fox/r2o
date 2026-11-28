# Implementation Plan: RAW TCP по умолчанию

**Branch**: `docs/spec-kit-discovery` | **Date**: 2026-11-28 | **Spec**: [spec.md](spec.md)

**Input**: `specs/001-raw-tcp-default/spec.md`

**Status**: План для следующего задания реализации. В этом коммите меняются только
документы и инструменты разработки.

## Summary

Согласовать default-on в launcher и общем Rust helper, сохранить явный opt-out
и существующие capability/apply/Discovery ограничения. Изолировать незавершённые
UDP-наблюдения от доступности TCP. Повторно проверить точные привязки, корреляцию
ACK, холодный обмен и reuse без принудительного `R2O_RAW_DISCOVERY=1` в тесте.
Алгоритм RAW-кандидата, уровень доказательства и формат разрешений не расширяются.

## Technical Context

**Language/Version**: Rust edition 2024 из текущих Cargo.toml; shell launcher.
Использовать действующий toolchain CI и Cargo.lock, не обновлять зависимости ради этапа.

**Primary Dependencies**: Существующие r2k-core, r2o-controller, r2o-datapath,
NFQUEUE/control V48, router service scripts. Новых runtime dependencies нет.

**Storage**: Существующий `catalog.json`; новая база данных и новый wire version не нужны.

**Testing**: Cargo targeted tests, действующие shell installation/lifecycle tests,
живой Linux NFQUEUE IPv4/IPv6, QEMU ARM64/MIPSEL, отдельная физическая приёмка.

**Target Platform**: Keenetic и OpenWrt/ImmortalWrt; ARM64/MIPSEL обязательны.

**Project Type**: Существующая система router services и Rust workspace.

**Performance Goals**: Default-on без регрессии распознанного трафика; сохранить
численные границы RAW из [data-model.md](data-model.md). Измерить разницу CPU/RSS,
cold/reuse и числа проб относительно baseline в одинаковых условиях.

**Constraints**: Сборки на ПК. Без нового daemon, фоновых проб, UI-переключателя,
обучающего рейтинга, UDP-синтеза или переноса recipes в этом этапе.

**Scale/Scope**: Один независимый этап; исходный baseline —
`3b40fe97d8232947bc6556abe5f92947e4deec2b`, факты в [research.md](research.md).

## Constitution Check

| Правило | Решение плана | Проверка |
| --- | --- | --- |
| I — доказательство | ACK остаётся transport-only; прикладной клиент тестируется отдельно | Корреляционные негативные сценарии + живой обмен |
| II — scope | endpoint/profile и downgrade guard сохраняются | Cold/reuse/mismatch/перепись старым контроллером |
| III — существующий конвейер | Правки defaults и ёмкости в действующих модулях | Diff не добавляет второй путь Discovery |
| IV — ограниченные затраты | Сохранить лимиты и bounded причины состояния | Saturation/churn + CPU/RSS A/B |
| V — контекст | Не менять policy routing/RPDB в этом этапе | Нет новых route gates и per-packet запросов |

На стадии проектирования нарушения не найдены. Этот вывод не является прохождением
runtime-приёмки; после реализации таблица сверяется с diff и результатами.

## Project Structure

### Documentation (this feature)

В этом каталоге: `spec.md`, `research.md`, `plan.md`, `data-model.md`,
`contracts/runtime.md`, `quickstart.md`, `tasks.md`, `checklists/requirements.md`.
Результаты реализации позднее записываются в `acceptance.md` с точными SHA и командами.

### Source Code (repository root)

| Путь | Назначение возможной правки |
| --- | --- |
| `router/S99r2o`, `router/config.default` | Default/комментарий и сохранение явного выбора |
| `crates/r2k-core/src/raw_flow.rs` | Единое толкование настройки |
| `crates/r2o-controller/src/main.rs`, `crates/r2o-datapath/src/main.rs` | Фактические gates и лёгкий статус, без нового loop |
| `crates/r2o-datapath/src/raw_discovery.rs` | UDP/TCP ёмкость и существующая корреляция |
| `crates/r2o-controller/src/raw_discovery.rs`, `catalog.rs` | Сохранение/reuse; менять только при выявленной регрессии |
| `crates/r2o-controller/tests/raw_endpoint_discovery.rs` | Целевые регрессии доказательств и scope |
| `scripts/test-raw-discovery-nfq.sh`, `.github/workflows/ci.yml` | Default-on живой обмен обоих семейств |
| `scripts/test-router-config-defaults-differential.sh`, `scripts/test-router-openwrt-init.sh`, `scripts/test-signed-install-rollback.sh` | Настройки, установка/обновление и восстановление |

**Structure Decision**: Использовать существующие модули. Допустим узкий новый
тестовый файл рядом с действующими тестами, если старый тест привязан к донорским
defaults; не менять эталон донора ради прохождения нового контракта.

## Design Decisions

1. Применить таблицу настройки из [runtime contract](contracts/runtime.md).
   Единая семантика обязательна; конкретную factoring-функцию выбирает исполнитель.
2. Предпочтительный минимальный вариант — не создавать незавершённые UDP-наблюдения
   в обычном RAW TCP пути. Резервирование TCP-ёмкости также допустимо, если общий
   предел работы не увеличен и это подтверждено тестом. Не вводить дополнительный
   пользовательский флаг, чтобы обойти этот выбор.
3. Использовать существующие health/diagnostics для фактического enable/reason,
   без регулярных внешних команд. Ограниченные причины описаны в data-model.
4. Оставить существующие корреляцию, RAW split, exact bindings и downgrade guard.
   Не улучшать протокол доказательства одновременно со сменой defaults.

## Validation and Completion

Порядок и команды — [quickstart.md](quickstart.md); задачи — [tasks.md](tasks.md).
Сначала воспроизвести baseline defaults, затем проверить матрицу настроек и
обе стороны запуска. После этого — saturation, proof/reuse, живой IPv4/IPv6,
платформенные сборки и полевая сессия.

Подготовка спецификаций заканчивается до реализации. Следующий этап 002 не
реализуется этим планом. Отчёт MUST разделять пройденные/проваленные/недоступные
проверки; недоступное устройство оставляет полевую приёмку открытой.

## Complexity Tracking

Отклонений от конституции и дополнительных runtime-компонентов нет.
