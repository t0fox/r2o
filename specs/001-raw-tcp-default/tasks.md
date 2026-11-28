# Tasks: RAW TCP Discovery по умолчанию

**Input**: [spec.md](spec.md), [plan.md](plan.md), [research.md](research.md),
[data-model.md](data-model.md), [runtime contract](contracts/runtime.md).

**Status**: Все задачи открыты. Это план следующего задания, не журнал выполненных работ.

**Tests**: Целевые регрессии и живой обмен требуются spec. Существующие корректные
тесты переиспользовать; не переписывать их ради нового названия. Вновь добавленный
тест нового default сначала должен воспроизвести отсутствие поведения на baseline.

## Phase 1: Setup

- [ ] T001 Сверить свежий `main` и состояние checkout с `research.md`, обновить факты при изменениях; создать `specs/001-raw-tcp-default/acceptance.md` с SHA baseline, матрицей FR/SC и открытыми полевыми проверками.

## Phase 2: Foundational

- [ ] T002 Зафиксировать baseline defaults, ёмкость и proof на текущих `router/S99r2o`, `crates/r2k-core/src/raw_flow.rs`, `crates/r2o-datapath/src/raw_discovery.rs`; записать команды и результаты в `specs/001-raw-tcp-default/acceptance.md`, не менять протокол или scope.

## Phase 3: US1 — обычная установка включает RAW (P1)

**Goal**: Одинаковые defaults в launcher/бинарниках; явный opt-out сохраняется.

**Independent Test**: Матрица unset/empty/0/1/invalid, install/update/restart,
режимы и фактическая доступность из runtime contract.

- [ ] T003 [US1] Дополнить тесты настройки в `crates/r2k-core/src/raw_flow.rs` и подходящие service/install тесты рядом с `scripts/test-router-config-defaults-differential.sh`; покрыть старый конфиг без ключа, явное `0` и прямой запуск обоих бинарников. Не менять донорские эталоны ради нового default. (FR-001, FR-002, SC-001)
- [ ] T004 [US1] Согласовать семантику default-on в `crates/r2k-core/src/raw_flow.rs`, `router/S99r2o` и `router/config.default`, сохранив конфиг владельца; реализовать ограничения **RawSetting.value** из `data-model.md`. (FR-001, FR-002)
- [ ] T005 [US1] Проверить enable/capability gates в `crates/r2o-controller/src/main.rs` и `crates/r2o-datapath/src/main.rs`, добавить недостающее отображение в существующую диагностику без нового loop; реализовать **RawSetting.active** и **RawSetting.reason** из `data-model.md`. (FR-003, FR-008)

**Checkpoint**: Обычный старт даёт RAW TCP, explicit-0 и неподдерживаемые режимы
отличимы; запускается существующий путь Discovery.

## Phase 4: US2 — ограниченные затраты и смешанная нагрузка (P1)

**Goal**: Незавершённые UDP-наблюдения не лишают TCP всей ёмкости.

**Independent Test**: UDP saturation + TCP-повтор, churn/expiry, распознанный
и частичный известный handshake.

- [ ] T006 [US2] Добавить недостающие saturation/expiry и протокольные регрессии в `crates/r2o-datapath/src/raw_discovery.rs` и/или `crates/r2o-controller/tests/raw_endpoint_discovery.rs`; доказать доступность TCP и сохранение известных/частичных handshakes. (FR-004, FR-005, FR-008, SC-003)
- [ ] T007 [US2] Устранить UDP starvation в `crates/r2o-datapath/src/raw_discovery.rs` и точке вызова `crates/r2o-datapath/src/main.rs` по plan.md; сохранить **RawTrial.limits** из `data-model.md`, без увеличения общего пула и без активного UDP-синтеза. (FR-004, FR-005)

**Checkpoint**: Смешанный трафик не вытесняет весь RAW TCP; state остаётся ограниченным.

## Phase 5: US3 — точный reuse и честное доказательство (P2)

**Goal**: Default-on не ослабляет корреляцию, scope или откат.

**Independent Test**: Cold/restart/reuse, endpoint/profile mismatch, негативные ACK,
перепись каталога старым controller и отключение RAW.

- [ ] T008 [US3] Запустить и дополнить только недостающие proof/scope/downgrade сценарии в `crates/r2o-controller/tests/raw_endpoint_discovery.rs` и `crates/r2o-controller/tests/catalog.rs`; проверить partial/stale ACK, generation, RST, timeout, отмену и потерю обязательного RAW profile. (FR-006, FR-007, SC-003)
- [ ] T009 [US3] Сохранить текущую реализацию `crates/r2o-datapath/src/raw_discovery.rs`, `crates/r2o-controller/src/raw_discovery.rs` и `catalog.rs`; исправлять только выявленные регрессии, соблюдая **RawTrial.identity**, **RawTrial.evidence**, **RawBinding.scope**, **RawBinding.proof** из `data-model.md`. Не создавать пустой code diff при успешной проверке. (FR-006, FR-007)
- [ ] T010 [US3] Доработать `scripts/test-raw-discovery-nfq.sh` и сетевой job `.github/workflows/ci.yml`: default без принудительного `1`, отдельные explicit-0/1, IPv4/IPv6, полный обмен клиента и reuse после рестарта. При выделении IPv6 script обновить `quickstart.md`. (FR-001, FR-006, FR-007, SC-002)

## Phase 6: Acceptance and Documentation

- [ ] T011 Собрать controller/datapath для ARM64 и MIPSEL существующими build scripts/CI на ПК; выполнить целевые тесты и installation/update/rollback сценарии из `quickstart.md`, записать target/ABI и фактические результаты в `specs/001-raw-tcp-default/acceptance.md`. (SC-001, SC-002, SC-003)
- [ ] T012 Провести сопоставимые baseline/candidate клиентские сессии по 10 минут на доступном роутере по `quickstart.md`; записать cold/reuse, число проб, CPU, RSS/peak, stripped binary sizes и восстановление в `specs/001-raw-tcp-default/acceptance.md`. При отсутствии устройства оставить задачу открытой с причиной. (SC-004)
- [ ] T013 Обновить `router/README.md` по фактическому поведению и добавить `.changes/raw-tcp-default.json` в тот же коммит, что код, по `AGENTS.md`; выполнить три release-note проверки. Описать transport-only, не обещать неподтверждённую работу или экономию памяти. (FR-001, FR-002, FR-006)
- [ ] T014 Сверить итоговый diff с `spec.md`, constitution и `acceptance.md`; закрыть только выполненные задачи, записать отклонения и статус в `specs/README.md`. Не начинать 002/003 и не выпускать результат этим заданием.

## Dependencies & Execution Order

T001 → T002 → US1 → US2 → US3 → приёмка. T003 предшествует T004/T005;
T006 предшествует T007; T008 предшествует возможным исправлениям T009 и T010.
T011 проверяет совокупный candidate; T012 требует готовых бинарников и рабочего
отката. T013 выполняется до code commit; T014 учитывает незакрытые проверки.

Каждый US имеет отдельный проверяемый результат. US2/US3 можно исследовать на
существующем opt-in baseline независимо, но default-on интегрируется последовательно,
поскольку main.rs и raw_discovery.rs общие. Ошибки одного US не скрываются успехом другого.

## Parallel Opportunities

У задач нет `[P]`: основные правки пересекаются по файлам. После фиксации candidate
ARM64/MIPSEL сборки T011 и read-only ревью документов могут идти параллельно.
У US1/US2/US3 независимы обзоры тестовых сценариев, но не одновременные правки
общих модулей или сетевые тесты в одной среде.

## Implementation Strategy

Минимальный полезный результат — US1 с действующими guards; выпуск default-on требует
также US2/US3 и явного отчёта о приёмке. Сначала устранить реальные расхождения,
потом измерить. Никаких новых таблиц обучения, формул рейтинга или recipes в этом diff.

## Coverage

| Requirement | Tasks |
| --- | --- |
| FR-001 | T003, T004, T010, T013 |
| FR-002 | T003, T004, T013 |
| FR-003 | T005 |
| FR-004 | T006, T007 |
| FR-005 | T006, T007, T012 |
| FR-006 | T008, T009, T010, T013 |
| FR-007 | T008, T009, T010 |
| FR-008 | T005, T006 |
| SC-001 | T003, T011 |
| SC-002 | T010, T011 |
| SC-003 | T006, T008, T011 |
| SC-004 | T012 |
