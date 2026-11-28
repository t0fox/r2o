# Quickstart: проверка будущей реализации RAW default-on

Команды выполняются на ПК из корня checkout. Этот файл — инструкция приёмки;
он не утверждает, что перечисленные проверки уже выполнены.

## 1. Выбор этапа и baseline

```sh
export SPECIFY_FEATURE_DIRECTORY="$PWD/specs/001-raw-tcp-default"
bash .specify/scripts/bash/check-prerequisites.sh --json --require-spec --require-tasks --include-tasks
git rev-parse HEAD
git status --short
```

Перед правками сверить текущий `origin/main` и `research.md`. Зафиксировать SHA,
версии kernel/toolchain, платформу, режим, конфиг без секретов, каталог и сценарий
нагрузки в `acceptance.md`. Для A/B использовать одинаковые endpoints, workload,
прогрев и исходный каталог; cold и reuse не смешивать.

## 2. Целевые проверки

Нужны host Rust toolchain текущего CI, Bash, Python 3 и OpenSSL с Ed25519.
Для подписанной установки/отката нужны все шесть host release binaries
(`datapath`, `controller`, `panel`, `telegram`, `manager`, `fetch`); собираем их
на ПК в стандартный `target/release`. При другом каталоге передать `R2O_RELEASE_BIN`.

```sh
cargo build --release --workspace --bins
cargo test -p r2k-core raw_flow
cargo test -p r2o-datapath raw_discovery
cargo test -p r2o-controller --test raw_endpoint_discovery
bash scripts/test-router-openwrt-init.sh
sh scripts/test-signed-install-rollback.sh
```

Донорский `scripts/test-router-config-defaults-differential.sh` дополнительно требует
`R2O_DONOR_ROOT`, указывающий на локальный D2O checkout ровно
`a378e230947ebfd011439e1cac0f1e994d883aae`. При доступном checkout запустить его
через `sh` с этой переменной; иначе отметить внешнюю регрессию недоступной.
Матрицу нового RAW default проверить самостоятельным тестом T003 без зависимости
от донора и добавить фактическую команду сюда. Донорский тест её не заменяет.

Это существующие точки входа. В рамках реализации расширить их или добавить узкие
тесты по tasks.md; запуск неизменённых тестов не доказывает новые случаи. В отчёте
проверить фактическое число выполненных тестов, чтобы фильтр не дал ложный зелёный
результат с нулём случаев.

Матрица: unset/empty/0/1/invalid; launcher и прямой запуск обоих бинарников;
чистая установка, старый конфиг без ключа, update с явным `0`, restart/rollback;
применяющий/наблюдающий режим и неподдерживаемый control version.
Ожидания — [runtime.md](contracts/runtime.md).

Проверить UDP saturation и освобождение RAW-слотов; известные/частичные handshakes;
full/partial/stale ACK, RST, timeout, отмену, смену поколения и неуспешную отправку.
Проверить несовпадающие порт/семейство/profile и перепись каталога старым controller.

## 3. Живой Linux NFQUEUE

Нужны Linux с network namespaces/NFQUEUE, права управления тестовой сетью,
действующие зависимости из job `ci.yml`; тест запускается в изолированном стенде.

```sh
sh scripts/test-raw-discovery-nfq.sh
```

До изменения smoke принудительно задаёт RAW=1 и проверяет IPv4. Исполнитель MUST
доработать тест для default-on и IPv6. Если для IPv6 выбран отдельный script,
добавить его команду сюда и в соответствующий CI job.

Проверить холодный полный обмен тестового клиента, transport evidence, точную запись
в каталог и повтор после перезапуска. Отдельно запустить explicit-0/1. Клиентский
application exchange проверяется тестом независимо от transport-статуса R2O.

## 4. Платформы и 10-минутная полевая сессия

ARM64/MIPSEL собирать на ПК существующими build scripts/CI matrix. Сверять target,
ABI и runtime версии, включая Keenetic/Entware и OpenWrt; инструкции и зависимости
есть в [.github/workflows/ci.yml](../../.github/workflows/ci.yml) и
[QEMU guide](../../scripts/qemu-platform/README.md).

На доступном устройстве использовать уже разрешённый способ доступа. Секреты не
добавлять в репозиторий. Перед заменой сохранить бинарники, config и catalog.
Сборку на роутере не выполнять.

Для baseline и candidate провести по 10 минут одного клиентского сценария:
обычный распознанный трафик, холодный RAW, reuse после рестарта и смешанная UDP/TCP
нагрузка. Снимать CPU, текущую/пиковую RSS обоих процессов существующими лёгкими
средствами, время до результата, число проб, обрывы и падения. Записать частоту
семплирования; sampled peak отличается от lifetime peak, если доступен только один.
Сравнить stripped release binaries одинакового target/profile. Не обещать ускорение
по одному удачному соединению.

Проверить `R2O_RAW_DISCOVERY=0` + restart и полный `update-rollback`. При восстановлении
конфига/каталога сервис остановлен; результат не теряет точность старых привязок.
Если физического устройства нет, записать «не выполнено» и сохранить этот пункт
открытым. Не считать QEMU физической приёмкой.

## 5. Завершение

```sh
python3 -B scripts/release_notes.py check
python3 -B scripts/test-release-notes.py
python3 -B scripts/test-release-changelog.py
```

В `acceptance.md`: SHA baseline/candidate, что изменено, команды/выходы, матрица
FR/SC, pass/fail/unavailable, результаты A/B и восстановление. Только после
проверок обновить статус этапа. Переход к 002, публикация и выпуск — отдельные действия.
