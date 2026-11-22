# r2o-manager

Менеджер проверяет подпись Ed25519 над точными байтами `latest.json`, проверяет
описание выпуска, выбирает архитектуру и вычисляет SHA-256 архива при чтении.
Команда ручной проверки принимает открытый ключ размером 32 байта, строку
шестнадцатеричных цифр длиной 64 символа или файл PEM с SubjectPublicKeyInfo.

```sh
r2o-manager verify-release \
  --manifest latest.json \
  --signature latest.json.sig \
  --public-key release-public.pem \
  --architecture mipsel \
  --archive r2o-mipsel.tar.gz
```

Для OpenWrt MIPS32r2 с musl передайте `--architecture mipsel-openwrt-musl` и
архив `r2o-mipsel-openwrt-musl.tar.gz`. Подписанный манифест содержит отдельную
запись для каждого ABI; менеджер проверяет выбранную запись и имя бинарника.

Для OpenWrt ARMv7 hard-float musl используйте `--architecture armv7-openwrt-musl`
и архив `r2o-armv7-openwrt-musl.tar.gz`. Менеджер выбирает для проверки запись
архитектуры из манифеста выпуска.

При успехе выводится JSON с полями `verified`, идентификатором выпуска,
версией, архитектурой и контрольной суммой архива. При ошибке команда
завершается с ненулевым кодом и не выводит запись об успехе. Переданный
открытый ключ должен быть доверенным.

Формат манифеста соответствует выпускам r2o:

```json
{"release_id":"r2o-20261018","version":"0.1.0","notes":"","assets":{"mipsel":{"sha256":"<64 lowercase hex characters>"},"mipsel-openwrt-musl":{"sha256":"<64 lowercase hex characters>"},"armv7-openwrt-musl":{"sha256":"<64 lowercase hex characters>"}}}
```

Неизвестные и повторяющиеся поля, небезопасные идентификаторы, неверные
контрольные суммы, неизвестные архитектуры, ошибочные подписи и несовпадение
архива приводят к отказу.

## Локальная установка и откат

`install-archive` связывает проверку выпуска с его активацией. Архив копируется
в закрытый временный каталог, затем проверяются подпись и хеш. При распаковке
отклоняются выход за пределы каталога, ссылки и специальные файлы. После этого
активный слот атомарно переключается:

```sh
r2o-manager install-archive --root /opt/r2o \
  --archive r2o-mipsel.tar.gz \
  --manifest latest.json \
  --signature latest.json.sig \
  --public-key release-public.pem \
  --architecture mipsel
```

## Обновление через сеть

Менеджер читает подписанный каталог стабильных выпусков GitHub Releases.
Ручная установка принимает тег из каталога и выбранный источник. По умолчанию
архив загружается через самый быстрый доступный маршрут. Все источники
проверяются одним закреплённым ключом Ed25519 и подписанным SHA-256.

```sh
r2o-manager update-check --root /opt/r2o
r2o-manager update-install --root /opt/r2o
r2o-manager update-install --root /opt/r2o --release TAG --source github
r2o-manager update-rollback --root /opt/r2o
r2o-manager update-cancel --root /opt/r2o
r2o-manager update-recover --root /opt/r2o
```

Панель запускает менеджер отдельным процессом. Менеджер оставляет службы
работать до проверки и подготовки архива, переключает слоты и фиксирует
установку после проверки готовности. OpenWrt и Keenetic запускают, останавливают
и проверяют службы через штатный адаптер `S99r2o`. Журнал позволяет вернуть
прошлый слот независимо от состояния панели.

Поддерживаемые выпуски используют общий формат конфигурации и обученного
каталога. При несовместимости новая версия отклоняется до активации.
Для прежнего формата нужна чистая установка базового выпуска.

`install-local` копирует уже распакованный пакет в `ROOT/releases/RELEASE_ID`,
атомарно обновляет `ROOT/release-slots` и заменяет стабильный исполняемый файл
`ROOT/r2o-manager`. Пакет должен содержать исполняемые файлы
`builds/{r2o-datapath,r2o-controller,r2o-panel,r2o-telegram,r2o-manager,r2o-fetch}-linux-ARCH`.
Ссылки и специальные файлы отклоняются. Менеджер сериализует установку и откат
межпроцессной блокировкой. Каталог `config` и другие файлы за пределами
`releases/` не затрагиваются.

```sh
r2o-manager install-local --root /opt/r2o \
  --bundle /tmp/r2o-release --release-id r2o-20261018 --architecture mipsel
r2o-manager rollback --root /opt/r2o
```

`install-local` предназначен для пакета, которому доверяет местный оператор;
проверка подписи выпуска при этом пропускается. `router/install.sh` выполняет
аналогичную начальную установку автономного пакета.

При первой установке `config-init` создаёт `ROOT/config` из `config.default`.
Если передан `--donor-config`, совместимые параметры переносятся как данные,
без выполнения кода оболочки. Путь состояния донора под `/opt/d2k` или `/opt/d2o`
переносится под `/opt/r2o`; режим Telegram `relay` становится локальным режимом
`r2o-telegram`. `FLOWS` переносится в `R2O_FLOW_CAPACITY` для общего ограничения
таблиц TCP/UDP datapath. Неподдерживаемые ключи возвращаются в поле `unsupported`, а
существующий `ROOT/config` никогда не перезаписывается.
Ответ также содержит проверенные `state_dir` и `donor_state_dir`; установщик
использует эти поля для переноса каталога состояния, не выполняя конфигурацию.

Стабильная команда менеджера запускает компонент из активного слота без
изменяемой символической ссылки:

```sh
/opt/r2o/r2o-manager exec --root /opt/r2o --component r2o-datapath -- --queue 2000
```
