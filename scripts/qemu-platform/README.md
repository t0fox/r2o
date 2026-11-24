# Программная приёмка роутера в QEMU

Сценарий устанавливает локальный пакет штатным `router/install.sh`, проверяет его удаление, ставит опубликованный пакет и повторяет установку кандидата после `update-stop`. После загрузки того же диска гостевой менеджер служб запускает R2O автоматически. LAN-клиент проверяет TCP/443, UDP/443 и ответ DNS/53 с полезной нагрузкой по IPv4 и IPv6. На OpenWrt отдельный запрос проходит через системный dnsmasq.

Сценарий стабильности длится 600 секунд по часам гостя. На Malta TCG это может занять больше десяти минут на хосте. Примерно каждые 30 секунд он проверяет оба процесса, RSS, PSS, CPU, файловые дескрипторы, обе NFQUEUE и шесть прикладных ответов. `soak-report.py` агрегирует serial-журналы успешных прогонов. Отключены интерфейс R2O, Telegram и сетевые автообновления. Гости запускаются с `-nic none`.

## Подготовка

Нужны QEMU, Python 3, e2fsprogs и компилятор для тестового `probe.c`. Все они работают вне production-сборки R2O. Используйте проверенный архив опубликованного выпуска и распакованный штатный пакет кандидата. Подпись манифеста выпуска проверяется ключом из `crates/r2o-manager/release-public.pem`, хеш файла берётся из этого манифеста. Для закрытого локального пакета используются его локальный манифест и SHA‑256; сценарий не обращается к каналу публикации.

```sh
openssl pkeyutl -verify -pubin -inkey crates/r2o-manager/release-public.pem \
  -rawin -in published/latest.json -sigfile published/latest.json.sig
zig cc -target mipsel-linux-musleabi -mcpu=mips32r2+soft_float -static -Os \
  scripts/qemu-platform/probe.c -o probe-mipsel
zig cc -target x86_64-linux-musl -static -Os scripts/qemu-platform/probe.c -o probe-x86_64
```

Архив `r2o-qemu-platform-seeds.tar.gz` содержит готовые ядра, начальные файловые системы, пакеты стенда и тестовые клиенты. Перед запуском распакуйте его в отдельный каталог и выполните там `sha256sum -c SHA256SUMS`. Пути в командах ниже указывают на файлы из `keenetic/` или `openwrt/` этого архива. Оригинальные SquashFS Keenetic загружаются отдельно.

## Keenetic Viva и Hopper

Используйте `keenetic49-virt-ppe.elf`, `initramfs.gz` и подготовленное дерево Entware из утверждённого стенда Keenetic. Дерево содержит `bin/opkg`, `bin/busybox-bootstrap`, `feed/`, `lab/opkg.conf` и `lab/xtables-legacy-multi`. Точные исходники и сборка ядра приводятся в `sources.md` архива стенда. `prepare-rootfs.py` извлекает SquashFS из оригинальной прошивки модели и проверяет хеш.

```sh
python3 scripts/qemu-platform/prepare-rootfs.py KN-1910 KN-1910.squashfs
scripts/qemu-platform/stage-opt.sh keenetic viva-test.img ./probe-mipsel \
  ./candidate-mipsel r2o-lab-candidate ./published/r2o-mipsel.tar.gz "$PUBLISHED_TAG" ./entware-base
for phase in install reboot; do
  python3 scripts/qemu-platform/run-keenetic.py KN-1910 \
    --qemu qemu-system-mipsel --qemu-data /usr/share/qemu \
    --kernel keenetic49-virt-ppe.elf --initramfs initramfs.gz \
    --firmware-rootfs KN-1910.squashfs --opt viva-test.img --usb-opt --entropy \
    --phase "$phase" --log "viva-$phase.log" || exit
done
```

Для Viva KN-1913 и Hopper KN-3810 создайте отдельные тестовые диски и подставьте индекс модели во все команды. Runner выделяет KN-1910 128 МБ, а KN-1913 и KN-3810 по 256 МБ. У каждой модели собственный SquashFS KeeneticOS 5.1.8 и проверка SHA‑256. Runner записывает изменения в тестовый USB-диск и монтирует прошивку только для чтения. Исходный NDM не завершает старт на Malta из-за несовместимости модулей и платы. `nix-keenetic` воспроизводит OPKG lifecycle и вызывает оригинальные скрипты R2O. Запросы к системному NDM/NDNS по штатному IPC и аппаратный PPE/WHNAT остаются вне покрытия. Проверки с программным vendor `xt_PPE` содержатся также в предыдущем регрессионном сценарии стенда.

Для TLS-фикстуры `R2O_LAB_TLS_DIR` указывает на дерево с распакованным `openssl-util` и его зависимостями Entware в `opt/`, архивом `python-fixture.tar.gz` с тестовым Python Entware и `tls-origin.py` под именем `peer.py`, тестовыми `cert.pem` и `key.pem`, а также `xt_u32.ko`, `xt_length.ko` и `xt_connmark.ko` из используемой сборки ядра. Запустите отдельный диск с `--phase discovery`. Сертификат нужен для `a.example.com`, который используется только внутри гостя. В OpenWrt эквивалент запускается штатным тестом `scripts/test-geneva-midpoint-netns.sh DATAPATH CONTROLLER --lan-discovery`.

TLS-сценарий сначала проверяет сервер и контрольный отказ, затем ждёт автоматический подбор с пустым каталогом. Успех подтверждает полный ответ LAN-клиенту с проверенным сертификатом, HTTP 200 и заданным телом. Второй запрос выполняется после перезапуска datapath и controller и проверяет повторное применение сохранённой стратегии.

Флаг `--rpdb` добавляет только в гостевом network namespace правило для метки зонда с недоступным маршрутом. Сценарий проверяет тайм-аут LAN, рост последовательности NFQUEUE без потерь и доставку наблюдений TLS и повтора ClientHello в controller при запрете применения плана. На физическом KN‑1913 сравнивайте счётчики правил и очередей до и после тайм-аута LAN-клиента.

Для замера самостоятельного повторного подбора добавьте `measure-discovery.sh` в `R2O_LAB_TLS_DIR`, используйте `tls-origin.py` и сертификат с SAN `DNS:a.example.com,DNS:b.example.net`, затем добавьте `--measure` к запуску Keenetic. Для OpenWrt укажите абсолютный путь к помощнику внутри гостя в `R2O_DISCOVERY_MEASURE` при запуске `test-geneva-midpoint-netns.sh --lan-discovery`. Первый запрос направляется на `a.example.com`, следующий на новое имя и новый IP. Оба начальных запроса должны завершиться без полного ответа. Стенд фиксирует подтверждение плана в журнале, полный ответ LAN-клиенту и первую видимость привязки в атомарно заменённом файле каталога. Все три времени считаются от первого запроса к конкретной цели. Точки наблюдаются с шагом до секунды.

## OpenWrt

Используйте рабочую копию ext4 официального OpenWrt x86-64 25.12.5, ядро Linux 6.12.94 из того же образа и соответствующие пакеты OpenWrt в `/lab/packages`. Понадобятся `ip-full`, `libbpf1`, `libelf1`, `kmod-veth`, `kmod-nf-conntrack-netlink`, `kmod-nfnetlink-queue`, `kmod-nft-queue`. Временная служба приёмки запускается обычным procd, применяет локальную топологию и оставляет serial-журнал. Обе загрузки используют один и тот же тестовый ext4 и один и тот же `/opt`.

```sh
scripts/qemu-platform/stage-opt.sh openwrt openwrt-opt.img ./probe-x86_64 \
  ./candidate-x86 r2o-lab-candidate ./published/r2o-x86_64-musl.tar.gz "$PUBLISHED_TAG"
scripts/qemu-platform/run-openwrt.sh openwrt-copy.ext4 openwrt.kernel openwrt-opt.img logs
python3 scripts/qemu-platform/soak-report.py logs/OpenWrt-SECOND.log
```

Сравнение при удалении проверяет политику и порядок правил, настройки DNS, оригинальное состояние accounting, удаление служебных файлов R2O и доступность WAN из LAN. Из снимка iptables исключаются меняющиеся счётчики. В OpenWrt дополнительно сравниваются UCI `firewall` и `dhcp`. Десятиминутный прогон может выявить рост памяти или дескрипторов на заданном профиле, но не заменяет длительный тест с нагрузкой реальной сети.
