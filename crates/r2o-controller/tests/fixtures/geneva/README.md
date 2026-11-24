# Geneva differential fixtures

Эталон снят с `avatarDD/geneva_c` commit `bdb767d`, сборка `make -j8`,
из `tests/golden/in.pcap` (пакет 10 — TLS ClientHello, IPv4, seq=7001,
ack=9001, flags=PA, длина нагрузки 111).

Стратегия:

```
[TCP:flags:PA]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-
```

Команда:

```sh
build/geneva apply \
  -s '[TCP:flags:PA]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-' \
  -i tests/golden/in.pcap -o /tmp/geneva-out.pcap -p 443 --rng-seed 1
```

Файлы:

- `clienthello_in.bin` — входной IPv4/TCP-пакет;
- `clienthello_original.bin` — оригинал из вывода geneva_c;
- `clienthello_flags_rst.bin` — изменённая копия (flags=R, испорченная
  контрольная сумма).

`crates/r2o-controller/tests/geneva_compile_differential.rs` компилирует
эту стратегию в R2OP, собирает оба пакета через `r2k-core::wire` и
сравнивает их с эталоном после нормализации IP ID и контрольных сумм.

## Сетевая проверка

Нужны Linux с NFQUEUE, `ip`, `nft`, OpenSSL, Python 3 и права на
создание сетевых пространств имён. Скрипт поднимает изолированные клиент
и сервер, использует локальный тестовый сертификат и печатает путь к журналам.

```sh
cargo build --locked -p r2o-datapath -p r2o-controller
sudo bash scripts/test-geneva-midpoint-netns.sh \
    target/debug/r2o-datapath target/debug/r2o-controller
sudo bash scripts/test-geneva-midpoint-netns.sh \
    target/debug/r2o-datapath target/debug/r2o-controller --discovery
```

Первый сценарий проверяет именной TCP-план с разрезом ClientHello.
В режиме `--discovery` проверяются сохранение найденной стратегии
из пустого каталога и полный HTTPS-ответ по ней. Происхождение корпуса
и лицензия указаны в [THIRD_PARTY_NOTICES.md](../../../../../THIRD_PARTY_NOTICES.md).
