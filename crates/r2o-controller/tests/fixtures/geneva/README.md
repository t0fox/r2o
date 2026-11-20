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
