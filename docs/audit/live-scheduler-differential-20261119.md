# Live scheduler differential 2026-11-19

Проверка production-пути `T_ASKING → VERIFY → PLANNING` на реальном NFQUEUE-датапате
в netns. C-оракул — `d2kc` из pinned D2O `7a5fab97`, Rust — production
`r2o-controller`. Оба работали с production `r2o-datapath` (очередь 2300,
`--probe-mark 46`, `--controller-mode`), nft `postrouting`/`input`, TLS-box
с обрывом тела после полных заголовков и полным gzip-контролем.

## Общий результат

Оба контроллера прошли полный путь:

```text
RST TCP после TLS-данных (SUSPECT code 5)
→ парная identity/gzip RX-проверка
→ обрыв подтверждён
→ классификация
→ собственный зонд подтвердил план
→ привязка сохранена в каталог
```

C (`d2kc`):

```text
объёмный замер TLS 1.3 ... RX identity 16384/16384 ... gzip complete=1
подтверждён повторяемый обрыв входящего ответа около 16 КБ
ПОДТВЕРЖДЕНО собственным зондом: plan-1bc820bc
итог поиска: outcome=probe-confirmed path=property probe_units=13
elapsed_ms=14741 queue_ms=0
```

Rust (`r2o-controller`):

```text
парная RX-проверка live.example.com: обрыв подтверждён по identity/gzip
подтверждённый RX-обрыв поставил классификацию live.example.com в очередь
исполнение подтверждено: plan=d7965b265bcc358d2dd77d666b644dae
автопоиск подтвердил и сохранил план d7965b...
```

Команды датапата совпали по счётчикам:

```text
план подготовлен 1, ДОИСПОЛНЕН 1, выпущено 3, отложено 2
(сразу 1, из очереди 2), потоков испорчено 0
```

Каталог: оба сохранили `1 box / 1 binding` для `live.example.com`,
`level=3`, `transport=6`, `family=4`, `shape=1`.

## Найденное расхождение

Профиль TCP-метки времени в сохранённой привязке:

```text
C:    tcp_profile = 1 (NO_TS)
Rust: tcp_profile = 0 (UNKNOWN)
```

Диагностика Rust на этом же прогоне:

```text
target profile = 2 (TS), has_timestamp = None
```

То есть датапат/контроллер видят разные источники профиля: Rust-target
считает, что TS есть, а в binding уходит UNKNOWN; C сохраняет NO_TS.
Это не исправлено. Нужен отдельный адресный разбор `CLIENT_TCP`/`SHAPE` →
`tcp_profile` в v22/v48 и решение, какой источник является эталонным.

## Ограничения

- Box-режимы подобраны под порядок проб каждого контроллера; это не один
  универсальный target, а два прогона с одинаковым типом обрыва.
- Тайминги отличаются: C `elapsed_ms=14741`, Rust подтверждение плана
  примерно через 16.3 с по журналу; это не побайтовый timing-дифференциал.
- Внешний IPv6 не проверялся (только ULA, default route нет).
- Каталог 11/115 недоступен; восстановлен 9/83.
