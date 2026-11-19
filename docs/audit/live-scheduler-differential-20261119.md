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
elapsed_ms=14757 queue_ms=0
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

## Исправленное расхождение профиля TCP

Первый прогон выявил:

```text
C:    tcp_profile = 1 (NO_TS)
Rust: tcp_profile = 0 (UNKNOWN), target profile = 2 (TS)
```

Причины и исправления:

1. `r2o-datapath` отправлял v22 `CLIENT_TCP` из опций сегмента ClientHello
   (обычно пустых), а не из SYN. Теперь опции SYN сохраняются в
   `TcpSession.client_tcp_options` и уходят в `CLIENT_TCP`; v48 `HELLO`
   получает тот же профиль из сессии.
2. `r2o-controller` при сохранении привязки брал
   `r2k_link_shape_tcp_profile(target.shape)` (для базовой формы это
   UNKNOWN), а не `target.tcp_profile()`. Исправлено в `discovery.rs`.

Адресные тесты:

```text
r2o-datapath: autottl... проверяет r2o_client_tcp_options_for_packet
r2o-controller: measured_binding_берёт_профиль_цели_а_не_базовую_форму
```

Повторный live-прогон:

```text
C:    tcp_profile = 2 (TS)
Rust: tcp_profile = 2 (TS)
```

Оба каталога снова дали `1 box / 1 binding`, `level=3`, `transport=6`,
`family=4`, `shape=1`; полный путь до `PLANNING` подтверждён обоими
контроллерами.

## Попытка единого box-режима

Единый режим без подгонки под порядок проб (по `Accept-Encoding` и фазе
`identity_cuts/gzip`) дошёл до подтверждения обрыва. C `d2kc` после этого
подтвердил план (`probe-confirmed`, `elapsed_ms=116`), Rust-контроллер
остановился после постановки классификации в очередь: discovery-пробы
получали полный ответ, и классификатор не нашёл план. Нужен phase-aware box
(block/split на время классификации, complete на время проверки) либо
предварительно seeded plan. Это ограничение, а не закрытый live-дифференциал.

## Ограничения

- Box-режимы подобраны под порядок проб каждого контроллера; это не один
  универсальный target, а два прогона с одинаковым типом обрыва.
- Тайминги отличаются: C `elapsed_ms=14757`, Rust подтверждение плана
  примерно через 16.3 с по журналу; это не побайтовый timing-дифференциал.
- Внешний IPv6 не проверялся (только ULA, default route нет).
- Каталог 11/115 недоступен; восстановлен 9/83.
