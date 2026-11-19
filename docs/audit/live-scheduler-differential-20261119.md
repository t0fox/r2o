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

## Единый phase-aware box

Сделан один режим без подгонки под порядок проб:

1. первое соединение — полный ответ и RST после app-data (SUSPECT);
2. identity-пробы — обрыв тела после полных заголовков;
3. gzip-проба — полный gzip-ответ;
4. после подтверждения обрыва — discovery-режим: полный ClientHello
   блокируется, split-фрагмент проксируется в полный TLS-сервер.

Повторный live-прогон:

```text
C d2kc:      обрыв подтверждён, plan-1bc820bc подтверждён,
             outcome=probe-confirmed, elapsed_ms=2940
Rust:        обрыв подтверждён по identity/gzip,
             plan d7965b... подтверждён и сохранён
```

Оба каталога:

```text
C:    boxes=1 bindings=1 tcp_profile=2 (TS)
Rust: boxes=1 bindings=1 tcp_profile=2 (TS)
```

Счётчики датапата совпали:

```text
план подготовлен 1, ДОИСПОЛНЕН 1, выпущено 3, отложено 2
```

Тайминги: C `elapsed_ms=2940`; Rust от RST до подтверждения исполнения
примерно 4.28 с по журналу.

## Ограничения

- Box синтетический: TLS/HTTP и обрыв эмулируются локально, но режим один
  для C и Rust; это не реальный DPI-бокс.
- Тайминги отличаются: C `elapsed_ms=2940`, Rust примерно 4.28 с от RST до
  подтверждения исполнения; это не побайтовый timing-дифференциал.
- Внешний IPv6 не проверялся (только ULA, default route нет).
- Каталог 11/115 недоступен; восстановлен 9/83.
