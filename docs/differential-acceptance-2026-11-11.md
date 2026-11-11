# Differential-приёмка TLS 1.2 → QUIC и Discord (2026-11-11)

## Закреплённые источники

- D2O oracle: `a378e230947ebfd011439e1cac0f1e994d883aae`
- R2O: `b5a36db` (`rt_proxy: публичный sentinel RuTracker и устойчивый upstream-пул`)
- Linux-проверки: WSL Ubuntu 26.04, root, `CC=gcc`, `cargo +1.98.0`

## Прошедшие differential-проверки

### TLS 1.2 / TLS 1.3 / ECH

- `test-controller-clienthello-differential.sh` — PASS, 56 кейсов ClientHello/TLS 1.2/1.3/ECH.
- `r2o-tls-verify-differential.sh` — PASS, 16/16.
- `r2o-ech-rx-ladder-differential.sh` — PASS.
- `r2o-layered-rx-differential.sh` — PASS.
- `test-d2o-shared-fixtures.sh` — PASS, включая TLS response 13 кейсов, EINTR и DNS rotation.
- `test-classifier-white-decoy-differential.sh` — PASS.
- `test-classifier-full-tree-control-differential.sh` — PASS.
- `r2o-fallback-differential.sh` — PASS.
- `r2o-raw-profile-differential.sh` — PASS.
- `r2o-raw-emission-cancel-differential.sh` — PASS.
- `r2o-raw-connect-fallback-differential.sh` — PASS, 18/18.
- `r2o-raw-split-support-differential.sh` — PASS.

### QUIC / HTTP/3

- `r2o-quic-hello-differential.sh` — PASS.
- `r2o-quic-local-address-differential.sh` — PASS.
- `r2o-discovery-quic-stop-differential.sh` — PASS.
- `r2o-quic-stun-watch-differential.sh` — PASS.
- `test-quic-http3-full-stage-differential.sh` — 18/18 passed, 137.07 с.
- `test-quic-app-bytes-differential.sh` — `VERDICT|match`.
- `test-quic-budget-init-differential.sh` — все значения совпали.
- `test-quic-short-control-differential.sh` — `VERDICT|match`.

## Живая проверка после перезагрузки роутера

- `r2o-datapath` — IPv4+IPv6.
- `r2o-controller` — IPv4+IPv6.
- `rt-proxy RuTracker` — `:1445`.
- Очереди NFQUEUE 2000/2001 привязаны, firewall установлен.

RuTracker:

```json
{"title":"RuTracker.org","css":4,"imgs":157,"total":157,"failures":[]}
```

Rutor:

```json
{"title":"rutor.info :: Свободный торрент трекер","css":1,"imgs":786,"total":786,"failures":[]}
```

YouTube: видео воспроизводится, `readyState=4`, `paused=false`, `currentTime` растёт.

## Discord

Cold-start приложения после перезагрузки дошёл до авторизованной сессии:

```text
[GatewaySocket] [CONNECTED] wss://gateway.discord.gg ... in 244 ms
[GatewaySocket] [READY] took 1563ms, as 017dc4983e8e52e30e6f947823243c1f
[GatewaySocket] [READY_SUPPLEMENTAL] took 1943ms
```

Предыдущая голосовая сессия до cold-start:

```text
RTC_CONNECTED
RTC connected to media server: 104.29.149.39:19329
Ping received ... rtt: 29
Transport stats ... rtt: 29 [ms]
```

Для повторной проверки голосового RTC после cold-start нужно вручную войти в голосовой канал: приложение не восстанавливает voice-сессию автоматически.

## Оставшиеся ограничения

1. Web-страница `discord.com/login` отдаёт документ 200, но часть CSS-ассетов получает `ERR_CONNECTION_RESET`. Приложение Discord при этом работает и дошло до `READY`.
2. `latency.discord.media` отдаёт HTTP 520 со всех Cloudflare-адресов даже при принудительном `--resolve`; это состояние endpoint на стороне Discord/Cloudflare, а не отказ обхода.
3. Голосовой RTC после cold-start не проверен без ручного входа в голосовой канал.
4. Физический long-running RTC-сеанс и аппаратные тайминги не входят в этот прогон.
