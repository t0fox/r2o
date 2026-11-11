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
[GatewaySocket] [READY] took 1021ms, as ccfd9db11edc1a80d3a787e399cba793
[GatewaySocket] [READY_SUPPLEMENTAL] took 1238ms
```

Web-страница `discord.com/login` проверена в **обычном headed Chromium** с нормальным
User-Agent: документ 200, `css: 359`, ошибок загрузки ассетов нет, отображается форма
входа. В headless Chromium те же CSS-запросы получают `ERR_CONNECTION_RESET` — это
anti-bot поведение Discord для headless-браузера, а не сетевое расхождение R2O.

Голосовой RTC после cold-start подтверждён вручную:

```text
07:26:00.683 RTC connection state: AWAITING_ENDPOINT => CONNECTING
07:26:00.896 RTCControlSocket [READY] took 214 ms
07:26:00.936 RTC_CONNECTING => RTC_CONNECTED
07:26:00.939 RTC connected to media server: 104.29.149.20:19302
```

RTP-метрики при этом:

```text
Ping received from 104.29.149.20:19302, seq: 38, rtt: 28
Transport stats ... rtt: 28 [ms]
packets sent: 402, received: 134, bytes sent: 19305, received: 6968
```

`--voice-list` на роутере видит живой поток:

```text
104.29.149.20:19302 <- 192.168.1.216:51775 пакетов 396
```

Отображаемые в Discord «5000 мс» не являются RTP-задержкой: фактический media RTT
26–28 мс. Они совпадают с недоступным `latency.discord.media` (HTTP 520) и
периодическими `RTCControlSocket HEARTBEAT ACK TIMEOUT`, то есть это метрика
control/latency-канала, а не голосового медиапотока.

## Оставшиеся ограничения

1. `latency.discord.media` отдаёт HTTP 520 со всех Cloudflare-адресов даже при принудительном `--resolve`; это состояние endpoint на стороне Discord/Cloudflare. Из-за него Discord может показывать 5000 мс, хотя RTP RTT 26–28 мс.
2. `RTCControlSocket` периодически получает `HEARTBEAT ACK TIMEOUT` и переподключается; media RTP при этом продолжает идти.
3. Физический long-running RTC-сеанс и аппаратные тайминги не входят в этот прогон.
