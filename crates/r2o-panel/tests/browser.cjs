"use strict";

const assert = require("node:assert/strict");
const { once } = require("node:events");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const root = path.resolve(__dirname, "../../..");
const assets = path.join(root, "crates/r2o-panel/assets");
const panelUi = require(path.join(assets, "panel.js"));
const diagnosticsUi = require(path.join(assets, "diagnostics.js"));
const work = fs.mkdtempSync(path.join(os.tmpdir(), "r2o-panel-browser-"));
const chromeProfile = path.join(work, "chrome");
const panelBinary = process.env.R2O_PANEL_BIN || path.join(root, "target/debug/r2o-panel");
const chromeBinary = process.env.CHROME_BIN || "google-chrome";
const captureDir = process.env.R2O_CAPTURE_DIR;
let panel;
let chrome;
let socket;

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function verifyUpdatePollingMatchesD2oIdleCadence() {
  const realNow = Date.now;
  let clock = 100000;
  let calls = 0;
  let busy = "";
  let fail = false;
  Date.now = () => clock;
  try {
    const app = new panelUi.App({ hidden: false, getElementById: (id) => id === "updates-body" ? {} : null }, {
      setTimeout,
      clearTimeout,
      fetch: async () => ({}),
    });
    app.updateRequest = async () => {
      calls += 1;
      if (fail) throw new Error("offline");
      return { ok: true, data: { busy } };
    };
    app.renderUpdates = () => {};

    await app.pollUpdates();
    for (let i = 0; i < 29; i += 1) {
      clock += 2000;
      await app.pollUpdates(true);
    }
    assert.equal(calls, 1, "idle scheduled polling waits one minute, as in d2o");
    clock += 2000;
    await app.pollUpdates(true);
    assert.equal(calls, 2, "idle polling refreshes at one minute");
    await app.pollUpdates();
    assert.equal(calls, 3, "manual refresh bypasses the idle interval");

    busy = "checking";
    await app.pollUpdates();
    clock += 2000;
    await app.pollUpdates(true);
    assert.equal(calls, 5, "scheduled polling stays fast while updater is busy");

    busy = "";
    await app.pollUpdates();
    fail = true;
    await app.pollUpdates();
    fail = false;
    clock += 2000;
    await app.pollUpdates(true);
    assert.equal(calls, 8, "polling retries quickly after an error");
    clock += 2000;
    await app.pollUpdates(true);
    assert.equal(calls, 8, "polling returns to the idle interval after recovery");
  } finally {
    Date.now = realNow;
  }
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "localhost", resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitFor(read, description, attempts = 200) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const value = await read();
    if (value) return value;
    await delay(50);
  }
  throw new Error(`Истекло время ожидания: ${description}`);
}

async function main() {
  await verifyUpdatePollingMatchesD2oIdleCadence();
  const voiceStages = [
    ["измеряем живой голосовой поток", 0],
    ["приём голоса стоит, ждём разговора", 1],
    ["приём применился к разговору, ждём ответа сервера", 2],
  ];
  for (const [phase, at] of voiceStages) {
    const track = panelUi.trackFor(phase);
    assert.equal(track?.voice, true, `голосовой статус «${phase}» использует дорожку d2o`);
    assert.equal(track?.at, at, `голосовой статус «${phase}» отмечает правильный этап d2o`);
    assert.deepEqual(track?.steps.map((step) => step.label), ["Замер голоса", "Приём стоит", "Ждём ответа"]);
  }
  const ownPlanTrack = panelUi.trackFor("проверяем свои планы");
  assert.equal(ownPlanTrack?.at, 5, "фаза проверки своего плана остаётся на дорожке d2o");
  assert.deepEqual(ownPlanTrack?.steps.map((step) => step.label), ["Очередь", "Форма", "Распознаём", "Свойства", "Планы", "Проверка", "Подтверждено"]);
  assert.equal(panelUi.trackFor("неизвестная фаза новой сборки"), null, "неизвестная фаза не выдумывает этап");
  assert.equal(diagnosticsUi.summary({ samples: [{ at: 1, processes: [], bindings: 0, plans: 0 }], events: [{ outcome: "failed" }, { outcome: "queue-expired" }, { outcome: "plan-found" }] }).includes("без подтверждённого результата: 2"), true, "диагностика считает отказ и истёкшую очередь неподтверждёнными исходами");
  const datapathSnapshot = (at, ticks, rss, anonymous) => ({ at, mono_ms: at * 1000,
    processes: [{ name: "r2o-datapath", pid: 17, start_ticks: ticks, rss_kib: rss, anon_kib: anonymous,
      heap_live_bytes: 95, heap_peak_bytes: 300 }] });
  const datapathHistory = diagnosticsUi.processMemoryRows([
    datapathSnapshot(60, 17, 1024, 0), datapathSnapshot(120, 17, 1536, 256),
    datapathSnapshot(180, 18, 4096, null), datapathSnapshot(240, 18, 5120, 2048)
  ], "r2o-datapath");
  assert.equal(datapathHistory[0].rss_anon, 0);
  assert.equal(datapathHistory[2].rss_anon, null);
  assert.equal(datapathHistory[2].heap_peak, 300);
  assert.equal(diagnosticsUi.seriesEndpoints(datapathHistory, "rss").delta, 1048576,
    "повторный PID не выдаёт рост предыдущего процесса");
  for (const [base, step] of [[1, 60], [1000, 60000]]) {
    const history = diagnosticsUi.memoryRows({
      memory_history: { time_base: [1000, base], fields: ["at_delta_s", "mono_delta_s", "rss_kib"],
        samples: [[0, 0, 100], [60, step, 200]] },
      samples: [{ at: 1000, mono_ms: 1000 }, { at: 1060, mono_ms: 61000 }]
    });
    assert.equal(history[1].time - history[0].time, 60, "старые и новые отчёты дают одну минуту между точками");
    assert.equal(diagnosticsUi.rowsInRange(history, 2).length, 2);
  }
  assert.ok(fs.existsSync(panelBinary), `Не найден исполняемый файл панели: ${panelBinary}`);
  fs.mkdirSync(chromeProfile, { recursive: true });

  const port = await freePort();
  const configPath = path.join(work, "config");
  const serviceLog = path.join(work, "service.log");
  const servicePath = path.join(work, "service.sh");
  const livePath = path.join(work, "live.json");
  fs.mkdirSync(path.join(work, "state"), { recursive: true });
  fs.writeFileSync(path.join(work, "telegram.status"), "error\n");
  fs.writeFileSync(path.join(work, "telegram-diagnostics.json"), JSON.stringify({
    checked_at: 1_800_000_000,
    state: "partial",
    data_centers: [
      { dc: 1, state: "healthy", routes: [
        { transport: "cf-worker", state: "healthy", domain: "worker.example", selected_ip: "203.0.113.1", http_status: null, dns_ms: 2, tcp_ms: null, tls_ms: 5, websocket_ms: 3, mtproto_ms: 4, first_response_ms: 14 },
        { transport: "cf-proxy", state: "unavailable", domain: "kws1.pool.example", extended: true, failed_stage: "timeout" },
      ] },
      { dc: 2, state: "blocked", routes: [] },
      { dc: 3, state: "unavailable", routes: [] },
      { dc: 4, state: "unverified", routes: [] },
      { dc: 5, state: "healthy", routes: [] },
    ],
  }));
  const enginePidPath = path.join(work, "engine.pid");
  const splitEnginePidPath = path.join(work, "engine4.pid");
  const controllerPidPath = path.join(work, "controller.pid");
  const splitControllerPidPath = path.join(work, "controller4.pid");
  fs.writeFileSync(configPath, `MODE=observe\nSTATE_DIR=${path.join(work, "state")}\nQUEUE_NUM=2000\nQUEUE_NUM6=2001\nR2O_FLOW_CAPACITY=2048\nIPV6_ENABLED=1\nMARK=45\nPROBE_MARK=0\nONLY_MARK=\nFW_BACKEND=auto\nPORTS=0:65535\nCONNBYTES=0:8\nVOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344\nVOICE_CONNBYTES=0:4\nHTTP_KEEPALIVE_PORTS=80\nDNS_PORTS=53,853\nTG_ENABLED=1\nTG_MODE=local\nTG_PORT=1443\nR2O_PPE_DEOFFLOAD=1\nLOGMAX=2097152\nLOGKEEP=1048576\nLOG_EVERY=60\n`);
  fs.writeFileSync(enginePidPath, String(process.pid));
  fs.writeFileSync(controllerPidPath, String(process.pid));
  fs.writeFileSync(livePath, JSON.stringify({
    linked: true,
    catalog_at: new Date().toISOString(),
    boxes: [],
    groups: [],
    dns_source_status: "known",
    dns_services: [
      { protocol: "dot", host: "dns.example", port: 853, resolved_ip: "192.0.2.8", state: "direct_ok", checked_at: new Date().toISOString(), answer_rtt_ms: 17, availability: "available", usage_observed: false, dns_answer_confirmed: true, status_reason: "DoT: получен корректный DNS-ответ" },
      { protocol: "doq", host: "quic-with-a-long-resolver-name.example", port: 853, resolved_ip: "2001:db8::9", router_seen_at: new Date(Date.now() - 1000).toISOString(), state: "plan_applied", availability: "checking", plan_applied: true, applied_plan_id: "8d3c8fc1b32c52c2013cb04f82891245", dns_answer_via_plan: false, status_reason: "DNS-ответ через план ещё проверяется" },
      { protocol: "doh3", host: "old.example", port: 443, path: "/dns-query", resolved_ip: "192.0.2.9", state: "direct_ok", availability: "available", dns_answer_confirmed: true, checked_at: new Date(Date.now() - 720000).toISOString(), last_result: { state: "available", checked_at: new Date(Date.now() - 720000).toISOString(), answer_rtt_ms: 22 } },
      { protocol: "doh", host: "refused.example", port: 443, path: "/dns-query", resolved_ip: "192.0.2.10", state: "failed", availability: "unavailable", failure: "server", checked_at: new Date().toISOString(), status_reason: "HTTP 403: сервер отклонил запрос" },
    ].map(({ protocol, host, port, path, usage_observed = true, router_seen_at, ...connection }) => ({
      profile_id: host, protocol, host, port, path, scope: "router", configured: true,
      service_active: true, usage_observed, router_seen_at,
      connections: [{ family: connection.resolved_ip.includes(":") ? 6 : 4, ...connection }],
    })),
    searches: [{
      target: "blocked.example",
      family: 4,
      transport: 6,
      ip: "192.0.2.4",
      port: 443,
      phase: "проверяем выведенный план",
      since: new Date().toISOString(),
      attempts: 1,
      probes: 3,
      question: "",
      candidate: "план поставлен: split sni_middle +0",
      source: "выведен из замера",
      plan: "split sni_middle +0 · fake payload=1 poison=1…",
      application: "точный APPLIED получен",
      last_result: "план применён; получен полный HTTPS-ответ HTTP 200",
      shape: 1,
    }],
    targets: 0,
    confirms: 0,
    probes_used: 3,
    client_unfit: 0,
    measurements: { active: 1, limit: 2, queued: 0, cpu_usage_pct: 48,
      busiest_core_usage_pct: 100, scheduler_cpu_reserve_pct: 7, free_pct: 7, cores: 4 },
  }));
  const liveState = JSON.parse(fs.readFileSync(livePath, "utf8"));
  liveState.searches.push(
    {
      target: "queued.example",
      family: 4,
      transport: 6,
      ip: "192.0.2.5",
      port: 443,
      phase: "ожидает безопасного слота замера",
      since: new Date().toISOString(),
      attempts: 0,
      probes: 0,
      question: "",
      candidate: "",
      source: "",
      plan: "",
      application: "",
      last_result: "",
      shape: 1,
    },
    {
      target: "classifying.example",
      family: 4,
      transport: 6,
      ip: "192.0.2.6",
      port: 443,
      phase: "распознаём поведение",
      since: new Date().toISOString(),
      attempts: 0,
      probes: 1,
      question: "whole",
      candidate: "",
      source: "",
      plan: "",
      application: "",
      last_result: "",
      shape: 1,
    },
    {
      target: "failed.example",
      family: 4,
      transport: 6,
      ip: "192.0.2.7",
      port: 443,
      phase: "проверяем выведенный план",
      since: new Date().toISOString(),
      attempts: 1,
      probes: 3,
      question: "",
      candidate: "план поставлен: split sni_middle +0",
      source: "выведен из замера",
      plan: "",
      application: "обход не подтверждён",
      last_result: "TLS-рукопожатие не завершилось: Resource temporarily unavailable (os error 11)",
      shape: 1,
    },
    {
      target: "starting.example",
      family: 4,
      transport: 6,
      ip: "192.0.2.8",
      port: 443,
      phase: "заводим поиск",
      since: new Date().toISOString(),
      attempts: 0,
      probes: 0,
      question: "",
      candidate: "",
      source: "",
      plan: "",
      application: "",
      last_result: "",
      shape: 1,
    }
  );
  liveState.boxes.push({
    id: "discord-voice",
    created: new Date().toISOString(),
    updated: new Date().toISOString(),
    signals: [{ kind: "discord-voice", human: "Голос Discord" }],
    plans: [],
    bindings: [{
      target: "@discord-voice",
      kind: "name",
      family: 4,
      transport: 17,
      shape: 5,
      level: 3,
      level_name: "подтверждено",
      successes: 1,
      confirmed: new Date().toISOString(),
      enabled: true,
      recheck: false,
      verified_by: 3,
    }],
  });
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  fs.writeFileSync(servicePath, `#!/bin/sh\nprintf '%s\\n' "$*" >> '${serviceLog}'
if [ "$1" = meta-protection-product ]; then
  case "$3" in
    off) touch '${work}/meta-protection.'"$2"'.disabled' ;;
    on) rm -f '${work}/meta-protection.'"$2"'.disabled' ;;
  esac
fi
case "$1" in
  meta-protection-off) touch '${work}/meta-protection.disabled'; rm -f '${work}/meta-protection.enabled' ;;
  meta-protection-on) touch '${work}/meta-protection.enabled'; rm -f '${work}/meta-protection.disabled' ;;
esac
`);
  fs.chmodSync(servicePath, 0o700);
  const managerRoot = path.join(work, "manager");
  fs.mkdirSync(path.join(managerRoot, "run"), { recursive: true });
  fs.writeFileSync(path.join(managerRoot, "run/meta-dns-scheduler.pid"), String(process.pid));
  const metaTime = Math.floor(Date.now() / 1000);
  fs.writeFileSync(path.join(work, "meta-status.json"), JSON.stringify({
    checked_at: metaTime,
    families: [
      { product: "facebook", checked: 2, verified_domains: 2, dns_ok: 2, domains: 24, ipv4: 2 },
      { product: "instagram", checked: 6, verified_domains: 5, domains: 12, dns_ok: 5, ipv4: 3, ipv6: 2, pinned: 1,
        checked_at: metaTime, sample: [{ host: "i.instagram.com", address: { ip: "2a03:2880::1", asn: 32934, result: "TLS подтверждён" } }] },
      { product: "whatsapp", checked: 5, verified_domains: 5 },
      { product: "messenger", checked: 1, verified_domains: 0, last_failure: { host: "edge-chat.facebook.com", at: metaTime, detail: "Тайм-аут TCP" } },
      { product: "quest", checked: 3, verified_domains: 3 },
    ],
    sources: [{ id: "geosite-meta", synced_at: metaTime, entries: 43, sha256: "82fe2d56672eabc3" }],
  }));
  const updateFile = path.join(managerRoot, "state/update.json");
  const updateState = { current: "test-1", latest: { release_id: "test-2", version: "R2O 2" }, check_ok: true };
  fs.mkdirSync(path.dirname(updateFile), { recursive: true });
  const writeUpdate = (state) => fs.writeFileSync(updateFile, JSON.stringify({
    ...updateState, checked_utc: Math.floor(Date.now() / 1000), ...state,
  }));
  writeUpdate({});
  panel = spawn(panelBinary, [
    "serve",
    "--listen", `localhost:${port}`,
    "--config", configPath,
    "--service", servicePath,
    "--manager", servicePath,
    "--manager-root", managerRoot,
    "--assets", path.join(work, "embedded-only"),
    "--state-dir", work,
    "--live", livePath,
    "--engine-pid", enginePidPath,
    "--engine-pid-fallback", splitEnginePidPath,
    "--controller-pid", controllerPidPath,
    "--controller-pid-fallback", splitControllerPidPath,
    "--health-file", path.join(work, "panel.health"),
  ], { stdio: ["ignore", "pipe", "pipe"] });
  let panelOutput = "";
  panel.stdout.on("data", (chunk) => { panelOutput = (panelOutput + chunk).slice(-4000); });
  panel.stderr.on("data", (chunk) => { panelOutput = (panelOutput + chunk).slice(-4000); });
  const panelExit = new Promise((resolve) => panel.once("exit", (code) => resolve(code)));
  await waitFor(async () => {
    if (panel.exitCode !== null) throw new Error(`Панель завершилась с кодом ${await panelExit}: ${panelOutput}`);
    try {
      const response = await fetch(`http://localhost:${port}/`);
      return response.ok;
    } catch {
      return false;
    }
  }, "запуск HTTP-панели");

  const chromeArgs = [
    "--headless=new",
    "--no-first-run",
    "--disable-dev-shm-usage",
    "--hide-scrollbars",
    "--remote-debugging-port=0",
    `--user-data-dir=${chromeProfile}`,
    "about:blank",
  ];
  if (process.env.R2O_CHROME_NO_SANDBOX === "1") chromeArgs.unshift("--no-sandbox");
  chrome = spawn(chromeBinary, chromeArgs, { stdio: ["ignore", "ignore", "pipe"] });
  let chromeOutput = "";
  chrome.stderr.on("data", (chunk) => { chromeOutput = (chromeOutput + chunk).slice(-4000); });
  const activePortFile = path.join(chromeProfile, "DevToolsActivePort");
  const debugPort = await waitFor(() => {
    try {
      return Number(fs.readFileSync(activePortFile, "utf8").split("\n")[0]);
    } catch {
      return null;
    }
  }, `запуск Chrome: ${chromeOutput}`);
  const tab = await (await fetch(`http://localhost:${debugPort}/json/new?about:blank`, { method: "PUT" })).json();

  socket = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });

  let nextId = 0;
  const pending = new Map();
  const runtimeErrors = [];
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(String(event.data));
    if (message.id) {
      const request = pending.get(message.id);
      if (!request) return;
      pending.delete(message.id);
      if (message.error) request.reject(new Error(message.error.message));
      else request.resolve(message.result);
    } else if (message.method === "Runtime.exceptionThrown") {
      runtimeErrors.push(message.params.exceptionDetails.text);
    }
  });

  function call(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++nextId;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
  }

  async function evaluate(expression) {
    const result = await call("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
    return result.result.value;
  }

  async function press(key, windowsVirtualKeyCode) {
    await call("Input.dispatchKeyEvent", { type: "rawKeyDown", key, code: key, windowsVirtualKeyCode });
    await call("Input.dispatchKeyEvent", { type: "keyUp", key, code: key, windowsVirtualKeyCode });
  }

  await call("Page.enable");
  await call("Runtime.enable");
  await call("Page.navigate", { url: `http://localhost:${port}/` });
  await waitFor(() => evaluate("document.readyState === 'complete' && !!document.querySelector('#app')"), "загрузка страницы R2O");
  await evaluate("document.fonts.ready.then(() => true)");
  await waitFor(() => evaluate("!!document.querySelector('#engine-state small')"), "состояние движка в верхней панели");
  await waitFor(() => evaluate("document.querySelectorAll('#status-panel .metric-card').length === 6"), "единая сводка Discovery");
  await call("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  assert.deepEqual(await evaluate(`(() => {
    const cards = [...document.querySelectorAll('#status-panel .metric-card')];
    return [new Set(cards.map(card => card.offsetTop)).size,
      cards[1].querySelector('.metric-reading').textContent,
      document.querySelector('#discovery-slots').children.length,
      document.querySelector('#discovery-cpu-label').textContent,
      document.querySelector('#discovery-cpu-value').textContent,
      document.querySelector('#discovery-cpu .discovery-gauge').getBoundingClientRect().width > 100];
  })()`), [1, "1 / 2", 2, "Общая нагрузка CPU", "48%", true]);
  const measurements = liveState.measurements;
  const nextSlot = "document.querySelectorAll('.discovery-slot-fill')[1]";
  const slotAnimating = `${nextSlot}.getAnimations().some(animation => animation.playState === 'running')`;
  const metricReading = "document.querySelectorAll('#overview-metrics .metric-value')[1].firstElementChild";
  const readingAnimating = `${metricReading}.getAnimations().some(animation => animation.playState === 'running')`;
  const updateActiveSlots = async (active, limit = measurements.limit, cpu = {}) => {
    liveState.measurements = { ...measurements, active, limit, ...cpu };
    fs.writeFileSync(livePath, JSON.stringify(liveState));
    await evaluate("document.dispatchEvent(new Event('visibilitychange'))");
  };
  await updateActiveSlots(measurements.active, measurements.limit, {
    cpu_usage_pct: undefined, busiest_core_usage_pct: undefined, scheduler_cpu_reserve_pct: undefined, free_pct: 92,
  });
  await waitFor(() => evaluate(`document.querySelector('#discovery-cpu-value').textContent === '—'
    && document.querySelector('#discovery-cpu-core').textContent === '—'
    && document.querySelector('#discovery-cpu-reserve').textContent === '92%'
    && document.querySelector('#discovery-cpu').offsetHeight > 0`), "из старого снимка читается только резерв CPU");
  await updateActiveSlots(measurements.active, measurements.limit, { cpu_usage_pct: 0 });
  await waitFor(() => evaluate("document.querySelector('#discovery-cpu-value').textContent === '0%' && document.querySelector('#discovery-cpu-fill').style.transform === 'scaleX(0)'"), "реальный нулевой замер отличается от отсутствия данных");
  await updateActiveSlots(measurements.active, measurements.limit, { cpu_usage_pct: 71 });
  await waitFor(() => evaluate("document.querySelector('#discovery-cpu-value').textContent === '71%' && document.querySelector('#discovery-cpu-fill').style.transform === 'scaleX(0.71)'"), "процент и длина шкалы CPU совпадают");
  await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] });
  await evaluate(`window.initialDiscoverySlot = ${nextSlot}`);
  await updateActiveSlots(2);
  await waitFor(() => evaluate(`${slotAnimating} && ${nextSlot}.style.getPropertyValue('--slot-fill') === '1'`), "новый слот плавно заполняется");
  await waitFor(() => evaluate(`${readingAnimating} && ${metricReading}.textContent === '2 / 2'`), "оба числа замеров обновляются одной прокруткой");
  await waitFor(() => evaluate(`!${slotAnimating} && !${readingAnimating}`), "при неизменной загрузке шкала и цифры статичны");
  await updateActiveSlots(1);
  await waitFor(() => evaluate(`${slotAnimating} && ${nextSlot}.style.getPropertyValue('--slot-fill') === '0'`), "освободившийся слот плавно гаснет");
  await waitFor(() => evaluate(`${readingAnimating} && ${metricReading}.textContent === '1 / 2'`), "пара чисел прокручивается при освобождении слота");
  assert.equal(await evaluate(`window.initialDiscoverySlot === ${nextSlot}`), true, "слоты сохраняют DOM между замерами");
  assert.equal(await evaluate("document.querySelector('#discovery-capacity-status').textContent"), "Свободно 1");
  await updateActiveSlots(0, 6);
  await waitFor(() => evaluate("document.querySelector('#discovery-capacity-status').textContent === 'Свободно 6'"), "шесть свободных слотов");
  await updateActiveSlots(6, 6);
  await waitFor(() => evaluate(`(() => {
    const slots = document.querySelector('#discovery-slots');
    return slots.querySelectorAll('.discovery-slot[data-occupied]').length === 6
      && slots.querySelectorAll('.discovery-slot[data-preview]').length === 6
      && document.querySelector('#discovery-capacity-status[data-full]').textContent === 'Все 6 заняты'
      && slots.getAnimations({subtree: true}).some(animation => animation.effect.target?.classList.contains('discovery-slot'));
  })()`), "при шести занятых слотах шкала плавно расширяется еще на шесть ячеек");
  await waitFor(() => evaluate("!document.querySelector('#discovery-slots').getAnimations({subtree: true}).length"), "при полной загрузке анимация завершается");
  assert.equal(await evaluate("Number(document.querySelector('#overview-metrics').children[2].querySelector('.metric-number').textContent) > 0"), true, "очередь видна отдельно от полной шкалы");
  assert.equal(await evaluate(`${metricReading}.textContent`), "6 / 6", "пунктирные ячейки не меняют лимит");
  await updateActiveSlots(6, 12);
  await waitFor(() => evaluate(`${metricReading}.textContent === '6 / 12' && !document.querySelector('#discovery-slots [data-preview]')`),
    "дополнительные слоты становятся реальными после изменения лимита");
  await updateActiveSlots(12, 12);
  await waitFor(() => evaluate("document.querySelectorAll('#discovery-slots [data-preview]').length === 6"
    + " && document.querySelectorAll('#discovery-slots [data-occupied]').length === 12"), "следующий блок появляется при 12 / 12");
  await updateActiveSlots(measurements.active);
  liveState.confirms += 1;
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate(`(() => {
    const metrics = document.querySelector('#overview-metrics');
    return metrics.children[3].querySelector('.metric-number').textContent === '1'
      && !metrics.querySelector('.metric-reading-outgoing') && !metrics.getAnimations({subtree: true}).length;
  })()`), "после обновления счётчика сводка статична");
  if (captureDir) {
    const screenshot = await call("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(captureDir, "discovery-overview-desktop.png"), Buffer.from(screenshot.data, "base64"));
  }
  liveState.confirms -= 1;
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await call("Emulation.clearDeviceMetricsOverride");
  assert.match(await evaluate("document.querySelector('#engine-state .mast-state-text').textContent"), /^Движок работает /);
  assert.equal(await evaluate("document.querySelectorAll('#engine-state[role=status]').length === 1 && !document.querySelector('#status-state, #rail-status')"), true);
  assert.equal(await evaluate(`(() => {
    document.querySelector('#engine-actions [data-control=restart]').click();
    const status = document.querySelector('#engine-state');
    return status.textContent.includes('Движок перезапускается') && status.querySelector('.lamp').dataset.tone === 'live';
  })()`), true, "запрос перезапуска сразу меняет единственный статус");
  await waitFor(() => evaluate("document.querySelector('#engine-state .mast-state-text').textContent.startsWith('Движок работает')"), "возврат к статусу движка после команды");
  fs.writeFileSync(splitEnginePidPath, String(process.pid));
  fs.writeFileSync(splitControllerPidPath, String(process.pid));
  fs.unlinkSync(enginePidPath);
  fs.unlinkSync(controllerPidPath);
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  assert.deepEqual(
    await evaluate(`fetch('/api/status').then(response => response.json()).then(({snapshot, knowledge}) =>
      [snapshot.engine_running, snapshot.controller_running, knowledge.linked])`),
    [true, true, true],
    "переход на раздельные процессы сохраняет актуальное состояние без перезапуска панели",
  );
  fs.unlinkSync(splitEnginePidPath);
  fs.unlinkSync(splitControllerPidPath);
  await waitFor(() => evaluate("document.querySelector('#engine-state .mast-state-text').textContent.startsWith('Движок остановлен')"), "опрос отражает фактическую остановку");
  await waitFor(() => evaluate("document.querySelector('#now-title').textContent === 'Подбор приостановлен'"), "карточка обзора показывает состояние подбора");
  assert.equal(await evaluate("document.querySelector('#dns-protection-list .meta-chip').textContent"), "Состояние неизвестно");
  assert.equal(await evaluate("document.querySelector('#nav-now').textContent"), "");
  fs.writeFileSync(enginePidPath, String(process.pid));
  fs.writeFileSync(controllerPidPath, String(process.pid));
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate("document.querySelector('#engine-state .mast-state-text').textContent.startsWith('Движок работает')"), "опрос отражает возобновление работы");
  await evaluate(`(() => {
    const fetchStatus = window.fetch;
    window.restoreStatusFetch = () => { window.fetch = fetchStatus; };
    window.fetch = (url, options) => String(url).startsWith("/api/status")
      ? Promise.reject(new Error("Связь с панелью прервана"))
      : fetchStatus.call(window, url, options);
  })()`);
  await waitFor(() => evaluate(`(() => {
    const status = document.querySelector('#engine-state');
    return status.textContent.trim() === 'Статус движка неизвестен'
      && status.querySelector('.lamp').dataset.tone === 'warn'
      && !status.querySelector('small');
  })()`), "при недоступном API старый статус сменяется предупреждением");
  assert.deepEqual(await evaluate("[...document.querySelectorAll('#dns-protection-list .meta-chip, #dns-protection-extra .meta-chip')].map(node => node.textContent)"), ["Состояние неизвестно", "Состояние неизвестно", "Состояние неизвестно", "Состояние неизвестно"]);
  assert.equal(await evaluate("document.querySelector('#dns-protection-list').textContent.includes('Последний план')"), true);
  await evaluate("window.restoreStatusFetch()");
  await waitFor(() => evaluate("document.querySelector('#engine-state .mast-state-text').textContent.startsWith('Движок работает')"), "успешный запрос возвращает актуальный статус");
  await waitFor(() => evaluate("!document.querySelector('#now').hidden && document.querySelector('#now #dns-protection-list').children.length === 3"), "карточки зашифрованного DNS на обзоре");
  assert.deepEqual(await evaluate("[...document.querySelectorAll('#dns-protection-list .meta-chip')].map(node => node.textContent)"), ["Доступен", "Проверяется", "Состояние неизвестно"]);
  assert.equal(await evaluate("!!document.querySelector('[data-nav=dns-protection]')"), false);
  assert.equal(await evaluate("document.querySelector('[data-nav=now]').getAttribute('aria-current')"), "page");
  assert.equal(await evaluate("document.querySelector('#dns-protection-list').textContent.includes('[2001:db8::9]:853')"), true);
  assert.equal(await evaluate("document.querySelector('#dns-protection-list').textContent.includes('17 мс')"), true);
  assert.equal(await evaluate("document.querySelector('#dns-protection-more summary').textContent"), "Ещё 1 профиль · с ошибкой 1");
  await evaluate("document.querySelector('#dns-protection-more summary').click()");
  assert.equal(await evaluate("document.querySelector('#dns-protection-more').open && document.querySelector('#dns-protection-extra .meta-chip').textContent === 'Недоступен'"), true);
  const dot = liveState.dns_services[0];
  const dotV4 = dot.connections[0];
  const refusedResolver = liveState.dns_services[3];
  assert.deepEqual(await evaluate(`[...document.querySelectorAll('#dns-protection-list > li')].slice(0, 2).map(card =>
    [...card.querySelectorAll('.dns-service-connection')].map(path => path.dataset.family))`),
    [["4"], ["6"]], "карточки IPv4-only и IPv6-only показывают только своё семейство");
  const dotV6 = { ...dotV4, family: 6, resolved_ip: "2001:db8::53", answer_rtt_ms: 24 };
  const explicitV6 = { ...dot, profile_id: "explicit-ip", host: "2001:db8::54", connections: [{
    family: 6, resolved_ip: "2001:db8::54", state: "no_route", availability: "unavailable",
    checked_at: new Date().toISOString(), failure: "no_route", status_reason: "У роутера нет маршрута к этому адресу.",
  }] };
  liveState.dns_services[3] = explicitV6;
  dot.connections.push(dotV6);
  dotV4.answer_rtt_ms = 18;
  dot.usage_observed = null;
  liveState.dns_source_status = "activity_unknown";
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate(`(() => {
    const card = document.querySelector('#dns-protection-list > li');
    const variants = [...card.querySelectorAll('.dns-service-connection')];
    const diagnostics = card.querySelector('.dns-service-diagnostics');
    return variants.length === 2 && variants[0].dataset.family === '4' && variants[0].textContent.includes('18 мс')
      && variants[1].dataset.family === '6' && variants[1].textContent.includes('24 мс')
      && !diagnostics.open && diagnostics.textContent.includes('ЗапросыНеизвестно')
      && !card.querySelector('.dns-service-connections').textContent.includes('Настройка')
      && card.querySelector('.meta-chip').textContent === 'Доступен';
  })()`), "оба семейства одного профиля и отдельные подробности диагностики");
  assert.equal(await evaluate("document.querySelectorAll('#dns-protection-list > li').length"), 3, "дополнительное семейство не создаёт карточку");
  assert.equal(await evaluate("document.querySelector('#dns-protection-extra .meta-chip').textContent"), "Недоступен");
  assert.equal(await evaluate("document.querySelector('#dns-protection-extra').textContent.includes('[2001:db8::54]:853')"), true);
  await evaluate("document.querySelector('#dns-protection-list .dns-service-diagnostics summary').click()");
  assert.equal(await evaluate("document.querySelector('#dns-protection-list .dns-service-diagnostics').open"), true);
  assert.equal(await evaluate(`(() => {
    const first = document.querySelector('#dns-protection-list .dns-service-diagnostics');
    const next = document.querySelectorAll('#dns-protection-list .dns-service-diagnostics')[1];
    return first.firstElementChild.tagName === "SUMMARY"
      && first.querySelector('.dns-service-body').getClientRects().length > 0
      && next.querySelector('.dns-service-body').getClientRects().length === 0;
  })()`), true, "параметры каждого DNS-профиля раскрываются независимо");
  liveState.dns_source_status = "unknown";
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate("document.querySelector('#dns-protection-summary').textContent.includes('неизвестно')"), "потеря системного источника");
  assert.equal(await evaluate("document.querySelector('#dns-protection-list').textContent.includes('22 мс')"), true, "прошлый достоверный результат остаётся видимым");
  assert.equal(await evaluate("document.querySelector('#dns-protection-list .dns-service-diagnostics').open"), true,
    "обновление данных сохраняет раскрытые подробности профиля");
  liveState.dns_source_status = "known";
  liveState.dns_services[3] = { ...explicitV6, service_active: false };
  dot.connections.pop();
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate("document.querySelector('#dns-protection-extra').textContent.includes('Служба выключена')"),
    "выключенная служба не отображается доступной");
  assert.equal(await evaluate("document.querySelector('#dns-protection-extra .meta-chip').textContent"), "Состояние неизвестно");
  assert.equal(await evaluate("document.querySelector('#dns-protection-list li').querySelector('[data-family=\"6\"]') === null"), true, "неприменимый IPv6 исчезает из профиля");
  liveState.dns_services[3] = refusedResolver;
  dotV4.answer_rtt_ms = 17;
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate("document.querySelector('#dns-protection-extra .meta-chip')?.textContent === 'Недоступен'"), "отказ DNS-сервера остаётся ошибкой");
  await evaluate("document.querySelector('#dns-protection-more summary').click()");
  await call("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  assert.equal(await evaluate(`(() => {
    const cards = [...document.querySelectorAll('#dns-protection-list > li')].map(node => node.getBoundingClientRect());
    return cards.every(card => card.top === cards[0].top)
      && cards[0].right < cards[1].left && cards[1].right < cards[2].left;
  })()`), true, "на широком экране три карточки идут в один ряд");
  if (captureDir) {
    await delay(350);
    const screenshot = await call("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(captureDir, "dns-overview-desktop.png"), Buffer.from(screenshot.data, "base64"));
  }
  const masterSwitch = "document.getElementById('meta-protection-switch')";
  const metaDetailsHidden = `(() => {
    const blocks = ["meta-protection-families", "meta-protection-infrastructure"];
    return blocks.every(id => getComputedStyle(document.getElementById(id)).display === "none");
  })()`;
  assert.equal(await evaluate(masterSwitch + ".getAttribute('aria-checked')"), "false");
  assert.equal(await evaluate(metaDetailsHidden), true, "при первом запуске сервисы, CDN и источники скрыты");
  await evaluate(masterSwitch + ".click()");
  await waitFor(() => evaluate(masterSwitch + ".getAttribute('aria-checked') === 'true'"), "Meta Protection включается общим переключателем");
  assert.equal(await evaluate(metaDetailsHidden), false, "после включения доступны все сервисы");
  const metaSwitch = "[data-family=instagram] [role=switch]";
  const metaLabel = "[data-family=instagram] .meta-family-head";
  assert.equal(await evaluate("document.querySelectorAll('#meta-protection [role=switch]').length"), 8);
  assert.equal(await evaluate("document.querySelectorAll('#meta-protection-families .meta-mark').length"), 6);
  assert.equal(await evaluate("fetch('/assets/meta-marks.png').then(r => r.ok && r.headers.get('Content-Type') === 'image/png')"), true);
  assert.match(await evaluate(`document.querySelector('${metaLabel}').textContent`), /TLS частично 5\/6/);
  await call("Page.bringToFront");
  await evaluate(`document.querySelector('${metaLabel}').focus()`);
  assert.equal(await evaluate(`document.activeElement.matches('${metaLabel}')`), true);
  await call("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", text: "\r", windowsVirtualKeyCode: 13 });
  await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  await waitFor(() => evaluate("document.querySelector('[data-family=instagram] details').open"), "раскрытие Instagram с клавиатуры");
  assert.match(await evaluate("document.querySelector('[data-family=instagram] .meta-detail-body').textContent"), /2a03:2880::1/);
  await evaluate("document.querySelector('.meta-infrastructure > details summary').click()");
  assert.match(await evaluate("document.querySelector('#meta-protection-sources').textContent"), /geosite-meta/);
  await evaluate(`document.querySelector('${metaSwitch}').focus()`);
  await call("Input.dispatchKeyEvent", { type: "keyDown", key: " ", code: "Space", text: " ", windowsVirtualKeyCode: 32 });
  await call("Input.dispatchKeyEvent", { type: "keyUp", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
  await waitFor(() => evaluate(`document.querySelector('${metaSwitch}').getAttribute('aria-checked') === 'false'`), "выключение защиты Instagram с клавиатуры");
  assert.equal(await evaluate(`document.activeElement.matches('${metaSwitch}') && document.querySelector('[data-family=instagram] details').open`), true);
  assert.equal(await evaluate("document.querySelector('[data-family=facebook] [role=switch]').getAttribute('aria-checked')"), "true");
  const beforeReload = await evaluate("performance.timeOrigin");
  await call("Page.reload");
  await waitFor(() => evaluate(`performance.timeOrigin > ${beforeReload} && document.querySelector('${metaSwitch}')?.getAttribute('aria-checked') === 'false'`), "настройка Instagram переживает перезагрузку панели");
  await evaluate(`document.querySelector('${metaSwitch}').scrollIntoView({block:'center'})`);
  const thumb = await evaluate(`(() => {
    const {left, right, top, height} = document.querySelector('${metaSwitch} .meta-switch-track').getBoundingClientRect();
    return { left: left + 6, right: right - 6, y: top + height / 2 };
  })()`);
  await call("Input.dispatchMouseEvent", { type: "mousePressed", x: thumb.left, y: thumb.y, button: "left", clickCount: 1 });
  await call("Input.dispatchMouseEvent", { type: "mouseMoved", x: thumb.right, y: thumb.y, button: "left", buttons: 1 });
  await call("Input.dispatchMouseEvent", { type: "mouseReleased", x: thumb.right, y: thumb.y, button: "left", clickCount: 1 });
  await waitFor(() => evaluate(`document.querySelector('${metaSwitch}').getAttribute('aria-checked') === 'true'`), "включение защиты Instagram перетаскиванием");
  assert.deepEqual(fs.readFileSync(serviceLog, "utf8").split("\n").filter(line => line.startsWith("meta-protection-product")), [
    "meta-protection-product instagram off", "meta-protection-product instagram on",
  ]);
  await evaluate(masterSwitch + ".click()");
  await waitFor(() => evaluate(masterSwitch + ".getAttribute('aria-checked') === 'false'"), "общий переключатель останавливает Meta Protection");
  assert.equal(await evaluate(metaDetailsHidden), true, "после выключения сервисы снова скрыты");
  assert.equal(await evaluate("document.querySelector('[data-family=facebook] [role=switch]').getAttribute('aria-checked')"), "true");
  await evaluate(masterSwitch + ".click()");
  await waitFor(() => evaluate(masterSwitch + ".getAttribute('aria-checked') === 'true'"), "общий переключатель восстанавливает Meta Protection");
  assert.equal(await evaluate(metaDetailsHidden), false);
  for (const width of [1440, 390, 320]) {
    await call("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
    await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
    await evaluate("document.querySelector('#meta-protection').scrollIntoView()");
    const frame = await evaluate(`(() => {
      const card = document.getElementById('meta-protection');
      const { left, top, width, height } = card.getBoundingClientRect();
      return { x: left + scrollX, y: top + scrollY, width, height, scale: 1,
        overflow: card.scrollWidth > card.clientWidth,
        motion: getComputedStyle(card.querySelector('.meta-switch-thumb')).transitionProperty };
    })()`);
    assert.equal(frame.overflow, false, `карточка Meta помещается при ${width} px`);
    assert.equal(frame.motion, "none");
    if (captureDir && width !== 320) {
      const {overflow, motion, ...clip} = frame;
      const screenshot = await call("Page.captureScreenshot", { format: "png", clip, captureBeyondViewport: true });
      fs.writeFileSync(path.join(captureDir, `meta-protection-${width}.png`), Buffer.from(screenshot.data, "base64"));
    }
  }
  await call("Emulation.setEmulatedMedia", { features: [] });
  for (const width of [320, 390, 768, 1024]) {
    await call("Emulation.setDeviceMetricsOverride", { width, height: 844, deviceScaleFactor: 1, mobile: false });
    assert.equal(await evaluate("document.documentElement.scrollWidth <= innerWidth && [...document.querySelectorAll('.index a')].every(el => { const rect = el.getBoundingClientRect(); return rect.width >= 44 && rect.right <= innerWidth && rect.bottom <= innerHeight; })"), true, `обзор и навигация помещаются на экране ${width} px`);
  }
  await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: false });
  assert.equal(await evaluate(`document.querySelectorAll('#dns-protection-list > li')[1]
    .querySelector('.dns-service-body').getClientRects().length`), 0, "на телефоне параметры DNS скрыты при загрузке");
  await evaluate("document.querySelectorAll('#dns-protection-list > li')[1].querySelector('summary').click()");
  assert.equal(await evaluate(`(() => {
    const row = document.querySelectorAll('#dns-protection-list > li')[1];
    const protocol = row.querySelector('.dns-service-protocol').getBoundingClientRect();
    const host = row.querySelector('.dns-service-host').getBoundingClientRect();
    const address = row.querySelector('.dns-service-address').getBoundingClientRect();
    const status = row.querySelector('.meta-chip').getBoundingClientRect();
    const details = row.querySelector('.dns-service-details').getBoundingClientRect();
    return status.left > protocol.right && status.bottom <= host.top
      && host.bottom < address.top && address.bottom < details.top && row.scrollWidth <= row.clientWidth;
  })()`), true, "на телефоне длинное имя, адрес, план и статус помещаются в карточку");
  await evaluate("document.querySelectorAll('#dns-protection-list > li')[1].querySelector('summary').click()");
  if (captureDir) {
    await evaluate("document.querySelector('#dns-protection').scrollIntoView()");
    await delay(350);
    const screenshot = await call("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(captureDir, "dns-overview-mobile.png"), Buffer.from(screenshot.data, "base64"));
  }
  const doq = liveState.dns_services[1];
  const previousDnsConnection = doq.connections[0];
  doq.connections[0] = {
    ...previousDnsConnection,
    state: "recovered",
    availability: "recovered",
    checked_at: new Date().toISOString(),
    dns_answer_via_plan: true,
    dns_answer_confirmed: false,
  };
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  const doqBadge = "document.querySelectorAll('#dns-protection-list .meta-chip')[1].textContent";
  await waitFor(async () => await evaluate(doqBadge) === "Состояние неизвестно", "статус восстановления требует подтверждённого DNS-ответа");
  doq.connections[0].dns_answer_confirmed = true;
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(async () => await evaluate(doqBadge) === "Восстановлен", "подтверждённый DNS-ответ отображает восстановление");
  doq.connections[0] = previousDnsConnection;
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await call("Emulation.clearDeviceMetricsOverride");
  await evaluate("location.hash = '#diagnostics'");
  await waitFor(() => evaluate("document.querySelector('#diagnostic-state')?.dataset.phase === 'off'"), "загрузка управления диагностикой");
  assert.equal(await evaluate("(() => { const help = document.querySelector('#diagnostic-history-help'); return !!help && help.querySelector('summary')?.textContent.includes('Что сохраняется') && help.textContent.includes('120') && help.textContent.includes('64') && help.textContent.includes('домены и IP-адреса') && help.textContent.includes('никуда не отправляется'); })()"), true, "диагностика сообщает пределы истории и состав локального отчёта как d2o");
  await evaluate("document.querySelector('#diagnostic-toggle').click()");
  await waitFor(() => evaluate("document.querySelector('#diagnostic-state').dataset.enabled === 'true'"), "включение локальной диагностики");
  assert.equal(await evaluate("document.querySelector('#diagnostic-download').hidden"), true, "скачивание ждёт первого снимка контроллера");
  assert.equal(await evaluate("document.querySelector('#diagnostic-data').hidden"), true, "пустые виджеты скрыты до первого снимка");
  const diagDir = path.join(work, "diagnostics");
  const now = Math.floor(Date.now() / 1000);
  const common = { processes: [{ name: "r2o-controller", pid: 7, rss_kib: 2048, anon_kib: 1024 }], workers_running: 1 };
  const diag = {
    enabled: true, sample_interval_ms: 60000,
    samples: Array.from({ length: 18 }, (_, i) => ({
      ...common, at: now - (17 - i) * 60,
      processes: [{ ...common.processes[0], rss_kib: 4879 + [0, 35, 13, 126, 109, 153][i % 6] + i * 23,
        anon_kib: 1120 + i * 7 },
      { name: "r2o-datapath", pid: 20, start_ticks: 124, rss_kib: 6280 + i * 6, anon_kib: 2010 + i }]
    })),
    memory_tracking: { sites: [{ name: "Пустой участок", live_bytes: 0, peak_bytes: 0, created: 0 }] },
    madvise: { successes: 0, failures: 0, requested_bytes: 0, errno: [] },
    limit_transitions: [
      { at: now - 60, measurement_limit: 2, measurement_slots: 64, limit_reason: ["no-current-resource-limit"] },
      { at: now, measurement_limit: 2, measurement_slots: 64, limit_reason: ["no-current-resource-limit"], cpu_valid: true }
    ],
    memory_details: [{ name: "r2o-controller", latest: { pid: 7, smaps_rollup_status: "unsupported" } }],
    events: [
      { id: 2, at: now, target: "v.example", outcome: "inconclusive", reason: "истёк срок пробы", elapsed_ms: 2200 },
      { id: 1, at: now - 1, target: "ok.example", outcome: "plan-found" }
    ]
  };
  fs.writeFileSync(path.join(diagDir, "report.json"), JSON.stringify(diag), {mode: 0o600});
  await waitFor(() => evaluate("document.querySelector('#diagnostic-state').dataset.phase === 'ready'"), "первый отчёт появляется после короткого опроса");
  assert.equal(await evaluate("document.querySelector('#diagnostic-data').hidden"), false, "появились данные");
  assert.equal(await evaluate("document.querySelector('#diagnostic-memory-chart').getBoundingClientRect().height > 0"), true, "график виден после первого отчёта");
  assert.equal(await evaluate(`(() => {
    const process = document.querySelector('#diagnostic-memory-process');
    return process.options.length === 2 && process.getClientRects().length === 1
      && !document.querySelector('#diagnostic-memory-process-trigger');
  })()`), true, "диагностика показывает один нативный выбор процесса");
  await evaluate(`(() => {
    const process = document.querySelector('#diagnostic-memory-process');
    process.value = 'r2o-datapath'; process.dispatchEvent(new Event('change'));
  })()`);
  assert.match(await evaluate("document.querySelector('#diagnostic-memory-chart').getAttribute('aria-label')"), /^Датапат/);
  await evaluate(`(() => {
    const process = document.querySelector('#diagnostic-memory-process');
    process.value = 'r2o-controller'; process.dispatchEvent(new Event('change'));
  })()`);
  await evaluate("document.querySelector('#diagnostic-event-filter-trigger').scrollIntoView({block:'center', behavior:'instant'})");
  await evaluate("document.querySelector('#diagnostic-event-filter-trigger').click()");
  await waitFor(() => evaluate("document.querySelector('#diagnostic-event-filter-options').matches(':popover-open')"), "меню фильтра открывается в панели");
  await press("End", 35);
  assert.equal(await evaluate("document.activeElement.textContent.trim()"), "Без подтверждения");
  await press("Enter", 13);
  assert.equal(await evaluate("document.querySelector('#diagnostic-event-filter').value"), "unconfirmed");
  await evaluate("const f = document.querySelector('#diagnostic-event-filter'); f.value = 'all'; f.dispatchEvent(new Event('change'))");
  for (const [width, height] of [[1440, 1050], [1024, 900], [768, 1024], [390, 1020], [320, 900]]) {
    await call("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 600 });
    await waitFor(() => evaluate("(() => {const svg = document.querySelector('#diagnostic-memory-chart'); return getComputedStyle(svg).visibility === 'visible' && Math.abs(svg.viewBox.baseVal.width - svg.clientWidth) <= 2})()"), "график занимает доступную ширину " + width);
    assert.equal(await evaluate("document.documentElement.scrollWidth <= innerWidth"), true, "без горизонтальной прокрутки на " + width);
    if (captureDir && (width === 1440 || width === 390)) {
      await evaluate("scrollTo(0, 0)");
      const screenshot = await call("Page.captureScreenshot", { format: "png" });
      fs.writeFileSync(path.join(captureDir, "diagnostics-" + width + ".png"), Buffer.from(screenshot.data, "base64"));
    }
  }
  await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
  await evaluate("document.querySelector('[data-memory-range=\\\"24\\\"]').click()");
  assert.equal(await evaluate("new URLSearchParams(location.search).get('diag-period')"), "24");
  assert.equal(await evaluate("document.querySelector('#diagnostic-memory-chart').getAnimations().length"), 0, "уменьшение движения отключает анимацию графика");
  await evaluate("document.querySelector('[data-memory-range=\\\"2\\\"]').click()");
  await call("Emulation.setEmulatedMedia", { features: [] });
  await call("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1050, deviceScaleFactor: 1, mobile: false });
  await evaluate("document.querySelector('#diagnostic-event-filter').value = 'unconfirmed'; document.querySelector('#diagnostic-event-filter').dispatchEvent(new Event('change'))");
  assert.equal(await evaluate("document.querySelector('#diagnostic-event-list').childElementCount"), 1);
  await evaluate("document.querySelector('#diagnostic-event-list summary').click()");
  assert.equal(await evaluate("document.querySelector('#diagnostic-event-list details[open] p').textContent"), "истёк срок пробы");
  assert.equal(await evaluate("document.querySelector('#diagnostic-cursor-input').disabled"), false, "можно выбрать снимок");
  await evaluate("(() => { const graph = document.querySelector('#diagnostic-memory-chart'); graph.dispatchEvent(new MouseEvent('click', { clientX: graph.getBoundingClientRect().left + 40 })); })()");
  assert.equal(await evaluate("document.querySelector('#diagnostic-cursor-input').value"), "0", "нажатие по графику выбирает ближайший снимок");
  await evaluate("document.querySelector('#diagnostic-cursor-input').focus()");
  await call("Input.dispatchKeyEvent", { type: "rawKeyDown", key: "ArrowRight", code: "ArrowRight", windowsVirtualKeyCode: 39 });
  await call("Input.dispatchKeyEvent", { type: "keyUp", key: "ArrowRight", code: "ArrowRight", windowsVirtualKeyCode: 39 });
  assert.equal(await evaluate("document.querySelector('#diagnostic-cursor-input').value"), "1", "ползунок переключает снимок с клавиатуры");
  assert.equal(await evaluate("document.querySelector('#diagnostic-technical').hidden"), true, "нет технических карточек без измерений");
  assert.equal(await evaluate("document.querySelector('#diagnostic-warnings').textContent.includes('smaps_rollup')"), false, "отсутствие smaps_rollup не показывает подсказку");
  const fullSamples = diag.samples;
  diag.samples = fullSamples.slice(-2);
  fs.writeFileSync(path.join(diagDir, "report.json"), JSON.stringify(diag));
  await evaluate("document.querySelector('#diagnostic-refresh').click()");
  await waitFor(() => evaluate("document.querySelector('#diagnostic-memory-chart').dataset.points === '2'"), "короткий ряд доступен");
  assert.equal(await evaluate("document.querySelector('#diagnostic-memory-chart path[data-series=rss]').getAttribute('d').includes('L')"), true,
    "два соседних снимка образуют линию");
  const recent = fullSamples.slice(-3);
  diag.samples = [{ ...recent[0], at: recent[0].at - 120 }, recent[1],
    { ...recent[2], processes: [{ ...recent[2].processes[0], pid: 8 }] }];
  fs.writeFileSync(path.join(diagDir, "report.json"), JSON.stringify(diag));
  await evaluate("document.querySelector('#diagnostic-refresh').click()");
  await waitFor(() => evaluate("document.querySelector('#diagnostic-memory-chart').dataset.points === '3'"), "ряд с разрывами доступен");
  assert.equal(await evaluate("document.querySelector('#diagnostic-memory-chart path[data-series=rss]')"), null,
    "через пропущенный снимок и смену PID линия не рисуется");
  assert.equal(await evaluate("document.querySelectorAll('#diagnostic-memory-chart circle.diag-line-rss.diag-point:not(.diag-cursor-mark *)').length"),
    3, "изолированные замеры остаются видимыми");
  diag.samples = fullSamples;
  diag.memory_tracking.sites.push({ name: "Измеренный участок", peak_bytes: 2048, created: 1, destroyed: 1 });
  diag.madvise.failures = 1;
  diag.limit_transitions.push({ at: now, measurement_limit: 1, measurement_slots: 64, limit_reason: ["cpu"] });
  fs.writeFileSync(path.join(diagDir, "report.json"), JSON.stringify(diag));
  await evaluate("document.querySelector('#diagnostic-refresh').click()");
  await waitFor(() => evaluate("!document.querySelector('#diagnostic-technical').hidden"), "технические данные появились");
  assert.equal(await evaluate("document.querySelector('#diagnostic-memory-sites').children.length"), 1);
  assert.equal(await evaluate("document.querySelector('#diagnostic-aimd-history').children.length"), 1);
  assert.equal(await evaluate("document.querySelector('#diagnostic-madvise-errors').parentElement.hidden"), true);
  assert.equal(await evaluate("document.querySelector('#diagnostic-madvise-results').textContent"), "ошибок 1");

  await evaluate("document.querySelector('#diagnostic-toggle').click()");
  await waitFor(() => evaluate("document.querySelector('#diagnostic-state').dataset.phase === 'paused'"), "остановка записи");
  assert.equal(fs.existsSync(path.join(diagDir, "report.json")), true, "остановка сохраняет отчёт");
  await evaluate("document.querySelector('#diagnostic-clear').click()");
  assert.equal(await evaluate("document.querySelector('#diagnostic-stop-dialog').open"), true);
  await evaluate("document.querySelector('#diagnostic-stop-dialog button[value=cancel]').click()");
  assert.equal(await evaluate("document.querySelector('#diagnostic-stop-dialog').open"), false);
  assert.equal(fs.existsSync(path.join(diagDir, "report.json")), true, "отмена сохраняет историю");
  await evaluate("document.querySelector('#diagnostic-clear').click(); document.querySelector('#diagnostic-stop-dialog button[value=clear]').click()");
  await waitFor(() => evaluate("document.querySelector('#diagnostic-state').dataset.phase === 'paused' && document.querySelector('#diagnostic-data').hidden"), "очистка истории при остановленном сборе");
  assert.equal(fs.existsSync(path.join(diagDir, "report.json")), false);
  await evaluate("location.hash = '#now'");
  await waitFor(() => evaluate("!document.querySelector('#now').hidden"), "возврат к обзору");
  assert.equal(await evaluate("document.title.includes('R2O')"), true, "заголовок страницы панели");
  assert.equal(await evaluate("document.querySelector('#r2o-settings') === null && ![...document.querySelectorAll('.index a')].some((link) => link.hash === '#r2o-settings')"), true, "в панели нет отдельного раздела настроек, которого нет в d2o");
  assert.equal(await evaluate("document.querySelectorAll('#app > section').length"), 6, "карточки DNS остаются внутри обзора");
  assert.equal(await evaluate("[...document.querySelectorAll('#app > section')].filter((section) => !section.hidden).length"), 1, "одновременно открыт ровно один экран");
  assert.equal(await evaluate("document.querySelector('#now').hidden === false"), true, "панель открывается на обзоре");
  assert.equal(await evaluate("!!document.querySelector('#overview-metrics .metric-card')"), true, "обзор содержит быстрые переходы к разделам");
  assert.equal(await evaluate("document.querySelectorAll('#overview-metrics .metric-card').length"), 6, "сводка обзора показывает шесть ключевых чисел");
  assert.equal(await evaluate("getComputedStyle(document.body).fontFamily.includes('Manrope')"), true, "оформление использует Manrope");
  assert.equal(await evaluate("document.fonts.check('500 16px Manrope')"), true, "локальный шрифт Manrope загружен");
  assert.equal(await evaluate("document.fonts.check('600 16px Unbounded')"), true, "локальный шрифт Unbounded загружен");
  assert.equal(await evaluate("document.fonts.check('400 16px \\\"IBM Plex Mono\\\"')"), true, "локальный IBM Plex Mono загружен");
  assert.equal(await evaluate("document.querySelectorAll('script:not([src])').length"), 0, "встроенные скрипты макета не исполняются");
  await waitFor(() => evaluate("document.querySelector('#now-title').textContent !== 'Получаем состояние…'"), "состояние из /api/status");
  assert.equal(await evaluate("document.querySelector('#now-lede').textContent"), "Измеряем сетевые сбои и проверяем стратегии.");
  assert.deepEqual(await evaluate(`[
    document.querySelector("#discovery-cpu-label").textContent,
    document.querySelector("#discovery-cpu-value").textContent,
    document.querySelector("#discovery-cpu-fill").style.transform,
    document.querySelector("#discovery-cpu-core").textContent,
    document.querySelector("#discovery-cpu-reserve").textContent
  ]`), ["Общая нагрузка CPU", "48%", "scaleX(0.48)", "100%", "7%"], "общая загрузка, ядро и резерв отображаются раздельно");
  await waitFor(() => evaluate("document.querySelector('.bindings tr[data-enabled] .t')?.textContent === 'Голос Discord'"), "голосовая привязка в коробке");
  assert.equal(await evaluate("document.querySelectorAll('.bindings .proof-note').length"), 0, "голосовая привязка не добавляет заметку о RTP, которой нет в d2o");
  assert.equal(await evaluate("[...document.querySelectorAll('.search-plan-details')].some(plan => !plan.hidden)"), true, "карточка Discovery раскрывает сведения о плане");
  await waitFor(() => evaluate("[...document.querySelectorAll('.search-call .search-question')].some((row) => !row.hidden && row.textContent.includes('Что проверяем: whole'))"), "текущий вопрос классификатора в карточке Discovery");
  assert.equal(await evaluate("document.querySelectorAll('#searches .search').length"), 4, "активные стадии представлены карточками, очередь выделена отдельно");
  assert.equal(await evaluate("document.querySelectorAll('#searches .search-visual').length"), 4, "у каждой карточки поиска есть сцена текущего этапа");
  assert.equal(await evaluate("[...document.querySelectorAll('#searches .search')].every((row) => row.dataset.stage !== undefined && row.dataset.stage !== 'idle')"), true, "сцена поиска получает этап подбора для анимации");
  assert.equal(await evaluate("document.querySelectorAll('#searches .queue-list .queue-target').length"), 1, "ожидающие замера собраны в список D2O");
  assert.equal(await evaluate("document.querySelector('#workload-meta').textContent"), "4 в работе · 1 ждут", "ожидающая задача не входит в число работающих");
  assert.equal(await evaluate("(() => { const row = [...document.querySelectorAll('#searches .search')].find((item) => item.querySelector('.search-target')?.textContent === 'starting.example'); return row?.querySelector('.search-phase')?.textContent === 'Заводим поиск' && row.querySelector('.search-clock').textContent.includes('идёт') && !row.querySelector('.search-clock').textContent.includes('в очереди'); })()"), true, "фаза запуска совпадает с D2O и не дублирует отдельную очередь");
  assert.equal(await evaluate(`(() => {
    const row = [...document.querySelectorAll('.search')].find(item => item.querySelector('.search-target')?.textContent === 'failed.example');
    const details = row.querySelector('.search-plan-details');
    return row.dataset.callState === 'running' && row.querySelector('.search-call .search-phase').textContent === 'Проверяем план'
      && !!row.querySelector('.status-mark') && !details.open
      && details.querySelector('.search-findings').textContent.includes('Resource temporarily unavailable');
  })()`), true, "ошибка отдельной пробы остаётся в подробностях активного поиска");
  assert.equal(await evaluate("[...document.querySelectorAll('.search .track')].every((track) => track.querySelectorAll('.track-step').length === 7 && track.querySelector('.track-step:last-child').textContent === 'Подтверждено')"), true, "карточка использует исходные семь этапов d2o");
  const liveSearch = liveState.searches.find((search) => search.target === "classifying.example");
  liveSearch.probes = 2;
  liveSearch.question = "split";
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate("[...document.querySelectorAll('.search-call .search-question')].some((row) => !row.hidden && row.textContent.includes('Что проверяем: split'))"), "автоматическое обновление вопроса и числа зондов");
  const closed = liveState.searches.find((search) => search.target === "failed.example");
  Object.assign(closed, {
    phase: "подбор завершился без сохранения плана", outcome: "closed", completed_at: new Date().toISOString(),
    candidate: "", probe_applied: false,
    last_result: "TLS-рукопожатие не завершилось: Connection reset by peer (os error 104)"
  });
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate("document.querySelector('.search[data-outcome=closed][data-call-state=failed] .search-call') !== null"),
    "неудачный поиск показывает итог без сохранённого плана");
  assert.deepEqual(await evaluate(`(() => {
    const row = document.querySelector('.search[data-outcome=closed]');
    const details = row.querySelector('.search-plan-details');
    const closed = !details.open && !details.hidden;
    details.querySelector('summary').click();
    const proof = details.querySelector('.search-findings');
    return [closed, row.dataset.stage, details.open, row.querySelector('.search-phase').textContent,
      proof.textContent.includes('Не подтверждено'), proof.textContent.includes('Connection reset by peer (os error 104)')];
  })()`), [true, "5", true, "Обход не подтверждён", true, true],
  "в раскрытых деталях сохранены данные о применении и полная ошибка зонда");
  const resolved = liveState.searches.shift();
  liveState.searches.push(resolved);
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate("[...document.querySelectorAll('#searches .search-target')].at(-1)?.textContent === 'blocked.example'"), "проверяемый поиск находится внизу списка");
  await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] });
  Object.assign(resolved, {
    phase: "подбор завершён", outcome: "saved", completed_at: new Date().toISOString(),
    plan_id: "test-plan", probe_applied: true, verified: true, verify_level: 3,
    source: "запасной перебор d2o",
    last_result: "Продолжаю запасной перебор D2O. Получен полный HTTPS-ответ.",
  });
  liveState.boxes[0].plans.push({ id: "test-plan", text: "r2o-plan 1 5\nproto tcp tls\nsplit sni_middle +0\norder reverse" });
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await evaluate("document.dispatchEvent(new Event('visibilitychange'))");
  await waitFor(() => evaluate("document.querySelector('#searches .search:first-child[data-outcome=saved] summary')?.dataset.mark === 'Сохранено · test-plan'"), "завершённый поиск поднялся наверх, хотя в снимке он последний");
  assert.equal(await evaluate(`(() => {
    const row = document.querySelector('.search[data-outcome=saved][data-call-state=saved]');
    const details = row.querySelector('.search-plan-details');
    const proof = details.querySelector('.search-findings').textContent;
    return !details.open && proof.includes('Применён для проверки') && proof.includes('Сервис ответил на проверку')
      && proof.includes('полный HTTPS-ответ') && !row.querySelector('.search-proof');
  })()`), true, "подтверждение, уровень и подробный ответ помещены в карточку плана");
  assert.equal(await evaluate("document.querySelector('.search[data-outcome=saved] summary').textContent.includes('Разделяет TLS-приветствие')"), true);
  assert.equal(await evaluate("document.querySelector('.search[data-outcome=saved]').textContent.toLowerCase().includes('d2o')"), false, "старые снимки отображаются без имени донора");
  if (captureDir) {
    await call("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
    await waitFor(() => evaluate("document.querySelector('.search[data-outcome=saved] .track-step:last-child').dataset.state === 'now'"), "маркер дошёл до итога");
    await evaluate("document.querySelector('.search[data-outcome=saved]').scrollIntoView({block:'center'})");
    const screenshot = await call("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(captureDir, "discovery-result.png"), Buffer.from(screenshot.data, "base64"));
  }
  await waitFor(() => evaluate(`(() => {
    const row = document.querySelector('#searches .search:first-child[data-outcome=saved]');
    if (!row) return false;
    const style = getComputedStyle(row);
    return +style.opacity > 0 && +style.opacity < 1 && new DOMMatrixReadOnly(style.transform).m42 < 0;
  })()`), "готовый результат гаснет и уходит вверх с первой позиции");
  await waitFor(() => evaluate("!document.querySelector('#searches .search[data-outcome=saved]')"), "завершённая карточка удалена из списка");
  assert.equal(await evaluate("document.querySelectorAll('#searches .search').length"), 3, "оставшиеся активные карточки видны");
  await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
  for (const [name, width, height] of [
    ["телефон", 320, 740],
    ["широкий телефон", 390, 844],
    ["граница компактного режима", 640, 1020],
    ["планшет", 768, 1024],
    ["ноутбук", 1280, 800],
    ["широкий экран", 1920, 1080],
  ]) {
    await call("Emulation.setDeviceMetricsOverride", {
      width,
      height,
      deviceScaleFactor: 1,
      mobile: width < 600,
    });
    await evaluate("scrollTo(0, 0)");
    await delay(100);
    const layout = await evaluate(`(() => ({
      overflow: document.documentElement.scrollWidth > innerWidth,
      nav: [...document.querySelectorAll('.index a')].every((link) => link.getClientRects().length > 0),
      mast: document.querySelector('.mast').getBoundingClientRect().width > 0
    }))()`);
    assert.equal(layout.overflow, false, `${name}: нет горизонтальной прокрутки`);
    assert.equal(layout.nav, true, `${name}: пункты навигации видны`);
    assert.equal(layout.mast, true, `${name}: шапка панели отображается`);

    if (captureDir && [320, 1280].includes(width)) {
      const screenshot = await call("Page.captureScreenshot", { format: "png" });
      fs.writeFileSync(path.join(captureDir, `r2o-panel-${width}.png`), Buffer.from(screenshot.data, "base64"));
    }
  }

  assert.equal(await evaluate("document.querySelector('#searches .search[data-outcome=saved]')"), null, "старый результат из следующего снимка не появляется снова");
  resolved.completed_at = new Date().toISOString();
  liveState.searches = [resolved];
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await evaluate("document.dispatchEvent(new Event('visibilitychange'))");
  await waitFor(() => evaluate("document.querySelectorAll('#searches .search[data-outcome=saved]').length === 1"), "финальная карточка показывается с уменьшенным движением");
  await waitFor(() => evaluate("document.querySelector('#searches .quiet') !== null"), "после ухода последней карточки появляется пустой список");
  assert.equal(await evaluate("document.querySelector('#searches .quiet').textContent"), "Результаты для сайтов сохраняются в каталоге, для DNS отображаются в карточке сервера.", "пустой список показывает, где появятся результаты, независимо от счётчика замеров");
  await waitFor(() => evaluate("!!document.querySelector('#telegram-body')?.dataset.state"), "обновление статуса Telegram");
  assert.equal(await evaluate("document.querySelector('#telegram-body').dataset.state"), "stopped", "неизвестный Telegram status использует fallback d2o");

  await evaluate(`document.querySelector('a[href="#telegram"]').click()`);
  assert.equal(await evaluate("location.hash"), "#telegram", "ссылка навигации открывает раздел Telegram");
  assert.equal(await evaluate("document.querySelector('#telegram').hidden === false && document.querySelector('#now').hidden === true"), true, "переход меняет активный экран, а не просто прокручивает страницу");
  assert.equal(await evaluate("document.querySelector('.index a[data-nav=\\\"telegram\\\"]').getAttribute('aria-current')"), "page", "активный пункт навигации отмечен");
  await waitFor(() => evaluate(
    "(() => { const body = document.querySelector('#telegram-body'); const c = document.querySelector('#telegram-body canvas.tg-flow-canvas'); return !!body && !!body.dataset.state && !!document.querySelector('.tg-hero') && !!c && c.width >= 300 && document.querySelectorAll('.tg-route').length === 4; })()"
  ), "новый экран Telegram-прокси и карта маршрутов смонтированы");
  assert.equal(await evaluate("document.querySelectorAll('.tg-stat').length"), 6, "у прокси шесть ровных карточек состояния");
  assert.equal(await evaluate("document.querySelector('#telegram').textContent.toLowerCase().includes('туннель')"), false, "в разделе Telegram больше нет слова «туннель»");
  await waitFor(() => evaluate("document.querySelector('.tg-check-details')?.textContent.includes('DC5')"), "диагностика маршрутов Telegram DC1–DC5");
  assert.equal(await evaluate("document.querySelector('.tg-check-details').textContent.includes('Все пять DC')"), false, "частичный resPQ не отображается как успех для всех DC");
  assert.equal(await evaluate("document.querySelector('.tg-check-details').textContent.includes('DC2 · маршруты заблокированы')"), true, "панель показывает заблокированный DC из отчёта");
  assert.equal(await evaluate("document.querySelector('.tg-check-details').textContent.includes('HTTP 0')"), false, "отсутствующий HTTP status не превращается в ноль");
  assert.equal(await evaluate("[...document.querySelectorAll('#telegram-body button')].some(button => button.textContent.includes('Проверить DC1–DC5'))"), true, "в Telegram-секции есть запуск активной проверки");
  assert.equal(await evaluate("document.querySelector('[data-control=telegram-check-extended]')?.textContent.includes('Расширенная проверка')"), true, "расширенная проверка запускается отдельно");
  assert.equal(await evaluate("document.querySelector('.tg-check-details').textContent.includes('всего до resPQ 14 мс')"), true, "показано полное время до MTProto-ответа");
  assert.equal(await evaluate("document.querySelector('.tg-check-details').textContent.includes('расширенная проверка')"), true, "таймаут публичного пула помечен как результат расширенной проверки");
  assert.equal(await evaluate("[...document.querySelectorAll('#telegram-body button')].some(button => button.textContent.includes('Запустить прокси'))"), true, "остановленный прокси предлагает запуск");
  assert.equal(await evaluate("[...document.querySelectorAll('#telegram-body button')].some(button => button.textContent.includes('Остановить прокси'))"), false, "остановленный прокси не предлагает остановку");
  assert.equal(await evaluate("document.querySelector('[data-tg-state-badge]').textContent"), "Остановлен", "состояние прокси показано явно");

  await call("Emulation.setDeviceMetricsOverride", {
    width: 1280,
    height: 800,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await evaluate("scrollTo(0, 0)");
  await delay(500);
  assert.equal(await evaluate("document.querySelector('.tg-flow-canvas').classList.contains('is-compact')"), false,
    "широкая карта располагает клиент, прокси, маршруты и DC в одном ряду");
  if (captureDir) {
    const screenshot = await call("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(captureDir, "r2o-panel-telegram-1280.png"), Buffer.from(screenshot.data, "base64"));
  }
  await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] });
  await evaluate("document.querySelector('.tg-flow-orb').scrollIntoView({ block: 'center', behavior: 'instant' })");
  await evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))");
  await evaluate(`(() => {
    const canvas = document.querySelector('.tg-flow-canvas');
    const context = document.querySelector('.tg-flow-particles').getContext('2d');
    const arc = context.arc;
    window.routeMapSamples = 0;
    window.routeMapSizes = new Set();
    window.routeMapColors = new Set();
    context.arc = function (...args) {
      window.routeMapSamples += 1;
      window.routeMapSizes.add(args[2]);
      window.routeMapColors.add(this.fillStyle);
      return arc.apply(this, args);
    };
    window.routeMapFixture = { active_connections: 10, accepted_connections: 993, max_connections: 64,
      active_sessions: Array.from({ length: 10 }, (_, i) => ({ id: i + 1, dc: i === 9 ? 203 : 2,
        is_media: i === 9, fallback_state: 'selected', fallback_transport: i === 0 ? 'cloudflare_worker' : 'cloudflare_proxy',
        selected_transport: i === 0 ? 'cloudflare_worker' : 'cloudflare_proxy', stage: 'first_wss_binary_response',
        telegram_response_seen: true, bytes_from_clients: 0, bytes_from_upstreams: 0 })) };
    const random = Math.random;
    const draws = [0.1, 0.15, 0.75, 0.95];
    let draw = 0;
    Math.random = () => draws[draw++ % draws.length];
    try { canvas.closest('.tg-proxy').__flow.update(window.routeMapFixture) } finally { Math.random = random; }
  })()`);
  await waitFor(() => evaluate("window.routeMapSamples > 0 && !!document.querySelector('.tg-flow-links [data-link=out-2-2][data-state=confirmed]')"), "поток по SVG-линии подтверждённого маршрута DC2");
  await waitFor(() => evaluate("window.routeMapColors.size > 1 && window.routeMapSizes.size > 1"),
    "частицы различаются цветом и размером");
  await waitFor(() => evaluate(`(() => {
    const worker = document.querySelector('[data-link="out-1-2"]');
    const proxy = document.querySelector('[data-link="out-2-2"]');
    return worker && proxy && getComputedStyle(worker).stroke !== getComputedStyle(proxy).stroke;
  })()`), "Worker и CF Proxy имеют собственные цвета линий");
  const orbPoint = await evaluate(`(() => {
    const rect = document.querySelector('.tg-flow-orb').getBoundingClientRect();
    return { x: Math.round(rect.left + rect.width * .24), y: Math.round(rect.top + rect.height * .59) };
  })()`);
  await waitFor(() => evaluate(`document.elementFromPoint(${orbPoint.x}, ${orbPoint.y})?.classList.contains('tg-orbit-hit')`),
    "ядро доступно курсору в видимой области");
  await evaluate(`(() => {
    const orb = document.querySelector('.tg-flow-orb');
    window.orbPieces = [...orb.querySelectorAll('g rect')];
    window.orbRotation = orb.querySelector('.tg-orbit-turn').getAnimations()[0];
    window.orbPhase = window.orbRotation.currentTime;
  })()`);
  await call("Input.dispatchMouseEvent", { type: "mouseMoved", ...orbPoint });
  await waitFor(() => evaluate(`(() => {
    const pieces = [...document.querySelectorAll('.tg-orbit-label rect[transform]')];
    const offsets = pieces.map(piece => piece.transform.baseVal.getItem(0).matrix);
    return offsets.length > 30 && offsets.some(m => m.e < -20) && offsets.some(m => m.e > 20)
      && offsets.some(m => m.f < -15) && offsets.some(m => m.f > 15)
      && !!document.querySelector('.tg-orbit-turn rect[transform]');
  })()`), "частицы букв и орбит разлетаются в разные стороны");
  await call("Input.dispatchMouseEvent", { type: "mouseMoved", x: 1, y: 1 });
  assert.equal(await evaluate("!!document.querySelector('.tg-orbit-label rect[transform]')"), true,
    "после ухода курсора надпись продолжает движение из текущего положения");
  await waitFor(() => evaluate("!document.querySelector('.tg-flow-orb g rect[transform]')"),
    "ядро плавно собирается из тех же частиц");
  assert.equal(await evaluate(`(() => {
    const orb = document.querySelector('.tg-flow-orb');
    const pieces = [...orb.querySelectorAll('g rect')];
    return pieces.length === window.orbPieces.length && pieces.every((piece, i) => piece === window.orbPieces[i])
      && orb.querySelector('.tg-orbit-turn').getAnimations()[0] === window.orbRotation
      && window.orbRotation.currentTime > window.orbPhase + 200;
  })()`), true, "у ядра сохраняются частицы и фаза вращения");

  const pulseDuration = await evaluate(`['in', 'dispatch-2', 'out-2-2'].reduce((ms, link) =>
    ms + document.querySelector('[data-link="' + link + '"]').getTotalLength() / .31, 120)`);
  await delay(pulseDuration);
  await evaluate(`(() => {
    const path = document.querySelector('[data-link="out-2-2"]');
    const point = path.getPointAtLength;
    window.routeOffsets = [];
    path.getPointAtLength = function (offset) {
      window.routeOffsets.push(offset);
      return point.call(this, offset);
    };
    window.routePulse = field => {
      window.routeOffsets.length = 0;
      window.routeMapFixture.active_sessions[1][field] += 64;
      path.closest('.tg-proxy').__flow.update(window.routeMapFixture);
    };
    window.routePulse('bytes_from_upstreams');
  })()`);
  await waitFor(() => evaluate("window.routeOffsets.length >= 10 && window.routeOffsets.at(-1) < window.routeOffsets[0]"),
    "ответ идёт от DC к клиенту");
  await delay(pulseDuration);
  await evaluate("window.routePulse('bytes_from_clients')");
  await waitFor(() => evaluate("window.routeOffsets.length >= 10 && window.routeOffsets.at(-1) > window.routeOffsets[0]"),
    "запрос идёт от клиента к DC");
  if (captureDir) {
    const clip = await evaluate(`(() => {
      const r = document.querySelector('.tg-flow-stage').getBoundingClientRect();
      return { x: r.x + scrollX, y: r.y + scrollY, width: r.width, height: r.height, scale: 1 };
    })()`);
    const screenshot = await call("Page.captureScreenshot", { format: "png", clip, captureBeyondViewport: true });
    fs.writeFileSync(path.join(captureDir, "telegram-route-map-desktop.png"), Buffer.from(screenshot.data, "base64"));
  }
  await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
  const samplesBefore = await evaluate("window.routeMapSamples");
  await delay(240);
  assert.equal(await evaluate("window.routeMapSamples"), samplesBefore, "настройка уменьшенного движения останавливает поток частиц");

  await call("Emulation.setDeviceMetricsOverride", {
    width: 390,
    height: 844,
    deviceScaleFactor: 1,
    mobile: true,
  });
  await evaluate("scrollTo(0, 0)");
  await delay(500);
  const telegramMobile = await evaluate(`(() => ({
    overflow: document.documentElement.scrollWidth > innerWidth,
    stats: getComputedStyle(document.querySelector('.tg-stats')).gridTemplateColumns.split(' ').length,
    routes: getComputedStyle(document.querySelector('.tg-route-grid')).gridTemplateColumns.split(' ').length,
    canvas: !!document.querySelector('.tg-flow-canvas.is-compact')
  }))()`);
  assert.equal(telegramMobile.overflow, false, "Telegram на телефоне: нет горизонтальной прокрутки");
  assert.equal(telegramMobile.stats, 2, "Telegram на телефоне: две колонки статистики");
  assert.equal(telegramMobile.routes, 1, "Telegram на телефоне: маршруты в одну колонку");
  assert.equal(telegramMobile.canvas, true, "Telegram на телефоне: карта маршрутов остаётся видимой");
  if (captureDir) {
    const screenshot = await call("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(captureDir, "r2o-panel-telegram-390.png"), Buffer.from(screenshot.data, "base64"));
    const clip = await evaluate(`(() => {
      const canvas = document.querySelector('.tg-flow-canvas');
      canvas.closest('.tg-proxy').__flow.update(window.routeMapFixture);
      const r = canvas.getBoundingClientRect();
      return { x: r.x + scrollX, y: r.y + scrollY, width: r.width, height: r.height, scale: 1 };
    })()`);
    const map = await call("Page.captureScreenshot", { format: "png", clip, captureBeyondViewport: true });
    fs.writeFileSync(path.join(captureDir, "telegram-route-map-mobile.png"), Buffer.from(map.data, "base64"));
  }
  await call("Emulation.setDeviceMetricsOverride", {
    width: 1280,
    height: 800,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await evaluate("document.querySelector('#filter').focus(); document.querySelector('#filter').value = 'example'; document.querySelector('#filter').dispatchEvent(new Event('input', { bubbles: true }))");
  assert.equal(await evaluate("document.querySelector('#filter').value"), "example", "поле поиска принимает ввод");
  await delay(100);
  assert.equal(await evaluate("document.querySelector('#filter-clear').hidden === false"), true, "у активного поиска есть очистка");
  await evaluate("document.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true }))");
  await waitFor(() => evaluate("document.querySelector('#command').open === true"), "командная палитра открывается по Ctrl K");
  assert.equal(await evaluate("document.querySelectorAll('#command-list .command-item').length >= 6"), true, "палитра содержит навигацию по разделам");
  await evaluate("document.querySelector('#command').close()");
  await evaluate("location.hash = '#updates'");
  await waitFor(() => evaluate("!document.querySelector('#update-install').hidden"), "доступный выпуск в панели");
  await evaluate("document.querySelector('#update-install').click()");
  assert.equal(await evaluate("document.querySelector('#ask').open"), true);
  await evaluate("document.querySelector('[data-ask=no]').click()");
  assert.equal(fs.existsSync(serviceLog) && fs.readFileSync(serviceLog, "utf8").includes("update-install"), false);
  await evaluate("document.querySelector('#update-install').click(); document.querySelector('[data-ask=yes]').click()");
  await waitFor(() => fs.existsSync(serviceLog) && fs.readFileSync(serviceLog, "utf8").includes("update-install"), "штатный HTTP-запуск установки");
  await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] });
  for (const stage of [0, 1, 2, 3, 4]) {
    writeUpdate({
      busy: stage < 2 ? "staging" : "", install_stage: stage,
      last_ok: stage >= 2, last_utc: Math.floor(Date.now() / 1000), current: stage >= 3 ? "test-2" : "test-1",
    });
    await waitFor(() => evaluate(`document.querySelector('#update-progress').value === ${stage} && !document.querySelector('#update-progress').hidden`), "этап установки " + stage);
    if (stage < 4) {
      assert.equal(await evaluate("getComputedStyle(document.querySelector('#install-steps [aria-current=step]'), '::after').animationName"), "install-progress-signal");
    }
    if (stage === 3) {
      await call("Network.enable");
      await call("Network.setBlockedURLs", { urls: [`http://localhost:${port}/api/update`] });
      await waitFor(() => evaluate("document.querySelector('#update-progress-text').textContent.includes('ждём связи')"), "потеря связи во время перезапуска");
      assert.equal(await evaluate("document.querySelector('#update-progress').value"), 3);
      assert.equal(await evaluate("getComputedStyle(document.querySelector('#install-steps [aria-current=step]'), '::after').animationName"), "install-progress-signal");
      await call("Network.setBlockedURLs", { urls: [] });
    }
    if (stage === 3 && captureDir) {
      assert.equal(await evaluate("document.querySelector('#update-empty').hidden"), true);
      const screenshot = await call("Page.captureScreenshot", { format: "png" });
      fs.writeFileSync(path.join(captureDir, "update-startup.png"), Buffer.from(screenshot.data, "base64"));
    }
  }
  assert.equal(await evaluate("document.querySelector('#updates-body').dataset.install"), "done");
  assert.equal(await evaluate("document.querySelector('#install-steps [aria-current=step]')"), null);
  const failedAt = Math.floor(Date.now() / 1000);
  writeUpdate({ busy: "", install_stage: 2, last_utc: failedAt, last_ok: false,
    last_message: "Активация прервана, рабочая версия восстановлена" });
  await call("Page.reload");
  await waitFor(() => evaluate("document.querySelector('#updates-body')?.dataset.install === 'error'"), "ошибка установки после перезапуска");
  assert.equal(await evaluate("document.querySelector('#update-install').disabled"), false);
  assert.match(await evaluate("document.querySelector('#update-reason').textContent"), /рабочая версия восстановлена/);

  const latest = { release_id: "r2o-test-2", version: "R2O 2", title: "Последний выпуск", created_utc: failedAt,
    sequence: 2, notes: "Новый выпуск", commit: "2".repeat(40), architecture: "mipsel", size: 8192,
    sources: ["github", "gh-proxy", "ghproxy", "ghfast"] };
  const older = { ...latest, release_id: "r2o-test-1", version: "R2O 1", title: "Базовый выпуск",
    sequence: 1, notes: "Изменения базы", commit: "1".repeat(40) };
  fs.writeFileSync(path.join(managerRoot, "state/update-catalog.json"), JSON.stringify({ releases: [latest, older] }));
  writeUpdate({ latest, current: "r2o-test-2", previous: "r2o-test-1",
    history: [{ utc: failedAt, message: "Проверка пройдена", release_id: "r2o-test-2" }] });
  await call("Page.reload");
  await waitFor(() => evaluate("document.querySelector('#update-target')?.options.length === 2"), "каталог подписанных выпусков");
  await evaluate("document.querySelector('#update-target-trigger').scrollIntoView({block:'center', behavior:'instant'})");
  await evaluate("document.querySelector('#update-target-trigger').focus()");
  await press("ArrowDown", 40);
  await waitFor(() => evaluate("document.querySelector('#update-target-options').matches(':popover-open')"), "список выпусков открывается с клавиатуры");
  await press("End", 35);
  await press("Enter", 13);
  assert.equal(await evaluate("document.querySelector('#update-target').value"), "r2o-test-1");
  assert.equal(await evaluate("document.querySelector('#update-notes-text').textContent"), "Изменения базы");
  assert.equal(await evaluate("document.querySelector('#update-rollback').hidden"), false);
  assert.match(await evaluate("document.querySelector('#update-history-list').textContent"), /Проверка пройдена/);
  for (const [width, height] of [[1280, 900], [390, 844]]) {
    await call("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 600 });
    await evaluate("document.querySelector('#update-source-trigger').scrollIntoView({block:'center', behavior:'instant'})");
    await evaluate("document.querySelector('#update-source-trigger').click()");
    await waitFor(() => evaluate("document.querySelector('#update-source-options').matches(':popover-open')"), "фирменное меню источника " + width);
    const popup = await evaluate(`(() => {
      const menu = document.querySelector('#update-source-options');
      const rect = menu.getBoundingClientRect();
      return { bg: getComputedStyle(menu).backgroundImage,
        fits: rect.top >= 0 && rect.left >= 0 && rect.right <= innerWidth && rect.bottom <= innerHeight };
    })()`);
    assert.match(popup.bg, /linear-gradient/);
    assert.equal(popup.fits, true, "меню вписывается в экран " + width);
    if (captureDir) {
      const screenshot = await call("Page.captureScreenshot", { format: "png" });
      fs.writeFileSync(path.join(captureDir, `update-source-${width}.png`), Buffer.from(screenshot.data, "base64"));
    }
    await press("Escape", 27);
    assert.equal(await evaluate("document.activeElement.id"), "update-source-trigger");
    assert.equal(await evaluate("document.querySelector('#update-source-options').matches(':popover-open')"), false);
  }
  await press("ArrowDown", 40);
  await press("ArrowDown", 40);
  await press("ArrowDown", 40);
  await press("Enter", 13);
  assert.equal(await evaluate("document.querySelector('#update-source').value"), "gh-proxy");
  await evaluate("document.querySelector('#update-selected').click(); document.querySelector('[data-ask=yes]').click()");
  await waitFor(() => fs.readFileSync(serviceLog, "utf8").includes("update-install --release r2o-test-1 --source gh-proxy"),
    "выбранный downgrade и зеркало переданы обновлятору");

  await call("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
  await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "no-preference" }] });
  assert.equal(await evaluate("performance.getEntriesByType('resource').some(item => item.name.includes('/assets/supporter'))"), false,
    "ресурсы страницы подгружаются только с логотипа");
  await evaluate("document.querySelector('.brand-mark').scrollIntoView({ block: 'nearest', behavior: 'instant' })");
  await evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))");
  const brandPoint = await waitFor(() => evaluate(`(() => {
    const mark = document.querySelector(".brand-mark");
    const flow = mark.querySelector(".brand-flow").getAnimations()
      .find(animation => animation.animationName === "loop-flow");
    const transform = mark.getScreenCTM();
    if (!transform || flow?.playState !== "running" || flow.pending) return null;
    const stroke = document.querySelector("#r2o-loop").getPointAtLength(0);
    const { x, y } = stroke.matrixTransform(transform);
    if (!mark.contains(document.elementFromPoint(x, y))) return null;
    window.panelBrandFlow = flow;
    return { x, y };
  })()`), "видимый логотип панели с работающей анимацией после смены размера экрана");
  const brandTime = await evaluate("panelBrandFlow.currentTime");
  await call("Input.dispatchMouseEvent", { type: "mouseMoved", ...brandPoint });
  await waitFor(() => evaluate("document.querySelector('.brand-mark[data-mark-repel] rect[data-flow-lit]') !== null"),
    "световой импульс остаётся видимым во время рассыпания логотипа панели");
  const brandPulse = await evaluate(`Array.from(document.querySelectorAll(".brand-mark .brand-pixels rect"),
    pixel => Number(pixel.hasAttribute("data-flow-lit"))).join("")`);
  await waitFor(() => evaluate(`Array.from(document.querySelectorAll(".brand-mark .brand-pixels rect"),
    pixel => Number(pixel.hasAttribute("data-flow-lit"))).join("") !== "${brandPulse}"`),
    "импульс продолжает двигаться по частицам под неподвижным курсором");
  await call("Input.dispatchMouseEvent", { type: "mouseMoved", x: 500, y: 93 });
  await waitFor(() => evaluate("!document.querySelector('.brand-mark[data-mark-repel]')"), "логотип панели собирается обратно");
  assert.equal(await evaluate(`document.querySelector(".brand-mark .brand-flow").getAnimations().includes(panelBrandFlow)
    && panelBrandFlow.currentTime > ${brandTime}`), true, "фаза CSS-анимации сохраняется после сборки логотипа");

  await evaluate("document.querySelector('.brand').focus()");
  const beforeGallery = await evaluate("[location.hash, scrollY, document.querySelector('#update-target').value]");
  await call("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", text: "\r", windowsVirtualKeyCode: 13 });
  await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  await waitFor(() => evaluate("document.querySelector('#supporter-gallery')?.open"), "открытие страницы с логотипа");
  assert.equal(await evaluate("document.activeElement.id"), "supporter-title");
  assert.equal(await evaluate("document.querySelectorAll('.index a').length"), 6);
  const notes = await evaluate("[...document.querySelectorAll('.supporter-note')].map(node => node.textContent.trim())");
  assert.equal(notes.every(Boolean) && new Set(notes).size === notes.length, true, "у каждого участника свой текст");
  const canvases = "Array.from(document.querySelectorAll('.supporter-exhibit canvas'))";
  const painted = `${canvases}.every(canvas => canvas.width > 300 && canvas.getContext('2d').getImageData(canvas.width / 2, canvas.height / 2, 1, 1).data[3] > 0)`;
  await waitFor(() => evaluate(painted), "отрисовка отдельных сцен");
  await evaluate(`window.artBefore = ${canvases}.map(canvas => canvas.toDataURL())`);
  await waitFor(() => evaluate(`${canvases}.every((canvas, i) => canvas.toDataURL() !== artBefore[i])`), "анимация обеих сцен");
  const galleryCaptureDir = process.env.R2O_LOCAL_GALLERY_CAPTURE_DIR;
  async function galleryCapture(name) {
    if (!galleryCaptureDir) return;
    await delay(580);
    const screenshot = await call("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(galleryCaptureDir, `${name}.png`), Buffer.from(screenshot.data, "base64"));
  }
  await galleryCapture("gallery-desktop");
  await evaluate("document.querySelector('.supporter-exhibit').focus()");
  await call("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", text: "\r", windowsVirtualKeyCode: 13 });
  await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  await waitFor(() => evaluate("document.querySelector('#supporter-detail').open"), "увеличенная сцена первого участника");
  assert.equal(await evaluate("document.activeElement.id"), "supporter-detail-name");
  assert.equal(await evaluate("document.querySelector('#supporter-detail-name').textContent === document.querySelector('.supporter-name').textContent"), true);
  await evaluate(`window.artPaused = ${canvases}[0].toDataURL()`);
  await galleryCapture("gallery-orbital");
  await delay(180);
  assert.equal(await evaluate(`${canvases}[0].toDataURL() === artPaused`), true, "галерея приостанавливается за открытой сценой");
  await press("Escape", 27);
  await waitFor(() => evaluate("!document.querySelector('#supporter-detail').open"), "Esc закрывает сцену");
  assert.equal(await evaluate("document.activeElement === document.querySelector('.supporter-exhibit')"), true);
  await evaluate("document.querySelectorAll('.supporter-exhibit')[1].click()");
  await waitFor(() => evaluate("document.querySelector('#supporter-detail').open"), "увеличенная сцена второго участника");
  await galleryCapture("gallery-prism");
  await evaluate("history.back()");
  await waitFor(() => evaluate("!document.querySelector('#supporter-detail').open"), "браузер возвращает из сцены");
  await evaluate("document.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true }))");
  assert.equal(await evaluate("document.querySelector('#command').open"), false, "командная палитра не перекрывает галерею");
  await evaluate("document.querySelector('.supporter-footer').scrollIntoView({ block: 'end', behavior: 'instant' })");
  const finaleCanvas = "document.querySelector('.supporter-finale canvas')";
  await waitFor(() => evaluate(`${finaleCanvas}.width > 300`), "финальная сборка логотипа видна в галерее");

  await waitFor(() => evaluate(`import('/assets/supporter-art.js').then(({ artTime }) => artTime(${finaleCanvas}) >= 3.6)`),
    "логотип собирается из частиц");
  const markPoint = await evaluate(`(() => {
    window.finaleMark = ${finaleCanvas};
    const rect = finaleMark.getBoundingClientRect();
    return { x: rect.left + rect.width * .4, y: rect.top + rect.height * .5 };
  })()`);
  const scatteredPixels = `(() => {
    const { width, height } = finaleMark;
    const data = finaleMark.getContext('2d').getImageData(0, 0, width, height).data;
    const limit = 59 * Math.min(width / 570, height / 178);
    let count = 0;
    for (let y = 0; y < height; y += 2) {
      if (Math.abs(y - height / 2) < limit) continue;
      for (let x = 0; x < width; x += 2) {
        if (data[(y * width + x) * 4 + 3] > 100) count++;
      }
    }
    return count;
  })()`;
  const restPixels = await evaluate(scatteredPixels);
  await call("Input.dispatchMouseEvent", { type: "mouseMoved", ...markPoint });
  await waitFor(() => evaluate(`${scatteredPixels} > ${restPixels + 20}`), "частицы логотипа расходятся от курсора");
  await delay(450);
  await evaluate("window.finaleFrame = finaleMark.toDataURL()");
  await waitFor(() => evaluate("finaleMark.toDataURL() !== finaleFrame"), "световой импульс виден в рассыпанном знаке");
  await call("Input.dispatchMouseEvent", { type: "mouseMoved", x: 24, y: 24 });
  await waitFor(() => evaluate(`${scatteredPixels} <= ${restPixels + 3}`), "те же частицы возвращаются на контур");
  assert.equal(await evaluate(`${finaleCanvas} === finaleMark && !finaleMark.hidden`), true,
    "собранный логотип остаётся частицами");
  await galleryCapture("gallery-finale");
  await evaluate("history.back()");
  await waitFor(() => evaluate("!document.querySelector('#supporter-gallery')?.open"), "браузер возвращает в прежний раздел");
  assert.deepEqual(await evaluate("[location.hash, scrollY, document.querySelector('#update-target').value]"), beforeGallery);
  assert.equal(await evaluate("document.activeElement.matches('.brand')"), true);
  await waitFor(() => evaluate("!document.querySelector('#supporter-gallery')"), "закрытая галерея освобождает сцены");

  await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
  await call("Emulation.setDeviceMetricsOverride", { width: 375, height: 812, deviceScaleFactor: 1, mobile: true });
  await evaluate("document.querySelector('.mast-brand').click()");
  await waitFor(() => evaluate("document.querySelector('#supporter-gallery')?.open"), "мобильный логотип открывает галерею");
  await galleryCapture("gallery-mobile");
  const layoutFits = `(() => {
    const gallery = document.querySelector('#supporter-gallery');
    const back = gallery.querySelector('.supporter-back').getBoundingClientRect();
    return gallery.scrollWidth === gallery.clientWidth && back.height >= 44;
  })()`;
  assert.equal(await evaluate(layoutFits), true, "галерея и кнопка возврата помещаются на 375 пикселях");
  const mobileCanvas = `${canvases}[0]`;
  await waitFor(() => evaluate(`${mobileCanvas}.width > 300`), "первый объект виден в статическом режиме");
  await delay(80);
  await evaluate(`window.stillArt = ${mobileCanvas}.toDataURL()`);
  await delay(180);
  assert.equal(await evaluate(`${mobileCanvas}.toDataURL() === stillArt`), true, "режим уменьшенного движения оставляет статическую сцену");
  await call("Emulation.setDeviceMetricsOverride", { width: 812, height: 375, deviceScaleFactor: 1, mobile: true });
  assert.equal(await evaluate(layoutFits), true, "галерея помещается в альбомной ориентации");
  await call("Emulation.setDeviceMetricsOverride", { width: 375, height: 812, deviceScaleFactor: 1, mobile: true });
  await evaluate("document.querySelector('#supporter-gallery .supporter-back').click()");
  await waitFor(() => evaluate("!document.querySelector('#supporter-gallery')"), "мобильная кнопка возвращает в панель");
  assert.equal(await evaluate("document.activeElement.matches('.mast-brand')"), true, "фокус возвращается на мобильный логотип");
  assert.deepEqual(runtimeErrors, [], `ошибки JavaScript в браузере: ${runtimeErrors.join("; ")}`);
  console.log("Проверка Chrome-панели R2O: ПРОЙДЕНА");
}

main()
  .catch((error) => {
    console.error(error.stack || error);
    process.exitCode = 1;
  })
  .finally(async () => {
    socket?.close();
    for (const child of [chrome, panel]) {
      if (!child?.pid || child.exitCode !== null || child.signalCode !== null) continue;
      const exited = once(child, "exit");
      child.kill("SIGTERM");
      await exited;
    }
    fs.rmSync(work, { recursive: true, force: true });
  });
