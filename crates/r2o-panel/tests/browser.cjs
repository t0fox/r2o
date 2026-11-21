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
      { dc: 1, state: "healthy", routes: [{ transport: "direct-wss", state: "healthy", domain: "kws1.web.telegram.org", selected_ip: "203.0.113.1", http_status: null, dns_ms: 2, tcp_ms: null, tls_ms: 5, websocket_ms: 3, mtproto_ms: 4 }] },
      { dc: 2, state: "blocked", routes: [] },
      { dc: 3, state: "unavailable", routes: [] },
      { dc: 4, state: "unverified", routes: [] },
      { dc: 5, state: "healthy", routes: [] },
    ],
  }));
  const enginePidPath = path.join(work, "engine.pid");
  const controllerPidPath = path.join(work, "controller.pid");
  fs.writeFileSync(configPath, `MODE=observe\nSTATE_DIR=${path.join(work, "state")}\nQUEUE_NUM=2000\nQUEUE_NUM6=2001\nR2O_FLOW_CAPACITY=2048\nIPV6_ENABLED=1\nMARK=45\nPROBE_MARK=0\nONLY_MARK=\nFW_BACKEND=auto\nPORTS=0:65535\nCONNBYTES=0:8\nVOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344\nVOICE_CONNBYTES=0:4\nHTTP_KEEPALIVE_PORTS=80\nDNS_PORTS=53,853\nTG_ENABLED=1\nTG_MODE=local\nTG_PORT=1443\nR2O_PPE_DEOFFLOAD=1\nLOGMAX=2097152\nLOGKEEP=1048576\nLOG_EVERY=60\n`);
  fs.writeFileSync(enginePidPath, String(process.pid));
  fs.writeFileSync(controllerPidPath, String(process.pid));
  fs.writeFileSync(livePath, JSON.stringify({
    linked: true,
    catalog_at: new Date().toISOString(),
    boxes: [],
    groups: [],
    dns_services: [
      { protocol: "dot", host: "dns.example", port: 853, resolved_ip: "192.0.2.8", state: "direct_ok", checked_at: new Date().toISOString(), answer_rtt_ms: 17, status_reason: "DoT: получен корректный DNS-ответ" },
      { protocol: "doq", host: "quic-with-a-long-resolver-name.example", port: 853, resolved_ip: "2001:db8::9", state: "plan_applied", plan_applied: true, applied_plan_id: "8d3c8fc1b32c52c2013cb04f82891245", dns_answer_via_plan: false, status_reason: "DNS-ответ через план ещё проверяется" },
      { protocol: "doh", host: "old.example", port: 443, path: "/dns-query", state: "direct_ok", checked_at: new Date(Date.now() - 720000).toISOString() },
      { protocol: "doh", host: "refused.example", port: 443, path: "/dns-query", state: "failed", failure: "server", checked_at: new Date().toISOString(), status_reason: "HTTP 403: сервер отклонил запрос" },
    ],
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
    measurements: { active: 1, limit: 2, queued: 0, free_pct: 96, cores: 2 },
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
  const updateTimeout = path.join(work, "update-timeout");
  fs.writeFileSync(servicePath, `#!/bin/sh\nprintf '%s\\n' "$*" >> '${serviceLog}'\nif [ "$1" = update-install ] && [ -f '${updateTimeout}' ]; then exit 124; fi\n`);
  fs.chmodSync(servicePath, 0o700);
  const managerRoot = path.join(work, "manager");
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
    "--controller-pid", controllerPidPath,
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

  await call("Page.enable");
  await call("Runtime.enable");
  await call("Page.navigate", { url: `http://localhost:${port}/` });
  await waitFor(() => evaluate("document.readyState === 'complete' && !!document.querySelector('#app')"), "загрузка страницы R2O");
  await evaluate("document.fonts.ready.then(() => true)");
  await waitFor(() => evaluate("!!document.querySelector('#engine-state small')"), "состояние движка в верхней панели");
  assert.match(await evaluate("document.querySelector('#engine-state .mast-state-text').textContent"), /^Движок работает /);
  assert.equal(await evaluate("document.querySelectorAll('#engine-state[role=status]').length === 1 && !document.querySelector('#status-state, #rail-status')"), true);
  assert.equal(await evaluate(`(() => {
    document.querySelector('#engine-actions [data-control=restart]').click();
    const status = document.querySelector('#engine-state');
    return status.textContent.includes('Движок перезапускается') && status.querySelector('.lamp').dataset.tone === 'live';
  })()`), true, "запрос перезапуска сразу меняет единственный статус");
  await waitFor(() => evaluate("document.querySelector('#engine-state .mast-state-text').textContent.startsWith('Движок работает')"), "возврат к статусу движка после команды");
  fs.unlinkSync(enginePidPath);
  await waitFor(() => evaluate("document.querySelector('#engine-state .mast-state-text').textContent.startsWith('Движок остановлен')"), "опрос отражает фактическую остановку");
  await waitFor(() => evaluate("document.querySelector('#now-title').textContent === 'Подбор приостановлен'"), "карточка обзора показывает состояние подбора");
  assert.equal(await evaluate("document.querySelector('#nav-now').textContent"), "");
  fs.writeFileSync(enginePidPath, String(process.pid));
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
  await evaluate("window.restoreStatusFetch()");
  await waitFor(() => evaluate("document.querySelector('#engine-state .mast-state-text').textContent.startsWith('Движок работает')"), "успешный запрос возвращает актуальный статус");
  await waitFor(() => evaluate("!document.querySelector('#now').hidden && document.querySelector('#now #dns-protection-list').children.length === 3"), "карточки зашифрованного DNS на обзоре");
  assert.deepEqual(await evaluate("[...document.querySelectorAll('#dns-protection-list .meta-chip')].map(node => node.textContent)"), ["Доступен напрямую", "Подбор", "Устарело"]);
  assert.equal(await evaluate("!!document.querySelector('[data-nav=dns-protection]')"), false);
  assert.equal(await evaluate("document.querySelector('[data-nav=now]').getAttribute('aria-current')"), "page");
  assert.equal(await evaluate("document.querySelector('#dns-protection-list').textContent.includes('[2001:db8::9]:853')"), true);
  assert.equal(await evaluate("document.querySelector('#dns-protection-list').textContent.includes('17 мс')"), true);
  assert.equal(await evaluate("document.querySelector('#dns-protection-more summary').textContent"), "Ещё 1 сервер · с ошибкой 1");
  await evaluate("document.querySelector('#dns-protection-more summary').click()");
  assert.equal(await evaluate("document.querySelector('#dns-protection-more').open && document.querySelector('#dns-protection-extra .meta-chip').textContent === 'Ошибка'"), true);
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
  for (const width of [320, 390, 768, 1024]) {
    await call("Emulation.setDeviceMetricsOverride", { width, height: 844, deviceScaleFactor: 1, mobile: false });
    assert.equal(await evaluate("document.documentElement.scrollWidth <= innerWidth && [...document.querySelectorAll('.index a')].every(el => { const rect = el.getBoundingClientRect(); return rect.width >= 44 && rect.right <= innerWidth && rect.bottom <= innerHeight; })"), true, `обзор и навигация помещаются на экране ${width} px`);
  }
  await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: false });
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
  if (captureDir) {
    await evaluate("document.querySelector('#dns-protection').scrollIntoView()");
    await delay(350);
    const screenshot = await call("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(captureDir, "dns-overview-mobile.png"), Buffer.from(screenshot.data, "base64"));
  }
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
        anon_kib: 1120 + i * 7 }]
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
  assert.equal(await evaluate("document.querySelectorAll('#diagnostic-memory-chart path[data-series]').length"), 0, "два снимка показаны точками");
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
  assert.equal(await evaluate("document.querySelector('#overview-metrics').textContent.includes('CPU роутера свободен на 96%')"), true, "сводка показывает свободный CPU всего роутера");
  await waitFor(() => evaluate("document.querySelector('.bindings tr[data-enabled] .t')?.textContent === 'Голос Discord'"), "голосовая привязка в коробке");
  assert.equal(await evaluate("document.querySelectorAll('.bindings .proof-note').length"), 0, "голосовая привязка не добавляет заметку о RTP, которой нет в d2o");
  assert.equal(await evaluate("[...document.querySelectorAll('.search-plan-details')].some(plan => !plan.hidden)"), true, "карточка Discovery раскрывает сведения о плане");
  await waitFor(() => evaluate("[...document.querySelectorAll('.search-question')].some((row) => !row.hidden && row.textContent.includes('Вопрос коробке: whole'))"), "текущий вопрос классификатора в карточке Discovery");
  assert.equal(await evaluate("document.querySelectorAll('#searches .search').length"), 4, "активные стадии представлены карточками, очередь выделена отдельно");
  assert.equal(await evaluate("document.querySelectorAll('#searches .search-visual').length"), 4, "у каждой карточки поиска есть сцена текущего этапа");
  assert.equal(await evaluate("[...document.querySelectorAll('#searches .search')].every((row) => row.dataset.stage !== undefined && row.dataset.stage !== 'idle')"), true, "сцена поиска получает этап подбора для анимации");
  assert.equal(await evaluate("document.querySelectorAll('#searches .queue-list .queue-target').length"), 1, "ожидающие замера собраны в список D2O");
  assert.equal(await evaluate("document.querySelector('#workload-meta').textContent"), "4 в работе · 1 ждут", "ожидающая задача не входит в число работающих");
  assert.equal(await evaluate("(() => { const row = [...document.querySelectorAll('#searches .search')].find((item) => item.querySelector('.search-target')?.textContent === 'starting.example'); return row?.querySelector('.search-phase')?.textContent === 'Заводим поиск' && row.querySelector('.search-clock').textContent.includes('идёт') && !row.querySelector('.search-clock').textContent.includes('в очереди'); })()"), true, "фаза запуска совпадает с D2O и не дублирует отдельную очередь");
  assert.equal(await evaluate("(() => { const row = [...document.querySelectorAll('.search')].find((item) => item.querySelector('.search-target')?.textContent === 'failed.example'); return row?.querySelector('.search-phase')?.textContent.startsWith('Проверяем выведенный план') && !row.querySelector('.search-proof').hidden; })()"), true, "карточка сохраняет текущую фазу и показывает причину отказа");
  assert.equal(await evaluate("[...document.querySelectorAll('.search .track')].every((track) => track.querySelectorAll('.track-step').length === 7 && track.querySelector('.track-step:last-child').textContent === 'Подтверждено')"), true, "карточка использует исходные семь этапов d2o");
  const liveSearch = liveState.searches.find((search) => search.target === "classifying.example");
  liveSearch.probes = 2;
  liveSearch.question = "split";
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate("[...document.querySelectorAll('.search-question')].some((row) => !row.hidden && row.textContent.includes('Вопрос коробке: split'))"), "автоматическое обновление вопроса и числа зондов");
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
  await waitFor(() => evaluate("document.querySelector('#searches .search:first-child[data-outcome=saved] summary')?.dataset.mark === 'Сохранено · test-plan'"), "завершённый поиск поднялся наверх, хотя в снимке он последний");
  assert.equal(await evaluate("document.querySelector('.search[data-outcome=saved] .search-proof').textContent.includes('Точный APPLIED получен для пробы')"), true);
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
  await waitFor(() => evaluate("document.querySelectorAll('#searches .search[data-outcome=saved]').length === 1"), "финальная карточка показывается с уменьшенным движением");
  await waitFor(() => evaluate("document.querySelector('#searches .quiet') !== null"), "после ухода последней карточки появляется пустой список");
  assert.equal(await evaluate("document.querySelector('#searches .quiet').textContent.includes('Рабочий прямой трафик подбор не запускает')"), true, "пустой список поисков отображается как в d2o, независимо от счётчика замеров");
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
  if (captureDir) {
    const screenshot = await call("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(captureDir, "r2o-panel-telegram-1280.png"), Buffer.from(screenshot.data, "base64"));
  }

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
    canvas: !!document.querySelector('.tg-flow-canvas')
  }))()`);
  assert.equal(telegramMobile.overflow, false, "Telegram на телефоне: нет горизонтальной прокрутки");
  assert.equal(telegramMobile.stats, 2, "Telegram на телефоне: две колонки статистики");
  assert.equal(telegramMobile.routes, 1, "Telegram на телефоне: маршруты в одну колонку");
  assert.equal(telegramMobile.canvas, true, "Telegram на телефоне: карта маршрутов остаётся видимой");
  if (captureDir) {
    const screenshot = await call("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(captureDir, "r2o-panel-telegram-390.png"), Buffer.from(screenshot.data, "base64"));
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
  fs.writeFileSync(updateTimeout, "");
  writeUpdate({ busy: "", install_stage: 2, last_utc: Math.floor(Date.now() / 1000), last_ok: true });
  assert.equal(await evaluate("fetch('/api/control/update-install', {method:'POST'}).then(r => r.status)"), 202);
  await call("Page.reload");
  await waitFor(() => evaluate("document.querySelector('#updates-body').dataset.install === 'error'"), "таймаут активации показан как ошибка");
  assert.equal(await evaluate("document.querySelector('#update-install').disabled"), false);
  assert.match(await evaluate("document.querySelector('#update-reason').textContent"), /Активация не завершилась вовремя/);
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
