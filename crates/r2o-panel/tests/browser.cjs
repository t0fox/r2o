"use strict";

const assert = require("node:assert/strict");
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
  assert.equal(diagnosticsUi.summary({ samples: [{ at: 1, processes: [], bindings: 0, plans: 0 }], events: [{ outcome: "failed" }, { outcome: "queue-expired" }, { outcome: "plan-found" }] }).includes("без подтверждённого результата: 2"), true, "диагностика считает отказ и истёкшую очередь неподтверждёнными исходами");
  assert.ok(fs.existsSync(panelBinary), `Не найден исполняемый файл панели: ${panelBinary}`);
  fs.mkdirSync(chromeProfile, { recursive: true });

  const port = await freePort();
  const configPath = path.join(work, "config");
  const serviceLog = path.join(work, "service.log");
  const servicePath = path.join(work, "service.sh");
  const livePath = path.join(work, "live.json");
  fs.mkdirSync(path.join(work, "state"), { recursive: true });
  fs.writeFileSync(path.join(work, "telegram.status"), "error\n");
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
      question: "whole · проверок: 1, прошло: 0, отказов: 1",
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
  fs.writeFileSync(servicePath, `#!/bin/sh\nprintf '%s\\n' "$*" >> '${serviceLog}'\n`);
  fs.chmodSync(servicePath, 0o700);
  panel = spawn(panelBinary, [
    "serve",
    "--listen", `localhost:${port}`,
    "--config", configPath,
    "--service", servicePath,
    "--assets", assets,
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
  await waitFor(() => evaluate("!!document.querySelector('#diagnostic-toggle')"), "загрузка управления диагностикой");
  assert.equal(await evaluate("(() => { const help = document.querySelector('#diagnostic-history-help'); return !!help && help.querySelector('summary')?.textContent.includes('Что сохраняется') && help.textContent.includes('120') && help.textContent.includes('64') && help.textContent.includes('домены и IP-адреса') && help.textContent.includes('никуда не отправляется'); })()"), true, "диагностика сообщает пределы истории и состав локального отчёта как d2o");
  await evaluate("document.querySelector('#diagnostic-toggle').click()");
  await waitFor(() => evaluate("document.querySelector('#diagnostic-state').dataset.enabled === 'true'"), "включение локальной диагностики");
  assert.equal(await evaluate("document.querySelector('#diagnostic-download').hidden"), true, "скачивание ждёт первого снимка контроллера");
  await evaluate("document.querySelector('#diagnostic-toggle').click()");
  await waitFor(() => evaluate("document.querySelector('#diagnostic-state').dataset.enabled === 'false'"), "выключение диагностики с удалением истории");
  assert.equal(await evaluate("document.title.includes('R2O')"), true, "заголовок страницы панели");
  assert.equal(await evaluate("document.querySelector('#r2o-settings') === null && ![...document.querySelectorAll('.index a')].some((link) => link.hash === '#r2o-settings')"), true, "в панели нет отдельного раздела настроек, которого нет в d2o");
  assert.equal(await evaluate("document.querySelectorAll('#app > section').length"), 6, "все разделы панели отображаются");
  assert.equal(await evaluate("getComputedStyle(document.body).fontFamily.includes('Nunito')"), true, "оформление использует Nunito");
  assert.equal(await evaluate("document.fonts.check('500 16px Nunito')"), true, "локальный шрифт Nunito загружен");
  assert.equal(await evaluate("document.fonts.check('400 16px \\\"JetBrains Mono\\\"')"), true, "локальный JetBrains Mono загружен");
  assert.equal(await evaluate("document.querySelectorAll('script:not([src])').length"), 0, "встроенные скрипты макета не исполняются");
  await waitFor(() => evaluate("document.querySelector('#now-title').textContent !== 'Получаем состояние…'"), "состояние из /api/status");
  await waitFor(() => evaluate("document.querySelector('.bindings tr[data-enabled] .t')?.textContent === 'Голос Discord'"), "голосовая привязка в коробке");
  assert.equal(await evaluate("document.querySelectorAll('.bindings .proof-note').length"), 0, "голосовая привязка не добавляет заметку о RTP, которой нет в d2o");
  assert.equal(await evaluate("document.querySelector('.search-plan') === null && document.querySelector('.search-plan-result') === null"), true, "карточка Discovery показывает тот же набор статусов, что и d2o");
  await waitFor(() => evaluate("[...document.querySelectorAll('.search-question')].some((row) => !row.hidden && row.textContent.includes('whole · проверок: 1'))"), "текущий вопрос классификатора в карточке Discovery");
  assert.equal(await evaluate("document.querySelectorAll('#searches .search').length"), 4, "активные стадии представлены карточками, очередь выделена отдельно");
  assert.equal(await evaluate("document.querySelectorAll('#searches .queue-list .queue-target').length"), 1, "ожидающие замера собраны в список D2O");
  assert.equal(await evaluate("(() => { const row = [...document.querySelectorAll('#searches .search')].find((item) => item.querySelector('.search-target')?.textContent === 'starting.example'); return row?.querySelector('.search-phase')?.textContent === 'Заводим поиск' && row.querySelector('.search-clock').textContent.includes('идёт') && !row.querySelector('.search-clock').textContent.includes('в очереди'); })()"), true, "фаза запуска совпадает с D2O и не дублирует отдельную очередь");
  assert.equal(await evaluate("(() => { const row = [...document.querySelectorAll('.search')].find((item) => item.querySelector('.search-target')?.textContent === 'failed.example'); return row?.querySelector('.search-phase')?.textContent.startsWith('Проверяем выведенный план'); })()"), true, "отказный поиск отображает исходную фазу d2o без дополнительной строки результата");
  assert.equal(await evaluate("[...document.querySelectorAll('.search .track')].every((track) => track.querySelectorAll('.track-step').length === 7 && track.querySelector('.track-step:last-child').textContent === 'Подтверждено')"), true, "карточка использует исходные семь этапов d2o");
  const liveSearch = liveState.searches.find((search) => search.target === "classifying.example");
  liveSearch.probes = 2;
  liveSearch.question = "split · проверок: 2, прошло: 1, отказов: 1";
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate("[...document.querySelectorAll('.search-question')].some((row) => !row.hidden && row.textContent.includes('split · проверок: 2'))"), "автоматическое обновление вопроса и числа зондов");
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

  liveState.searches = [];
  fs.writeFileSync(livePath, JSON.stringify(liveState));
  await waitFor(() => evaluate("document.querySelector('#searches .quiet') !== null"), "пустой список поисков");
  assert.equal(await evaluate("document.querySelector('#searches .quiet').textContent.includes('Рабочий прямой трафик подбор не запускает')"), true, "пустой список поисков отображается как в d2o, независимо от счётчика замеров");
  await waitFor(() => evaluate("!!document.querySelector('#telegram-body')?.dataset.state"), "обновление статуса Telegram");
  assert.equal(await evaluate("document.querySelector('#telegram-body').dataset.state"), "stopped", "неизвестный Telegram status использует fallback d2o");

  await evaluate(`document.querySelector('a[href="#telegram"]').click()`);
  assert.equal(await evaluate("location.hash"), "#telegram", "ссылка навигации открывает раздел Telegram");
  await evaluate("document.querySelector('#filter').focus(); document.querySelector('#filter').value = 'example'; document.querySelector('#filter').dispatchEvent(new Event('input', { bubbles: true }))");
  assert.equal(await evaluate("document.querySelector('#filter').value"), "example", "поле поиска принимает ввод");
  await delay(100);
  assert.deepEqual(runtimeErrors, [], `ошибки JavaScript в браузере: ${runtimeErrors.join("; ")}`);
  console.log("Проверка Chrome-панели R2O: ПРОЙДЕНА");
}

main()
  .catch((error) => {
    console.error(error.stack || error);
    process.exitCode = 1;
  })
  .finally(() => {
    socket?.close();
    chrome?.kill("SIGTERM");
    panel?.kill("SIGTERM");
    fs.rmSync(work, { recursive: true, force: true });
  });
