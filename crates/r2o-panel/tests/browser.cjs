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

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
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
  assert.equal(panelUi.voiceProofNote({ transport: 17, shape: 5, verified_by: 3 }), "STUN Binding подтверждён; RTP не проверен", "STUN не выдаётся за подтверждение RTP");
  assert.equal(panelUi.voiceProofNote({ transport: 17, shape: 5, verified_by: 4 }), "IP Discovery подтверждён; RTP не проверен", "Discovery не выдаётся за подтверждение RTP");
  assert.equal(panelUi.voiceProofNote({ transport: 17, shape: 5, verified_by: 5 }), "Двусторонний RTP подтверждён; качество аудио не измерялось", "RTP-подтверждение не выдаётся за качество аудио");
  assert.equal(panelUi.voiceProofNote({ transport: 17, shape: 5, verified_by: 0 }), "RTP не проверен", "голосовая привязка без источника подтверждения не заявляет RTP");
  assert.equal(panelUi.voiceProofNote({ transport: 6, shape: 5, verified_by: 3 }), "", "заметка RTP не показывается для TCP");
  assert.ok(fs.existsSync(panelBinary), `Не найден исполняемый файл панели: ${panelBinary}`);
  fs.mkdirSync(chromeProfile, { recursive: true });

  const port = await freePort();
  const configPath = path.join(work, "config");
  const serviceLog = path.join(work, "service.log");
  const servicePath = path.join(work, "service.sh");
  fs.writeFileSync(configPath, `MODE=observe\nSTATE_DIR=${path.join(work, "state")}\nQUEUE_NUM=2000\nQUEUE_NUM6=2001\nR2O_FLOW_CAPACITY=2048\nIPV6_ENABLED=1\nMARK=45\nPROBE_MARK=0\nONLY_MARK=\nFW_BACKEND=auto\nPORTS=0:65535\nCONNBYTES=0:8\nVOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344\nVOICE_CONNBYTES=0:4\nHTTP_KEEPALIVE_PORTS=80\nDNS_PORTS=53,853\nTG_PORT=1443\nR2O_PPE_DEOFFLOAD=1\nLOGMAX=2097152\nLOGKEEP=1048576\nLOG_EVERY=60\n`);
  fs.writeFileSync(servicePath, `#!/bin/sh\nprintf '%s\\n' "$*" >> '${serviceLog}'\n`);
  fs.chmodSync(servicePath, 0o700);
  panel = spawn(panelBinary, [
    "serve",
    "--listen", `127.0.0.1:${port}`,
    "--config", configPath,
    "--service", servicePath,
    "--assets", assets,
    "--state-dir", work,
    "--live", path.join(work, "live.json"),
    "--health-file", path.join(work, "panel.health"),
  ], { stdio: ["ignore", "pipe", "pipe"] });
  let panelOutput = "";
  panel.stdout.on("data", (chunk) => { panelOutput = (panelOutput + chunk).slice(-4000); });
  panel.stderr.on("data", (chunk) => { panelOutput = (panelOutput + chunk).slice(-4000); });
  const panelExit = new Promise((resolve) => panel.once("exit", (code) => resolve(code)));
  await waitFor(async () => {
    if (panel.exitCode !== null) throw new Error(`Панель завершилась с кодом ${await panelExit}: ${panelOutput}`);
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`);
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
  const tab = await (await fetch(`http://127.0.0.1:${debugPort}/json/new?about:blank`, { method: "PUT" })).json();

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
  await call("Page.navigate", { url: `http://127.0.0.1:${port}/` });
  await waitFor(() => evaluate("document.readyState === 'complete' && !!document.querySelector('#app')"), "загрузка страницы R2O");
  await evaluate("document.fonts.ready.then(() => true)");

  assert.equal(await evaluate("document.title.includes('R2O')"), true, "заголовок страницы панели");
  assert.equal(await evaluate("document.querySelectorAll('#app > section').length"), 7, "все разделы панели отображаются");
  assert.equal(await evaluate("getComputedStyle(document.body).fontFamily.includes('Nunito')"), true, "оформление использует Nunito");
  assert.equal(await evaluate("document.fonts.check('500 16px Nunito')"), true, "локальный шрифт Nunito загружен");
  assert.equal(await evaluate("document.fonts.check('400 16px \\\"JetBrains Mono\\\"')"), true, "локальный JetBrains Mono загружен");
  assert.equal(await evaluate("document.querySelectorAll('script:not([src])').length"), 0, "встроенные скрипты макета не исполняются");
  await waitFor(() => evaluate("document.querySelector('#now-title').textContent !== 'Получаем состояние…'"), "состояние из /api/status");
  assert.equal(await evaluate("document.querySelector('#r2o-settings') !== null"), true, "доступен раздел настроек");
  assert.equal(await evaluate("document.querySelectorAll('#r2o-settings-form input, #r2o-settings-form select').length === 20"), true, "форма содержит параметры datapath, firewall, PPE и Telegram");
  await waitFor(() => evaluate("document.querySelector('#settings-mode').value === 'observe' && document.querySelector('#settings-queue').value === '2000' && document.querySelector('#settings-queue6').value === '2001' && document.querySelector('#settings-firewall').value === 'auto'"), "загрузка текущих настроек");
  assert.equal(await evaluate("document.querySelector('#settings-ppe-deoffload').checked"), true, "форма загружает настройку PPE");
  assert.equal(await evaluate("document.querySelector('[data-control=\\\"settings\\\"]') === null"), true, "шапка соответствует макету");

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

  await evaluate(`document.querySelector('a[href="#telegram"]').click()`);
  assert.equal(await evaluate("location.hash"), "#telegram", "ссылка навигации открывает раздел Telegram");
  await evaluate(`document.querySelector('a[href="#r2o-settings"]').click()`);
  assert.equal(await evaluate("location.hash"), "#r2o-settings", "ссылка навигации открывает настройки");
  await evaluate("document.querySelector('#settings-mode').value = 'apply'; document.querySelector('#settings-queue').value = '321'; document.querySelector('#settings-queue6').value = '322'; document.querySelector('#settings-capacity').value = '4096'; document.querySelector('#settings-ipv6').value = 'false'; document.querySelector('#settings-mark').value = '0x2d'; document.querySelector('#settings-probe-mark').value = '7'; document.querySelector('#settings-only-mark').value = '9/255'; document.querySelector('#settings-firewall').value = 'nft'; document.querySelector('#settings-ports').value = '80,443'; document.querySelector('#settings-connbytes').value = '0:12'; document.querySelector('#settings-voice-ports').value = '3478:3481'; document.querySelector('#settings-voice-connbytes').value = '0:6'; document.querySelector('#settings-http-keepalive-ports').value = '8080'; document.querySelector('#settings-dns-ports').value = '53,853,5353'; document.querySelector('#settings-tg-port').value = '1444'; document.querySelector('#settings-ppe-deoffload').checked = false; document.querySelector('#settings-log-max').value = '4194304'; document.querySelector('#settings-log-keep').value = '2097152'; document.querySelector('#settings-log-every').value = '120'; document.querySelector('#r2o-settings-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))");
  await waitFor(async () => {
    const config = fs.readFileSync(configPath, "utf8");
    return config.includes("MODE=apply") && config.includes("QUEUE_NUM=321") &&
      config.includes("QUEUE_NUM6=322") && config.includes("R2O_FLOW_CAPACITY=4096") &&
      config.includes("IPV6_ENABLED=0") && config.includes("MARK=0x2d") &&
      config.includes("ONLY_MARK=9/255") && config.includes("FW_BACKEND=nft") &&
      config.includes("PORTS=80,443") && config.includes("CONNBYTES=0:12") &&
      config.includes("VOICE_PORTS=3478:3481") && config.includes("VOICE_CONNBYTES=0:6") &&
      config.includes("HTTP_KEEPALIVE_PORTS=8080") && config.includes("DNS_PORTS=53,853,5353") &&
      config.includes("TG_PORT=1444") && config.includes("R2O_PPE_DEOFFLOAD=0") &&
      config.includes("LOGMAX=4194304") && config.includes("LOGKEEP=2097152") &&
      config.includes("LOG_EVERY=120");
  }, "сохранение настроек из панели");
  await waitFor(() => fs.existsSync(serviceLog) && fs.readFileSync(serviceLog, "utf8").includes("settings-restart"), "перезапуск служб после сохранения настроек");
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
