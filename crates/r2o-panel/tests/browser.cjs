"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const root = path.resolve(__dirname, "../../..");
const assets = path.join(root, "crates/r2o-panel/assets");
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
  assert.ok(fs.existsSync(panelBinary), `Не найден исполняемый файл панели: ${panelBinary}`);
  fs.mkdirSync(chromeProfile, { recursive: true });

  const port = await freePort();
  panel = spawn(panelBinary, [
    "serve",
    "--listen", `127.0.0.1:${port}`,
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
  assert.equal(await evaluate("document.querySelectorAll('#app > section').length"), 6, "все разделы панели отображаются");
  assert.equal(await evaluate("getComputedStyle(document.body).fontFamily.includes('Nunito')"), true, "оформление использует Nunito");
  assert.equal(await evaluate("document.querySelectorAll('script:not([src])').length"), 0, "встроенные скрипты макета не исполняются");
  await waitFor(() => evaluate(`!!document.querySelector('[data-control="settings"]')`), "кнопка настроек R2O");
  await evaluate(`document.querySelector('[data-control="settings"]').click()`);
  assert.equal(await evaluate("document.querySelector('#r2o-settings').open"), true, "настройки открываются из шапки");
  await evaluate("document.querySelector('[data-settings-close]').click()");
  assert.equal(await evaluate("document.querySelector('#r2o-settings').open"), false, "настройки закрываются");

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
