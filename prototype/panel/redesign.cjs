"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const fs = require("node:fs/promises");
const path = require("node:path");
const { chromium } = require("playwright");

const url = "http://127.0.0.1:" + (process.env.R2O_PREVIEW_PORT || 4187);
const capture = path.join(__dirname, "captures/redesign");
const tabs = ["now", "families", "boxes", "telegram", "updates", "diagnostics"];

async function visit(page, section) {
  await page.locator('[data-nav="' + section + '"]').click();
  await page.locator("#" + section).waitFor({ state: "visible" });
  assert.equal(await page.locator('[aria-current="page"]').getAttribute("data-nav"), section);
}

async function assertDecodeBaseline(label) {
  const delta = await label.evaluate(element => {
    const original = [...element.childNodes].find(node => node.nodeType === Node.TEXT_NODE && node.textContent.trim());
    const start = original.textContent.search(/\S/);
    const range = document.createRange();
    range.setStart(original, start);
    range.setEnd(original, start + 1);
    const baseline = range.getBoundingClientRect().top;
    const ink = element.querySelector(".decode-ink");
    const probe = document.createElement("span");
    probe.style.cssText = ink.firstElementChild.style.cssText;
    const sample = document.createElement("span");
    sample.style.display = "inline-block";
    sample.textContent = range.toString();
    probe.append(sample);
    ink.append(probe);
    range.selectNodeContents(sample);
    const shift = range.getBoundingClientRect().top - baseline;
    probe.remove();
    return shift;
  });
  assert.ok(Math.abs(delta) < .5, "Смещение текста при расшифровке: " + delta + " px");
}

async function record(browser) {
  const video = path.join(capture, "r2o-motion.webm");
  const encoder = spawn(process.env.R2O_CAPTURE_FFMPEG || "ffmpeg", [
    "-loglevel", "error", "-f", "image2pipe", "-framerate", "20", "-vcodec", "mjpeg",
    "-i", "pipe:0", "-c:v", "libvpx-vp9", "-deadline", "realtime", "-cpu-used", "8", "-y", video
  ], { stdio: ["pipe", "ignore", "inherit"] });
  await once(encoder, "spawn");
  const finished = once(encoder, "close");
  encoder.stdin.on("error", () => {});
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  let frame;
  const frames = setInterval(() => {
    if (frame && !encoder.stdin.destroyed && !encoder.stdin.writableNeedDrain) encoder.stdin.write(frame);
  }, 50);
  try {
    await page.screencast.start({ onFrame: next => { frame = next.data; } });
    await page.goto(url + "/?episode=live");
    const mark = await page.locator(".brand-mark").boundingBox();
    await page.mouse.move(mark.x + mark.width * .18, mark.y + mark.height * .63);
    await page.mouse.move(mark.x + mark.width * .8, mark.y + mark.height * .63, { steps: 12 });
    await page.locator(".search .track-step").first().waitFor();
    await page.locator(".workload-card").scrollIntoViewIfNeeded();
    await page.locator(".search[data-outcome=saved]").waitFor();
    await page.locator(".search-plan-details summary").click();
    await page.waitForTimeout(650);
    await visit(page, "updates");
    await page.locator("#update-install").click();
    await page.getByRole("button", { name: "Установить", exact: true }).click();
    await page.locator("#install-steps li:nth-child(3)[aria-current=step]").waitFor();
    await page.screenshot({ path: path.join(capture, "install-1280.png") });
    await page.waitForTimeout(950);
  } finally {
    clearInterval(frames);
    encoder.stdin.end();
    await context.close();
    const [code] = await finished;
    assert.equal(code, 0, "Код завершения FFmpeg");
  }
  assert.ok((await fs.stat(video)).size > 0);
  console.log("Видео успешного поиска и запуска установки — OK");
}

async function main() {
  await fs.mkdir(capture, { recursive: true });
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN || undefined,
    args: ["--use-gl=angle", "--use-angle=swiftshader", "--enable-unsafe-swiftshader"]
  });
  try {
    for (const width of [1440, 860, 390, 320]) {
      const page = await browser.newPage({
        viewport: { width, height: width > 760 ? 960 : 844 },
        isMobile: width <= 390, hasTouch: width <= 390
      });
      const errors = [];
      page.on("pageerror", error => errors.push(error.message));
      page.on("console", message => {
        if (message.type() === "error") errors.push(message.text());
      });
      await page.goto(url + "/?episode=applied");
      await page.locator(".search[data-outcome=saved]").waitFor();
      await page.evaluate(() => document.fonts.ready);

      for (const section of tabs) {
        await visit(page, section);
        await page.waitForFunction(() => !document.querySelector("[data-decoding], [data-nav-motion]"));
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, width + " / " + section);
        if (width === 1440 || width === 390) {
          await page.screenshot({ path: path.join(capture, section + "-" + width + ".png") });
        }
      }

      if (width === 1440) {
        const mark = page.locator(".brand-mark");
        const markBox = await mark.boundingBox();
        const markY = markBox.y + markBox.height * .56;
        const markX = markBox.x + markBox.width * .72;
        await page.mouse.move(markBox.x + markBox.width * .18, markY);
        await page.mouse.move(markX, markY, { steps: 7 });
        const wordmark = page.locator(".brand .brand-text strong");
        await wordmark.locator(".decode-ink > span").first().waitFor({ state: "attached" });
        const glyph = await wordmark.locator(".decode-ink > span").first().evaluate(el => {
          const style = getComputedStyle(el);
          return { font: style.fontFamily, color: style.color };
        });
        assert.match(glyph.font, /Unbounded/);
        assert.equal(glyph.color, "rgb(255, 255, 255)");
        await assertDecodeBaseline(wordmark);
        assert.equal(await wordmark.textContent(), "r2o");
        const spread = () => mark.locator(".brand-pixels rect").evaluateAll(pixels => Math.max(0, ...pixels.map(pixel => {
          const shift = pixel.transform.baseVal.getItem(0).matrix;
          return Math.hypot(shift.e, shift.f);
        })));
        await page.waitForFunction(() =>
          [...document.querySelectorAll(".brand-mark .brand-pixels rect")].some(pixel =>
            Math.abs(pixel.transform.baseVal.getItem(0).matrix.e) > 4));
        const directions = await mark.evaluate((svg, { x, y }) => {
          const cursor = new DOMPoint(x, y).matrixTransform(svg.getScreenCTM().inverse());
          return [...svg.querySelectorAll(".brand-pixels rect")].map(pixel => {
            const shift = pixel.transform.baseVal.getItem(0).matrix;
            return (pixel.x.baseVal.value + 1.25 - cursor.x) * shift.e +
              (pixel.y.baseVal.value + 1.25 - cursor.y) * shift.f;
          });
        }, { x: markX, y: markY });
        assert.ok(directions.filter(dot => dot > 5).length > 8);
        assert.ok(directions.every(dot => dot >= -.1));
        await page.screenshot({ path: path.join(capture, "pixel-logo-1440.png"), clip: { x: 70, y: 5, width: 108, height: 100 } });
        const scattered = await spread();
        await page.mouse.move(40, markY);
        await page.waitForTimeout(95);
        const returning = await spread();
        assert.ok(returning > .1 && returning < scattered);
        await page.mouse.move(markX, markY);
        await page.waitForTimeout(150);
        assert.ok(await spread() > returning);
        await page.mouse.move(40, markY);
        await page.locator(".brand-mark[data-mark-repel]").waitFor({ state: "detached" });
        await wordmark.locator(".decode-ink").waitFor({ state: "detached" });
        await page.evaluate(() => {
          for (const tab of ["families", "updates", "diagnostics", "now", "boxes"]) {
            document.querySelector('[data-nav="' + tab + '"]').click();
          }
        });
        await page.locator('#boxes:not([hidden])').waitFor();
        assert.equal(await page.locator('[aria-current="page"]').getAttribute("data-nav"), "boxes");
        await visit(page, "now");
        await page.locator("#now-title[data-decoding]").waitFor();
        assert.ok(await page.locator("#now-title").textContent());
        await assertDecodeBaseline(page.locator("#now-title"));
        await page.locator("#now-title[data-decoding]").waitFor({ state: "detached" });
        const panel = page.locator("#status-panel");
        const box = await panel.boundingBox();
        await page.mouse.move(box.x + box.width * .65, box.y + 40);
        await page.mouse.move(box.x + box.width * .83, box.y + 65, { steps: 9 });
        assert.equal(await panel.getAttribute("data-r2o-spot"), "tilt");
        await page.waitForFunction(() => document.querySelector(".pixel-trail").dataset.renderer);
        await page.screenshot({ path: path.join(capture, "spotlight-1440.png") });
        await page.mouse.move(30, 20);
        await page.waitForFunction(() => !document.querySelector("[data-r2o-spot]"));
        const doneClock = await page.locator(".search[data-outcome=saved] .search-clock strong").textContent();
        await page.evaluate(() => {
          const fetch = window.fetch;
          window.fetch = async (...args) => {
            const response = await fetch(...args);
            if (String(args[0]).startsWith("/api/status")) document.documentElement.dataset.testPoll = "seen";
            return response;
          };
        });
        await page.waitForFunction(() => document.documentElement.dataset.testPoll === "seen", null, { timeout: 9000 });
        assert.equal(await page.locator(".search[data-outcome=saved] .search-clock strong").textContent(), doneClock);
        assert.equal(await page.locator("#now-title[data-decoding]").count(), 0);
        const telegram = page.locator('[data-nav="telegram"]');
        await telegram.focus();
        await telegram.press("Enter");
        await page.locator("#telegram:not([hidden])").waitFor();
        await page.goBack();
        await page.locator("#now").waitFor({ state: "visible" });
        await visit(page, "diagnostics");
        await page.locator("#diagnostic-toggle").click();
        await page.locator("#diagnostic-state[data-phase=paused]").waitFor();
        await page.locator("#diagnostic-toggle").click();
        await page.locator("#diagnostic-state[data-phase=ready]").waitFor();
        await page.locator("#diagnostic-clear").click();
        await page.locator('#diagnostic-stop-dialog [value=clear]').click();
        await page.locator("#diagnostic-state[data-phase=pending]").waitFor();
        await page.emulateMedia({ reducedMotion: "reduce" });
        await visit(page, "families");
        assert.equal(await page.locator("[data-decoding], [data-nav-motion]").count(), 0);
        assert.equal(await page.locator(".brand-flow").first().evaluate(e => getComputedStyle(e).animationName), "none");
        await mark.hover();
        assert.equal(await mark.locator(".brand-pixels rect").count(), 0);
      }
      assert.deepEqual(errors, []);
      await page.close();
      console.log(width + " px: 6 разделов, адаптивность и консоль — OK");
    }

    for (const renderer of ["webgl2", "canvas2d"]) {
      const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
      await page.addInitScript(renderer => {
        const get = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function (kind, settings) {
          if (kind === "webgl2" && this.classList.contains("pixel-trail")) {
            if (renderer === "canvas2d") return null;
            return get.call(this, kind, { ...settings, failIfMajorPerformanceCaveat: false, preserveDrawingBuffer: true });
          }
          return get.call(this, kind, settings);
        };
      }, renderer);
      await page.goto(url);
      const hero = page.locator("#status-panel");
      await hero.hover();
      const canvas = page.locator(".pixel-trail");
      await page.waitForFunction(renderer => document.querySelector(".pixel-trail").dataset.renderer === renderer, renderer);
      const peak = () => canvas.evaluate((element, renderer) => {
        const width = element.width, height = element.height;
        let rgba;
        if (renderer === "webgl2") {
          const gl = element.getContext(renderer);
          rgba = new Uint8Array(width * height * 4);
          gl.readPixels(0, 0, width, height, gl.RGBA, gl.UNSIGNED_BYTE, rgba);
        } else {
          rgba = element.getContext("2d").getImageData(0, 0, width, height).data;
        }
        for (let i = 3; i < rgba.length; i += 4) if (rgba[i] > 0) return true;
        return false;
      }, renderer);
      assert.equal(await peak(), true, renderer + ": видимые пиксели");
      await page.mouse.move(30, 20);
      await page.waitForTimeout(620);
      assert.equal(await peak(), false, renderer + ": кадр очищен");
      await page.close();
      console.log(renderer + ": след появился и затух — OK");
    }
    if (process.argv.includes("--record")) await record(browser);
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
