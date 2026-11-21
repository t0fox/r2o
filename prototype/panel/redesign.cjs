"use strict";

const assert = require("node:assert/strict");
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

async function record(browser) {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 900 }, recordVideo: { dir: capture, size: { width: 1280, height: 900 } }
  });
  const page = await context.newPage();
  try {
    await page.goto(url + "/?episode=live");
    await page.locator(".search .track-step").first().waitFor();
    await page.locator(".workload-card").scrollIntoViewIfNeeded();
    await page.locator(".search[data-outcome=saved]").waitFor();
    await page.locator(".search-plan-details summary").click();
    await page.waitForTimeout(650);
    await visit(page, "updates");
    await page.locator("#update-install").click();
    await page.getByRole("button", { name: "Установить", exact: true }).click();
    await page.locator("#install-steps [aria-current=step]").waitFor();
    await page.screenshot({ path: path.join(capture, "install-1280.png") });
    await page.waitForTimeout(950);
  } finally {
    await context.close();
  }
  await page.video().saveAs(path.join(capture, "r2o-motion.webm"));
  await page.video().delete();
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
        const markY = markBox.y + markBox.height * .65;
        await page.mouse.move(markBox.x + markBox.width * .18, markY);
        await page.mouse.move(markBox.x + markBox.width * .78, markY, { steps: 9 });
        await mark.locator(".brand-trail rect").first().waitFor({ state: "attached" });
        assert.ok(await mark.locator(".brand-trail rect").count() > 3);
        await page.screenshot({ path: path.join(capture, "pixel-logo-1440.png"), clip: { x: 70, y: 5, width: 108, height: 100 } });
        await mark.locator(".brand-trail rect").first().waitFor({ state: "detached" });
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
        await page.waitForTimeout(2100);
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
        assert.equal(await mark.locator(".brand-trail rect").count(), 0);
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
