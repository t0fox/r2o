'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require('playwright');

const url = 'http://127.0.0.1:' + (process.env.R2O_PREVIEW_PORT || 4187);
const capture = path.join(__dirname, 'captures/search-card');

async function main() {
  await fs.mkdir(capture, { recursive: true });
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || undefined });
  try {
    const wide = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = [];
    wide.on('pageerror', error => errors.push(error.message));
    await wide.goto(url + '/?search-ui=1&episode=live');
    const search = wide.locator('.search-concept');
    await search.and(wide.locator('[data-call-state=queued]')).waitFor();
    await search.and(wide.locator('[data-call-state=running]')).waitFor();
    await search.and(wide.locator('[data-call-state=saved]')).waitFor({ timeout: 22000 });
    assert.match(await search.locator('.search-proof').textContent(), /Точный APPLIED/);
    await search.locator('.search-plan-details summary').press('Enter');
    assert.equal(await search.locator('.search-plan-details').getAttribute('open'), '');
    await wide.getByRole('button', { name: 'Демо · Повторить поиск' }).click();
    await search.and(wide.locator('[data-call-state=queued]')).waitFor();
    assert.deepEqual(errors, []);
    await wide.close();

    for (const width of [1440, 390, 320]) {
      const page = await browser.newPage({ viewport: { width, height: 900 }, hasTouch: width < 500, reducedMotion: 'reduce' });
      for (const [episode, state, progress] of [['plan', 'running', 5 / 7], ['applied', 'saved', 1],
        ['partial', 'partial', 5 / 7], ['failed', 'failed', 5 / 7]]) {
        await page.goto(url + '/?search-ui=1&episode=' + episode);
        const card = page.locator('.search-concept[data-call-state=' + state + ']');
        await card.waitFor();
        assert.equal(await card.evaluate(el => Number(el.style.getPropertyValue('--call-progress'))), progress);
        assert.equal(await card.evaluate(el => el.scrollWidth <= el.clientWidth), true, width + ' / ' + episode);
        assert.ok(await card.locator('.status-mark-arc').evaluate(el => parseFloat(getComputedStyle(el).transitionDuration) <= .001));
        if (width !== 320) await card.screenshot({ path: path.join(capture, episode + '-' + width + '.png') });
      }
      await page.close();
    }
    console.log('Проверены живой сценарий, повтор, четыре состояния и ширины 1440 / 390 / 320 px');
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
