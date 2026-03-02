import { chromium } from 'playwright';
import { mkdir } from 'node:fs/promises';

const BASE_URL = process.env.TOOLKIT_URL ?? 'http://127.0.0.1:5173/builder';
const SCREENSHOT_PATH = 'test-results/inline-copy-button.png';

(async () => {
  console.log(` Checking inline copy button at ${BASE_URL}`);
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  try {
    await page.goto(BASE_URL, { waitUntil: 'networkidle' });
    let copyButton;
    try {
      copyButton = await page.waitForSelector('button[aria-label="Copy generated calldata"]', {
        timeout: 20_000,
      });
    } catch (error) {
      await mkdir('test-results', { recursive: true });
      const errorShot = 'test-results/builder-load-error.png';
      await page.screenshot({ path: errorShot, fullPage: true });
      console.error(` Failed to detect inline copy button. Screenshot saved to ${errorShot}`);
      throw error;
    }

    if (!copyButton) {
      throw new Error('Inline copy button not found');
    }

    await mkdir('test-results', { recursive: true });
    await copyButton.screenshot({ path: SCREENSHOT_PATH });

    const state = await copyButton.getAttribute('data-state');
    console.log(` Inline copy button rendered (data-state=${state ?? 'idle'})`);
    console.log(` Screenshot saved to ${SCREENSHOT_PATH}`);
  } finally {
    await browser.close();
  }
})();
