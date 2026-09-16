import assert from "node:assert/strict";
import { chromium } from "playwright";
import { freshApp, ALICE } from "../tests/helpers.js";

const browser = await chromium.launch({ headless: true });
try {
  for (const vulnerable of [true, false]) {
    const app = await freshApp({ XSS: vulnerable });
    await app.listen({ port: 0, host: "127.0.0.1" });
    const address = app.server.address();
    if (!address || typeof address === "string") throw new Error("Porta de teste ausente");
    const context = await browser.newContext();
    try {
      const page = await context.newPage();
      const base = `http://localhost:${address.port}`;
      await page.goto(base + "/login");
      await page.locator('[name="email"]').fill(ALICE.email);
      await page.locator('[name="password"]').fill(ALICE.password);
      await page.getByRole("button", { name: "Entrar" }).click();
      await page.waitForURL("**/dashboard");
      await page.locator('[name="to"]').fill("MP-001003");
      await page.locator('[name="amount"]').first().fill("1,00");
      await page.locator('[name="description"]').fill('<img src="/missing-xss-image" onerror="document.body.dataset.xss=\'executed\'">');
      await page.locator('form[action="/transfer"] button').click();
      await page.waitForURL("**/dashboard?msg=**");
      await page.waitForLoadState("networkidle");
      const executed = await page.locator("body").getAttribute("data-xss");
      assert.equal(executed, vulnerable ? "executed" : null);
      console.log(`XSS ${vulnerable ? "vulnerável: execução comprovada" : "corrigido: execução bloqueada"}`);
      if (!vulnerable) {
        await page.goto(base + "/assistant");
        await page.locator('[data-question]').first().click();
        await page.locator('.chat-message-assistant:not(.chat-pending)').waitFor();
        await page.reload();
        assert.equal(await page.locator('.chat-message-user').count(), 1);
        console.log("Chat: envio e histórico preservados.");
      }
    } finally { await context.close(); await app.close(); }
  }
} finally { await browser.close(); }
