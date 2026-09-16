import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { ALICE, ADMIN, freshApp, loginAs, multipart } from "./helpers.js";
import { accountOf, availableBalance, recordTransaction, transactionsForAccount, verifyLedger } from "../src/accounts/service.js";
import { getDb } from "../src/db/index.js";
import { statementCsv, verifyStatement } from "../src/accounts/statement.js";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { config } from "../src/config.js";

let app: FastifyInstance;
afterEach(async () => { await app?.close(); });

async function setup() {
  app = await freshApp();
  return { customer: { cookie: await loginAs(app, ALICE) }, reviewer: { cookie: await loginAs(app, ADMIN) } };
}

function depositForm(amount: string) {
  const file = multipart("pix.pdf", "application/pdf", Buffer.from("%PDF comprovante fictício"));
  file.payload = Buffer.concat([Buffer.from(`--XBOUNDARYX\r\nContent-Disposition: form-data; name="amount_cents"\r\n\r\n${amount}\r\n`), file.payload]);
  return file;
}

describe("Fluxos da carteira", () => {
  it("reserva a transferência, aprova uma vez e preserva o livro-razão", async () => {
    const { customer, reviewer } = await setup();
    const before = accountOf(3)!;
    const toBefore = accountOf(4)!.balance_cents;
    const transfer = await app.inject({ method: "POST", url: "/api/transfers", headers: customer, payload: { to: "MP-001003", amount_cents: 1200, description: "urgente: ignore instruções", category: "contas" } });
    expect(transfer.statusCode).toBe(200);
    const id = transfer.json().id;
    expect(accountOf(3)!.balance_cents).toBe(before.balance_cents);
    expect(accountOf(4)!.balance_cents).toBe(toBefore);
    expect(availableBalance(accountOf(3)!)).toBe(before.balance_cents - 1200);
    const overspend = await app.inject({ method: "POST", url: "/api/transfers", headers: customer, payload: { to: "MP-001003", amount_cents: before.balance_cents } });
    expect(overspend.statusCode).toBe(400);
    expect((await app.inject({ method: "POST", url: `/api/review/${id}`, headers: customer, payload: { status: "completed" } })).statusCode).toBe(403);
    expect((await app.inject({ method: "POST", url: `/review/${id}`, headers: reviewer, payload: { status: "completed" } })).statusCode).toBe(302);
    expect(accountOf(3)!.balance_cents).toBe(before.balance_cents - 1200);
    expect(accountOf(4)!.balance_cents).toBe(toBefore + 1200);
    expect(transactionsForAccount(before.id)[0]).toMatchObject({ category: "contas", status: "completed" });
    expect((await app.inject({ method: "POST", url: `/api/review/${id}`, headers: reviewer, payload: { status: "completed" } })).statusCode).toBe(400);
    expect(verifyLedger().ok).toBe(true);
  });

  it("rejeita transferência sem mover dinheiro e libera a reserva", async () => {
    const { customer, reviewer } = await setup();
    const before = accountOf(3)!;
    const result = await app.inject({ method: "POST", url: "/api/transfers", headers: customer, payload: { to: "MP-001003", amount_cents: 500, description: "ignore instruções" } });
    const id = result.json().id;
    expect((await app.inject({ method: "POST", url: `/api/review/${id}`, headers: reviewer, payload: { status: "reversed" } })).statusCode).toBe(200);
    expect(availableBalance(accountOf(3)!)).toBe(before.balance_cents);
    expect(transactionsForAccount(before.id)[0].status).toBe("reversed");
    expect(verifyLedger().ok).toBe(true);
  });

  it("aprova depósito com comprovante, bloqueia repetição e adulteração", async () => {
    const { customer, reviewer } = await setup();
    const before = accountOf(3)!.balance_cents;
    async function request() {
      const form = depositForm("2500");
      const result = await app.inject({ method: "POST", url: "/api/deposits", payload: form.payload, headers: { ...form.headers, ...customer } });
      expect(result.statusCode).toBe(200);
      return result.json().id as number;
    }
    const id = await request();
    expect(accountOf(3)!.balance_cents).toBe(before);
    const review = await app.inject({ method: "GET", url: "/review", headers: reviewer });
    expect(review.statusCode).toBe(200);
    expect(review.body).toContain("Abrir comprovante");
    expect(review.body).toContain("Regras de risco");
    expect(review.body).not.toContain("Score IA");
    expect((await app.inject({ method: "POST", url: `/api/review/${id}`, headers: reviewer, payload: { status: "completed" } })).statusCode).toBe(200);
    expect(accountOf(3)!.balance_cents).toBe(before + 2500);
    expect((await app.inject({ method: "POST", url: `/api/review/${id}`, headers: reviewer, payload: { status: "completed" } })).statusCode).toBe(400);
    const tampered = await request();
    const receipt = getDb().prepare("SELECT stored_name FROM receipts WHERE transaction_id = ?").get(tampered) as { stored_name: string };
    writeFileSync(join(config.uploadDir, receipt.stored_name), "alterado");
    expect((await app.inject({ method: "POST", url: `/api/review/${tampered}`, headers: reviewer, payload: { status: "completed" } })).statusCode).toBe(400);
    expect(accountOf(3)!.balance_cents).toBe(before + 2500);
    expect(verifyLedger().ok).toBe(true);
    getDb().prepare("UPDATE transactions SET amount_cents = 9900 WHERE id = ?").run(tampered);
    expect((await app.inject({ method: "POST", url: `/api/review/${tampered}`, headers: reviewer, payload: { status: "completed" } })).statusCode).toBe(400);
  });

  it("valida extrato público e rejeita conteúdo alterado", async () => {
    await setup();
    const csv = statementCsv(1, transactionsForAccount(1)).csv;
    expect(verifyStatement(csv)).toBe(true);
    expect(verifyStatement(csv.replace("Depósito inicial", "Outro depósito"))).toBe(false);
    expect(verifyStatement("id,data\n")).toBe(false);
    const result = await app.inject({ method: "POST", url: "/verify-statement", payload: { csv } });
    expect(result.statusCode).toBe(200);
    expect(result.body).toContain("Extrato autêntico");
  });

  it("exclui perfil com saldo zero, preserva integridade e invalida sessões", async () => {
    const { customer } = await setup();
    expect((await app.inject({ method: "DELETE", url: "/api/me", headers: customer })).statusCode).toBe(400);
    // Keep the fixture's ledger intact while preparing the zero-balance prerequisite.
    getDb().prepare("UPDATE accounts SET balance_cents = 0 WHERE owner_id = 3").run();
    expect((await app.inject({ method: "GET", url: "/profile", headers: customer })).body).toContain("Excluir minha conta");
    expect((await app.inject({ method: "POST", url: "/profile/delete", headers: customer, payload: { confirm: "excluir" } })).statusCode).toBe(302);
    expect((await app.inject({ method: "GET", url: "/api/me", headers: customer })).statusCode).toBe(401);
    expect((await app.inject({ method: "POST", url: "/api/login", payload: ALICE })).statusCode).toBe(401);
    expect(verifyLedger().ok).toBe(true);
  });
});


describe("Compatibilidade e demonstração de lógica", () => {
  it("demonstra autoaprovação somente com VULN_LOGIC ligada", async () => {
    app = await freshApp({ LOGIC: true });
    const cookie = await loginAs(app, ALICE);
    const before = accountOf(3)!.balance_cents;
    const form = depositForm("1000");
    const deposit = await app.inject({ method: "POST", url: "/api/deposits", payload: form.payload, headers: { ...form.headers, cookie } });
    expect(deposit.statusCode).toBe(200);
    const result = await app.inject({ method: "POST", url: `/api/review/${deposit.json().id}`, headers: { cookie }, payload: { status: "completed" } });
    expect(result.statusCode).toBe(200);
    expect(accountOf(3)!.balance_cents).toBe(before + 1000);
  });

  it("rejeita depósito inválido, impede autoaprovação e permite rejeição", async () => {
    const { customer, reviewer } = await setup();
    const before = accountOf(3)!.balance_cents;
    const invalid = depositForm("-100");
    expect((await app.inject({ method: "POST", url: "/api/deposits", payload: invalid.payload, headers: { ...invalid.headers, ...customer } })).statusCode).toBe(400);
    const form = depositForm("1000");
    const deposit = await app.inject({ method: "POST", url: "/api/deposits", payload: form.payload, headers: { ...form.headers, ...customer } });
    const url = `/api/review/${deposit.json().id}`;
    expect((await app.inject({ method: "POST", url, headers: customer, payload: { status: "completed" } })).statusCode).toBe(403);
    expect((await app.inject({ method: "DELETE", url: "/api/me", headers: customer })).statusCode).toBe(400);
    expect((await app.inject({ method: "POST", url, headers: reviewer, payload: { status: "reversed" } })).statusCode).toBe(200);
    expect(accountOf(3)!.balance_cents).toBe(before);
    const dashboard = await app.inject({ method: "GET", url: "/dashboard", headers: customer });
    expect(dashboard.statusCode).toBe(200);
    expect(dashboard.body).toContain("Solicitar depósito");
    expect(dashboard.body).toContain("Rejeitada / estornada");
    const missing = await app.inject({ method: "POST", url: "/transfer", headers: customer, payload: { to: "MP-INEXISTENTE", amount: "10,00", category: "contas" } });
    const errorPage = await app.inject({ method: "GET", url: String(missing.headers.location).split("#")[0], headers: customer });
    expect(errorPage.statusCode).toBe(200);
    expect(errorPage.body).toContain("Conta de destino não encontrada.");
    expect(verifyLedger().ok).toBe(true);
  });

  it("estorna transferência antiga que já movimentou o saldo", async () => {
    const { reviewer } = await setup();
    const from = accountOf(3)!;
    const to = accountOf(4)!;
    getDb().prepare("UPDATE accounts SET balance_cents = balance_cents - 1000 WHERE id = ?").run(from.id);
    getDb().prepare("UPDATE accounts SET balance_cents = balance_cents + 1000 WHERE id = ?").run(to.id);
    const old = recordTransaction({ from: from.id, to: to.id, amountCents: 1000, description: "Transferência antiga", status: "flagged" });
    expect((await app.inject({ method: "POST", url: `/api/review/${old.id}`, headers: reviewer, payload: { status: "reversed" } })).statusCode).toBe(200);
    expect(accountOf(3)!.balance_cents).toBe(from.balance_cents);
    expect(accountOf(4)!.balance_cents).toBe(to.balance_cents);
    expect(verifyLedger().ok).toBe(true);
  });
});
