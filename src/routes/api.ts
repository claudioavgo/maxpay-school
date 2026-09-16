import type { FastifyInstance } from "fastify";
import { vuln } from "../config.js";
import { getDb, type UserRow } from "../db/index.js";
import { login } from "../auth/login.js";
import { establishSession, destroySession } from "../auth/session.js";
import { ownsOrPrivileged, requireAuth, requireRole } from "../authz/guards.js";
import { accountById, accountOf, flaggedTransactions, searchTransactions, setTransactionStatus, transactionsForAccount, transfer, verifyLedger } from "../accounts/service.js";
import { statementCsv } from "../accounts/statement.js";
import { readReceipt, receiptById, receiptsOf, storeReceipt } from "../receipts/service.js";
import { ask, suspicionScore } from "../ai/assistant.js";
import { anonymizedDatasetCsv, userView } from "../security/privacy.js";
import { listSecurityEvents } from "../security/events.js";
import { publicKeyPem } from "../crypto/signature.js";

export async function apiRoutes(app: FastifyInstance): Promise<void> {
  app.post<{ Body: { email: string; password: string; totp?: string } }>("/api/login", {
    config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
    schema: { body: { type: "object", required: ["email", "password"], properties: { email: { type: "string" }, password: { type: "string" }, totp: { type: "string" } } } },
  }, async (req, reply) => {
    const r = await login(req.body.email, req.body.password, req.body.totp, req.ip);
    if (!r.ok) return reply.code(401).send({ error: r.reason });
    establishSession(req, r.user);
    return { ok: true, user: req.session.get("user") };
  });

  app.post("/api/logout", async (req, reply) => {
    destroySession(req, reply);
    return { ok: true };
  });

  app.get("/api/me", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    const row = getDb().prepare("SELECT * FROM users WHERE id = ?").get(user.id) as UserRow;
    return userView(row, user.role, vuln.EXPOSE);
  });

  app.get<{ Params: { id: string } }>("/api/accounts/:id", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    const account = accountById(Number(req.params.id));
    if (!account) return reply.code(404).send({ error: "Conta não encontrada." });
    if (!ownsOrPrivileged(req, user, account.owner_id)) return reply.code(403).send({ error: "Acesso negado." });
    return { ...account, transactions: transactionsForAccount(account.id) };
  });

  app.get<{ Querystring: { q?: string } }>("/api/transactions/search", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    const account = accountOf(user.id);
    if (!account) return [];
    try {
      return searchTransactions(account.id, req.query.q ?? "");
    } catch (e) {
      return reply.code(400).send({ error: vuln.MISCONFIG ? (e as Error).stack : "Consulta inválida." });
    }
  });

  app.post<{ Body: { to: string; amount_cents: number; description?: string } }>("/api/transfers", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    schema: vuln.LOGIC ? undefined : { body: { type: "object", required: ["to", "amount_cents"], properties: { to: { type: "string" }, amount_cents: { type: "integer", minimum: 1 }, description: { type: "string", maxLength: 140 } } } },
  }, async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    const r = transfer(user.id, String(req.body.to), Number(req.body.amount_cents), String(req.body.description ?? ""), req.ip);
    if (!r.ok) return reply.code(400).send({ error: r.error });
    return r.transaction;
  });

  app.get("/api/statement.csv", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    const account = accountOf(user.id);
    if (!account) return reply.code(404).send({ error: "Sem conta." });
    const s = statementCsv(account.id, transactionsForAccount(account.id));
    reply.header("Content-Type", "text/csv; charset=utf-8");
    reply.header("Content-Disposition", `attachment; filename="extrato-${account.number}.csv"`);
    reply.header("X-Content-SHA256", s.sha256);
    reply.header("X-Signature", s.signature);
    return s.csv;
  });

  app.get("/api/public-key", async () => ({ algorithm: "RSA-2048 PSS SHA-256", pem: publicKeyPem() }));

  app.get("/api/ledger/verify", async (req, reply) => {
    const user = requireRole(req, reply, "analyst", "admin");
    if (!user) return;
    return verifyLedger();
  });

  app.post("/api/receipts", async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    const file = await req.file();
    if (!file) return reply.code(400).send({ error: "Nenhum arquivo enviado." });
    const data = await file.toBuffer();
    const txField = file.fields.transaction_id as { value?: string } | undefined;
    const r = storeReceipt(user.id, file.filename, file.mimetype, data, txField?.value ? Number(txField.value) : null, req.ip);
    if (!r.ok) return reply.code(400).send({ error: r.error });
    return r.receipt;
  });

  app.get("/api/receipts", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    return receiptsOf(user.id);
  });

  app.get<{ Params: { id: string } }>("/api/receipts/:id", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    const receipt = receiptById(Number(req.params.id));
    if (!receipt) return reply.code(404).send({ error: "Comprovante não encontrado." });
    if (!ownsOrPrivileged(req, user, receipt.owner_id)) return reply.code(403).send({ error: "Acesso negado." });
    const r = readReceipt(receipt, req.ip);
    if (!r.ok) return reply.code(r.error === "missing" ? 404 : 409).send({ error: r.error === "tampered" ? "Falha de integridade: o arquivo foi alterado." : "Arquivo ausente." });
    reply.header("Content-Type", receipt.mime);
    reply.header("Content-Disposition", `inline; filename="${encodeURIComponent(receipt.original_name)}"`);
    reply.header("X-Content-SHA256", receipt.sha256);
    return r.data;
  });

  app.post<{ Body: { question: string } }>("/api/ai/ask", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
    schema: { body: { type: "object", required: ["question"], properties: { question: { type: "string", maxLength: 500 } } } },
  }, async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    return ask(user.id, req.body.question, req.ip);
  });

  app.get("/api/review/flagged", async (req, reply) => {
    const user = requireRole(req, reply, "analyst", "admin");
    if (!user) return;
    const rows = flaggedTransactions();
    return Promise.all(rows.map(async (t) => ({ ...t, ai: await suspicionScore(t) })));
  });

  app.post<{ Params: { id: string }; Body: { status: "completed" | "reversed" } }>("/api/review/:id", {
    schema: { body: { type: "object", required: ["status"], properties: { status: { type: "string", enum: ["completed", "reversed"] } } } },
  }, async (req, reply) => {
    const user = requireRole(req, reply, "analyst", "admin");
    if (!user) return;
    setTransactionStatus(Number(req.params.id), req.body.status);
    return { ok: true };
  });

  app.get("/api/users", async (req, reply) => {
    const user = requireRole(req, reply, "analyst", "admin");
    if (!user) return;
    const rows = getDb().prepare("SELECT * FROM users ORDER BY id").all() as UserRow[];
    return rows.map((u) => userView(u, user.role, vuln.EXPOSE));
  });

  app.get("/api/admin/events", async (req, reply) => {
    const user = requireRole(req, reply, "admin");
    if (!user) return;
    return listSecurityEvents();
  });

  app.get("/api/admin/dataset.csv", async (req, reply) => {
    const user = requireRole(req, reply, "admin");
    if (!user) return;
    reply.header("Content-Type", "text/csv; charset=utf-8");
    reply.header("Content-Disposition", 'attachment; filename="dataset-anonimizado.csv"');
    return anonymizedDatasetCsv();
  });

  app.delete("/api/me", async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    getDb().prepare("DELETE FROM users WHERE id = ?").run(user.id);
    destroySession(req, reply);
    return { ok: true };
  });
}
