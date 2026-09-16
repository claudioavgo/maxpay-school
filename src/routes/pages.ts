import type { FastifyInstance } from "fastify";
import { vuln } from "../config.js";
import { getDb, type TransactionRow, type UserRow } from "../db/index.js";
import { login, enableMfa, disableMfa } from "../auth/login.js";
import { currentUser, destroySession, establishSession } from "../auth/session.js";
import { requireAuth, requireRole } from "../authz/guards.js";
import { accountOf, flaggedTransactions, searchTransactions, transactionsForAccount, transfer, verifyLedger } from "../accounts/service.js";
import { receiptsOf, storeReceipt } from "../receipts/service.js";
import { ask, cents, suspicionScore } from "../ai/assistant.js";
import { userView } from "../security/privacy.js";
import { listSecurityEvents } from "../security/events.js";

export async function pageRoutes(app: FastifyInstance): Promise<void> {
  app.get("/", async (req, reply) => {
    const user = currentUser(req);
    return reply.redirect(user ? "/dashboard" : "/login");
  });

  app.get<{ Querystring: { error?: string; mfa?: string } }>("/login", async (req, reply) => {
    return reply.view("login.ejs", { error: req.query.error ?? null, mfa: req.query.mfa === "1", user: null });
  });

  app.post<{ Body: { email: string; password: string; totp?: string } }>("/login", {
    config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
  }, async (req, reply) => {
    const r = await login(req.body.email, req.body.password, req.body.totp || undefined, req.ip);
    if (!r.ok) {
      if (r.reason === "mfa_required") return reply.redirect("/login?mfa=1");
      const msg = r.reason === "locked" ? "Conta bloqueada temporariamente." : "Credenciais inválidas.";
      return reply.redirect("/login?error=" + encodeURIComponent(msg));
    }
    establishSession(req, r.user);
    return reply.redirect("/dashboard");
  });

  app.post("/logout", async (req, reply) => {
    destroySession(req, reply);
    return reply.redirect("/login");
  });

  app.get<{ Querystring: { q?: string; msg?: string; error?: string } }>("/dashboard", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    if (user.role !== "customer") return reply.redirect(user.role === "admin" ? "/admin" : "/review");
    const account = accountOf(user.id)!;
    const q = req.query.q ?? "";
    let transactions: TransactionRow[];
    let error = req.query.error ?? null;
    try {
      transactions = q ? searchTransactions(account.id, q) : transactionsForAccount(account.id);
    } catch (e) {
      transactions = [];
      error = vuln.MISCONFIG ? (e as Error).stack ?? "" : "Consulta inválida.";
    }
    return reply.view("dashboard.ejs", { user, account, transactions, receipts: receiptsOf(user.id), q, msg: req.query.msg ?? null, error, cents });
  });

  app.post<{ Body: { to: string; amount: string; description?: string } }>("/transfer", async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    const amountCents = Math.round(Number(String(req.body.amount).replace(",", ".")) * 100);
    const r = transfer(user.id, req.body.to, amountCents, req.body.description ?? "", req.ip);
    return reply.redirect(r.ok ? "/dashboard?msg=" + encodeURIComponent("Transferência realizada.") : "/dashboard?error=" + encodeURIComponent(r.error));
  });

  app.post("/receipts", async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    const file = await req.file();
    if (!file) return reply.redirect("/dashboard?error=" + encodeURIComponent("Nenhum arquivo enviado."));
    const r = storeReceipt(user.id, file.filename, file.mimetype, await file.toBuffer(), null, req.ip);
    return reply.redirect(r.ok ? "/dashboard?msg=" + encodeURIComponent("Comprovante enviado.") : "/dashboard?error=" + encodeURIComponent(r.error));
  });

  app.get("/assistant", async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    const history = getDb().prepare("SELECT * FROM ai_messages WHERE user_id = ? ORDER BY id DESC LIMIT 10").all(user.id);
    return reply.view("assistant.ejs", { user, history, result: null });
  });

  app.post<{ Body: { question: string } }>("/assistant", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
  }, async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    const result = await ask(user.id, String(req.body.question).slice(0, 500), req.ip);
    const history = getDb().prepare("SELECT * FROM ai_messages WHERE user_id = ? ORDER BY id DESC LIMIT 10").all(user.id);
    return reply.view("assistant.ejs", { user, history, result });
  });

  app.get("/profile", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    const row = getDb().prepare("SELECT * FROM users WHERE id = ?").get(user.id) as UserRow;
    return reply.view("profile.ejs", { user, me: userView(row, user.role, false), mfa: null });
  });

  app.post("/profile/mfa/enable", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    const mfa = enableMfa(user.id);
    const row = getDb().prepare("SELECT * FROM users WHERE id = ?").get(user.id) as UserRow;
    return reply.view("profile.ejs", { user, me: userView(row, user.role, false), mfa });
  });

  app.post("/profile/mfa/disable", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    disableMfa(user.id);
    return reply.redirect("/profile");
  });

  app.get("/review", async (req, reply) => {
    const user = requireRole(req, reply, "analyst", "admin");
    if (!user) return;
    const flagged = await Promise.all(flaggedTransactions().map(async (t) => ({ ...t, ai: await suspicionScore(t) })));
    const users = (getDb().prepare("SELECT * FROM users WHERE role = 'customer' ORDER BY id").all() as UserRow[]).map((u) => userView(u, user.role, false));
    return reply.view("review.ejs", { user, flagged, users, ledger: verifyLedger(), cents });
  });

  app.get("/admin", async (req, reply) => {
    const user = requireRole(req, reply, "admin");
    if (!user) return;
    return reply.view("admin.ejs", { user, events: listSecurityEvents(100), vuln });
  });
}
