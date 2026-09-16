import type { FastifyInstance } from "fastify";
import { vuln } from "../config.js";
import { getDb, type TransactionRow, type UserRow } from "../db/index.js";
import { login, enableMfa, disableMfa } from "../auth/login.js";
import { currentUser, destroySession, establishSession } from "../auth/session.js";
import { requireAuth, requireRole } from "../authz/guards.js";
import { accountOf, availableBalance, CATEGORIES, reviewTransaction, flaggedTransactions, searchTransactions, transactionsForAccount, transfer, verifyLedger } from "../accounts/service.js";
import { receiptsOf } from "../receipts/service.js";
import { requestDeposit } from "../accounts/deposits.js";
import { ask, cents, suspicionScore } from "../ai/assistant.js";
import { closeAccount, userView } from "../security/privacy.js";
import { verifyStatement } from "../accounts/statement.js";
import { toDataURL } from "qrcode";
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

  app.get<{ Querystring: { q?: string; msg?: string; error?: string; transferError?: string } }>("/dashboard", async (req, reply) => {
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
    return reply.view("dashboard.ejs", { user, account, available: availableBalance(account), categories: CATEGORIES, transactions, receipts: receiptsOf(user.id), q, msg: req.query.msg ?? null, error, transferError: req.query.transferError, cents });
  });

  app.post<{ Body: { to: string; amount: string; description?: string; category?: string } }>("/transfer", async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    const amountCents = Math.round(Number(String(req.body.amount).replace(",", ".")) * 100);
    const r = transfer(user.id, req.body.to, amountCents, req.body.description ?? "", req.ip, req.body.category);
    return reply.redirect(r.ok ? "/dashboard?msg=" + encodeURIComponent(r.transaction.status === "flagged" ? "Transferência em análise. O valor está reservado até a decisão." : "Transferência realizada.") : "/dashboard?transferError=" + encodeURIComponent(r.error) + "#transfer");
  });

  app.post("/deposits", async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    const file = await req.file();
    if (!file) return reply.redirect("/dashboard?error=" + encodeURIComponent("Nenhum arquivo enviado."));
    const data = await file.toBuffer();
    const field = file.fields.amount as { value?: string } | undefined;
    const amount = Math.round(Number(String(field?.value ?? "").replace(",", ".")) * 100);
    const r = requestDeposit(user.id, amount, file.filename, file.mimetype, data, req.ip);
    return reply.redirect(r.ok ? "/dashboard?msg=" + encodeURIComponent("Depósito enviado para análise. O saldo será creditado após aprovação.") : "/dashboard?error=" + encodeURIComponent(r.error));
  });

  app.get("/assistant", async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    const history = getDb().prepare("SELECT * FROM ai_messages WHERE user_id = ? ORDER BY id DESC LIMIT 30").all(user.id).reverse();
    return reply.view("assistant.ejs", { user, history, error: null, question: "" });
  });

  app.post<{ Body: { question: string } }>("/assistant", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
  }, async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    let error = null;
    const question = String(req.body.question ?? "").trim().slice(0, 500);
    try {
      await ask(user.id, question, req.ip);
      return reply.redirect("/assistant");
    }
    catch { error = "O assistente está indisponível no momento. Tente novamente."; }
    const history = getDb().prepare("SELECT * FROM ai_messages WHERE user_id = ? ORDER BY id DESC LIMIT 30").all(user.id).reverse();
    return reply.view("assistant.ejs", { user, history, error, question });
  });

  app.get<{ Querystring: { error?: string } }>("/profile", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    const row = getDb().prepare("SELECT * FROM users WHERE id = ?").get(user.id) as UserRow;
    return reply.view("profile.ejs", { user, me: userView(row, user.role, false), mfa: null, error: req.query.error });
  });

  app.post("/profile/mfa/enable", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    const enabled = enableMfa(user.id);
    const mfa = { ...enabled, qr: await toDataURL(enabled.otpauth, { width: 220, margin: 1 }) };
    const row = getDb().prepare("SELECT * FROM users WHERE id = ?").get(user.id) as UserRow;
    return reply.view("profile.ejs", { user, me: userView(row, user.role, false), mfa, error: null });
  });

  app.post("/profile/mfa/disable", async (req, reply) => {
    const user = requireAuth(req, reply);
    if (!user) return;
    disableMfa(user.id);
    return reply.redirect("/profile");
  });

  app.get<{ Querystring: { error?: string; msg?: string } }>("/review", async (req, reply) => {
    const user = requireRole(req, reply, "analyst", "admin");
    if (!user) return;
    const flagged = await Promise.all(flaggedTransactions().map(async (t) => ({ ...t, risk: await suspicionScore(t) })));
    const users = (getDb().prepare("SELECT * FROM users WHERE role = 'customer' AND password_hash != '' ORDER BY id").all() as UserRow[]).map((u) => userView(u, user.role, false));
    return reply.view("review.ejs", { user, flagged, users, error: req.query.error, msg: req.query.msg, ledger: verifyLedger(), cents });
  });

  app.post<{ Params: { id: string }; Body: { status: "completed" | "reversed" } }>("/review/:id", async (req, reply) => {
    const user = requireRole(req, reply, "analyst", "admin");
    if (!user) return;
    try { reviewTransaction(Number(req.params.id), req.body.status, user.id, req.ip); }
    catch (e) { return reply.redirect("/review?error=" + encodeURIComponent((e as Error).message)); }
    return reply.redirect("/review?msg=" + encodeURIComponent("Decisão registrada."));
  });

  app.post<{ Body: { confirm?: string } }>("/profile/delete", async (req, reply) => {
    const user = requireRole(req, reply, "customer");
    if (!user) return;
    try {
      if (req.body.confirm !== "excluir") throw new Error("Confirme a exclusão da conta.");
      closeAccount(user.id);
    } catch (e) { return reply.redirect("/profile?error=" + encodeURIComponent((e as Error).message)); }
    destroySession(req, reply);
    return reply.redirect("/login");
  });

  app.get("/verify-statement", async (req, reply) => reply.view("verify-statement.ejs", { user: currentUser(req), result: null }));
  app.post<{ Body: { csv?: string } }>("/verify-statement", async (req, reply) => {
    const csv = String(req.body.csv ?? "").replace(/\r\n/g, "\n");
    return reply.view("verify-statement.ejs", { user: currentUser(req), result: verifyStatement(csv) });
  });

  app.get("/admin", async (req, reply) => {
    const user = requireRole(req, reply, "admin");
    if (!user) return;
    return reply.view("admin.ejs", { user, events: listSecurityEvents(100), vuln });
  });
}
