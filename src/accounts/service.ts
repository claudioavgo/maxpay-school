import { vuln } from "../config.js";
import { getDb, type AccountRow, type TransactionRow } from "../db/index.js";
import { sha256Hex } from "../crypto/hash.js";
import { sign, verify } from "../crypto/signature.js";
import { readReceipt } from "../receipts/service.js";
import type { ReceiptRow } from "../db/index.js";
import { logSecurityEvent } from "../security/events.js";

const GENESIS = "0".repeat(64);

export function accountOf(userId: number): AccountRow | undefined {
  return getDb().prepare("SELECT * FROM accounts WHERE owner_id = ?").get(userId) as AccountRow | undefined;
}

export function accountById(id: number): AccountRow | undefined {
  return getDb().prepare("SELECT * FROM accounts WHERE id = ?").get(id) as AccountRow | undefined;
}

export function accountByNumber(number: string): AccountRow | undefined {
  return getDb().prepare("SELECT * FROM accounts WHERE number = ?").get(number) as AccountRow | undefined;
}

export function transactionPayload(t: Omit<TransactionRow, "hash" | "signature" | "id" | "created_at" | "funds_moved"> & { created_at: string; funds_moved?: number }): string {
  return [t.from_account_id ?? "", t.to_account_id ?? "", t.amount_cents, t.description, t.status, t.prev_hash, t.created_at].join("|") + (t.funds_moved === 0 ? "|pending" : "");
}

function lastHash(): string {
  const row = getDb().prepare("SELECT hash FROM transactions ORDER BY id DESC LIMIT 1").get() as { hash: string } | undefined;
  return row?.hash ?? GENESIS;
}

export function recordTransaction(input: {
  from: number | null;
  to: number | null;
  amountCents: number;
  description: string;
  status?: TransactionRow["status"];
  category?: string | null;
  fundsMoved?: boolean;
}): TransactionRow {
  const db = getDb();
  const created_at = new Date().toISOString();
  const prev_hash = lastHash();
  const base = {
    funds_moved: input.fundsMoved === false ? 0 : 1,
    from_account_id: input.from,
    to_account_id: input.to,
    amount_cents: input.amountCents,
    description: input.description,
    category: input.category ?? null,
    status: input.status ?? "completed",
    prev_hash,
    created_at,
  };
  const hash = sha256Hex(transactionPayload(base));
  const signature = sign(hash);
  const r = db
    .prepare(
      `INSERT INTO transactions (from_account_id, to_account_id, amount_cents, description, category, status, prev_hash, hash, signature, created_at, funds_moved)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(base.from_account_id, base.to_account_id, base.amount_cents, base.description, base.category, base.status, prev_hash, hash, signature, created_at, input.fundsMoved === false ? 0 : 1);
  return db.prepare("SELECT * FROM transactions WHERE id = ?").get(r.lastInsertRowid) as TransactionRow;
}

export type TransferResult = { ok: true; transaction: TransactionRow } | { ok: false; error: string };

const SUSPICIOUS_PATTERNS = /(ignore|ignor[ae]|instru[cç][õo]es|system prompt|aprovad[oa]|legitim[oa]|cpf de todos|todos os clientes)/i;

export function transfer(fromUserId: number, toNumber: string, amountCents: number, description: string, ip: string, category = "outros"): TransferResult {
  const db = getDb();
  if (!CATEGORIES.includes(category)) return { ok: false, error: "Categoria inválida." };
  const from = accountOf(fromUserId);
  const to = accountByNumber(toNumber);
  if (!from) return { ok: false, error: "Conta de origem não encontrada." };
  if (to && !(getDb().prepare("SELECT password_hash FROM users WHERE id = ?").get(to.owner_id) as { password_hash: string }).password_hash) return { ok: false, error: "Conta de destino encerrada." };
  if (!to) return { ok: false, error: "Conta de destino não encontrada." };
  if (to.id === from.id) return { ok: false, error: "Não é possível transferir para a própria conta." };
  if (!vuln.LOGIC) {
    if (!Number.isSafeInteger(amountCents) || amountCents <= 0) return { ok: false, error: "Valor inválido." };
    if (description.length > 140) return { ok: false, error: "Descrição muito longa." };
  }
  const flagged = amountCents >= 500_000 || SUSPICIOUS_PATTERNS.test(description);
  const run = db.transaction(() => {
    const fresh = accountById(from.id)!;
    if (!vuln.LOGIC && availableBalance(fresh) < amountCents) throw new Error("Saldo insuficiente.");
    if (!flagged) {
      db.prepare("UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ?").run(amountCents, from.id);
      db.prepare("UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?").run(amountCents, to.id);
    }
    return recordTransaction({ from: from.id, to: to.id, amountCents, description, category, fundsMoved: !flagged, status: flagged ? "flagged" : "completed" });
  });
  try {
    const transaction = run();
    logSecurityEvent("transfer", flagged ? "warn" : "info", { userId: fromUserId, ip, details: { id: transaction.id, amountCents, flagged } });
    return { ok: true, transaction };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

export function transactionsForAccount(accountId: number): TransactionRow[] {
  return getDb()
    .prepare("SELECT t.*, COALESCE(r.status, t.status) AS status FROM transactions t LEFT JOIN transaction_reviews r ON r.transaction_id = t.id WHERE from_account_id = ? OR to_account_id = ? ORDER BY t.id DESC")
    .all(accountId, accountId) as TransactionRow[];
}

export function searchTransactions(accountId: number, term: string): TransactionRow[] {
  const db = getDb();
  if (vuln.SQLI) {
    const sql = `SELECT * FROM transactions WHERE (from_account_id = ${accountId} OR to_account_id = ${accountId}) AND description LIKE '%${term}%' ORDER BY id DESC`;
    return db.prepare(sql).all() as TransactionRow[];
  }
  return db
    .prepare("SELECT t.*, COALESCE(r.status, t.status) AS status FROM transactions t LEFT JOIN transaction_reviews r ON r.transaction_id = t.id WHERE (from_account_id = ? OR to_account_id = ?) AND description LIKE ? ORDER BY t.id DESC")
    .all(accountId, accountId, `%${term}%`) as TransactionRow[];
}

export interface IntegrityReport {
  ok: boolean;
  checked: number;
  broken: Array<{ id: number; reason: "hash_mismatch" | "chain_broken" | "bad_signature" }>;
}

export function verifyLedger(): IntegrityReport {
  const rows = getDb().prepare("SELECT * FROM transactions ORDER BY id ASC").all() as TransactionRow[];
  const broken: IntegrityReport["broken"] = [];
  let prev = GENESIS;
  for (const t of rows) {
    const expected = sha256Hex(transactionPayload({ ...t }));
    if (t.prev_hash !== prev) broken.push({ id: t.id, reason: "chain_broken" });
    else if (expected !== t.hash) broken.push({ id: t.id, reason: "hash_mismatch" });
    else if (!verify(t.hash, t.signature)) broken.push({ id: t.id, reason: "bad_signature" });
    prev = t.hash;
  }
  const reviews = getDb().prepare("SELECT r.*, t.hash FROM transaction_reviews r JOIN transactions t ON t.id = r.transaction_id").all() as Array<{ transaction_id: number; status: string; reviewer_id: number; signature: string; hash: string }>;
  for (const r of reviews) {
    if (!verify(`${r.hash}|${r.status}|${r.reviewer_id}`, r.signature)) broken.push({ id: r.transaction_id, reason: "bad_signature" });
  }
  if (broken.length) logSecurityEvent("ledger_integrity_failure", "critical", { details: broken });
  return { ok: broken.length === 0, checked: rows.length, broken };
}

export const CATEGORIES = ["mercado", "transporte", "lazer", "contas", "saúde", "educação", "outros"];

export function availableBalance(account: AccountRow): number {
  const pending = getDb().prepare(`SELECT COALESCE(SUM(amount_cents), 0) AS amount FROM transactions
    WHERE from_account_id = ? AND status = 'flagged' AND funds_moved = 0
    AND id NOT IN (SELECT transaction_id FROM transaction_reviews)`).get(account.id) as { amount: number };
  return account.balance_cents - pending.amount;
}

export function flaggedTransactions(): Array<TransactionRow & { receipt_id: number | null; from_number: string | null; to_number: string | null }> {
  return getDb().prepare(`SELECT t.*, receipts.id AS receipt_id, origin.number AS from_number, destination.number AS to_number FROM transactions t
    LEFT JOIN accounts origin ON origin.id = t.from_account_id
    LEFT JOIN accounts destination ON destination.id = t.to_account_id
    LEFT JOIN receipts ON receipts.transaction_id = t.id
    WHERE t.status = 'flagged' AND t.id NOT IN (SELECT transaction_id FROM transaction_reviews)
    ORDER BY t.id DESC`).all() as Array<TransactionRow & { receipt_id: number | null; from_number: string | null; to_number: string | null }>;
}

export function reviewTransaction(id: number, status: "completed" | "reversed", reviewerId: number, ip: string): void {
  const db = getDb();
  db.transaction(() => {
    const t = db.prepare("SELECT * FROM transactions WHERE id = ?").get(id) as TransactionRow | undefined;
    if (!t || t.status !== "flagged" || db.prepare("SELECT 1 FROM transaction_reviews WHERE transaction_id = ?").get(id)) throw new Error("Transação não está pendente.");
    if (!["completed", "reversed"].includes(status)) throw new Error("Decisão inválida.");
    if (!verifyLedger().ok) throw new Error("Falha de integridade no livro-razão.");
    const ownAccount = accountOf(reviewerId);
    if (!vuln.LOGIC && ownAccount && [t.from_account_id, t.to_account_id].includes(ownAccount.id)) throw new Error("Não é permitido revisar a própria transação.");
    if (status === "completed" && t.from_account_id === null) {
      const receipt = db.prepare("SELECT * FROM receipts WHERE transaction_id = ?").get(id) as ReceiptRow | undefined;
      if (!receipt || !readReceipt(receipt, ip).ok) throw new Error("Comprovante ausente ou com falha de integridade.");
    }
    if (status === "completed" && !t.funds_moved) {
      if (t.from_account_id !== null) {
        const result = db.prepare("UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ? AND balance_cents >= ?").run(t.amount_cents, t.from_account_id, t.amount_cents);
        if (!result.changes) throw new Error("Saldo insuficiente.");
      }
      db.prepare("UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?").run(t.amount_cents, t.to_account_id);
    }
    // Older flagged transfers already moved money. Rejecting them must refund it.
    if (status === "reversed" && t.funds_moved) {
      const result = db.prepare("UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ? AND balance_cents >= ?").run(t.amount_cents, t.to_account_id, t.amount_cents);
      if (!result.changes) throw new Error("Saldo do destinatário insuficiente para estornar.");
      db.prepare("UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?").run(t.amount_cents, t.from_account_id);
    }
    db.prepare("INSERT INTO transaction_reviews (transaction_id, status, reviewer_id, signature) VALUES (?, ?, ?, ?)")
      .run(id, status, reviewerId, sign(`${t.hash}|${status}|${reviewerId}`));
    logSecurityEvent("transaction_review", "info", { userId: reviewerId, ip, details: { id, status } });
  })();
}
