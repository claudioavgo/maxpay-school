import { vuln } from "../config.js";
import { getDb, type AccountRow, type TransactionRow } from "../db/index.js";
import { sha256Hex } from "../crypto/hash.js";
import { sign, verify } from "../crypto/signature.js";
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

export function transactionPayload(t: Omit<TransactionRow, "hash" | "signature" | "id" | "created_at"> & { created_at: string }): string {
  return [t.from_account_id ?? "", t.to_account_id ?? "", t.amount_cents, t.description, t.status, t.prev_hash, t.created_at].join("|");
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
}): TransactionRow {
  const db = getDb();
  const created_at = new Date().toISOString();
  const prev_hash = lastHash();
  const base = {
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
      `INSERT INTO transactions (from_account_id, to_account_id, amount_cents, description, category, status, prev_hash, hash, signature, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(base.from_account_id, base.to_account_id, base.amount_cents, base.description, base.category, base.status, prev_hash, hash, signature, created_at);
  return db.prepare("SELECT * FROM transactions WHERE id = ?").get(r.lastInsertRowid) as TransactionRow;
}

export type TransferResult = { ok: true; transaction: TransactionRow } | { ok: false; error: string };

const SUSPICIOUS_PATTERNS = /(ignore|ignor[ae]|instru[cç][õo]es|system prompt|aprovad[oa]|legitim[oa]|cpf de todos|todos os clientes)/i;

export function transfer(fromUserId: number, toNumber: string, amountCents: number, description: string, ip: string): TransferResult {
  const db = getDb();
  const from = accountOf(fromUserId);
  const to = accountByNumber(toNumber);
  if (!from) return { ok: false, error: "Conta de origem não encontrada." };
  if (!to) return { ok: false, error: "Conta de destino não encontrada." };
  if (to.id === from.id) return { ok: false, error: "Não é possível transferir para a própria conta." };
  if (!vuln.LOGIC) {
    if (!Number.isInteger(amountCents) || amountCents <= 0) return { ok: false, error: "Valor inválido." };
    if (description.length > 140) return { ok: false, error: "Descrição muito longa." };
  }
  const flagged = amountCents >= 500_000 || SUSPICIOUS_PATTERNS.test(description);
  const run = db.transaction(() => {
    const fresh = accountById(from.id)!;
    if (!vuln.LOGIC && fresh.balance_cents < amountCents) throw new Error("Saldo insuficiente.");
    db.prepare("UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ?").run(amountCents, from.id);
    db.prepare("UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?").run(amountCents, to.id);
    return recordTransaction({ from: from.id, to: to.id, amountCents, description, status: flagged ? "flagged" : "completed" });
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
    .prepare("SELECT * FROM transactions WHERE from_account_id = ? OR to_account_id = ? ORDER BY id DESC")
    .all(accountId, accountId) as TransactionRow[];
}

export function searchTransactions(accountId: number, term: string): TransactionRow[] {
  const db = getDb();
  if (vuln.SQLI) {
    const sql = `SELECT * FROM transactions WHERE (from_account_id = ${accountId} OR to_account_id = ${accountId}) AND description LIKE '%${term}%' ORDER BY id DESC`;
    return db.prepare(sql).all() as TransactionRow[];
  }
  return db
    .prepare("SELECT * FROM transactions WHERE (from_account_id = ? OR to_account_id = ?) AND description LIKE ? ORDER BY id DESC")
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
  if (broken.length) logSecurityEvent("ledger_integrity_failure", "critical", { details: broken });
  return { ok: broken.length === 0, checked: rows.length, broken };
}

export function flaggedTransactions(): TransactionRow[] {
  return getDb().prepare("SELECT * FROM transactions WHERE status = 'flagged' ORDER BY id DESC").all() as TransactionRow[];
}

export function setTransactionStatus(id: number, status: TransactionRow["status"]): void {
  getDb().prepare("UPDATE transactions SET status = ? WHERE id = ?").run(status, id);
}
