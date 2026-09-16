import { createHmac, randomBytes } from "node:crypto";
import { config } from "../config.js";
import { accountOf } from "../accounts/service.js";
import { deleteReceipt, receiptsOf } from "../receipts/service.js";
import { encryptString, decryptString } from "../crypto/symmetric.js";
import { getDb, type UserRow } from "../db/index.js";

export function maskCpf(cpf: string): string {
  const d = cpf.replace(/\D/g, "");
  return `***.***.${d.slice(6, 9)}-**`;
}

export function formatCpf(cpf: string): string {
  const d = cpf.replace(/\D/g, "");
  return `${d.slice(0, 3)}.${d.slice(3, 6)}.${d.slice(6, 9)}-${d.slice(9)}`;
}

export function pseudonym(userId: number): string {
  return "U-" + createHmac("sha256", config.sessionSecret + ":pseudo").update(String(userId)).digest("hex").slice(0, 10);
}

export function ageBand(birthDate: string): string {
  const age = Math.floor((Date.now() - new Date(birthDate).getTime()) / (365.25 * 24 * 3600 * 1000));
  const lo = Math.floor(age / 10) * 10;
  return `${lo}-${lo + 9}`;
}

export function userView(u: UserRow, viewerRole: "customer" | "analyst" | "admin", exposeAll: boolean) {
  const cpf = decryptString(u.cpf_enc);
  if (exposeAll) return { ...u, cpf };
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    cpf: viewerRole === "admin" ? formatCpf(cpf) : maskCpf(cpf),
    phone: u.phone,
    birth_date: u.birth_date,
    mfa_enabled: Boolean(u.mfa_secret),
    created_at: u.created_at,
  };
}

export function anonymizedDatasetCsv(): string {
  const rows = getDb()
    .prepare(
      `SELECT u.id AS user_id, u.birth_date, t.amount_cents, COALESCE(r.status, t.status) AS status, t.category, t.created_at,
              CASE WHEN t.to_account_id = a.id THEN 'credito' ELSE 'debito' END AS tipo
       FROM transactions t
       LEFT JOIN transaction_reviews r ON r.transaction_id = t.id
       JOIN accounts a ON a.id = t.from_account_id OR a.id = t.to_account_id
       JOIN users u ON u.id = a.owner_id
       WHERE u.password_hash != ''
       ORDER BY t.id`,
    )
    .all() as Array<{ user_id: number; birth_date: string; amount_cents: number; status: string; category: string | null; created_at: string; tipo: string }>;
  const lines = ["pseudonimo,faixa_etaria,tipo,valor_centavos,status,categoria,mes"];
  for (const r of rows) {
    lines.push([pseudonym(r.user_id), ageBand(r.birth_date), r.tipo, r.amount_cents, r.status, r.category ?? "", r.created_at.slice(0, 7)].join(","));
  }
  return lines.join("\n") + "\n";
}

export function closeAccount(userId: number): void {
  const db = getDb();
  const account = accountOf(userId);
  if (!account) throw new Error("Conta não encontrada.");
  if (account.balance_cents !== 0) throw new Error("Transfira seu saldo antes de excluir a conta.");
  const pending = db.prepare(`SELECT 1 FROM transactions WHERE (from_account_id = ? OR to_account_id = ?)
    AND status = 'flagged' AND id NOT IN (SELECT transaction_id FROM transaction_reviews)`).get(account.id, account.id);
  if (pending) throw new Error("Aguarde a revisão das transações pendentes antes de excluir a conta.");
  for (const receipt of receiptsOf(userId)) deleteReceipt(receipt);
  db.transaction(() => {
    db.prepare("DELETE FROM ai_messages WHERE user_id = ?").run(userId);
    db.prepare("UPDATE users SET name = 'Conta excluída', email = ?, password_hash = '', cpf_enc = ?, cpf_hash = ?, phone = '', birth_date = '', mfa_secret = NULL WHERE id = ?")
      .run(`excluido-${userId}@invalid.local`, encryptString(""), randomBytes(32).toString("hex"), userId);
  })();
}
