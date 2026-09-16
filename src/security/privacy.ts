import { createHmac } from "node:crypto";
import { config } from "../config.js";
import { decryptString } from "../crypto/symmetric.js";
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
      `SELECT u.id AS user_id, u.birth_date, t.amount_cents, t.status, t.category, t.created_at,
              CASE WHEN t.to_account_id = a.id THEN 'credito' ELSE 'debito' END AS tipo
       FROM transactions t
       JOIN accounts a ON a.id = t.from_account_id OR a.id = t.to_account_id
       JOIN users u ON u.id = a.owner_id
       ORDER BY t.id`,
    )
    .all() as Array<{ user_id: number; birth_date: string; amount_cents: number; status: string; category: string | null; created_at: string; tipo: string }>;
  const lines = ["pseudonimo,faixa_etaria,tipo,valor_centavos,status,categoria,mes"];
  for (const r of rows) {
    lines.push([pseudonym(r.user_id), ageBand(r.birth_date), r.tipo, r.amount_cents, r.status, r.category ?? "", r.created_at.slice(0, 7)].join(","));
  }
  return lines.join("\n") + "\n";
}
