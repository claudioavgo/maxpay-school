import { sha256Hex } from "../crypto/hash.js";
import { sign } from "../crypto/signature.js";
import type { TransactionRow } from "../db/index.js";

export function statementCsv(accountId: number, rows: TransactionRow[]): { csv: string; sha256: string; signature: string } {
  const lines = ["id,data,tipo,valor_centavos,descricao,status"];
  for (const t of rows) {
    const type = t.to_account_id === accountId ? "credito" : "debito";
    lines.push([t.id, t.created_at, type, t.amount_cents, csvEscape(t.description), t.status].join(","));
  }
  const csv = lines.join("\n") + "\n";
  const digest = sha256Hex(csv);
  return { csv, sha256: digest, signature: sign(digest) };
}

function csvEscape(s: string): string {
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
