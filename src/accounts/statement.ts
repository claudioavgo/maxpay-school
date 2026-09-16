import { sha256Hex } from "../crypto/hash.js";
import { sign, verify } from "../crypto/signature.js";
import type { TransactionRow } from "../db/index.js";

export function statementCsv(accountId: number, rows: TransactionRow[]): { csv: string; sha256: string; signature: string } {
  const lines = ["id,data,tipo,valor_centavos,descricao,status"];
  for (const t of rows) {
    const type = t.to_account_id === accountId ? "credito" : "debito";
    lines.push([t.id, t.created_at, type, t.amount_cents, csvEscape(t.description), t.status].join(","));
  }
  const csv = lines.join("\n") + "\n";
  const digest = sha256Hex(csv);
  const signature = sign(digest);
  return { csv: csv + `# SHA-256,${digest}\n# Assinatura,${signature}\n`, sha256: digest, signature };
}

function csvEscape(s: string): string {
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function verifyStatement(csv: string): boolean {
  const match = /# SHA-256,([a-f0-9]{64})\n# Assinatura,([A-Za-z0-9+/=]+)\n?$/.exec(csv);
  if (!match || (match.index > 0 && csv[match.index - 1] !== "\n")) return false;
  const content = csv.slice(0, match.index);
  try { return sha256Hex(content) === match[1] && verify(match[1]!, match[2]!); }
  catch { return false; }
}
