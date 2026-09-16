import { getDb } from "../db/index.js";
import { accountOf, recordTransaction, type TransferResult } from "./service.js";
import { storeReceipt } from "../receipts/service.js";

export function requestDeposit(userId: number, amountCents: number, filename: string, mime: string, data: Buffer, ip: string): TransferResult {
  if (!Number.isSafeInteger(amountCents) || amountCents <= 0) return { ok: false, error: "Valor inválido." };
  const account = accountOf(userId);
  if (!account) return { ok: false, error: "Conta não encontrada." };
  try {
    const transaction = getDb().transaction(() => {
      const t = recordTransaction({ from: null, to: account.id, amountCents, description: "Depósito com comprovante", category: "depósito", status: "flagged", fundsMoved: false });
      const r = storeReceipt(userId, filename, mime, data, t.id, ip);
      if (!r.ok) throw new Error(r.error);
      return t;
    })();
    return { ok: true, transaction };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}
