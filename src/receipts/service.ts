import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { config, vuln } from "../config.js";
import { getDb, type ReceiptRow } from "../db/index.js";
import { decrypt, encrypt } from "../crypto/symmetric.js";
import { safeEqualHex, sha256Hex } from "../crypto/hash.js";
import { sign, verify } from "../crypto/signature.js";
import { logSecurityEvent } from "../security/events.js";

const ALLOWED: Record<string, Buffer[]> = {
  "application/pdf": [Buffer.from("%PDF")],
  "image/png": [Buffer.from([0x89, 0x50, 0x4e, 0x47])],
  "image/jpeg": [Buffer.from([0xff, 0xd8, 0xff])],
};

export type StoreResult = { ok: true; receipt: ReceiptRow } | { ok: false; error: string };

export function storeReceipt(ownerId: number, originalName: string, mime: string, data: Buffer, transactionId: number | null, ip: string): StoreResult {
  if (transactionId !== null) {
    const owned = getDb().prepare(`SELECT 1 FROM transactions t JOIN accounts a ON a.id = t.to_account_id
      WHERE t.id = ? AND a.owner_id = ? AND t.from_account_id IS NULL AND t.status = 'flagged'
      AND NOT EXISTS (SELECT 1 FROM receipts WHERE transaction_id = t.id)
      AND NOT EXISTS (SELECT 1 FROM transaction_reviews WHERE transaction_id = t.id)`).get(transactionId, ownerId);
    if (!owned) return { ok: false, error: "Depósito inválido ou já possui comprovante." };
  }
  mkdirSync(config.uploadDir, { recursive: true });
  if (!vuln.UPLOAD) {
    if (data.length > config.maxUploadBytes) return { ok: false, error: "Arquivo maior que 2 MB." };
    const magics = ALLOWED[mime];
    if (!magics || !magics.some((m) => data.subarray(0, m.length).equals(m))) {
      logSecurityEvent("upload_rejected", "warn", { userId: ownerId, ip, details: { originalName, mime } });
      return { ok: false, error: "Tipo de arquivo não permitido. Envie PDF, PNG ou JPEG." };
    }
  }
  const sha256 = sha256Hex(data);
  const storedName = vuln.UPLOAD ? originalName : randomBytes(16).toString("hex") + ".bin";
  const enc = vuln.UPLOAD ? null : encrypt(data);
  writeFileSync(join(config.uploadDir, storedName), enc ? enc.ciphertext : data);
  const r = getDb()
    .prepare(
      `INSERT INTO receipts (owner_id, transaction_id, original_name, stored_name, mime, size, sha256, iv, auth_tag, key_id, signature)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(ownerId, transactionId, originalName, storedName, mime, data.length, sha256, enc?.iv ?? "", enc?.authTag ?? "", enc?.keyId ?? "plain", sign(sha256));
  logSecurityEvent("receipt_uploaded", "info", { userId: ownerId, ip, details: { id: r.lastInsertRowid, sha256 } });
  return { ok: true, receipt: receiptById(Number(r.lastInsertRowid))! };
}

export function receiptById(id: number): ReceiptRow | undefined {
  return getDb().prepare("SELECT * FROM receipts WHERE id = ?").get(id) as ReceiptRow | undefined;
}

export function receiptsOf(ownerId: number): ReceiptRow[] {
  return getDb().prepare("SELECT * FROM receipts WHERE owner_id = ? ORDER BY id DESC").all(ownerId) as ReceiptRow[];
}

export type ReadResult = { ok: true; data: Buffer } | { ok: false; error: "tampered" | "missing" };

export function readReceipt(receipt: ReceiptRow, ip: string): ReadResult {
  let raw: Buffer;
  try {
    raw = readFileSync(join(config.uploadDir, receipt.stored_name));
  } catch {
    return { ok: false, error: "missing" };
  }
  let data: Buffer;
  if (receipt.key_id === "plain") {
    data = raw;
  } else {
    try {
      data = decrypt({ ciphertext: raw, iv: receipt.iv, authTag: receipt.auth_tag, keyId: receipt.key_id });
    } catch {
      logSecurityEvent("receipt_integrity_failure", "critical", { ip, details: { id: receipt.id, stage: "gcm_auth" } });
      return { ok: false, error: "tampered" };
    }
  }
  if (!vuln.NO_INTEGRITY) {
    const digest = sha256Hex(data);
    if (!safeEqualHex(digest, receipt.sha256) || !verify(receipt.sha256, receipt.signature)) {
      logSecurityEvent("receipt_integrity_failure", "critical", { ip, details: { id: receipt.id, expected: receipt.sha256, actual: digest } });
      return { ok: false, error: "tampered" };
    }
  }
  return { ok: true, data };
}

export function deleteReceipt(receipt: ReceiptRow): void {
  try {
    unlinkSync(join(config.uploadDir, receipt.stored_name));
  } catch {
    // The database entry must also be removed when the file is already absent.
  }
  getDb().prepare("DELETE FROM receipts WHERE id = ?").run(receipt.id);
}
