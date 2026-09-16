import { afterEach, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { join, dirname } from "node:path";
import { readFileSync, writeFileSync } from "node:fs";
import { freshApp } from "./helpers.js";
import { config, validateSecrets } from "../src/config.js";
import { getDb, type UserRow } from "../src/db/index.js";
import { initializeDatabase } from "../src/db/initialize.js";
import { rotateLocalSecrets } from "../src/crypto/rotate-keys.js";
import { decryptString } from "../src/crypto/symmetric.js";
import { receiptById, readReceipt, storeReceipt } from "../src/receipts/service.js";
import { cpfLookupHash } from "../src/crypto/hash.js";
import { verifyLedger } from "../src/accounts/service.js";

let app: FastifyInstance;
afterEach(async () => { await app?.close(); });

it("preserva dados ao inicializar um banco existente", async () => {
  app = await freshApp();
  getDb().prepare("UPDATE accounts SET balance_cents = 123456 WHERE id = 1").run();
  const before = getDb().prepare("SELECT * FROM transactions").all();
  await initializeDatabase();
  await initializeDatabase();
  expect(getDb().prepare("SELECT balance_cents FROM accounts WHERE id = 1").get()).toEqual({balance_cents:123456});
  expect(getDb().prepare("SELECT * FROM transactions").all()).toEqual(before);
});

it("migra chaves sem alterar CPF, comprovantes ou assinaturas", async () => {
  app = await freshApp();
  const envPath = join(dirname(config.dbPath), ".env");
  writeFileSync(envPath, `SESSION_SECRET=${config.sessionSecret}\nMASTER_KEY_HEX=${config.masterKeyHex}\nDEEPSEEK_MODEL=deepseek-flash\n`);
  const originalKey = config.masterKeyHex;
  const user = getDb().prepare("SELECT * FROM users WHERE id = 3").get() as UserRow;
  const cpf = decryptString(user.cpf_enc);
  const result = storeReceipt(3,"proof.pdf","application/pdf",Buffer.from("%PDF test"),null,"test");
  if (!result.ok) throw new Error(result.error);
  const backup = await rotateLocalSecrets(envPath,join(dirname(config.dbPath),"backups"));
  expect(readFileSync(join(backup,".env"),"utf8")).toContain(originalKey);
  expect(config.masterKeyHex).not.toBe(originalKey);
  expect(readFileSync(envPath,"utf8")).toContain("DEEPSEEK_MODEL=deepseek-flash");
  const updated = getDb().prepare("SELECT * FROM users WHERE id = 3").get() as UserRow;
  expect(decryptString(updated.cpf_enc)).toBe(cpf);
  expect(updated.cpf_hash).toBe(cpfLookupHash(cpf));
  const receipt = receiptById(result.receipt.id)!;
  const read = readReceipt(receipt,"test");
  expect(read.ok && read.data.toString()).toBe("%PDF test");
  expect(receipt.signature).toBe(result.receipt.signature);
  expect(verifyLedger().ok).toBe(true);
  expect(()=>validateSecrets()).not.toThrow();
});

it("cancela migração e preserva configuração quando o arquivo foi adulterado", async () => {
  app = await freshApp();
  const envPath = join(dirname(config.dbPath),".env");
  const originalEnv = `SESSION_SECRET=${config.sessionSecret}\nMASTER_KEY_HEX=${config.masterKeyHex}\n`;
  writeFileSync(envPath,originalEnv);
  const originalUsers = getDb().prepare("SELECT cpf_enc FROM users").all();
  const result = storeReceipt(3,"proof.pdf","application/pdf",Buffer.from("%PDF test"),null,"test");
  if (!result.ok) throw new Error(result.error);
  writeFileSync(join(config.uploadDir,result.receipt.stored_name),"broken");
  await expect(rotateLocalSecrets(envPath,join(dirname(config.dbPath),"backups"))).rejects.toThrow();
  expect(readFileSync(envPath,"utf8")).toBe(originalEnv);
  expect(getDb().prepare("SELECT cpf_enc FROM users").all()).toEqual(originalUsers);
});

it("recusa segredos de exemplo e chave mestra ausente", async () => {
  app = await freshApp();
  const good = config.sessionSecret;
  config.sessionSecret = "change-me-32-bytes-minimum-please-change-me";
  expect(()=>validateSecrets()).toThrow();
  config.sessionSecret = good;
  config.masterKeyHex = "";
  expect(()=>validateSecrets()).toThrow();
});
