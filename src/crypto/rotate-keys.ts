import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { config } from "../config.js";
import { getDb, type ReceiptRow } from "../db/index.js";
import { sha256Hex } from "./hash.js";
import { verify } from "./signature.js";

// Offline operation: stop the server first. Backups retain the old encrypted data and keys.
export async function rotateLocalSecrets(envPath = ".env", backupRoot = ".backups"): Promise<string> {
  const env = readFileSync(envPath, "utf8");
  const previousKey = config.masterKeyHex
    ? Buffer.from(config.masterKeyHex, "hex")
    : createHash("sha256").update(config.sessionSecret).digest();
  if (previousKey.length !== 32) throw new Error("Chave anterior inválida.");
  const nextKey = randomBytes(32);
  const sessionSecret = randomBytes(32).toString("hex");
  const db = getDb();
  const backup = join(backupRoot, `keys-${Date.now()}`);
  mkdirSync(backup, { recursive: true, mode: 0o700 });
  chmodSync(backup, 0o700);
  await db.backup(join(backup, "database.sqlite"));
  copyFileSync(envPath, join(backup, ".env"));
  chmodSync(join(backup, ".env"), 0o600);
  if (existsSync(config.uploadDir)) cpSync(config.uploadDir, join(backup, "uploads"), { recursive: true });

  function decrypt(ciphertext: Buffer, iv: string, tag: string): Buffer {
    const decipher = createDecipheriv("aes-256-gcm", previousKey, Buffer.from(iv, "base64"));
    decipher.setAuthTag(Buffer.from(tag, "base64"));
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }
  function encrypt(data: Buffer) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", nextKey, iv);
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    return { ciphertext, iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64") };
  }
  const newFiles: string[] = [];
  const oldFiles: string[] = [];
  const nextEnv = env.split("\n").filter(line => !/^\s*(SESSION_SECRET|MASTER_KEY_HEX)\s*=/.test(line)).join("\n").trimEnd()
    + `\nSESSION_SECRET=${sessionSecret}\nMASTER_KEY_HEX=${nextKey.toString("hex")}\n`;
  try {
    db.transaction(() => {
      const users = db.prepare("SELECT id, cpf_enc FROM users").all() as Array<{ id: number; cpf_enc: string }>;
      for (const user of users) {
        const [, iv, tag, data] = user.cpf_enc.split(".");
        const plaintext = decrypt(Buffer.from(data, "base64"), iv, tag);
        const encrypted = encrypt(plaintext);
        db.prepare("UPDATE users SET cpf_enc = ?, cpf_hash = CASE WHEN ? = '' THEN cpf_hash ELSE ? END WHERE id = ?")
          .run(["master-v1", encrypted.iv, encrypted.tag, encrypted.ciphertext.toString("base64")].join("."), plaintext.toString(), createHmac("sha256", sessionSecret).update(plaintext.toString().replace(/\D/g, "")).digest("hex"), user.id);
      }
      for (const receipt of db.prepare("SELECT * FROM receipts").all() as ReceiptRow[]) {
        const oldPath = join(config.uploadDir, receipt.stored_name);
        const raw = readFileSync(oldPath);
        const plaintext = receipt.key_id === "plain" ? raw : decrypt(raw, receipt.iv, receipt.auth_tag);
        if (sha256Hex(plaintext) !== receipt.sha256 || !verify(receipt.sha256, receipt.signature)) throw new Error(`Integridade inválida no comprovante ${receipt.id}. Migração cancelada.`);
        const encrypted = encrypt(plaintext);
        const name = randomBytes(16).toString("hex") + ".bin";
        const path = join(config.uploadDir, name);
        newFiles.push(path);
        writeFileSync(path, encrypted.ciphertext, { mode: 0o600 });
        oldFiles.push(oldPath);
        db.prepare("UPDATE receipts SET stored_name = ?, iv = ?, auth_tag = ?, key_id = 'master-v1' WHERE id = ?")
          .run(name, encrypted.iv, encrypted.tag, receipt.id);
      }
      writeFileSync(`${envPath}.next`, nextEnv, { mode: 0o600 });
      renameSync(`${envPath}.next`, envPath);
    })();
  } catch (error) {
    writeFileSync(envPath, env, { mode: 0o600 });
    for (const path of newFiles) rmSync(path, { force: true });
    rmSync(`${envPath}.next`, { force: true });
    throw error;
  }
  config.masterKeyHex = nextKey.toString("hex");
  config.sessionSecret = sessionSecret;
  for (const path of oldFiles) rmSync(path, { force: true });
  return backup;
}

if (process.argv[1]?.endsWith("rotate-keys.ts")) {
  const backup = await rotateLocalSecrets();
  console.log(`Chaves renovadas e dados preservados. Backup privado: ${backup}. Reinicie o serviço e entre novamente.`);
}
