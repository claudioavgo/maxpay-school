import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { masterKey } from "./keys.js";

export interface Encrypted {
  ciphertext: Buffer;
  iv: string;
  authTag: string;
  keyId: string;
}

export function encrypt(plaintext: Buffer): Encrypted {
  const { id, key } = masterKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, iv: iv.toString("base64"), authTag: cipher.getAuthTag().toString("base64"), keyId: id };
}

export function decrypt(e: Encrypted): Buffer {
  const { key } = masterKey();
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(e.iv, "base64"));
  decipher.setAuthTag(Buffer.from(e.authTag, "base64"));
  return Buffer.concat([decipher.update(e.ciphertext), decipher.final()]);
}

export function encryptString(s: string): string {
  const e = encrypt(Buffer.from(s, "utf8"));
  return [e.keyId, e.iv, e.authTag, e.ciphertext.toString("base64")].join(".");
}

export function decryptString(packed: string): string {
  const [keyId, iv, authTag, ct] = packed.split(".");
  return decrypt({ keyId, iv, authTag, ciphertext: Buffer.from(ct, "base64") }).toString("utf8");
}
