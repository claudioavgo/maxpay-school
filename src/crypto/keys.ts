import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { config } from "../config.js";

const KEY_ID = "master-v1";

export function masterKey(): { id: string; key: Buffer } {
  if (config.masterKeyHex.length === 64) {
    return { id: KEY_ID, key: Buffer.from(config.masterKeyHex, "hex") };
  }
  return { id: "derived-dev", key: createHash("sha256").update(config.sessionSecret).digest() };
}

export function ensureSigningKeys(): { privateKey: string; publicKey: string } {
  mkdirSync(config.certDir, { recursive: true });
  const priv = join(config.certDir, "signing-private.pem");
  const pub = join(config.certDir, "signing-public.pem");
  if (!existsSync(priv) || !existsSync(pub)) {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    writeFileSync(priv, privateKey, { mode: 0o600 });
    writeFileSync(pub, publicKey);
  }
  return { privateKey: readFileSync(priv, "utf8"), publicKey: readFileSync(pub, "utf8") };
}

export function newMasterKeyHex(): string {
  return randomBytes(32).toString("hex");
}
