import { constants, createSign, createVerify } from "node:crypto";
import { ensureSigningKeys } from "./keys.js";

export function sign(data: string | Buffer): string {
  const { privateKey } = ensureSigningKeys();
  const s = createSign("sha256");
  s.update(data);
  return s.sign({ key: privateKey, padding: constants.RSA_PKCS1_PSS_PADDING }, "base64");
}

export function verify(data: string | Buffer, signature: string): boolean {
  const { publicKey } = ensureSigningKeys();
  const v = createVerify("sha256");
  v.update(data);
  try {
    return v.verify({ key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING }, signature, "base64");
  } catch {
    return false;
  }
}

export function publicKeyPem(): string {
  return ensureSigningKeys().publicKey;
}
