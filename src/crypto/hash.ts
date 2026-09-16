import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { config } from "../config.js";

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

export function cpfLookupHash(cpf: string): string {
  return createHmac("sha256", config.sessionSecret).update(cpf.replace(/\D/g, "")).digest("hex");
}

export function safeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}
