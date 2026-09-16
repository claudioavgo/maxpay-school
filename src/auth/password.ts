import argon2 from "argon2";
import { createHash } from "node:crypto";
import { vuln } from "../config.js";

export async function hashPassword(plain: string): Promise<string> {
  if (vuln.WEAK_AUTH) return "md5$" + createHash("md5").update(plain).digest("hex");
  return argon2.hash(plain, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
}

export async function verifyPassword(stored: string, plain: string): Promise<boolean> {
  if (stored.startsWith("md5$")) return stored === "md5$" + createHash("md5").update(plain).digest("hex");
  try {
    return await argon2.verify(stored, plain);
  } catch {
    return false;
  }
}

export function passwordPolicyError(plain: string): string | null {
  if (vuln.WEAK_AUTH) return null;
  if (plain.length < 10) return "A senha deve ter pelo menos 10 caracteres.";
  if (!/[A-Z]/.test(plain) || !/[a-z]/.test(plain) || !/[0-9]/.test(plain)) {
    return "A senha deve conter letras maiúsculas, minúsculas e números.";
  }
  return null;
}
