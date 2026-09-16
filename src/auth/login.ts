import { generateSecret, generateURI, verify as verifyTotp } from "otplib";
import { config, vuln } from "../config.js";
import { getDb, type UserRow } from "../db/index.js";
import { logSecurityEvent } from "../security/events.js";
import { verifyPassword } from "./password.js";

export type LoginResult =
  | { ok: true; user: UserRow }
  | { ok: false; reason: "invalid" | "locked" | "mfa_required" | "mfa_invalid" };

export async function login(email: string, password: string, totp: string | undefined, ip: string): Promise<LoginResult> {
  const db = getDb();
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as UserRow | undefined;
  if (!user) {
    logSecurityEvent("login_failed", "warn", { ip, details: { email, reason: "unknown_user" } });
    return { ok: false, reason: "invalid" };
  }
  if (!vuln.WEAK_AUTH && user.locked_until && new Date(user.locked_until) > new Date()) {
    logSecurityEvent("login_locked", "warn", { userId: user.id, ip });
    return { ok: false, reason: "locked" };
  }
  if (!(await verifyPassword(user.password_hash, password))) {
    registerFailure(user, ip);
    return { ok: false, reason: "invalid" };
  }
  if (user.mfa_secret) {
    if (!totp) return { ok: false, reason: "mfa_required" };
    if (!(await verifyTotp({ secret: user.mfa_secret, token: totp, epochTolerance: 30 })).valid) {
      registerFailure(user, ip);
      logSecurityEvent("mfa_failed", "warn", { userId: user.id, ip });
      return { ok: false, reason: "mfa_invalid" };
    }
  }
  db.prepare("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?").run(user.id);
  logSecurityEvent("login_ok", "info", { userId: user.id, ip, details: { mfa: Boolean(user.mfa_secret) } });
  return { ok: true, user };
}

function registerFailure(user: UserRow, ip: string): void {
  const db = getDb();
  const failures = user.failed_logins + 1;
  let lockedUntil: string | null = null;
  if (!vuln.WEAK_AUTH && failures >= config.maxLoginFailures) {
    lockedUntil = new Date(Date.now() + config.lockoutMinutes * 60_000).toISOString();
    logSecurityEvent("account_locked", "critical", { userId: user.id, ip, details: { failures } });
  }
  db.prepare("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?").run(failures, lockedUntil, user.id);
  logSecurityEvent("login_failed", "warn", { userId: user.id, ip, details: { failures } });
}

export function enableMfa(userId: number): { secret: string; otpauth: string } {
  const user = getDb().prepare("SELECT email FROM users WHERE id = ?").get(userId) as { email: string };
  const secret = generateSecret();
  getDb().prepare("UPDATE users SET mfa_secret = ? WHERE id = ?").run(secret, userId);
  logSecurityEvent("mfa_enabled", "info", { userId });
  return { secret, otpauth: generateURI({ issuer: "MaxPay", label: user.email, secret }) };
}

export function disableMfa(userId: number): void {
  getDb().prepare("UPDATE users SET mfa_secret = NULL WHERE id = ?").run(userId);
  logSecurityEvent("mfa_disabled", "warn", { userId });
}
