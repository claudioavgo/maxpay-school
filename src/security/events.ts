import { getDb } from "../db/index.js";

export type Severity = "info" | "warn" | "critical";

export function logSecurityEvent(
  type: string,
  severity: Severity,
  opts: { userId?: number | null; ip?: string; details?: unknown } = {},
): void {
  getDb()
    .prepare("INSERT INTO security_events (type, severity, user_id, ip, details) VALUES (?, ?, ?, ?, ?)")
    .run(type, severity, opts.userId ?? null, opts.ip ?? null, opts.details === undefined ? null : JSON.stringify(opts.details));
}

export function listSecurityEvents(limit = 200) {
  return getDb()
    .prepare("SELECT * FROM security_events ORDER BY id DESC LIMIT ?")
    .all(limit) as Array<{ id: number; type: string; severity: Severity; user_id: number | null; ip: string | null; details: string | null; created_at: string }>;
}
